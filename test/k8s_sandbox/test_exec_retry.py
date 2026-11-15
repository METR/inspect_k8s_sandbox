import asyncio
import collections.abc
import contextlib
import json
import socket
import sys
import threading
from pathlib import Path
from unittest import mock
from unittest.mock import AsyncMock, MagicMock

import anyio
import kubernetes.client
import pytest
import urllib3
import websocket
from inspect_ai.util import ExecResult, OutputLimitExceededError
from kubernetes.client.exceptions import ApiException
from tenacity import wait_none

from k8s_sandbox import _helm, _sandbox_environment
from k8s_sandbox._pod import execd, op, pod
from k8s_sandbox._pod.error import (
    ContainerStoppedError,
    ExecdResultUnknownError,
    ExecResultUnknownError,
    ExecutableNotFoundError,
    GetReturncodeError,
    PodError,
    PodReplacedError,
)
from k8s_sandbox._sandbox_environment import (
    K8sError,
    K8sSandboxEnvironment,
)


@pytest.fixture(autouse=True)
def _no_retry_wait(monkeypatch: pytest.MonkeyPatch) -> None:
    """Disable tenacity's exponential backoff in tests."""
    original = _sandbox_environment._retry

    def _fast_retry():
        r = original()
        r.wait = wait_none()
        return r

    monkeypatch.setattr(_sandbox_environment, "_retry", _fast_retry)


def _make_sandbox() -> tuple[K8sSandboxEnvironment, MagicMock]:
    """Create a K8sSandboxEnvironment with mocked internals.

    Returns the sandbox and the mock pod (MagicMock) so callers can assign
    specific AsyncMock methods without mypy method-assign errors.
    """
    sandbox = object.__new__(K8sSandboxEnvironment)
    mock_pod = mock.create_autospec(pod.Pod, instance=True)
    sandbox._pod = mock_pod
    mock_pod.info = op.PodInfo("test-pod", "ns", None, "default", "uid", 0, "raise")
    sandbox._config = _sandbox_environment._ResolvedConfig(
        chart=None,
        values=None,
        context=None,
        default_user=None,
        restarted_container_behavior="raise",
        max_pod_ops=None,
    )
    sandbox.release = mock.create_autospec(
        _helm.Release, instance=True, task_name="test-task"
    )
    return sandbox, mock_pod


def _make_sandbox_with_mock_pod() -> tuple[K8sSandboxEnvironment, AsyncMock]:
    """Create a K8sSandboxEnvironment with a mocked _pod.exec."""
    sandbox, mock_pod = _make_sandbox()
    return sandbox, mock_pod.exec


def _make_sandbox_with_mock_read() -> tuple[K8sSandboxEnvironment, AsyncMock]:
    """Create a K8sSandboxEnvironment with a mocked _pod.read_file."""
    sandbox, mock_pod = _make_sandbox()
    return sandbox, mock_pod.read_file


def _make_sandbox_with_mock_write() -> tuple[K8sSandboxEnvironment, AsyncMock]:
    """Create a K8sSandboxEnvironment with a mocked _pod.write_file."""
    sandbox, mock_pod = _make_sandbox()
    return sandbox, mock_pod.write_file


def _success_result() -> ExecResult[str]:
    return ExecResult(success=True, returncode=0, stdout="ok", stderr="")


class TestExecRetryTransient:
    """Transient errors should be retried up to 5 times."""

    @pytest.mark.parametrize(
        "error",
        [
            pytest.param(
                ApiException(status=503, reason="Service Unavailable"),
                id="ApiException",
            ),
            pytest.param(
                websocket.WebSocketConnectionClosedException("gone"),
                id="WebSocketException",
            ),
            pytest.param(
                ConnectionError("connection refused"),
                id="ConnectionError",
            ),
            pytest.param(
                OSError("socket error"),
                id="OSError",
            ),
            pytest.param(
                PodError("WebSocket connection lost", pod="test-pod"),
                id="PodError",
            ),
            pytest.param(
                GetReturncodeError("no return code"),
                id="GetReturncodeError",
            ),
            pytest.param(
                ExecResultUnknownError("WebSocket connection lost", pod="test-pod"),
                id="ExecResultUnknownError",
            ),
        ],
    )
    async def test_transient_error_is_retried(self, error: Exception) -> None:
        sandbox, mock_exec = _make_sandbox_with_mock_pod()
        mock_exec.side_effect = [error, _success_result()]

        result = await sandbox.exec(["echo", "hello"])

        assert result.success
        assert result.stdout == "ok"
        assert mock_exec.call_count == 2

    async def test_transient_error_retried_multiple_times(self) -> None:
        sandbox, mock_exec = _make_sandbox_with_mock_pod()
        mock_exec.side_effect = [
            ApiException(status=503, reason="Service Unavailable"),
            ApiException(status=503, reason="Service Unavailable"),
            _success_result(),
        ]

        result = await sandbox.exec(["echo", "hello"])

        assert result.success
        assert mock_exec.call_count == 3

    async def test_each_resend_is_logged(
        self, caplog: pytest.LogCaptureFixture
    ) -> None:
        """A command sent again may have run twice: the log has to show it."""
        sandbox, mock_exec = _make_sandbox_with_mock_pod()
        mock_exec.side_effect = [ConnectionError("cut"), _success_result()]

        with caplog.at_level("WARNING"):
            await sandbox.exec(["echo", "hello"])

        assert caplog.text.count("sending it again") == 1
        assert "ConnectionError('cut')" in caplog.text


class TestExecRetryPermanent:
    """Permanent errors should NOT be retried."""

    @pytest.mark.parametrize(
        "error, expected_exception",
        [
            pytest.param(
                ExecutableNotFoundError("/bin/sh not found"),
                K8sError,
                id="ExecutableNotFoundError",
            ),
            pytest.param(
                RuntimeError("Pod UID mismatch"),
                K8sError,
                id="RuntimeError",
            ),
            pytest.param(
                PermissionError("permission denied"),
                PermissionError,
                id="PermissionError",
            ),
            pytest.param(
                ExecdResultUnknownError("execd stopped", pod="test-pod"),
                K8sError,
                id="ExecdResultUnknownError",
            ),
        ],
    )
    async def test_permanent_error_is_not_retried(
        self, error: Exception, expected_exception: type[Exception]
    ) -> None:
        sandbox, mock_exec = _make_sandbox_with_mock_pod()
        mock_exec.side_effect = error

        with pytest.raises(expected_exception):
            await sandbox.exec(["echo", "hello"])

        assert mock_exec.call_count == 1


class TestExecRetryExpectedExceptions:
    """Expected exceptions should pass through without retry."""

    @pytest.mark.parametrize(
        "error",
        [
            pytest.param(TimeoutError("timed out"), id="TimeoutError"),
            pytest.param(
                UnicodeDecodeError("utf-8", b"\xff", 0, 1, "invalid start byte"),
                id="UnicodeDecodeError",
            ),
            pytest.param(
                OutputLimitExceededError(limit_str="10MB", truncated_output="..."),
                id="OutputLimitExceededError",
            ),
        ],
    )
    async def test_expected_exception_passes_through(self, error: Exception) -> None:
        sandbox, mock_exec = _make_sandbox_with_mock_pod()
        mock_exec.side_effect = error

        with pytest.raises(type(error)):
            await sandbox.exec(["echo", "hello"])

        assert mock_exec.call_count == 1


class TestExecRetryExhausted:
    """After 5 failed attempts, the error should propagate."""

    async def test_retries_exhausted_raises_k8s_error(self) -> None:
        sandbox, mock_exec = _make_sandbox_with_mock_pod()
        mock_exec.side_effect = ApiException(status=503, reason="Service Unavailable")

        with pytest.raises(K8sError):
            await sandbox.exec(["echo", "hello"])

        assert mock_exec.call_count == 5


# -- read_file retry tests --


def _read_file_side_effect(error: Exception, content: bytes = b"file-content"):
    """Return a side_effect that fails once then writes content to dst."""
    calls = 0

    async def impl(src: Path, dst):
        nonlocal calls
        calls += 1
        if calls == 1:
            raise error
        dst.write(content)

    return impl


class TestReadFileRetryTransient:
    """Transient errors during read_file should be retried."""

    @pytest.mark.parametrize(
        "error",
        [
            pytest.param(
                ApiException(status=503, reason="Service Unavailable"),
                id="ApiException",
            ),
            pytest.param(
                websocket.WebSocketConnectionClosedException("gone"),
                id="WebSocketException",
            ),
            pytest.param(
                ConnectionError("connection refused"),
                id="ConnectionError",
            ),
            pytest.param(
                PodError("WebSocket connection lost", pod="test-pod"),
                id="PodError",
            ),
        ],
    )
    async def test_transient_error_is_retried(self, error: Exception) -> None:
        sandbox, mock_read = _make_sandbox_with_mock_read()
        mock_read.side_effect = _read_file_side_effect(error)

        contents = await sandbox.read_file("/tmp/test.txt")

        assert contents == "file-content"
        assert mock_read.call_count == 2


class TestReadFileRetryPermanent:
    """Permanent errors during read_file should NOT be retried."""

    async def test_permission_error_not_retried(self) -> None:
        sandbox, mock_read = _make_sandbox_with_mock_read()
        mock_read.side_effect = PermissionError("permission denied")

        with pytest.raises(PermissionError):
            await sandbox.read_file("/tmp/test.txt")

        assert mock_read.call_count == 1

    async def test_file_not_found_not_retried(self) -> None:
        sandbox, mock_read = _make_sandbox_with_mock_read()
        mock_read.side_effect = FileNotFoundError("no such file")

        with pytest.raises(FileNotFoundError):
            await sandbox.read_file("/tmp/test.txt")

        assert mock_read.call_count == 1

    async def test_stopped_container_not_retried(self) -> None:
        # A retry would read from the container that replaces it.
        sandbox, mock_read = _make_sandbox_with_mock_read()
        mock_read.side_effect = ContainerStoppedError("stopped")

        with pytest.raises(K8sError):
            await sandbox.read_file("/tmp/test.txt")

        assert mock_read.call_count == 1


class TestReadFileRetryExhausted:
    """After 5 failed attempts, read_file should propagate the error."""

    async def test_retries_exhausted_raises_k8s_error(self) -> None:
        sandbox, mock_read = _make_sandbox_with_mock_read()
        mock_read.side_effect = ApiException(status=503, reason="Service Unavailable")

        with pytest.raises(K8sError):
            await sandbox.read_file("/tmp/test.txt")

        assert mock_read.call_count == 5


# -- write_file retry tests --


class TestWriteFileRetryTransient:
    """Transient errors during write_file should be retried."""

    @pytest.mark.parametrize(
        "error",
        [
            pytest.param(
                ApiException(status=503, reason="Service Unavailable"),
                id="ApiException",
            ),
            pytest.param(
                websocket.WebSocketConnectionClosedException("gone"),
                id="WebSocketException",
            ),
            pytest.param(
                ConnectionError("connection refused"),
                id="ConnectionError",
            ),
            pytest.param(
                PodError("WebSocket connection lost", pod="test-pod"),
                id="PodError",
            ),
        ],
    )
    async def test_transient_error_is_retried(self, error: Exception) -> None:
        sandbox, mock_write = _make_sandbox_with_mock_write()
        mock_write.side_effect = [error, None]

        await sandbox.write_file("/tmp/test.txt", "hello")

        assert mock_write.call_count == 2


class TestWriteFileRetryPermanent:
    """Permanent errors during write_file should NOT be retried."""

    async def test_permission_error_not_retried(self) -> None:
        sandbox, mock_write = _make_sandbox_with_mock_write()
        mock_write.side_effect = PermissionError("permission denied")

        with pytest.raises(PermissionError):
            await sandbox.write_file("/tmp/test.txt", "hello")

        assert mock_write.call_count == 1

    async def test_is_a_directory_not_retried(self) -> None:
        sandbox, mock_write = _make_sandbox_with_mock_write()
        mock_write.side_effect = IsADirectoryError("is a directory")

        with pytest.raises(IsADirectoryError):
            await sandbox.write_file("/tmp/test.txt", "hello")

        assert mock_write.call_count == 1


class TestWriteFileRetryExhausted:
    """After 5 failed attempts, write_file should propagate the error."""

    async def test_retries_exhausted_raises_k8s_error(self) -> None:
        sandbox, mock_write = _make_sandbox_with_mock_write()
        mock_write.side_effect = ApiException(status=503, reason="Service Unavailable")

        with pytest.raises(K8sError):
            await sandbox.write_file("/tmp/test.txt", "hello")

        assert mock_write.call_count == 5


def _shows(status: int, restarts: int = 0) -> bytes:
    """An API server's answer: the pod, its container restarted this often."""
    container = {"name": "default", "restartCount": restarts, "state": {"running": {}}}
    shown = {"metadata": {"name": "p", "uid": "u"}}
    body = json.dumps(shown | {"status": {"containerStatuses": [container]}})
    head = f"HTTP/1.1 {status} \r\nConnection: close\r\nContent-Length: {len(body)}"
    return f"{head}\r\n\r\n{body}".encode()


Api = collections.abc.Callable[..., list[bytes]]


@pytest.fixture
def api(monkeypatch: pytest.MonkeyPatch) -> collections.abc.Iterator[Api]:
    """Starts a local API server: it gives each request the next answer, then stops."""
    listening = socket.create_server(("127.0.0.1", 0), backlog=0)
    listening.settimeout(30)  # only bounds a hang
    held = socket.socket()
    asked: list[bytes] = []
    servers: list[threading.Thread] = []

    def serve(answers: list[bytes], then: str) -> None:
        with contextlib.suppress(OSError):  # it ends with its test, which then fails
            for n, answer in enumerate(answers, 1):
                connection, _ = listening.accept()
                with connection:
                    connection.settimeout(30)  # only bounds a hang
                    asked.append(connection.recv(65536))
                    last = n == len(answers)
                    if last and then in ("drops the connect", "never answers"):
                        monkeypatch.setattr(op, "API_TIMEOUT", 1)  # for what comes now
                        if then == "drops the connect":
                            held.connect(listening.getsockname())  # fills the queue
                    elif last:
                        listening.close()  # before the answer is read
                    connection.sendall(answer)

    def start(answers: list[bytes], then: str = "refuses") -> list[bytes]:
        host = f"http://127.0.0.1:{listening.getsockname()[1]}"
        configuration = kubernetes.client.Configuration(host=host)
        # urllib3's own retries would only lengthen the wait.
        configuration.retries = 0  # type: ignore[attr-defined]
        client = kubernetes.client.CoreV1Api(kubernetes.client.ApiClient(configuration))
        monkeypatch.setattr(op, "k8s_client", lambda _: client)
        server = threading.Thread(target=serve, args=(answers, then), daemon=True)
        servers.append(server)
        server.start()
        return asked

    # Off, so that the provider's check is the only one before an attempt.
    monkeypatch.setenv("INSPECT_POD_RESTART_CHECK", "false")
    yield start
    held.close()
    listening.close()
    for server in servers:
        server.join(30)  # only bounds a hang


@pytest.mark.parametrize(
    ("then", "tried_again"),
    [
        ("refuses", True),
        ("cuts the connection", True),
        pytest.param(
            "drops the connect",  # as Linux does one that finds its queue full
            False,
            marks=pytest.mark.skipif(sys.platform != "linux", reason="Linux only"),
        ),
        ("never answers", False),
    ],
)
async def test_only_a_connection_that_fails_at_once_is_tried_again(
    api: Api, caplog: pytest.LogCaptureFixture, then: str, tried_again: bool
) -> None:
    """Regression: an API server down at a file operation's restart check failed it."""
    cut = [b""] if then == "cuts the connection" else []  # closed with no answer
    api([_shows(500), _shows(200), *cut], then)  # its exec fails, no restart shows
    sandbox, _ = _make_sandbox()
    sandbox._pod = pod.Pod("p", "ns", None, "default", "u", 0, "raise")

    with (
        caplog.at_level("WARNING"),
        pytest.raises(_sandbox_environment.K8sError) as raised,
    ):
        await asyncio.wait_for(sandbox.read_file("/tmp/f"), 30)

    assert isinstance(raised.value.__cause__, urllib3.exceptions.MaxRetryError)
    # One that waited out a timeout has cost four minutes already.
    assert (caplog.text.count("sending it again") > 1) == tried_again


# -- exec_stdio retry tests --


class TestExecStdioRetry:
    """Opening is retried as exec() is, and runs as the default user unless told."""

    async def test_transient_error_is_retried(self) -> None:
        sandbox, mock_pod = _make_sandbox()
        stream = mock.create_autospec(execd.ExecdStream, instance=True)
        mock_pod.exec_stdio.side_effect = [
            ApiException(status=503, reason="Unavailable"),
            stream,
        ]

        opened = await sandbox.exec_stdio(["inspect-sandbox-tools", "bridge"])

        assert mock_pod.exec_stdio.call_count == 2
        assert opened is stream

    async def test_a_pod_replaced_while_the_stream_opened_fails_the_open(self) -> None:
        """Nothing checks the pod again while the stream lasts."""
        sandbox, mock_pod = _make_sandbox()
        stream = mock.create_autospec(execd.ExecdStream, instance=True)
        mock_pod.exec_stdio.return_value = stream
        mock_pod.check_for_pod_restart.side_effect = PodReplacedError(
            pod_name="test-pod", old_uid="a", new_uid="b", new_restart_count=0
        )

        with pytest.raises(K8sError) as error:
            await sandbox.exec_stdio(["inspect-sandbox-tools", "bridge"])

        assert isinstance(error.value.__cause__, PodReplacedError)
        stream.aclose.assert_awaited_once()

    async def test_a_stream_whose_pod_check_is_cancelled_is_closed(self) -> None:
        sandbox, mock_pod = _make_sandbox()
        stream = mock.create_autospec(execd.ExecdStream, instance=True)
        mock_pod.exec_stdio.return_value = stream
        mock_pod.check_for_pod_restart.side_effect = anyio.Event().wait

        with anyio.fail_after(30):
            async with anyio.create_task_group() as tasks:
                tasks.start_soon(sandbox.exec_stdio, ["inspect-sandbox-tools"])
                await anyio.wait_all_tasks_blocked()
                tasks.cancel_scope.cancel()

        stream.aclose.assert_awaited_once()

    async def test_a_failed_pod_check_does_not_start_the_command_again(self) -> None:
        sandbox, mock_pod = _make_sandbox()
        stream = mock.create_autospec(execd.ExecdStream, instance=True)
        mock_pod.exec_stdio.return_value = stream
        mock_pod.check_for_pod_restart.side_effect = [
            ApiException(status=503, reason="Unavailable"),
            None,
        ]

        await sandbox.exec_stdio(["inspect-sandbox-tools", "bridge"])

        assert mock_pod.exec_stdio.call_count == 1

    @pytest.mark.parametrize("user, expected", [(None, "agent"), ("root", "root")])
    async def test_the_default_user_is_used_unless_one_is_given(
        self, user: str | None, expected: str
    ) -> None:
        sandbox, mock_pod = _make_sandbox()
        sandbox._config = sandbox._config.model_copy(update={"default_user": "agent"})

        await sandbox.exec_stdio(["inspect-sandbox-tools", "bridge"], user)

        assert mock_pod.exec_stdio.call_args.args == (
            ["inspect-sandbox-tools", "bridge"],
            expected,
        )
