import os
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator
from unittest.mock import AsyncMock, MagicMock, call, patch

import anyio
import pytest
import websocket
from inspect_ai.util import ExecResult, OutputLimitExceededError
from kubernetes.client.exceptions import ApiException
from tenacity import wait_none

import k8s_sandbox._pod.execute as execute_module
from k8s_sandbox import _sandbox_environment
from k8s_sandbox._pod.error import (
    ContainerStoppedError,
    ExecRecordUnfinishedError,
    ExecResultUnknownError,
    ExecStreamLostError,
    ExecutableNotFoundError,
    GetReturncodeError,
    PodError,
    PodReplacedError,
)
from k8s_sandbox._pod.execute import ExecuteOperation
from k8s_sandbox._sandbox_environment import (
    K8sError,
    K8sSandboxEnvironment,
)
from test.k8s_sandbox.pod.test_check_for_pod_restart import _k8s_pod, _make_pod
from test.k8s_sandbox.pod.test_execute import (
    _SHELLS,
    STDERR,
    STDOUT,
    _FakeWSClient,
    _run_script,
    _stand_in_for_cat,
    _status,
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
    mock_pod = MagicMock()
    sandbox._pod = mock_pod
    mock_pod.info = MagicMock()
    mock_pod.info.name = "test-pod"
    sandbox._config = MagicMock()
    sandbox._config.default_user = None
    sandbox.release = MagicMock()
    sandbox.release.task_name = "test-task"
    mock_pod.check_for_pod_restart = AsyncMock()
    return sandbox, mock_pod


def _make_sandbox_with_mock_pod() -> tuple[K8sSandboxEnvironment, AsyncMock]:
    """Create a K8sSandboxEnvironment with a mocked _pod.exec."""
    sandbox, mock_pod = _make_sandbox()
    mock_exec = AsyncMock()
    mock_pod.exec = mock_exec
    return sandbox, mock_exec


def _make_sandbox_with_mock_read() -> tuple[K8sSandboxEnvironment, AsyncMock]:
    """Create a K8sSandboxEnvironment with a mocked _pod.read_file."""
    sandbox, mock_pod = _make_sandbox()
    mock_read = AsyncMock()
    mock_pod.read_file = mock_read
    return sandbox, mock_read


def _make_sandbox_with_mock_write() -> tuple[K8sSandboxEnvironment, AsyncMock]:
    """Create a K8sSandboxEnvironment with a mocked _pod.write_file."""
    sandbox, mock_pod = _make_sandbox()
    mock_write = AsyncMock()
    mock_pod.write_file = mock_write
    return sandbox, mock_write


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
                ExecResultUnknownError("WebSocket connection lost", pod="test-pod"),
                K8sError,
                id="ExecResultUnknownError",
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

    @pytest.mark.parametrize(
        "then",
        [
            pytest.param(ExecStreamLostError("lost", pod="test-pod"), id="lost-again"),
            pytest.param(ApiException(status=503, reason="Unavailable"), id="503"),
        ],
    )
    async def test_retries_exhausted_after_a_lost_connection_leave_the_result_unknown(
        self, then: Exception
    ) -> None:
        """No attempt reached the record of a command that may have run."""
        sandbox, mock_exec = _make_sandbox_with_mock_pod()
        lost = ExecStreamLostError("lost", pod="test-pod")
        mock_exec.side_effect = [lost, then, then, then, then]

        with pytest.raises(K8sError) as raised:
            await sandbox.exec(["echo", "hello"])

        assert mock_exec.call_count == 5
        assert isinstance(raised.value.__cause__, ExecResultUnknownError)

    async def test_a_timeout_after_a_lost_connection_is_still_a_timeout(self) -> None:
        sandbox, mock_exec = _make_sandbox_with_mock_pod()
        mock_exec.side_effect = [
            ExecStreamLostError("lost", pod="test-pod"),
            TimeoutError("Command timed out after 30s."),
        ]

        with pytest.raises(TimeoutError):
            await sandbox.exec(["echo", "hello"], timeout=30)

        assert mock_exec.call_count == 2


class TestExecRetryById:
    """A retry asks for the same exec again, so it cannot run the command twice."""

    async def test_attempts_share_an_id_that_the_next_exec_does_not(self) -> None:
        sandbox, mock_pod = _make_sandbox()
        mock_pod.exec = AsyncMock(
            side_effect=[
                ApiException(status=503, reason="Service Unavailable"),
                ExecStreamLostError("lost", pod="test-pod"),
                _success_result(),
                ExecRecordUnfinishedError("unfinished", pod="test-pod"),
                _success_result(),
            ]
        )

        await sandbox.exec(["echo", "hello"])
        await sandbox.exec(["echo", "hello"])

        ids, resent, started = zip(*(c.args[6:] for c in mock_pod.exec.call_args_list))
        # Only a lost connection may have sent the command: the 503 sent nothing.
        assert resent == (False, False, True, False, True)
        # Only a record that was sent says the command has started.
        assert started == (False, False, False, False, True)
        assert ids[0] == ids[1] == ids[2] != ids[3] == ids[4]
        # A lost attempt may yet reach the pod, and must find its record there.
        assert mock_pod.exec_finished.call_args_list == [call(None, ids[3])]


class _ShellWSClient(_FakeWSClient):
    """An exec in a pod that is this machine: `shell` runs the script written to it."""

    def __init__(self, shell: list[str], scripts: list[str]) -> None:
        super().__init__([])
        self._shell = shell
        self._scripts = scripts
        self._script = ""

    def write_stdin(self, data: str) -> None:
        self._script += data
        if data == "}\n":  # The closing line: the shell has it all, and runs it.
            self._scripts.append(self._script)
            result = _run_script(self._shell, self._script)
            self._frames = [
                (STDOUT, result.stdout),
                (STDERR, result.stderr),
                _status(result.returncode),
            ]


@pytest.mark.skipif(os.name != "posix", reason="Requires a POSIX shell")
@pytest.mark.parametrize("shell", _SHELLS)
class TestExecInAShell:
    """exec() from end to end, with a shell here for the pod's."""

    @pytest.fixture
    def scripts(
        self, shell: list[str], tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> list[str]:
        """The scripts exec() sends: `shell` runs each, its record in `tmp_path`."""
        scripts: list[str] = []

        @contextmanager
        def shell_here(
            self: ExecuteOperation, command: list[str]
        ) -> Iterator[_ShellWSClient]:
            yield _ShellWSClient(shell, scripts)

        monkeypatch.setattr(ExecuteOperation, "_interactive_shell", shell_here)
        (tmp_path / "tmp").mkdir()
        (tmp_path / "tmp").chmod(0o1777)  # Sticky, as a pod's /tmp is.
        monkeypatch.setattr(
            execute_module, "RECORD_PREFIX", str(tmp_path / "tmp" / "exec-")
        )
        return scripts

    @pytest.fixture
    def sandbox(self, scripts: list[str]) -> Iterator[K8sSandboxEnvironment]:
        sandbox, _ = _make_sandbox()
        sandbox._pod = _make_pod()
        with patch("k8s_sandbox._pod.op.k8s_client") as client:
            client.return_value.read_namespaced_pod.return_value = _k8s_pod(
                uid="uid-OLD", container_name="default", restart_count=0
            )
            yield sandbox

    @pytest.fixture
    def stand_in(self, shell: list[str]) -> None:
        """For a test that stands in for `cat`."""
        if shell[0] == "busybox":
            pytest.skip("busybox sh runs its own cat, whatever the PATH")

    async def test_a_record_sent_before_its_end_is_asked_for_again(
        self,
        stand_in: None,
        sandbox: K8sSandboxEnvironment,
        scripts: list[str],
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Its relays were slow: here they copy nothing until a record has been sent."""
        sent = tmp_path / "sent"
        _stand_in_for_cat(
            tmp_path,
            monkeypatch,
            relay=f"until [ -e {sent} ]; do sleep 0.05; done\nexec $CAT",
            sender=f'$CAT "$@"\n: > {sent}',
        )
        runs = tmp_path / "runs"
        cmd = ["sh", "-c", f"echo run >> {runs}; echo out; echo err >&2; exit 3"]

        result = await sandbox.exec(cmd)

        assert (result.returncode, result.stdout, result.stderr) == (
            3,
            "out\n",
            "err\n",
        )
        assert (len(scripts), runs.read_text()) == (2, "run\n")

    async def test_a_command_that_has_started_is_not_started_again(
        self,
        stand_in: None,
        sandbox: K8sSandboxEnvironment,
        scripts: list[str],
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """A record was sent, not complete, and the command moved its record away."""
        sent = tmp_path / "sent"
        _stand_in_for_cat(
            tmp_path,
            monkeypatch,
            relay=f"until [ -e {sent} ]; do sleep 0.05; done\nexec $CAT",
            sender=f'$CAT "$@"\n: > {sent}',
        )
        runs = tmp_path / "runs"
        moves = f"mv {tmp_path}/tmp/exec-* {tmp_path}/moved"

        with pytest.raises(K8sError) as raised:
            await sandbox.exec(["sh", "-c", f"echo run >> {runs}; {moves}; echo out"])

        assert isinstance(raised.value.__cause__, ExecResultUnknownError)
        assert (len(scripts), runs.read_text()) == (2, "run\n")

    async def test_a_record_that_never_gets_its_end_leaves_the_result_unknown(
        self,
        stand_in: None,
        sandbox: K8sSandboxEnvironment,
        scripts: list[str],
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Its relays lost the output: no attempt may pass off what there is as all."""
        _stand_in_for_cat(tmp_path, monkeypatch, relay="exec $CAT >/dev/null")

        with pytest.raises(K8sError) as raised:
            await sandbox.exec(["sh", "-c", "echo out; exit 3"])

        assert isinstance(raised.value.__cause__, ExecResultUnknownError)
        assert len(scripts) == 5


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


# -- exec_stdio retry tests --


class TestExecStdioRetry:
    """Opening is retried as exec() is, and runs as the default user unless told."""

    async def test_transient_error_is_retried(self) -> None:
        sandbox, mock_pod = _make_sandbox()
        stream = MagicMock()
        mock_pod.exec_stdio = AsyncMock(
            side_effect=[ApiException(status=503, reason="Unavailable"), stream]
        )

        opened = await sandbox.exec_stdio(["inspect-sandbox-tools", "bridge"])

        assert mock_pod.exec_stdio.call_count == 2
        assert opened is stream

    async def test_a_pod_replaced_while_the_stream_opened_fails_the_open(self) -> None:
        """Nothing checks the pod again while the stream lasts."""
        sandbox, mock_pod = _make_sandbox()
        stream = AsyncMock()
        mock_pod.exec_stdio = AsyncMock(return_value=stream)
        mock_pod.check_for_pod_restart = AsyncMock(
            side_effect=PodReplacedError(
                pod_name="test-pod", old_uid="a", new_uid="b", new_restart_count=0
            )
        )

        with pytest.raises(K8sError) as error:
            await sandbox.exec_stdio(["inspect-sandbox-tools", "bridge"])

        assert isinstance(error.value.__cause__, PodReplacedError)
        stream.aclose.assert_awaited_once()

    async def test_a_stream_whose_pod_check_is_cancelled_is_closed(self) -> None:
        sandbox, mock_pod = _make_sandbox()
        stream = AsyncMock()
        mock_pod.exec_stdio = AsyncMock(return_value=stream)
        mock_pod.check_for_pod_restart = AsyncMock(side_effect=anyio.Event().wait)

        with anyio.fail_after(30):
            async with anyio.create_task_group() as tasks:
                tasks.start_soon(sandbox.exec_stdio, ["inspect-sandbox-tools"])
                await anyio.wait_all_tasks_blocked()
                tasks.cancel_scope.cancel()

        stream.aclose.assert_awaited_once()

    async def test_a_failed_pod_check_does_not_start_the_command_again(self) -> None:
        sandbox, mock_pod = _make_sandbox()
        stream = MagicMock()
        mock_pod.exec_stdio = AsyncMock(return_value=stream)
        mock_pod.check_for_pod_restart = AsyncMock(
            side_effect=[ApiException(status=503, reason="Unavailable"), None]
        )

        await sandbox.exec_stdio(["inspect-sandbox-tools", "bridge"])

        assert mock_pod.exec_stdio.call_count == 1

    @pytest.mark.parametrize("user, expected", [(None, "agent"), ("root", "root")])
    async def test_the_default_user_is_used_unless_one_is_given(
        self, user: str | None, expected: str
    ) -> None:
        sandbox, mock_pod = _make_sandbox()
        sandbox._config = MagicMock(default_user="agent")
        mock_pod.exec_stdio = AsyncMock()

        await sandbox.exec_stdio(["inspect-sandbox-tools", "bridge"], user)

        assert mock_pod.exec_stdio.call_args.args == (
            ["inspect-sandbox-tools", "bridge"],
            expected,
        )
