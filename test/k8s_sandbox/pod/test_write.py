import concurrent.futures
import io
import os
import signal
import socket
import subprocess
import sys
import threading
import time
import types
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Callable, Generator
from unittest.mock import MagicMock, patch

import kubernetes.client
import pytest
from kubernetes.stream.ws_client import (  # type: ignore[import-untyped]
    ERROR_CHANNEL,
    STDERR_CHANNEL,
    STDOUT_CHANNEL,
    WSClient,
)
from websocket import WebSocketConnectionClosedException

import k8s_sandbox._pod.op as op_module
import k8s_sandbox._pod.read as read_module
import k8s_sandbox._pod.write as write_module
from k8s_sandbox._pod.error import (
    ContainerStoppedError,
    ExecResultUnknownError,
    PodError,
)
from k8s_sandbox._pod.read import ReadFileOperation
from k8s_sandbox._pod.write import WriteFileOperation
from test.k8s_sandbox.pod import test_execute, test_op
from test.k8s_sandbox.pod.test_execute import _FakeWSClient, _status

_frame = test_execute._frame  # pyright: ignore[reportPrivateUsage]
_upgrade = test_op._upgrade  # pyright: ignore[reportPrivateUsage]
tls_sockets = test_execute.tls_sockets

# Each file operation's wait for its exec to end.
_WAITS = [
    pytest.param(
        write_module,
        lambda ws: WriteFileOperation(MagicMock())._handle_stream_output(ws),
        id="write",
    ),
    pytest.param(
        read_module,
        lambda ws: ReadFileOperation(MagicMock())._handle_stream_output(
            ws, io.BytesIO()
        ),
        id="read",
    ),
]


@pytest.mark.parametrize(("module", "wait"), _WAITS)
@pytest.mark.parametrize("ended", [False, True], ids=["no-status", "status"])
def test_an_exec_whose_close_never_comes_is_not_waited_for(
    module: Any, wait: Callable[[WSClient], None], ended: bool
) -> None:
    """Regression: a write whose command had ended waited two hours for its close."""
    ws = _FakeWSClient([_status(0)] if ended else [], ends=False)
    clock = types.SimpleNamespace(monotonic=lambda: ws.now)

    with patch.object(module, "time", clock):
        if ended:
            wait(ws)  # its status is in: the operation is done
        else:
            with pytest.raises(ExecResultUnknownError):
                wait(ws)

    assert ws.now == op_module.API_TIMEOUT


def test_a_read_that_goes_on_past_the_bound_is_not_cut_short() -> None:
    """The bound is on its silence: a large file takes longer than that to read."""
    pause = op_module.API_TIMEOUT - 1.0
    ws, dst = (
        _FakeWSClient(
            [(STDOUT_CHANNEL, b"a"), pause, (STDOUT_CHANNEL, b"b"), pause, _status(0)]
        ),
        io.BytesIO(),
    )
    clock = types.SimpleNamespace(monotonic=lambda: ws.now)

    with patch.object(read_module, "time", clock):
        ReadFileOperation(MagicMock())._handle_stream_output(ws, dst)

    assert dst.getvalue() == b"ab"


@pytest.mark.parametrize(("module", "wait"), _WAITS)
def test_an_end_tls_has_already_decrypted_is_read(
    module: Any,
    wait: Callable[[WSClient], None],
    tls_sockets: tuple[Any, Any],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Output, the status and the close in one TLS record, as a proxy sends them on."""
    monkeypatch.setattr(module, "API_TIMEOUT", 0.5)
    client, server = tls_sockets
    err = _frame(STDERR_CHANNEL, b"sh: ") + _frame(STDERR_CHANNEL, b"Permission denied")
    server.sendall(err + _frame(*_status(1)) + test_execute._close_frame())  # pyright: ignore[reportPrivateUsage]
    # Each as it opens its exec: a write's output is text.
    ws = test_execute._SocketWSClient(client, binary=module is read_module)  # pyright: ignore[reportPrivateUsage]

    with pytest.raises(PermissionError, match="sh: Permission denied"):
        wait(ws)


def test_write_file_writes_data_via_chunked_helper(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(op_module, "STDIN_CHUNK_SIZE", 4)
    op = WriteFileOperation(MagicMock())
    ws = MagicMock(spec=WSClient)
    captured: dict[str, int] = {}

    @contextmanager
    def fake_start_write_command(
        dst: Path, file_size: int
    ) -> Generator[MagicMock, None, None]:
        captured["file_size"] = file_size
        yield ws

    monkeypatch.setattr(op, "_start_write_command", fake_start_write_command)
    monkeypatch.setattr(op, "_handle_stream_output", lambda ws_client: None)
    data = b"abcdefghij"

    op.write_file(data, Path("/tmp/dst"))

    assert captured["file_size"] == len(data)
    assert b"".join(call.args[0] for call in ws.write_stdin.call_args_list) == data
    assert ws.write_stdin.call_count > 1


@pytest.mark.parametrize(("module", "wait"), _WAITS)
def test_a_frame_cut_short_is_not_waited_for_past_the_bound(
    module: Any,
    wait: Callable[[WSClient], None],
    tls_sockets: tuple[Any, Any],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Part of a frame and no more, as from a connection that has gone dark."""
    monkeypatch.setattr(module, "API_TIMEOUT", 0.5)
    client, server = tls_sockets
    server.sendall(_frame(STDOUT_CHANNEL, b"x"))  # a record of its own, read whole
    server.sendall(_frame(STDERR_CHANNEL, b"x")[:1])
    unblock = threading.Timer(30, server.close)  # only bounds a hang
    unblock.start()

    try:
        with pytest.raises(ExecResultUnknownError):
            wait(test_execute._SocketWSClient(client))  # pyright: ignore[reportPrivateUsage]
    finally:
        unblock.cancel()


@pytest.mark.parametrize(
    ("returncode", "error"),
    [
        # `head` and `mkdir` never exit 255: Kata's status for a stopped VM.
        pytest.param(255, ContainerStoppedError, id="container-stopped"),
        pytest.param(2, PodError, id="failed"),
    ],
)
def test_a_255_is_a_stopped_container(returncode: int, error: type[Exception]) -> None:
    ws = _FakeWSClient([_status(returncode)])

    with pytest.raises(error) as raised:
        WriteFileOperation(MagicMock())._handle_stream_output(ws)

    assert type(raised.value) is error


@pytest.mark.parametrize(
    "lost",
    [ConnectionResetError(), WebSocketConnectionClosedException()],
    ids=["reset", "closed"],
)
@pytest.mark.parametrize(
    ("frames", "stopped"),
    [
        ([_status(255)], True),
        ([_status(2)], False),
        # As for an exec into a dead container: no exit code, nor even `details`.
        ([(ERROR_CHANNEL, b'{"status":"Failure","reason":"InternalError"}')], False),
        ([], False),
    ],
    ids=["255", "another-status", "no-exit-code", "no-status"],
)
def test_a_255_before_the_connection_is_lost_is_a_stopped_container(
    frames: list[tuple[int, bytes]], stopped: bool, lost: Exception
) -> None:
    ws = _FakeWSClient(frames, error=lost)

    with pytest.raises(Exception) as raised:
        WriteFileOperation(MagicMock())._handle_stream_output(ws)

    assert type(raised.value) is (ContainerStoppedError if stopped else type(lost))


@pytest.mark.parametrize(
    ("code", "raised"),
    [
        (255, ContainerStoppedError),
        (2, OSError),  # the upload's own, which the provider retries
    ],
)
def test_a_255_sent_before_the_upload_failed_is_a_stopped_container(
    monkeypatch: pytest.MonkeyPatch, code: int, raised: type[Exception]
) -> None:
    """Regression: the upload's error was retried, in the container's replacement."""
    listening = socket.create_server(("127.0.0.1", 0))
    listening.settimeout(30)  # only bounds a hang

    def ends() -> None:  # the exec, with the upload unread
        connection, _ = listening.accept()
        with connection:
            connection.settimeout(30)  # only bounds a hang
            _upgrade(connection)
            connection.sendall(_frame(*_status(code)))

    server = threading.Thread(target=ends, daemon=True)
    server.start()
    host = f"http://127.0.0.1:{listening.getsockname()[1]}"
    configuration = kubernetes.client.Configuration(host=host)
    api = kubernetes.client.CoreV1Api(kubernetes.client.ApiClient(configuration))
    monkeypatch.setattr(op_module, "k8s_client", lambda _: api)
    pod = op_module.PodInfo("p", "ns", None, "default", "u", 0, "warn")
    pool = concurrent.futures.ThreadPoolExecutor(1)

    write = pool.submit(
        WriteFileOperation(pod).write_file, bytes(2**25), Path("/tmp/dst")
    )

    try:
        assert isinstance(write.exception(timeout=30), raised)  # only bounds a hang
    finally:
        listening.close()
        pool.shutdown(wait=False)
        server.join(30)


@pytest.mark.skipif(os.name != "posix", reason="Requires a POSIX shell")
def test_a_directory_that_looks_like_an_option_is_made(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    op = WriteFileOperation(MagicMock())
    exec_kwargs: dict[str, Any] = {}

    def fake_exec(**kwargs: Any) -> Generator[MagicMock, None, None]:
        exec_kwargs.update(kwargs)
        yield MagicMock(spec=WSClient)

    monkeypatch.setattr(op, "create_websocket_client_for_exec", fake_exec)
    with op._start_write_command(Path("-dir/dst"), 4):
        pass

    subprocess.run(
        exec_kwargs["command"],
        input=b"data",
        cwd=tmp_path,
        capture_output=True,
        timeout=30,
    )

    assert (tmp_path / "-dir" / "dst").read_bytes() == b"data"


@pytest.mark.skipif(os.name != "posix", reason="Requires a POSIX shell")
def test_mkdir_and_head_are_not_found_through_the_path(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """They run as the container's user."""
    ran = tmp_path / "ran"
    stubs = tmp_path / "stubs"
    stubs.mkdir()
    for name in ("mkdir", "head"):
        stub = stubs / name
        stub.write_text(f"#!/bin/sh\necho {name} >> {ran}\n")
        stub.chmod(0o755)
    op = WriteFileOperation(MagicMock())
    exec_kwargs: dict[str, Any] = {}

    def fake_exec(**kwargs: Any) -> Generator[MagicMock, None, None]:
        exec_kwargs.update(kwargs)
        yield MagicMock(spec=WSClient)

    monkeypatch.setattr(op, "create_websocket_client_for_exec", fake_exec)
    dst = tmp_path / "new" / "dir" / "dst"
    with op._start_write_command(dst, 4):
        pass
    env = {**os.environ, "PATH": f"{stubs}:{os.environ['PATH']}"}

    subprocess.run(
        exec_kwargs["command"], input=b"data", env=env, capture_output=True, timeout=30
    )

    assert not ran.exists()
    assert dst.read_bytes() == b"data"


@pytest.mark.skipif(os.name != "posix", reason="Requires a POSIX shell")
@pytest.mark.parametrize(
    "dst",
    ["file/dst", ".", "/dev/full"],
    ids=["no directory", "a directory", "no room"],
)
def test_a_write_that_fails_reads_its_whole_upload(tmp_path: Path, dst: str) -> None:
    """Regression: with input unread the exec never ended, and nor did write_file()."""
    if dst == "/dev/full" and not os.path.exists(dst):
        pytest.skip("no /dev/full here")
    (tmp_path / "file").touch()
    data = bytes(1024**2)  # more than a pipe holds
    command = write_module.write_command(tmp_path / dst, len(data))

    with (
        subprocess.Popen(
            command, stdin=subprocess.PIPE, stderr=subprocess.DEVNULL, bufsize=0
        ) as shell,
        concurrent.futures.ThreadPoolExecutor() as pool,
    ):
        try:
            assert shell.stdin is not None
            # Its stdin stays open, as an exec's does.
            assert pool.submit(shell.stdin.write, data).result(30) == len(data)
            assert shell.wait(30) != 0
        finally:
            shell.kill()  # and so a write still waiting on it ends


@pytest.mark.skipif(sys.platform != "linux", reason="Finds a process in /proc")
def test_a_write_whose_first_head_is_killed_is_no_success(tmp_path: Path) -> None:
    """What it had passed on would be the file, and the write a success."""
    command = write_module.write_command(tmp_path / "dst", 4)

    def reading(pipe: str) -> int | None:
        """The `head` whose stdin is the pipe: the write's first."""
        for pid in filter(str.isdigit, os.listdir("/proc")):
            try:
                stdin = os.readlink(f"/proc/{pid}/fd/0")
                name = Path(f"/proc/{pid}/comm").read_text()
            except OSError:  # gone, or not ours to read
                continue
            if (stdin, name) == (pipe, "head\n"):
                return int(pid)
        return None

    with subprocess.Popen(command, stdin=subprocess.PIPE) as shell:
        try:
            pipe = os.readlink(f"/proc/{shell.pid}/fd/0")
            deadline = time.monotonic() + 30  # only bounds a hang
            while (head := reading(pipe)) is None and time.monotonic() < deadline:
                time.sleep(0.01)
            assert head is not None
            os.kill(head, signal.SIGKILL)
            assert shell.wait(30) != 0
        finally:
            shell.kill()
