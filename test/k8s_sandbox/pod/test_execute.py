import concurrent.futures
import io
import json
import os
import pwd
import re
import shlex
import shutil
import socket
import ssl
import subprocess
import sys
import threading
import time
import types
from contextlib import contextmanager
from pathlib import Path
from typing import Callable, Generator, Iterable, Sequence
from unittest.mock import MagicMock, patch

import pytest
import websocket
from inspect_ai.util import ExecResult, OutputLimitExceededError
from kubernetes.stream.ws_client import (  # type: ignore
    ERROR_CHANNEL,
    WSClient,
)
from kubernetes.stream.ws_client import (
    STDERR_CHANNEL as STDERR,
)
from kubernetes.stream.ws_client import (
    STDOUT_CHANNEL as STDOUT,
)

import k8s_sandbox._pod.execute as execute_module
import k8s_sandbox._pod.op as op_module
from k8s_sandbox._pod.error import (
    ExecResultUnknownError,
    GetReturncodeError,
    PodError,
)
from k8s_sandbox._pod.execute import ExecuteOperation, _shell_command

MARKER = "<completed-sentinel-value-0123456789abcdef0123456789abcdef-"


def _marker(returncode: int) -> bytes:
    return f"{MARKER}{returncode}>".encode()


def _status(returncode: int) -> tuple[int, bytes]:
    """The status channel frame the API server sends as the exec ends."""
    if returncode == 0:
        return ERROR_CHANNEL, b'{"metadata":{},"status":"Success"}'
    cause = {"reason": "ExitCode", "message": str(returncode)}
    status = {"status": "Failure", "details": {"causes": [cause]}}
    return ERROR_CHANNEL, json.dumps(status).encode()


class _FakeWSClient(WSClient):
    """A WSClient whose frames come from a list rather than a socket.

    Only update() is replaced, so peek_*() and read_*() behave as they do for real,
    including peek_*() calling update(timeout=0) and so taking in the next frame.

    A number in place of a frame is a pause, in seconds, before the next one. Once the
    frames run out the exec ends (the server closes the connection), unless
    `ends=False`, which is a background process holding stdout or stderr open: then
    nothing more ever arrives.
    """

    def __init__(
        self,
        frames: Sequence[tuple[int, bytes] | float],
        ends: bool = True,
        error: Exception | None = None,
    ) -> None:
        self._connected = True
        self._channels: dict[int, bytes] = {}
        self._closed_channels: set[int] = set()
        self.subprotocol = None
        self.binary = True
        # No socket: nothing for _take_decrypted_frames to read, nothing to close.
        self.sock = types.SimpleNamespace(sock=None, close=lambda **kwargs: None)
        self._frames = list(frames)
        self._ends = ends
        self._error = error

    def update(self, timeout: float | None = 0) -> None:
        if not self.is_open():
            return
        if self._frames and isinstance(self._frames[0], float):
            pause = self._frames[0]
            if timeout is not None and timeout < pause:
                time.sleep(timeout)
                self._frames[0] = pause - timeout
                return
            time.sleep(pause)
            self._frames.pop(0)
        if self._frames:
            frame = self._frames.pop(0)
            assert not isinstance(frame, float)
            channel, data = frame
            self._channels[channel] = self._channels.get(channel, b"") + data
        elif self._error is not None:
            raise self._error
        elif self._ends:
            self._connected = False
        elif timeout is None:
            raise AssertionError("update(timeout=None) would block forever")
        else:
            time.sleep(timeout)


def _handle(
    ws: WSClient, user: str | None = None, timeout: int | None = None
) -> ExecResult[str]:
    return ExecuteOperation(MagicMock())._handle_shell_output(ws, user, timeout, MARKER)


@pytest.fixture
def short_grace(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(execute_module, "STREAM_END_GRACE_SECONDS", 0.01)


class TestCompletion:
    """The command's exit code comes from the status channel, not from its output."""

    def test_exit_code_comes_from_the_status_channel(self) -> None:
        ws = _FakeWSClient(
            [(STDOUT, b"out" + _marker(0)), (STDERR, _marker(0)), _status(3)]
        )

        result = _handle(ws)

        assert (result.returncode, result.success) == (3, False)
        assert result.stdout == "out"

    def test_a_status_that_arrives_wins_over_the_markers(
        self, short_grace: None
    ) -> None:
        """Even if the connection then stays open past the grace period."""
        ws = _FakeWSClient(
            [(STDOUT, _marker(0)), (STDERR, _marker(0)), _status(3)], ends=False
        )

        result = _handle(ws)

        assert (result.returncode, result.success) == (3, False)

    @pytest.mark.parametrize(
        "printed",
        [
            pytest.param(b"<completed-sentinel-value-0>", id="old-fixed-sentinel"),
            pytest.param(
                b"<completed-sentinel-value-ffffffffffffffffffffffffffffffff-0>",
                id="marker-of-another-exec",
            ),
        ],
    )
    def test_output_imitating_a_marker_does_not_end_the_exec(
        self, printed: bytes
    ) -> None:
        """A command printing a marker must neither end the exec nor set its code."""
        ws = _FakeWSClient(
            [
                (STDOUT, b"before " + printed + b" after"),
                (STDERR, printed),
                (STDOUT, b" still running"),
                (STDOUT, _marker(1)),
                (STDERR, _marker(1)),
                _status(1),
            ]
        )

        result = _handle(ws)

        assert result.returncode == 1
        assert result.stdout == f"before {printed.decode()} after still running"
        assert result.stderr == printed.decode()

    @pytest.mark.parametrize("cut", range(1, len(b"out" + _marker(255))))
    def test_a_marker_split_across_frames_is_recognised(
        self, cut: int, short_grace: None
    ) -> None:
        """Here the exec stays open, so only the split marker can end it."""
        stdout = b"out" + _marker(255)
        ws = _FakeWSClient(
            [(STDOUT, stdout[:cut]), (STDOUT, stdout[cut:]), (STDERR, _marker(255))],
            ends=False,
        )

        result = _handle(ws)

        assert result.returncode == 255
        assert result.stdout == "out"

    def test_returns_while_a_background_process_holds_the_streams_open(
        self, short_grace: None
    ) -> None:
        ws = _FakeWSClient(
            [(STDOUT, b"out" + _marker(0)), (STDERR, b"err" + _marker(0))],
            ends=False,
        )

        result = _handle(ws)

        assert (result.returncode, result.success) == (0, True)
        assert (result.stdout, result.stderr) == ("out", "err")

    def test_markers_that_disagree_are_not_trusted(self, short_grace: None) -> None:
        """Code the command runs can read stdout's marker back and forge it."""
        ws = _FakeWSClient([(STDOUT, _marker(0)), (STDERR, _marker(1))], ends=False)

        with pytest.raises(ExecResultUnknownError, match="disagree"):
            _handle(ws)

    def test_a_status_without_an_exit_code_leaves_it_to_the_markers(self) -> None:
        status = {
            "status": "Failure",
            "message": "error executing command in container",
            "details": {"causes": [{"message": "failed while waiting for exec"}]},
        }
        ws = _FakeWSClient(
            [
                (STDOUT, _marker(5)),
                (STDERR, _marker(5)),
                (ERROR_CHANNEL, json.dumps(status).encode()),
            ]
        )

        result = _handle(ws)

        assert result.returncode == 5

    def test_output_after_the_marker_is_dropped(self, short_grace: None) -> None:
        """Only background processes can write after the shell's marker."""
        ws = _FakeWSClient(
            [
                (STDOUT, b"out" + _marker(0) + b"bg"),
                (STDERR, _marker(0)),
                (STDOUT, b"longer than the bytes held back for a split marker " * 4),
            ],
            ends=False,
        )

        result = _handle(ws)

        assert result.stdout == "out"

    def test_waits_for_the_marker_on_both_streams(self, short_grace: None) -> None:
        """Stderr's tail can arrive after stdout's marker (#23), so wait for both."""
        ws = _FakeWSClient(
            [(STDOUT, _marker(0)), 0.1, (STDERR, b"late" + _marker(0))], ends=False
        )

        result = _handle(ws)

        assert result.stderr == "late"

    def test_output_over_the_limit_fails_without_waiting_for_more(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Only output that could still turn out to be the marker is held back."""
        monkeypatch.setattr(execute_module.limits, "MAX_EXEC_OUTPUT_SIZE", 8)
        ws = _FakeWSClient([(STDOUT, b"x" * 9)], ends=False)

        with pytest.raises(OutputLimitExceededError):
            _handle(ws)

    def test_success_without_the_markers_means_output_was_lost(self) -> None:
        """The shell writes both markers before it can exit 0."""
        ws = _FakeWSClient([(STDOUT, b"the start of the output"), _status(0)])

        with pytest.raises(ExecResultUnknownError, match="end of the command's output"):
            _handle(ws)

    def test_held_back_bytes_are_kept_when_the_stream_ends_without_a_marker(
        self,
    ) -> None:
        ws = _FakeWSClient([(STDOUT, b"out<completed-sen"), _status(1)])

        result = _handle(ws)

        assert result.stdout == "out<completed-sen"

    def test_held_back_bytes_count_against_the_output_limit(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(execute_module.limits, "MAX_EXEC_OUTPUT_SIZE", 8)
        ws = _FakeWSClient([(STDOUT, b"12345678<"), _status(1)])

        with pytest.raises(OutputLimitExceededError):
            _handle(ws)

    def test_a_stream_that_ends_without_a_marker_keeps_all_its_output(self) -> None:
        """E.g. `cd` failed, so the shell exited before the command ran."""
        ws = _FakeWSClient([(STDERR, b"sh: cd: can't cd to /nope"), _status(2)])

        result = _handle(ws)

        assert result.returncode == 2
        assert result.stderr == "sh: cd: can't cd to /nope"


_SHELLS = [
    pytest.param(shell, id=shell[0])
    for shell in (["sh"], ["bash"], ["dash"], ["busybox", "sh"])
    if shutil.which(shell[0])
]


def _run_script(shell: list[str], script: str) -> subprocess.CompletedProcess[bytes]:
    """Run an exec's script as the pod's shell gets it: stdin stays open after it."""
    read_end, write_end = os.pipe()
    os.write(write_end, script.encode())
    try:
        return subprocess.run(shell, stdin=read_end, capture_output=True, timeout=10)
    finally:
        os.close(read_end)
        os.close(write_end)


def _script(cmd: list[str], stdin: str | bytes | None = None) -> str:
    return ExecuteOperation(MagicMock())._build_shell_script(
        cmd, stdin, None, {}, None, MARKER
    )


@pytest.mark.skipif(os.name != "posix", reason="Requires a POSIX shell")
@pytest.mark.parametrize("shell", _SHELLS)
class TestScriptInAShell:
    def test_both_streams_end_with_the_marker(self, shell: list[str]) -> None:
        script = _script(["sh", "-c", "echo out; echo err >&2; exit 3"])

        result = _run_script(shell, script)

        assert result.returncode == 3
        assert result.stdout == b"out\n" + _marker(3)
        assert result.stderr == b"err\n" + _marker(3)

    @pytest.mark.parametrize(
        "stdin",
        [
            pytest.param(
                bytes(range(256)) * 2 + b"'%s%%\\0\\n\x001\n7", id="every-byte"
            ),
            pytest.param("caf\u00e9 'quoted' \"double\" %d \\\n\u03bb", id="text"),
            pytest.param("", id="empty"),
            pytest.param("-hello", id="leading-hyphen"),
            pytest.param("--", id="double-hyphen"),
            pytest.param("-n", id="option-like"),
        ],
    )
    def test_input_reaches_the_command_byte_for_byte(
        self, shell: list[str], stdin: str | bytes
    ) -> None:
        script = _script(["cat"], stdin)

        result = _run_script(shell, script)

        expected = stdin if isinstance(stdin, bytes) else stdin.encode()
        assert result.stdout == expected + _marker(0)

    @pytest.mark.parametrize(
        ("cmd", "returncode"),
        [(["exit", "0"], 0), (["exit", "3"], 3), (["exec", "true"], 0)],
    )
    def test_a_command_that_ends_its_shell_still_gets_the_markers(
        self, shell: list[str], cmd: list[str], returncode: int
    ) -> None:
        result = _run_script(shell, _script(cmd))

        assert result.returncode == returncode
        assert result.stdout == _marker(returncode)
        assert result.stderr == _marker(returncode)

    def test_a_callers_ifs_does_not_change_the_exit_code(
        self, shell: list[str]
    ) -> None:
        script = ExecuteOperation(MagicMock())._build_shell_script(
            ["sh", "-c", "exit 13"], None, None, {"IFS": "3"}, None, MARKER
        )

        result = _run_script(shell, script)

        assert result.returncode == 13

    def test_needs_no_sync(self, shell: list[str], tmp_path: Path) -> None:
        """Images no longer need `sync` (prerequisites.md)."""
        (tmp_path / "cat").symlink_to(shutil.which("cat") or "/bin/cat")
        (tmp_path / "file").write_text("output")
        script = _script(["cat", str(tmp_path / "file")])
        read_end, write_end = os.pipe()
        os.write(write_end, script.encode())

        try:
            result = subprocess.run(
                [shutil.which(shell[0]) or shell[0], *shell[1:]],
                stdin=read_end,
                capture_output=True,
                timeout=10,
                env={"PATH": str(tmp_path)},
            )
        finally:
            os.close(read_end)
            os.close(write_end)

        assert result.stdout == b"output" + _marker(0)
        assert result.stderr == _marker(0)

    def test_the_command_cannot_read_the_marker_from_stdin(
        self, shell: list[str]
    ) -> None:
        """Bash reads its script a byte at a time, so it must still read all of it."""
        echo_pending_stdin = (
            "import os, select\n"
            "if select.select([0], [], [], 0.5)[0]:\n"
            "    os.write(1, os.read(0, 65536))"
        )
        script = _script([sys.executable, "-c", echo_pending_stdin])

        result = _run_script(shell, script)

        assert result.stdout == _marker(0)


@pytest.mark.skipif(os.name != "posix", reason="Requires a POSIX shell")
@pytest.mark.parametrize("shell", _SHELLS)
def test_a_script_cut_short_runs_nothing(shell: list[str], tmp_path: Path) -> None:
    """A connection lost while sending the script leaves nothing run to repeat."""
    ran = tmp_path / "ran"
    script = ExecuteOperation(MagicMock())._build_shell_script(
        ["touch", str(ran)], None, str(tmp_path), {"K": "V"}, None, MARKER
    )
    # Cut after each line but the last, as a dropped connection might: the shell then
    # reads end of input.
    cuts = [i + 1 for i, char in enumerate(script[:-1]) if char == "\n"]

    for cut in cuts:
        result = subprocess.run(shell, input=script[:cut].encode(), capture_output=True)

        assert not ran.exists(), f"ran after a cut at {cut}: {script[:cut]!r}"
        assert result.stdout == b""


class TestBrokenPipeAfterMarkers:
    """The connection can drop after both markers but before the status arrives."""

    def test_broken_pipe_after_markers_with_timeout_raises_timeout_error(self) -> None:
        """Marker rc=124 with timeout: raise TimeoutError."""
        ws = _FakeWSClient(
            [(STDOUT, b"output" + _marker(124)), (STDERR, _marker(124))],
            error=BrokenPipeError("socket closed"),
        )

        with pytest.raises(TimeoutError):
            _handle(ws, timeout=30)

    @pytest.mark.parametrize(
        "error",
        [BrokenPipeError("socket closed"), ConnectionResetError("connection reset")],
    )
    def test_error_after_markers_returns_result(self, error: Exception) -> None:
        ws = _FakeWSClient(
            [(STDOUT, b"hello" + _marker(0)), (STDERR, _marker(0))], error=error
        )

        result = _handle(ws)

        assert result.returncode == 0
        assert result.stdout == "hello"
        assert result.stderr == ""


@pytest.fixture
def tls_sockets(
    tmp_path: Path,
) -> Generator[tuple[ssl.SSLSocket, ssl.SSLSocket], None, None]:
    """A client and a server socket with TLS between them."""
    if shutil.which("openssl") is None:
        pytest.skip("Needs openssl to make a certificate")
    key, cert = tmp_path / "key.pem", tmp_path / "cert.pem"
    subprocess.run(
        ["openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt"]
        + ["ec_paramgen_curve:prime256v1", "-nodes", "-days", "1", "-subj", "/CN=x"]
        + ["-keyout", str(key), "-out", str(cert)],
        check=True,
        capture_output=True,
    )
    server_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    server_context.load_cert_chain(cert, key)
    client_context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    client_context.check_hostname = False
    client_context.verify_mode = ssl.CERT_NONE
    a, b = socket.socketpair()
    server = server_context.wrap_socket(
        a, server_side=True, do_handshake_on_connect=False
    )
    client = client_context.wrap_socket(b, do_handshake_on_connect=False)
    handshake = threading.Thread(target=server.do_handshake)
    handshake.start()
    client.do_handshake()
    handshake.join()
    yield client, server
    server.close()
    client.close()


class _SocketWSClient(WSClient):
    """A WSClient on a real socket, with the client's own update() and its poll."""

    def __init__(self, sock: socket.socket) -> None:
        self._connected = True
        self._channels: dict[int, bytes] = {}
        self._closed_channels: set[int] = set()
        self._all = io.BytesIO()
        self.subprotocol = None
        self.binary = True
        self.sock = websocket.WebSocket()
        self.sock.sock = sock
        self.sock.connected = True


def _frame(channel: int, data: bytes) -> bytes:
    """A server's (unmasked) exec frame."""
    opcode = websocket.ABNF.OPCODE_BINARY
    return websocket.ABNF(1, 0, 0, 0, opcode, 0, bytes([channel]) + data).format()


def _close_frame() -> bytes:
    """The server closing the connection (status 1000, normal closure)."""
    opcode = websocket.ABNF.OPCODE_CLOSE
    return websocket.ABNF(1, 0, 0, 0, opcode, 0, b"\x03\xe8").format()


@contextmanager
def _sending(
    tls_sockets: tuple[ssl.SSLSocket, ssl.SSLSocket],
    records: Iterable[bytes],
    pause: float = 0,
) -> Generator[None, None, None]:
    """Send each of `records` as a TLS record of its own, from another thread."""
    client, server = tls_sockets
    stop = threading.Event()

    def send() -> None:
        try:
            for record in records:
                if stop.wait(pause):
                    return
                server.sendall(record)
        except OSError:
            pass  # The client stopped reading.

    thread = threading.Thread(target=send)
    thread.start()
    try:
        yield
    finally:
        stop.set()
        # Fails a read or a send still waiting, so that a failure can't hang the suite.
        client.shutdown(socket.SHUT_RDWR)
        client.close()
        thread.join()


def _straddling(first: bytes, frame: bytes, count: int) -> list[bytes]:
    """TLS records holding `first`, then `count` copies of `frame`.

    Each record ends one byte into the next frame, so TLS always holds part of one.
    """
    return [first + frame[:1]] + [frame[1:] + frame[:1]] * (count - 1) + [frame[1:]]


def test_frames_tls_has_already_decrypted_are_read(
    tls_sockets: tuple[ssl.SSLSocket, ssl.SSLSocket], short_grace: None
) -> None:
    """Both markers in one TLS record, then nothing: as a background process does."""
    client, server = tls_sockets
    server.sendall(_frame(STDOUT, b"out" + _marker(0)) + _frame(STDERR, _marker(0)))
    ws = _SocketWSClient(client)

    pool = concurrent.futures.ThreadPoolExecutor(1)
    reading = pool.submit(_handle, ws)
    try:
        result = reading.result(timeout=5)
    finally:
        # Wakes a read still waiting, so that a failure can't hang the suite.
        server.close()
        pool.shutdown()

    assert (result.returncode, result.stdout) == (0, "out")


def test_a_flood_of_output_is_checked_against_the_limit_frame_by_frame(
    tls_sockets: tuple[ssl.SSLSocket, ssl.SSLSocket], monkeypatch: pytest.MonkeyPatch
) -> None:
    """Output that never pauses, so TLS always holds more."""
    monkeypatch.setattr(execute_module.limits, "MAX_EXEC_OUTPUT_SIZE", 10_000)
    ws = _SocketWSClient(tls_sockets[0])
    frames_read = 0
    recv_data_frame = ws.sock.recv_data_frame

    def counting(control_frame: bool = False) -> tuple[int, websocket.ABNF]:
        nonlocal frames_read
        frames_read += 1
        return recv_data_frame(control_frame)

    monkeypatch.setattr(ws.sock, "recv_data_frame", counting)
    records = _straddling(b"", _frame(STDOUT, b"x" * 1000), 200)

    with _sending(tls_sockets, records):
        with pytest.raises(OutputLimitExceededError):
            _handle(ws)

    assert frames_read <= 12


def test_output_after_the_markers_does_not_hold_the_exec_open(
    tls_sockets: tuple[ssl.SSLSocket, ssl.SSLSocket], short_grace: None
) -> None:
    """A background process that keeps writing, so TLS always holds more."""
    markers = _frame(STDOUT, b"out" + _marker(0)) + _frame(STDERR, _marker(0))
    # For at least 3 seconds.
    records = _straddling(markers, _frame(STDOUT, b"late"), 3000)
    ws = _SocketWSClient(tls_sockets[0])
    pool = concurrent.futures.ThreadPoolExecutor(1)

    with _sending(tls_sockets, records, pause=0.001):
        start = time.monotonic()
        result = pool.submit(_handle, ws).result(timeout=10)
        elapsed = time.monotonic() - start
    pool.shutdown()

    assert (result.returncode, result.stdout) == (0, "out")
    assert elapsed < 1


def test_output_read_before_a_failed_close_reply_is_kept(
    tls_sockets: tuple[ssl.SSLSocket, ssl.SSLSocket],
) -> None:
    """All of it in one TLS record, and the server gone before the client replies."""
    client, server = tls_sockets
    server.sendall(
        _frame(STDOUT, b"out" + _marker(3))
        + _frame(STDERR, _marker(3))
        + _frame(*_status(3))
        + _close_frame()
    )
    server.close()

    result = _handle(_SocketWSClient(client))

    assert (result.returncode, result.stdout) == (3, "out")


def test_the_probe_reads_a_close_tls_has_already_decrypted(
    tls_sockets: tuple[ssl.SSLSocket, ssl.SSLSocket], monkeypatch: pytest.MonkeyPatch
) -> None:
    """The status and the close in one TLS record, and the server awaiting the reply."""
    monkeypatch.setattr(execute_module, "API_TIMEOUT", 2)
    client, server = tls_sockets
    server.sendall(_frame(*_status(1)) + _close_frame())
    op = ExecuteOperation(MagicMock())

    @contextmanager
    def shell(command: list[str]) -> Generator[WSClient, None, None]:
        yield _SocketWSClient(client)

    with patch.object(op, "_interactive_shell", shell):
        answer = op.probe_switch("agent")

    assert answer is True


class TestStatusReceivedBeforeTheConnectionWasLost:
    def test_the_status_is_used_without_markers(self) -> None:
        """E.g. `cd` failed, so the command never ran."""
        ws = _FakeWSClient([_status(2)], error=ConnectionResetError("reset"))

        result = _handle(ws)

        assert result.returncode == 2

    def test_the_status_wins_over_the_markers(self) -> None:
        ws = _FakeWSClient(
            [(STDOUT, _marker(0)), (STDERR, _marker(0)), _status(3)],
            error=ConnectionResetError("connection reset"),
        )

        result = _handle(ws)

        assert result.returncode == 3

    def test_output_read_by_an_update_that_then_failed_is_kept(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """As kubernetes 37's update() can: read every frame waiting, then fail."""
        ws = _FakeWSClient(
            [(STDOUT, b"out" + _marker(3)), (STDERR, _marker(3)), _status(3)],
            error=ConnectionResetError("connection reset"),
        )
        read_one = ws.update

        def read_all_then_fail(timeout: float | None = 0) -> None:
            while True:
                read_one(timeout)

        monkeypatch.setattr(ws, "update", read_all_then_fail)

        result = _handle(ws)

        assert (result.returncode, result.stdout) == (3, "out")


class TestResultLostAfterTheScriptWasSent:
    """Once the script is sent the command may run, so a lost result isn't retried."""

    @pytest.mark.parametrize(
        "error",
        [
            BrokenPipeError("socket closed"),
            ConnectionResetError("connection reset"),
            websocket.WebSocketConnectionClosedException("gone"),
            ssl.SSLEOFError("EOF occurred in violation of protocol"),
        ],
    )
    def test_connection_lost_before_the_markers(self, error: Exception) -> None:
        ws = _FakeWSClient([(STDOUT, b"partial")], error=error)

        with pytest.raises(ExecResultUnknownError, match="WebSocket connection lost"):
            _handle(ws)

    def test_connection_lost_between_the_markers(self) -> None:
        """Stderr may be missing its end, so stdout's marker alone isn't a result."""
        ws = _FakeWSClient(
            [(STDOUT, _marker(0)), (STDERR, b"part of stderr")],
            error=ConnectionResetError("connection reset"),
        )

        with pytest.raises(ExecResultUnknownError):
            _handle(ws)

    def test_exec_ending_without_a_status(self) -> None:
        """Still a GetReturncodeError, which callers (Hawk's VM-death report) match."""
        ws = _FakeWSClient([(STDOUT, b"partial")])

        with pytest.raises(GetReturncodeError) as raised:
            _handle(ws)

        assert isinstance(raised.value, ExecResultUnknownError)


class TestNonUtf8Output:
    """A command emitting non-UTF-8 bytes must not abort exec()."""

    def test_binary_byte_with_sentinel_in_same_frame(self) -> None:
        ws = _FakeWSClient(
            [(STDOUT, b"before \xbb after" + _marker(0)), (STDERR, _marker(0))]
            + [_status(0)]
        )

        result = _handle(ws)

        assert result.returncode == 0
        assert result.stdout == "before \ufffd after"

    def test_binary_byte_on_stderr(self) -> None:
        ws = _FakeWSClient(
            [(STDOUT, _marker(0)), (STDERR, b"warn \xbb done\n" + _marker(0))]
            + [_status(0)]
        )

        result = _handle(ws)

        assert result.returncode == 0
        assert result.stderr == "warn \ufffd done\n"

    def test_binary_byte_in_earlier_frame_than_sentinel(self) -> None:
        ws = _FakeWSClient(
            [(STDOUT, b"raw \xbb bytes"), (STDOUT, b"more" + _marker(0))]
            + [(STDERR, _marker(0)), _status(0)]
        )

        result = _handle(ws)

        assert result.returncode == 0
        assert result.stdout == "raw \ufffd bytesmore"


class TestRunuserErrors:
    def test_user_command_runuser_error_with_sentinel_returns_result(self) -> None:
        ws = _FakeWSClient(
            [
                (STDERR, b"runuser: user foo does not exist\n" + _marker(1)),
                (STDOUT, _marker(1)),
                _status(1),
            ]
        )

        result = _handle(ws, user="nobody")

        assert result.returncode == 1
        assert result.stderr == "runuser: user foo does not exist\n"

    def test_wrapper_runuser_error_without_sentinel_raises(self) -> None:
        stderr = b"runuser: user foo does not exist\n"
        ws = _FakeWSClient([(STDERR, stderr), _status(1)])

        with pytest.raises(RuntimeError, match="does not appear to exist"):
            _handle(ws, user="foo")

    def test_non_runuser_error_without_sentinel_returns_result(self) -> None:
        ws = _FakeWSClient([_status(1)])

        result = _handle(ws, user="foo")

        assert result.returncode == 1


class TestExecChunksStdin:
    def test_exec_writes_shell_script_in_chunks(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # Tiny chunk size (patched in op.py, where _write_stdin_chunked reads it)
        # plus stubbed shell creation + output handling, so only the write path runs.
        monkeypatch.setattr(op_module, "_STDIN_CHUNK_SIZE", 16)
        ws = MagicMock(spec=WSClient)

        @contextmanager
        def fake_interactive_shell(
            command: list[str],
        ) -> Generator[MagicMock, None, None]:
            yield ws

        op = ExecuteOperation(MagicMock())
        monkeypatch.setattr(op, "_interactive_shell", fake_interactive_shell)
        monkeypatch.setattr(
            execute_module.secrets, "token_hex", lambda n: MARKER.split("-")[-2]
        )
        sentinel = ExecResult(success=True, returncode=0, stdout="", stderr="")
        monkeypatch.setattr(op, "_handle_shell_output", lambda *a, **k: sentinel)

        # The assembled script (input + pipeline) is several hundred bytes,
        # well above the 16-byte chunk size, so it splits into many frames.
        result = op.exec(
            ["cat"], stdin=b"x" * 100, cwd=None, env={}, user=None, timeout=None
        )

        expected_script = op._build_shell_script(
            ["cat"], b"x" * 100, None, {}, None, MARKER
        )
        written = "".join(call.args[0] for call in ws.write_stdin.call_args_list)
        assert written == expected_script
        assert ws.write_stdin.call_count > 1
        assert all(len(c.args[0]) <= 16 for c in ws.write_stdin.call_args_list)
        assert result is sentinel


def _exec_writing_to(
    monkeypatch: pytest.MonkeyPatch, fails: Callable[[str], bool] = lambda data: False
) -> tuple[list[str], ExecuteOperation]:
    """An ExecuteOperation recording its stdin writes, which fail where `fails` says."""
    monkeypatch.setattr(op_module, "_STDIN_CHUNK_SIZE", 16)
    writes: list[str] = []
    ws = MagicMock(spec=WSClient)

    def write_stdin(data: str) -> None:
        writes.append(data)
        if fails(data):
            raise BrokenPipeError("socket closed")

    ws.write_stdin.side_effect = write_stdin

    @contextmanager
    def fake_interactive_shell(command: list[str]) -> Generator[MagicMock, None, None]:
        yield ws

    op = ExecuteOperation(MagicMock())
    monkeypatch.setattr(op, "_interactive_shell", fake_interactive_shell)
    done = ExecResult(success=True, returncode=0, stdout="", stderr="")
    monkeypatch.setattr(op, "_handle_shell_output", lambda *a, **k: done)
    return writes, op


class TestClosingLine:
    """A shell runs a { } group once it has the `}`, even if the newline never came."""

    def test_is_sent_whole_and_last(self, monkeypatch: pytest.MonkeyPatch) -> None:
        writes, op = _exec_writing_to(monkeypatch)

        op.exec(["cat"], stdin=b"x" * 100, cwd=None, env={}, user=None, timeout=None)

        assert writes[-1] == "}\n"
        assert "".join(writes).endswith('exit "$returncode"\n}\n')

    def test_a_failure_before_it_is_left_to_the_caller_to_retry(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        writes, op = _exec_writing_to(monkeypatch, fails=lambda data: data != "}\n")

        with pytest.raises(BrokenPipeError):
            op.exec(["cat"], stdin=None, cwd=None, env={}, user=None, timeout=None)

    def test_a_failure_sending_it_may_have_run_the_command(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Over plain ws://, the `}` alone can arrive from a frame cut off."""
        writes, op = _exec_writing_to(monkeypatch, fails=lambda data: data == "}\n")

        with pytest.raises(ExecResultUnknownError):
            op.exec(["cat"], stdin=None, cwd=None, env={}, user=None, timeout=None)


class TestFreshMarker:
    def test_each_exec_ends_its_output_with_a_new_marker(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        ws = MagicMock(spec=WSClient)

        @contextmanager
        def fake_interactive_shell(
            command: list[str],
        ) -> Generator[MagicMock, None, None]:
            yield ws

        op = ExecuteOperation(MagicMock())
        monkeypatch.setattr(op, "_interactive_shell", fake_interactive_shell)
        handled: list[str] = []
        done = ExecResult(success=True, returncode=0, stdout="", stderr="")

        def handle(ws: WSClient, user: object, timeout: object, marker: str) -> object:
            handled.append(marker)
            return done

        monkeypatch.setattr(op, "_handle_shell_output", handle)

        for _ in range(2):
            op.exec(["true"], stdin=None, cwd=None, env={}, user=None, timeout=None)

        scripts = "".join(c.args[0] for c in ws.write_stdin.call_args_list)
        assert handled[0] != handled[1]
        for marker in handled:
            assert re.fullmatch(r"<completed-sentinel-value-[0-9a-f]{32}-", marker)
        for marker in handled:
            assert scripts.count(f"printf '{marker}%d>'") == 2


class TestShellCommand:
    """`runuser` is only reached for when the container is not already that user."""

    def test_no_user_opens_a_plain_shell(self) -> None:
        assert _shell_command(None) == ["/bin/sh"]

    def test_user_falls_back_to_runuser(self) -> None:
        command = _shell_command("agent")

        assert command[:2] == ["/bin/sh", "-c"]
        assert "exec runuser -u agent -- /bin/sh" in command[2]

    def test_user_skips_runuser_when_already_that_user(self) -> None:
        """A no-op switch still needs CAP_SETGID, so avoid runuser when we can."""
        script = _shell_command("agent")[2]

        assert '[ "$(id -un 2>/dev/null)" = agent ]' in script
        assert "then exec /bin/sh; fi" in script

    def test_a_name_is_compared_against_the_name_and_a_uid_against_the_uid(
        self,
    ) -> None:
        """Cross-comparing would match an account *named* "0" against uid 0."""
        by_name = _shell_command("agent")[2]
        by_uid = _shell_command("1000")[2]

        assert "id -un" in by_name and "id -u " not in by_name
        assert '[ "$(id -u 2>/dev/null)" = 1000 ]' in by_uid
        assert "id -un" not in by_uid

    def test_a_probed_container_opens_the_shell_it_needs(self) -> None:
        """No check, and so two fewer process starts, once a probe has answered."""
        assert _shell_command("agent", switch=False) == ["/bin/sh"]
        assert _shell_command("agent", switch=True) == [
            "runuser",
            "-u",
            "agent",
            "--",
            "/bin/sh",
        ]

    def test_an_empty_user_is_left_to_runuser(self) -> None:
        """It matches nothing, and an empty `id` output must not look equal."""
        assert _shell_command("") == ["runuser", "-u", "", "--", "/bin/sh"]

    @pytest.mark.parametrize("user", ["a b", "a;rm -rf /", "$(whoami)", "'"])
    def test_user_is_quoted(self, user: str) -> None:
        """The user reaches two more shell words than it used to; quote all three."""
        script = _shell_command(user)[2]

        assert script.count(shlex.quote(user)) == 2
        assert user not in script.replace(shlex.quote(user), "")


def _probe_script(user: str) -> str:
    op = ExecuteOperation(MagicMock())
    commands: list[list[str]] = []

    @contextmanager
    def capture(command: list[str]) -> Generator[WSClient, None, None]:
        commands.append(command)
        yield _FakeWSClient([_status(0)])

    with patch.object(op, "_interactive_shell", capture):
        op.probe_switch(user)
    assert commands[0][:2] == ["/bin/sh", "-c"]
    return commands[0][2]


class TestProbeSwitch:
    @pytest.mark.parametrize(
        ("returncode", "switch"), [(0, False), (1, True), (2, None)]
    )
    def test_answer_comes_from_the_exit_status(
        self, returncode: int, switch: bool | None
    ) -> None:
        op = ExecuteOperation(MagicMock())

        @contextmanager
        def fake_shell(command: list[str]) -> Generator[WSClient, None, None]:
            yield _FakeWSClient([(STDOUT, b"0"), _status(returncode)])

        with patch.object(op, "_interactive_shell", fake_shell):
            answer = op.probe_switch("agent")

        assert answer is switch

    @pytest.mark.skipif(os.name != "posix", reason="Requires a POSIX shell")
    @pytest.mark.parametrize("shell", _SHELLS)
    @pytest.mark.parametrize(
        ("user", "runuser", "expected"),
        [
            pytest.param(
                pwd.getpwuid(os.getuid()).pw_name, None, 0, id="already-that-user"
            ),
            pytest.param(str(os.getuid()), None, 0, id="already-that-uid"),
            pytest.param("someone-else", "exit 0", 1, id="runuser-can-switch"),
            pytest.param("someone-else", "exit 1", 2, id="runuser-cannot-switch"),
            # A real runuser can't switch to a user that doesn't exist either.
            pytest.param("no-such-user-k8s-sandbox", None, 2, id="no-such-user"),
        ],
    )
    def test_probe_in_a_shell(
        self,
        shell: list[str],
        user: str,
        runuser: str | None,
        expected: int,
        tmp_path: Path,
    ) -> None:
        if runuser is not None:
            stub = tmp_path / "runuser"
            stub.write_text(f"#!/bin/sh\n{runuser}\n")
            stub.chmod(0o755)
        path = f"{tmp_path}:{os.environ['PATH']}"

        result = subprocess.run(
            [*shell, "-c", _probe_script(user)], env={**os.environ, "PATH": path}
        )

        assert result.returncode == expected


class TestProbeBounds:
    """A planted `id` or `runuser` can hold the probe's output open or flood it."""

    def test_gives_up_on_a_probe_that_never_ends(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(execute_module, "API_TIMEOUT", 0.05)
        op = ExecuteOperation(MagicMock())

        @contextmanager
        def fake_shell(command: list[str]) -> Generator[WSClient, None, None]:
            yield _FakeWSClient([(STDOUT, b"x")], ends=False)

        with patch.object(op, "_interactive_shell", fake_shell):
            with pytest.raises(PodError, match="timed out"):
                op.probe_switch("agent")

    def test_keeps_none_of_the_containers_output(self) -> None:
        op = ExecuteOperation(MagicMock())
        ws = _FakeWSClient([(STDOUT, b"x" * 100), (STDERR, b"y" * 100), _status(1)])

        @contextmanager
        def fake_shell(command: list[str]) -> Generator[WSClient, None, None]:
            yield ws

        with patch.object(op, "_interactive_shell", fake_shell):
            answer = op.probe_switch("agent")

        assert answer is True
        assert STDOUT not in ws._channels and STDERR not in ws._channels


class TestRunuserErrorMessages:
    @pytest.mark.parametrize(
        ("stderr", "expected"),
        [
            ("runuser: user agent does not exist", "does not appear to exist"),
        ],
    )
    def test_an_unknown_user_still_raises(self, stderr: str, expected: str) -> None:
        """The one case no fallback can rescue: the name simply isn't there."""
        executor = ExecuteOperation(MagicMock())

        with pytest.raises(RuntimeError, match=expected):
            executor._check_for_runuser_error(stderr, "agent")

    @pytest.mark.parametrize(
        "stderr",
        [
            "runuser: may not be used by non-root users",
            "runuser: cannot set groups: Operation not permitted",
            "/bin/sh: 1: exec: runuser: not found",
        ],
    )
    def test_environment_failures_warn_rather_than_raise(self, stderr: str) -> None:
        """inspect-ai probes with user="root" and falls back when it fails.

        All three describe an environment that cannot switch users, rather than a
        caller naming something that does not exist. Raising made the fallback
        unreachable, so a sandbox that is merely unable to switch could not run
        any task using the injected tools.
        """
        executor = ExecuteOperation(MagicMock())

        executor._check_for_runuser_error(stderr, "agent")  # does not raise

    @pytest.mark.parametrize(
        "stderr",
        [
            "ls: /nope: No such file",
            "newgrp: cannot set groups: Operation not permitted",
            "su: cannot set groups: Operation not permitted",
        ],
    )
    def test_unrelated_stderr_is_not_claimed_as_a_runuser_error(
        self, stderr: str
    ) -> None:
        executor = ExecuteOperation(MagicMock())

        executor._check_for_runuser_error(stderr, "agent")  # does not raise
