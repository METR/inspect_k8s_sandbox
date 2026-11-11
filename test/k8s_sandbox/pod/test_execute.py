import asyncio
import concurrent.futures
import contextlib
import contextvars
import io
import json
import logging
import os
import pwd
import re
import select
import shlex
import shutil
import socket
import ssl
import struct
import subprocess
import sys
import threading
import time
import types
from contextlib import contextmanager
from importlib.metadata import version
from pathlib import Path
from typing import AsyncIterator, Callable, Generator, Iterable, Sequence
from unittest.mock import MagicMock, patch

import anyio
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
from k8s_sandbox._pod.execute import ExecuteOperation, PodStdio, _shell_command
from k8s_sandbox._pod.executor import PodOpExecutor
from k8s_sandbox._pod.pod import Pod

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
        # No socket: nothing for _update to read, nothing to close.
        self.sock = types.SimpleNamespace(
            sock=None, close=lambda **kwargs: None, settimeout=lambda timeout: None
        )
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


def _run_script(
    shell: list[str], script: str, env: dict[str, str] | None = None
) -> subprocess.CompletedProcess[bytes]:
    """Run an exec's script as the pod's shell gets it: stdin stays open after it."""
    read_end, write_end = os.pipe()
    os.write(write_end, script.encode())
    try:
        return subprocess.run(
            shell, stdin=read_end, capture_output=True, timeout=30, env=env
        )
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

    def test_base64_and_timeout_are_not_found_through_the_path(
        self, shell: list[str], tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """They run as the container's user; the command still gets the PATH."""
        # The real ones stand in for /usr/bin and /bin: macOS has no /usr/bin/timeout.
        system = tmp_path / "system"
        stubs = tmp_path / "stubs"
        system.mkdir()
        stubs.mkdir()
        ran = tmp_path / "ran"
        for name in ("base64", "timeout"):
            real = shutil.which(name)
            if real is None:
                pytest.skip(f"Requires {name}")
            (system / name).symlink_to(real)
            stub = stubs / name
            stub.write_text(f"#!/bin/sh\necho {name} >> {ran}\n")
            stub.chmod(0o755)
        monkeypatch.setattr(execute_module, "SYSTEM_PATH", str(system))
        path = f"{stubs}:{os.environ['PATH']}"
        script = ExecuteOperation(MagicMock())._build_shell_script(
            ["sh", "-c", 'cat; printf %s "$PATH"'], "input", None, {}, 30, MARKER
        )

        result = _run_script(shell, script, env={**os.environ, "PATH": path})

        assert not ran.exists()
        assert result.stdout == f"input{path}".encode() + _marker(0)

    def test_printf_is_not_found_through_the_path(
        self, shell: list[str], tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Where the shell has no printf builtin: bash with its builtin turned off."""
        if shell[0] != "bash":
            pytest.skip("Needs bash, whose printf builtin can be turned off")
        system = tmp_path / "system"
        stubs = tmp_path / "stubs"
        system.mkdir()
        stubs.mkdir()
        ran = tmp_path / "ran"
        (system / "printf").symlink_to(shutil.which("printf") or "/usr/bin/printf")
        stub = stubs / "printf"
        stub.write_text(f"#!/bin/sh\necho printf >> {ran}\n")
        stub.chmod(0o755)
        monkeypatch.setattr(execute_module, "SYSTEM_PATH", str(system))
        script = "enable -n printf\n" + ExecuteOperation(
            MagicMock()
        )._build_shell_script(["true"], None, None, {}, None, MARKER)
        path = f"{stubs}:{os.environ['PATH']}"

        result = _run_script(shell, script, env={**os.environ, "PATH": path})

        assert not ran.exists()
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
    client, server = _tls(tmp_path, *socket.socketpair())
    yield client, server
    server.close()
    client.close()


def _tls(
    tmp_path: Path, server_socket: socket.socket, client_socket: socket.socket
) -> tuple[ssl.SSLSocket, ssl.SSLSocket]:
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
    server = server_context.wrap_socket(
        server_socket, server_side=True, do_handshake_on_connect=False
    )
    client = client_context.wrap_socket(client_socket, do_handshake_on_connect=False)
    handshake = threading.Thread(target=server.do_handshake)
    handshake.start()
    client.do_handshake()
    handshake.join()
    return client, server


def _keep_a_tls_error(tmp_path: Path, other: ssl.SSLSocket) -> bool:
    """Whether `other`, waiting for nothing, reports a system error left in the queue.

    OpenSSL keeps a reset connection's write error in its queue for this thread.
    """
    for _ in range(5):  # A write can find the reset still on its way.
        with socket.create_server(("127.0.0.1", 0)) as listener:
            client_socket = socket.create_connection(listener.getsockname())
            server_socket, _ = listener.accept()
        client, server = _tls(tmp_path, server_socket, client_socket)
        reset = socket.socket(fileno=server.detach())
        reset.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0))
        reset.close()
        with contextlib.suppress(OSError):
            client.recv(10)
        with contextlib.suppress(OSError):
            client.send(b"x")
        client.close()
        try:
            other.recv(10)
        except ssl.SSLWantReadError:
            continue
        except OSError:
            return True
    return False


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


@pytest.mark.skipif(
    int(version("kubernetes").split(".")[0]) >= 37,
    reason="kubernetes 37's update() reads every frame already waiting (#278)",
)
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


def test_a_frame_cut_off_after_the_markers_does_not_hold_the_exec_open(
    tls_sockets: tuple[ssl.SSLSocket, ssl.SSLSocket], short_grace: None
) -> None:
    """Part of a background process's frame, then the connection stalls."""
    client, server = tls_sockets
    markers = _frame(STDOUT, b"out" + _marker(0)) + _frame(STDERR, _marker(0))
    server.sendall(markers + _frame(STDOUT, b"late")[:3])
    pool = concurrent.futures.ThreadPoolExecutor(1)

    reading = pool.submit(_handle, _SocketWSClient(client))
    try:
        result = reading.result(timeout=5)
    finally:
        # Wakes a read still waiting, so that a failure can't hang the suite.
        server.close()
        pool.shutdown()

    assert (result.returncode, result.stdout) == (0, "out")


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


def test_the_socket_is_closed_after_the_server_closed_the_connection(
    tls_sockets: tuple[ssl.SSLSocket, ssl.SSLSocket],
) -> None:
    """Rather than when the garbage collector gets to it."""
    client, server = tls_sockets
    server.sendall(
        _frame(STDOUT, _marker(0))
        + _frame(STDERR, _marker(0))
        + _frame(*_status(0))
        + _close_frame()
    )
    op = ExecuteOperation(MagicMock())

    with (
        patch.object(op_module, "k8s_client"),
        patch.object(op_module, "stream", return_value=_SocketWSClient(client)),
    ):
        with op._interactive_shell(["/bin/sh"]) as ws:
            op._handle_shell_output(ws, None, None, MARKER)

    assert client.fileno() == -1


def test_the_probe_reads_a_status_tls_has_already_decrypted(
    tls_sockets: tuple[ssl.SSLSocket, ssl.SSLSocket], monkeypatch: pytest.MonkeyPatch
) -> None:
    """Output, the status and the close in one TLS record; the server awaits a reply."""
    monkeypatch.setattr(execute_module, "API_TIMEOUT", 2)
    client, server = tls_sockets
    server.sendall(_frame(STDOUT, b"x") + _frame(*_status(1)) + _close_frame())
    op = ExecuteOperation(MagicMock())

    @contextmanager
    def shell(command: list[str]) -> Generator[WSClient, None, None]:
        yield _SocketWSClient(client)

    with patch.object(op, "_interactive_shell", shell):
        answer = op.probe_switch("agent")

    assert answer is True


def test_the_probe_gives_up_on_a_frame_cut_off(
    tls_sockets: tuple[ssl.SSLSocket, ssl.SSLSocket], monkeypatch: pytest.MonkeyPatch
) -> None:
    """Part of the status frame, then the connection stalls."""
    monkeypatch.setattr(execute_module, "API_TIMEOUT", 0.5)
    client, server = tls_sockets
    server.sendall(_frame(*_status(1))[:5])
    op = ExecuteOperation(MagicMock())

    @contextmanager
    def shell(command: list[str]) -> Generator[WSClient, None, None]:
        yield _SocketWSClient(client)

    pool = concurrent.futures.ThreadPoolExecutor(1)
    with patch.object(op, "_interactive_shell", shell):
        probing = pool.submit(op.probe_switch, "agent")
        try:
            with pytest.raises(PodError, match="timed out"):
                probing.result(timeout=5)
        finally:
            # Wakes a read still waiting, so that a failure can't hang the suite.
            server.close()
            pool.shutdown()


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
        """Still a GetReturncodeError, so callers that match one still do."""
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
        monkeypatch.setattr(op_module, "STDIN_CHUNK_SIZE", 16)
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
    monkeypatch.setattr(op_module, "STDIN_CHUNK_SIZE", 16)
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
        assert "exec /sbin/runuser -u agent -- /bin/sh" in command[2]

    def test_user_skips_runuser_when_already_that_user(self) -> None:
        """A no-op switch still needs CAP_SETGID, so avoid runuser when we can."""
        script = _shell_command("agent")[2]

        assert '[ "$(PATH=/usr/bin:/bin; id -un 2>/dev/null)" = agent ]' in script
        assert "then exec /bin/sh; fi" in script

    def test_a_name_is_compared_against_the_name_and_a_uid_against_the_uid(
        self,
    ) -> None:
        """Cross-comparing would match an account *named* "0" against uid 0."""
        by_name = _shell_command("agent")[2]
        by_uid = _shell_command("1000")[2]

        assert "id -un" in by_name and "id -u " not in by_name
        assert '[ "$(PATH=/usr/bin:/bin; id -u 2>/dev/null)" = 1000 ]' in by_uid
        assert "id -un" not in by_uid

    def test_runuser_is_started_directly_once_a_probe_found_it_works(self) -> None:
        """No check, and so two fewer process starts."""
        assert _shell_command("agent", switch=True) == [
            "/sbin/runuser",
            "-u",
            "agent",
            "--",
            "/bin/sh",
        ]

    def test_otherwise_the_shell_checks_for_itself(self) -> None:
        """Even if the container ran as the user when probed.

        A plain shell in a pod replaced since would run as whoever the new one runs as.
        """
        assert _shell_command("agent", switch=False) == _shell_command("agent")
        assert _shell_command("agent")[:2] == ["/bin/sh", "-c"]

    def test_an_empty_user_is_left_to_runuser(self) -> None:
        """It matches nothing, and an empty `id` output must not look equal."""
        assert _shell_command("") == ["/sbin/runuser", "-u", "", "--", "/bin/sh"]

    @pytest.mark.skipif(os.name != "posix", reason="Requires a POSIX shell")
    @pytest.mark.parametrize("shell", _SHELLS)
    def test_id_and_runuser_are_not_found_through_the_path(
        self, shell: list[str], tmp_path: Path
    ) -> None:
        """They run as the container's user, before the switch."""
        ran = tmp_path / "ran"
        for name in ("id", "runuser"):
            stub = tmp_path / name
            stub.write_text(f"#!/bin/sh\necho {name} >> {ran}\n")
            stub.chmod(0o755)
        env = {**os.environ, "PATH": f"{tmp_path}:{os.environ['PATH']}"}

        user = "someone-else"
        for script in (_shell_command(user)[2], _probe_script(user)):
            subprocess.run(
                [*shell, "-c", script],
                env=env,
                stdin=subprocess.DEVNULL,
                capture_output=True,
                timeout=30,
            )

        assert not ran.exists()

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
    @pytest.mark.skipif(os.name != "posix", reason="Requires a POSIX shell")
    @pytest.mark.parametrize("shell", _SHELLS)
    def test_the_probe_runs_nothing_from_the_path_once_switched(
        self, shell: list[str], tmp_path: Path
    ) -> None:
        """The user may be uid 0 by another name, and runuser may keep the PATH."""
        ran = tmp_path / "ran"
        stub = tmp_path / "true"
        stub.write_text(f"#!/bin/sh\necho true >> {ran}\n")
        stub.chmod(0o755)
        forward = tmp_path / "forward"  # runuser without the switch
        forward.write_text(
            '#!/bin/sh\nwhile [ "$1" != -- ]; do shift; done\nshift\nexec "$@"\n'
        )
        forward.chmod(0o755)
        script = _probe_script("someone-else").replace("/sbin/runuser", str(forward))
        env = {**os.environ, "PATH": f"{tmp_path}:{os.environ['PATH']}"}

        result = subprocess.run(
            [*shell, "-c", script], env=env, capture_output=True, timeout=30
        )

        assert result.returncode == 1  # the switch works
        assert not ran.exists()

    @pytest.mark.parametrize(
        ("returncode", "switch"), [(0, False), (1, True), (2, False)]
    )
    def test_answer_comes_from_the_exit_status(
        self, returncode: int, switch: bool
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
        script = _probe_script(user)
        if runuser is not None:
            stub = tmp_path / "runuser"
            stub.write_text(f"#!/bin/sh\n{runuser}\n")
            stub.chmod(0o755)
            script = script.replace("/sbin/runuser", str(stub))

        result = subprocess.run([*shell, "-c", script])

        assert result.returncode == expected


class TestProbeBounds:
    """A misbehaving `id` or `runuser` can hold the probe's output open or flood it."""

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

    def test_a_status_received_before_the_connection_was_lost_answers(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """As kubernetes 37's update() can: read the status, then fail.

        E.g. replying to the server's close after it has gone.
        """
        op = ExecuteOperation(MagicMock())
        ws = _FakeWSClient([_status(1)], error=BrokenPipeError("gone"))
        read_one = ws.update

        def read_all_then_fail(timeout: float | None = 0) -> None:
            while True:
                read_one(timeout)

        monkeypatch.setattr(ws, "update", read_all_then_fail)

        @contextmanager
        def fake_shell(command: list[str]) -> Generator[WSClient, None, None]:
            yield ws

        with patch.object(op, "_interactive_shell", fake_shell):
            answer = op.probe_switch("agent")

        assert answer is True

    def test_answers_without_waiting_for_the_server_to_close(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(execute_module, "API_TIMEOUT", 0.5)
        op = ExecuteOperation(MagicMock())

        @contextmanager
        def fake_shell(command: list[str]) -> Generator[WSClient, None, None]:
            yield _FakeWSClient([_status(1)], ends=False)

        with patch.object(op, "_interactive_shell", fake_shell):
            answer = op.probe_switch("agent")

        assert answer is True

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
            "/bin/sh: 1: exec: /sbin/runuser: not found",  # dash
            "/bin/sh: exec: line 0: /sbin/runuser: not found",  # busybox
            "/bin/sh: line 1: /sbin/runuser: No such file or directory",  # bash
        ],
    )
    def test_a_missing_runuser_is_named(
        self, stderr: str, caplog: pytest.LogCaptureFixture
    ) -> None:
        executor = ExecuteOperation(MagicMock())

        executor._check_for_runuser_error(stderr, "agent")

        assert "runuser binary" in caplog.text

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


def _stdio(client: ssl.SSLSocket) -> PodStdio:
    """A stream on `client`, opened as Pod.exec_stdio() opens one."""
    op = ExecuteOperation(MagicMock())
    with (
        patch.object(op_module, "k8s_client", autospec=True),
        patch.object(
            op_module, "stream", autospec=True, return_value=_SocketWSClient(client)
        ),
    ):
        stack, ws = op.open_stdio(["inspect-sandbox-tools", "bridge"], None)
    return PodStdio(stack, ws)


def _reader(server: ssl.SSLSocket) -> websocket.WebSocket:
    """Reads the client's (masked) frames on the server's side."""
    server.settimeout(30)
    ws = websocket.WebSocket()
    ws.sock = server
    ws.connected = True
    return ws


async def _send_in_progress(
    stream: PodStdio, server: ssl.SSLSocket
) -> asyncio.Task[None]:
    """A send more than the socket buffers hold, once its first bytes are out."""
    sending = asyncio.create_task(stream.send(b"x" * 64 * 1024**2))
    await _wait_for(lambda: bool(select.select([server], [], [], 0)[0]))
    return sending


async def _wait_for(condition: Callable[[], bool]) -> None:
    with anyio.fail_after(30):
        while not condition():
            await anyio.sleep(0.01)


class TestExecStdio:
    async def test_the_command_runs_as_the_user_with_stdin_unread(
        self, tls_sockets: tuple[ssl.SSLSocket, ssl.SSLSocket]
    ) -> None:
        """From argv, through the user switch exec() uses: nothing reads stdin first."""
        client, server = tls_sockets
        op = ExecuteOperation(MagicMock())
        with (
            patch.object(op_module, "k8s_client", autospec=True),
            patch.object(
                op_module, "stream", autospec=True, return_value=_SocketWSClient(client)
            ) as stream,
        ):
            stack, ws = op.open_stdio(["printf", "%s\n", "a b"], "agent")
        stdio = PodStdio(stack, ws)
        with anyio.fail_after(30):
            await stdio.send(b"a request\n")
        _, first = _reader(server).recv_data_frame(True)
        await stdio.aclose()

        assert stream.call_args.kwargs["command"] == [
            "/bin/sh",
            "-c",
            'if [ "$(PATH=/usr/bin:/bin; id -un 2>/dev/null)" = agent ]; '
            "then exec printf '%s\n' 'a b'; fi; "
            "exec /sbin/runuser -u agent -- printf '%s\n' 'a b'",
        ]
        assert first.data == b"\x00a request\n"

    async def test_the_stream_is_stdout_until_the_exec_ends(
        self, tls_sockets: tuple[ssl.SSLSocket, ssl.SSLSocket]
    ) -> None:
        """Frames TLS has already decrypted included, stderr left out."""
        client, server = tls_sockets
        stream = _stdio(client)
        server.sendall(
            _frame(STDOUT, b"ready\n")
            + _frame(STDERR, b"a warning")
            + _frame(STDOUT, b"a reply\n")
            + _frame(*_status(0))
            + _close_frame()
        )

        with anyio.fail_after(30):
            received = [piece async for piece in _receiving(stream, max_bytes=4)]
        await _wait_for(lambda: client.fileno() == -1)

        assert b"".join(received) == b"ready\na reply\n"
        assert max(len(piece) for piece in received) == 4

    async def test_a_lost_connection_breaks_the_stream(
        self, tls_sockets: tuple[ssl.SSLSocket, ssl.SSLSocket]
    ) -> None:
        client, server = tls_sockets
        stream = _stdio(client)
        server.sendall(_frame(STDOUT, b"a reply\n"))
        server.close()

        with anyio.fail_after(30):
            reply = await stream.receive()
            with pytest.raises(anyio.BrokenResourceError) as broken:
                await stream.receive()

        assert reply == b"a reply\n"
        assert str(broken.value)  # Names what broke it, for the host's log.

    async def test_sent_bytes_reach_the_command_s_stdin(
        self, tls_sockets: tuple[ssl.SSLSocket, ssl.SSLSocket]
    ) -> None:
        client, server = tls_sockets
        stream = _stdio(client)
        reader = _reader(server)
        request = bytes(range(256)) + b"\n"

        with anyio.fail_after(30):
            await stream.send(request)
        _, frame = reader.recv_data_frame(True)
        await stream.aclose()

        assert frame.data == b"\x00" + request

    async def test_a_large_send_goes_out_in_frames_the_api_server_takes(
        self, tls_sockets: tuple[ssl.SSLSocket, ssl.SSLSocket]
    ) -> None:
        """Single frames of tens of MiB make the API server reset the connection."""
        client, server = tls_sockets
        stream = _stdio(client)
        reader = _reader(server)
        request = os.urandom(op_module.STDIN_CHUNK_SIZE * 2 + 1)
        frames: list[bytes] = []

        def read() -> None:
            while sum(len(frame) - 1 for frame in frames) < len(request):
                frames.append(reader.recv_data_frame(True)[1].data)

        reading = threading.Thread(target=read)
        reading.start()
        with anyio.fail_after(30):
            await stream.send(request)
        reading.join(30)
        await stream.aclose()

        assert b"".join(frame[1:] for frame in frames) == request
        assert [len(frame) - 1 for frame in frames] == [
            op_module.STDIN_CHUNK_SIZE,
            op_module.STDIN_CHUNK_SIZE,
            1,
        ]

    async def test_the_stream_sends_no_resize_keepalive(
        self, tls_sockets: tuple[ssl.SSLSocket, ssl.SSLSocket]
    ) -> None:
        """CRI-O does not drain resize events for an exec without a TTY.

        They would stall the stream's stdin.
        """
        before = set(threading.enumerate())
        stream = _stdio(tls_sockets[0])
        started = [
            thread
            for thread in threading.enumerate()
            if thread not in before and thread.name == "ws-keepalive"
        ]
        await stream.aclose()

        assert started == []

    async def test_a_command_that_fails_to_start_is_logged(
        self,
        tls_sockets: tuple[ssl.SSLSocket, ssl.SSLSocket],
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        """Its caller sees only the stream end, and closes the stream on it.

        Logged in the caller's context, where Inspect finds the sample's log.
        """
        sample = contextvars.ContextVar[str | None]("sample", default=None)
        sample.set("this sample")

        class NoteSample(logging.Filter):
            def filter(self, record: logging.LogRecord) -> bool:
                record.sample = sample.get()
                return True

        client, server = tls_sockets
        stream = _stdio(client)
        server.sendall(
            _frame(STDOUT, b"")  # Every exec opens with one.
            + _frame(STDERR, b"sh: 1: exec: inspect-sandbox-tools: not found\n")
            + _frame(*_status(127))
            + _close_frame()
        )

        with (
            caplog.filtering(NoteSample()),
            anyio.fail_after(30),
            pytest.raises(anyio.EndOfStream),
        ):
            await stream.receive()
        await stream.aclose()

        warning = caplog.records[-1]
        assert (warning.levelname, getattr(warning, "sample")) == (
            "WARNING",
            "this sample",
        )
        assert "127" in warning.getMessage()  # The exec's status.
        assert "inspect-sandbox-tools: not found" in warning.getMessage()

    async def test_a_stream_closed_before_any_output_logs_no_failure(
        self,
        tls_sockets: tuple[ssl.SSLSocket, ssl.SSLSocket],
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        """As when the pod check after the open fails, or the host stops waiting."""
        client, _ = tls_sockets
        stream = _stdio(client)

        await stream.aclose()
        await _wait_for(lambda: client.fileno() == -1)

        assert [r for r in caplog.records if r.levelname == "WARNING"] == []

    async def test_a_receive_cancelled_as_stdout_arrives_loses_nothing(
        self, tls_sockets: tuple[ssl.SSLSocket, ssl.SSLSocket]
    ) -> None:
        """By Task.cancel(), which a memory stream's own receive() loses data to."""
        client, server = tls_sockets
        stream = _stdio(client)
        receiving = asyncio.create_task(stream.receive())
        await anyio.wait_all_tasks_blocked()  # It now waits for stdout.
        server.sendall(_frame(STDOUT, b"a reply\n"))
        select.select([client], [], [], 30)  # Its wait is over, but it has not run.

        receiving.cancel()
        with pytest.raises(asyncio.CancelledError):
            await receiving
        with anyio.fail_after(30):
            reply = await stream.receive()
        await stream.aclose()

        assert reply == b"a reply\n"

    async def test_a_flood_of_stdout_does_not_hold_the_event_loop(
        self, tls_sockets: tuple[ssl.SSLSocket, ssl.SSLSocket]
    ) -> None:
        """Reads of it let other tasks run, which can cancel them: losing nothing."""
        client, server = tls_sockets
        client.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 1024**2)
        server.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 1024**2)
        flood = b"".join(_frame(STDOUT, b"x") for _ in range(1000))
        server.sendall(flood + _frame(*_status(0)))
        stream = _stdio(client)
        received = b""

        async def read_all() -> None:
            nonlocal received
            while len(received) < 1000:
                received += await stream.receive()

        async def cancel(scope: anyio.CancelScope) -> None:
            scope.cancel()

        with anyio.fail_after(30):
            async with anyio.create_task_group() as tasks:
                tasks.start_soon(read_all)
                tasks.start_soon(cancel, tasks.cancel_scope)
            cancelled_at = len(received)
            rest = b"".join([piece async for piece in _receiving(stream, 65536)])

        assert cancelled_at < 1000  # Cancelled mid-flood.
        assert received + rest == b"x" * 1000

    async def test_a_large_reply_costs_a_busy_event_loop_few_turns(
        self, tls_sockets: tuple[ssl.SSLSocket, ssl.SSLSocket]
    ) -> None:
        """A turn for every receive() made 48 MiB take minutes under load on staging."""
        client, server = tls_sockets
        client.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 1024**2)
        server.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 1024**2)
        server.sendall(b"".join(_frame(STDOUT, b"x") for _ in range(640)))
        stream = _stdio(client)
        turns = 0

        async def other_task() -> None:
            nonlocal turns
            while True:
                turns += 1
                await anyio.lowlevel.checkpoint()

        received = b""
        with anyio.fail_after(30):
            async with anyio.create_task_group() as tasks:
                tasks.start_soon(other_task)
                while len(received) < 640:
                    received += await stream.receive()
                tasks.cancel_scope.cancel()
        await stream.aclose()

        assert turns < 160

    async def test_a_send_with_room_takes_no_turn_of_the_event_loop(
        self, tls_sockets: tuple[ssl.SSLSocket, ssl.SSLSocket]
    ) -> None:
        """Each turn of a busy loop is a burst of other work: a request waits for it."""
        stream = _stdio(tls_sockets[0])
        turns = 0

        async def other_task() -> None:
            nonlocal turns
            turns += 1

        with anyio.fail_after(30):
            async with anyio.create_task_group() as tasks:
                tasks.start_soon(other_task)
                await stream.send(b"a request\n")
                sent_with = turns
        await stream.aclose()

        assert sent_with == 0

    async def test_a_receive_cancelled_at_any_step_loses_nothing(
        self, tls_sockets: tuple[ssl.SSLSocket, ssl.SSLSocket]
    ) -> None:
        """A Task.cancel() can land before it runs, or once it has (it ends in one)."""
        client, server = tls_sockets
        stream = _stdio(client)
        for steps in range(2):
            line = b"reply %d\n" % steps
            server.sendall(_frame(STDOUT, line))
            await _wait_for(lambda: bool(select.select([client], [], [], 0)[0]))
            receiving = asyncio.create_task(stream.receive())
            for _ in range(steps):
                await asyncio.sleep(0)  # It runs that many steps.

            receiving.cancel()
            received = b""
            with contextlib.suppress(asyncio.CancelledError):
                received = await receiving
            with anyio.fail_after(30):
                while not received.endswith(b"\n"):
                    received += await stream.receive()

            assert received == line
        await stream.aclose()

    async def test_a_receive_cancelled_as_it_lets_others_run_loses_nothing(
        self, tls_sockets: tuple[ssl.SSLSocket, ssl.SSLSocket]
    ) -> None:
        """Where a turn ends: here the call and its frames end one with stdout read."""
        client, server = tls_sockets
        stream = _stdio(client)
        frames = execute_module._STEPS_PER_TURN - 2
        stderr = b"".join(_frame(STDERR, b"x") for _ in range(frames))
        server.sendall(stderr + _frame(STDOUT, b"a reply\n"))
        await _wait_for(lambda: bool(select.select([client], [], [], 0)[0]))
        receiving = asyncio.create_task(stream.receive())
        await asyncio.sleep(0)  # It reads to the turn's end, and lets others run.

        receiving.cancel()
        received = b""
        with contextlib.suppress(asyncio.CancelledError):
            received = await receiving
        with anyio.fail_after(30):
            while not received.endswith(b"\n"):
                received += await stream.receive()
        await stream.aclose()

        assert received == b"a reply\n"

    async def test_a_receive_in_a_task_already_cancelled_takes_nothing(
        self, tls_sockets: tuple[ssl.SSLSocket, ssl.SSLSocket]
    ) -> None:
        """By a bare Task.cancel(), which anyio's own check for cancellation misses."""
        client, server = tls_sockets
        stream = _stdio(client)
        server.sendall(_frame(STDOUT, b"a reply\n"))
        await _wait_for(lambda: bool(select.select([client], [], [], 0)[0]))

        async def cancelled_receive() -> bytes:
            task = asyncio.current_task()
            assert task is not None
            task.cancel()
            return await stream.receive()

        with pytest.raises(asyncio.CancelledError):
            await asyncio.create_task(cancelled_receive())
        server.sendall(_frame(STDOUT, b"another\n"))
        with anyio.fail_after(30):
            reply = await stream.receive()
        await stream.aclose()

        assert reply == b"a reply\n"

    async def test_a_send_in_a_task_already_cancelled_sends_nothing(
        self, tls_sockets: tuple[ssl.SSLSocket, ssl.SSLSocket]
    ) -> None:
        """By a bare Task.cancel(): a frame cut short would have closed the stream."""
        client, server = tls_sockets
        stream = _stdio(client)

        async def cancelled_send() -> None:
            task = asyncio.current_task()
            assert task is not None
            task.cancel()
            await stream.send(b"x" * 64 * 1024**2)

        with pytest.raises(asyncio.CancelledError):
            await asyncio.create_task(cancelled_send())
        await stream.send(b"a request\n")
        first = _reader(server).recv_data_frame(True)[1].data
        await stream.aclose()

        assert first == b"\0a request\n"

    async def test_a_send_cancelled_as_it_is_handed_the_lock_sends_nothing(
        self, tls_sockets: tuple[ssl.SSLSocket, ssl.SSLSocket]
    ) -> None:
        """A frame cut short would have closed the stream for the sends after it."""
        client, server = tls_sockets
        stream = _stdio(client)
        reader = _reader(server)
        frames: list[bytes] = []
        second = anyio.CancelScope()

        def read() -> None:
            while not frames or frames[-1] != b"\0after\n":
                frames.append(reader.recv_data_frame(True)[1].data)

        async def first() -> None:
            await stream.send(b"a" * 3 * 1024**2)
            second.cancel()  # the lock is the second send's now, which has not run

        async def then() -> None:
            with second:
                await stream.send(b"b" * 3 * 1024**2)

        reading = threading.Thread(target=read)
        with anyio.fail_after(30):
            async with anyio.create_task_group() as tasks:
                tasks.start_soon(first)
                tasks.start_soon(then)
                await anyio.wait_all_tasks_blocked()  # the first stopped partway
                reading.start()
            await stream.send(b"after\n")
        reading.join(30)
        await stream.aclose()

        assert [set(frame[1:]) for frame in frames[:-1]] == [{97}] * 3

    async def test_receives_in_a_cancelled_tasks_shielded_cleanup_take_few_turns(
        self, tls_sockets: tuple[ssl.SSLSocket, ssl.SSLSocket]
    ) -> None:
        """As exec_remote's kill of a cancelled command reads its reply."""
        client, server = tls_sockets
        server.sendall(_frame(STDOUT, b"x" * 64 * 64))
        stream = _stdio(client)
        turns = 0
        received = b""

        async def other_task() -> None:
            nonlocal turns
            while True:
                turns += 1
                await anyio.lowlevel.checkpoint()

        with anyio.fail_after(30):
            async with anyio.create_task_group() as tasks:
                tasks.start_soon(other_task)
                with anyio.CancelScope() as cancelled:
                    cancelled.cancel()
                    try:
                        await anyio.sleep_forever()
                    finally:
                        with anyio.CancelScope(shield=True):
                            before = turns
                            while len(received) < 64 * 64:
                                received += await stream.receive(64)
                            during = turns - before
                tasks.cancel_scope.cancel()
        await stream.aclose()

        assert during < 16

    @pytest.mark.parametrize("max_bytes", [0, -1])
    async def test_receiving_nothing_is_refused(
        self, tls_sockets: tuple[ssl.SSLSocket, ssl.SSLSocket], max_bytes: int
    ) -> None:
        """As anyio's streams refuse it: b"" would read as the end of the stream."""
        client, server = tls_sockets
        stream = _stdio(client)
        server.sendall(_frame(STDOUT, b"a reply\n"))

        with anyio.fail_after(30), pytest.raises(ValueError):
            await stream.receive(max_bytes)
        await stream.aclose()

    async def test_stdout_read_before_the_stream_broke_is_kept(
        self, tls_sockets: tuple[ssl.SSLSocket, ssl.SSLSocket]
    ) -> None:
        client, server = tls_sockets
        stream = _stdio(client)
        server.sendall(_frame(STDOUT, b"a reply\n"))
        with anyio.fail_after(30):
            first = await stream.receive(2)  # The rest of the frame stays read.
        server.close()

        with anyio.fail_after(30), pytest.raises(anyio.BrokenResourceError):
            while True:
                await stream.send(b"a request\n")
        with anyio.fail_after(30):
            rest = await stream.receive()
            with pytest.raises(anyio.BrokenResourceError):
                await stream.receive()

        assert first + rest == b"a reply\n"

    async def test_a_closed_stream_gives_nothing_it_had_read(
        self, tls_sockets: tuple[ssl.SSLSocket, ssl.SSLSocket]
    ) -> None:
        client, server = tls_sockets
        stream = _stdio(client)
        server.sendall(_frame(STDOUT, b"a reply\n"))
        with anyio.fail_after(30):
            first = await stream.receive(2)  # The rest of the frame stays read.

        await stream.aclose()

        assert first == b"a "
        with pytest.raises(anyio.ClosedResourceError):
            await stream.receive()

    async def test_sends_at_once_go_out_one_after_the_other(
        self, tls_sockets: tuple[ssl.SSLSocket, ssl.SSLSocket]
    ) -> None:
        """Frames larger than the socket buffers, so that each send waits partway."""
        client, server = tls_sockets
        stream = _stdio(client)
        reader = _reader(server)
        requests = [b"a" * 3 * 1024**2, b"b" * 3 * 1024**2]
        frames: list[bytes] = []

        def read() -> None:
            while sum(len(frame) - 1 for frame in frames) < 6 * 1024**2:
                frames.append(reader.recv_data_frame(True)[1].data)

        reading = threading.Thread(target=read)
        with anyio.fail_after(30):
            async with anyio.create_task_group() as tasks:
                for request in requests:
                    tasks.start_soon(stream.send, request)
                # Nothing is read until both sends are under way: the first stops
                # partway, and the second either waits its turn or writes too.
                await anyio.wait_all_tasks_blocked()
                reading.start()
        reading.join(30)
        await stream.aclose()

        # The first send's frames all go out before the second's.
        assert [set(frame[1:]) for frame in frames] == [{97}] * 3 + [{98}] * 3

    async def test_closing_fails_a_send_the_server_is_not_reading(
        self, tls_sockets: tuple[ssl.SSLSocket, ssl.SSLSocket]
    ) -> None:
        client, server = tls_sockets
        stream = _stdio(client)
        sending = await _send_in_progress(stream, server)

        await stream.aclose()

        with anyio.fail_after(30), pytest.raises(anyio.ClosedResourceError):
            await sending
        assert client.fileno() == -1

    async def test_the_stream_ends_with_the_exec_while_a_send_is_stuck(
        self, tls_sockets: tuple[ssl.SSLSocket, ssl.SSLSocket]
    ) -> None:
        """The pod no longer reads stdin: the send waits for room that never comes."""
        client, server = tls_sockets
        stream = _stdio(client)
        sending = await _send_in_progress(stream, server)

        server.sendall(_frame(*_status(1)) + _close_frame())

        with anyio.fail_after(30):
            with pytest.raises(anyio.EndOfStream):
                await stream.receive()
            with pytest.raises(anyio.BrokenResourceError):
                await sending

    async def test_an_open_whose_caller_stopped_waiting_is_closed(
        self,
        tls_sockets: tuple[ssl.SSLSocket, ssl.SSLSocket],
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """By the open's own close, not the garbage collector's.

        That can run late, and on the event loop, which the close blocks for seconds.
        """
        client, _ = tls_sockets
        opening, release = threading.Event(), threading.Event()
        closed = threading.Event()

        class Shell:
            """A shell the garbage collector never closes, unlike a generator."""

            def __enter__(self) -> WSClient:
                opening.set()
                release.wait(30)
                return _SocketWSClient(client)

            def __exit__(self, *exc_info: object) -> None:
                closed.set()

        monkeypatch.setattr(PodOpExecutor, "_instance", None)  # A pool of its own.
        pod = Pod("pod", "ns", None, "default", "uid", 0, "raise")
        with patch.object(
            ExecuteOperation, "_interactive_shell", lambda *_, **__: Shell()
        ):
            starting = asyncio.create_task(pod.exec_stdio(["cat"], None))
            await _wait_for(opening.is_set)
            starting.cancel()
            with pytest.raises(asyncio.CancelledError):
                await starting
            release.set()

            await _wait_for(closed.is_set)

    async def test_a_plain_socket_s_reads_wait_like_tls_ones(self) -> None:
        """For an API server without TLS, whose socket says so with BlockingIOError."""
        client, server = socket.socketpair()
        stream = PodStdio(contextlib.ExitStack(), _SocketWSClient(client))
        receiving = asyncio.create_task(stream.receive())
        await anyio.wait_all_tasks_blocked()  # It now waits for stdout.

        server.sendall(_frame(STDOUT, b"a reply\n"))
        with anyio.fail_after(30):
            reply = await receiving
        server.close()
        with anyio.fail_after(30), pytest.raises(anyio.BrokenResourceError):
            await stream.receive()

        assert reply == b"a reply\n"

    async def test_a_cancelled_send_closes_the_stream(
        self, tls_sockets: tuple[ssl.SSLSocket, ssl.SSLSocket]
    ) -> None:
        """A frame cut short would corrupt any later one."""
        client, server = tls_sockets
        stream = _stdio(client)
        sending = await _send_in_progress(stream, server)

        sending.cancel()  # As Task.cancel() can, which no shield stops.
        with anyio.fail_after(30), pytest.raises(asyncio.CancelledError):
            await sending

        with anyio.fail_after(30), pytest.raises(anyio.ClosedResourceError):
            await stream.receive()
        await _wait_for(lambda: client.fileno() == -1)

    async def test_the_stream_ends_at_the_exec_s_status(
        self, tls_sockets: tuple[ssl.SSLSocket, ssl.SSLSocket]
    ) -> None:
        """Not at the server's close, which can come later."""
        client, server = tls_sockets
        stream = _stdio(client)
        server.sendall(_frame(STDOUT, b"a reply\n") + _frame(*_status(0)))

        with anyio.fail_after(30):
            received = [piece async for piece in _receiving(stream, 65536)]

        assert received == [b"a reply\n"]
        assert client.fileno() == -1

    async def test_a_stream_s_end_leaves_other_tls_connections_working(
        self, tls_sockets: tuple[ssl.SSLSocket, ssl.SSLSocket], tmp_path: Path
    ) -> None:
        """On the event loop, which a runner's other TLS connections share.

        CPython raises a TLS read or write's system error (EPIPE, say) without clearing
        it from OpenSSL's queue for the thread, and OpenSSL 3.5 then reports it for the
        thread's next TLS call that would wait. A stream's read left one on staging.
        """
        client, _ = tls_sockets
        stream = _stdio(client)
        other, _peer = _tls(tmp_path, *socket.socketpair())
        other.setblocking(False)
        if not _keep_a_tls_error(tmp_path, other):
            pytest.skip("This OpenSSL keeps no system error for the thread")

        await stream.aclose()

        with pytest.raises(ssl.SSLWantReadError):
            other.recv(10)

    async def test_small_reads_of_one_frame_let_other_tasks_run(
        self, tls_sockets: tuple[ssl.SSLSocket, ssl.SSLSocket]
    ) -> None:
        client, server = tls_sockets
        server.sendall(_frame(STDOUT, b"x" * 4096))
        stream = _stdio(client)
        turns = 0

        async def other_task() -> None:
            nonlocal turns
            while True:
                turns += 1
                await anyio.lowlevel.checkpoint()

        received = b""
        with anyio.fail_after(30):
            async with anyio.create_task_group() as tasks:
                tasks.start_soon(other_task)
                while len(received) < 4096:
                    received += await stream.receive(1)
                tasks.cancel_scope.cancel()
        await stream.aclose()

        assert turns > 50

    async def test_a_flood_of_stderr_does_not_hold_the_event_loop(
        self, tls_sockets: tuple[ssl.SSLSocket, ssl.SSLSocket]
    ) -> None:
        """Other tasks run again and again while the one receive() reading it lasts."""
        client, server = tls_sockets
        client.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 1024**2)
        server.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 1024**2)
        flood = b"".join(_frame(STDERR, b"x") for _ in range(10_000))
        server.sendall(flood + _frame(STDOUT, b"a reply\n"))
        stream = _stdio(client)
        turns = 0

        async def other_task() -> None:
            nonlocal turns
            while True:
                turns += 1
                await anyio.lowlevel.checkpoint()

        with anyio.fail_after(30):
            async with anyio.create_task_group() as tasks:
                tasks.start_soon(other_task)
                reply = await stream.receive()
                tasks.cancel_scope.cancel()
        await stream.aclose()

        assert reply == b"a reply\n"
        assert turns > 100

    async def test_a_receive_whose_caller_was_cancelled_takes_nothing(
        self, tls_sockets: tuple[ssl.SSLSocket, ssl.SSLSocket]
    ) -> None:
        client, server = tls_sockets
        stream = _stdio(client)
        server.sendall(_frame(STDOUT, b"a reply\n"))

        with anyio.CancelScope() as scope:
            scope.cancel()
            await stream.receive()
        assert scope.cancelled_caught
        with anyio.fail_after(30):
            reply = await stream.receive()
        await stream.aclose()

        assert reply == b"a reply\n"

    async def test_closing_ends_a_pending_receive_without_a_close_handshake(
        self, tls_sockets: tuple[ssl.SSLSocket, ssl.SSLSocket]
    ) -> None:
        """websocket-client's handshake waits up to 3 s for the server's answer."""
        client, server = tls_sockets
        stream = _stdio(client)
        reader = _reader(server)
        receiving = asyncio.create_task(stream.receive())
        await anyio.wait_all_tasks_blocked()  # It now waits for stdout.

        await stream.aclose()

        with anyio.fail_after(30), pytest.raises(anyio.ClosedResourceError):
            await receiving
        with pytest.raises((websocket.WebSocketConnectionClosedException, OSError)):
            reader.recv_frame()  # The connection ended, with no close frame first.
        assert client.fileno() == -1

    async def test_requests_and_replies_pass_while_other_threads_are_starved(
        self,
        tls_sockets: tuple[ssl.SSLSocket, ssl.SSLSocket],
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """As a busy runner's event loop can starve them of the GIL, for good.

        CPython hands the GIL to a waiting thread only once one hold outlasts the
        switch interval, so an event loop busy for less at a time keeps it.
        """
        client, server = tls_sockets
        released = threading.Event()
        start = threading.Thread.start

        def held_back(thread: threading.Thread) -> None:
            run = thread.run

            def run_once_released() -> None:
                released.wait()  # Set when the test ends, passed or not.
                run()

            thread.run = run_once_released  # type: ignore[method-assign]
            start(thread)

        monkeypatch.setattr(threading.Thread, "start", held_back)
        try:
            stream = _stdio(client)
            reader = _reader(server)
            receiving = asyncio.create_task(stream.receive())
            await anyio.wait_all_tasks_blocked()  # It now waits for stdout.
            server.sendall(_frame(STDOUT, b"ready\n"))
            with anyio.fail_after(30):
                ready = await receiving
                await stream.send(b"a request\n")
            _, request = reader.recv_data_frame(True)
        finally:
            released.set()
        await stream.aclose()

        assert (ready, request.data) == (b"ready\n", b"\x00a request\n")

    async def test_a_frame_split_across_reads_is_read_whole(
        self, tls_sockets: tuple[ssl.SSLSocket, ssl.SSLSocket]
    ) -> None:
        """websocket-client keeps the part read while the read waits for the rest."""
        client, server = tls_sockets
        stream = _stdio(client)
        frame = _frame(STDOUT, b"a reply\n")
        receiving = asyncio.create_task(stream.receive())

        for part in (frame[:1], frame[1:5], frame[5:]):  # Header, then payload.
            await _wait_for(lambda: not select.select([client], [], [], 0)[0])
            assert not receiving.done()
            server.sendall(part)
        with anyio.fail_after(30):
            reply = await receiving
        await stream.aclose()

        assert reply == b"a reply\n"

    async def test_a_message_in_several_frames_is_read_whole(
        self, tls_sockets: tuple[ssl.SSLSocket, ssl.SSLSocket]
    ) -> None:
        """With a ping between them, as RFC 6455 lets a server send."""
        client, server = tls_sockets
        stream = _stdio(client)
        abnf = websocket.ABNF
        server.sendall(
            abnf(0, 0, 0, 0, abnf.OPCODE_BINARY, 0, bytes([STDOUT]) + b"a r").format()
            + abnf(1, 0, 0, 0, abnf.OPCODE_PING, 0, b"").format()
            + abnf(0, 0, 0, 0, abnf.OPCODE_CONT, 0, b"ep").format()
            + abnf(1, 0, 0, 0, abnf.OPCODE_CONT, 0, b"ly\n").format()
            + _frame(*_status(0))
        )

        with anyio.fail_after(30):
            received = [piece async for piece in _receiving(stream, 65536)]

        assert b"".join(received) == b"a reply\n"


async def _receiving(stream: PodStdio, max_bytes: int) -> AsyncIterator[bytes]:
    while True:
        try:
            yield await stream.receive(max_bytes)
        except anyio.EndOfStream:
            return
