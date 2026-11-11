import asyncio
import base64
import contextlib
import logging
import re
import secrets
import shlex
import socket
import ssl
import threading
import time
from contextlib import ExitStack, contextmanager
from typing import Generator

import anyio
import websocket
from anyio.abc import ByteStream
from inspect_ai.util import ExecResult, OutputLimitExceededError
from inspect_ai.util import SandboxEnvironmentLimits as limits
from kubernetes.stream.ws_client import (  # type: ignore[import-untyped]
    ERROR_CHANNEL,
    STDERR_CHANNEL,
    STDOUT_CHANNEL,
    WSClient,
)
from websocket import ABNF

from k8s_sandbox._logger import log_trace
from k8s_sandbox._pod.buffer import LimitedBuffer
from k8s_sandbox._pod.error import ExecResultUnknownError, GetReturncodeError, PodError
from k8s_sandbox._pod.get_returncode import get_returncode
from k8s_sandbox._pod.op import API_TIMEOUT, PodOperation

COMPLETED_SENTINEL = "completed-sentinel-value"
# How long to wait, once both end markers have arrived, for the exec to end by itself
# and report the shell's exit status (which takes milliseconds). It only runs out when
# a background process still holds the command's stdout or stderr open.
STREAM_END_GRACE_SECONDS = 0.1
EXEC_USER_URL = "https://k8s-sandbox.aisi.org.uk/design/limitations#exec-user"
# The last line of every exec script, which closes its { } group: see exec().
_CLOSE_GROUP = "}\n"
# Kept from an exec_stdio command's stderr, to explain one that failed to start.
_STDERR_TAIL_BYTES = 4096

logger = logging.getLogger(__name__)


def _shell_command(user: str | None, switch: bool = False) -> list[str]:
    """The command to open the interactive shell an exec() runs inside.

    When a user is requested, only reach for `runuser` if the container is not
    already running as that user. `runuser` calls setgroups(2), which needs
    CAP_SETGID even when switching root -> root, so an unconditional wrapper
    makes every exec(user=...) fail in a container whose capabilities have been
    dropped. Skipping it is close to a no-op, but not exactly one: runuser also
    normalizes HOME, SHELL, USER, LOGNAME and PATH, which the skip path
    inherits from the container instead.

    `switch` is whether a probe of the container (ExecuteOperation.probe_switch)
    found that it needs `runuser` for this user, and that `runuser` works. Otherwise
    the shell checks for itself, which costs two more process starts per exec. It does
    even where the probe found the container already running as the user: a pod
    replaced under the same name since might not, and a plain shell would then run the
    command as someone else, where `runuser` can only switch or fail. `sh -c` takes its
    script from argv, so stdin reaches whichever shell is exec'd unread, and the
    caller's protocol is unchanged.
    """
    if user is None:
        return ["/bin/sh"]
    if not user or switch:
        # An empty user matches nothing; leave runuser to reject it as it did before.
        return ["runuser", "-u", user, "--", "/bin/sh"]
    return [
        "/bin/sh",
        "-c",
        f"if {_runs_as(user)}; then exec /bin/sh; fi; "
        f"exec runuser -u {shlex.quote(user)} -- /bin/sh",
    ]


def _runs_as(user: str) -> str:
    """A shell test of whether the container runs as `user`.

    `user` may be a name or a uid, and the two must be compared against
    different things: testing a uid against `id -un` (or a name against `id -u`)
    would match an account merely *named* "0" against uid 0 and run the command
    as the wrong user. So only the applicable test is emitted.

    `id -un` reports only the first passwd name for a uid, so a second name for
    the same uid (root/toor) is not recognised and falls through to `runuser` --
    i.e. the previous behaviour, which is the safe direction. A missing or failing
    `id` leaves the substitution empty, which cannot equal a non-empty user, so
    that also falls through to `runuser`.
    """
    current = "id -u" if user.isdigit() else "id -un"
    return f'[ "$({current} 2>/dev/null)" = {shlex.quote(user)} ]'


class ExecuteOperation(PodOperation):
    def exec(
        self,
        cmd: list[str],
        stdin: str | bytes | None,
        cwd: str | None,
        env: dict[str, str],
        user: str | None,
        timeout: int | None,
        switch: bool = False,
    ) -> ExecResult[str]:
        # The shell ends the command's output with this marker. It holds a random value
        # made up for this exec, so nothing the command prints can be taken for it.
        marker = f"<{COMPLETED_SENTINEL}-{secrets.token_hex(16)}-"
        shell_script = self._build_shell_script(cmd, stdin, cwd, env, timeout, marker)
        with self._interactive_shell(_shell_command(user, switch)) as ws_client:
            # Write the script to the shell's stdin rather than passing it as a command
            # argument (-c) to better support potentially long commands. Nothing runs
            # until the group's closing `}` arrives, so a failure before then may be
            # retried. A shell that got the `}` runs the group even without the
            # newline after it, and over plain ws:// part of a frame cut off by a lost
            # connection can still arrive: once that line is being sent, it may run.
            self._write_stdin_chunked(ws_client, shell_script[: -len(_CLOSE_GROUP)])
            try:
                ws_client.write_stdin(_CLOSE_GROUP)
            except (OSError, websocket.WebSocketException) as e:
                raise ExecResultUnknownError(
                    "WebSocket connection lost during exec",
                    pod=self._pod.name,
                ) from e
            result = self._handle_shell_output(ws_client, user, timeout, marker)
        return result

    def open_stdio(
        self, cmd: list[str], user: str | None
    ) -> tuple[ExitStack, WSClient]:
        """Start `cmd` as exec() would for `user`, joined to the websocket's stdio.

        Returns the websocket and the stack that closes it. The shell reads one line
        and execs the command, which inherits the rest of stdin. The caller must write
        nothing more until the command has answered: dash and busybox sh read ahead.
        """
        with ExitStack() as stack:
            ws_client = stack.enter_context(
                self._interactive_shell(_shell_command(user))
            )
            ws_client.write_stdin(f"exec {shlex.join(cmd)}\n")
            return stack.pop_all(), ws_client

    def probe_switch(self, user: str) -> bool:
        """Whether exec(user=...) can start `runuser` directly to run as `user`.

        True if the container isn't running as `user` and `runuser` can switch to them.
        Otherwise (it already runs as them, `runuser` is missing, the user doesn't
        exist, or the container may not switch users) the shell's own check handles
        each exec, as before. Starting `runuser` directly only once it is known to work
        matters: one that fails at once ends the exec before its script arrives, and
        the server then resets the connection, losing the error. The answer is the exit
        status the exec's status channel reports, so nothing the container prints can
        change it.
        """
        quoted = shlex.quote(user)
        probe = (
            f"if {_runs_as(user)}; then exit 0; fi; "
            f"if runuser -u {quoted} -- true 2>/dev/null; then exit 1; fi; exit 2"
        )
        with self._interactive_shell(["/bin/sh", "-c", probe]) as ws_client:
            deadline = time.monotonic() + API_TIMEOUT
            # The answer is in with the status; the server's close needn't follow.
            while ws_client.is_open() and ERROR_CHANNEL not in ws_client._channels:
                wait = deadline - time.monotonic()
                if wait <= 0:
                    raise PodError(f"Probing exec(user={user!r}) timed out")
                # Also times out a read that stalls partway through a frame, within
                # about twice the deadline (a frame still trickling in can take longer).
                ws_client.sock.settimeout(wait)
                try:
                    _update(ws_client, wait)
                except websocket.WebSocketTimeoutException:
                    continue  # The deadline has passed.
                except (OSError, websocket.WebSocketException):
                    if ERROR_CHANNEL not in ws_client._channels:
                        raise
                # The probe prints nothing, so keep nothing a planted `id` might.
                ws_client._channels.pop(STDOUT_CHANNEL, None)
                ws_client._channels.pop(STDERR_CHANNEL, None)
            ws_client.close()
            returncode = get_returncode(ws_client)
        return returncode == 1

    @contextmanager
    def _interactive_shell(self, command: list[str]) -> Generator[WSClient, None, None]:
        # ExecutableNotFoundError from here only means /bin/sh, or runuser once a
        # probe has found it, is missing. A missing `runuser` is otherwise exec'd by
        # the shell rather than by the API server, so it surfaces as a 127 on stderr
        # and is handled by _check_for_runuser_error instead.
        yield from self.create_websocket_client_for_exec(
            command=command,
            stderr=True,
            stdin=True,
            stdout=True,
            # Leave stdout and stderr as binary. Has no effect on stdin.
            binary=True,
        )

    def _build_shell_script(
        self,
        command: list[str],
        stdin: str | bytes | None,
        cwd: str | None,
        env: dict[str, str],
        timeout: int | None,
        marker: str,
    ) -> str:
        def generate() -> Generator[str, None, None]:
            # A group is read in full before any of it runs, so the command cannot
            # read the rest of the script, marker included, from the shell's stdin.
            yield "{\n"
            if cwd is not None:
                yield f"cd {shlex.quote(cwd)} || exit $?\n"
            for key, value in env.items():
                yield f"export {shlex.quote(key)}={shlex.quote(value)}\n"
            # Run the command in a subshell, so that one which exits or execs this
            # shell doesn't end it before it writes the markers.
            pipe = "" if stdin is None else self._pipe_user_input(stdin)
            yield f"({pipe}{self._prefix_timeout(timeout)}{shlex.join(command)})\n"
            # Store the returncode so that the `printf` below doesn't overwrite it.
            yield "returncode=$?\n"
            # End both streams with the marker and the returncode. The exec's status
            # channel reports the returncode when the shell exits; the markers are for
            # when a background process keeps stdout or stderr, and so the exec, open.
            yield f"printf '{marker}%d>' \"$returncode\"\n"
            yield f"printf '{marker}%d>' \"$returncode\" >&2\n"
            # Exit the shell. This won't actually close the websocket connection until
            # stdout and stderr (which have been inherited by the user command) are
            # closed.
            yield 'exit "$returncode"\n'
            yield _CLOSE_GROUP

        return "".join(generate())

    def _pipe_user_input(self, stdin: str | bytes) -> str:
        # Encode the user-provided input as base64 for 2 reasons:
        # 1. To avoid issues with special characters (e.g. new lines) in the input.
        # 2. To support binary input (e.g. null byte).
        stdin_b64 = base64.b64encode(
            stdin if isinstance(stdin, bytes) else stdin.encode("utf-8")
        ).decode("ascii")
        # Pipe user input. Simply writing it to the shell's stdin after a command e.g.
        # `cat` results in `cat` blocking indefinitely as there is no way to close the
        # stdin stream in v4.channel.k8s.io.
        return f"echo '{stdin_b64}' | base64 -d | "

    def _prefix_timeout(self, timeout: int | None) -> str:
        if timeout is None:
            return ""
        # Enforce timeout using `timeout` on the Pod. Simpler than alternative of
        # enforcing this on the client side (requires terminating the remote process).
        # `-k 5s` sends SIGKILL after grace period in case user command doesn't respect
        # SIGTERM.
        return f"timeout -k 5s {timeout}s "

    def _handle_shell_output(
        self, ws_client: WSClient, user: str | None, timeout: int | None, marker: str
    ) -> ExecResult[str]:
        def stream_output() -> tuple[ExecResult[str], bool]:
            stdout = _MarkedStream(marker)
            stderr = _MarkedStream(marker)
            # Set once both markers are in: the command has exited.
            deadline: float | None = None
            while ws_client.is_open():
                wait = None if deadline is None else deadline - time.monotonic()
                if wait is not None and wait <= 0:
                    break
                lost = None
                try:
                    # Until both markers are in, `wait` is None and this blocks until
                    # there is data to read.
                    _update(ws_client, wait)
                except (OSError, websocket.WebSocketException) as e:
                    lost = e
                # Take what was read straight from the client's buffers, also by an
                # update() that then failed (from kubernetes 37 it reads every frame
                # waiting). The peek_*() calls read another frame first, and one for
                # the stream already read would wait unseen through the next blocking
                # update().
                stderr.append(ws_client._channels.pop(STDERR_CHANNEL, b""))
                stdout.append(ws_client._channels.pop(STDOUT_CHANNEL, b""))
                self._verify_output_limit(stdout.buffer, stderr.buffer)
                if deadline is None and None not in (
                    stdout.returncode,
                    stderr.returncode,
                ):
                    deadline = time.monotonic() + STREAM_END_GRACE_SECONDS
                    # Nor wait past it for the rest of a frame already started.
                    ws_client.sock.settimeout(STREAM_END_GRACE_SECONDS)
                if lost is not None:
                    if deadline is None and ERROR_CHANNEL not in ws_client._channels:
                        raise ExecResultUnknownError(
                            "WebSocket connection lost during exec",
                            pod=self._pod.name,
                        ) from lost
                    break
            if deadline is None or ERROR_CHANNEL in ws_client._channels:
                # The exec reported the shell's exit status, or ended before the
                # markers (e.g. `cd` failed, so the command never ran).
                if ws_client.is_open():
                    ws_client.close()
                stdout.flush()
                stderr.flush()
                self._verify_output_limit(stdout.buffer, stderr.buffer)
                try:
                    returncode = get_returncode(ws_client)
                except GetReturncodeError as e:
                    if deadline is None:
                        raise ExecResultUnknownError(
                            "The exec ended without the command's exit code",
                            pod=self._pod.name,
                        ) from e
                    returncode = self._marked_returncode(stdout, stderr)
                # The shell can only exit 0 once it has written both markers, so a
                # missing one means the end of the output was lost on the way.
                if returncode == 0 and None in (stdout.returncode, stderr.returncode):
                    raise ExecResultUnknownError(
                        "The exec ended without the end of the command's output",
                        pod=self._pod.name,
                    )
            else:
                # Both markers are in but no exit status: a background process is
                # holding stdout or stderr open, or the connection was lost after the
                # command exited.
                returncode = self._marked_returncode(stdout, stderr)
            return (
                ExecResult(
                    success=returncode == 0,
                    returncode=returncode,
                    stdout=str(stdout.buffer),
                    stderr=str(stderr.buffer),
                ),
                stdout.returncode is not None,
            )

        result, saw_completed_sentinel = stream_output()
        # 124 is the exit code for the `timeout` command.
        if timeout is not None and result.returncode == 124:
            raise TimeoutError(f"Command timed out after {timeout}s. {result}")
        # The Inspect SandboxEnvironment interface expects us to raise a
        # PermissionError for exit code 126 and stderr containing "permission denied".
        if result.returncode == 126 and "permission denied" in result.stderr.casefold():
            raise PermissionError(f"Permission denied executing command. {result}")
        # Only parse runuser errors if the wrapper failed before it could run the
        # shell script and write our sentinel. If the sentinel was seen, any runuser
        # stderr came from the user-supplied command.
        if result.returncode != 0 and user is not None and not saw_completed_sentinel:
            self._check_for_runuser_error(result.stderr, user)
        return result

    def _check_for_runuser_error(self, stderr: str, user: str) -> None:
        if re.search(r"runuser: user \S+ does not exist", stderr, re.IGNORECASE):
            raise RuntimeError(
                f"The user parameter '{user}' provided to exec() does "
                f"not appear to exist in the container. Docs: {EXEC_USER_URL}\n{stderr}"
            )
        # The three arms below describe an environment that cannot perform the
        # switch, not a caller asking for something that does not exist. Callers
        # are entitled to handle that: inspect-ai probes with `user="root"` and
        # falls back to the default user when it fails, which is how a rootless
        # sandbox is meant to work. Raising here made that fallback unreachable
        # and turned a supported configuration into a fatal error, so warn and
        # let the failed ExecResult through. Only an unknown user still raises,
        # because no fallback makes a name that isn't there work.
        if "runuser: may not be used by non-root users" in stderr.casefold():
            logger.warning(
                "exec(user=%r) failed: the container is not running as root, so "
                "runuser cannot switch users. Docs: %s\n%s",
                user,
                EXEC_USER_URL,
                stderr,
            )
            return
        # Anchored on the `runuser: ` prefix like the arms above it: `newgrp`,
        # `sg`, `su` and `login` print the same message body, so an unanchored
        # match would blame the sandbox's capabilities for a user command's own
        # failure.
        if re.search(r"runuser: cannot set groups", stderr, re.IGNORECASE):
            logger.warning(
                "exec(user=%r) failed: runuser needs CAP_SETGID to call "
                "setgroups(2), and the container's capabilities appear to have "
                "been dropped. Docs: %s\n%s",
                user,
                EXEC_USER_URL,
                stderr,
            )
            return
        if re.search(r"runuser: not found", stderr, re.IGNORECASE):
            logger.warning(
                "exec(user=%r) failed: switching users needs the runuser binary, "
                "which is not installed in this container. Docs: %s\n%s",
                user,
                EXEC_USER_URL,
                stderr,
            )
            return

    def _marked_returncode(
        self, stdout: "_MarkedStream", stderr: "_MarkedStream"
    ) -> int:
        # The markers disagree only if something besides the shell wrote one: code the
        # command runs can read its own stdout back through /proc and so learn it.
        if stdout.returncode is None or stdout.returncode != stderr.returncode:
            raise ExecResultUnknownError(
                "The command's end markers disagree, so its exit code is unknown",
                pod=self._pod.name,
            )
        return stdout.returncode

    def _verify_output_limit(
        self, stdout: LimitedBuffer, stderr: LimitedBuffer
    ) -> None:
        if stdout.truncated or stderr.truncated:
            raise OutputLimitExceededError(
                limit_str=limits.MAX_EXEC_OUTPUT_SIZE_STR,
                truncated_output=str(stdout) + str(stderr),
            )


def _update(ws_client: WSClient, timeout: float | None) -> None:
    """ws_client.update(timeout), or a frame TLS has already decrypted if there is one.

    Before kubernetes 37, update() reads one frame but polls only the raw socket, which
    can't see a decrypted one: a frame that arrived in the same TLS record as the last
    would wait unseen for more data, forever while a background process holds the exec
    open. Take just the one, so that the caller checks its output limit and deadline
    after each frame.
    """
    sock = ws_client.sock.sock
    if not (isinstance(sock, ssl.SSLSocket) and sock.pending()):
        ws_client.update(timeout=timeout)
        return
    op_code, frame = ws_client.sock.recv_data_frame(True)
    if op_code == ABNF.OPCODE_CLOSE:
        ws_client._connected = False
    elif op_code in (ABNF.OPCODE_BINARY, ABNF.OPCODE_TEXT) and len(frame.data) > 1:
        channel, data = frame.data[0], frame.data[1:]
        ws_client._channels[channel] = ws_client._channels.get(channel, b"") + data


class PodStdio(ByteStream):
    """An exec's stdin and stdout as a byte stream (see Pod.exec_stdio()).

    A thread reads the websocket into a bounded buffer, so a slow reader of the
    stream stops it, and then TCP. It owns the websocket: once the exec ends or the
    stream is closed, it closes the websocket.
    """

    def __init__(
        self, operation: PodOperation, stack: ExitStack, ws_client: WSClient
    ) -> None:
        self._operation = operation
        self._ws = ws_client
        self._loop = asyncio.get_running_loop()
        self._stdout_in, self._stdout = anyio.create_memory_object_stream[bytes](16)
        # Set when a piece of stdout, or its end, arrives. receive() waits on this
        # rather than in the memory stream, which hands a piece straight to a waiting
        # receiver: one cancelled by Task.cancel() before it resumed would lose it.
        self._arrived = asyncio.Event()
        self._unread = b""
        self._error: Exception | None = None
        # Writes take no tokens from anyio's shared limiter, so a wedged one can't
        # hold up other threads.
        self._limiter = anyio.CapacityLimiter(1)
        threading.Thread(
            target=self._read, args=(stack,), daemon=True, name="pod-stdio"
        ).start()

    def _read(self, stack: ExitStack) -> None:
        stderr = b""
        try:
            while self._ws.is_open():
                _update(self._ws, None)
                stderr += self._ws._channels.pop(STDERR_CHANNEL, b"")
                stderr = stderr[-_STDERR_TAIL_BYTES:]
                if stdout := self._ws._channels.pop(STDOUT_CHANNEL, b""):
                    put = self._put(stdout)
                    asyncio.run_coroutine_threadsafe(put, self._loop).result()
        except Exception as e:
            # A failed read, or the stream closed under the reader.
            if ERROR_CHANNEL not in self._ws._channels:
                self._error = e
        finally:
            _shutdown(self._ws)
            with contextlib.suppress(RuntimeError):  # The event loop is closed.
                self._loop.call_soon_threadsafe(self._end)
            stack.close()
            if stderr:
                log_trace("An exec_stdio command wrote to stderr.", stderr=stderr)

    async def _put(self, stdout: bytes) -> None:
        await self._stdout_in.send(stdout)
        self._arrived.set()

    def _end(self) -> None:
        self._stdout_in.close()
        self._arrived.set()

    async def receive(self, max_bytes: int = 65536) -> bytes:
        while not self._unread:
            self._arrived.clear()
            try:
                self._unread = self._stdout.receive_nowait()
            except anyio.WouldBlock:
                await self._arrived.wait()
            except anyio.EndOfStream:
                if self._error is not None:
                    raise anyio.BrokenResourceError from self._error
                raise
        data, self._unread = self._unread[:max_bytes], self._unread[max_bytes:]
        return data

    async def send(self, item: bytes) -> None:
        try:
            await anyio.to_thread.run_sync(
                self._operation._write_stdin_chunked,
                self._ws,
                item,
                abandon_on_cancel=True,
                limiter=self._limiter,
            )
        except (OSError, websocket.WebSocketException) as e:
            raise anyio.BrokenResourceError from e

    async def send_eof(self) -> None:
        raise NotImplementedError("v4.channel.k8s.io cannot close stdin alone")

    async def aclose(self) -> None:
        # Awaits nothing, so that it cannot be cancelled halfway. The reader, woken by
        # either, then closes the websocket and ends a pending receive().
        self._stdout.close()
        _shutdown(self._ws)


def _shutdown(ws_client: WSClient) -> None:
    """Fail a read or write waiting on the websocket's socket, at once.

    The plain socket's shutdown: SSLSocket.shutdown (and WebSocket.abort(), which
    calls it) drops TLS first, so a write racing it could go out unencrypted.
    """
    sock = getattr(ws_client.sock, "sock", None)
    if sock is not None:
        with contextlib.suppress(OSError):
            socket.socket.shutdown(sock, socket.SHUT_RDWR)


class _MarkedStream:
    """One of the command's output streams, up to the shell's end marker.

    A frame can end partway through the marker, so the bytes at the end of each frame
    that could be its start are held back until the next frame settles it.
    """

    def __init__(self, marker: str) -> None:
        self.buffer = LimitedBuffer(limits.MAX_EXEC_OUTPUT_SIZE)
        self.returncode: int | None = None
        self._prefix = marker.encode()
        self._pattern = re.compile(re.escape(self._prefix) + rb"(\d{1,3})>")
        # The longest marker less one byte: a returncode has at most three digits.
        self._hold = len(marker) + 3
        self._pending = b""

    def append(self, data: bytes) -> None:
        if self.returncode is not None:
            # Written after the command exited, by a background process.
            return
        data = self._pending + data
        match = self._pattern.search(data)
        if match:
            self.buffer.append(data[: match.start()])
            self.returncode = int(match[1])
            self._pending = b""
        else:
            # Hold back only a tail that could still become the marker, which starts at
            # its only `<`.
            start = data.rfind(b"<", max(0, len(data) - self._hold))
            if start == -1 or not self._could_become_marker(data[start:]):
                start = len(data)
            self.buffer.append(data[:start])
            self._pending = data[start:]

    def _could_become_marker(self, tail: bytes) -> bool:
        head, digits = tail[: len(self._prefix)], tail[len(self._prefix) :]
        return self._prefix.startswith(head) and (digits.isdigit() or not digits)

    def flush(self) -> None:
        """Release the held-back bytes of a stream that ended without a marker."""
        self.buffer.append(self._pending)
        self._pending = b""
