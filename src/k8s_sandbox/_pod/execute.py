import base64
import contextlib
import logging
import re
import secrets
import shlex
import ssl
import time
from contextlib import ExitStack, contextmanager
from typing import Awaitable, Callable, Generator, Sequence, cast

import anyio
import anyio.lowlevel
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

from k8s_sandbox._logger import log_trace, log_warn
from k8s_sandbox._pod.buffer import LimitedBuffer
from k8s_sandbox._pod.error import (
    ContainerStoppedError,
    ExecResultUnknownError,
    GetReturncodeError,
    PodError,
)
from k8s_sandbox._pod.get_returncode import get_returncode, returncode_from_status
from k8s_sandbox._pod.op import (
    API_TIMEOUT,
    STDIN_CHUNK_SIZE,
    SYSTEM_PATH,
    PodOperation,
)

COMPLETED_SENTINEL = "completed-sentinel-value"
# After both end markers, how long the exec has to report the shell's exit status.
STREAM_END_GRACE_SECONDS = 0.1
EXEC_USER_URL = "https://k8s-sandbox.aisi.org.uk/design/limitations#exec-user"
# The last line of every exec script, which closes its { } group: see exec().
_CLOSE_GROUP = "}\n"
# Kept from an exec_stdio command's stderr, to explain one that failed to start.
_STDERR_TAIL_BYTES = 4096
# How often an exec_stdio stream retries TLS that must write to read, or read to write.
_TLS_RETRY_SECONDS = 0.01
# The receive() calls and frames an exec_stdio stream takes before others get a turn.
_STEPS_PER_TURN = 32
# The users that mean uid 0 whatever passwd says: their exec runs behind _ROOT_CHECK.
ROOT_USERS = ("root", "0")
# A root exec's uid check, in builtins alone; it refuses as `runuser -u root` does.
_ROOT_CHECK = (
    '(u=; while read -r k r e x; do [ "$k" = Uid: ] && u=$e && break; done'
    ' </proc/self/status; [ "$u" = 0 ]) ||'
    ' { echo "runuser: may not be used by non-root users" >&2; exit 1; }\n'
)
# Not found through the image's PATH (see SYSTEM_PATH): util-linux puts it here.
_RUNUSER = "/sbin/runuser"

logger = logging.getLogger(__name__)


def _shell_command(
    user: str | None, switch: bool = False, command: Sequence[str] = ("/bin/sh",)
) -> list[str]:
    """The command that runs `command` (by default, exec()'s shell) as `user`.

    When a user is requested, only reach for `runuser` if the container is not
    already running as that user. `runuser` calls setgroups(2), which needs
    CAP_SETGID even when switching root -> root, so an unconditional wrapper
    makes every exec(user=...) fail in a container whose capabilities have been
    dropped. Skipping it is close to a no-op, but not exactly one: runuser also
    normalizes HOME, SHELL, USER, LOGNAME and PATH, which the skip path
    inherits from the container instead.

    `switch` is whether a probe found that this user needs `runuser`, and that it works.
    `sh -c` takes its script from argv, so stdin reaches the command it execs
    unread, and the caller's protocol is unchanged.
    """
    if user is None:
        return list(command)
    if not user or switch:
        # An empty user matches nothing; leave runuser to reject it as it did before.
        return [_RUNUSER, "-u", user, "--", *command]
    run = shlex.join(command)
    return [
        "/bin/sh",
        "-c",
        f"if {_runs_as(user)}; then exec {run}; fi; "
        f"exec {_RUNUSER} -u {shlex.quote(user)} -- {run}",
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
    return f'[ "$(PATH={SYSTEM_PATH}; {current} 2>/dev/null)" = {shlex.quote(user)} ]'


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
        # Random per exec, so nothing the command prints can be taken for the marker.
        marker = f"<{COMPLETED_SENTINEL}-{secrets.token_hex(16)}-"
        root = user in ROOT_USERS
        shell_script = self._build_shell_script(
            cmd, stdin, cwd, env, timeout, marker, root=root
        )
        shell = ["/bin/sh"] if root else _shell_command(user, switch)
        with self._interactive_shell(shell) as ws_client:
            # Write the script to the shell's stdin rather than passing it as a command
            # argument (-c) to better support potentially long commands.
            self._write_stdin_chunked(ws_client, shell_script[: -len(_CLOSE_GROUP)])
            # Nothing runs before the `}`: only a failure from here on may have run it.
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
        self, cmd: list[str], user: str | None, stderr: bool = True
    ) -> tuple[ExitStack, WSClient]:
        """Start `cmd` as `user`, switched to as exec() does, joined to a websocket."""
        stack = ExitStack()
        # No resize keepalive: its events can stall the stdin (see _send_keepalive).
        ws_client = stack.enter_context(
            self._interactive_shell(
                _shell_command(user, command=cmd), send_keepalive=False, stderr=stderr
            )
        )
        return stack, ws_client

    def probe_switch(self, user: str) -> bool:
        """Whether exec(user=...) can start `runuser` directly to run as `user`."""
        quoted = shlex.quote(user)
        probe = (
            f"if {_runs_as(user)}; then exit 0; fi; "
            f"if {_RUNUSER} -u {quoted} -- /bin/sh -c : 2>/dev/null; then exit 1; fi; "
            "exit 2"
        )
        returncode, _, _ = self.run_argv(["/bin/sh", "-c", probe])
        # The probe exits 0, 1 or 2: 255 is Kata's status for a stopped container.
        if returncode == 255:
            raise ContainerStoppedError(
                "The exec's container stopped under the user probe",
                pod=self._pod.name,
                returncode=returncode,
            )
        return returncode == 1

    def run_argv(self, cmd: list[str]) -> tuple[int, bytes, bytes]:
        """Run `cmd` with nothing on its stdin; return its status, stdout and stderr."""
        out = {STDOUT_CHANNEL: b"", STDERR_CHANNEL: b""}
        with self._interactive_shell(cmd) as ws_client:
            deadline = time.monotonic() + API_TIMEOUT
            while ws_client.is_open() and ERROR_CHANNEL not in ws_client._channels:
                wait = deadline - time.monotonic()
                if wait <= 0:
                    raise PodError(f"{cmd[0]} timed out", pod=self._pod.name)
                ws_client.sock.settimeout(wait)
                try:
                    _update(ws_client, wait)
                except websocket.WebSocketTimeoutException:
                    continue
                except (OSError, websocket.WebSocketException):
                    if ERROR_CHANNEL not in ws_client._channels:
                        raise
                for channel in out:  # capped: callers want a line or a status
                    out[channel] = (
                        out[channel] + ws_client._channels.pop(channel, b"")
                    )[:4096]
            ws_client.close()
            returncode = get_returncode(ws_client)
        return returncode, out[STDOUT_CHANNEL], out[STDERR_CHANNEL]

    @contextmanager
    def _interactive_shell(
        self, command: list[str], send_keepalive: bool = True, stderr: bool = True
    ) -> Generator[WSClient, None, None]:
        # ExecutableNotFoundError here: no /bin/sh, or no runuser a probe had found.
        yield from self.create_websocket_client_for_exec(
            send_keepalive,
            command=command,
            stderr=stderr,
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
        root: bool = False,
    ) -> str:
        def generate() -> Generator[str, None, None]:
            # A group is read whole before it runs: the command can't read the marker.
            yield "{\n"
            if root:
                yield _ROOT_CHECK
            if cwd is not None:
                yield f"cd {shlex.quote(cwd)} || exit $?\n"
            for key, value in env.items():
                yield f"export {shlex.quote(key)}={shlex.quote(value)}\n"
            # In a subshell, so `exit` or `exec` in the command can't skip the markers.
            pipe = "" if stdin is None else self._pipe_user_input(stdin)
            yield f"({pipe}{self._prefix_timeout(timeout)}{shlex.join(command)})\n"
            # Store the returncode so that the `printf` below doesn't overwrite it.
            yield "returncode=$?\n"
            # `printf` is a builtin in dash, bash and busybox, but not every shell.
            yield f"PATH={SYSTEM_PATH}\n"
            # The markers end each stream when a background process keeps the exec open.
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
        return f"echo '{stdin_b64}' | (PATH={SYSTEM_PATH}; exec base64 -d) | "

    def _prefix_timeout(self, timeout: int | None) -> str:
        if timeout is None:
            return ""
        # Enforce timeout using `timeout` on the Pod. Simpler than alternative of
        # enforcing this on the client side (requires terminating the remote process).
        # `-k 5s` sends SIGKILL after grace period in case user command doesn't respect
        # SIGTERM.
        find = f"PATH={SYSTEM_PATH}; command -v timeout || echo /usr/bin/timeout"
        # In a substitution, so PATH stays its own; the echo names what was missing.
        return f'"$({find})" -k 5s {timeout}s '

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
                    # `wait` is None until both markers are in: this blocks for data.
                    _update(ws_client, wait)
                except (OSError, websocket.WebSocketException) as e:
                    lost = e
                # Not peek_*(): it reads another frame first, which may wait unseen.
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
                # The exec gave a status, or ended before its markers (a failed `cd`).
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
                # The shell exits 0 only after both markers: one missing is lost output.
                if returncode == 0 and None in (stdout.returncode, stderr.returncode):
                    raise ExecResultUnknownError(
                        "The exec ended without the end of the command's output",
                        pod=self._pod.name,
                    )
                # 255 unless both markers say so is Kata's status for a VM that stopped.
                if returncode == 255 and (stdout.returncode, stderr.returncode) != (
                    255,
                    255,
                ):
                    raise ContainerStoppedError(
                        "The exec's container stopped under the command",
                        pod=self._pod.name,
                        returncode=returncode,
                    )
            else:
                # No status after both markers: output held open, or a lost connection.
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
        # Only without the marker can a runuser error on stderr be the user switch's.
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
        # dash and busybox say "not found", bash "No such file or directory".
        if re.search(
            r"runuser: (?:not found|no such file or directory)", stderr, re.IGNORECASE
        ):
            logger.warning(
                "exec(user=%r) failed: switching users needs the runuser binary, "
                "at /sbin/runuser, which this container lacks. Docs: %s\n%s",
                user,
                EXEC_USER_URL,
                stderr,
            )
            return

    def _marked_returncode(
        self, stdout: "_MarkedStream", stderr: "_MarkedStream"
    ) -> int:
        # They differ only if the command forged one, having read its own stdout back.
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
    """ws_client.update(timeout), or a frame TLS has already decrypted, if any."""
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
    """An exec's stdin and stdout as a byte stream (see Pod.exec_stdio())."""

    def __init__(
        self,
        stack: ExitStack,
        ws_client: WSClient,
        stopped: Callable[[], None] | None = None,
        restarted: Callable[[], Exception | None] | None = None,
    ) -> None:
        self._stack = stack
        self._ws = ws_client
        # Called on a status of 255 after stdout: Kata's for a command whose VM stopped.
        self._stopped = stopped
        # The restart found since the stream opened, if any.
        self._restarted = restarted
        sock = ws_client.sock.sock
        self._fd = sock.fileno()  # websocket-client closes the socket at its end.
        sock.setblocking(False)
        self._sock = sock
        self._stdout = bytearray()
        self._message = b""  # A message's frames so far, until its last.
        self._stderr = b""
        self._status: bytes | None = None
        self._wrote = False
        self._ended = False
        self._error: Exception | None = None
        self._closed = False
        self._unyielded = 0  # Steps since the stream last let other tasks run.
        self._send_lock = anyio.Lock(fast_acquire=True)  # Free: no turn of the loop.

    async def receive(self, max_bytes: int = 65536) -> bytes:
        if max_bytes < 1:
            raise ValueError("max_bytes must be at least 1")
        await _land_pending_cancel()
        self._drop_if_restarted()
        await self._turn()
        while not self._stdout or self._closed:
            if self._closed:
                raise anyio.ClosedResourceError
            if self._ended:
                if self._error is not None:
                    raise anyio.BrokenResourceError(repr(self._error)) from self._error
                raise anyio.EndOfStream
            try:
                # websocket-client keeps a frame read in part for the next call.
                self._take(self._ws.sock.recv_frame())
            except (ssl.SSLWantReadError, BlockingIOError):
                await self._wait(anyio.wait_readable)
                self._unyielded = 0
            except ssl.SSLWantWriteError:
                await anyio.sleep(_TLS_RETRY_SECONDS)  # See send().
            except (OSError, websocket.WebSocketException) as e:
                self._end(e)
            else:
                await self._turn()
        # Also for a reply that came while this waited.
        self._drop_if_restarted()
        data = bytes(self._stdout[:max_bytes])
        del self._stdout[:max_bytes]
        return data

    def _drop_if_restarted(self) -> None:
        """End the stream if a restart was found since it opened, as if it was lost."""
        if self._closed or self._restarted is None:
            return
        if (error := self._restarted()) is not None:
            self._end(error)
            raise anyio.BrokenResourceError(repr(error)) from error

    async def _turn(self) -> None:
        """Count a call or a frame read, and let other tasks run every so many."""
        self._unyielded += 1
        if self._unyielded >= _STEPS_PER_TURN:
            self._unyielded = 0
            await anyio.lowlevel.checkpoint()

    def _take(self, frame: ABNF) -> None:
        """Take a frame of the exec's output, up to its status."""
        if frame.opcode == ABNF.OPCODE_CLOSE:
            self._end(None)
            return
        payload = cast(bytes, frame.data)  # recv_frame() reads bytes.
        if frame.opcode == ABNF.OPCODE_CONT:
            message = self._message + payload
        elif frame.opcode in (ABNF.OPCODE_BINARY, ABNF.OPCODE_TEXT):
            message = payload
        else:
            # No pong for a ping: it could land inside a frame a send() has begun.
            return
        self._message = b"" if frame.fin else message
        if not frame.fin or len(message) < 2:
            return
        channel, data = message[0], memoryview(message)[1:]
        if channel == STDOUT_CHANNEL:
            self._stdout += data
            self._wrote = True
        elif channel == STDERR_CHANNEL:
            self._stderr = (self._stderr + data)[-_STDERR_TAIL_BYTES:]
        elif channel == ERROR_CHANNEL:
            self._status = bytes(data)
            if self._stopped is not None and self._wrote and _is_255(self._status):
                self._stopped()
            self._end(None)

    async def send(self, item: bytes) -> None:
        async with self._send_lock:
            await _land_pending_cancel()  # also one that came as it waited for the lock
            self._drop_if_restarted()
            try:
                for i in range(0, len(item), STDIN_CHUNK_SIZE):
                    chunk = b"\0" + item[i : i + STDIN_CHUNK_SIZE]  # Stdin's channel.
                    frame = ABNF.create_frame(chunk, ABNF.OPCODE_BINARY).format()
                    await self._write(memoryview(frame))
            except OSError as e:
                self._end(e)
                raise anyio.BrokenResourceError(repr(e)) from e
            except anyio.get_cancelled_exc_class():
                # A frame cut short would corrupt any later one.
                self._close()
                raise

    async def _write(self, data: memoryview) -> None:
        while data:
            if self._closed:
                raise anyio.ClosedResourceError
            if self._ended:
                raise anyio.BrokenResourceError("the exec has ended") from self._error
            try:
                data = data[self._sock.send(data) :]
            except (ssl.SSLWantWriteError, BlockingIOError):
                await self._wait(anyio.wait_writable)
            except ssl.SSLWantReadError:
                # Not wait_readable(): a receive() may be waiting on the socket already.
                await anyio.sleep(_TLS_RETRY_SECONDS)

    async def _wait(self, wait: Callable[[int], Awaitable[None]]) -> None:
        """Wait for the socket; the stream ending or closing meanwhile ends the wait."""
        with contextlib.suppress(anyio.ClosedResourceError):
            await wait(self._fd)

    async def send_eof(self) -> None:
        raise NotImplementedError("v4.channel.k8s.io cannot close stdin alone")

    async def aclose(self) -> None:
        self._close()  # Awaits nothing, so that it cannot be cancelled halfway.

    def _close(self) -> None:
        self._closed = True
        self._end(None)

    def _end(self, error: Exception | None) -> None:
        """Close the websocket, ending a receive() or send() waiting on its socket."""
        if self._ended:
            return
        _clear_tls_errors()  # It may follow a failed read or write.
        self._ended = True
        self._error = error
        anyio.notify_closing(self._fd)
        self._ws.sock.shutdown()  # Closes the socket: the close then awaits no answer.
        self._stack.close()
        if not (self._wrote or self._closed):
            # It failed to start, and the caller only sees the stream end: say why.
            log_warn(
                "An exec_stdio command ended before writing to stdout.",
                status=self._status,
                stderr=self._stderr,
            )
        elif self._stderr:
            log_trace("An exec_stdio command wrote to stderr.", stderr=self._stderr)


def _is_255(status: bytes) -> bool:
    try:
        return returncode_from_status(status) == 255
    except Exception:  # A status without an exit code.
        return False


async def _land_pending_cancel() -> None:
    """Let a cancellation already due in this task land before the stream acts."""
    if anyio.get_current_task().has_pending_cancellation():
        await anyio.lowlevel.checkpoint()


# For _clear_tls_errors: making a TLS object clears the thread's OpenSSL error queue.
_TLS_ERROR_CLEARER = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)


def _clear_tls_errors() -> None:
    """Clear OpenSSL's error queue for this thread: on an event loop, everyone's."""
    _TLS_ERROR_CLEARER.wrap_bio(ssl.MemoryBIO(), ssl.MemoryBIO(), server_side=True)


class _MarkedStream:
    """One of the command's output streams, up to the shell's end marker."""

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
            # Hold back only a tail that could become the marker, from its one `<`.
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
