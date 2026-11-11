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
    STDIN_UNCHECKED_SIZE,
    SYSTEM_PATH,
    PodOperation,
)

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
# How often an exec_stdio stream retries TLS that must write to read, or read to write.
_TLS_RETRY_SECONDS = 0.01
# The most receive() calls and frames read an exec_stdio stream takes, while they keep
# coming, before it lets other tasks run: a few per reply, so a large one rarely waits
# for a busy event loop.
_STEPS_PER_TURN = 32
# The users that mean uid 0, whatever the image's passwd says. exec() runs a command as
# one of them in the container's own shell, behind _ROOT_CHECK: one program start where
# `_shell_command`'s check and second shell cost three.
ROOT_USERS = ("root", "0")
# The first line of a root exec's script, inside its { } group. Unless the shell is
# uid 0 it ends the exec before the command runs, with the message and status
# `runuser -u root` gives in a container that is not root, so the refusal is handled
# as one. Shell builtins only: the effective uid comes from /proc, not from `id`. A
# shell that cannot read it is refused the same way, after its own error saying why;
# container runtimes mount /proc. The subshell keeps its variables from the command;
# a fork costs a fraction of a millisecond even where a program start costs 20 ms.
_ROOT_CHECK = (
    '(u=; while read -r k r e x; do [ "$k" = Uid: ] && u=$e && break; done'
    ' </proc/self/status; [ "$u" = 0 ]) ||'
    ' { echo "runuser: may not be used by non-root users" >&2; exit 1; }\n'
)
# The user switch runs `runuser` as the container's user, before switching, so it is
# not found through the image's PATH either (see SYSTEM_PATH): it is at this path
# wherever util-linux provides it (Debian, Ubuntu, RHEL and its rebuilds, Alpine).
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

    `switch` is whether a probe of the container (ExecuteOperation.probe_switch)
    found that it needs `runuser` for this user, and that `runuser` works. Otherwise
    the shell checks for itself, which costs two more process starts per exec. It does
    even where the probe found the container already running as the user: a pod
    replaced under the same name since might not, and a plain shell would then run the
    command as someone else, where `runuser` can only switch or fail. `sh -c` takes its
    script from argv, so stdin reaches the command it execs unread, and the caller's
    protocol is unchanged.
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
        # The shell ends the command's output with this marker. It holds a random value
        # made up for this exec, so nothing the command prints can be taken for it.
        marker = f"<{COMPLETED_SENTINEL}-{secrets.token_hex(16)}-"
        root = user in ROOT_USERS
        shell_script = self._build_shell_script(
            cmd, stdin, cwd, env, timeout, marker, root=root
        )
        shell = ["/bin/sh"] if root else _shell_command(user, switch)
        if len(shell_script.encode()) > STDIN_UNCHECKED_SIZE:
            # A script this big could reach the shell reordered (STDIN_UNCHECKED_SIZE),
            # so it is staged in pieces, as the shell's user, and a loader runs it.
            directory = self._stage(
                shell_script.encode(),
                lambda command: (
                    command if root else _shell_command(user, switch, command=command)
                ),
                # A user switch fails as it would have for the shell itself.
                lambda stderr: (
                    None
                    if user is None
                    else self._check_for_runuser_error(stderr, user)
                ),
            )
            staged = shlex.quote(directory)
            shell_script = (
                f'{{\ntrap "rm -rf -- {staged}" EXIT\n. {staged}/data\n{_CLOSE_GROUP}'
            )
        with self._interactive_shell(shell) as ws_client:
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
        """Start `cmd` as `user`, switched to as exec() does, joined to the websocket.

        Returns the websocket and the stack that closes it. The command is the exec's
        argv (through `sh -c` to switch users), so stdin reaches it unread.
        """
        stack = ExitStack()
        # No resize keepalive: resize events for an exec without a TTY stall its stdin
        # where they go unread (CRI-O, and any runtime over v5.channel.k8s.io: see
        # _send_keepalive). TCP keepalives keep the connection alive; a stream idle past
        # the runtime's stream idle timeout (4 h by default) closes, and Inspect opens
        # another.
        ws_client = stack.enter_context(
            self._interactive_shell(
                _shell_command(user, command=cmd), send_keepalive=False
            )
        )
        return stack, ws_client

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
            f"if {_RUNUSER} -u {quoted} -- /bin/sh -c : 2>/dev/null; then exit 1; fi; "
            "exit 2"
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
                # The probe prints nothing, so keep nothing `id` or `runuser` might.
                ws_client._channels.pop(STDOUT_CHANNEL, None)
                ws_client._channels.pop(STDERR_CHANNEL, None)
            ws_client.close()
            returncode = get_returncode(ws_client)
        # The probe exits 0, 1 or 2: 255 is Kata's status for a stopped container.
        if returncode == 255:
            raise ContainerStoppedError(
                "The exec's container stopped under the user probe",
                pod=self._pod.name,
                returncode=returncode,
            )
        return returncode == 1

    @contextmanager
    def _interactive_shell(
        self, command: list[str], send_keepalive: bool = True
    ) -> Generator[WSClient, None, None]:
        # ExecutableNotFoundError from here only means /bin/sh, or runuser once a
        # probe has found it, is missing. A missing `runuser` is otherwise exec'd by
        # the shell rather than by the API server, so it surfaces as a 127 on stderr
        # and is handled by _check_for_runuser_error instead.
        yield from self.create_websocket_client_for_exec(
            send_keepalive,
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
        root: bool = False,
    ) -> str:
        def generate() -> Generator[str, None, None]:
            # A group is read in full before any of it runs, so the command cannot
            # read the rest of the script, marker included, from the shell's stdin.
            yield "{\n"
            if root:
                yield _ROOT_CHECK
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
            # `printf` is a builtin in dash, bash and busybox, but not every shell.
            yield f"PATH={SYSTEM_PATH}\n"
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
        # stdin stream in v4.channel.k8s.io. `base64` is found in the system
        # directories, in a subshell of its own (which a pipeline's part runs in
        # anyway), so the command keeps the PATH.
        return f"echo '{stdin_b64}' | (PATH={SYSTEM_PATH}; exec base64 -d) | "

    def _prefix_timeout(self, timeout: int | None) -> str:
        if timeout is None:
            return ""
        # Enforce timeout using `timeout` on the Pod. Simpler than alternative of
        # enforcing this on the client side (requires terminating the remote process).
        # `-k 5s` sends SIGKILL after grace period in case user command doesn't respect
        # SIGTERM. `timeout` runs from the path that a substitution finds in the system
        # directories, so the PATH it sets does not reach the command. With no
        # `timeout` there, the error names /usr/bin/timeout.
        find = f"PATH={SYSTEM_PATH}; command -v timeout || echo /usr/bin/timeout"
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
                # 255 unless both say so is Kata's status for a command whose VM
                # stopped under its shell.
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
        # Without our sentinel, the wrapper or a root exec's uid check may have failed
        # before the command ran, so parse runuser errors. With it, any runuser
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
        # dash and busybox say "not found" for a missing /sbin/runuser, bash "No such
        # file or directory".
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

    receive() and send() read and write the websocket's socket, made non-blocking,
    in the task that calls them: no thread has to win the GIL from a busy event loop
    to pass a reply on. Nothing is read while no one receives, so a slow reader stops
    the command through TCP. The websocket closes at the exec's status, or once the
    stream is closed.
    """

    def __init__(
        self,
        stack: ExitStack,
        ws_client: WSClient,
        stopped: Callable[[], None] | None = None,
        restarted: Callable[[], Exception | None] | None = None,
    ) -> None:
        self._stack = stack
        self._ws = ws_client
        # Called if the exec's status is 255 once the command has written stdout: Kata's
        # status for a command whose VM stopped, for a command that never exits 255
        # itself after its first output. Inspect's tools bridge writes its ready line
        # first, then exits only with 0 (its stdin closed) or 1 (an uncaught exception,
        # under PyInstaller 4.3 or later); PyInstaller's own 255 precedes any output.
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
        """End the stream if a restart was found since it opened, as if it was lost.

        Its command may run in the replacement, so not even replies already read are
        given out.
        """
        if self._closed or self._restarted is None:
            return
        if (error := self._restarted()) is not None:
            self._end(error)
            raise anyio.BrokenResourceError(repr(error)) from error

    async def _turn(self) -> None:
        """Count a call or a frame read, and let other tasks run every so many.

        So that frames or calls that keep coming (a flood of stdout or stderr, or many
        small reads) do not hold the event loop. What was read stays read, so a cancel
        here loses nothing.
        """
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
            # A ping goes unanswered: the API server sends none, and a pong could
            # land inside a frame a send() has begun.
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
                # TLS 1.3 never reads to write (1.2 could, to renegotiate), and the
                # read and write directions may not both wait on the socket at once.
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
            # It failed to start (a missing user, runuser or executable): the caller
            # only sees the stream end.
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
    """Let a cancellation already due in this task land before the stream acts.

    A cancel scope's, or a bare Task.cancel() requested while the task ran, which
    anyio's checkpoint_if_cancelled() misses. Otherwise none lands while the stream
    reads or writes without waiting.
    """
    if anyio.get_current_task().has_pending_cancellation():
        await anyio.lowlevel.checkpoint()


# For _clear_tls_errors: making a TLS object clears the thread's OpenSSL error queue.
_TLS_ERROR_CLEARER = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)


def _clear_tls_errors() -> None:
    """Clear OpenSSL's error queue for this thread: on an event loop, everyone's.

    CPython raises a TLS read or write's system error (EPIPE, say) as OSError without
    clearing the queue, and OpenSSL then reports any later TLS call on the thread that
    would wait as that error, ending the loop's other TLS connections.
    """
    _TLS_ERROR_CLEARER.wrap_bio(ssl.MemoryBIO(), ssl.MemoryBIO(), server_side=True)


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
