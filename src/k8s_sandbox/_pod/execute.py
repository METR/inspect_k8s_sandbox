import base64
import logging
import re
import secrets
import shlex
import time
from contextlib import contextmanager
from typing import Generator

from inspect_ai.util import ExecResult, OutputLimitExceededError
from inspect_ai.util import SandboxEnvironmentLimits as limits
from kubernetes.stream.ws_client import (  # type: ignore[import-untyped]
    STDERR_CHANNEL,
    STDOUT_CHANNEL,
    WSClient,
)

from k8s_sandbox._pod.buffer import LimitedBuffer
from k8s_sandbox._pod.error import PodError
from k8s_sandbox._pod.get_returncode import get_returncode
from k8s_sandbox._pod.op import PodOperation

COMPLETED_SENTINEL = "completed-sentinel-value"
# How long to wait, once both end markers have arrived, for the exec to end by itself
# and report the shell's exit status (which takes milliseconds). It only runs out when
# a background process still holds the command's stdout or stderr open.
STREAM_END_GRACE_SECONDS = 1
EXEC_USER_URL = "https://k8s-sandbox.aisi.org.uk/design/limitations#exec-user"

logger = logging.getLogger(__name__)


def _shell_command(user: str | None) -> list[str]:
    """The command to open the interactive shell an exec() runs inside.

    When a user is requested, only reach for `runuser` if the container is not
    already running as that user. `runuser` calls setgroups(2), which needs
    CAP_SETGID even when switching root -> root, so an unconditional wrapper
    makes every exec(user=...) fail in a container whose capabilities have been
    dropped. Skipping it is close to a no-op, but not exactly one: runuser also
    normalizes HOME, SHELL, USER, LOGNAME and PATH, which the skip path
    inherits from the container instead.

    The check runs in the container rather than here so that it costs no extra
    round trip. `sh -c` takes its script from argv, so stdin reaches whichever
    shell is exec'd unread, and the caller's protocol is unchanged.

    `user` may be a name or a uid, and the two must be compared against
    different things: testing a uid against `id -un` (or a name against `id -u`)
    would match an account merely *named* "0" against uid 0 and run the command
    as the wrong user. So only the applicable test is emitted.

    `id -un` reports only the first passwd name for a uid, so a second name for
    the same uid (root/toor) is not recognised and falls through to `runuser` --
    i.e. the previous behaviour, which is the safe direction.
    """
    if user is None:
        return ["/bin/sh"]
    if not user:
        # Matches nothing; leave runuser to reject it as it did before.
        return ["runuser", "-u", user, "--", "/bin/sh"]
    quoted = shlex.quote(user)
    # A missing or failing `id` leaves the substitution empty, which cannot
    # equal a non-empty user, so that also falls through to `runuser`.
    current = "id -u" if user.isdigit() else "id -un"
    return [
        "/bin/sh",
        "-c",
        f'if [ "$({current} 2>/dev/null)" = {quoted} ]; then exec /bin/sh; fi; '
        f"exec runuser -u {quoted} -- /bin/sh",
    ]


class ExecuteOperation(PodOperation):
    def exec(
        self,
        cmd: list[str],
        stdin: str | bytes | None,
        cwd: str | None,
        env: dict[str, str],
        user: str | None,
        timeout: int | None,
    ) -> ExecResult[str]:
        # The shell ends the command's output with this marker. It holds a random value
        # made up for this exec, so nothing the command prints can be taken for it.
        marker = f"<{COMPLETED_SENTINEL}-{secrets.token_hex(16)}-"
        shell_script = self._build_shell_script(cmd, stdin, cwd, env, timeout, marker)
        with self._interactive_shell(user) as ws_client:
            # Write the script to the shell's stdin rather than passing it as a command
            # argument (-c) to better support potentially long commands.
            self._write_stdin_chunked(ws_client, shell_script)
            result = self._handle_shell_output(ws_client, user, timeout, marker)
        return result

    @contextmanager
    def _interactive_shell(self, user: str | None) -> Generator[WSClient, None, None]:
        # ExecutableNotFoundError from here now only means /bin/sh is missing. A
        # missing `runuser` is exec'd by the shell rather than by the API server,
        # so it surfaces as a 127 on stderr and is handled by
        # _check_for_runuser_error instead.
        yield from self.create_websocket_client_for_exec(
            command=_shell_command(user),
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
            if stdin is not None:
                yield self._pipe_user_input(stdin)
            yield f"{self._prefix_timeout(timeout)}{shlex.join(command)}\n"
            # Store the returncode so that the `printf` below doesn't overwrite it.
            yield "returncode=$?\n"
            # Ensure stdout and stderr are flushed before writing the sentinel value.
            yield "sync\n"
            # End both streams with the marker and the returncode. The exec's status
            # channel reports the returncode when the shell exits; the markers are for
            # when a background process keeps stdout or stderr, and so the exec, open.
            yield f"printf '{marker}%d>' \"$returncode\"\n"
            yield f"printf '{marker}%d>' \"$returncode\" >&2\n"
            # Exit the shell. This won't actually close the websocket connection until
            # stdout and stderr (which have been inherited by the user command) are
            # closed.
            yield "exit $returncode\n"
            yield "}\n"

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
            returncode: int | None = None
            # Set once both markers are in: the command has exited.
            deadline: float | None = None
            while ws_client.is_open():
                wait = None if deadline is None else deadline - time.monotonic()
                if wait is not None and wait <= 0:
                    # A background process is holding stdout or stderr open, so the
                    # exec won't end by itself. Take the marker's returncode.
                    returncode = stdout.returncode
                    break
                try:
                    # Until both markers are in, `wait` is None and `update` blocks
                    # until there is data to read.
                    ws_client.update(timeout=wait)
                    # Take what update() read straight from the client's buffers. The
                    # peek_*() calls read another frame first, and one for the stream
                    # already read would wait unseen through the next blocking update().
                    stderr.append(ws_client._channels.pop(STDERR_CHANNEL, b""))
                    stdout.append(ws_client._channels.pop(STDOUT_CHANNEL, b""))
                    self._verify_output_limit(stdout.buffer, stderr.buffer)
                except (BrokenPipeError, ConnectionResetError) as e:
                    if deadline is not None:
                        # Both markers already received — we have the result.
                        returncode = stdout.returncode
                        break
                    raise PodError(
                        "WebSocket connection lost during exec",
                        pod=self._pod.name,
                    ) from e
                if deadline is None and None not in (
                    stdout.returncode,
                    stderr.returncode,
                ):
                    deadline = time.monotonic() + STREAM_END_GRACE_SECONDS
            if returncode is None:
                # The exec ended by itself, so the status channel has the shell's exit
                # status, also when the script stopped early (e.g. `cd` failed).
                stdout.flush()
                stderr.flush()
                self._verify_output_limit(stdout.buffer, stderr.buffer)
                returncode = get_returncode(ws_client)
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

    def _verify_output_limit(
        self, stdout: LimitedBuffer, stderr: LimitedBuffer
    ) -> None:
        if stdout.truncated or stderr.truncated:
            raise OutputLimitExceededError(
                limit_str=limits.MAX_EXEC_OUTPUT_SIZE_STR,
                truncated_output=str(stdout) + str(stderr),
            )


class _MarkedStream:
    """One of the command's output streams, up to the shell's end marker.

    A frame can end partway through the marker, so the bytes at the end of each frame
    that could be its start are held back until the next frame settles it.
    """

    def __init__(self, marker: str) -> None:
        self.buffer = LimitedBuffer(limits.MAX_EXEC_OUTPUT_SIZE)
        self.returncode: int | None = None
        self._pattern = re.compile(re.escape(marker.encode()) + rb"(\d{1,3})>")
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
            self.buffer.append(data[: -self._hold])
            self._pending = data[-self._hold :]

    def flush(self) -> None:
        """Release the held-back bytes of a stream that ended without a marker."""
        self.buffer.append(self._pending)
        self._pending = b""
