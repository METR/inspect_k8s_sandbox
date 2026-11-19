import contextlib
import shlex
from contextlib import contextmanager
from pathlib import Path
from typing import Generator

from kubernetes.stream.ws_client import WSClient  # type: ignore[import-untyped]
from websocket import WebSocketException

from k8s_sandbox._pod.error import ContainerStoppedError, PodError
from k8s_sandbox._pod.execute import STREAM_END_GRACE_SECONDS, _shell_command
from k8s_sandbox._pod.get_returncode import (
    get_returncode,
    raise_if_stopped_before_lost,
)
from k8s_sandbox._pod.op import (
    SYSTEM_PATH,
    PodOperation,
    raise_for_known_read_write_errors,
)


def write_command(dst: Path, file_size: int) -> list[str]:
    """The command that writes its stdin to a file, over Kubernetes exec."""
    mkdir_command = f"mkdir -p -- {shlex.quote(dst.parent.as_posix())}"
    # v4.channel.k8s.io cannot close stdin, so `head` reads the file's size and ends.
    head_command = f"head -c {file_size}"
    dst_quoted = shlex.quote(dst.as_posix())
    # Unread input holds the exec open; a short read must not pass for the whole file.
    write = (
        f"{{ {head_command} || kill $$; }} | {{ {mkdir_command} && {head_command} "
        f"> {dst_quoted}; s=$?; {head_command} > /dev/null; exit $s; }}"
    )
    # The script runs only helpers, which are found in the system directories.
    return ["/bin/sh", "-c", f"PATH={SYSTEM_PATH}; {write}"]


class WriteFileOperation(PodOperation):
    def write_file(
        self, data: bytes, dst: Path, user: str | None = None, switch: bool = False
    ) -> None:
        with self._start_write_command(dst, len(data), user, switch) as ws_client:
            try:
                self._write_stdin_chunked(ws_client, data)
            except (OSError, WebSocketException) as e:
                # A status the exec sent before the upload failed is still unread.
                with contextlib.suppress(OSError, WebSocketException):
                    ws_client.run_forever(timeout=STREAM_END_GRACE_SECONDS)
                raise_if_stopped_before_lost(ws_client, e, self._pod.name)
                raise
            self._handle_stream_output(ws_client)

    @contextmanager
    def _start_write_command(
        self, dst: Path, file_size: int, user: str | None = None, switch: bool = False
    ) -> Generator[WSClient, None, None]:
        yield from self.create_websocket_client_for_exec(
            # As `user`, switched to as exec() does: directories and file are theirs.
            command=_shell_command(user, switch, write_command(dst, file_size)),
            stderr=True,
            stdin=True,
            stdout=True,
            # Read stdout and stderr as text. Has no effect on stdin.
            binary=False,
        )

    def _handle_stream_output(self, ws_client: WSClient) -> None:
        # Wait until the websocket connection is closed. All stderr will be stored by us
        # in memory anyway so there is no value in streaming it.
        try:
            ws_client.run_forever()
        except (OSError, WebSocketException) as e:
            raise_if_stopped_before_lost(ws_client, e, self._pod.name)
            raise
        returncode = get_returncode(ws_client)
        # `head` and `mkdir` never exit 255: Kata gives it when the VM stopped.
        if returncode == 255:
            raise ContainerStoppedError(
                "The container stopped while writing the file.",
                pod=self._pod.name,
                returncode=returncode,
            )
        if returncode != 0:
            stderr = ws_client.read_stderr()
            raise_for_known_read_write_errors(stderr)
            raise PodError(
                "Unrecognised error writing file to pod.",
                returncode=returncode,
                stderr=stderr,
            )
