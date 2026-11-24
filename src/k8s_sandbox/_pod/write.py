import contextlib
import shlex
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Generator

from kubernetes.stream.ws_client import (  # type: ignore[import-untyped]
    ERROR_CHANNEL,
    STDERR_CHANNEL,
    WSClient,
)
from websocket import WebSocketException

from k8s_sandbox._pod.error import ContainerStoppedError, PodError
from k8s_sandbox._pod.execute import STREAM_END_GRACE_SECONDS, update_by
from k8s_sandbox._pod.get_returncode import (
    get_returncode,
    raise_if_stopped_before_lost,
)
from k8s_sandbox._pod.op import (
    API_TIMEOUT,
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
    def write_file(self, data: bytes, dst: Path) -> None:
        with self._start_write_command(dst, len(data)) as ws_client:
            # Nor is a send that the exec does not read waited for past the bound.
            ws_client.sock.settimeout(API_TIMEOUT)
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
        self, dst: Path, file_size: int
    ) -> Generator[WSClient, None, None]:
        yield from self.create_websocket_client_for_exec(
            command=write_command(dst, file_size),
            stderr=True,
            stdin=True,
            stdout=True,
            # Leave stdout and stderr as binary. Has no effect on stdin.
            binary=True,
        )

    def _handle_stream_output(self, ws_client: WSClient) -> None:
        deadline = time.monotonic() + API_TIMEOUT
        while ws_client.is_open() and ERROR_CHANNEL not in ws_client._channels:
            update_by(ws_client, deadline, self._pod.name)
        ws_client.close(timeout=0)  # The status is the result: no wait for an answer.
        returncode = get_returncode(ws_client)
        # `head` and `mkdir` never exit 255: Kata gives it when the VM stopped.
        if returncode == 255:
            raise ContainerStoppedError(
                "The container stopped while writing the file.",
                pod=self._pod.name,
                returncode=returncode,
            )
        if returncode != 0:
            stderr = str(ws_client._channels.pop(STDERR_CHANNEL, b""), errors="replace")
            raise_for_known_read_write_errors(stderr)
            raise PodError(
                "Unrecognised error writing file to pod.",
                returncode=returncode,
                stderr=stderr,
            )
