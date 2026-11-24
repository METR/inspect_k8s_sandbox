import time
from contextlib import contextmanager
from pathlib import Path
from typing import IO, Generator

from inspect_ai.util import OutputLimitExceededError
from inspect_ai.util import SandboxEnvironmentLimits as limits
from kubernetes.stream.ws_client import (  # type: ignore[import-untyped]
    ERROR_CHANNEL,
    STDERR_CHANNEL,
    STDOUT_CHANNEL,
    WSClient,
)

from k8s_sandbox._pod.buffer import LimitedBuffer
from k8s_sandbox._pod.error import ContainerStoppedError, PodError
from k8s_sandbox._pod.execute import update_by
from k8s_sandbox._pod.get_returncode import get_returncode
from k8s_sandbox._pod.op import (
    API_TIMEOUT,
    SYSTEM_PATH,
    PodOperation,
    raise_for_known_read_write_errors,
)


def read_command(src: Path) -> list[str]:
    """The command that prints a file, read_file() on either transport."""
    # A shell, so that `head` comes from SYSTEM_PATH; exec'd, so the errors are head's.
    return [
        "/bin/sh",
        "-c",
        f'PATH={SYSTEM_PATH}; exec head -c "$1" -- "$2"',
        "sh",
        str(limits.MAX_READ_FILE_SIZE + 1),
        "./-" if src.as_posix() == "-" else src.as_posix(),  # head's name for stdin
    ]


class ReadFileOperation(PodOperation):
    def read_file(self, src: Path, dst: IO[bytes]) -> None:
        with self._start_read_command(src) as ws_client:
            self._handle_stream_output(ws_client, dst)

    @contextmanager
    def _start_read_command(self, src: Path) -> Generator[WSClient, None, None]:
        yield from self.create_websocket_client_for_exec(
            command=read_command(src),
            stderr=True,
            # Without stdin, kubelet closes the exec's input as soon as the stream
            # opens, which races the stdout read in Kata Containers' Go shim and hangs
            # or truncates the read (kata-containers/kata-containers#9071).
            stdin=True,
            stdout=True,
            # Leave stdout (and stderr) as binary.
            binary=True,
        )

    def _handle_stream_output(self, ws_client: WSClient, dst: IO[bytes]) -> None:
        # `head` should not produce large amounts of stderr, but limit it nonetheless.
        stderr = LimitedBuffer(limits.MAX_EXEC_OUTPUT_SIZE)
        start_position = dst.tell()
        # Stream the response, writing it to dst as we go to avoid holding the whole
        # response in memory.
        quiet = time.monotonic() + API_TIMEOUT
        # As in exec(), the exec's status ends the read: only its close comes after.
        while ws_client.is_open() and ERROR_CHANNEL not in ws_client._channels:
            update_by(ws_client, quiet, self._pod.name)
            # Not peek_*(): it reads another frame first, and may wait for the rest.
            if out := ws_client._channels.pop(STDOUT_CHANNEL, b""):
                dst.write(out)
                self._verify_output_limit(dst.tell() - start_position)
                quiet = time.monotonic() + API_TIMEOUT
            stderr.append(ws_client._channels.pop(STDERR_CHANNEL, b""))
        ws_client.close()
        returncode = get_returncode(ws_client)
        # `head` never exits 255: Kata gives it when the VM stopped.
        if returncode == 255:
            raise ContainerStoppedError(
                "The container stopped while reading the file.",
                pod=self._pod.name,
                returncode=returncode,
            )
        if returncode != 0:
            stderr_str = str(stderr)
            raise_for_known_read_write_errors(stderr_str)
            raise PodError(
                "Unrecognised error reading file from pod.",
                returncode=returncode,
                stderr=stderr_str,
            )
        dst.flush()

    def _verify_output_limit(self, bytes_written: int) -> None:
        if bytes_written > limits.MAX_READ_FILE_SIZE:
            raise OutputLimitExceededError(
                limit_str=limits.MAX_READ_FILE_SIZE_STR, truncated_output=None
            )
