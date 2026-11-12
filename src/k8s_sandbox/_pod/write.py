import shlex
from contextlib import contextmanager
from pathlib import Path
from typing import Generator

from kubernetes.stream.ws_client import WSClient  # type: ignore[import-untyped]
from websocket import WebSocketException

from k8s_sandbox._pod.error import ContainerStoppedError, PodError
from k8s_sandbox._pod.get_returncode import (
    get_returncode,
    raise_if_stopped_before_lost,
)
from k8s_sandbox._pod.op import (
    STDIN_UNCHECKED_SIZE,
    SYSTEM_PATH,
    PodOperation,
    raise_for_known_read_write_errors,
)


class WriteFileOperation(PodOperation):
    def write_file(self, data: bytes, dst: Path) -> None:
        if len(data) > STDIN_UNCHECKED_SIZE:
            directory = self._stage(
                data, lambda command: command, raise_for_known_read_write_errors
            )
            with self._start_join_command(directory, dst) as ws_client:
                self._handle_stream_output(ws_client)
            return
        with self._start_write_command(dst, len(data)) as ws_client:
            self._write_stdin_chunked(ws_client, data)
            self._handle_stream_output(ws_client)

    @contextmanager
    def _start_join_command(
        self, directory: str, dst: Path
    ) -> Generator[WSClient, None, None]:
        staged = shlex.quote(directory)
        command = [
            "/bin/sh",
            "-c",
            f"PATH={SYSTEM_PATH}; "
            f"mkdir -p -- {shlex.quote(dst.parent.as_posix())} "
            f"&& cat -- {staged}/data > {shlex.quote(dst.as_posix())}; "
            f'returncode=$?; rm -rf -- {staged}; exit "$returncode"',
        ]
        yield from self.create_websocket_client_for_exec(
            command=command, stderr=True, stdin=True, stdout=True, binary=False
        )

    @contextmanager
    def _start_write_command(
        self, dst: Path, file_size: int
    ) -> Generator[WSClient, None, None]:
        mkdir_command = f"mkdir -p -- {shlex.quote(dst.parent.as_posix())}"
        # Use `head` with `-c <file size>` because we have no way of closing the stdin
        # stream in v4.channel.k8s.io (which means the websocket connection would never
        # close).
        head_command = f"head -c {file_size}"
        dst_quoted = shlex.quote(dst.as_posix())
        # The shell (e.g. ash) execs into the trailing `head`, whose stdout is the
        # file, so nothing holds the exec stdout pipe open. Its EOF makes the runtime
        # close stdin mid-write and `head -c N` then exits 0, silently truncating.
        # fd 3 survives the exec and keeps that pipe open.
        # https://github.com/UKGovernmentBEIS/inspect_k8s_sandbox/issues/225
        keep_stdout_open = "exec 3>&1"
        # The script runs only helpers, which are found in the system directories.
        command = [
            "/bin/sh",
            "-c",
            f"{keep_stdout_open}; PATH={SYSTEM_PATH}; "
            f"{mkdir_command} && {head_command} > {dst_quoted}",
        ]
        yield from self.create_websocket_client_for_exec(
            command=command,
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
