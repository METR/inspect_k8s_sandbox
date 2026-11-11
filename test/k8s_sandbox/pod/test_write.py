from contextlib import contextmanager
from pathlib import Path
from typing import Generator
from unittest.mock import MagicMock

import pytest
from kubernetes.stream.ws_client import WSClient  # type: ignore[import-untyped]

import k8s_sandbox._pod.op as op_module
import k8s_sandbox._pod.write as writefile_module
from k8s_sandbox._pod.error import ContainerStoppedError, PodError
from k8s_sandbox._pod.write import WriteFileOperation


def test_write_file_writes_data_via_chunked_helper(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(op_module, "_STDIN_CHUNK_SIZE", 4)
    op = WriteFileOperation(MagicMock())
    ws = MagicMock(spec=WSClient)
    captured: dict[str, int] = {}

    @contextmanager
    def fake_start_write_command(
        dst: Path, file_size: int
    ) -> Generator[MagicMock, None, None]:
        captured["file_size"] = file_size
        yield ws

    monkeypatch.setattr(op, "_start_write_command", fake_start_write_command)
    monkeypatch.setattr(op, "_handle_stream_output", lambda ws_client: None)
    data = b"abcdefghij"

    op.write_file(data, Path("/tmp/dst"))

    assert captured["file_size"] == len(data)
    assert b"".join(call.args[0] for call in ws.write_stdin.call_args_list) == data
    assert ws.write_stdin.call_count > 1


@pytest.mark.parametrize(
    ("returncode", "error"),
    [
        # `head` and `mkdir` never exit 255: Kata's status for a stopped VM.
        pytest.param(255, ContainerStoppedError, id="container-stopped"),
        pytest.param(2, PodError, id="failed"),
    ],
)
def test_a_255_is_a_stopped_container(
    monkeypatch: pytest.MonkeyPatch, returncode: int, error: type[Exception]
) -> None:
    monkeypatch.setattr(writefile_module, "get_returncode", lambda _ws: returncode)
    op = WriteFileOperation(MagicMock())
    ws = MagicMock(spec=WSClient)
    ws.is_open.return_value = False
    ws.read_stderr.return_value = ""

    with pytest.raises(error) as raised:
        op._handle_stream_output(ws)

    assert type(raised.value) is error
