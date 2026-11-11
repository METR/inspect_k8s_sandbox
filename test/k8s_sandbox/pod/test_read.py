import io
from pathlib import Path
from typing import Any, Generator
from unittest.mock import MagicMock

import pytest
from kubernetes.stream.ws_client import WSClient  # type: ignore[import-untyped]

import k8s_sandbox._pod.read as readfile_module
from k8s_sandbox._pod.error import ContainerStoppedError, PodError
from k8s_sandbox._pod.read import ReadFileOperation


def test_read_file_opens_stdin(monkeypatch: pytest.MonkeyPatch) -> None:
    # A read exec without stdin hangs or truncates on Kata Containers' Go shim
    # (kata-containers/kata-containers#9071).
    op = ReadFileOperation(MagicMock())
    exec_kwargs: dict[str, Any] = {}

    def fake_exec(**kwargs: Any) -> Generator[MagicMock, None, None]:
        exec_kwargs.update(kwargs)
        yield MagicMock(spec=WSClient)

    monkeypatch.setattr(op, "create_websocket_client_for_exec", fake_exec)
    monkeypatch.setattr(op, "_handle_stream_output", lambda ws_client, dst: None)

    op.read_file(Path("/tmp/src"), io.BytesIO())

    assert exec_kwargs["stdin"] is True
    assert exec_kwargs["command"][-1] == "/tmp/src"


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
    monkeypatch.setattr(readfile_module, "get_returncode", lambda _ws: returncode)
    op = ReadFileOperation(MagicMock())
    ws = MagicMock(spec=WSClient)
    ws.is_open.return_value = False
    ws.read_stderr.return_value = ""

    with pytest.raises(error) as raised:
        op._handle_stream_output(ws, io.BytesIO())

    assert type(raised.value) is error
