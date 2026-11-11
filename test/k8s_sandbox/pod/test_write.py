import os
import subprocess
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Generator
from unittest.mock import MagicMock

import pytest
from kubernetes.stream.ws_client import (  # type: ignore[import-untyped]
    ERROR_CHANNEL,
    WSClient,
)
from websocket import WebSocketConnectionClosedException

import k8s_sandbox._pod.op as op_module
import k8s_sandbox._pod.write as writefile_module
from k8s_sandbox._pod.error import ContainerStoppedError, PodError
from k8s_sandbox._pod.write import WriteFileOperation
from test.k8s_sandbox.pod.test_execute import _FakeWSClient, _status


def test_write_file_writes_data_via_chunked_helper(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(op_module, "STDIN_CHUNK_SIZE", 4)
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


@pytest.mark.parametrize(
    "lost",
    [ConnectionResetError(), WebSocketConnectionClosedException()],
    ids=["reset", "closed"],
)
@pytest.mark.parametrize(
    ("frames", "stopped"),
    [
        ([_status(255)], True),
        ([_status(2)], False),
        # As for an exec into a dead container: no exit code, nor even `details`.
        ([(ERROR_CHANNEL, b'{"status":"Failure","reason":"InternalError"}')], False),
        ([], False),
    ],
    ids=["255", "another-status", "no-exit-code", "no-status"],
)
def test_a_255_before_the_connection_is_lost_is_a_stopped_container(
    frames: list[tuple[int, bytes]], stopped: bool, lost: Exception
) -> None:
    ws = _FakeWSClient(frames, error=lost)

    with pytest.raises(Exception) as raised:
        WriteFileOperation(MagicMock())._handle_stream_output(ws)

    assert type(raised.value) is (ContainerStoppedError if stopped else type(lost))


@pytest.mark.skipif(os.name != "posix", reason="Requires a POSIX shell")
def test_a_directory_that_looks_like_an_option_is_made(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    op = WriteFileOperation(MagicMock())
    exec_kwargs: dict[str, Any] = {}

    def fake_exec(**kwargs: Any) -> Generator[MagicMock, None, None]:
        exec_kwargs.update(kwargs)
        yield MagicMock(spec=WSClient)

    monkeypatch.setattr(op, "create_websocket_client_for_exec", fake_exec)
    with op._start_write_command(Path("-dir/dst"), 4):
        pass

    subprocess.run(
        exec_kwargs["command"],
        input=b"data",
        cwd=tmp_path,
        capture_output=True,
        timeout=30,
    )

    assert (tmp_path / "-dir" / "dst").read_bytes() == b"data"


@pytest.mark.skipif(os.name != "posix", reason="Requires a POSIX shell")
def test_mkdir_and_head_are_not_found_through_the_path(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """They run as the container's user."""
    ran = tmp_path / "ran"
    stubs = tmp_path / "stubs"
    stubs.mkdir()
    for name in ("mkdir", "head"):
        stub = stubs / name
        stub.write_text(f"#!/bin/sh\necho {name} >> {ran}\n")
        stub.chmod(0o755)
    op = WriteFileOperation(MagicMock())
    exec_kwargs: dict[str, Any] = {}

    def fake_exec(**kwargs: Any) -> Generator[MagicMock, None, None]:
        exec_kwargs.update(kwargs)
        yield MagicMock(spec=WSClient)

    monkeypatch.setattr(op, "create_websocket_client_for_exec", fake_exec)
    dst = tmp_path / "new" / "dir" / "dst"
    with op._start_write_command(dst, 4):
        pass
    env = {**os.environ, "PATH": f"{stubs}:{os.environ['PATH']}"}

    subprocess.run(
        exec_kwargs["command"], input=b"data", env=env, capture_output=True, timeout=30
    )

    assert not ran.exists()
    assert dst.read_bytes() == b"data"
