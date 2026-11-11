import io
import os
import subprocess
from pathlib import Path
from typing import Any, Generator
from unittest.mock import MagicMock

import pytest
from kubernetes.stream.ws_client import WSClient  # type: ignore[import-untyped]

from k8s_sandbox._pod.read import ReadFileOperation


def _exec_kwargs(monkeypatch: pytest.MonkeyPatch, src: Path) -> dict[str, Any]:
    """The arguments read_file() opens its exec with."""
    op = ReadFileOperation(MagicMock())
    exec_kwargs: dict[str, Any] = {}

    def fake_exec(**kwargs: Any) -> Generator[MagicMock, None, None]:
        exec_kwargs.update(kwargs)
        yield MagicMock(spec=WSClient)

    monkeypatch.setattr(op, "create_websocket_client_for_exec", fake_exec)
    monkeypatch.setattr(op, "_handle_stream_output", lambda ws_client, dst: None)

    op.read_file(src, io.BytesIO())
    return exec_kwargs


def test_read_file_opens_stdin(monkeypatch: pytest.MonkeyPatch) -> None:
    # A read exec without stdin hangs or truncates on Kata Containers' Go shim
    # (kata-containers/kata-containers#9071).
    exec_kwargs = _exec_kwargs(monkeypatch, Path("/tmp/src"))

    assert exec_kwargs["stdin"] is True
    assert exec_kwargs["command"][-1] == "/tmp/src"


@pytest.mark.skipif(os.name != "posix", reason="Requires a POSIX shell")
def test_head_is_not_found_through_the_path(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """It runs as the container's user."""
    ran = tmp_path / "ran"
    stub = tmp_path / "head"
    stub.write_text(f"#!/bin/sh\necho head >> {ran}\n")
    stub.chmod(0o755)
    src = tmp_path / "src"
    src.write_bytes(b"contents")
    command = _exec_kwargs(monkeypatch, src)["command"]
    env = {**os.environ, "PATH": f"{tmp_path}:{os.environ['PATH']}"}

    result = subprocess.run(command, env=env, capture_output=True, timeout=30)

    assert not ran.exists()
    assert result.stdout == b"contents"
