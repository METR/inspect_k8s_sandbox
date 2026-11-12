"""Stdin over 32 KiB is staged in hash-checked pieces of at most 64 KiB, one exec each.

AWS Nitro Sandboxes can swap an exec's stdin in 32 KiB chunks; see STDIN_UNCHECKED_SIZE.
These tests pin the hazard's boundary as the literal 64 KiB, not the module constant, so
raising the constant fails them.
"""

import hashlib
import os
import re
import shlex
import shutil
import subprocess
from collections import Counter
from contextlib import contextmanager
from pathlib import Path
from typing import Callable, Generator
from unittest.mock import MagicMock

import pytest
from inspect_ai.util import ExecResult
from kubernetes.stream.ws_client import WSClient  # type: ignore[import-untyped]

import k8s_sandbox._pod.execute as execute_module
import k8s_sandbox._pod.op as op_module
from k8s_sandbox._pod.error import ContainerStoppedError, PodError
from k8s_sandbox._pod.execute import ExecuteOperation, _shell_command
from k8s_sandbox._pod.op import raise_for_known_read_write_errors
from k8s_sandbox._pod.write import WriteFileOperation
from test.k8s_sandbox.pod.test_execute import _SHELLS, MARKER

UNCHECKED = (
    32 * 1024
)  # The most stdin sent unstaged: one chunk, which cannot be swapped.
PIECE = 64 * 1024  # The most stdin one staging exec sends.


class _FakeContainer:
    """Runs _stage's piece and join scripts against an in-memory filesystem."""

    def __init__(
        self,
        corrupt: Callable[[str, int], bool] = lambda name, attempt: False,
        corrupt_join: bool = False,
    ) -> None:
        self.files: dict[str, dict[str, bytes]] = {}
        self.commands: list[list[str]] = []
        self.frames: list[int] = []
        self.attempts: Counter[str] = Counter()
        self._corrupt = corrupt
        self._corrupt_join = corrupt_join

    def run_piece(
        self,
        as_user: Callable[[list[str]], list[str]],
        script: str,
        piece: bytes,
        check: Callable[[str], None],
    ) -> tuple[str, str]:
        self.commands.append(as_user(["/bin/sh", "-c", script]))
        self.frames.append(len(piece))
        write = re.fullmatch(
            r'd=(\$\(mktemp -d\)|\S+) && head -c (\d+) > "\$d/(\w+)" && echo "\$d" '
            r'&& sha256sum < "\$d/\w+"',
            script,
        )
        if write:
            into, size, name = write.groups()
            directory = (
                f"/tmp/tmp.{len(self.files)}"
                if into == "$(mktemp -d)"
                else shlex.split(into)[0]
            )
            assert int(size) == len(piece)
            self.attempts[name] += 1
            kept = (
                piece[1:] + piece[:1]
                if self._corrupt(name, self.attempts[name])
                else piece
            )
            self.files.setdefault(directory, {})[name] = kept
            return directory, hashlib.sha256(kept).hexdigest()
        join = re.fullmatch(
            r'd=(\S+) && cat "\$d"/0\* > "\$d/data" && rm -f "\$d"/0\* '
            r'&& echo "\$d" && sha256sum < "\$d/data"',
            script,
        )
        assert join, script
        directory = shlex.split(join.group(1))[0]
        files = self.files[directory]
        # The shell's glob sorts names; only the pieces' names start with "0".
        joined = b"".join(files[name] for name in sorted(files) if name.startswith("0"))
        if self._corrupt_join:
            joined = joined[::-1]
        self.files[directory] = {"data": joined}
        return directory, hashlib.sha256(joined).hexdigest()


def _stage(data: bytes, container: _FakeContainer) -> str:
    op = WriteFileOperation(MagicMock())
    op._run_piece = container.run_piece  # type: ignore[method-assign]
    return op._stage(data, lambda command: command, lambda stderr: None)


class TestStage:
    def test_every_piece_is_one_exec_of_at_most_64_kib(self) -> None:
        # Eleven pieces or more, so a glob over unpadded names would join out of order.
        data = os.urandom(11 * PIECE + 123)
        container = _FakeContainer()

        directory = _stage(data, container)

        assert container.files[directory] == {"data": data}
        assert max(container.frames) <= PIECE
        assert sum(container.frames) == len(data)
        # One exec per piece, plus the join (which sends no stdin).
        assert len(container.commands) == 12 + 1
        assert container.frames[-1] == 0

    def test_a_corrupted_piece_is_sent_again(self) -> None:
        data = os.urandom(3 * PIECE)
        container = _FakeContainer(
            corrupt=lambda name, n: name == "00000001" and n == 1
        )

        directory = _stage(data, container)

        assert container.files[directory] == {"data": data}
        assert container.attempts == {"00000000": 1, "00000001": 2, "00000002": 1}

    def test_a_piece_corrupted_every_time_is_an_error(self) -> None:
        container = _FakeContainer(corrupt=lambda name, n: name == "00000001")

        with pytest.raises(PodError, match="corrupted 3 times"):
            _stage(os.urandom(2 * PIECE + 1), container)

        assert container.attempts["00000001"] == 3

    def test_a_join_that_comes_back_different_is_an_error(self) -> None:
        with pytest.raises(PodError, match="joined corrupted"):
            _stage(os.urandom(2 * PIECE + 1), _FakeContainer(corrupt_join=True))

    @pytest.mark.skipif(
        shutil.which("sha256sum") is None or shutil.which("mktemp") is None,
        reason="Needs the container's helpers (Linux)",
    )
    def test_the_scripts_run_in_a_real_shell(self) -> None:
        data = os.urandom(3 * PIECE + 7)
        sent: list[int] = []

        def run_piece(
            as_user: Callable[[list[str]], list[str]],
            script: str,
            piece: bytes,
            check: Callable[[str], None],
        ) -> tuple[str, str]:
            sent.append(len(piece))
            command = as_user(["/bin/sh", "-c", script])
            done = subprocess.run(command, input=piece, capture_output=True, check=True)
            directory, digest = done.stdout.decode().split()[:2]
            return directory, digest

        op = WriteFileOperation(MagicMock())
        op._run_piece = run_piece  # type: ignore[method-assign]
        directory = op._stage(data, lambda command: command, lambda stderr: None)
        try:
            assert Path(directory, "data").read_bytes() == data
            assert sorted(p.name for p in Path(directory).iterdir()) == ["data"]
            assert max(sent) <= PIECE
        finally:
            shutil.rmtree(directory)


class TestRunPiece:
    def _op_with_ws(self, ws: MagicMock) -> WriteFileOperation:
        op = WriteFileOperation(MagicMock())

        def create(**kwargs: object) -> Generator[MagicMock, None, None]:
            yield ws

        op.create_websocket_client_for_exec = create  # type: ignore[assignment,method-assign]
        return op

    def test_the_piece_goes_in_one_frame(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(op_module, "get_returncode", lambda ws: 0)
        ws = MagicMock(spec=WSClient)
        ws.read_stdout.return_value = "/tmp/tmp.x\n" + "ab" * 32 + "  -\n"
        piece = os.urandom(PIECE)

        result = self._op_with_ws(ws)._run_piece(
            lambda c: c, "true", piece, lambda stderr: None
        )

        assert result == ("/tmp/tmp.x", "ab" * 32)
        assert [call.args[0] for call in ws.write_stdin.call_args_list] == [piece]

    @pytest.mark.parametrize(
        ("returncode", "stderr", "error"),
        [
            (255, "", ContainerStoppedError),
            # The caller's check raises its own error for a failure it knows.
            (1, "head: /x: Permission denied", PermissionError),
            (1, "something else", PodError),
        ],
    )
    def test_a_failed_exec_raises(
        self,
        monkeypatch: pytest.MonkeyPatch,
        returncode: int,
        stderr: str,
        error: type[Exception],
    ) -> None:
        monkeypatch.setattr(op_module, "get_returncode", lambda ws: returncode)
        ws = MagicMock(spec=WSClient)
        ws.read_stderr.return_value = stderr

        with pytest.raises(error):
            self._op_with_ws(ws)._run_piece(
                lambda c: c, "true", b"x", raise_for_known_read_write_errors
            )


class TestWriteFile:
    @pytest.mark.parametrize("size", [0, 1, UNCHECKED])
    def test_up_to_32_kib_is_one_exec_as_before(
        self, monkeypatch: pytest.MonkeyPatch, size: int
    ) -> None:
        op = WriteFileOperation(MagicMock())
        ws = MagicMock(spec=WSClient)

        @contextmanager
        def start(dst: Path, file_size: int) -> Generator[MagicMock, None, None]:
            yield ws

        def no_stage(*args: object) -> str:
            raise AssertionError("staged")

        monkeypatch.setattr(op, "_start_write_command", start)
        monkeypatch.setattr(op, "_handle_stream_output", lambda ws_client: None)
        monkeypatch.setattr(op, "_stage", no_stage)

        op.write_file(b"x" * size, Path("/tmp/dst"))

        assert b"".join(c.args[0] for c in ws.write_stdin.call_args_list) == b"x" * size

    def test_over_32_kib_is_staged_then_joined_into_the_file(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        data = os.urandom(UNCHECKED + 1)
        container = _FakeContainer()
        op = WriteFileOperation(MagicMock())
        op._run_piece = container.run_piece  # type: ignore[method-assign]
        joined: list[tuple[str, Path]] = []

        @contextmanager
        def join(directory: str, dst: Path) -> Generator[MagicMock, None, None]:
            joined.append((directory, dst))
            yield MagicMock(spec=WSClient)

        def no_write(*args: object) -> None:
            raise AssertionError("written whole")

        monkeypatch.setattr(op, "_start_join_command", join)
        monkeypatch.setattr(op, "_handle_stream_output", lambda ws_client: None)
        monkeypatch.setattr(op, "_start_write_command", no_write)

        op.write_file(data, Path("/home/agent/dst"))

        [(directory, dst)] = joined
        assert dst == Path("/home/agent/dst")
        assert container.files[directory] == {"data": data}
        assert max(container.frames) <= PIECE

    def test_a_failed_stage_raises_the_file_error(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        op = WriteFileOperation(MagicMock())
        ws = MagicMock(spec=WSClient)
        ws.read_stderr.return_value = "mktemp: /tmp/tmp.X: Permission denied"

        def create(**kwargs: object) -> Generator[MagicMock, None, None]:
            yield ws

        monkeypatch.setattr(op_module, "get_returncode", lambda ws: 1)
        monkeypatch.setattr(op, "create_websocket_client_for_exec", create)

        with pytest.raises(PermissionError):
            op.write_file(os.urandom(UNCHECKED + 1), Path("/tmp/dst"))

    def test_the_join_command_writes_dst_and_removes_the_stage(self) -> None:
        op = WriteFileOperation(MagicMock())
        captured: dict[str, object] = {}

        def create(**kwargs: object) -> Generator[MagicMock, None, None]:
            captured.update(kwargs)
            yield MagicMock(spec=WSClient)

        op.create_websocket_client_for_exec = create  # type: ignore[assignment,method-assign]
        with op._start_join_command("/tmp/tmp.x", Path("/a b/dst")):
            pass

        script = captured["command"][-1]  # type: ignore[index]
        assert "mkdir -p -- '/a b' && cat -- /tmp/tmp.x/data > '/a b/dst'" in script
        assert 'rm -rf -- /tmp/tmp.x; exit "$returncode"' in script


class TestExec:
    def _exec(
        self,
        monkeypatch: pytest.MonkeyPatch,
        stdin: bytes | None,
        user: str | None = None,
        staged: str = "/tmp/tmp.x",
    ) -> tuple[str, list[list[str]], list[bytes]]:
        ws = MagicMock(spec=WSClient)
        shells: list[list[str]] = []
        stages: list[bytes] = []
        wrapped: list[list[str]] = []

        @contextmanager
        def shell(command: list[str]) -> Generator[MagicMock, None, None]:
            shells.append(command)
            yield ws

        def stage(
            data: bytes,
            as_user: Callable[[list[str]], list[str]],
            check: Callable[[str], None],
        ) -> str:
            stages.append(data)
            wrapped.append(as_user(["/bin/sh", "-c", "piece"]))
            return staged

        op = ExecuteOperation(MagicMock())
        monkeypatch.setattr(op, "_interactive_shell", shell)
        monkeypatch.setattr(op, "_stage", stage)
        monkeypatch.setattr(
            execute_module.secrets, "token_hex", lambda n: MARKER.split("-")[-2]
        )
        sentinel = ExecResult(success=True, returncode=0, stdout="", stderr="")
        monkeypatch.setattr(op, "_handle_shell_output", lambda *a, **k: sentinel)

        op.exec(["cat"], stdin=stdin, cwd=None, env={}, user=user, timeout=None)

        written = "".join(c.args[0] for c in ws.write_stdin.call_args_list)
        return written, wrapped, stages

    def test_a_small_script_is_written_to_the_shell_as_before(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        written, _, stages = self._exec(monkeypatch, b"x" * 1024)

        assert stages == []
        assert "base64 -d" in written

    def test_a_script_over_32_kib_is_staged_and_the_shell_gets_a_loader(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # 24 KiB of input is 32 KiB in base64, so the script passes 32 KiB.
        stdin = os.urandom(24 * 1024)
        written, _, stages = self._exec(monkeypatch, stdin)

        script = ExecuteOperation(MagicMock())._build_shell_script(
            ["cat"], stdin, None, {}, None, MARKER
        )
        assert stages == [script.encode()]
        assert len(written.encode()) <= UNCHECKED
        assert written == '{\ntrap "rm -rf -- /tmp/tmp.x" EXIT\n. /tmp/tmp.x/data\n}\n'

    @pytest.mark.parametrize(
        ("user", "wrap"),
        [
            (None, ["/bin/sh", "-c", "piece"]),
            ("root", ["/bin/sh", "-c", "piece"]),
            ("agent", _shell_command("agent", command=["/bin/sh", "-c", "piece"])),
        ],
        ids=["default", "root", "agent"],
    )
    def test_the_stage_is_written_as_the_execs_user(
        self, monkeypatch: pytest.MonkeyPatch, user: str | None, wrap: list[str]
    ) -> None:
        _, wrapped, _ = self._exec(monkeypatch, os.urandom(UNCHECKED), user=user)

        assert wrapped == [wrap]

    @pytest.mark.parametrize(
        ("user", "stderr", "error"),
        [
            ("ghost", "runuser: user ghost does not exist", RuntimeError),
            # Not FileNotFoundError: that is write_file's, for its destination.
            (None, "mktemp: /nope/tmp.X: No such file or directory", PodError),
        ],
    )
    def test_a_failed_stage_raises_what_the_shell_would_have(
        self,
        monkeypatch: pytest.MonkeyPatch,
        user: str | None,
        stderr: str,
        error: type[Exception],
    ) -> None:
        op = ExecuteOperation(MagicMock())
        ws = MagicMock(spec=WSClient)
        ws.read_stderr.return_value = stderr

        def create(**kwargs: object) -> Generator[MagicMock, None, None]:
            yield ws

        @contextmanager
        def no_shell(command: list[str]) -> Generator[MagicMock, None, None]:
            raise AssertionError("ran the shell")
            yield

        monkeypatch.setattr(op_module, "get_returncode", lambda ws: 1)
        monkeypatch.setattr(op, "create_websocket_client_for_exec", create)
        monkeypatch.setattr(op, "_interactive_shell", no_shell)

        with pytest.raises(error) as raised:
            op.exec(
                ["cat"],
                os.urandom(UNCHECKED),
                cwd=None,
                env={},
                user=user,
                timeout=None,
            )
        assert type(raised.value) is error

    @pytest.mark.skipif(os.name != "posix", reason="Requires a POSIX shell")
    @pytest.mark.parametrize("shell", _SHELLS)
    def test_the_loader_runs_the_staged_script_and_removes_it(
        self, monkeypatch: pytest.MonkeyPatch, shell: list[str], tmp_path: Path
    ) -> None:
        stdin = os.urandom(100 * 1024)
        stage = tmp_path / "stage"
        stage.mkdir()
        script = ExecuteOperation(MagicMock())._build_shell_script(
            ["sh", "-c", "cat > out; exit 3"], stdin, str(tmp_path), {}, None, MARKER
        )
        (stage / "data").write_text(script)
        loader, _, _ = self._exec(monkeypatch, stdin, staged=str(stage))

        result = subprocess.run(shell, input=loader.encode(), capture_output=True)

        assert result.returncode == 3
        assert (tmp_path / "out").read_bytes() == stdin
        assert result.stdout.endswith(f"{MARKER}3>".encode())
        assert not stage.exists()
