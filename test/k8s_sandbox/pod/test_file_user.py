"""read_file() and write_file() as a named user, without a cluster or root.

A real switch to another user needs root: Inspect's self_check tests
test_read_file_as_user and test_write_file_as_user cover that on a cluster.
"""

import asyncio
import getpass
import io
import json
import subprocess
from collections.abc import Generator
from contextlib import contextmanager
from pathlib import Path
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from inspect_ai.util import SandboxUserUnsupportedError

import k8s_sandbox._pod.op as op_module
from k8s_sandbox._error import K8sError
from k8s_sandbox._pod import execd
from k8s_sandbox._pod.error import PodError
from k8s_sandbox._pod.execute import _RUNUSER, ExecuteOperation
from k8s_sandbox._pod.read import ReadFileOperation, read_command
from k8s_sandbox._pod.write import WriteFileOperation
from k8s_sandbox._sandbox_environment import K8sSandboxEnvironment, _ResolvedConfig
from test.k8s_sandbox.pod.test_check_for_pod_restart import _k8s_pod, _make_pod
from test.k8s_sandbox.pod.test_execd import (  # noqa: F401
    Daemons,
    daemons,
    frame,
    read_frame,
)
from test.k8s_sandbox.pod.test_execute import STDOUT, _FakeWSClient, _status

ME = getpass.getuser()


# --- execd transport -----------------------------------------------------------------


async def test_execd_file_operations_start_as_the_user(daemons: Daemons) -> None:  # noqa: F811
    requests: list[dict[str, Any]] = []

    async def serves(r: asyncio.StreamReader, w: asyncio.StreamWriter) -> None:
        while True:
            kind, call_id, payload = await read_frame(r)
            if kind == execd.START:
                requests.append(json.loads(payload))
                w.write(frame(execd.STDOUT, call_id, b"data"))
                w.write(frame(execd.EXIT, call_id, b'{"code": 0}'))

    await daemons.serve(serves)
    client = daemons.client()
    out = io.BytesIO()

    await client.read_file(Path("/f"), out, "agent")
    await client.write_file(b"x", Path("/f"), "agent")
    await client.read_file(Path("/f"), io.BytesIO())

    assert out.getvalue() == b"data"
    assert [request["user"] for request in requests] == ["agent", "agent", ""]


@pytest.mark.parametrize(
    ("exit", "stderr"),
    [
        pytest.param(
            b'{"code": 1, "error": "cannot run as agent: execd is not root"}',
            b"",
            id="execd-is-not-root",
        ),
        pytest.param(
            b'{"code": 1, "error": "unknown user agent"}', b"", id="no-such-user"
        ),
        pytest.param(
            b'{"code": 126}',
            b"execd: operation not permitted\n",
            id="may-not-switch-users",
        ),
    ],
)
async def test_what_execd_refuses_for_a_user_is_an_unsupported_user(
    daemons: Daemons,  # noqa: F811
    exit: bytes,
    stderr: bytes,
) -> None:
    async def refuses(r: asyncio.StreamReader, w: asyncio.StreamWriter) -> None:
        while True:
            kind, call_id, _ = await read_frame(r)
            if kind == execd.START:
                if stderr:
                    w.write(frame(execd.STDERR, call_id, stderr))
                w.write(frame(execd.EXIT, call_id, exit))

    await daemons.serve(refuses)
    client = daemons.client()

    with pytest.raises(SandboxUserUnsupportedError):
        await client.read_file(Path("/f"), io.BytesIO(), "agent")
    with pytest.raises(SandboxUserUnsupportedError):
        await client.write_file(b"x", Path("/f"), "agent")
    # With no user asked for, the same failure is the file operation's, as before.
    with pytest.raises(PodError):
        await client.read_file(Path("/f"), io.BytesIO())


# --- Kubernetes exec transport -------------------------------------------------------


def _file_commands(
    monkeypatch: pytest.MonkeyPatch,
    path: Path,
    size: int,
    user: str | None,
    switch: bool,
) -> tuple[list[str], list[str]]:
    """The commands a write and a read of `path` start in the container."""
    commands: list[list[str]] = []

    def started(
        self: object, send_keepalive: bool = True, **kwargs: Any
    ) -> Generator[MagicMock, None, None]:
        commands.append(kwargs["command"])
        yield MagicMock()

    monkeypatch.setattr(
        op_module.PodOperation, "create_websocket_client_for_exec", started
    )
    with WriteFileOperation(MagicMock())._start_write_command(path, size, user, switch):
        pass
    with ReadFileOperation(MagicMock())._start_read_command(path, user, switch):
        pass
    return commands[0], commands[1]


def test_file_commands_start_with_runuser_once_the_probe_found_it_works(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    write, read = _file_commands(monkeypatch, Path("/f"), 1, "agent", switch=True)

    assert write[:4] == [_RUNUSER, "-u", "agent", "--"]
    assert read == [_RUNUSER, "-u", "agent", "--", *read_command(Path("/f"))]


def test_file_commands_for_no_user_are_the_plain_ones(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _, read = _file_commands(monkeypatch, Path("/f"), 1, None, switch=False)

    assert read == read_command(Path("/f"))


def test_file_commands_for_the_user_the_container_runs_as_write_and_read(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """Run here, as this user: the unprobed wrapper finds it already is them."""
    target = tmp_path / "sub" / "f"
    write, read = _file_commands(monkeypatch, target, 5, ME, switch=False)

    wrote = subprocess.run(write, input=b"hello", capture_output=True)
    got = subprocess.run(read, capture_output=True)

    assert (wrote.returncode, wrote.stderr) == (0, b"")
    assert (got.returncode, got.stdout) == (0, b"hello")


@pytest.mark.parametrize("root", ["root", "0"])
@pytest.mark.parametrize(("returncode", "switch"), [(0, False), (1, None)])
def test_a_root_user_is_one_the_container_runs_as_or_cannot(
    root: str, returncode: int, switch: bool | None
) -> None:
    """Uid 0 or nothing: `runuser` is never tried, so 1 is not "it can switch"."""
    op = ExecuteOperation(MagicMock())
    probes: list[list[str]] = []

    @contextmanager
    def fake_shell(command: list[str]) -> Generator[_FakeWSClient, None, None]:
        probes.append(command)
        yield _FakeWSClient([(STDOUT, b""), _status(returncode)])

    with patch.object(op, "_interactive_shell", fake_shell):
        answer = op.probe_switch(root)

    assert answer is switch
    assert _RUNUSER not in probes[0][2]


@pytest.mark.skipif(ME == "root", reason="Shows what a container that is not root does")
@pytest.mark.parametrize("root", ["root", "0"])
def test_a_file_command_as_root_does_nothing_in_a_container_that_is_not_root(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, root: str
) -> None:
    target = tmp_path / "f"
    write, read = _file_commands(monkeypatch, target, 5, root, switch=False)

    wrote = subprocess.run(write, input=b"hello", capture_output=True)
    got = subprocess.run(read, capture_output=True)

    assert wrote.returncode != 0 and got.returncode != 0
    assert not target.exists()


async def test_a_user_it_cannot_run_as_is_refused_before_any_file_command() -> None:
    pod = _make_pod()
    with (
        patch("k8s_sandbox._pod.op.k8s_client") as client,
        patch("k8s_sandbox._pod.pod.ExecuteOperation") as exec_op,
        patch("k8s_sandbox._pod.pod.WriteFileOperation") as write_op,
        patch("k8s_sandbox._pod.pod.ReadFileOperation") as read_op,
    ):
        client.return_value.read_namespaced_pod.return_value = _k8s_pod(
            uid="uid-OLD", container_name="default", restart_count=0
        )
        exec_op.return_value.probe_switch.side_effect = lambda user: {
            "agent": True,
            "root": False,
        }.get(user)

        with pytest.raises(SandboxUserUnsupportedError):
            await pod.write_file(b"x", Path("/f"), "ghost")
        with pytest.raises(SandboxUserUnsupportedError):
            await pod.read_file(Path("/f"), io.BytesIO(), "ghost")
        assert not write_op.return_value.write_file.called
        assert not read_op.return_value.read_file.called

        await pod.write_file(b"x", Path("/f"), "agent")
        await pod.write_file(b"x", Path("/f"), "agent")
        await pod.write_file(b"x", Path("/f"), "root")
        await pod.write_file(b"x", Path("/f"))

    calls = write_op.return_value.write_file.call_args_list
    assert [call.args[2:] for call in calls] == [
        ("agent", True),
        ("agent", True),
        ("root", False),
        (None, False),
    ]
    # Once for a user it can run as; each time for one it cannot ("ghost", twice):
    # the sample may have created them since.
    probed = [call.args[0] for call in exec_op.return_value.probe_switch.call_args_list]
    assert probed == ["ghost", "ghost", "agent", "root"]


# --- the sandbox environment ---------------------------------------------------------


def _sandbox(pod: MagicMock) -> K8sSandboxEnvironment:
    pod.info.name = "p"
    config = _ResolvedConfig(
        chart=None,
        values=None,
        context=None,
        default_user=None,
        restarted_container_behavior="warn",
        max_pod_ops=None,
    )
    return K8sSandboxEnvironment(MagicMock(), pod, config)


async def test_an_unsupported_user_reaches_inspect_as_itself_and_once() -> None:
    pod = MagicMock()
    pod.read_file = AsyncMock(side_effect=SandboxUserUnsupportedError("no"))
    pod.write_file = AsyncMock(side_effect=SandboxUserUnsupportedError("no"))
    sandbox = _sandbox(pod)

    with pytest.raises(SandboxUserUnsupportedError) as read:
        await sandbox.read_file("/f", user="agent")
    with pytest.raises(SandboxUserUnsupportedError) as wrote:
        await sandbox.write_file("/f", "x", user="agent")

    # Inspect catches the error by its own type, which a K8sError wrapper would hide.
    assert not isinstance(read.value, K8sError)
    assert not isinstance(wrote.value, K8sError)
    assert (pod.read_file.await_count, pod.write_file.await_count) == (1, 1)
    assert pod.read_file.await_args.args[2] == "agent"
    assert pod.write_file.await_args.args[2] == "agent"


def test_inspect_sees_that_file_operations_take_a_user() -> None:
    sandbox = _sandbox(MagicMock())

    assert sandbox._supports_file_user("read_file")
    assert sandbox._supports_file_user("write_file")


async def test_an_empty_user_is_refused_before_the_pod_is_asked() -> None:
    pod = MagicMock()
    pod.read_file = AsyncMock()
    pod.write_file = AsyncMock()
    sandbox = _sandbox(pod)

    with pytest.raises(SandboxUserUnsupportedError):
        await sandbox.read_file("/f", user="")
    with pytest.raises(SandboxUserUnsupportedError):
        await sandbox.write_file("/f", "x", user="")

    assert not pod.read_file.called and not pod.write_file.called
