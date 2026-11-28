import asyncio
import pathlib
from typing import AsyncGenerator

import pytest
import pytest_asyncio
from inspect_ai.util._sandbox.self_check import *  # noqa: F401, F403

from k8s_sandbox import _sandbox_environment
from k8s_sandbox._sandbox_environment import K8sSandboxEnvironment
from test.k8s_sandbox.utils import install_sandbox_environments

pytestmark = pytest.mark.req_k8s

# Known failures per sandbox, applied as strict xfails in the sandbox_env fixture
# (keyed on the running check's function name). Strict means a check that starts
# passing here is surfaced rather than silently ignored.
_ROOT_XFAILS = {
    # A nonexistent user raises a K8sError (by design), which the check does not accept.
    "test_exec_as_nonexistent_user": "k8s raises for a nonexistent user",
    # Root can read/write regardless of the permission bits.
    "test_read_file_not_allowed": "root can read after chmod -r",
    "test_write_text_file_without_permissions": "root can write after chmod -w",
    "test_write_binary_file_without_permissions": "root can write after chmod -w",
}
_NON_ROOT_XFAILS = {
    "test_exec_as_nonexistent_user": "k8s raises for a nonexistent user",
    # In k8s the container must run as root to exec as a different user.
    "test_exec_as_user": "container must run as root to exec as a different user",
}
# Non-strict: the drop is environment-dependent (fails on one minikube at
# ~40-44 MiB, passes on another at 50 MiB), so an XPASS is not a signal.
_NONSTRICT_XFAILS = {
    "test_exec_input_large": "large stdin can be silently dropped, see #244",
}


@pytest.fixture(scope="module", params=["exec", "execd", "execd-stdio"])
def transport(request: pytest.FixtureRequest) -> str:
    return request.param


@pytest_asyncio.fixture(scope="module")
async def sandboxes(
    transport: str, tmp_path_factory: pytest.TempPathFactory
) -> AsyncGenerator[dict[str, K8sSandboxEnvironment], None]:
    values = "values.yaml" if transport == "exec" else "execd-values.yaml"
    if transport == "execd-stdio":  # the same pods, reached as one with no network card
        on_tcp = (pathlib.Path(__file__).parent / "resources" / values).read_text()
        stdio = tmp_path_factory.mktemp("values") / values
        stdio.write_text(on_tcp.replace('/execd: "true"', '/execd: "stdio"'))
        values = str(stdio)
    async with install_sandbox_environments(__file__, values) as envs:
        yield envs


@pytest_asyncio.fixture(
    params=[("default", _ROOT_XFAILS), ("nonroot", _NON_ROOT_XFAILS)],
    ids=["root", "non-root"],
)
async def sandbox_env(
    request: pytest.FixtureRequest,
    transport: str,
    sandboxes: dict[str, K8sSandboxEnvironment],
) -> K8sSandboxEnvironment:
    key, xfails = request.param
    reason = xfails.get(request.node.originalname)
    if reason is not None:
        request.node.add_marker(pytest.mark.xfail(reason=reason, strict=True))
    nonstrict_reason = _NONSTRICT_XFAILS.get(request.node.originalname)
    if nonstrict_reason is not None and transport == "exec":  # execd must keep it all
        request.node.add_marker(
            pytest.mark.xfail(reason=nonstrict_reason, strict=False)
        )
    return sandboxes[key]


async def test_annotation_picks_transport(
    transport: str, sandbox_env: K8sSandboxEnvironment
) -> None:
    # execd starts a command itself; Kubernetes exec starts it from a shell.
    result = await sandbox_env.exec(["sh", "-c", "cat /proc/$PPID/cmdline"])
    assert result.success, result.stderr
    assert ("execd" in result.stdout) == (transport != "exec"), result.stdout
    assert ("--socket" in result.stdout) == (transport == "execd-stdio"), result.stdout


async def test_a_script_with_no_interpreter_line_runs(
    sandbox_env: K8sSandboxEnvironment,
) -> None:
    await sandbox_env.write_file("/tmp/seven", "exit 7\n")
    await sandbox_env.exec(["chmod", "+x", "/tmp/seven"])

    result = await sandbox_env.exec(["/tmp/seven"])

    assert result.returncode == 7, result


async def test_a_command_is_found_on_the_path_as_its_user(
    sandboxes: dict[str, K8sSandboxEnvironment],
) -> None:
    root = sandboxes["default"]
    # Root finds this `id` first; the user can't enter its directory.
    hide = "mkdir -m 700 /tmp/roots && cp /bin/false /tmp/roots/id"
    assert (await root.exec(["sh", "-c", hide])).success

    result = await root.exec(
        ["id", "-un"], env={"PATH": "/tmp/roots:/usr/bin"}, user="nobody"
    )

    assert result.stdout == "nobody\n", result


@pytest.mark.parametrize("service", ["default", "runc"])  # on gVisor, and on Linux
async def test_a_kill_reaches_what_another_users_command_detached(
    transport: str,
    sandboxes: dict[str, _sandbox_environment.K8sSandboxEnvironment],
    service: str,
) -> None:
    if transport == "exec":
        pytest.skip("Kubernetes exec leaves what a command started running")
    root = sandboxes[service]
    # Out of the group a kill signals, its parent gone: only the tag leads a kill to it.
    orphan = "while kill -0 $PPID 2>/dev/null; do :; done; echo $$ > /tmp/detached"
    detach = f"(setsid sh -c '{orphan}; kill -STOP $$' &); sleep 600"
    command = asyncio.ensure_future(root.exec(["sh", "-c", detach], user="nobody"))

    async def detached() -> str:
        while not (pid := (await root.exec(["cat", "/tmp/detached"])).stdout):
            await asyncio.sleep(0.1)
        return pid.strip()

    async def gone() -> None:
        while (await root.exec(["test", "-e", f"/proc/{pid}"])).success:
            await asyncio.sleep(0.1)

    left = "kill -9 $(cat /tmp/detached); "  # what a failed run leaves
    try:
        pid = await asyncio.wait_for(detached(), 30)
        command.cancel()

        # Without CAP_SYS_PTRACE root can't read the user's environment for its tag.
        await asyncio.wait_for(gone(), 30)
        left = ""
    finally:
        command.cancel()
        await root.exec(["sh", "-c", left + "rm -f /tmp/detached"])
