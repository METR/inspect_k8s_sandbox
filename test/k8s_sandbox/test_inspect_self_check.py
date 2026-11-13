import asyncio
from typing import AsyncGenerator

import pytest
import pytest_asyncio
from inspect_ai.util._sandbox.self_check import *  # noqa: F401, F403

from k8s_sandbox._sandbox_environment import K8sSandboxEnvironment
from test.k8s_sandbox.utils import install_sandbox_environments

pytestmark = pytest.mark.req_k8s

# Known failures per sandbox, applied as strict xfails in the sandbox_env fixture
# (keyed on the running check's function name). Strict means a check that starts
# passing here is surfaced rather than silently ignored.
_ROOT_XFAILS = {
    # Running as a nonexistent user raises (by design) instead of returning a
    # failed ExecResult, which is what the check expects.
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


@pytest.fixture(scope="module", params=["exec", "execd"])
def transport(request: pytest.FixtureRequest) -> str:
    return request.param


@pytest_asyncio.fixture(scope="module")
async def sandboxes(
    transport: str,
) -> AsyncGenerator[dict[str, K8sSandboxEnvironment], None]:
    values = "values.yaml" if transport == "exec" else "execd-values.yaml"
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
    # Only execd tags what it starts.
    result = await sandbox_env.exec(["sh", "-c", "echo ${HAWK_NEXT_EXEC:+execd}"])
    assert result.success, result.stderr
    assert ("execd" in result.stdout) == (transport == "execd"), result.stdout


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
    await root.exec(["sh", "-c", hide])

    result = await root.exec(
        ["id", "-un"], env={"PATH": "/tmp/roots:/usr/bin"}, user="nobody"
    )

    assert result.stdout == "nobody\n", result


async def test_a_kill_reaches_what_another_users_command_detached(
    transport: str, sandboxes: dict[str, K8sSandboxEnvironment]
) -> None:
    if transport == "exec":
        pytest.skip("Kubernetes exec leaves what a command started running")
    root = sandboxes["default"]
    # setsid takes it out of the process group a kill signals.
    detach = "setsid sh -c 'echo $$ > /tmp/detached; kill -STOP $$' & wait"
    command = asyncio.ensure_future(root.exec(["sh", "-c", detach], user="nobody"))

    async def detached() -> str:
        while not (pid := (await root.exec(["cat", "/tmp/detached"])).stdout):
            await asyncio.sleep(0.1)
        return pid.strip()

    pid = await asyncio.wait_for(detached(), 30)
    command.cancel()

    async def gone() -> None:
        while (await root.exec(["test", "-e", f"/proc/{pid}"])).success:
            await asyncio.sleep(0.1)

    # Without CAP_SYS_PTRACE root can't read the user's environment for the call's tag.
    await asyncio.wait_for(gone(), 30)
