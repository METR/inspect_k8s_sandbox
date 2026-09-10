import asyncio
import logging
from dataclasses import dataclass, field
from unittest.mock import AsyncMock

import anyio
import pytest

from k8s_sandbox import K8sSandboxEnvironment, _helm, _sandbox_environment
from k8s_sandbox._helm import Release, ValuesSource
from k8s_sandbox._manager import HelmReleaseManager
from k8s_sandbox._pod import Pod


@dataclass
class _Cluster:
    manager: HelmReleaseManager = field(default_factory=HelmReleaseManager)
    installed: list[Release] = field(default_factory=list)
    deleted: list[Release] = field(default_factory=list)
    install_started: asyncio.Event = field(default_factory=asyncio.Event)
    cleanup_started: asyncio.Event = field(default_factory=asyncio.Event)
    install_wait: asyncio.Event | None = None
    cleanup_wait: asyncio.Event | None = None
    install_error: Exception | None = None
    cleanup_error: Exception | None = None
    install_cleanup: list[bool] = field(default_factory=list)


@pytest.fixture
def cluster(monkeypatch: pytest.MonkeyPatch) -> _Cluster:
    result = _Cluster()
    monkeypatch.setattr(_helm, "get_default_namespace", lambda _: "test-namespace")
    monkeypatch.setattr(_sandbox_environment, "validate_prereqs", AsyncMock())
    monkeypatch.setattr(
        _sandbox_environment.PodOpExecutor, "get_instance", lambda **_: None
    )
    monkeypatch.setattr(K8sSandboxEnvironment, "_adjust_rlimit", lambda _: None)
    monkeypatch.setattr(HelmReleaseManager, "get_instance", lambda: result.manager)

    async def install(release: Release, *, cleanup_on_cancel: bool = True) -> None:
        result.installed.append(release)
        result.install_cleanup.append(cleanup_on_cancel)
        result.install_started.set()
        if result.install_wait is not None:
            await result.install_wait.wait()
        if result.install_error is not None:
            raise result.install_error

    async def uninstall(release: Release, quiet: bool) -> None:
        result.cleanup_started.set()
        if result.cleanup_wait is not None:
            await result.cleanup_wait.wait()
        if result.cleanup_error is not None:
            raise result.cleanup_error
        result.deleted.append(release)

    async def pods(release: Release) -> dict[str, Pod]:
        return {
            name: Pod(
                name=f"{release.release_name}-{name}-0",
                namespace=release.namespace,
                context_name=None,
                default_container_name=name,
                uid=f"{release.release_name}-{name}-uid",
                initial_restart_count=0,
                restarted_container_behavior="raise",
            )
            for name in ("auxiliary", "default")
        }

    monkeypatch.setattr(Release, "install", install)
    monkeypatch.setattr(Release, "uninstall", uninstall)
    monkeypatch.setattr(Release, "get_sandbox_pods", pods)
    return result


async def test_repeated_contexts_delete_only_their_own_release(
    cluster: _Cluster,
) -> None:
    parent = Release("agent-task", None, ValuesSource.none(), None)
    await cluster.manager.install(parent)
    releases = []

    for _ in range(2):
        async with K8sSandboxEnvironment.create("grading", None, {}) as environments:
            assert list(environments) == ["default", "auxiliary"]
            sandbox = environments["default"].as_type(K8sSandboxEnvironment)
            releases.append(sandbox.release)
            assert sandbox.release.task_name == "grading"
            assert sandbox.release in cluster.manager._installed_releases
            assert sandbox.release not in cluster.deleted
            assert parent in cluster.manager._installed_releases
        assert sandbox.release in cluster.deleted
        assert cluster.manager._installed_releases == [parent]

    assert releases[0].release_name != releases[1].release_name
    assert parent not in cluster.deleted
    assert cluster.install_cleanup == [True, False, False]


async def test_installation_failure_is_cleaned_up(cluster: _Cluster) -> None:
    error = RuntimeError("insufficient capacity")
    cluster.install_error = error

    with pytest.raises(RuntimeError) as caught:
        async with K8sSandboxEnvironment.create("grading", None, {}):
            pytest.fail("Failed installation must not yield handles")

    assert caught.value is error
    assert cluster.deleted == cluster.installed
    assert cluster.manager._installed_releases == []


async def test_failure_reading_handles_is_cleaned_up(
    cluster: _Cluster, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(
        Release, "get_sandbox_pods", AsyncMock(side_effect=RuntimeError("missing pods"))
    )

    with pytest.raises(RuntimeError, match="missing pods"):
        async with K8sSandboxEnvironment.create("grading", None, {}):
            pytest.fail("Failed handle discovery must not yield handles")

    assert cluster.deleted == cluster.installed
    assert cluster.manager._installed_releases == []


async def test_cancellation_during_installation_is_cleaned_up(
    cluster: _Cluster,
) -> None:
    cluster.install_wait = asyncio.Event()

    async def create() -> None:
        async with K8sSandboxEnvironment.create("grading", None, {}):
            pytest.fail("Cancelled installation must not yield handles")

    task = asyncio.create_task(create())
    await asyncio.wait_for(cluster.install_started.wait(), 1)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await asyncio.wait_for(task, 1)

    assert cluster.deleted == cluster.installed
    assert cluster.manager._installed_releases == []


async def test_anyio_cancellation_during_installation_is_cleaned_up(
    cluster: _Cluster,
) -> None:
    cluster.install_wait = asyncio.Event()

    async def create() -> None:
        async with K8sSandboxEnvironment.create("grading", None, {}):
            pytest.fail("Cancelled installation must not yield handles")

    with anyio.fail_after(1):
        async with anyio.create_task_group() as tasks:
            tasks.start_soon(create)
            await cluster.install_started.wait()
            tasks.cancel_scope.cancel()

    assert cluster.deleted == cluster.installed
    assert cluster.manager._installed_releases == []


@pytest.mark.parametrize("cleanup_fails", [False, True])
async def test_body_error_is_preserved(
    cluster: _Cluster, caplog: pytest.LogCaptureFixture, cleanup_fails: bool
) -> None:
    original = ValueError("invalid submission")
    if cleanup_fails:
        cluster.cleanup_error = RuntimeError("API unavailable")

    with caplog.at_level(logging.WARNING), pytest.raises(ValueError) as caught:
        async with K8sSandboxEnvironment.create("grading", None, {}):
            raise original

    assert caught.value is original
    assert cluster.cleanup_started.is_set()
    if cleanup_fails:
        assert cluster.manager._installed_releases == cluster.installed
        assert cluster.installed[0].release_name in caplog.text
        assert "API unavailable" in caplog.text
    else:
        assert cluster.manager._installed_releases == []


async def test_cleanup_failure_surfaces_and_remains_tracked(cluster: _Cluster) -> None:
    original = RuntimeError("API unavailable")
    cluster.cleanup_error = original

    with pytest.raises(RuntimeError) as caught:
        async with K8sSandboxEnvironment.create("grading", None, {}):
            pass

    assert caught.value is original
    assert cluster.manager._installed_releases == cluster.installed
    assert cluster.deleted == []


async def test_cleanup_timeout_surfaces_and_remains_tracked(cluster: _Cluster) -> None:
    cluster.cleanup_wait = asyncio.Event()

    with pytest.raises(TimeoutError):
        async with K8sSandboxEnvironment.create(
            "grading", None, {}, cleanup_timeout=0.01
        ):
            pass

    assert cluster.manager._installed_releases == cluster.installed
    assert cluster.deleted == []


async def test_direct_cancellation_waits_for_cleanup(cluster: _Cluster) -> None:
    cluster.cleanup_wait = asyncio.Event()

    async def create() -> None:
        async with K8sSandboxEnvironment.create("grading", None, {}):
            pass

    task = asyncio.create_task(create())
    await asyncio.wait_for(cluster.cleanup_started.wait(), 1)
    task.cancel()
    # Cancellation reaches the owner while the deletion task remains blocked.
    await asyncio.sleep(0)
    task.cancel()
    await asyncio.sleep(0)
    assert not task.done()
    cluster.cleanup_wait.set()
    with pytest.raises(asyncio.CancelledError):
        await asyncio.wait_for(task, 1)

    assert cluster.deleted == cluster.installed
    assert cluster.manager._installed_releases == []


@pytest.mark.parametrize("timeout", [0, -1, float("inf"), float("nan")])
async def test_invalid_cleanup_timeout_creates_nothing(
    cluster: _Cluster, timeout: float
) -> None:
    with pytest.raises(ValueError, match="positive and finite"):
        async with K8sSandboxEnvironment.create(
            "grading", None, {}, cleanup_timeout=timeout
        ):
            pytest.fail("Invalid timeout must not yield")

    assert cluster.installed == []


async def test_context_owns_cancellation_cleanup_in_real_release_install(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    manager = HelmReleaseManager()
    started = asyncio.Event()
    deleted: list[Release] = []
    monkeypatch.setattr(_helm, "get_default_namespace", lambda _: "test-namespace")
    monkeypatch.setattr(_sandbox_environment, "validate_prereqs", AsyncMock())
    monkeypatch.setattr(
        _sandbox_environment.PodOpExecutor, "get_instance", lambda **_: None
    )
    monkeypatch.setattr(HelmReleaseManager, "get_instance", lambda: manager)

    async def install(*args: object, **kwargs: object) -> None:
        started.set()
        await asyncio.Event().wait()

    async def uninstall(release: Release, quiet: bool) -> None:
        deleted.append(release)

    monkeypatch.setattr(Release, "_install", install)
    monkeypatch.setattr(Release, "uninstall", uninstall)

    async def create() -> None:
        async with K8sSandboxEnvironment.create("grading", None, {}):
            pytest.fail("Cancelled installation must not yield handles")

    task = asyncio.create_task(create())
    await asyncio.wait_for(started.wait(), 1)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await asyncio.wait_for(task, 1)

    # The context's bounded cleanup is the only uninstall, rather than waiting
    # for install()'s usual unbounded cancellation cleanup before reaching it.
    assert len(deleted) == 1
    assert manager._installed_releases == []
