import asyncio
import contextvars
import threading
from time import sleep
from typing import Generator
from unittest.mock import patch

import anyio
import pytest
from pytest import MonkeyPatch

from k8s_sandbox._pod.executor import PodOpExecutor


@pytest.fixture(autouse=True)
def reset_singleton() -> Generator:
    # Ensure that each test starts with a fresh singleton instance.
    PodOpExecutor._instance = None
    yield


def test_get_instance() -> None:
    result1 = PodOpExecutor.get_instance()
    result2 = PodOpExecutor.get_instance()

    assert result1 == result2


def test_default_max_workers(monkeypatch: MonkeyPatch) -> None:
    monkeypatch.delenv("INSPECT_MAX_POD_OPS", raising=False)

    with patch("os.cpu_count", return_value=4):
        actual = PodOpExecutor.get_instance()

    assert actual._max_workers == 16


def test_max_workers_via_env_var(monkeypatch: MonkeyPatch) -> None:
    monkeypatch.setenv("INSPECT_MAX_POD_OPS", "42")

    actual = PodOpExecutor.get_instance()

    assert actual._max_workers == 42


def test_max_workers_via_parameter(monkeypatch: MonkeyPatch) -> None:
    monkeypatch.delenv("INSPECT_MAX_POD_OPS", raising=False)

    actual = PodOpExecutor.get_instance(max_pod_ops=64)

    assert actual._max_workers == 64


def test_parameter_takes_precedence_over_env_var(monkeypatch: MonkeyPatch) -> None:
    monkeypatch.setenv("INSPECT_MAX_POD_OPS", "42")

    actual = PodOpExecutor.get_instance(max_pod_ops=64)

    assert actual._max_workers == 64


def test_parameter_conflicting_with_existing_executor_raises(
    monkeypatch: MonkeyPatch,
) -> None:
    monkeypatch.delenv("INSPECT_MAX_POD_OPS", raising=False)

    with patch("os.cpu_count", return_value=4):
        PodOpExecutor.get_instance()

    with pytest.raises(ValueError) as exc_info:
        PodOpExecutor.get_instance(max_pod_ops=64)

    # The message names the source of the existing limit so that users can tell
    # a default from an explicitly-configured value.
    assert (
        "already initialized with max_pod_ops=16 (from default (cpu_count=4 * 4))"
        in str(exc_info.value)
    )


async def test_queue_operation(monkeypatch: MonkeyPatch) -> None:
    monkeypatch.setenv("INSPECT_MAX_POD_OPS", "10")
    executor = PodOpExecutor.get_instance()

    op1 = executor.queue_operation(lambda: _synchronous_operation(1))
    op2 = executor.queue_operation(lambda: _synchronous_operation(2))

    result1, result2 = await asyncio.gather(op1, op2)
    assert result1 == (1, "pod-op-executor_0")
    assert result2 == (2, "pod-op-executor_1")


async def test_queue_more_operations_than_max_workers(monkeypatch: MonkeyPatch) -> None:
    monkeypatch.setenv("INSPECT_MAX_POD_OPS", "2")
    executor = PodOpExecutor.get_instance()

    op1 = executor.queue_operation(lambda: _synchronous_operation(1))
    op2 = executor.queue_operation(lambda: _synchronous_operation(2))
    op3 = executor.queue_operation(lambda: _synchronous_operation(3))

    result1, result2, result3 = await asyncio.gather(op1, op2, op3)
    assert result1 == (1, "pod-op-executor_0")
    assert result2 == (2, "pod-op-executor_1")
    # The third operation should be executed by one of the two existing workers.
    assert result3 == (3, "pod-op-executor_0") or result3 == (3, "pod-op-executor_1")


async def test_queue_operation_propagates_caller_context(
    monkeypatch: MonkeyPatch,
) -> None:
    monkeypatch.setenv("INSPECT_MAX_POD_OPS", "1")
    executor = PodOpExecutor.get_instance()
    var: contextvars.ContextVar[str] = contextvars.ContextVar(
        "test_var", default="default"
    )
    var.set("override")

    seen = await executor.queue_operation(var.get)

    assert seen == "override"


def _synchronous_operation(value: int) -> tuple[int, str]:
    sleep(1)
    return value, threading.current_thread().name


async def test_a_result_in_as_its_caller_stops_waiting_is_discarded_off_the_loop() -> (
    None
):
    """Discarding closes a connection, which can block for seconds."""
    executor = PodOpExecutor.get_instance(max_pod_ops=1)
    started, release, discarded = (
        threading.Event(),
        threading.Event(),
        threading.Event(),
    )
    discarded_on: list[threading.Thread] = []

    def operation() -> str:
        started.set()
        release.wait(30)
        return "an open connection"

    def discard(result: str) -> None:
        discarded_on.append(threading.current_thread())
        discarded.set()

    task = asyncio.create_task(executor.queue_operation(operation, discard))
    with anyio.fail_after(30):
        while not started.is_set():
            await asyncio.sleep(0)
    # The event loop is held from here until the cancel, so the result comes in where
    # the caller cannot see it: the pool's one thread takes the next only after.
    release.set()
    executor._executor.submit(lambda: None).result(timeout=30)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task

    assert discarded.wait(timeout=30)
    assert discarded_on[0] is not threading.current_thread()
