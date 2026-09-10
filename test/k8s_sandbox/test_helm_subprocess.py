import asyncio
import os
import signal
import sys
from contextlib import suppress
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, AsyncIterator

import anyio
import pytest

from k8s_sandbox import _helm


@dataclass
class _Subprocesses:
    processes: list[asyncio.subprocess.Process] = field(default_factory=list)
    creation_gate: asyncio.Event | None = None


@pytest.fixture
async def subprocesses(monkeypatch: pytest.MonkeyPatch) -> AsyncIterator[_Subprocesses]:
    result = _Subprocesses()
    create = asyncio.create_subprocess_exec

    async def record(*args: Any, **kwargs: Any) -> asyncio.subprocess.Process:
        process = await create(*args, **kwargs)
        result.processes.append(process)
        if result.creation_gate is not None:
            await result.creation_gate.wait()
        return process

    monkeypatch.setattr(asyncio, "create_subprocess_exec", record)
    monkeypatch.setattr(_helm, "_SUBPROCESS_TERMINATE_TIMEOUT", 0.05)
    monkeypatch.setattr(_helm, "_SUBPROCESS_DRAIN_TIMEOUT", 0.05)
    try:
        yield result
    finally:
        # Reap children even if an assertion fails, without relying on the code
        # under test to stop a process which deliberately ignores SIGTERM.
        if result.creation_gate is not None:
            result.creation_gate.set()
        for process in result.processes:
            if process.returncode is None:
                process.kill()
        for process in result.processes:
            await asyncio.wait_for(process.wait(), timeout=2)


def _ignoring_sigterm_args(ready: Path) -> list[str]:
    return [
        "-c",
        "import os, pathlib, signal, sys, time\n"
        "signal.signal(signal.SIGTERM, signal.SIG_IGN)\n"
        "pathlib.Path(sys.argv[1]).touch()\n"
        # More than the pipe capacity, to exercise draining stdout and stderr
        # while waiting for the process to exit.
        "for _ in range(32):\n"
        "    os.write(1, b'x' * 65536)\n"
        "    os.write(2, b'y' * 65536)\n"
        "time.sleep(60)\n",
        str(ready),
    ]


async def _wait_ready(ready: Path) -> None:
    with anyio.fail_after(2):
        while not ready.exists():
            await asyncio.sleep(0.005)


def _assert_reaped(
    subprocesses: _Subprocesses, initial_tasks: set[asyncio.Task[Any]]
) -> None:
    assert len(subprocesses.processes) == 1
    assert subprocesses.processes[0].returncode == -signal.SIGKILL
    assert not asyncio.all_tasks().difference(initial_tasks)


@pytest.mark.parametrize("exit_code", [0, 7])
async def test_subprocess_result_is_preserved(exit_code: int) -> None:
    result = await _helm._run_subprocess(
        sys.executable,
        [
            "-c",
            "import sys; print('out'); print('err', file=sys.stderr); "
            f"sys.exit({exit_code})",
        ],
        capture_output=True,
    )

    assert result.success is (exit_code == 0)
    assert result.stdout == "out\n"
    assert result.stderr == "err\n"
    if exit_code:
        assert result.returncode == exit_code


@pytest.mark.skipif(sys.platform == "win32", reason="Requires POSIX signal handling")
async def test_repeated_cancellation_kills_and_reaps_subprocess(
    subprocesses: _Subprocesses, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    initial_tasks = asyncio.all_tasks()
    ready = tmp_path / "ready"
    task = asyncio.create_task(
        _helm._run_subprocess(sys.executable, _ignoring_sigterm_args(ready), True)
    )
    await _wait_ready(ready)
    process = subprocesses.processes[0]
    terminated = asyncio.Event()
    terminate = process.terminate

    def record_terminate() -> None:
        terminate()
        terminated.set()

    monkeypatch.setattr(process, "terminate", record_terminate)
    task.cancel("original cancellation")
    await asyncio.wait_for(terminated.wait(), timeout=2)
    task.cancel("later cancellation")
    done, _ = await asyncio.wait({task}, timeout=2)
    assert task in done
    with pytest.raises(asyncio.CancelledError, match="original cancellation"):
        await task

    _assert_reaped(subprocesses, initial_tasks)


@pytest.mark.skipif(sys.platform == "win32", reason="Requires POSIX signal handling")
async def test_subprocess_timeout_escalates_to_kill(
    subprocesses: _Subprocesses, tmp_path: Path
) -> None:
    initial_tasks = asyncio.all_tasks()
    ready = tmp_path / "ready"
    task = asyncio.create_task(
        _helm._run_subprocess(sys.executable, _ignoring_sigterm_args(ready), True)
    )
    await _wait_ready(ready)
    timeout = asyncio.create_task(asyncio.wait_for(task, timeout=0.01))

    with pytest.raises(asyncio.TimeoutError):
        await asyncio.wait_for(asyncio.shield(timeout), timeout=2)
    assert timeout.done()
    assert task.cancelled()
    _assert_reaped(subprocesses, initial_tasks)


@pytest.mark.skipif(sys.platform == "win32", reason="Requires POSIX signal handling")
async def test_anyio_cancellation_kills_and_reaps_subprocess(
    subprocesses: _Subprocesses, tmp_path: Path
) -> None:
    initial_tasks = asyncio.all_tasks()
    ready = tmp_path / "ready"
    with anyio.fail_after(2):
        async with anyio.create_task_group() as tasks:
            tasks.start_soon(
                _helm._run_subprocess,
                sys.executable,
                _ignoring_sigterm_args(ready),
                True,
            )
            await _wait_ready(ready)
            tasks.cancel_scope.cancel()

    _assert_reaped(subprocesses, initial_tasks)


@pytest.mark.skipif(sys.platform == "win32", reason="Requires POSIX signal handling")
async def test_cancellation_while_creation_returns_keeps_process_handle(
    subprocesses: _Subprocesses, tmp_path: Path
) -> None:
    initial_tasks = asyncio.all_tasks()
    subprocesses.creation_gate = asyncio.Event()
    ready = tmp_path / "ready"
    task = asyncio.create_task(
        _helm._run_subprocess(sys.executable, _ignoring_sigterm_args(ready), True)
    )
    await _wait_ready(ready)
    task.cancel("cancelled during creation")
    await asyncio.sleep(0)
    subprocesses.creation_gate.set()

    done, _ = await asyncio.wait({task}, timeout=2)
    assert task in done
    with pytest.raises(asyncio.CancelledError, match="cancelled during creation"):
        await task

    _assert_reaped(subprocesses, initial_tasks)


@pytest.mark.skipif(sys.platform == "win32", reason="Requires POSIX signal handling")
async def test_inherited_pipes_do_not_block_cancellation(
    subprocesses: _Subprocesses, tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    initial_tasks = asyncio.all_tasks()
    ready = tmp_path / "ready"
    descendant_pid = tmp_path / "descendant-pid"
    task = asyncio.create_task(
        _helm._run_subprocess(
            sys.executable,
            [
                "-c",
                "import pathlib, signal, subprocess, sys, time\n"
                "signal.signal(signal.SIGTERM, signal.SIG_IGN)\n"
                "child = subprocess.Popen([sys.executable, '-c', "
                "'import time; time.sleep(60)'])\n"
                "pathlib.Path(sys.argv[2]).write_text(str(child.pid))\n"
                "pathlib.Path(sys.argv[1]).touch()\n"
                "time.sleep(60)\n",
                str(ready),
                str(descendant_pid),
            ],
            True,
        )
    )
    try:
        await _wait_ready(ready)
        task.cancel("original cancellation")
        done, _ = await asyncio.wait({task}, timeout=2)
        assert task in done
        with pytest.raises(asyncio.CancelledError, match="original cancellation"):
            await task

        _assert_reaped(subprocesses, initial_tasks)
        process = subprocesses.processes[0]
        assert process._transport.is_closing()  # type: ignore[attr-defined]
        assert "Timed out draining output" in caplog.text
    finally:
        if descendant_pid.exists():
            with suppress(ProcessLookupError):
                os.kill(int(descendant_pid.read_text()), signal.SIGKILL)
