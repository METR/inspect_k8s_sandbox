import dataclasses
from unittest.mock import MagicMock, patch

import pytest
from inspect_ai.util import ExecResult
from kubernetes.client.exceptions import ApiException

from k8s_sandbox._pod.error import (
    ContainerRestartedError,
    ExecResultUnknownError,
    PodError,
)
from k8s_sandbox._pod.pod import Pod
from test.k8s_sandbox.pod.test_check_for_pod_restart import _k8s_pod, _make_pod

OK = ExecResult(success=True, returncode=0, stdout="", stderr="")


async def _exec_as(pod: Pod, *users: str | None) -> None:
    for user in users:
        await pod.exec(["true"], stdin=None, cwd=None, env={}, user=user, timeout=None)


def _switches(op: MagicMock) -> list[bool]:
    return [call.args[-1] for call in op.exec.call_args_list]


async def test_each_user_is_probed_once() -> None:
    pod = _make_pod()
    with (
        patch("k8s_sandbox._pod.op.k8s_client") as client,
        patch("k8s_sandbox._pod.pod.ExecuteOperation") as op_cls,
    ):
        client.return_value.read_namespaced_pod.return_value = _k8s_pod(
            uid="uid-OLD", container_name="default", restart_count=0
        )
        op = op_cls.return_value
        op.probe_switch.side_effect = lambda user: user == "agent"
        op.exec.return_value = OK

        await _exec_as(pod, "agent", "agent", "root", "0", None, "agent")

    assert [call.args for call in op.probe_switch.call_args_list] == [("agent",)]
    assert _switches(op) == [True, True, False, False, False, True]


async def test_a_container_that_cannot_switch_is_probed_once() -> None:
    """The shell checks for itself on every call then; probing again gains nothing."""
    pod = _make_pod()
    with (
        patch("k8s_sandbox._pod.op.k8s_client") as client,
        patch("k8s_sandbox._pod.pod.ExecuteOperation") as op_cls,
    ):
        client.return_value.read_namespaced_pod.return_value = _k8s_pod(
            uid="uid-OLD", container_name="default", restart_count=0
        )
        op = op_cls.return_value
        op.probe_switch.return_value = False
        op.exec.return_value = OK

        await _exec_as(pod, "agent", "agent")

    assert op.probe_switch.call_count == 1
    assert _switches(op) == [False, False]


async def test_a_failed_probe_leaves_the_check_to_the_shell_and_is_tried_again() -> (
    None
):
    pod = _make_pod()
    with (
        patch("k8s_sandbox._pod.op.k8s_client") as client,
        patch("k8s_sandbox._pod.pod.ExecuteOperation") as op_cls,
    ):
        client.return_value.read_namespaced_pod.return_value = _k8s_pod(
            uid="uid-OLD", container_name="default", restart_count=0
        )
        op = op_cls.return_value
        op.probe_switch.side_effect = [ApiException(status=500), True]
        op.exec.return_value = OK

        await _exec_as(pod, "agent", "agent")

    assert op.probe_switch.call_count == 2
    assert _switches(op) == [False, True]


async def test_a_restarted_container_is_probed_again() -> None:
    pod = _make_pod(restarted_container_behavior="warn")
    with (
        patch("k8s_sandbox._pod.op.k8s_client") as client,
        patch("k8s_sandbox._pod.pod.ExecuteOperation") as op_cls,
    ):
        client.return_value.read_namespaced_pod.side_effect = [
            _k8s_pod(uid="uid-OLD", container_name="default", restart_count=0),
            _k8s_pod(uid="uid-OLD", container_name="default", restart_count=1),
        ]
        op = op_cls.return_value
        op.probe_switch.side_effect = [False, True]
        op.exec.return_value = OK

        await _exec_as(pod, "agent", "agent")

    assert op.probe_switch.call_count == 2
    assert _switches(op) == [False, True]


async def test_a_replaced_pod_is_probed_again() -> None:
    pod = _make_pod(restarted_container_behavior="warn")
    with (
        patch("k8s_sandbox._pod.op.k8s_client") as client,
        patch("k8s_sandbox._pod.pod.ExecuteOperation") as op_cls,
    ):
        client.return_value.read_namespaced_pod.side_effect = [
            _k8s_pod(uid="uid-OLD", container_name="default", restart_count=0),
            _k8s_pod(uid="uid-NEW", container_name="default", restart_count=0),
        ]
        op = op_cls.return_value
        op.probe_switch.side_effect = [False, True]
        op.exec.return_value = OK

        await _exec_as(pod, "agent", "agent")

    assert op.probe_switch.call_count == 2
    assert _switches(op) == [False, True]


async def test_a_probe_that_times_out_fails_the_exec() -> None:
    """The shell's own check would wait on the same container, with no bound.

    A PodError, so the call is retried rather than reported as the command timing out.
    """
    pod = _make_pod()
    with (
        patch("k8s_sandbox._pod.op.k8s_client") as client,
        patch("k8s_sandbox._pod.pod.ExecuteOperation") as op_cls,
    ):
        client.return_value.read_namespaced_pod.return_value = _k8s_pod(
            uid="uid-OLD", container_name="default", restart_count=0
        )
        op = op_cls.return_value
        op.probe_switch.side_effect = PodError("Probing exec(user='agent') timed out")

        with pytest.raises(PodError):
            await _exec_as(pod, "agent")

    op.exec.assert_not_called()


async def test_a_container_changed_during_the_probe_checks_for_itself() -> None:
    pod = _make_pod()

    def replaced_meanwhile(user: str) -> bool:
        pod._info = dataclasses.replace(pod._info, uid="uid-NEW")
        return True

    with (
        patch("k8s_sandbox._pod.op.k8s_client") as client,
        patch("k8s_sandbox._pod.pod.ExecuteOperation") as op_cls,
    ):
        client.return_value.read_namespaced_pod.return_value = _k8s_pod(
            uid="uid-OLD", container_name="default", restart_count=0
        )
        op = op_cls.return_value
        op.probe_switch.side_effect = replaced_meanwhile
        op.exec.return_value = OK

        await _exec_as(pod, "agent")

    assert _switches(op) == [False]


@pytest.mark.parametrize(
    ("restart_count", "raised"),
    [(1, ContainerRestartedError), (0, ExecResultUnknownError)],
)
async def test_a_lost_result_is_explained_by_a_restart(
    restart_count: int, raised: type[Exception]
) -> None:
    pod = _make_pod()
    with (
        patch("k8s_sandbox._pod.op.k8s_client") as client,
        patch("k8s_sandbox._pod.pod.ExecuteOperation") as op_cls,
    ):
        client.return_value.read_namespaced_pod.side_effect = [
            _k8s_pod(uid="uid-OLD", container_name="default", restart_count=count)
            for count in (0, restart_count)
        ]
        op_cls.return_value.exec.side_effect = ExecResultUnknownError("lost")

        with pytest.raises(raised):
            await _exec_as(pod, None)


async def test_a_lost_result_after_a_warned_restart_raises_the_restart() -> None:
    """The check before the exec already saw it, so the one after can't."""
    pod = _make_pod(restarted_container_behavior="warn")
    with (
        patch("k8s_sandbox._pod.op.k8s_client") as client,
        patch("k8s_sandbox._pod.pod.ExecuteOperation") as op_cls,
    ):
        client.return_value.read_namespaced_pod.return_value = _k8s_pod(
            uid="uid-OLD", container_name="default", restart_count=1
        )
        op_cls.return_value.exec.side_effect = ExecResultUnknownError("lost")

        with pytest.raises(ContainerRestartedError):
            await _exec_as(pod, None)
