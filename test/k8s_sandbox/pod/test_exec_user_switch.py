import dataclasses
from unittest import mock

import inspect_ai.util
import kubernetes.client.exceptions
import pytest

from k8s_sandbox._pod import error
from k8s_sandbox._pod import pod as pod_module
from test.k8s_sandbox.pod import test_check_for_pod_restart

_k8s_pod = test_check_for_pod_restart._k8s_pod  # pyright: ignore[reportPrivateUsage]
_make_pod = test_check_for_pod_restart._make_pod  # pyright: ignore[reportPrivateUsage]
OK = inspect_ai.util.ExecResult(success=True, returncode=0, stdout="", stderr="")


async def _exec_as(pod: pod_module.Pod, *users: str | None) -> None:
    for user in users:
        await pod.exec(["true"], stdin=None, cwd=None, env={}, user=user, timeout=None)


def _switches(op: mock.MagicMock) -> list[bool]:
    return [call.args[-1] for call in op.exec.call_args_list]


async def test_each_user_is_probed_once() -> None:
    pod = _make_pod()
    with (
        mock.patch("k8s_sandbox._pod.op.k8s_client", autospec=True) as client,
        mock.patch("k8s_sandbox._pod.pod.ExecuteOperation", autospec=True) as op_cls,
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
        mock.patch("k8s_sandbox._pod.op.k8s_client", autospec=True) as client,
        mock.patch("k8s_sandbox._pod.pod.ExecuteOperation", autospec=True) as op_cls,
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
        mock.patch("k8s_sandbox._pod.op.k8s_client", autospec=True) as client,
        mock.patch("k8s_sandbox._pod.pod.ExecuteOperation", autospec=True) as op_cls,
    ):
        client.return_value.read_namespaced_pod.return_value = _k8s_pod(
            uid="uid-OLD", container_name="default", restart_count=0
        )
        op = op_cls.return_value
        op.probe_switch.side_effect = [
            kubernetes.client.exceptions.ApiException(status=500),
            True,
        ]
        op.exec.return_value = OK

        await _exec_as(pod, "agent", "agent")

    assert op.probe_switch.call_count == 2
    assert _switches(op) == [False, True]


async def test_a_restarted_container_is_probed_again() -> None:
    pod = _make_pod(restarted_container_behavior="warn")
    with (
        mock.patch("k8s_sandbox._pod.op.k8s_client", autospec=True) as client,
        mock.patch("k8s_sandbox._pod.pod.ExecuteOperation", autospec=True) as op_cls,
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
        mock.patch("k8s_sandbox._pod.op.k8s_client", autospec=True) as client,
        mock.patch("k8s_sandbox._pod.pod.ExecuteOperation", autospec=True) as op_cls,
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
        mock.patch("k8s_sandbox._pod.op.k8s_client", autospec=True) as client,
        mock.patch("k8s_sandbox._pod.pod.ExecuteOperation", autospec=True) as op_cls,
    ):
        client.return_value.read_namespaced_pod.return_value = _k8s_pod(
            uid="uid-OLD", container_name="default", restart_count=0
        )
        op = op_cls.return_value
        op.probe_switch.side_effect = error.PodError(
            "Probing exec(user='agent') timed out"
        )

        with pytest.raises(error.PodError):
            await _exec_as(pod, "agent")

    op.exec.assert_not_called()


async def test_a_container_changed_during_the_probe_checks_for_itself() -> None:
    pod = _make_pod()

    def replaced_meanwhile(user: str) -> bool:
        pod._info = dataclasses.replace(pod._info, uid="uid-NEW")
        return True

    with (
        mock.patch("k8s_sandbox._pod.op.k8s_client", autospec=True) as client,
        mock.patch("k8s_sandbox._pod.pod.ExecuteOperation", autospec=True) as op_cls,
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
    [(1, error.ContainerRestartedError), (0, error.ExecResultUnknownError)],
)
async def test_a_lost_result_is_explained_by_a_restart(
    restart_count: int, raised: type[Exception]
) -> None:
    pod = _make_pod()
    with (
        mock.patch("k8s_sandbox._pod.op.k8s_client", autospec=True) as client,
        mock.patch("k8s_sandbox._pod.pod.ExecuteOperation", autospec=True) as op_cls,
    ):
        client.return_value.read_namespaced_pod.side_effect = [
            _k8s_pod(uid="uid-OLD", container_name="default", restart_count=count)
            for count in (0, restart_count)
        ]
        op_cls.return_value.exec.side_effect = error.ExecResultUnknownError("lost")

        with pytest.raises(raised):
            await _exec_as(pod, None)


async def test_a_lost_result_after_a_warned_restart_raises_the_restart() -> None:
    """The check before the exec already saw it, so the one after can't."""
    pod = _make_pod(restarted_container_behavior="warn")
    with (
        mock.patch("k8s_sandbox._pod.op.k8s_client", autospec=True) as client,
        mock.patch("k8s_sandbox._pod.pod.ExecuteOperation", autospec=True) as op_cls,
    ):
        client.return_value.read_namespaced_pod.return_value = _k8s_pod(
            uid="uid-OLD", container_name="default", restart_count=1
        )
        op_cls.return_value.exec.side_effect = error.ExecResultUnknownError("lost")

        with pytest.raises(error.ContainerRestartedError):
            await _exec_as(pod, None)
