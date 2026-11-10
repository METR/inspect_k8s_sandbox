from unittest.mock import MagicMock, patch

from inspect_ai.util import ExecResult
from kubernetes.client.exceptions import ApiException

from k8s_sandbox._pod.pod import Pod
from test.k8s_sandbox.pod.test_check_for_pod_restart import _k8s_pod, _make_pod

OK = ExecResult(success=True, returncode=0, stdout="", stderr="")


async def _exec_as(pod: Pod, *users: str | None) -> None:
    for user in users:
        await pod.exec(["true"], stdin=None, cwd=None, env={}, user=user, timeout=None)


def _switches(op: MagicMock) -> list[bool | None]:
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

        await _exec_as(pod, "agent", "agent", "root", None, "agent")

    assert [call.args for call in op.probe_switch.call_args_list] == [
        ("agent",),
        ("root",),
    ]
    assert _switches(op) == [True, True, False, None, True]


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
    assert _switches(op) == [None, True]


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
