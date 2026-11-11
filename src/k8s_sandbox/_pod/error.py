from typing import Any

from k8s_sandbox._error import K8sError
from k8s_sandbox._logger import format_log_message


class PodError(Exception):
    """
    A generic error raised when interacting with a Pod.

    This will typically cause the eval to fail.
    """

    def __init__(self, message: str, **kwargs: Any) -> None:
        super().__init__(format_log_message(message, **kwargs))


class GetReturncodeError(Exception):
    """The return code of a Pod operation could not be retrieved."""

    pass


class ExecResultUnknownError(PodError, GetReturncodeError):
    """An exec's command was sent to the pod, but its result could not be read.

    The command may have run, and may still be running, so it is not retried.
    """


class ContainerStoppedError(ExecResultUnknownError):
    """An operation's container stopped under it.

    The operation ended with the exit status 255 that Kata gives a command whose VM
    stopped, before its command did. With ``restarted_container_behavior="raise"`` the
    operation raises a ``ContainerRestartedError`` instead, from this.
    """


class ExecutableNotFoundError(Exception):
    """The executable could not be found in the container.

    This is **not** raised as a result of user-supplied commands not being found. It is
    typically raised when /bin/sh or runuser cannot be found in the container.
    """

    pass


class PodReplacedError(K8sError):
    """The pod's UID has changed since it was first observed.

    Typically caused by eviction (e.g. node disk/memory pressure, OOM) followed
    by the controlling workload (StatefulSet/Deployment) recreating the pod
    with the same name but a fresh UID. The previous pod is gone, along with
    any state held in its filesystem or memory that did not reside on a
    persistent volume.

    With ``restarted_container_behavior="warn"`` the sandbox provider refreshes
    its cached pod identity, so subsequent operations target the new pod and do
    not report it again unless yet another replacement occurs. With ``"raise"``
    every later operation in the sandbox raises it again.
    """

    def __init__(  # noqa: D107
        self,
        *,
        pod_name: str,
        old_uid: str,
        new_uid: str,
        new_restart_count: int,
        **kwargs: Any,
    ):
        self.pod_name = pod_name
        self.old_uid = old_uid
        self.new_uid = new_uid
        self.new_restart_count = new_restart_count
        super().__init__(
            f"Pod '{pod_name}' has been replaced "
            f"(old UID {old_uid}, new UID {new_uid})",
            pod=pod_name,
            old_uid=old_uid,
            new_uid=new_uid,
            **kwargs,
        )


class ContainerRestartedError(K8sError):
    """A container in the pod has restarted since the pod was first observed.

    The pod itself is the same (same UID), but the container's process was
    restarted (OOM, crash, liveness probe failure, a Kata VM's death, etc.).
    Files on the pod's volumes survive; the container's own filesystem, its
    in-memory state and any background processes started by the agent do not.

    With ``restarted_container_behavior="warn"`` the sandbox provider refreshes
    its cached restart count, so subsequent operations do not report it again
    unless a further restart occurs. With ``"raise"`` every later operation in
    the sandbox raises it again.
    """

    def __init__(  # noqa: D107
        self,
        *,
        pod_name: str,
        container_name: str,
        restart_count: int,
        last_reason: str,
        **kwargs: Any,
    ):
        self.pod_name = pod_name
        self.container_name = container_name
        self.restart_count = restart_count
        self.last_reason = last_reason
        super().__init__(
            f"Container '{container_name}' in pod '{pod_name}' has restarted "
            f"{restart_count} time(s) (last reason: {last_reason}); "
            "in-memory pod state is no longer guaranteed",
            pod=pod_name,
            container=container_name,
            restart_count=restart_count,
            last_reason=last_reason,
            **kwargs,
        )
