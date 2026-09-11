"""Resolve sandbox admission priority from Kubernetes Job metadata."""

from kubernetes import client  # type: ignore
from pydantic import BaseModel, ConfigDict, Field

from k8s_sandbox._kubernetes_api import k8s_client

PRIORITY_LABEL = "kueue.x-k8s.io/priority-class"
_READ_JOB_REQUEST_TIMEOUT = (5, 30)


class PrioritySourceJob(BaseModel):
    """A Kubernetes Job whose admission priority should be inherited."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    namespace: str = Field(min_length=1)
    name: str = Field(min_length=1)


def read_priority_class(source: PrioritySourceJob, context: str | None) -> str:
    """Read the Kueue priority class label from a Kubernetes Job."""
    api_client = k8s_client(context).api_client  # type: ignore[attr-defined]
    api = client.BatchV1Api(api_client=api_client)
    job = api.read_namespaced_job(
        name=source.name,
        namespace=source.namespace,
        _request_timeout=_READ_JOB_REQUEST_TIMEOUT,  # type: ignore[call-arg]
    )
    labels = job.metadata.labels if job.metadata is not None else None
    if labels is None or PRIORITY_LABEL not in labels:
        raise ValueError(
            f"Priority source Job '{source.namespace}/{source.name}' does not have "
            f"the required '{PRIORITY_LABEL}' label."
        )
    return labels[PRIORITY_LABEL]
