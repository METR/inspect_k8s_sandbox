from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest
from kubernetes.client.exceptions import ApiException
from pydantic import ValidationError

from k8s_sandbox._priority import (
    PRIORITY_LABEL,
    PrioritySourceJob,
    read_priority_class,
)


@pytest.mark.parametrize("priority_class", ["medium", "high"])
def test_read_priority_class_from_job_label(priority_class: str) -> None:
    source = PrioritySourceJob(namespace="runner", name="eval-job")
    api_client = object()
    core_client = SimpleNamespace(api_client=api_client)
    batch_client = MagicMock()
    batch_client.read_namespaced_job.return_value = SimpleNamespace(
        metadata=SimpleNamespace(labels={PRIORITY_LABEL: priority_class})
    )

    with patch("k8s_sandbox._priority.k8s_client", return_value=core_client):
        with patch(
            "k8s_sandbox._priority.client.BatchV1Api", return_value=batch_client
        ) as batch_api:
            result = read_priority_class(source, "dev-context")

    assert result == priority_class
    batch_api.assert_called_once_with(api_client=api_client)
    batch_client.read_namespaced_job.assert_called_once_with(
        name="eval-job",
        namespace="runner",
        _request_timeout=(2, 3),
    )


def test_read_priority_class_requires_job_label() -> None:
    source = PrioritySourceJob(namespace="runner", name="eval-job")
    batch_client = MagicMock()
    batch_client.read_namespaced_job.return_value = SimpleNamespace(
        metadata=SimpleNamespace(labels={})
    )

    with patch(
        "k8s_sandbox._priority.k8s_client",
        return_value=SimpleNamespace(api_client=object()),
    ):
        with patch(
            "k8s_sandbox._priority.client.BatchV1Api", return_value=batch_client
        ):
            with pytest.raises(ValueError) as excinfo:
                read_priority_class(source, None)

    message = str(excinfo.value)
    assert "runner/eval-job" in message
    assert PRIORITY_LABEL in message


@pytest.mark.parametrize(
    "error",
    [
        ApiException(status=403, reason="Forbidden"),
        ApiException(status=404, reason="Not Found"),
        TimeoutError("timed out"),
    ],
)
def test_read_priority_class_propagates_kubernetes_failures(error: Exception) -> None:
    source = PrioritySourceJob(namespace="runner", name="eval-job")
    batch_client = MagicMock()
    batch_client.read_namespaced_job.side_effect = error

    with patch(
        "k8s_sandbox._priority.k8s_client",
        return_value=SimpleNamespace(api_client=object()),
    ):
        with patch(
            "k8s_sandbox._priority.client.BatchV1Api", return_value=batch_client
        ):
            with pytest.raises(type(error)) as excinfo:
                read_priority_class(source, None)

    assert excinfo.value is error


@pytest.mark.parametrize(
    "data",
    [
        {"namespace": "", "name": "eval-job"},
        {"namespace": "runner", "name": ""},
        {"namespace": "runner", "name": "eval-job", "other": "value"},
    ],
)
def test_priority_source_job_rejects_invalid_fields(data: dict[str, str]) -> None:
    with pytest.raises(ValidationError):
        PrioritySourceJob.model_validate(data)


def test_priority_source_job_is_frozen() -> None:
    source = PrioritySourceJob(namespace="runner", name="eval-job")

    with pytest.raises(ValidationError):
        source.name = "other"  # type: ignore[misc]
