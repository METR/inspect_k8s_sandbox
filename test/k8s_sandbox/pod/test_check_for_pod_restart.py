import asyncio
import io
import json
import pathlib
import traceback
from unittest.mock import MagicMock, patch

import pytest
from inspect_ai.util import ExecResult

from k8s_sandbox._pod.error import (
    ContainerRestartedError,
    ContainerStoppedError,
    PodReplacedError,
)
from k8s_sandbox._pod.op import API_TIMEOUT, PodInfo, check_for_pod_restart
from k8s_sandbox._pod.pod import Pod


def _raw_pod_response(body: dict) -> MagicMock:
    """Mimic the raw urllib3 response returned by ``_preload_content=False``."""
    response = MagicMock()
    response.data = json.dumps(body).encode()
    return response


def _k8s_pod(uid: str, container_name: str, restart_count: int) -> MagicMock:
    return _raw_pod_response(
        {
            "metadata": {"uid": uid, "name": "agent-env-abc-default-0"},
            "status": {
                "containerStatuses": [
                    {
                        "name": container_name,
                        "restartCount": restart_count,
                        "state": {"running": {}},
                        "lastState": {"terminated": {"reason": "OOMKilled"}},
                    }
                ]
            },
        }
    )


def _pod_info(uid: str = "uid-1", restart_count: int = 0) -> PodInfo:
    return PodInfo(
        name="agent-env-abc-default-0",
        namespace="ns",
        context_name=None,
        default_container_name="default",
        uid=uid,
        initial_restart_count=restart_count,
        restarted_container_behavior="raise",
    )


def test_no_change_does_not_raise():
    with patch("k8s_sandbox._pod.op.k8s_client") as mock_client:
        mock_client.return_value.read_namespaced_pod.return_value = _k8s_pod(
            uid="uid-1", container_name="default", restart_count=0
        )
        # Should not raise
        check_for_pod_restart(_pod_info())
    # A stalled read gives up rather than hold its thread. The kubernetes client
    # ignores a timeout that is not an int.
    read = mock_client.return_value.read_namespaced_pod.call_args
    assert read.kwargs["_request_timeout"] == API_TIMEOUT
    assert isinstance(API_TIMEOUT, int)


def test_missing_container_statuses_skips_restart_check():
    # Briefly possible right after pod scheduling: same UID but kubelet
    # hasn't published container_statuses yet. Must not raise.
    pod = _raw_pod_response(
        {"metadata": {"uid": "uid-1", "name": "agent-env-abc-default-0"}, "status": {}}
    )
    with patch("k8s_sandbox._pod.op.k8s_client") as mock_client:
        mock_client.return_value.read_namespaced_pod.return_value = pod
        check_for_pod_restart(_pod_info(uid="uid-1"))


def test_pod_replaced_raises_typed_with_new_restart_count():
    with patch("k8s_sandbox._pod.op.k8s_client") as mock_client:
        mock_client.return_value.read_namespaced_pod.return_value = _k8s_pod(
            uid="uid-NEW", container_name="default", restart_count=2
        )
        with pytest.raises(PodReplacedError) as excinfo:
            check_for_pod_restart(_pod_info(uid="uid-OLD", restart_count=0))
    err = excinfo.value
    assert err.old_uid == "uid-OLD"
    assert err.new_uid == "uid-NEW"
    assert err.new_restart_count == 2
    assert err.pod_name == "agent-env-abc-default-0"


def test_container_restarted_raises_typed():
    with patch("k8s_sandbox._pod.op.k8s_client") as mock_client:
        mock_client.return_value.read_namespaced_pod.return_value = _k8s_pod(
            uid="uid-1", container_name="default", restart_count=3
        )
        with pytest.raises(ContainerRestartedError) as excinfo:
            check_for_pod_restart(_pod_info(uid="uid-1", restart_count=1))
    err = excinfo.value
    assert err.restart_count == 3
    assert err.container_name == "default"
    assert err.last_reason == "OOMKilled"


@pytest.mark.parametrize(
    ("state", "last_state", "restart_count", "reason"),
    [
        pytest.param(
            {"terminated": {"reason": "Error", "exitCode": 255}},
            {},
            0,
            "Error",
            id="stopped",
        ),
        # Its own reason, not its previous instance's.
        pytest.param(
            {"terminated": {"reason": "Error", "exitCode": 255}},
            {"terminated": {"reason": "OOMKilled"}},
            2,
            "Error",
            id="stopped-after-restarts",
        ),
        pytest.param(
            {"waiting": {"reason": "ContainerCreating"}},
            {"terminated": {"reason": "OOMKilled"}},
            0,
            "OOMKilled",
            id="starting-again",
        ),
        pytest.param(
            {"waiting": {"reason": "ContainerCreating"}},
            {},
            0,
            "unknown",
            id="no-history",
        ),
    ],
)
def test_container_not_running_raises_before_its_restart_count_moves(
    state: dict, last_state: dict, restart_count: int, reason: str
):
    # Between a Kata VM's death and its new containers starting, the pod shows the
    # container stopped at the old restart count.
    pod = _raw_pod_response(
        {
            "metadata": {"uid": "uid-1", "name": "agent-env-abc-default-0"},
            "status": {
                "containerStatuses": [
                    {
                        "name": "default",
                        "restartCount": restart_count,
                        "state": state,
                        "lastState": last_state,
                    }
                ]
            },
        }
    )
    with patch("k8s_sandbox._pod.op.k8s_client") as mock_client:
        mock_client.return_value.read_namespaced_pod.return_value = pod
        with pytest.raises(ContainerRestartedError) as excinfo:
            check_for_pod_restart(_pod_info(uid="uid-1", restart_count=restart_count))
    assert excinfo.value.restart_count == restart_count + 1
    assert excinfo.value.last_reason == reason


def _inline_executor():
    """Run the pod's operations inline, without the executor's threads."""
    executor = MagicMock()

    async def queue(callable):
        return callable()

    executor.queue_operation = queue
    return patch(
        "k8s_sandbox._pod.executor.PodOpExecutor.get_instance", return_value=executor
    )


def _make_pod(restarted_container_behavior: str = "raise") -> Pod:
    return Pod(
        name="agent-env-abc-default-0",
        namespace="ns",
        context_name=None,
        default_container_name="default",
        uid="uid-OLD",
        initial_restart_count=0,
        restarted_container_behavior=restarted_container_behavior,  # type: ignore[arg-type]
    )


def test_warn_mode_refreshes_uid_after_replacement():
    pod = _make_pod(restarted_container_behavior="warn")
    with patch("k8s_sandbox._pod.op.k8s_client") as mock_client:
        mock_client.return_value.read_namespaced_pod.return_value = _k8s_pod(
            uid="uid-NEW", container_name="default", restart_count=2
        )
        assert isinstance(pod._check_for_pod_restart_sync(), PodReplacedError)
        # Cached identity is refreshed so a subsequent call against the new pod
        # does NOT report it again.
        assert pod.info.uid == "uid-NEW"
        assert pod.info.initial_restart_count == 2
        assert pod._check_for_pod_restart_sync() is None


@pytest.mark.parametrize(
    ("uid", "restart_count", "error_type"),
    [
        pytest.param("uid-NEW", 0, PodReplacedError, id="replaced"),
        pytest.param("uid-OLD", 1, ContainerRestartedError, id="restarted"),
    ],
)
def test_raise_mode_raises_again_without_reading_the_pod(
    uid: str, restart_count: int, error_type: type[Exception]
):
    pod = _make_pod()
    with _inline_executor():
        with patch("k8s_sandbox._pod.op.k8s_client") as mock_client:
            mock_client.return_value.read_namespaced_pod.return_value = _k8s_pod(
                uid=uid, container_name="default", restart_count=restart_count
            )
            with pytest.raises(error_type) as first:
                asyncio.run(pod.check_for_pod_restart())
            depths = []
            for _ in range(2):
                with pytest.raises(error_type) as again:
                    asyncio.run(pod.check_for_pod_restart())
                # A fresh copy each time, so concurrent raises don't share one.
                assert again.value is not first.value
                assert vars(again.value) == vars(first.value)
                assert str(again.value) == str(first.value)
                depths.append(len(traceback.extract_tb(again.value.__traceback__)))
            assert mock_client.return_value.read_namespaced_pod.call_count == 1
    # Each raise starts a fresh traceback rather than adding to the last one's.
    assert depths[0] == depths[1]
    # What it keeps holds no operation's frames.
    assert pod._restart_error is not None
    assert pod._restart_error.__traceback__ is None
    # The identity stays the one the sample had.
    assert pod.info.uid == "uid-OLD"
    assert pod.info.initial_restart_count == 0


def test_warn_mode_logs_and_does_not_raise_but_still_refreshes(caplog):
    pod = _make_pod(restarted_container_behavior="warn")
    with patch("k8s_sandbox._pod.op.k8s_client") as mock_client:
        mock_client.return_value.read_namespaced_pod.return_value = _k8s_pod(
            uid="uid-NEW", container_name="default", restart_count=0
        )
        with caplog.at_level("WARNING"):
            pod._check_for_pod_restart_sync()
    assert pod.info.uid == "uid-NEW"
    assert any("has been replaced" in r.message for r in caplog.records)


def test_warn_mode_refreshes_restart_count_after_container_restart():
    pod = _make_pod(restarted_container_behavior="warn")
    with patch("k8s_sandbox._pod.op.k8s_client") as mock_client:
        mock_client.return_value.read_namespaced_pod.return_value = _k8s_pod(
            uid="uid-OLD", container_name="default", restart_count=4
        )
        assert isinstance(pod._check_for_pod_restart_sync(), ContainerRestartedError)
        assert pod.info.initial_restart_count == 4
        # Same restart_count next time → nothing to report.
        assert pod._check_for_pod_restart_sync() is None


# --- INSPECT_POD_RESTART_CHECK gating (METR-private; not upstream) -----------


def _make_replaced_pod_response() -> MagicMock:
    return _k8s_pod(uid="uid-NEW", container_name="default", restart_count=0)


def test_env_var_skips_file_op_check_but_not_exec(monkeypatch):
    # Sandbox provider: Pod.read_file / Pod.write_file must skip the pre-op
    # restart check when INSPECT_POD_RESTART_CHECK=false, while Pod.exec must
    # always run it. Gate the file-op API hammer; keep the high-signal exec
    # check unconditional.
    monkeypatch.setenv("INSPECT_POD_RESTART_CHECK", "false")

    # Patch the executor to run callables inline so we don't need a real
    # threadpool / event loop boundary here.
    with patch(
        "k8s_sandbox._pod.executor.PodOpExecutor.get_instance"
    ) as mock_get_instance:
        executor = MagicMock()

        async def queue(callable):
            return callable()

        executor.queue_operation = queue
        mock_get_instance.return_value = executor

        with patch("k8s_sandbox._pod.op.k8s_client") as mock_client:
            mock_client.return_value.read_namespaced_pod.return_value = (
                _make_replaced_pod_response()
            )
            # Patch the actual file ops so they don't try to hit a real pod.
            with (
                patch("k8s_sandbox._pod.pod.ReadFileOperation"),
                patch("k8s_sandbox._pod.pod.WriteFileOperation"),
                patch("k8s_sandbox._pod.pod.ExecuteOperation"),
            ):
                pod = _make_pod()

                # read_file: env var should suppress the check entirely.
                asyncio.run(pod.read_file(pathlib.Path("/x"), io.BytesIO()))
                assert mock_client.return_value.read_namespaced_pod.call_count == 0

                # write_file: same.
                asyncio.run(pod.write_file(b"", pathlib.Path("/x")))
                assert mock_client.return_value.read_namespaced_pod.call_count == 0

                # exec: must always check, env var notwithstanding.
                with pytest.raises(PodReplacedError):
                    asyncio.run(pod.exec(["true"], None, None, {}, None, None))
                assert mock_client.return_value.read_namespaced_pod.call_count == 1


def test_env_var_default_keeps_file_op_check(monkeypatch):
    monkeypatch.delenv("INSPECT_POD_RESTART_CHECK", raising=False)

    with patch(
        "k8s_sandbox._pod.executor.PodOpExecutor.get_instance"
    ) as mock_get_instance:
        executor = MagicMock()

        async def queue(callable):
            return callable()

        executor.queue_operation = queue
        mock_get_instance.return_value = executor

        with patch("k8s_sandbox._pod.op.k8s_client") as mock_client:
            mock_client.return_value.read_namespaced_pod.return_value = (
                _make_replaced_pod_response()
            )
            with patch("k8s_sandbox._pod.pod.ReadFileOperation"):
                pod = _make_pod()
                with pytest.raises(PodReplacedError):
                    asyncio.run(pod.read_file(pathlib.Path("/x"), io.BytesIO()))
                assert mock_client.return_value.read_namespaced_pod.call_count == 1


@pytest.mark.parametrize(
    ("uid", "restart_count", "error_type"),
    [
        pytest.param("uid-NEW", 0, PodReplacedError, id="replaced"),
        pytest.param("uid-OLD", 1, ContainerRestartedError, id="restarted"),
    ],
)
def test_raise_mode_fails_every_later_operation_with_the_check_off(
    monkeypatch, uid: str, restart_count: int, error_type: type[Exception]
):
    # A solver that caught the restart error must not carry on in the new container,
    # through a file operation either, when INSPECT_POD_RESTART_CHECK=false skips
    # their pod reads.
    monkeypatch.setenv("INSPECT_POD_RESTART_CHECK", "false")
    with _inline_executor():
        with patch("k8s_sandbox._pod.op.k8s_client") as mock_client:
            mock_client.return_value.read_namespaced_pod.return_value = _k8s_pod(
                uid=uid, container_name="default", restart_count=restart_count
            )
            with (
                patch("k8s_sandbox._pod.pod.ReadFileOperation") as read_op,
                patch("k8s_sandbox._pod.pod.WriteFileOperation") as write_op,
                patch("k8s_sandbox._pod.pod.ExecuteOperation") as exec_op,
            ):
                pod = _make_pod()
                with pytest.raises(error_type):
                    asyncio.run(pod.exec(["true"], None, None, {}, None, None))
                with pytest.raises(error_type):
                    asyncio.run(pod.exec(["true"], None, None, {}, None, None))
                with pytest.raises(error_type):
                    asyncio.run(pod.read_file(pathlib.Path("/x"), io.BytesIO()))
                with pytest.raises(error_type):
                    asyncio.run(pod.write_file(b"", pathlib.Path("/x")))
                assert mock_client.return_value.read_namespaced_pod.call_count == 1
                exec_op.return_value.exec.assert_not_called()
                read_op.return_value.read_file.assert_not_called()
                write_op.return_value.write_file.assert_not_called()


def _healthy_pod_response() -> MagicMock:
    return _k8s_pod(uid="uid-OLD", container_name="default", restart_count=0)


def test_raise_mode_keeps_a_container_that_stopped_under_a_command(monkeypatch):
    # Kata's 255 before the command's end, while Kubernetes still shows the container
    # running: later operations must not reach the container that replaces it.
    monkeypatch.setenv("INSPECT_POD_RESTART_CHECK", "false")
    with (
        _inline_executor(),
        patch("k8s_sandbox._pod.op.k8s_client") as mock_client,
        patch("k8s_sandbox._pod.pod.ExecuteOperation") as exec_op,
        patch("k8s_sandbox._pod.pod.ReadFileOperation") as read_op,
    ):
        mock_client.return_value.read_namespaced_pod.return_value = (
            _healthy_pod_response()
        )
        exec_op.return_value.exec.side_effect = ContainerStoppedError("stopped")
        pod = _make_pod()
        with pytest.raises(ContainerRestartedError) as excinfo:
            asyncio.run(pod.exec(["sleep", "300"], None, None, {}, None, None))
        assert isinstance(excinfo.value.__cause__, ContainerStoppedError)
        assert excinfo.value.restart_count == 1
        exec_op.return_value.exec.reset_mock()
        with pytest.raises(ContainerRestartedError):
            asyncio.run(pod.exec(["true"], None, None, {}, None, None))
        with pytest.raises(ContainerRestartedError):
            asyncio.run(pod.read_file(pathlib.Path("/x"), io.BytesIO()))
        exec_op.return_value.exec.assert_not_called()
        read_op.return_value.read_file.assert_not_called()


def test_warn_mode_reports_a_container_that_stopped_under_a_command():
    with (
        _inline_executor(),
        patch("k8s_sandbox._pod.op.k8s_client") as mock_client,
        patch("k8s_sandbox._pod.pod.ExecuteOperation") as exec_op,
    ):
        mock_client.return_value.read_namespaced_pod.return_value = (
            _healthy_pod_response()
        )
        exec_op.return_value.exec.side_effect = [
            ContainerStoppedError("stopped"),
            ExecResult(success=True, returncode=0, stdout="", stderr=""),
        ]
        pod = _make_pod(restarted_container_behavior="warn")
        with pytest.raises(ContainerStoppedError):
            asyncio.run(pod.exec(["sleep", "300"], None, None, {}, None, None))
        assert asyncio.run(pod.exec(["true"], None, None, {}, None, None)).success


def test_raise_mode_drops_a_result_got_while_a_restart_was_found():
    # Another operation found the restart while this one ran: its result may come from
    # the new container.
    pod = _make_pod()
    restart = ContainerRestartedError(
        pod_name="p", container_name="default", restart_count=1, last_reason="Error"
    )

    def exec_found_meanwhile(*_args):
        pod._restart_error = restart
        return ExecResult(success=True, returncode=0, stdout="", stderr="")

    with (
        _inline_executor(),
        patch("k8s_sandbox._pod.op.k8s_client") as mock_client,
        patch("k8s_sandbox._pod.pod.ExecuteOperation") as exec_op,
    ):
        mock_client.return_value.read_namespaced_pod.return_value = (
            _healthy_pod_response()
        )
        exec_op.return_value.exec.side_effect = exec_found_meanwhile
        with pytest.raises(ContainerRestartedError):
            asyncio.run(pod.exec(["true"], None, None, {}, None, None))


def test_warn_mode_reports_a_stopped_container_when_its_count_moves():
    stopped = _raw_pod_response(
        {
            "metadata": {"uid": "uid-OLD", "name": "agent-env-abc-default-0"},
            "status": {
                "containerStatuses": [
                    {
                        "name": "default",
                        "restartCount": 0,
                        "state": {"waiting": {"reason": "CrashLoopBackOff"}},
                    }
                ]
            },
        }
    )
    pod = _make_pod(restarted_container_behavior="warn")
    with patch("k8s_sandbox._pod.op.k8s_client") as mock_client:
        mock_client.return_value.read_namespaced_pod.return_value = stopped
        assert pod._check_for_pod_restart_sync() is None
        assert pod.info.initial_restart_count == 0


def test_raise_mode_keeps_a_container_that_stopped_under_a_file_operation(monkeypatch):
    monkeypatch.setenv("INSPECT_POD_RESTART_CHECK", "false")
    with (
        _inline_executor(),
        patch("k8s_sandbox._pod.op.k8s_client") as mock_client,
        patch("k8s_sandbox._pod.pod.ReadFileOperation") as read_op,
        patch("k8s_sandbox._pod.pod.ExecuteOperation") as exec_op,
    ):
        read_op.return_value.read_file.side_effect = ContainerStoppedError("stopped")
        pod = _make_pod()
        with pytest.raises(ContainerRestartedError) as excinfo:
            asyncio.run(pod.read_file(pathlib.Path("/x"), io.BytesIO()))
        assert isinstance(excinfo.value.__cause__, ContainerStoppedError)
        with pytest.raises(ContainerRestartedError):
            asyncio.run(pod.exec(["true"], None, None, {}, None, None))
        mock_client.return_value.read_namespaced_pod.assert_not_called()
        exec_op.return_value.exec.assert_not_called()


def test_a_stopped_sidecar_is_not_a_restart_of_the_sample():
    pod = _raw_pod_response(
        {
            "metadata": {"uid": "uid-1", "name": "agent-env-abc-default-0"},
            "status": {
                "containerStatuses": [
                    {"name": "default", "restartCount": 0, "state": {"running": {}}},
                    {
                        "name": "coredns",
                        "restartCount": 0,
                        "state": {"terminated": {"reason": "Error"}},
                    },
                ]
            },
        }
    )
    with patch("k8s_sandbox._pod.op.k8s_client") as mock_client:
        mock_client.return_value.read_namespaced_pod.return_value = pod
        check_for_pod_restart(_pod_info(uid="uid-1", restart_count=0))


def test_warn_mode_carries_on_after_a_restart():
    with (
        _inline_executor(),
        patch("k8s_sandbox._pod.op.k8s_client") as mock_client,
        patch("k8s_sandbox._pod.pod.ExecuteOperation") as exec_op,
    ):
        mock_client.return_value.read_namespaced_pod.return_value = _k8s_pod(
            uid="uid-OLD", container_name="default", restart_count=1
        )
        exec_op.return_value.exec.return_value = ExecResult(
            success=True, returncode=0, stdout="", stderr=""
        )
        pod = _make_pod(restarted_container_behavior="warn")
        for _ in range(2):
            assert asyncio.run(pod.exec(["true"], None, None, {}, None, None)).success
        assert exec_op.return_value.exec.call_count == 2


def test_a_file_read_that_fails_in_a_restarted_container_raises_the_restart(
    monkeypatch,
):
    # With the check off: the replacement has none of the sample's files.
    monkeypatch.setenv("INSPECT_POD_RESTART_CHECK", "false")
    with (
        _inline_executor(),
        patch("k8s_sandbox._pod.op.k8s_client") as mock_client,
        patch("k8s_sandbox._pod.pod.ReadFileOperation") as read_op,
    ):
        mock_client.return_value.read_namespaced_pod.return_value = _k8s_pod(
            uid="uid-OLD", container_name="default", restart_count=1
        )
        read_op.return_value.read_file.side_effect = FileNotFoundError("/x")
        pod = _make_pod()
        for _ in range(2):
            with pytest.raises(ContainerRestartedError):
                asyncio.run(pod.read_file(pathlib.Path("/x"), io.BytesIO()))
        assert mock_client.return_value.read_namespaced_pod.call_count == 1


def test_a_file_read_that_fails_in_a_healthy_container_keeps_its_error(monkeypatch):
    monkeypatch.setenv("INSPECT_POD_RESTART_CHECK", "false")
    with (
        _inline_executor(),
        patch("k8s_sandbox._pod.op.k8s_client") as mock_client,
        patch("k8s_sandbox._pod.pod.ReadFileOperation") as read_op,
    ):
        mock_client.return_value.read_namespaced_pod.return_value = _k8s_pod(
            uid="uid-OLD", container_name="default", restart_count=0
        )
        read_op.return_value.read_file.side_effect = FileNotFoundError("/x")
        pod = _make_pod()
        with pytest.raises(FileNotFoundError):
            asyncio.run(pod.read_file(pathlib.Path("/x"), io.BytesIO()))
        read_op.return_value.read_file.side_effect = None
        asyncio.run(pod.read_file(pathlib.Path("/x"), io.BytesIO()))
        # One read, after the failure; none for the read that succeeded.
        assert mock_client.return_value.read_namespaced_pod.call_count == 1


def test_an_operation_that_fails_while_a_restart_is_found_raises_the_restart():
    pod = _make_pod()
    restart = ContainerRestartedError(
        pod_name="p", container_name="default", restart_count=1, last_reason="Error"
    )

    def times_out_meanwhile(*_args):
        pod._restart_error = restart
        raise TimeoutError("Command timed out")

    with (
        _inline_executor(),
        patch("k8s_sandbox._pod.op.k8s_client") as mock_client,
        patch("k8s_sandbox._pod.pod.ExecuteOperation") as exec_op,
    ):
        mock_client.return_value.read_namespaced_pod.return_value = (
            _healthy_pod_response()
        )
        exec_op.return_value.exec.side_effect = times_out_meanwhile
        with pytest.raises(ContainerRestartedError):
            asyncio.run(pod.exec(["true"], None, None, {}, None, None))


def test_the_first_restart_found_is_the_one_kept():
    pod = _make_pod()

    def stopped(*_args):
        # Another operation found the pod replaced while this one ran.
        pod._restart_error = PodReplacedError(
            pod_name="p", old_uid="uid-OLD", new_uid="uid-NEW", new_restart_count=0
        )
        raise ContainerStoppedError("stopped")

    with (
        _inline_executor(),
        patch("k8s_sandbox._pod.pod.ExecuteOperation") as exec_op,
    ):
        exec_op.return_value.exec.side_effect = stopped
        with pytest.raises(PodReplacedError):
            asyncio.run(pod._run_async(lambda: exec_op.return_value.exec()))


def test_a_result_got_before_a_restart_was_found_but_returned_after_it_is_dropped():
    pod = _make_pod()
    restart = ContainerRestartedError(
        pod_name="p", container_name="default", restart_count=1, last_reason="Error"
    )
    executor = MagicMock()

    async def queue(callable):
        result = callable()
        # Another operation finds the restart before this one resumes.
        pod._restart_error = restart
        return result

    executor.queue_operation = queue
    with patch(
        "k8s_sandbox._pod.executor.PodOpExecutor.get_instance", return_value=executor
    ):
        with pytest.raises(ContainerRestartedError):
            asyncio.run(pod._run_async(lambda: "replacement's output"))


def _restart(restart_count: int = 1) -> ContainerRestartedError:
    return ContainerRestartedError(
        pod_name="p",
        container_name="default",
        restart_count=restart_count,
        last_reason="Error",
    )


def test_a_failure_got_before_a_restart_was_found_but_raised_after_it_raises_it():
    pod = _make_pod()
    executor = MagicMock()

    async def queue(callable):
        try:
            return callable()
        finally:
            # Another operation finds the restart before this one resumes.
            pod._restart_error = _restart()

    def times_out():
        raise TimeoutError("Command timed out")

    executor.queue_operation = queue
    with patch(
        "k8s_sandbox._pod.executor.PodOpExecutor.get_instance", return_value=executor
    ):
        with pytest.raises(ContainerRestartedError):
            asyncio.run(pod._run_async(times_out))


def test_an_operation_after_a_restart_was_found_is_not_queued():
    pod = _make_pod()
    pod._restart_error = _restart()
    executor = MagicMock()
    with patch(
        "k8s_sandbox._pod.executor.PodOpExecutor.get_instance", return_value=executor
    ):
        with pytest.raises(ContainerRestartedError):
            asyncio.run(pod._run_async(lambda: None))
    executor.queue_operation.assert_not_called()


def test_the_first_restart_kept_stays():
    pod = _make_pod()
    first, second = _restart(1), _restart(2)

    assert pod._keep(first) is first
    assert pod._keep(second) is first


# Whether the check before it warned of the restart, or the check after it would.
@pytest.mark.parametrize("check", ["true", "false"])
@pytest.mark.parametrize(
    "error",
    [
        # One the provider retries.
        pytest.param(ConnectionResetError(), id="connection-reset"),
        pytest.param(FileNotFoundError("/x"), id="file-not-found"),
    ],
)
def test_warn_mode_leaves_a_failed_file_operations_error_as_it_was(
    monkeypatch, check: str, error: Exception
):
    monkeypatch.setenv("INSPECT_POD_RESTART_CHECK", check)
    with (
        _inline_executor(),
        patch("k8s_sandbox._pod.op.k8s_client") as mock_client,
        patch("k8s_sandbox._pod.pod.ReadFileOperation") as read_op,
    ):
        mock_client.return_value.read_namespaced_pod.return_value = _k8s_pod(
            uid="uid-OLD", container_name="default", restart_count=1
        )
        read_op.return_value.read_file.side_effect = error
        pod = _make_pod(restarted_container_behavior="warn")
        with pytest.raises(type(error)):
            asyncio.run(pod.read_file(pathlib.Path("/x"), io.BytesIO()))


def test_warn_mode_raises_the_restart_a_user_probe_was_warned_of_when_it_stops():
    with (
        _inline_executor(),
        patch("k8s_sandbox._pod.op.k8s_client") as mock_client,
        patch("k8s_sandbox._pod.pod.ExecuteOperation") as exec_op,
    ):
        mock_client.return_value.read_namespaced_pod.return_value = _k8s_pod(
            uid="uid-OLD", container_name="default", restart_count=1
        )
        exec_op.return_value.probe_switch.side_effect = ContainerStoppedError("stopped")
        pod = _make_pod(restarted_container_behavior="warn")
        with pytest.raises(ContainerRestartedError):
            asyncio.run(pod.exec(["true"], None, None, {}, "agent", None))
        exec_op.return_value.exec.assert_not_called()


@pytest.mark.parametrize(
    "error",
    [
        pytest.param(ConnectionResetError(), id="connection-reset"),
        pytest.param(FileNotFoundError("/x"), id="file-not-found"),
    ],
)
def test_raise_mode_checks_a_failed_file_operation_also_after_a_connection_error(
    monkeypatch, error: Exception
):
    # With the check off, the provider would retry a connection error into the
    # restarted container.
    monkeypatch.setenv("INSPECT_POD_RESTART_CHECK", "false")
    with (
        _inline_executor(),
        patch("k8s_sandbox._pod.op.k8s_client") as mock_client,
        patch("k8s_sandbox._pod.pod.ReadFileOperation") as read_op,
    ):
        mock_client.return_value.read_namespaced_pod.return_value = _k8s_pod(
            uid="uid-OLD", container_name="default", restart_count=1
        )
        read_op.return_value.read_file.side_effect = error
        pod = _make_pod()
        with pytest.raises(ContainerRestartedError):
            asyncio.run(pod.read_file(pathlib.Path("/x"), io.BytesIO()))


@pytest.mark.parametrize("check_fails", [False, True], ids=["healthy", "check-fails"])
def test_raise_mode_leaves_a_failed_file_operations_error_if_its_check_finds_nothing(
    monkeypatch, check_fails: bool
):
    # For the provider to retry.
    monkeypatch.setenv("INSPECT_POD_RESTART_CHECK", "false")
    with (
        _inline_executor(),
        patch("k8s_sandbox._pod.op.k8s_client") as mock_client,
        patch("k8s_sandbox._pod.pod.ReadFileOperation") as read_op,
    ):
        read_pod = mock_client.return_value.read_namespaced_pod
        if check_fails:
            read_pod.side_effect = ConnectionRefusedError()
        else:
            read_pod.return_value = _k8s_pod(
                uid="uid-OLD", container_name="default", restart_count=0
            )
        read_op.return_value.read_file.side_effect = ConnectionResetError()
        pod = _make_pod()
        with pytest.raises(ConnectionResetError):
            asyncio.run(pod.read_file(pathlib.Path("/x"), io.BytesIO()))
        read_pod.assert_called_once()


def test_a_check_that_gives_up_still_raises_a_restart_kept_meanwhile(monkeypatch):
    monkeypatch.setenv("INSPECT_POD_RESTART_CHECK", "false")
    pod = _make_pod()

    async def gives_up() -> None:
        pod._restart_error = _restart()
        raise TimeoutError()

    with (
        _inline_executor(),
        patch("k8s_sandbox._pod.pod.ReadFileOperation") as read_op,
        patch.object(pod, "check_for_pod_restart", gives_up),
    ):
        read_op.return_value.read_file.side_effect = FileNotFoundError("/x")
        with pytest.raises(ContainerRestartedError):
            asyncio.run(pod.read_file(pathlib.Path("/x"), io.BytesIO()))


def test_a_later_detection_does_not_replace_the_first_kept():
    pod = _make_pod()
    with patch("k8s_sandbox._pod.op.k8s_client") as mock_client:
        mock_client.return_value.read_namespaced_pod.return_value = _k8s_pod(
            uid="uid-NEW", container_name="default", restart_count=0
        )
        with pytest.raises(PodReplacedError):
            pod._check_for_pod_restart_sync()
        mock_client.return_value.read_namespaced_pod.return_value = _k8s_pod(
            uid="uid-OLD", container_name="default", restart_count=1
        )
        with pytest.raises(ContainerRestartedError):
            pod._check_for_pod_restart_sync()
    assert isinstance(pod._restart_error, PodReplacedError)
