import concurrent.futures
import socket
from unittest.mock import MagicMock

import kubernetes.client
import pytest
from kubernetes.stream.ws_client import WSClient  # type: ignore[import-untyped]

import k8s_sandbox._pod.execute as execute_module
import k8s_sandbox._pod.op as op_module
from k8s_sandbox._pod.op import PodOperation


class _ConcretePodOp(PodOperation):
    """A concrete PodOperation so the base-class helper can be exercised."""


def _make_op() -> _ConcretePodOp:
    return _ConcretePodOp(MagicMock())


@pytest.mark.parametrize(
    ("chunk_size", "data", "expected"),
    [
        (4, b"abcdefghij", [b"abcd", b"efgh", b"ij"]),
        (1024, b"hello", [b"hello"]),
        (4, "abcdefg", ["abcd", "efg"]),  # str in -> str frames out
        (4, b"", []),
        (4, b"abcdefgh", [b"abcd", b"efgh"]),  # exact multiple, no trailing write
    ],
)
def test_write_stdin_chunked(
    monkeypatch: pytest.MonkeyPatch,
    chunk_size: int,
    data: str | bytes,
    expected: list[bytes | str],
) -> None:
    monkeypatch.setattr(op_module, "STDIN_CHUNK_SIZE", chunk_size)
    ws = MagicMock(spec=WSClient)

    _make_op()._write_stdin_chunked(ws, data)

    assert [call.args[0] for call in ws.write_stdin.call_args_list] == expected


def test_write_stdin_chunked_default_chunk_size_splits_oversized_payload() -> None:
    # Regression guard: a payload one byte over the chunk size must split into
    # more than one frame.
    ws = MagicMock(spec=WSClient)

    _make_op()._write_stdin_chunked(ws, b"x" * (op_module.STDIN_CHUNK_SIZE + 1))

    assert ws.write_stdin.call_count == 2
    assert len(ws.write_stdin.call_args_list[0].args[0]) == op_module.STDIN_CHUNK_SIZE


def test_an_exec_ends_when_the_api_server_never_answers(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Regression: its websocket connected with no timeout, and its thread waited."""
    silent = socket.create_server(("127.0.0.1", 0))  # takes a connection, says nothing
    host = f"http://127.0.0.1:{silent.getsockname()[1]}"
    configuration = kubernetes.client.Configuration(host=host)
    api = kubernetes.client.CoreV1Api(kubernetes.client.ApiClient(configuration))
    monkeypatch.setattr(op_module, "k8s_client", lambda _: api)
    monkeypatch.setattr(op_module, "API_TIMEOUT", 0.5)
    pod = op_module.PodInfo("p", "ns", None, "default", "u", 0, "raise")
    pool = concurrent.futures.ThreadPoolExecutor(1)

    exec_ = pool.submit(execute_module.ExecuteOperation(pod).run_argv, ["true"])

    try:
        with pytest.raises(kubernetes.client.exceptions.ApiException):
            exec_.result(timeout=30)  # only bounds a hang
    finally:
        silent.close()  # resets the connection, so a thread still waiting ends
        pool.shutdown(wait=False)
