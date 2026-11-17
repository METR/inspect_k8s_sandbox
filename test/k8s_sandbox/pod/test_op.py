import base64
import concurrent.futures
import contextlib
import hashlib
import re
import select
import socket
import threading
import time
import types
from unittest.mock import MagicMock

import kubernetes.client
import kubernetes.stream.ws_client  # type: ignore[import-untyped]
import pytest
import websocket
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


def _upgrade(connection: socket.socket) -> None:
    """Answer a websocket's upgrade request, as an API server does an exec's."""
    request = b""
    while b"\r\n\r\n" not in request and (more := connection.recv(65536)):
        request += more
    if key := re.search(rb"(?i)sec-websocket-key: (\S+)", request):
        accept = hashlib.sha1(key[1] + b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11")
        connection.sendall(
            b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n"
            b"Connection: Upgrade\r\nSec-WebSocket-Accept: "
            + base64.b64encode(accept.digest())
            + b"\r\n\r\n"
        )


@pytest.mark.parametrize("answers", [False, True], ids=["nothing", "without end"])
def test_an_exec_ends_when_the_api_server_never_answers(
    monkeypatch: pytest.MonkeyPatch, answers: bool
) -> None:
    """Regressions: its websocket connected with no timeout; then with one a byte."""
    silent = socket.create_server(("127.0.0.1", 0))  # takes a connection
    silent.settimeout(30)  # only bounds a hang
    taken: list[socket.socket] = []

    def answer() -> None:
        connection, _ = silent.accept()
        taken.append(connection)
        with contextlib.suppress(OSError):  # until the client, or the test, ends it
            while True:
                connection.sendall(b"H" * 65536)  # one header line: no read ever waits

    server = threading.Thread(target=answer, daemon=True)
    if answers:
        server.start()
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
        if answers:  # the client shut its end: it reads no more of the answer
            end = time.monotonic() + 30  # only bounds a hang
            with contextlib.suppress(ConnectionError):  # reset: shut, too
                while select.select(taken, [], [], max(0, end - time.monotonic()))[0]:
                    if not taken[0].recv(65536):  # its request, then its end
                        break
            assert select.select(taken, [], [], 0)[0]
    finally:
        for connection in taken:
            with contextlib.suppress(OSError):
                connection.shutdown(socket.SHUT_RDWR)
            connection.close()
        silent.close()  # resets the connection, so a thread still waiting ends
        pool.shutdown(wait=False)
        if answers:
            server.join(30)


def test_an_exec_ends_in_time_though_its_proxy_answers_late(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Regressions: a stall before its socket held an exec; a late one was used."""
    listening = socket.create_server(("127.0.0.1", 0))
    listening.settimeout(30)  # only bounds a hang
    answered = threading.Event()
    after: list[bytes] = []  # what the client sent once the proxy had answered

    def proxy() -> None:
        connection, _ = listening.accept()
        with connection:
            connection.settimeout(30)  # only bounds a hang
            try:
                connection.recv(65536)  # CONNECT
                connection.sendall(b"HTTP/1.1 200 ")
                while not answered.wait(0.1):  # a byte before any read times out
                    connection.sendall(b"-")
                connection.sendall(b"\r\n\r\n")
                after.append(connection.recv(65536))
            except ConnectionError:  # reset: closed, as the end of its input says
                after.append(b"")

    server = threading.Thread(target=proxy, daemon=True)
    server.start()
    configuration = kubernetes.client.Configuration(host="http://api.invalid")
    proxy_url = f"http://127.0.0.1:{listening.getsockname()[1]}"
    configuration.proxy = proxy_url  # type: ignore[attr-defined]
    api = kubernetes.client.CoreV1Api(kubernetes.client.ApiClient(configuration))
    monkeypatch.setattr(op_module, "k8s_client", lambda _: api)
    monkeypatch.setattr(op_module, "API_TIMEOUT", 0.5)
    pod = op_module.PodInfo("p", "ns", None, "default", "u", 0, "raise")
    pool = concurrent.futures.ThreadPoolExecutor(1)

    exec_ = pool.submit(execute_module.ExecuteOperation(pod).run_argv, ["true"])

    try:
        with pytest.raises(kubernetes.client.exceptions.ApiException):
            exec_.result(timeout=30)  # only bounds a hang
        answered.set()
        server.join(30)
        assert after == [b""]  # closed, with no exec asked for
    finally:
        answered.set()
        listening.close()
        pool.shutdown(wait=False)


def test_an_upgrade_answered_after_its_deadline_is_closed_not_used(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Regression: a caller that came back late used one answered past its deadline."""
    listening = socket.create_server(("127.0.0.1", 0))
    listening.settimeout(30)  # only bounds a hang
    clock = types.SimpleNamespace(monotonic=lambda: 0.0)
    after: list[bytes] = []  # what the client sent once its upgrade was answered

    def answers_late() -> None:
        connection, _ = listening.accept()
        with connection:
            connection.settimeout(30)  # only bounds a hang
            connection.recv(1, socket.MSG_PEEK)  # the request: its socket was in time
            clock.monotonic = lambda: op_module.API_TIMEOUT + 1.0
            _upgrade(connection)
            try:
                after.append(connection.recv(65536))
            except ConnectionError:  # reset: closed, as the end of its input says
                after.append(b"")

    server = threading.Thread(target=answers_late, daemon=True)
    server.start()
    host = f"http://127.0.0.1:{listening.getsockname()[1]}"
    configuration = kubernetes.client.Configuration(host=host)
    api = kubernetes.client.CoreV1Api(kubernetes.client.ApiClient(configuration))
    monkeypatch.setattr(op_module, "k8s_client", lambda _: api)
    monkeypatch.setattr(op_module, "time", clock)
    pod = op_module.PodInfo("p", "ns", None, "default", "u", 0, "raise")
    pool = concurrent.futures.ThreadPoolExecutor(1)

    exec_ = pool.submit(execute_module.ExecuteOperation(pod).run_argv, ["true"])

    try:
        with pytest.raises(kubernetes.client.exceptions.ApiException):
            exec_.result(timeout=30)  # only bounds a hang
        server.join(30)
        assert after == [b""]  # closed, with nothing sent on it
    finally:
        listening.close()
        pool.shutdown(wait=False)


def test_kubernetes_keeps_its_own_websocket_for_its_other_users() -> None:
    """Regression: every exec in the process got the provider's, and its deadline."""
    assert kubernetes.stream.ws_client.WebSocket is websocket.WebSocket
