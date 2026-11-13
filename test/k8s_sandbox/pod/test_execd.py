import asyncio
import contextlib
import dataclasses
import hashlib
import io
import itertools
import json
import shutil
import ssl
import subprocess
import time
import types
from collections.abc import AsyncIterator, Awaitable, Callable
from pathlib import Path
from typing import Any
from unittest.mock import patch

import anyio
import pytest
from inspect_ai.util import OutputLimitExceededError, override_sandbox_output_limit
from pytest import MonkeyPatch

from k8s_sandbox._kubernetes_api import _Config
from k8s_sandbox._pod import execd
from k8s_sandbox._pod.error import (
    ContainerRestartedError,
    ExecResultUnknownError,
    PodError,
)
from k8s_sandbox._pod.pod import Pod
from test.k8s_sandbox.pod.test_check_for_pod_restart import _k8s_pod

Handler = Callable[[asyncio.StreamReader, asyncio.StreamWriter], Awaitable[None]]


async def read_frame(reader: asyncio.StreamReader) -> tuple[int, bytes]:
    kind, n = execd.HEADER.unpack(await reader.readexactly(execd.HEADER.size))
    return kind, await reader.readexactly(n)


def frame(kind: int, payload: bytes = b"") -> bytes:
    return execd.HEADER.pack(kind, len(payload)) + payload


EXIT_0 = frame(execd.EXIT, b'{"code": 0}')


Tls = tuple[ssl.SSLContext, ssl.SSLContext, str]


@pytest.fixture(scope="module")
def tls(tmp_path_factory: pytest.TempPathFactory) -> Tls:
    """A server's TLS context, one with a long handshake, and the pin for both."""
    if shutil.which("openssl") is None:
        pytest.skip("needs openssl")
    tmp_path = tmp_path_factory.mktemp("tls")
    key, cert = tmp_path / "key.pem", tmp_path / "cert.pem"
    subprocess.run(
        ["openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt"]
        + ["ec_paramgen_curve:P-256", "-nodes", "-days", "1", "-subj", "/CN=x"]
        + ["-keyout", str(key), "-out", str(cert)],
        check=True,
        capture_output=True,
    )
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(cert, key)
    chain = tmp_path / "chain.pem"
    chain.write_text(cert.read_text() * 40)  # 16 KiB of certificates to send
    long = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    long.load_cert_chain(chain, key)
    der = ssl.PEM_cert_to_DER_cert(cert.read_text())
    return context, long, hashlib.sha256(der).hexdigest()


class Daemons:
    """Stand-ins for execd, over TLS, which the client starts in turn."""

    def __init__(self, tls: Tls):
        self._context, self._long, self._pin = tls
        self._unstarted: list[execd.Daemon | Exception] = []
        self.behind: dict[int, int] = {}  # a daemon's port: the proxy's in front of it
        self.servers: list[asyncio.Server] = []
        self.starts: list[bool] = []  # each start's `replace`
        self.connections = 0  # that sent the key

    async def serve(
        self, handler: Handler, pin: str | None = None, long_handshake: bool = False
    ) -> asyncio.Server:
        """Add one that takes AUTH, then hands the connection to handler."""

        async def connection(r: asyncio.StreamReader, w: asyncio.StreamWriter) -> None:
            with contextlib.suppress(asyncio.IncompleteReadError, ConnectionError):
                assert await read_frame(r) == (execd.AUTH, b"key")
                self.connections += 1
                await handler(r, w)

        context = self._long if long_handshake else self._context
        server = await asyncio.start_server(connection, "127.0.0.1", 0, ssl=context)
        self.servers.append(server)
        port = server.sockets[0].getsockname()[1]
        self._unstarted.append(
            execd.Daemon("127.0.0.1", port, pin or self._pin, b"key")
        )
        return server

    def fail_start(self, error: Exception) -> None:
        """Add a start that fails."""
        self._unstarted.append(error)

    def client(self) -> execd.ExecdClient:
        async def start(replace: bool) -> execd.Daemon:
            self.starts.append(replace)
            await asyncio.sleep(0)  # as an exec does: other calls run meanwhile
            started = self._unstarted.pop(0)
            if isinstance(started, Exception):
                raise started
            port = self.behind.get(started.port, started.port)
            return dataclasses.replace(started, port=port)

        return execd.ExecdClient(start)


@pytest.fixture
async def daemons(tls: Tls, monkeypatch: MonkeyPatch) -> AsyncIterator[Daemons]:
    def no_cluster() -> None:
        raise AssertionError("an operation left execd for the Kubernetes API")

    # A bug that takes an operation off execd fails here: it reaches no cluster.
    monkeypatch.setattr(_Config, "get_instance", no_cluster)
    stand_ins = Daemons(tls)
    yield stand_ins
    for server in stand_ins.servers:
        server.close()


async def exits(r: asyncio.StreamReader, w: asyncio.StreamWriter) -> None:
    await read_frame(r)  # START
    w.write(frame(execd.PING) + EXIT_0)  # as execd pings while a command runs


async def gone(r: asyncio.StreamReader) -> None:
    """Wait for the client to close or reset the connection."""
    with contextlib.suppress(OSError):
        await r.read()


async def until(condition: Callable[[], bool]) -> None:
    """Wait for a condition; the budget only bounds a hang."""

    async def poll() -> None:
        while not condition():
            await asyncio.sleep(0.01)

    await asyncio.wait_for(poll(), 30)


async def run(client: execd.ExecdClient, timeout: int | None = None) -> Any:
    return await client.exec(["true"], None, None, {}, None, timeout)


async def cat(client: execd.ExecdClient) -> execd.ExecdStream:
    return await client.open_stream(["cat"], None, lambda: None)


async def test_a_pod_with_execd_runs_every_operation_over_it(daemons: Daemons) -> None:
    await daemons.serve(exits)
    pod = Pod("p", "ns", None, "default", "uid", 0, "raise", execd=True)
    assert pod._execd is not None
    pod._execd._start = daemons.client()._start

    await pod.exec(["true"], None, None, {}, None, 10)
    await pod.write_file(b"x", Path("/tmp/x"))
    await pod.read_file(Path("/tmp/x"), io.BytesIO())
    await (await pod.exec_stdio(["cat"], None)).aclose()

    await until(lambda: daemons.connections == 4)


async def test_a_connection_lost_after_start_is_not_retryable(daemons: Daemons) -> None:
    starts = 0

    async def dies_after_start(
        r: asyncio.StreamReader, w: asyncio.StreamWriter
    ) -> None:
        nonlocal starts
        await read_frame(r)
        starts += 1
        w.close()

    await daemons.serve(dies_after_start)

    # A ConnectionError would be retried, running the command again.
    with pytest.raises(ExecResultUnknownError):
        await daemons.client().exec(["touch", "/once"], None, None, {}, None, 10)
    assert starts == 1


async def test_a_lost_exec_raises_the_restart_that_explains_it_and_so_do_later_ones(
    daemons: Daemons,
) -> None:
    async def dies_after_start(
        r: asyncio.StreamReader, w: asyncio.StreamWriter
    ) -> None:
        await read_frame(r)
        w.close()

    await daemons.serve(dies_after_start)
    pod = Pod("p", "ns", None, "default", "uid", 0, "raise", execd=True)
    assert pod._execd is not None
    pod._execd._start = daemons.client()._start

    with patch("k8s_sandbox._pod.op.k8s_client", autospec=True) as api:
        read = api.return_value.read_namespaced_pod
        read.return_value = _k8s_pod("uid", "default", restart_count=0)
        with pytest.raises(ExecResultUnknownError):  # and not run again another way
            await pod.exec(["true"], None, None, {}, None, 10)
        read.return_value = _k8s_pod("uid", "default", restart_count=1)
        with pytest.raises(ContainerRestartedError):
            await pod.exec(["true"], None, None, {}, None, 10)
    later = [
        pod.exec(["true"], None, None, {}, None, 10),
        pod.write_file(b"x", Path("/tmp/x")),
        pod.read_file(Path("/tmp/x"), io.BytesIO()),
        pod.exec_stdio(["cat"], None),
    ]
    turns: list[bool] = []
    for operation in later:
        asyncio.get_running_loop().call_soon(turns.append, True)
        with pytest.raises(ContainerRestartedError):
            await operation

    assert daemons.connections == 2  # none of them reached a daemon
    assert len(turns) == 4  # each gave way first: a caller may retry in a loop


async def test_what_ran_when_a_restart_was_found_raises_it_too(
    daemons: Daemons,
) -> None:
    found = asyncio.Event()

    async def answers_once_found(
        r: asyncio.StreamReader, w: asyncio.StreamWriter
    ) -> None:
        await read_frame(r)
        await found.wait()
        w.write(frame(execd.STDOUT, b"late") + frame(execd.EXIT, b'{"code": 1}'))

    await daemons.serve(answers_once_found)
    pod = Pod("p", "ns", None, "default", "uid", 0, "raise", execd=True)
    assert pod._execd is not None
    pod._execd._start = daemons.client()._start
    stream, idle = [await pod.exec_stdio(["cat"], None) for _ in range(2)]
    receiving = asyncio.create_task(stream.receive())
    running = [
        asyncio.create_task(pod.exec(["true"], None, None, {}, None, 10)),
        asyncio.create_task(pod.write_file(b"x", Path("/tmp/x"))),
        asyncio.create_task(pod.read_file(Path("/tmp/x"), io.BytesIO())),
    ]
    await until(lambda: daemons.connections == 5)

    with patch("k8s_sandbox._pod.op.k8s_client", autospec=True) as api:
        restarted = _k8s_pod("uid", "default", restart_count=1)
        api.return_value.read_namespaced_pod.return_value = restarted
        with pytest.raises(ContainerRestartedError):
            await pod.check_for_pod_restart()
    with pytest.raises(anyio.BrokenResourceError, match="ContainerRestartedError"):
        await asyncio.wait_for(idle.receive(), 30)  # with no output to wait for
    found.set()

    for operation in running:
        with pytest.raises(ContainerRestartedError):
            await operation
    with pytest.raises(anyio.BrokenResourceError, match="ContainerRestartedError"):
        await receiving
    for send in (stream.send(b"to a container that is gone"), stream.send_eof()):
        with pytest.raises(anyio.BrokenResourceError, match="ContainerRestartedError"):
            await send


async def test_a_daemon_that_is_gone_is_started_again(daemons: Daemons) -> None:
    first = await daemons.serve(exits)
    await daemons.serve(exits)
    client = daemons.client()
    await run(client)
    first.close()  # the daemon is gone: its port refuses connections
    await first.wait_closed()

    assert (await run(client)).success

    assert daemons.starts == [True, False]  # the second can't stop one that answers


async def test_a_daemon_that_cannot_be_reached_is_left_running(
    daemons: Daemons,
) -> None:
    server = await daemons.serve(exits)
    daemons.fail_start(execd.DaemonRunning("bind: address already in use"))
    server.close()  # as a network that lets no connection through
    await server.wait_closed()

    # Retryable, after one connect and one start that finds it running: not replaced.
    with pytest.raises(ConnectionError, match="execd unreachable"):
        await run(daemons.client())

    assert daemons.starts == [True, False]


async def test_a_port_held_at_the_first_start_says_so(daemons: Daemons) -> None:
    daemons.fail_start(execd.DaemonRunning("bind: address already in use"))

    with pytest.raises(RuntimeError, match="held by a process other than execd"):
        await run(daemons.client())


async def test_what_answers_without_tls_is_not_our_daemon(daemons: Daemons) -> None:
    async def answers_in_http(r: asyncio.StreamReader, w: asyncio.StreamWriter) -> None:
        w.write(b"HTTP/1.1 400 Bad Request\r\n\r\n")

    server = await daemons.serve(exits)
    daemons.fail_start(execd.DaemonRunning("bind: address already in use"))
    client = daemons.client()
    await run(client)
    port = server.sockets[0].getsockname()[1]
    server.close()  # as execd gone, and its port taken by another process
    plain = await asyncio.start_server(answers_in_http, "127.0.0.1", port)
    daemons.servers.append(plain)

    with pytest.raises(RuntimeError, match="held by a process other than execd"):
        await run(client)

    assert daemons.starts == [True, True]  # the second to replace what isn't ours


async def test_a_daemon_that_is_not_ours_gets_no_key_and_is_replaced(
    daemons: Daemons,
) -> None:
    await daemons.serve(exits, pin="0" * 64)  # another certificate than it reported
    await daemons.serve(exits)

    assert (await run(daemons.client())).success

    assert daemons.starts == [True, True]
    assert daemons.connections == 1  # the first got no key


async def test_a_daemon_reached_before_is_still_replaced_once_it_is_not_ours(
    daemons: Daemons,
) -> None:
    ours = await daemons.serve(exits)
    await daemons.serve(exits, pin="0" * 64)  # as one whose start's reply was lost
    await daemons.serve(exits)
    client = daemons.client()
    await run(client)
    ours.close()
    await ours.wait_closed()

    # The call that starts it fails after its second connect, and may be made again.
    with pytest.raises(ConnectionError, match="execd unreachable"):
        await run(client)
    assert (await run(client)).success

    assert daemons.starts == [True, False, True]


async def test_calls_made_together_start_one_daemon(daemons: Daemons) -> None:
    await daemons.serve(exits)
    client = daemons.client()

    results = await asyncio.gather(*(run(client) for _ in range(5)))

    assert all(result.success for result in results)
    assert daemons.starts == [True]


async def test_execd_s_word_that_a_command_timed_out_raises(daemons: Daemons) -> None:
    requests = []

    async def times_out(r: asyncio.StreamReader, w: asyncio.StreamWriter) -> None:
        requests.append(json.loads((await read_frame(r))[1]))
        w.write(frame(execd.EXIT, b'{"code": 137, "timeout": true}'))

    await daemons.serve(times_out)

    with pytest.raises(TimeoutError, match="Command timed out after 5s"):
        await run(daemons.client(), timeout=5)
    assert requests[0]["timeout"] == 5  # execd kills it then


@pytest.mark.parametrize("unread", ["start", "stdin"])
async def test_a_command_execd_never_ends_times_out_and_is_dropped(
    daemons: Daemons, monkeypatch: MonkeyPatch, unread: str
) -> None:
    dropped = asyncio.Event()

    async def never_ends(r: asyncio.StreamReader, w: asyncio.StreamWriter) -> None:
        if unread == "stdin":
            await read_frame(r)  # START, and no stdin after it
        with contextlib.suppress(ConnectionError):
            while True:  # as execd finds a client gone
                w.write(frame(execd.PING))
                await w.drain()
                await asyncio.sleep(0.01)
        dropped.set()

    await daemons.serve(never_ends)
    passing_clock(monkeypatch)  # past the timeout and the wait for execd's word
    big = "x" * (64 << 20)  # more than TCP holds: only an abort drops it unsent
    argv, stdin = ([big], None) if unread == "start" else (["cat"], big)

    with pytest.raises(TimeoutError, match="Command timed out after 1s"):
        run = daemons.client().exec(argv, stdin, None, {}, None, 1)
        await asyncio.wait_for(run, 30)
    await asyncio.wait_for(dropped.wait(), 30)  # which makes execd kill the command


async def test_a_timeout_of_zero_is_none(
    daemons: Daemons, monkeypatch: MonkeyPatch
) -> None:
    await daemons.serve(exits)
    passing_clock(monkeypatch)  # any deadline would have passed

    assert (await run(daemons.client(), timeout=0)).success  # as execd takes it


async def test_a_daemon_that_goes_silent_is_a_lost_connection(
    daemons: Daemons, monkeypatch: MonkeyPatch
) -> None:
    async def silent(r: asyncio.StreamReader, w: asyncio.StreamWriter) -> None:
        await gone(r)

    await daemons.serve(silent)
    monkeypatch.setattr(execd, "DEAD_AFTER", 0.05)

    with pytest.raises(ExecResultUnknownError, match="went silent"):
        await asyncio.wait_for(run(daemons.client()), 30)


async def test_a_loop_too_busy_to_read_does_not_take_execd_for_silent(
    daemons: Daemons, tls: Tls, monkeypatch: MonkeyPatch
) -> None:
    monkeypatch.setattr(execd, "DEAD_AFTER", 0.1)  # less than the loop is held
    monkeypatch.setattr(tls[0], "num_tickets", 0)  # so only the answer is to be read

    async def answers_while_the_loop_is_held(
        r: asyncio.StreamReader, w: asyncio.StreamWriter
    ) -> None:
        await read_frame(r)
        # Holds the client's loop too: its read times out as the answer arrives.
        time.sleep(0.15)
        w.write(EXIT_0)

    await daemons.serve(answers_while_the_loop_is_held)

    assert (await run(daemons.client())).success


async def test_a_write_sends_its_bytes_then_the_end_of_stdin(daemons: Daemons) -> None:
    data = bytes(range(256)) * (3 * execd.CHUNK // 256 + 1)  # a few frames, and a part
    received = bytearray()

    async def reads_stdin(r: asyncio.StreamReader, w: asyncio.StreamWriter) -> None:
        await read_frame(r)
        while payload := (await read_frame(r))[1]:
            received.extend(payload)
        w.write(EXIT_0)

    await daemons.serve(reads_stdin)

    await daemons.client().write_file(data, Path("/tmp/f"))

    assert bytes(received) == data


FILE_OPERATIONS: dict[str, Callable[[execd.ExecdClient], Awaitable[None]]] = {
    "write": lambda client: client.write_file(b"data", Path("/tmp/f")),
    "read": lambda client: client.read_file(Path("/tmp/f"), io.BytesIO()),
}


@pytest.mark.parametrize("operation", ["write", "read"])
@pytest.mark.parametrize("kind", [execd.STDERR, execd.STDOUT])
async def test_a_file_operation_stops_at_its_output_limit(
    daemons: Daemons, kind: int, operation: str
) -> None:
    async def chatters(r: asyncio.StreamReader, w: asyncio.StreamWriter) -> None:
        await read_frame(r)
        w.write(frame(kind, b"x" * 2048) + EXIT_0)  # past the limit, then done

    await daemons.serve(chatters)

    with override_sandbox_output_limit(1024), pytest.raises(OutputLimitExceededError):
        await FILE_OPERATIONS[operation](daemons.client())


async def test_a_file_operation_s_lost_connection_may_be_retried(
    daemons: Daemons,
) -> None:
    async def goes_away(r: asyncio.StreamReader, w: asyncio.StreamWriter) -> None:
        await read_frame(r)
        w.close()

    await daemons.serve(goes_away)
    client = daemons.client()

    for operation in FILE_OPERATIONS.values():
        with pytest.raises(PodError) as lost:  # which the sandbox environment retries
            await operation(client)
        assert not isinstance(lost.value, ExecResultUnknownError)


async def test_only_execd_itself_reports_an_unknown_user(daemons: Daemons) -> None:
    async def answers(r: asyncio.StreamReader, w: asyncio.StreamWriter) -> None:
        request = json.loads((await read_frame(r))[1])
        w.write(frame(execd.STDERR, b"execd: unknown user nobody2\n"))
        if request["user"]:  # execd couldn't start it
            status = b'{"code": 126, "error": "unknown user nobody2"}'
        else:  # a command printing the same
            status = b'{"code": 0}'
        w.write(frame(execd.EXIT, status))

    await daemons.serve(answers)
    client = daemons.client()

    assert (await client.exec(["sh"], None, None, {}, None, 30)).success
    with pytest.raises(RuntimeError, match="does not appear to exist"):
        await client.exec(["true"], None, None, {}, "nobody2", 30)


def passing_clock(monkeypatch: MonkeyPatch) -> None:
    """Make every look at the clock the calls' deadlines run on find 100 s gone."""
    clock = types.SimpleNamespace(monotonic=itertools.count(0, 100).__next__)
    monkeypatch.setattr(execd, "time", clock)


def frozen_clock(monkeypatch: MonkeyPatch) -> list[float]:
    """Stop the clock the bounds run on, at a time the test may then set."""
    now = [0.0]
    monkeypatch.setattr(execd, "time", types.SimpleNamespace(monotonic=lambda: now[0]))
    return now


@pytest.mark.parametrize(
    "sent",
    [
        frame(execd.STDERR, b"x") * 20_000,  # execd: one a millisecond
        frame(99),
        frame(execd.STDOUT, b"x" * (execd.CHUNK + 1)),
        frame(execd.EXIT, b"[]"),
        frame(execd.EXIT, b'{"code": "0"}'),
        frame(execd.EXIT, b'{"code": 0, "error": 5}'),
        frame(execd.EXIT, b"[" * 2000 + b"]" * 2000),
        frame(execd.EXIT, b'{"code": 0, "timeout": "no"}'),
    ],
    ids=["many-frames", "unknown-type", "large-output", "exit-not-an-object"]
    + ["exit-code-not-a-number", "exit-error-not-text", "exit-nested-too-deep"]
    + ["exit-timeout-not-a-flag"],
)
async def test_what_execd_never_sends_breaks_its_daemon_for_good(
    daemons: Daemons, monkeypatch: MonkeyPatch, sent: bytes
) -> None:
    async def not_execd(r: asyncio.StreamReader, w: asyncio.StreamWriter) -> None:
        await read_frame(r)
        w.write(sent + EXIT_0)

    server = await daemons.serve(not_execd)
    client = daemons.client()
    frozen_clock(monkeypatch)

    with pytest.raises(execd.NotExecd):
        await run(client)
    server.close()  # as a daemon that is gone, which a call would start again
    await server.wait_closed()
    with pytest.raises(execd.NotExecd):
        await run(client)

    assert daemons.starts == [True]  # no daemon was started in its place


async def test_frames_at_execd_s_pace_are_within_its_bounds(
    daemons: Daemons, monkeypatch: MonkeyPatch
) -> None:
    now = frozen_clock(monkeypatch)

    async def a_frame_a_millisecond(
        r: asyncio.StreamReader, w: asyncio.StreamWriter
    ) -> None:
        await read_frame(r)
        now[0] = 10.0  # as if for ten seconds
        w.write(frame(execd.STDERR, b"x") * 20_000 + EXIT_0)

    await daemons.serve(a_frame_a_millisecond)

    assert len((await run(daemons.client())).stderr) == 20_000


async def test_a_broken_daemon_s_open_stream_and_running_call_stop_too(
    daemons: Daemons,
) -> None:
    broke = asyncio.Event()

    async def not_execd_on_its_third(
        r: asyncio.StreamReader, w: asyncio.StreamWriter
    ) -> None:
        mine = daemons.connections
        await read_frame(r)
        if mine == 1:
            w.write(frame(execd.STDOUT, b"held"))
        elif mine == 2:
            await broke.wait()
            w.write(EXIT_0)
        else:
            w.write(frame(99))
        await gone(r)

    server = await daemons.serve(not_execd_on_its_third)
    client = daemons.client()
    stream = await cat(client)
    assert await stream.receive(1) == b"h"
    running = asyncio.create_task(run(client))
    await until(lambda: daemons.connections == 2)

    with pytest.raises(execd.NotExecd):
        await run(client)
    broke.set()

    with pytest.raises(execd.NotExecd):  # though its exit then came
        await running
    with pytest.raises(execd.NotExecd):
        await stream.send(b"to what is not execd")
    with pytest.raises(execd.NotExecd):  # though it holds output
        await stream.receive()
    port = server.sockets[0].getsockname()[1]
    server.close()
    dialled = []

    async def counts(r: asyncio.StreamReader, w: asyncio.StreamWriter) -> None:
        dialled.append(w)
        w.close()

    plain = await asyncio.start_server(counts, "127.0.0.1", port)
    daemons.servers.append(plain)
    with pytest.raises(execd.NotExecd):
        await run(client)
    assert not dialled  # a later call opens no connection


async def test_a_client_broken_while_a_call_connects_starts_no_daemon(
    daemons: Daemons,
) -> None:
    told, hung_up = asyncio.Event(), asyncio.Event()

    async def not_execd_when_told(
        r: asyncio.StreamReader, w: asyncio.StreamWriter
    ) -> None:
        await read_frame(r)
        await told.wait()
        w.write(frame(99))
        await gone(r)

    async def hangs_up_when_told(
        r: asyncio.StreamReader, w: asyncio.StreamWriter
    ) -> None:
        await hung_up.wait()
        w.close()

    server = await daemons.serve(not_execd_when_told)
    client = daemons.client()
    stream = await cat(client)
    port = server.sockets[0].getsockname()[1]
    server.close()  # the daemon listens no more, as one that is gone; the stream stays
    plain = await asyncio.start_server(hangs_up_when_told, "127.0.0.1", port)
    daemons.servers.append(plain)
    call = asyncio.create_task(run(client))  # which waits in a handshake none answers
    told.set()
    with pytest.raises(execd.NotExecd):
        await stream.receive()
    hung_up.set()

    with pytest.raises(execd.NotExecd):
        await call

    assert daemons.starts == [True]


async def test_a_stream_s_exit_that_is_not_execd_s_breaks_its_daemon(
    daemons: Daemons,
) -> None:
    async def not_a_status(r: asyncio.StreamReader, w: asyncio.StreamWriter) -> None:
        await read_frame(r)
        w.write(frame(execd.EXIT, b"[]"))

    await daemons.serve(not_a_status)
    client = daemons.client()
    stream = await cat(client)

    with pytest.raises(execd.NotExecd):
        await stream.receive()
    with pytest.raises(execd.NotExecd):
        await run(client)


async def test_more_tls_records_than_execd_sends_break_its_daemon(
    daemons: Daemons, monkeypatch: MonkeyPatch
) -> None:
    async def tiny_records(r: asyncio.StreamReader, w: asyncio.StreamWriter) -> None:
        await read_frame(r)
        for byte in frame(execd.STDOUT, b"x" * 20_000):  # one frame
            w.write(bytes([byte]))  # in a TLS record a byte
        w.write(EXIT_0)

    await daemons.serve(tiny_records)
    frozen_clock(monkeypatch)

    with pytest.raises(execd.NotExecd, match="TLS records"):
        await run(daemons.client())


async def trickling(daemons: Daemons, monkeypatch: MonkeyPatch, after: int) -> None:
    """Put a daemon behind a proxy that passes on a byte a segment, AFTER the first."""

    async def prints(r: asyncio.StreamReader, w: asyncio.StreamWriter) -> None:
        await read_frame(r)
        w.write(frame(execd.STDOUT, b"x" * 65536) + EXIT_0)

    # A handshake long enough to pass the bound however its bytes are read.
    server = await daemons.serve(prints, long_handshake=after == 0)
    daemon_port = server.sockets[0].getsockname()[1]

    async def trickle(r: asyncio.StreamReader, w: asyncio.StreamWriter) -> None:
        daemon, to_daemon = await asyncio.open_connection("127.0.0.1", daemon_port)

        async def to_client() -> None:
            passed = 0
            with contextlib.suppress(ConnectionError):
                while data := await daemon.read(65536):
                    whole = data[: max(0, after - passed)]
                    passed += len(data)
                    w.write(whole)
                    for i in range(len(whole), len(data)):
                        w.write(data[i : i + 1])
                        await w.drain()
                        await asyncio.sleep(0)

        task = asyncio.create_task(to_client())
        while data := await r.read(65536):
            to_daemon.write(data)
        task.cancel()

    proxy = await asyncio.start_server(trickle, "127.0.0.1", 0)
    daemons.servers.append(proxy)
    daemons.behind[daemon_port] = proxy.sockets[0].getsockname()[1]
    frozen_clock(monkeypatch)


async def test_more_tcp_reads_than_execd_makes_break_its_daemon(
    daemons: Daemons, monkeypatch: MonkeyPatch
) -> None:
    await trickling(daemons, monkeypatch, after=8192)  # its handshake, and some
    client = daemons.client()

    with pytest.raises(execd.NotExecd, match="TCP reads"):
        await run(client)


async def test_a_server_not_yet_pinned_cannot_break_the_daemon(
    daemons: Daemons, monkeypatch: MonkeyPatch
) -> None:
    await trickling(daemons, monkeypatch, after=0)  # from its handshake's first byte
    await daemons.serve(exits)
    client = daemons.client()

    assert (await run(client)).success  # on the daemon started in its place

    assert daemons.starts == [True, True]
    assert client.broken is None


async def test_a_large_read_is_within_execd_s_bounds(
    daemons: Daemons, monkeypatch: MonkeyPatch
) -> None:
    size = 32 << 20

    async def large(r: asyncio.StreamReader, w: asyncio.StreamWriter) -> None:
        await read_frame(r)
        for _ in range(size // execd.CHUNK):
            w.write(frame(execd.STDOUT, b"x" * execd.CHUNK))
            await w.drain()
        w.write(EXIT_0)

    await daemons.serve(large)
    frozen_clock(monkeypatch)  # so only its bytes allow for its records and reads
    got = io.BytesIO()

    await daemons.client().read_file(Path("/big"), got)

    assert got.tell() == size


async def echoes(r: asyncio.StreamReader, w: asyncio.StreamWriter) -> None:
    """As `cat` would: stdin to stdout, to stdin's end."""
    await read_frame(r)
    while payload := (await read_frame(r))[1]:
        w.write(frame(execd.STDERR, b"noise") + frame(execd.STDOUT, payload))
    w.write(EXIT_0)


async def test_a_stream_carries_stdin_and_stdout_to_the_command_s_exit(
    daemons: Daemons,
) -> None:
    await daemons.serve(echoes)
    stream = await cat(daemons.client())

    await stream.send(b"abc")
    assert await stream.receive(2) == b"ab"
    with anyio.CancelScope() as cancelled:
        cancelled.cancel()
        await stream.receive()
        pytest.fail("a cancelled receive took output")
    with anyio.CancelScope() as cancelled:
        cancelled.cancel()
        await stream.send(b"from a caller that is gone")
    assert await stream.receive() == b"c"
    await stream.send_eof()

    with pytest.raises(anyio.EndOfStream):
        await stream.receive()
    with pytest.raises(anyio.BrokenResourceError):  # not lost in silence
        await stream.send(b"late")


async def test_a_receive_cancelled_partway_through_a_frame_loses_none_of_it(
    daemons: Daemons,
) -> None:
    rest = asyncio.Event()

    async def in_two_parts(r: asyncio.StreamReader, w: asyncio.StreamWriter) -> None:
        await read_frame(r)
        first, second = frame(execd.STDOUT, b"first"), frame(execd.STDOUT, b"second")
        w.write(first + second[:8])  # one TLS record: the stream holds it all at once
        await rest.wait()
        w.write(second[8:])

    await daemons.serve(in_two_parts)
    stream = await cat(daemons.client())
    assert await stream.receive() == b"first"
    receiving = asyncio.create_task(stream.receive())
    await asyncio.sleep(0)  # it has the second frame's start, and waits for its rest

    receiving.cancel()
    with pytest.raises(asyncio.CancelledError):
        await receiving
    rest.set()

    assert await stream.receive() == b"second"


async def test_a_stream_s_start_says_so_and_closing_it_drops_the_connection(
    daemons: Daemons,
) -> None:
    requests = []
    dropped = asyncio.Event()

    async def records(r: asyncio.StreamReader, w: asyncio.StreamWriter) -> None:
        requests.append(json.loads((await read_frame(r))[1]))
        await gone(r)
        dropped.set()

    await daemons.serve(records)
    stream = await cat(daemons.client())
    receiving = asyncio.create_task(stream.receive())
    await asyncio.sleep(0)  # it waits for output

    await stream.aclose()

    await asyncio.wait_for(dropped.wait(), 30)  # which makes execd end the command
    assert requests[0]["stream"]  # so execd kills only the command itself
    with pytest.raises(anyio.ClosedResourceError):
        await receiving


async def test_a_stream_whose_connection_is_lost_is_broken(daemons: Daemons) -> None:
    async def goes_away(r: asyncio.StreamReader, w: asyncio.StreamWriter) -> None:
        await read_frame(r)
        w.close()

    await daemons.serve(goes_away)
    stream = await cat(daemons.client())

    with pytest.raises(anyio.BrokenResourceError):
        await stream.receive()


async def test_a_closed_stream_gives_no_more_of_what_it_held(daemons: Daemons) -> None:
    await daemons.serve(echoes)
    stream = await cat(daemons.client())
    await stream.send(b"abc")
    assert await stream.receive(1) == b"a"  # the rest stays with the stream

    await stream.aclose()

    with pytest.raises(anyio.ClosedResourceError):
        await stream.receive()


async def test_concurrent_sends_on_a_stream_stay_whole(daemons: Daemons) -> None:
    size = 16 << 20  # more than the socket buffers, so the first send waits partway
    received = bytearray()
    go = asyncio.Event()

    async def records_stdin(r: asyncio.StreamReader, w: asyncio.StreamWriter) -> None:
        await read_frame(r)
        await go.wait()  # unread, the sends back up
        while len(received) < 2 * size:
            received.extend((await read_frame(r))[1])

    await daemons.serve(records_stdin)
    stream = await cat(daemons.client())

    sends = asyncio.gather(stream.send(b"A" * size), stream.send(b"B" * size))
    await until(stream._send_lock.locked)  # a send is under way
    go.set()
    await asyncio.wait_for(sends, 30)
    await until(lambda: len(received) == 2 * size)

    assert bytes(received) in (b"A" * size + b"B" * size, b"B" * size + b"A" * size)


async def test_closing_a_stream_ends_a_send_the_command_is_not_reading(
    daemons: Daemons,
) -> None:
    async def never_reads(r: asyncio.StreamReader, w: asyncio.StreamWriter) -> None:
        await read_frame(r)
        await asyncio.sleep(3600)

    await daemons.serve(never_reads)
    stream = await cat(daemons.client())
    send = asyncio.create_task(stream.send(b"x" * (64 << 20)))  # more than TCP holds
    await until(stream._send_lock.locked)

    await stream.aclose()

    with pytest.raises(anyio.BrokenResourceError):
        await asyncio.wait_for(send, 30)


def test_only_one_fingerprint_line_starts_execd() -> None:
    assert execd.started("ip", b"k", 0, b"0" * 64 + b"\n", b"").fingerprint == "0" * 64

    cut = b"1" * 64 + b" " * 4032  # one token, but cut at run_argv's 4 KiB
    with pytest.raises(PodError, match="execd did not start"):
        execd.started("ip", b"k", 0, cut, b"")


def test_a_start_replaces_only_when_asked_and_says_when_the_port_is_taken() -> None:
    said = b"execd: daemon did not start: listen tcp :24601: bind: "

    with pytest.raises(execd.DaemonRunning):
        execd.started("ip", b"k", 2, b"", said + b"address already in use\n")

    asked = ["--replace" in execd.start_command(b"k", r) for r in (False, True)]
    assert asked == [False, True]
