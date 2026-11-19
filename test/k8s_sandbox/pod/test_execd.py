import asyncio
import collections.abc
import contextlib
import gc
import hashlib
import io
import itertools
import json
import math
import os
import pathlib
import shutil
import signal
import socket
import ssl
import struct
import subprocess
import sys
import threading
import time
import types
import urllib.parse

import anyio
import anyio.abc
import inspect_ai.util
import kubernetes.client.exceptions
import pytest

from k8s_sandbox import _helm, _sandbox_environment
from k8s_sandbox._pod import error, execd, op, snapshot
from k8s_sandbox._pod import pod as pod_module

Handler = collections.abc.Callable[
    [asyncio.StreamReader, asyncio.StreamWriter], collections.abc.Awaitable[None]
]
TlsDaemon = collections.abc.Callable[
    [Handler], collections.abc.Awaitable[execd.ExecdClient]
]


async def read_frame(reader: asyncio.StreamReader) -> tuple[int, int, bytes]:
    kind, call_id, n = execd.HEADER.unpack(await reader.readexactly(execd.HEADER.size))
    return kind, call_id, await reader.readexactly(n)


def frame(kind: int, call_id: int, payload: bytes = b"") -> bytes:
    return execd.HEADER.pack(kind, call_id, len(payload)) + payload


class Daemons:
    """Stand-ins for execd, which the client starts in turn."""

    def __init__(self) -> None:
        self.ports: dict[execd.Daemon, int] = {}
        self.unstarted: list[execd.Daemon] = []

    async def serve(self, handler: Handler, pod: str = "") -> asyncio.Server:
        """One that answers AUTH, then hands the connection to handler."""

        async def connection(r: asyncio.StreamReader, w: asyncio.StreamWriter) -> None:
            # Before Python 3.12 a read that fails here is reported in a later test.
            with contextlib.suppress(asyncio.IncompleteReadError, ConnectionError):
                await read_frame(r)  # AUTH
                w.write(frame(execd.OK, 0))
                await handler(r, w)

        server = await asyncio.start_server(connection, "127.0.0.1", 0)
        daemon = execd.Daemon("127.0.0.1", f"cert-{len(self.ports)}", b"key", pod)
        self.ports[daemon] = server.sockets[0].getsockname()[1]
        self.unstarted.append(daemon)
        return server

    def client(
        self, pod: collections.abc.Callable[[], str] = lambda: ""
    ) -> execd.ExecdClient:
        async def start(replace: bool) -> execd.Daemon:
            return self.unstarted.pop(0)

        return execd.ExecdClient(start, pod)


class Plain(execd._Pipe):
    """execd's pipe over plain TCP: these tests are about the protocol, not TLS."""

    def __init__(self, r: asyncio.StreamReader, w: asyncio.StreamWriter) -> None:
        self._reader, self._writer = r, w
        self.starts = 0  # the STARTs written to it

    async def readexactly(self, n: int) -> bytes:
        try:
            return await self._reader.readexactly(n)  # type: ignore[union-attr]
        except asyncio.IncompleteReadError:  # as execd's own pipe ends
            raise ConnectionResetError("execd closed the connection") from None

    async def write(self, data: bytes) -> None:
        self.starts += data[0] == execd.START
        self._writer.write(data)
        await self._writer.drain()


@pytest.fixture
def daemons(monkeypatch: pytest.MonkeyPatch) -> Daemons:
    stand_ins = Daemons()

    async def connect(daemon: execd.Daemon, pace: execd.Pace) -> execd._Pipe:
        r, w = await asyncio.open_connection("127.0.0.1", stand_ins.ports[daemon])
        return Plain(r, w)

    monkeypatch.setattr(execd, "_connect", connect)
    return stand_ins


async def until(condition: collections.abc.Callable[[], bool]) -> None:
    """Wait for a condition; the budget only bounds a hang."""

    async def poll() -> None:
        while not condition():
            await asyncio.sleep(0.01)

    await asyncio.wait_for(poll(), 30)


def held(stream: execd.ExecdStream) -> int:
    queued = list(stream._call.queue._queue)  # type: ignore[attr-defined]
    return sum(len(item[1]) for item in queued if isinstance(item, tuple))


def waiting(link: execd.Link) -> bool:
    """Whether a frame waits to be sent, behind another call's write."""
    return bool(link._wlock._waiters)


def starts_written(client: execd.ExecdClient) -> int:
    """How many STARTs its connection has written: a call's time runs from its own."""
    pipe = client._link.pipe if client._link else None
    return pipe.starts if isinstance(pipe, Plain) else 0


@pytest.fixture(autouse=True)
async def no_spin() -> collections.abc.AsyncIterator[None]:
    """A loop that spins gives a test's own timeouts no turn: a signal needs none."""
    if (  # no signal to be had: Windows, a thread, or another's alarm armed
        not hasattr(signal, "setitimer")
        or threading.current_thread() is not threading.main_thread()
        or signal.getitimer(signal.ITIMER_REAL)[0]
    ):
        yield
        return
    spun: list[str] = []

    def end(*_: object) -> None:
        spun.append("the event loop gave this test's own timeouts no turn in 30 s")
        pytest.fail(spun[0])  # in the task that spins: the test's end says it too

    async def beat() -> None:
        # Ours until another takes it: put off each second the loop turns, due in 30 s.
        while signal.getsignal(signal.SIGALRM) is end:
            signal.setitimer(signal.ITIMER_REAL, 30, 30)
            await asyncio.sleep(1)

    was = signal.signal(signal.SIGALRM, end)
    beating = asyncio.ensure_future(beat())
    yield
    beating.cancel()
    if signal.getsignal(signal.SIGALRM) is end:
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, was)
    assert not spun, spun[0]


@pytest.fixture(autouse=True)
def no_timer_lag(monkeypatch: pytest.MonkeyPatch) -> float:
    """Our timer fires at the timeout: no stand-in here has one of its own to follow."""
    lag = execd.TIMER_LAG
    monkeypatch.setattr(execd, "TIMER_LAG", 0.0)
    return lag


@pytest.fixture
def clock(monkeypatch: pytest.MonkeyPatch) -> types.SimpleNamespace:
    """Stand in for execd's clocks and sleeps: a sleep only moves the clock on."""
    fake = types.SimpleNamespace(now=0.0, cpu=lambda: 0.0)

    async def sleep(seconds: float) -> None:
        if seconds >= execd.PING_EVERY:  # a connection's pings never come
            await asyncio.Event().wait()
        # In whole milliseconds, as a loop's timers are: a shorter sleep takes one.
        fake.now += math.ceil(max(seconds, 0.0) * 1000 - 1e-6) / 1000
        await asyncio.sleep(0)

    clocks = types.SimpleNamespace(
        monotonic=lambda: fake.now, thread_time=lambda: fake.cpu()
    )
    monkeypatch.setattr(execd, "time", clocks)
    monkeypatch.setattr(
        execd, "asyncio", types.SimpleNamespace(**{**vars(asyncio), "sleep": sleep})
    )
    return fake


@pytest.fixture
def timers(clock: types.SimpleNamespace, monkeypatch: pytest.MonkeyPatch) -> None:
    """Have execd's waits end by the tests' clock too: no test races a real timer."""

    async def wait_for(
        awaited: collections.abc.Awaitable[object], timeout: float | None
    ) -> object:
        if timeout is None:
            return await awaited
        task, end = asyncio.ensure_future(awaited), clock.now + timeout
        try:
            while not task.done() and clock.now < end:
                clock.looks += 1
                await asyncio.wait({task}, timeout=0.001)
        finally:
            if expired := not task.done():
                task.cancel()
                await asyncio.wait({task})
        if expired and task.cancelled():
            clock.expired += 1
            raise asyncio.TimeoutError
        return task.result()

    clock.expired = 0  # the waits that have run out, for a test to wait on one
    clock.looks = 0  # at the clock: one more, and a wait has seen where it stands
    monkeypatch.setattr(execd.asyncio, "wait_for", wait_for)


@pytest.fixture
def interval(
    clock: types.SimpleNamespace, monkeypatch: pytest.MonkeyPatch
) -> collections.abc.Callable[[], None]:
    """Have a connection's ping intervals end at the test's word, on its clock."""
    told = asyncio.Event()
    sleep = execd.asyncio.sleep

    async def until_told(seconds: float) -> None:
        if seconds < execd.PING_EVERY:
            return await sleep(seconds)
        await told.wait()
        told.clear()
        clock.now += seconds

    monkeypatch.setattr(execd.asyncio, "sleep", until_told)
    return told.set


async def test_an_annotated_pod_runs_every_operation_over_execd(
    daemons: Daemons, monkeypatch: pytest.MonkeyPatch
) -> None:
    starts = 0

    async def exits(r: asyncio.StreamReader, w: asyncio.StreamWriter) -> None:
        nonlocal starts
        while True:
            kind, call_id, _ = await read_frame(r)
            if kind == execd.START:
                starts += 1
                w.write(frame(execd.EXIT, call_id, b'{"code": 0}'))

    await daemons.serve(exits, pod="u")
    # As in test_helm.py: no cluster config needed.
    monkeypatch.setattr("k8s_sandbox._helm.get_default_namespace", lambda _: "default")
    release = _helm.Release(__file__, None, _helm.ValuesSource.none(), None)
    release._ready_pods = [
        snapshot.PodSnapshot(
            name="p",
            uid="u",
            labels={"inspect/service": "default"},
            container_names=("default",),
            container_statuses=None,
            phase="Running",
            ip="10.0.0.1",
            annotations={execd.ANNOTATION: "true"},
        )
    ]
    pod = (await release.get_sandbox_pods())["default"]
    assert pod._execd is not None
    pod._execd._start = daemons.client()._start

    await pod.exec(["true"], None, None, {}, None, 30)
    await pod.write_file(b"x", pathlib.Path("/tmp/x"))
    await pod.read_file(pathlib.Path("/tmp/x"), io.BytesIO())
    await (await pod.exec_stdio(["cat"], None)).aclose()

    await until(lambda: starts == 4)


class Cluster:
    """What Kubernetes shows of pod p: running, its container restarted this often."""

    restarts = reads = 0
    uid, ip = "u", "10.0.0.1"
    unavailable = False  # its next read fails
    held: threading.Event | None = None  # its reads wait for it

    def read_namespaced_pod(self, **_: object) -> types.SimpleNamespace:
        self.reads += 1
        if self.held is not None:
            self.held.wait(60)  # past a test's bound: one never set fails its test
        if self.unavailable:
            self.unavailable = False
            raise kubernetes.client.exceptions.ApiException(status=503)
        container = {
            "name": "default",
            "restartCount": self.restarts,
            "state": {"running": {}},
        }
        pod = {
            "metadata": {"name": "p", "uid": self.uid},
            "status": {"podIP": self.ip, "containerStatuses": [container]},
        }
        return types.SimpleNamespace(data=json.dumps(pod))


@pytest.fixture
def cluster(monkeypatch: pytest.MonkeyPatch) -> collections.abc.Iterator[Cluster]:
    shown = Cluster()
    monkeypatch.setattr(op, "k8s_client", lambda _: shown)
    monkeypatch.setattr(pod_module, "k8s_client", lambda _: shown)
    monkeypatch.setattr(pod_module, "LATE_READ_WITHIN", 30)  # past CI's stalls
    yield shown
    if shown.held is not None:
        shown.held.set()  # no test leaves a read waiting


@pytest.mark.parametrize(
    "operation",
    [
        pytest.param(lambda p: p.exec(["true"], None, None, {}, None, None), id="exec"),
        pytest.param(
            lambda p: p.write_file(b"x", pathlib.Path("/tmp/x")), id="write_file"
        ),
        pytest.param(
            lambda p: p.read_file(pathlib.Path("/x"), io.BytesIO()), id="read_file"
        ),
    ],
)
async def test_a_restart_found_in_raise_mode_fails_operations_over_execd(
    tls_daemon: TlsDaemon,
    cluster: Cluster,
    operation: collections.abc.Callable[
        [pod_module.Pod], collections.abc.Awaitable[object]
    ],
) -> None:
    """Regression: a cached connection kept serving a restarted container's sample."""
    starts = 0
    found = asyncio.Event()

    async def exits_once_found(
        r: asyncio.StreamReader, w: asyncio.StreamWriter
    ) -> None:
        nonlocal starts
        while True:
            kind, call_id, _ = await read_frame(r)
            if kind == execd.START:
                starts += 1
                await found.wait()
                # Exit 1: exec() returns it, a file operation raises.
                w.write(frame(execd.EXIT, call_id, b'{"code": 1}'))

    pod = pod_module.Pod("p", "ns", None, "default", "u", 0, "raise")
    pod._execd = await tls_daemon(exits_once_found)
    running = asyncio.ensure_future(operation(pod))
    await until(lambda: starts == 1)
    cluster.restarts = 1
    with pytest.raises(error.ContainerRestartedError):
        await pod.check_for_pod_restart()
    found.set()

    with pytest.raises(error.ContainerRestartedError):  # found while it ran
        await running
    others_ran: list[bool] = []
    asyncio.get_running_loop().call_soon(others_ran.append, True)
    with pytest.raises(error.ContainerRestartedError):  # found before it ran
        await operation(pod)
    assert (starts, others_ran) == (1, [True])


async def test_a_restart_found_in_raise_mode_ends_streams_over_execd(
    tls_daemon: TlsDaemon, cluster: Cluster
) -> None:
    """Regression: a restarted container's stream stayed open, and another opened."""
    starts = 0
    found = asyncio.Event()

    async def writes_once_found(
        r: asyncio.StreamReader, w: asyncio.StreamWriter
    ) -> None:
        nonlocal starts
        while True:
            kind, call_id, _ = await read_frame(r)
            if kind == execd.START:
                starts += 1
                await found.wait()
                w.write(frame(execd.STDOUT, call_id, b"late"))

    pod = pod_module.Pod("p", "ns", None, "default", "u", 0, "raise")
    pod._execd = await tls_daemon(writes_once_found)
    stream = await pod.exec_stdio(["cat"], None)
    waiting = asyncio.ensure_future(stream.receive())
    await until(lambda: starts == 1)
    cluster.restarts = 1
    with pytest.raises(error.ContainerRestartedError):
        await pod.check_for_pod_restart()

    with pytest.raises(anyio.BrokenResourceError):
        await stream.send(b"x")
    with pytest.raises(anyio.BrokenResourceError):  # it waited: the send ended it
        await asyncio.wait_for(waiting, 30)
    found.set()
    with pytest.raises(anyio.BrokenResourceError):  # not the restarted container's
        await stream.receive()
    others_ran: list[bool] = []
    asyncio.get_running_loop().call_soon(others_ran.append, True)
    with pytest.raises(error.ContainerRestartedError):
        await pod.exec_stdio(["cat"], None)
    assert (starts, others_ran) == (1, [True])
    await stream.aclose()


async def test_output_the_caller_has_not_taken_stays_bounded(
    daemons: Daemons,
) -> None:
    flooded = asyncio.Event()

    async def flood(r: asyncio.StreamReader, w: asyncio.StreamWriter) -> None:
        _, call_id, _ = await read_frame(r)  # START
        chunk = frame(execd.STDOUT, call_id, b"x" * execd.CHUNK)
        try:
            # A peer that ignores acks, unlike execd, which stops at its window.
            for _ in range(execd.HOLD // execd.CHUNK + 16):
                w.write(chunk)
                await w.drain()
        except ConnectionError:
            pass
        flooded.set()

    await daemons.serve(flood)
    stream = await daemons.client().open_stream(["cat"], None)
    await asyncio.wait_for(flooded.wait(), 30)
    await until(lambda: stream._link.closed)

    assert held(stream) <= 4 << 20  # twice a stream's 1 MiB window and a frame
    assert stream._link.closed


async def test_exits_and_errors_the_caller_has_not_taken_stay_bounded(
    daemons: Daemons,
) -> None:
    """Regression: a stand-in queued 16 MiB of them on one call, past its hold."""

    async def floods(r: asyncio.StreamReader, w: asyncio.StreamWriter) -> None:
        _, call_id, _ = await read_frame(r)  # START
        for _ in range(64):
            w.write(frame(execd.ERROR, call_id, b"e" * execd.MAX_CONTROL))
        await r.read()

    await daemons.serve(floods)
    stream = await daemons.client().open_stream(["cat"], None)

    await until(lambda: stream._link.closed)
    assert held(stream) <= 16 << 10
    await stream.aclose()


async def test_a_stream_acks_only_what_its_reader_takes(daemons: Daemons) -> None:
    acks = 0
    start: dict[str, object] = {}

    marked = asyncio.Event()

    async def counts_acks(r: asyncio.StreamReader, w: asyncio.StreamWriter) -> None:
        nonlocal acks
        _, call_id, payload = await read_frame(r)  # START
        start.update(json.loads(payload))
        piece = frame(execd.STDOUT, call_id, b"x" * (64 << 10))
        w.write(piece * (execd.STREAM_WINDOW // (64 << 10)))  # then execd waits
        while True:
            kind, _, payload = await read_frame(r)
            acks += kind == execd.ACK
            if kind == execd.STDIN and payload == b"marker":
                marked.set()

    await daemons.serve(counts_acks)
    stream = await daemons.client().open_stream(["cat"], None)
    await until(lambda: held(stream) == execd.STREAM_WINDOW)
    await stream.send(b"marker")  # behind any ack sent on arrival
    await asyncio.wait_for(marked.wait(), 30)
    assert acks == 0
    got = 0
    while got < execd.STREAM_WINDOW:
        got += len(await stream.receive())

    await until(lambda: acks > 0)
    assert start["stream"]  # so execd ends it with its connection


async def test_a_stream_lets_a_cancellation_land_and_others_run(
    daemons: Daemons,
) -> None:
    """Regression: with output held, receive() gave way to nothing; send() wrote."""
    stdin = bytearray()

    async def writes(r: asyncio.StreamReader, w: asyncio.StreamWriter) -> None:
        while True:
            kind, call_id, payload = await read_frame(r)
            if kind == execd.START:
                w.write(frame(execd.STDOUT, call_id, b"ABC"))
            elif kind == execd.STDIN:
                stdin.extend(payload)

    await daemons.serve(writes)
    stream = await daemons.client().open_stream(["cat"], None)
    assert await stream.receive(1) == b"A"  # the rest is held
    others_ran: list[bool] = []
    asyncio.get_running_loop().call_soon(others_ran.append, True)

    assert (await stream.receive(1), others_ran) == (b"B", [True])
    got = None
    with anyio.CancelScope() as scope:
        scope.cancel()
        got = await stream.receive(1)
    with anyio.CancelScope() as scope:
        scope.cancel()
        await stream.send(b"x")
    await stream.send(b"y")

    await until(lambda: bool(stdin))
    assert (got, bytes(stdin)) == (None, b"y")
    await stream.aclose()


async def test_send_waiting_for_room_fails_when_the_connection_closes(
    daemons: Daemons,
) -> None:
    async def never_acks_stdin(
        r: asyncio.StreamReader, w: asyncio.StreamWriter
    ) -> None:
        await read_frame(r)  # START
        received = 0
        while received < execd.STDIN_WINDOW:
            received += len((await read_frame(r))[2])
        w.close()

    await daemons.serve(never_acks_stdin)
    stream = await daemons.client().open_stream(["cat"], None)

    with pytest.raises(anyio.BrokenResourceError):
        await asyncio.wait_for(stream.send(b"x" * (2 * execd.STDIN_WINDOW)), 30)


async def test_command_is_not_run_again_once_its_daemon_is_gone(
    daemons: Daemons,
) -> None:
    starts = []
    first: asyncio.Server

    async def dies_after_start(
        r: asyncio.StreamReader, w: asyncio.StreamWriter
    ) -> None:
        starts.append(await read_frame(r))
        first.close()  # the daemon is gone: its port refuses connections
        w.close()

    async def new_daemon(r: asyncio.StreamReader, w: asyncio.StreamWriter) -> None:
        while True:
            kind, call_id, payload = await read_frame(r)
            if kind == execd.START:
                starts.append((kind, call_id, payload))
            elif kind == execd.RESUME:
                w.write(frame(execd.ERROR, call_id, b"unknown call"))

    first = await daemons.serve(dies_after_start)
    await daemons.serve(new_daemon)

    with pytest.raises(error.ExecdResultUnknownError):
        await daemons.client().exec(["touch", "/once"], None, None, {}, None, 30)
    assert len(starts) == 1


async def test_stdin_in_flight_stays_within_the_window(
    tls_daemon: TlsDaemon,
) -> None:
    most_in_flight = received = 0

    async def acks_at_each_ping(
        r: asyncio.StreamReader, w: asyncio.StreamWriter
    ) -> None:
        nonlocal most_in_flight, received
        _, call_id, _ = await read_frame(r)  # START
        written = 0
        while True:
            kind, _, payload = await read_frame(r)
            if kind == execd.STDIN and payload:
                received += len(payload)
                continue
            # A ping, or stdin's end: all the client sent before it is in.
            most_in_flight = max(most_in_flight, received - written)
            written = received
            if kind == execd.STDIN:
                w.write(frame(execd.EXIT, call_id, b'{"code": 0}'))
                await r.read()  # open till the client is done: Python 3.13 closes TLS
                return
            put = json.dumps({"stdin": written}).encode()
            w.write(frame(execd.STDIN_ACK, call_id, put))

    client = await tls_daemon(acks_at_each_ping)
    stdin = b"x" * (3 * execd.STDIN_WINDOW)

    call = asyncio.ensure_future(client.exec(["cat"], stdin, None, {}, None, None))
    for windows in (1, 2):
        await until(lambda: received >= windows * execd.STDIN_WINDOW)
        assert client._link is not None
        await client._link.send(execd.PING, 0)  # behind the stdin sent so far
    result = await asyncio.wait_for(call, 30)

    assert result.returncode == 0
    assert most_in_flight <= execd.STDIN_WINDOW


async def test_connection_lost_after_start_is_not_retryable(
    daemons: Daemons, monkeypatch: pytest.MonkeyPatch
) -> None:
    async def unreachable(replace: bool) -> execd.Daemon:
        raise ConnectionError("no route to the pod")

    async def dies_after_start(
        r: asyncio.StreamReader, w: asyncio.StreamWriter
    ) -> None:
        await read_frame(r)  # START
        sandbox._start = unreachable  # and no new daemon can be reached
        server.close()
        w.close()

    server = await daemons.serve(dies_after_start)
    sandbox = daemons.client()
    monkeypatch.setattr(execd, "RECONNECT_FOR", 0.5)

    # A ConnectionError would be retried, running the command again.
    with pytest.raises(error.ExecdResultUnknownError):
        call = sandbox.exec(["touch", "/once"], None, None, {}, None, None)
        await asyncio.wait_for(call, 30)  # only bounds a hang


async def test_a_command_whose_connection_closed_before_it_was_sent_is_retryable(
    daemons: Daemons,
) -> None:
    async def reads(r: asyncio.StreamReader, w: asyncio.StreamWriter) -> None:
        await r.read()

    await daemons.serve(reads)
    sandbox = daemons.client()
    link = await sandbox._get()
    async with link._wlock:  # another call's write
        call = asyncio.create_task(
            sandbox.exec(["touch", "/once"], None, None, {}, None, 30)
        )
        await until(lambda: bool(link.calls))  # it waits to send its START
        await link.close()  # the connection drops meanwhile

    # Nothing ran, and an ExecdResultUnknownError would fail the sample.
    with pytest.raises(ConnectionError):
        await call


async def test_a_command_whose_connection_closed_after_it_was_sent_is_resumed(
    daemons: Daemons,
) -> None:
    """Regression: a second drop, before the RESUME was written, lost the command."""
    starts = connections = 0

    async def drops_twice(r: asyncio.StreamReader, w: asyncio.StreamWriter) -> None:
        nonlocal starts, connections
        connections += 1
        if connections == 2:  # the reopened connection is gone before the RESUME
            w.close()
            return
        kind, call_id, _ = await read_frame(r)
        starts += kind == execd.START
        if connections == 1:  # the command may have run
            w.close()
            return
        w.write(frame(execd.RESUMED, call_id, b'{"stdin": 0, "eof": true, "put": 0}'))
        w.write(frame(execd.EXIT, call_id, b'{"code": 7}'))
        await r.read()

    # Plain: over TLS the client writes its RESUME before it sees the close.
    await daemons.serve(drops_twice)

    call = daemons.client().exec(["touch", "/once"], None, None, {}, None, None)
    result = await asyncio.wait_for(call, 30)  # only bounds a hang

    # Sent once: a ConnectionError would be retried, running the command again.
    assert (result.returncode, starts) == (7, 1)


async def test_a_command_whose_start_was_cut_off_part_way_is_resumed(
    daemons: Daemons,
) -> None:
    """Regression: a START cut as it was written failed a call execd could resume."""
    starts = connections = 0
    first: list[asyncio.StreamWriter] = []
    resumes: list[bool] = []
    released = asyncio.Event()

    async def resets_the_first(
        r: asyncio.StreamReader, w: asyncio.StreamWriter
    ) -> None:
        nonlocal starts, connections
        connections += 1
        if connections == 1:
            first.append(w)
            _, call_id, _ = await read_frame(r)  # the command that opens the connection
            w.write(frame(execd.EXIT, call_id, b'{"code": 0}'))
            kind, _, _ = await read_frame(r)
            assert kind == execd.RELEASE  # else it is the write the reset meets
            released.set()
            await r.read()
            return
        kind, call_id, _ = await read_frame(r)
        while kind in (execd.RELEASE, execd.PING):  # the first command's, again
            kind, call_id, _ = await read_frame(r)
        resumes.append(kind == execd.RESUME)
        w.write(frame(execd.ERROR, call_id, b"unknown call"))
        kind, call_id, _ = await read_frame(r)
        starts += kind == execd.START
        w.write(frame(execd.EXIT, call_id, b'{"code": 7}'))
        await r.read()

    await daemons.serve(resets_the_first)
    client = daemons.client()
    await asyncio.wait_for(client.exec(["true"], None, None, {}, None, None), 30)
    await asyncio.wait_for(released.wait(), 30)
    reset = struct.pack("ii", 1, 0)  # close with a reset, not an end of stream
    first[0].get_extra_info("socket").setsockopt(
        socket.SOL_SOCKET, socket.SO_LINGER, reset
    )
    first[0].transport.abort()
    # Closed in this turn of the loop: the client's socket has the reset, its loop not.
    await asyncio.sleep(0)

    call = client.exec(["touch", "/once"], None, None, {}, None, None)
    result = await asyncio.wait_for(call, 30)  # only bounds a hang

    # Asked for first, then sent again once: execd had never read it.
    assert (result.returncode, resumes, starts) == (7, [True], 1)


@pytest.mark.parametrize(
    "before", [False, True], ids=["as its RESUME is written", "before its RESUME"]
)
async def test_a_connection_lost_while_a_call_resumes_on_it_is_left_once(
    daemons: Daemons, monkeypatch: pytest.MonkeyPatch, before: bool
) -> None:
    """The call hears of it twice, or only from its own send: it reopens once."""
    connections: list[asyncio.StreamWriter] = []
    started, resuming = asyncio.Event(), asyncio.Event()
    opened = 0

    class SecondIsLost(Plain):
        nth = reads = 0

        async def readexactly(self, n: int) -> bytes:
            self.reads += 1
            if before and self.nth == 2 and self.reads > 2:  # right behind its OK
                raise ConnectionResetError
            return await super().readexactly(n)

        async def write(self, data: bytes) -> None:
            if not before and self.nth == 2 and data[0] == execd.RESUME:
                resuming.set()
                await until(self._writer.transport.is_closing)
            await super().write(data)

    async def connect(daemon: execd.Daemon, pace: execd.Pace) -> execd._Pipe:
        nonlocal opened
        r, w = await asyncio.open_connection("127.0.0.1", daemons.ports[daemon])
        opened += 1
        pipe = SecondIsLost(r, w)
        pipe.nth = opened
        return pipe

    async def resumes_on_the_third(
        r: asyncio.StreamReader, w: asyncio.StreamWriter
    ) -> None:
        connections.append(w)
        nth = len(connections)
        if nth == 1:
            await read_frame(r)  # START
            started.set()
        if nth < 3:  # the test drops the first two
            await r.read()
            return
        _, call_id, _ = await read_frame(r)  # RESUME
        w.write(frame(execd.EXIT, call_id, b'{"code": 7}'))
        await r.read()

    monkeypatch.setattr(execd, "_connect", connect)
    await daemons.serve(resumes_on_the_third)
    call = asyncio.ensure_future(
        daemons.client().exec(["sleep", "1"], None, None, {}, None, None)
    )
    await asyncio.wait_for(started.wait(), 30)
    connections[0].transport.abort()
    if not before:
        await asyncio.wait_for(resuming.wait(), 30)
        connections[1].transport.abort()

    result = await asyncio.wait_for(call, 30)  # only bounds a hang

    assert (result.returncode, len(connections)) == (7, 3)


async def test_a_command_cancelled_while_cut_off_is_killed_when_execd_is_back(
    daemons: Daemons,
) -> None:
    """Regression: cancelled during a reconnect, it ran on until execd abandoned it."""
    auths = 0
    answer = asyncio.Event()
    started: list[int] = []
    got: list[tuple[int, int]] = []

    async def connection(r: asyncio.StreamReader, w: asyncio.StreamWriter) -> None:
        nonlocal auths
        await read_frame(r)  # AUTH
        auths += 1
        if auths == 1:
            w.write(frame(execd.OK, 0))
            started.append((await read_frame(r))[1])  # START
            w.close()  # the connection drops under the command
            return
        await answer.wait()  # the client is still reconnecting
        w.write(frame(execd.OK, 0))
        for _ in range(2):
            kind, call_id, _ = await read_frame(r)
            got.append((kind, call_id))
        await r.read()

    server = await asyncio.start_server(connection, "127.0.0.1", 0)
    daemon = execd.Daemon("127.0.0.1", "cert", b"key")
    daemons.ports[daemon] = server.sockets[0].getsockname()[1]
    daemons.unstarted.append(daemon)
    run = daemons.client().exec(["sleep", "600"], None, None, {}, None, None)
    call = asyncio.ensure_future(run)
    await until(lambda: auths == 2)

    call.cancel()
    with pytest.raises(asyncio.CancelledError):
        await call
    answer.set()

    await until(lambda: len(got) == 2)
    assert got == [(execd.KILL, started[0]), (execd.RELEASE, started[0])]


async def test_a_calls_last_frames_are_sent_again_until_a_pong_follows_them(
    tls_daemon: TlsDaemon,
) -> None:
    """Regressions: ids forgotten once written; a finished call's RELEASE not kept."""
    got: list[list[tuple[int, int]]] = []
    starts: list[int] = []
    drop = False  # the connection, under the next command sent

    async def answers_its_third_ping_late(
        r: asyncio.StreamReader, w: asyncio.StreamWriter
    ) -> None:
        nonlocal drop
        mine: list[tuple[int, int]] = []
        got.append(mine)
        pinged = False
        while True:
            kind, call_id, _ = await read_frame(r)
            if kind == execd.START and drop:
                break
            if kind == execd.START:
                starts.append(call_id)
                if len(starts) > 1:  # the first command is left running
                    w.write(frame(execd.EXIT, call_id, b'{"code": 0}'))
            elif kind == execd.RESUME:  # its START went into the dropped connection
                w.write(frame(execd.ERROR, call_id, b"unknown call"))
            elif kind == execd.PING:
                pinged = len(got) == 3
            elif kind in (execd.KILL, execd.RELEASE):
                mine.append((kind, call_id))
                if pinged:  # only now: this RELEASE came after the PING
                    w.write(frame(execd.PONG, 0))
                    pinged = False
        drop = False
        w.close()

    async def call() -> int:
        """Run a command; its id, once the stand-in has read its RELEASE."""
        await asyncio.wait_for(client.exec(["true"], None, None, {}, None, None), 30)
        await until(lambda: (execd.RELEASE, starts[-1]) in got[-1])
        return starts[-1]

    client = await tls_daemon(answers_its_third_ping_late)
    left = asyncio.ensure_future(
        client.exec(["sleep", "600"], None, None, {}, None, None)
    )
    await until(lambda: bool(starts))
    left.cancel()
    with pytest.raises(asyncio.CancelledError):
        await asyncio.wait_for(left, 30)
    a = starts[0]
    await until(lambda: (execd.RELEASE, a) in got[0])
    drop = True
    b = await call()
    drop = True
    c = await call()  # on the third connection, whose PONG comes behind this RELEASE
    d = await call()  # its EXIT comes behind the PONG: the client has read that
    drop = True
    e = await call()

    kept = [(execd.KILL, a), (execd.RELEASE, a), (execd.RELEASE, b)]
    after = [(execd.RELEASE, c), (execd.RELEASE, d)]
    # No PONG: sent again. A PONG: only what its PING followed is not sent again.
    assert got == [kept[:2], kept, kept + after, after + [(execd.RELEASE, e)]]


@pytest.mark.skipif(
    sys.version_info >= (3, 12), reason="there a replay is written in one step"
)
async def test_a_command_sent_during_a_replay_follows_what_is_owed(
    tls_daemon: TlsDaemon,
) -> None:
    """Regression: it went out between the frames owed, as each upload would."""
    got: list[list[int]] = []  # the kinds each connection got
    drop = False  # the first connection, under the next command sent
    replaying = asyncio.Event()

    async def answers_no_ping(r: asyncio.StreamReader, w: asyncio.StreamWriter) -> None:
        mine: list[int] = []
        got.append(mine)
        while True:
            kind, call_id, _ = await read_frame(r)
            if kind == execd.START and drop and len(got) == 1:
                break
            mine.append(kind)
            if len(got) == 2:
                replaying.set()
            if kind == execd.START and len(got) == 2:
                w.write(frame(execd.EXIT, call_id, b'{"code": 0}'))
            elif kind == execd.RESUME:  # its START went into the dropped connection
                w.write(frame(execd.ERROR, call_id, b"unknown call"))
        w.close()

    def call(*argv: str) -> asyncio.Future[object]:
        run = client.exec(list(argv) or ["true"], None, None, {}, None, None)
        return asyncio.ensure_future(run)

    client = await tls_daemon(answers_no_ping)
    left = [call("sleep", "600") for _ in range(64)]
    await until(lambda: bool(got) and got[0].count(execd.START) == 64)
    for running in left:
        running.cancel()
    await until(lambda: got[0].count(execd.RELEASE) == 64)
    drop = True
    reopens = call()
    await asyncio.wait_for(replaying.wait(), 30)
    during = call()
    await asyncio.wait_for(asyncio.gather(reopens, during), 30)

    assert got[1].index(execd.PING) < got[1].index(execd.START)


async def test_calls_awaiting_a_pong_are_bounded_and_each_pong_clears_its_pings(
    tls_daemon: TlsDaemon, clock: types.SimpleNamespace
) -> None:
    """Regressions: no PONG, and every call was kept; a busy, or slow, execd refused."""
    connections: list[asyncio.StreamWriter] = []
    starts: list[int] = []
    killed: list[int] = []
    released: list[int] = []
    drop = False  # the connection, under the next command sent
    half = execd.MAX_OWED // 2

    async def answers_no_ping(r: asyncio.StreamReader, w: asyncio.StreamWriter) -> None:
        nonlocal drop
        connections.append(w)
        second = len(connections) == 2
        while True:
            kind, call_id, _ = await read_frame(r)
            if kind == execd.START and drop:
                break
            if kind == execd.START:
                starts.append(call_id)
                if len(starts) > 1 + half:  # the first, and half the bound more, run on
                    w.write(frame(execd.EXIT, call_id, b'{"code": 0}'))
            elif kind == execd.RESUME:  # its START went into the dropped connection
                w.write(frame(execd.ERROR, call_id, b"unknown call"))
            elif kind == execd.KILL:
                killed.append(call_id)
            elif kind == execd.RELEASE and second:
                released.append(call_id)
        drop = False
        w.close()

    def call(*argv: str) -> asyncio.Future[object]:
        run = client.exec(list(argv) or ["true"], None, None, {}, None, None)
        return asyncio.ensure_future(run)

    client = await tls_daemon(answers_no_ping)
    held = call("sleep", "600")
    await until(lambda: len(starts) == 1)
    left = [call("sleep", "600") for _ in range(half)]
    await until(lambda: len(starts) == 1 + half)
    for _ in range(2):  # each half is asked about with a PING
        await asyncio.wait_for(asyncio.gather(*(call() for _ in range(half))), 30)
    commands: list[asyncio.Future[object]] = []
    for some in left[: half // 2], left[half // 2 :]:
        clock.now += execd.PING_EVERY  # the second begins to wait that much later
        commands.append(call())
        for running in some:  # a KILL is written behind a START that did not wait
            running.cancel()
        await asyncio.wait(some, timeout=30)
        await until(lambda: len(killed) == len(commands) * half // 2)
    early, late = commands
    waited = len(starts) == 1 + 3 * half
    # The second has now waited 56 s; the first, 71.
    clock.now += execd.DEAD_AFTER + execd.CONNECT_TIMEOUT + 1
    # One PONG; then the first command's exit, behind which the client has read it.
    exit_ = frame(execd.EXIT, starts[0], b'{"code": 0}')
    connections[0].write(frame(execd.PONG, 0) + exit_)
    await asyncio.wait_for(held, 30)  # as many calls as the bound still await a PONG
    connections[0].write(frame(execd.PONG, 0))
    with pytest.raises(ConnectionError, match="not confirmed"):  # its time was up
        await asyncio.wait_for(early, 30)
    await asyncio.wait_for(late, 30)
    drop = True
    await asyncio.wait_for(call(), 30)
    await until(lambda: starts[-1] in released)

    # The PONGs answered the first two PINGs: neither half is sent again.
    assert waited
    assert set(released) == {*starts[: 1 + half], starts[-2], starts[-1]}


async def test_a_command_handed_a_closed_connection_gets_its_pong_on_the_next(
    tls_daemon: TlsDaemon,
) -> None:
    """Regression: handed a connection just closed, it waited for a PONG on that one."""
    connections: list[asyncio.StreamWriter] = []

    async def closes_its_second(
        r: asyncio.StreamReader, w: asyncio.StreamWriter
    ) -> None:
        connections.append(w)
        nth = len(connections)
        if nth == 2:  # with its OK, a frame too large: the client closes it as it opens
            w.write(execd.HEADER.pack(execd.STDOUT, 1, execd.MAX_FRAME + 1))
        with contextlib.suppress(asyncio.IncompleteReadError):  # the client has gone
            while True:
                kind, call_id, _ = await read_frame(r)
                if kind == execd.START:
                    w.write(frame(execd.EXIT, call_id, b'{"code": 0}'))
                elif kind == execd.PING and nth > 1:  # the first answers no PING
                    w.write(frame(execd.PONG, 0))

    def call() -> collections.abc.Coroutine[object, object, object]:
        return client.exec(["true"], None, None, {}, None, None)

    client = await tls_daemon(closes_its_second)
    calls = (call() for _ in range(execd.MAX_OWED))
    await asyncio.wait_for(asyncio.gather(*calls), 30)
    connections[0].close()

    await asyncio.wait_for(call(), 30)

    assert len(connections) == 3


@pytest.mark.parametrize(
    ("waits", "opened"),
    [
        pytest.param([3600], 1, id="on the connection it began on"),
        pytest.param(
            [execd.DEAD_AFTER + execd.PING_EVERY + 1, execd.CONNECT_TIMEOUT],
            2,
            id="on the next: its time is one",
        ),
    ],
)
async def test_a_command_out_of_time_for_its_pong_is_refused_with_no_other_connection(
    tls_daemon: TlsDaemon,
    clock: types.SimpleNamespace,
    waits: list[float],
    opened: int,
) -> None:
    """Regression: its time up, another connection was opened before it was refused."""
    connections: list[asyncio.StreamWriter] = []
    asked: list[int] = []  # the connection each PING came on
    starts = 0
    killed = False

    async def answers_no_ping(r: asyncio.StreamReader, w: asyncio.StreamWriter) -> None:
        nonlocal starts, killed
        connections.append(w)
        nth = len(connections)
        with contextlib.suppress(asyncio.IncompleteReadError):  # the client has gone
            while True:
                kind, call_id, _ = await read_frame(r)
                if kind == execd.START:
                    starts += 1
                    if starts > 1:  # the first command runs on
                        w.write(frame(execd.EXIT, call_id, b'{"code": 0}'))
                elif kind == execd.KILL:
                    killed = True
                elif kind == execd.PING:
                    asked.append(nth)

    def call(*argv: str) -> asyncio.Future[object]:
        run = client.exec(list(argv) or ["true"], None, None, {}, None, None)
        return asyncio.ensure_future(run)

    client = await tls_daemon(answers_no_ping)
    running = call("sleep", "600")
    await until(lambda: starts == 1)
    calls = (call() for _ in range(execd.MAX_OWED))
    await asyncio.wait_for(asyncio.gather(*calls), 30)
    command = call()
    running.cancel()  # its KILL is written behind a START that did not wait
    await until(lambda: killed)
    for nth, seconds in enumerate(waits, 1):  # the last uses up the command's time
        await until(lambda: nth in asked)  # sent what is owed, and a PING
        clock.now += seconds
        connections[nth - 1].close()

    with pytest.raises(ConnectionError, match="not confirmed"):
        await asyncio.wait_for(command, 30)
    assert len(connections) == opened


async def test_a_call_left_once_its_connection_is_replaced_is_killed_on_the_new_one(
    tls_daemon: TlsDaemon,
) -> None:
    """Regression: it ran on until the next reconnect, or until execd let it go."""
    got: list[tuple[int, int, int]] = []
    connections = 0

    async def prints_then_drops(
        r: asyncio.StreamReader, w: asyncio.StreamWriter
    ) -> None:
        nonlocal connections
        connections += 1
        nth = connections
        while True:
            kind, call_id, _ = await read_frame(r)
            if kind == execd.START and nth == 1 and got:  # under the second command
                break
            got.append((nth, kind, call_id))
            if kind == execd.START and nth == 1:  # the command to be left
                w.write(frame(execd.STDOUT, call_id, b"x"))
            elif kind == execd.START:
                w.write(frame(execd.EXIT, call_id, b'{"code": 0}'))
            elif kind == execd.RESUME:  # its START went into the dropped connection
                w.write(frame(execd.ERROR, call_id, b"unknown call"))
        w.close()

    client = await tls_daemon(prints_then_drops)
    left = client.run(["cat"], env={}, cwd=None, user=None, stdin=None, timeout=None)
    await asyncio.wait_for(anext(left), 30)
    await asyncio.wait_for(client.exec(["true"], None, None, {}, None, None), 30)

    await asyncio.wait_for(left.aclose(), 30)

    call_id = got[0][2]
    await until(lambda: (2, execd.RELEASE, call_id) in got)
    assert (2, execd.KILL, call_id) in got


@pytest.mark.parametrize(
    ("verdict", "taken"),
    [
        # execd killed it at its timeout: the exit it marked, a timeout to exec()
        (
            b'{"code": 137, "timeout": true}',
            [(execd.PING, None), (execd.EXIT, {"code": 137, "timeout": True})],
        ),
        # it had ended by itself: its result, though our timer had passed
        (
            b'{"code": 0}',
            [(execd.PING, None), (execd.STDOUT, b"done\n"), (execd.EXIT, {"code": 0})],
        ),
    ],
    ids=["killed", "ended"],
)
async def test_a_call_timed_out_as_its_connection_drops_asks_execd_on_the_next(
    tls_daemon: TlsDaemon,
    clock: types.SimpleNamespace,
    timers: None,
    verdict: bytes,
    taken: list[tuple[int, object]],
) -> None:
    """Regression: it took its own timer's word; and once, never sent its RELEASE."""
    got: list[tuple[int, int]] = []
    starts: list[int] = []

    async def drops_the_first_at_our_timer(
        r: asyncio.StreamReader, w: asyncio.StreamWriter
    ) -> None:
        first = not starts
        while True:
            kind, call_id, _ = await read_frame(r)
            if first and kind == execd.START:
                starts.append(call_id)
            elif first and kind == execd.PING:  # our timer's
                w.transport.abort()
                return
            elif kind == execd.START:
                w.write(frame(execd.EXIT, call_id, b'{"code": 0}'))
            elif not first:
                got.append((kind, call_id))
                if kind == execd.RESUME:  # what execd holds of a call that has ended
                    w.write(
                        frame(
                            execd.RESUMED,
                            call_id,
                            b'{"stdin": 0, "eof": false, "put": 0}',
                        )
                    )
                    if b"timeout" not in verdict:
                        w.write(frame(execd.STDOUT, call_id, b"done\n"))
                    w.write(frame(execd.EXIT, call_id, verdict))

    client = await tls_daemon(drops_the_first_at_our_timer)
    argv = ["sleep", "9"] if b"timeout" in verdict else ["echo", "done"]
    run = client.run(argv, env={}, cwd=None, user=None, stdin=None, timeout=9)

    async def items() -> list[tuple[int, object]]:
        return [item async for item in run]

    taking = asyncio.ensure_future(items())
    await until(lambda: bool(starts))  # its START is written: its time runs from there
    clock.now += 2000  # past our timer
    assert await asyncio.wait_for(taking, 30) == taken
    await asyncio.wait_for(client.exec(["true"], None, None, {}, None, None), 30)

    # No KILL: either way execd has said that it ended.
    assert [k for k, i in got if i == starts[0]] == [execd.RESUME, execd.RELEASE]
    assert client._link is not None and not client._link.calls


async def test_a_kill_sent_into_a_dead_connection_is_sent_again_on_each_new_one(
    daemons: Daemons,
) -> None:
    """Regression: cancelled over a connection dead unnoticed, the command ran on."""
    left: list[int] = []
    dead: list[asyncio.StreamWriter] = []
    got: list[tuple[int, int]] = []

    async def swallows_the_first_two(
        r: asyncio.StreamReader, w: asyncio.StreamWriter
    ) -> None:
        if len(dead) < 2:  # as a network that drops everything: nothing sent arrives
            dead.append(w)
            if not left:
                left.append((await read_frame(r))[1])  # START
            await r.read()
            return
        while True:
            kind, call_id, _ = await read_frame(r)
            got.append((kind, call_id))
            if kind == execd.RESUME:  # of the next command, if it left on the first
                w.write(frame(execd.ERROR, call_id, b"unknown call"))
            elif kind == execd.START:
                w.write(frame(execd.EXIT, call_id, b'{"code": 0}'))

    await daemons.serve(swallows_the_first_two)
    client = daemons.client()
    run = client.exec(["sleep", "600"], None, None, {}, None, None)
    call = asyncio.ensure_future(run)
    await until(lambda: bool(left))
    call.cancel()
    with pytest.raises(asyncio.CancelledError):
        await call
    # The next connection takes the KILL, and is dead too.
    await asyncio.wait_for(client._get(stale=client._link), 30)
    dead[1].close()  # only now does the client learn that one is gone

    await asyncio.wait_for(client.exec(["true"], None, None, {}, None, None), 30)

    assert got[:2] == [(execd.KILL, left[0]), (execd.RELEASE, left[0])]


@pytest.mark.parametrize("stream", [False, True], ids=["exec", "exec_stdio"])
async def test_a_stdin_ack_read_before_its_send_returns_is_counted(
    daemons: Daemons, monkeypatch: pytest.MonkeyPatch, stream: bool
) -> None:
    """Regression: such an ack was dropped, and an upload past 8 MiB never finished."""
    got = 0

    class AckedFirst(Plain):  # a send returns once the client has handled its ack
        reads = sent = 0

        async def readexactly(self, n: int) -> bytes:
            self.reads += 1
            return await super().readexactly(n)

        async def write(self, data: bytes) -> None:
            await super().write(data)
            if data[0] == execd.STDIN and len(data) > execd.HEADER.size:
                self.sent += 1
                # OK and each ack take two reads: the next begins when it is handled.
                await until(lambda: self.reads > 2 * (self.sent + 1))

    async def connect(daemon: execd.Daemon, pace: execd.Pace) -> execd._Pipe:
        r, w = await asyncio.open_connection("127.0.0.1", daemons.ports[daemon])
        return AckedFirst(r, w)

    async def acks_at_once(r: asyncio.StreamReader, w: asyncio.StreamWriter) -> None:
        nonlocal got
        _, call_id, _ = await read_frame(r)  # START
        while True:
            kind, _, payload = await read_frame(r)
            if kind == execd.STDIN and payload:
                got += len(payload)
                ack = json.dumps({"stdin": got}).encode()
                w.write(frame(execd.STDIN_ACK, call_id, ack))
            elif kind == execd.STDIN:  # stdin's end
                w.write(frame(execd.EXIT, call_id, b'{"code": 0}'))

    monkeypatch.setattr(execd, "_connect", connect)
    await daemons.serve(acks_at_once)
    stdin = b"x" * (execd.STDIN_WINDOW + 2 * execd.CHUNK)
    client = daemons.client()

    if stream:
        opened = await client.open_stream(["cat"], None)
        await asyncio.wait_for(opened.send(stdin), 30)  # only bounds a hang
    else:
        call = client.exec(["cat"], stdin, None, {}, None, None)
        await asyncio.wait_for(call, 30)  # only bounds a hang

    await until(lambda: got == len(stdin))


async def test_a_peer_that_stops_reading_cannot_hang_a_timed_out_command(
    daemons: Daemons, monkeypatch: pytest.MonkeyPatch
) -> None:
    peers: list[asyncio.StreamWriter] = []

    async def stops_reading(r: asyncio.StreamReader, w: asyncio.StreamWriter) -> None:
        peers.append(w)
        await read_frame(r)  # START
        while True:  # alive, but never reads again: its receive window fills
            w.write(frame(execd.PONG, 0))
            await asyncio.sleep(0.05)

    await daemons.serve(stops_reading)
    monkeypatch.setattr(execd, "KILL_WAIT", 0.5)
    sandbox = daemons.client()

    async def times_out() -> None:
        with pytest.raises((TimeoutError, error.ExecdResultUnknownError)):
            await sandbox.exec(["cat"], b"x" * (64 << 20), None, {}, None, 1)

    task = asyncio.ensure_future(times_out())
    done, _ = await asyncio.wait({task}, timeout=30)
    for peer in peers:  # frees a hung client, so a failure ends here
        peer.transport.abort()
    assert done, "the blocked write held up the timeout"
    await task


async def test_a_commands_timeout_bounds_its_start_behind_a_blocked_write(
    daemons: Daemons, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Regression: another call's write to a peer that stopped reading held it 43 s."""
    blocked = asyncio.Event()

    class Stuck(Plain):
        async def write(self, data: bytes) -> None:
            if len(data) > execd.CHUNK:  # the upload's stdin: its peer won't read it
                blocked.set()
                await asyncio.Event().wait()
            await super().write(data)

    async def connect(daemon: execd.Daemon, pace: execd.Pace) -> execd._Pipe:
        r, w = await asyncio.open_connection("127.0.0.1", daemons.ports[daemon])
        return Stuck(r, w)

    async def answers_nothing(r: asyncio.StreamReader, w: asyncio.StreamWriter) -> None:
        await r.read()

    monkeypatch.setattr(execd, "_connect", connect)
    await daemons.serve(answers_nothing)
    sandbox = daemons.client()
    stdin = b"x" * execd.CHUNK
    upload = asyncio.ensure_future(sandbox.exec(["cat"], stdin, None, {}, None, None))
    await asyncio.wait_for(blocked.wait(), 30)

    async def times_out() -> None:
        with pytest.raises(TimeoutError):
            await sandbox.exec(["true"], None, None, {}, None, 1)

    task = asyncio.ensure_future(times_out())
    done, _ = await asyncio.wait({task}, timeout=30)
    link = sandbox._link
    upload.cancel()
    assert done, "the blocked write held up another command's START past its timeout"
    await task
    # Still open: closing it would send the pod's other calls to reconnect.
    assert link is not None and not link.closed


@pytest.mark.parametrize("exits", [True, False], ids=["exit", "output and no exit"])
async def test_a_call_ends_in_time_though_its_own_upload_is_stuck(
    daemons: Daemons,
    clock: types.SimpleNamespace,
    timers: None,
    monkeypatch: pytest.MonkeyPatch,
    exits: bool,
) -> None:
    """Regression: its RELEASE or its ack waited 45 s behind its stdin's write."""
    got: list[int] = []
    stuck = asyncio.Event()

    class Stuck(Plain):
        async def write(self, data: bytes) -> None:
            if data[0] == execd.STDIN:  # the pod stopped reading: the upload waits
                stuck.set()
                await asyncio.Event().wait()
            await super().write(data)

    async def connect(daemon: execd.Daemon, pace: execd.Pace) -> execd._Pipe:
        r, w = await asyncio.open_connection("127.0.0.1", daemons.ports[daemon])
        return Stuck(r, w)

    async def answers(r: asyncio.StreamReader, w: asyncio.StreamWriter) -> None:
        _, call_id, _ = await read_frame(r)  # START
        await stuck.wait()
        if exits:
            w.write(frame(execd.EXIT, call_id, b'{"code": 7}'))
        else:  # output enough to be acked
            w.write(frame(execd.STDOUT, call_id, b"x" * execd.ACK_EVERY))
        while True:
            got.append((await read_frame(r))[0])

    monkeypatch.setattr(execd, "_connect", connect)
    monkeypatch.setattr(execd, "KILL_WAIT", 0.0)  # nor a wait for execd's word
    await daemons.serve(answers)
    client = daemons.client()
    run = client.exec(["cat"], b"x", None, {}, None, None if exits else 9)
    call = asyncio.ensure_future(run)

    if exits:
        result = await asyncio.wait_for(call, 30)  # only bounds a hang
        assert result.returncode == 7
    else:
        await until(lambda: client._link is not None and bool(client._link._last))
        clock.now += 10  # past our timer; a stuck write is given up after 45 s
        with pytest.raises(TimeoutError, match="Command timed out"):
            await asyncio.wait_for(call, 30)  # only bounds a hang
    # Its last frames still go out, once its upload has let go of the connection.
    await until(lambda: got[-1:] == [execd.RELEASE])
    assert (execd.KILL in got) is not exits


async def test_a_calls_last_frames_wait_behind_one_start_or_upload_at_most(
    tls_daemon: TlsDaemon,
) -> None:
    """Regression: a call's KILL and RELEASE waited behind every START and upload."""
    got: list[int] = []
    reads = asyncio.Event()

    async def records(r: asyncio.StreamReader, w: asyncio.StreamWriter) -> None:
        while True:
            if got.count(execd.START) == 9:  # unread, the tenth's write waits
                await reads.wait()
            got.append((await read_frame(r))[0])

    def call(*argv: str, stdin: bytes | None = None) -> asyncio.Future[object]:
        run = client.exec(list(argv), stdin, None, {}, None, None)
        return asyncio.ensure_future(run)

    client = await tls_daemon(records)
    left = call("sleep", "600")
    uploads = [call("cat", stdin=b"x") for _ in range(8)]
    # More than the socket buffers hold: the uploads' stdin waits behind this START.
    uploads.append(call("echo", "x" * (16 << 20)))
    await until(lambda: got.count(execd.START) == 9)
    left.cancel()
    await asyncio.wait({left}, timeout=30)
    reads.set()
    await until(lambda: execd.RELEASE in got)

    # The KILL follows the START being written; its RELEASE, one frame more at most.
    assert (got.index(execd.KILL), got.index(execd.RELEASE)) in [(10, 11), (10, 12)]
    for running in uploads:
        running.cancel()


async def test_an_empty_user_is_refused_not_run_as_the_containers(
    daemons: Daemons,
) -> None:
    client = daemons.client()  # it serves nothing: a refusal needs no connection

    with pytest.raises(RuntimeError, match="empty user"):
        await client.exec(["id"], None, None, {}, "", None)
    with pytest.raises(RuntimeError, match="empty user"):
        await client.open_stream(["id"], "")


async def test_a_timeout_of_zero_is_no_timeout(daemons: Daemons) -> None:
    async def exits(r: asyncio.StreamReader, w: asyncio.StreamWriter) -> None:
        _, call_id, _ = await read_frame(r)  # START
        w.write(frame(execd.EXIT, call_id, b'{"code": 0}'))
        await r.read()

    await daemons.serve(exits)

    call = daemons.client().exec(["true"], None, None, {}, None, 0)
    result = await asyncio.wait_for(call, 30)  # only bounds a hang

    assert result.returncode == 0


@pytest.mark.parametrize("again", [False, True], ids=["its first", "sent again"])
async def test_a_start_whose_turn_comes_once_its_calls_time_is_up_is_not_written(
    daemons: Daemons,
    clock: types.SimpleNamespace,
    monkeypatch: pytest.MonkeyPatch,
    no_timer_lag: float,
    again: bool,
) -> None:
    """Regression: a START that had waited its turn went out after our timer."""
    monkeypatch.setattr(execd, "TIMER_LAG", no_timer_lag)  # as shipped: no START has it
    connections = [0]
    got: list[int] = []
    asked, answer = asyncio.Event(), asyncio.Event()

    async def starts(r: asyncio.StreamReader, w: asyncio.StreamWriter) -> None:
        connections[0] += 1
        if again and connections[0] == 1:
            await r.readexactly(execd.HEADER.size)  # of its START: no call yet
            w.close()
            return
        while True:
            kind, call_id, _ = await read_frame(r)
            got.append(kind)
            if kind == execd.RESUME:
                asked.set()
                await answer.wait()
                w.write(frame(execd.ERROR, call_id, b"unknown call"))
            if kind == execd.START:  # it runs, and ends
                w.write(frame(execd.EXIT, call_id, b'{"code": 0}'))

    await daemons.serve(starts)
    client = daemons.client()
    if not again:
        await client._get()
    call = asyncio.ensure_future(client.exec(["true"], None, None, {}, None, 9))
    if again:
        await asyncio.wait_for(asked.wait(), 30)  # only bounds a hang
    link = client._link
    assert link is not None
    await link._wlock.acquire()  # as another call's write has the turn
    answer.set()
    await until(lambda: link.bulk.locked())  # its START waits
    clock.now += 9.5  # past its timeout, in the second our timer follows execd's by
    link._wlock.release()

    with pytest.raises(TimeoutError, match="Command timed out"):
        await asyncio.wait_for(call, 30)  # only bounds a hang
    await until(lambda: execd.RELEASE in got)  # the call's last frame
    assert (execd.START in got, connections[0]) == (False, 1 + again)


@pytest.mark.parametrize(
    ("again", "held"),
    [(False, False), (True, False), (False, True)],
    ids=["its first", "sent again", "our loop held as its turn comes"],
)
async def test_a_command_has_its_whole_timeout_from_when_its_start_is_written(
    daemons: Daemons,
    clock: types.SimpleNamespace,
    timers: None,
    again: bool,
    held: bool,
) -> None:
    """Regression: our timer ran from the call, and passed with execd's own not up."""
    connections = [0]
    got: list[int] = []
    asked, answer, ends = asyncio.Event(), asyncio.Event(), asyncio.Event()

    async def runs(r: asyncio.StreamReader, w: asyncio.StreamWriter) -> None:
        connections[0] += 1
        if again and connections[0] == 1:
            await r.readexactly(execd.HEADER.size)  # of its START: no call yet
            w.close()
            return
        while True:
            kind, call_id, _ = await read_frame(r)
            got.append(kind)
            if kind == execd.RESUME:
                asked.set()
                await answer.wait()
                w.write(frame(execd.ERROR, call_id, b"unknown call"))
            if kind == execd.START:
                await ends.wait()
                w.write(frame(execd.STDOUT, call_id, b"done\n"))
                w.write(frame(execd.EXIT, call_id, b'{"code": 0}'))

    await daemons.serve(runs)
    client = daemons.client()
    link = await client._get()
    if not again:
        await link._wlock.acquire()  # as another call's write has the turn
    argv = ["echo", "done"]
    call = asyncio.ensure_future(client.exec(argv, None, None, {}, None, 9))
    waits = asked.wait() if again else until(lambda: link.bulk.locked())
    await asyncio.wait_for(waits, 30)  # only bounds a hang
    if held:  # the time passes after its turn has come, before its write's own step
        link._wlock.release()
        asyncio.get_running_loop().call_soon(setattr, clock, "now", clock.now + 8)
    else:
        clock.now += 8  # in the call's time still
        answer.set() if again else link._wlock.release()
    await until(lambda: execd.START in got)
    clock.now += 8  # past the call's own nine seconds, within the command's
    ends.set()

    result = await asyncio.wait_for(call, 30)  # only bounds a hang
    await until(lambda: execd.RELEASE in got)  # the call's last frame
    # No PING: our timer had not passed.
    assert (result.stdout, execd.PING in got) == ("done\n", False)


@pytest.mark.parametrize("again", [False, True], ids=["its first", "sent again"])
async def test_a_start_out_of_time_in_its_write_is_with_execd(
    daemons: Daemons,
    clock: types.SimpleNamespace,
    timers: None,
    monkeypatch: pytest.MonkeyPatch,
    again: bool,
) -> None:
    """Regression: cut off in its write, a START was taken for unsent, and killed."""
    connections = [0]
    got: list[int] = []

    class SlowToTake(Plain):
        async def write(self, data: bytes) -> None:
            await super().write(data)
            if data[0] == execd.START and connections[0] == 1 + again:
                await asyncio.Event().wait()  # handed over, and slow to go: no return

    async def connect(daemon: execd.Daemon, pace: execd.Pace) -> execd._Pipe:
        r, w = await asyncio.open_connection("127.0.0.1", daemons.ports[daemon])
        return SlowToTake(r, w)

    async def runs(r: asyncio.StreamReader, w: asyncio.StreamWriter) -> None:
        connections[0] += 1
        if again and connections[0] == 1:
            await r.readexactly(execd.HEADER.size)  # of its START: no call yet
            w.close()
            return
        while True:
            kind, call_id, _ = await read_frame(r)
            got.append(kind)
            if kind == execd.RESUME:
                w.write(frame(execd.ERROR, call_id, b"unknown call"))
            if kind == execd.PING and call_id:  # our timer's: it has ended by itself
                w.write(frame(execd.EXIT, call_id, b'{"code": 7}'))

    monkeypatch.setattr(execd, "_connect", connect)
    await daemons.serve(runs)
    argv = ["sh", "-c", "exit 7"]
    call = asyncio.ensure_future(daemons.client().exec(argv, None, None, {}, None, 9))
    await until(lambda: execd.START in got)  # execd has it: our write has not returned
    clock.now += 10  # past the call's time, and its timer

    result = await asyncio.wait_for(call, 30)  # only bounds a hang
    await until(lambda: execd.RELEASE in got)  # the call's last frame
    assert (result.returncode, execd.KILL in got) == (7, False)


@pytest.mark.parametrize("turn", ["another's", "late"])
async def test_a_start_that_waited_and_was_lost_is_not_sent_again_past_its_calls_time(
    daemons: Daemons, clock: types.SimpleNamespace, timers: None, turn: str
) -> None:
    """Only this fails where a START sent again has our timer's end to be written by."""
    connections = [0]
    got: list[int] = []
    asked, answer = asyncio.Event(), asyncio.Event()

    async def never_had(r: asyncio.StreamReader, w: asyncio.StreamWriter) -> None:
        connections[0] += 1
        if connections[0] == 1:
            await r.readexactly(execd.HEADER.size)  # of its START: no call yet
            w.close()
            return
        while True:
            kind, call_id, _ = await read_frame(r)
            got.append(kind)
            if kind == execd.RESUME:
                asked.set()
                await answer.wait()
                w.write(frame(execd.ERROR, call_id, b"unknown call"))
            if kind == execd.START:  # it runs, and ends
                w.write(frame(execd.EXIT, call_id, b'{"code": 0}'))

    late = False

    def pod() -> str:  # asked as a START's turn comes: no wait has run out by then
        if late:
            clock.now = max(clock.now, 12.0)  # past the call's time, within that timer
        return ""

    await daemons.serve(never_had)
    client = daemons.client(pod)
    link = await client._get()
    await link._wlock.acquire()  # as another call's write has the turn
    call = asyncio.ensure_future(client.exec(["true"], None, None, {}, None, 9))
    await until(lambda: link.bulk.locked())  # its START waits
    clock.now += 8  # in the call's time still: its timer starts again here
    link._wlock.release()
    await asyncio.wait_for(asked.wait(), 30)  # only bounds a hang
    again = client._link
    assert again is not None
    if turn == "late":  # asked for in the call's time
        late = True
    else:  # nor is its turn to be written waited for
        await again._wlock.acquire()
        clock.now += 4  # past the call's time, within that timer
    answer.set()

    with pytest.raises(TimeoutError, match="Command timed out"):
        await asyncio.wait_for(call, 30)  # only bounds a hang
    if turn == "another's":
        again._wlock.release()
    await until(lambda: execd.RELEASE in got)  # the call's last frame
    assert (execd.START in got, connections[0]) == (False, 2)


@pytest.mark.parametrize(
    "how",
    [
        "at once",
        "late in the wait",
        "as the wait ends",
        "in its last ms",
        "our loop held",
        "our loop held to its last second",
    ],
)
async def test_a_timed_out_call_whose_connection_went_silent_asks_execd_on_a_new_one(
    daemons: Daemons,
    clock: types.SimpleNamespace,
    timers: None,
    monkeypatch: pytest.MonkeyPatch,
    how: str,
) -> None:
    """Regression: a connection that had died with no word was waited on, to no end."""
    connections = [0]
    killed, dialled, reached = asyncio.Event(), asyncio.Event(), asyncio.Event()
    connect = execd._connect

    async def held(daemon: execd.Daemon, pace: execd.Pace) -> execd._Pipe:
        if connections[0]:  # the second is reached with so much of the wait left
            dialled.set()
            await reached.wait()
        return await connect(daemon, pace)

    async def goes_silent(r: asyncio.StreamReader, w: asyncio.StreamWriter) -> None:
        connections[0] += 1
        if connections[0] == 2:  # the new one takes that long to answer
            quick = {"as the wait ends": 0.01, "in its last ms": 0.0007}
            clock.now += quick.get(how, 0.1)
        while True:
            kind, call_id, _ = await read_frame(r)
            if connections[0] == 1:  # it takes what is sent, and answers nothing
                if kind == execd.PING:
                    killed.set()
            elif kind == execd.RESUME:
                resumed = b'{"stdin": 0, "eof": false, "put": 0}'
                w.write(frame(execd.RESUMED, call_id, resumed))
                w.write(frame(execd.STDOUT, call_id, b"done\n"))
                w.write(frame(execd.EXIT, call_id, b'{"code": 3}'))

    monkeypatch.setattr(execd, "_connect", held)
    await daemons.serve(goes_silent)
    client = daemons.client()
    argv = ["sh", "-c", "echo done; exit 3"]
    call = asyncio.ensure_future(client.exec(argv, None, None, {}, None, 9))
    other = asyncio.ensure_future(client.exec(argv, None, None, {}, None, None))
    await until(lambda: starts_written(client) == 2)
    clock.now += 2000  # past the first's timeout: its wait for execd's word begins
    await asyncio.wait_for(killed.wait(), 30)  # only bounds a hang
    asked, expired, opening = clock.now, clock.expired, client._opening
    if how.startswith("our loop held"):  # well past the half: looked at again
        last = how.endswith("second")  # a second on, or in half of what is left
        clock.now += execd.KILL_WAIT - 1 if last else execd.KILL_WAIT / 2 + 1.5
        await until(lambda: clock.expired > expired)
        assert client._opening is opening  # none asked for: what came may be unread
        clock.now += 0.5 if last else 1
    else:  # half of it passes with not a frame, and a timer's own lateness
        clock.now += execd.KILL_WAIT / 2 + 0.5
    await asyncio.wait_for(dialled.wait(), 30)  # only bounds a hang
    if how == "late in the wait":
        clock.now = asked + execd.KILL_WAIT - 0.4
    if how == "as the wait ends":  # the old one's turns are few then, not short
        clock.now = asked + execd.KILL_WAIT - 0.025
    if how == "in its last ms":  # no timer fits: one takes a whole millisecond
        clock.now = asked + execd.KILL_WAIT - 0.0016
    reached.set()

    # The pod's other call is asked about there too: execd serves its newest alone.
    results = await asyncio.wait_for(asyncio.gather(call, other), 30)

    assert [(r.returncode, r.stdout) for r in results] == [(3, "done\n")] * 2
    assert connections[0] == 2


async def test_a_connection_silent_for_a_call_is_replaced_though_it_answered_another(
    daemons: Daemons,
    clock: types.SimpleNamespace,
    timers: None,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Regression: what a call had asked was dropped where it joined a reopening."""
    connections = [0]
    asked: list[int] = []  # the calls that have asked on the first connection
    dialled, reached, answers = asyncio.Event(), asyncio.Event(), asyncio.Event()
    connect = execd._connect

    async def held(daemon: execd.Daemon, pace: execd.Pace) -> execd._Pipe:
        if connections[0]:  # the second is reached when the test says
            dialled.set()
            await reached.wait()
        return await connect(daemon, pace)

    async def answers_one(r: asyncio.StreamReader, w: asyncio.StreamWriter) -> None:
        connections[0] += 1
        first = connections[0] == 1
        while True:
            kind, call_id, _ = await read_frame(r)
            if first and kind == execd.PING and call_id:
                asked.append(call_id)
                if len(asked) == 1:  # the first to ask has its exit, late; then silence
                    await answers.wait()
                    w.write(frame(execd.EXIT, call_id, b'{"code": 3}'))
            elif not first and kind == execd.RESUME:
                resumed = b'{"stdin": 0, "eof": false, "put": 0}'
                w.write(frame(execd.RESUMED, call_id, resumed))
                w.write(frame(execd.EXIT, call_id, b'{"code": 7}'))

    monkeypatch.setattr(execd, "_connect", held)
    await daemons.serve(answers_one)
    client = daemons.client()
    one = asyncio.ensure_future(client.exec(["true"], None, None, {}, None, 9))
    other = asyncio.ensure_future(client.exec(["true"], None, None, {}, None, 99))
    await until(lambda: starts_written(client) == 2)
    link = await client._get()
    clock.now += 10  # past the first's timeout: it asks, and hears nothing by the half
    await until(lambda: len(asked) == 1)
    clock.now += execd.KILL_WAIT / 2 + 0.5
    await asyncio.wait_for(dialled.wait(), 30)  # only bounds a hang
    answers.set()
    assert (await asyncio.wait_for(one, 30)).returncode == 3
    clock.now += 100  # past the other's: it asks the connection, silent since that exit
    await until(lambda: len(asked) == 2)
    expired, opening = clock.expired, client._opening
    clock.now += execd.KILL_WAIT / 2 + 0.5  # and joins the reopening still under way
    await until(lambda: clock.expired > expired)
    assert opening is not None and client._opening is opening
    reached.set()
    await asyncio.wait({opening}, timeout=30)  # only bounds a hang

    assert client._link is not link  # silent for the other call: replaced
    result = await asyncio.wait_for(other, 30)  # only bounds a hang
    assert (result.returncode, connections[0]) == (7, 2)


async def test_a_call_that_joins_a_reopening_has_the_new_connection_in_its_own_wait(
    daemons: Daemons,
    clock: types.SimpleNamespace,
    timers: None,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Regression: a reopening waited on past the wait of a call that had joined it."""
    connections = [0]
    asked: list[int] = []  # the calls that have asked on the first connection
    reached, turns, joined = asyncio.Event(), asyncio.Event(), asyncio.Event()
    connect, sleep = execd._connect, execd.asyncio.sleep

    async def dials(daemon: execd.Daemon, pace: execd.Pace) -> execd._Pipe:
        pipe = await connect(daemon, pace)
        if connections[0]:  # the second
            reached.set()
        return pipe

    async def turn(seconds: float) -> None:
        if reached.is_set() and not joined.is_set():  # the old one's turns have begun
            turns.set()
            await joined.wait()
        await sleep(seconds)

    async def silent(r: asyncio.StreamReader, w: asyncio.StreamWriter) -> None:
        connections[0] += 1
        first = connections[0] == 1
        while True:
            kind, call_id, _ = await read_frame(r)
            if first and kind == execd.PING and call_id:  # and not a word back
                asked.append(call_id)
            elif not first and kind == execd.RESUME:
                resumed = b'{"stdin": 0, "eof": false, "put": 0}'
                w.write(frame(execd.RESUMED, call_id, resumed))
                w.write(frame(execd.EXIT, call_id, b'{"code": 3}'))

    monkeypatch.setattr(execd, "_connect", dials)
    monkeypatch.setattr(execd.asyncio, "sleep", turn)
    await daemons.serve(silent)
    client = daemons.client()
    soon = asyncio.ensure_future(client.exec(["true"], None, None, {}, None, 1))
    later = asyncio.ensure_future(client.exec(["true"], None, None, {}, None, 6))
    await until(lambda: starts_written(client) == 2)
    clock.now += 2  # past the first's timeout: it asks, and waits 10 s for a word
    await until(lambda: len(asked) == 1)
    clock.now += 4.5  # past the second's
    await until(lambda: len(asked) == 2)
    expired = clock.expired
    clock.now += 5.3  # our loop held: the first looks again 0.1 s on, the second asks
    await until(lambda: clock.expired >= expired + 2)
    await asyncio.wait_for(turns.wait(), 30)  # only bounds a hang
    assert not soon.done()  # dialled with no pause, young as the silent one is
    expired = clock.expired
    clock.now += 0.15  # the first joins, 0.05 s before its wait ends
    await until(lambda: clock.expired > expired)
    joined.set()

    results = await asyncio.wait_for(asyncio.gather(soon, later), 30)

    assert ([r.returncode for r in results], connections[0]) == ([3, 3], 2)


async def test_an_ack_that_waited_out_its_time_still_goes(
    daemons: Daemons, clock: types.SimpleNamespace, timers: None
) -> None:
    """Regression: an ack out of time was dropped: execd, its window full, waited."""
    held = asyncio.Event()

    async def needs_the_ack(r: asyncio.StreamReader, w: asyncio.StreamWriter) -> None:
        _, call_id, _ = await read_frame(r)  # START
        await held.wait()
        w.write(frame(execd.STDOUT, call_id, b"x" * execd.ACK_EVERY))
        while (ack := await read_frame(r))[0] != execd.ACK:  # room for the rest
            pass
        if json.loads(ack[2])["stdout"] == execd.ACK_EVERY:  # it ends
            w.write(frame(execd.EXIT, call_id, b'{"code": 7}'))
        await r.read()

    await daemons.serve(needs_the_ack)
    client = daemons.client()
    link = await client._get()
    call = asyncio.ensure_future(client.exec(["yes"], None, None, {}, None, 9))
    await until(lambda: starts_written(client) == 1)
    await link._wlock.acquire()  # as another call's write has the turn
    held.set()
    await until(lambda: bool(link._last))  # its ack
    expired = clock.expired
    clock.now += 10  # past our timer: the ack is waited for no longer
    await until(lambda: clock.expired > expired)
    link._wlock.release()

    result = await asyncio.wait_for(call, 30)  # only bounds a hang
    assert result.returncode == 7


async def test_a_timed_out_call_whose_ack_waits_still_asks_execd_on_a_new_connection(
    daemons: Daemons,
    clock: types.SimpleNamespace,
    timers: None,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Regression: its ack waited out our wait behind a stuck write: none was asked."""
    connections = [0]
    stuck = asyncio.Event()
    said = b"y" * execd.ACK_EVERY  # each of the two is acked

    class Stuck(Plain):
        async def write(self, data: bytes) -> None:
            if data[0] == execd.STDIN and connections[0] == 1:  # the pod reads no more
                stuck.set()
                await asyncio.Event().wait()
            await super().write(data)

    async def connect(daemon: execd.Daemon, pace: execd.Pace) -> execd._Pipe:
        r, w = await asyncio.open_connection("127.0.0.1", daemons.ports[daemon])
        return Stuck(r, w)

    async def ends_unheard(r: asyncio.StreamReader, w: asyncio.StreamWriter) -> None:
        connections[0] += 1
        while True:
            kind, call_id, _ = await read_frame(r)
            if kind == execd.START:  # it writes and ends: no exit comes on this one
                await stuck.wait()
                w.write(frame(execd.STDOUT, call_id, said) * 2)
            elif kind == execd.RESUME:
                have = b'{"stdin": 0, "eof": false, "put": 0}'
                w.write(frame(execd.RESUMED, call_id, have))
                w.write(frame(execd.EXIT, call_id, b'{"code": 137}'))

    monkeypatch.setattr(execd, "_connect", connect)
    await daemons.serve(ends_unheard)
    client = daemons.client()
    call = asyncio.ensure_future(client.exec(["sh"], b"x", None, {}, None, 9))
    await asyncio.wait_for(stuck.wait(), 30)  # only bounds a hang
    link = client._link
    assert link is not None
    # Both are read, and the first's ack waits its turn: from here it is silent.
    await until(lambda: [c.got[0] for c in link.calls.values()] == [2 * len(said)])
    await until(lambda: bool(link._last))
    expired = clock.expired
    clock.now += 10  # past our timer: its second ack waits its turn as the first did
    await until(lambda: clock.expired > expired)
    clock.now += execd.KILL_WAIT / 2 + 0.5  # half our wait passes with not a frame

    result = await asyncio.wait_for(call, 30)  # only bounds a hang

    got = (result.returncode, len(result.stdout), connections[0])
    assert got == (137, 2 * len(said), 2)


async def test_a_command_execd_still_gives_time_is_not_killed_at_our_timer(
    daemons: Daemons, clock: types.SimpleNamespace, timers: None
) -> None:
    """Regression: our timer's KILL ended a command execd had started late."""
    connections = [0]
    got: list[int] = []
    asked: list[tuple[asyncio.StreamWriter, int]] = []

    async def started_late(r: asyncio.StreamReader, w: asyncio.StreamWriter) -> None:
        connections[0] += 1
        while True:
            kind, call_id, _ = await read_frame(r)
            got.append(kind)
            if kind == execd.PING:  # it answers: by its own count there is time
                asked.append((w, call_id))
                w.write(frame(execd.PONG, call_id))
            elif kind == execd.KILL:  # as execd ends a command it is told to kill
                w.write(frame(execd.EXIT, call_id, b'{"code": 137}'))

    await daemons.serve(started_late)
    client = daemons.client()
    argv = ["sh", "-c", "sleep 8; exit 7"]
    call = asyncio.ensure_future(client.exec(argv, None, None, {}, None, 9))
    await until(lambda: starts_written(client) == 1)
    link, opening = client._link, client._opening
    assert link is not None
    clock.now += 2000  # past our timer: the wait for execd's word begins
    await until(lambda: link._last_rx == clock.now)  # the PONG is read
    expired = clock.expired
    clock.now += execd.KILL_WAIT / 2  # half of it passes
    await until(lambda: clock.expired > expired or call.done())  # or it was killed
    assert client._opening is opening  # it answered: no other is asked for
    w, call_id = asked[0]
    w.write(frame(execd.EXIT, call_id, b'{"code": 7}'))  # the command ends by itself

    result = await asyncio.wait_for(call, 30)  # only bounds a hang
    await until(lambda: execd.RELEASE in got)  # the call's last frame
    assert (result.returncode, connections[0]) == (7, 1)


@pytest.mark.parametrize("dropped", [False, True], ids=["its own", "a new one"])
async def test_a_command_execd_still_gives_time_has_its_stdin_past_our_timer(
    daemons: Daemons, clock: types.SimpleNamespace, timers: None, dropped: bool
) -> None:
    """Regression: our timer stopped the upload: the command got no more stdin."""
    connections, took = [0], [0]
    got: list[int] = []
    ended: list[int] = []

    async def reads_on(r: asyncio.StreamReader, w: asyncio.StreamWriter) -> None:
        connections[0] += 1
        while True:
            kind, call_id, payload = await read_frame(r)
            got.append(kind)
            if kind == execd.STDIN and payload:
                took[0] += len(payload)
            elif kind == execd.STDIN:  # its end: the command has what came, and ends
                ended.append(took[0])
                w.write(frame(execd.EXIT, call_id, b'{"code": 0}'))
            elif kind == execd.PING and dropped and connections[0] == 1:
                w.transport.abort()
                return
            elif kind == execd.PING:  # our timer's: by its own count it reads on
                w.write(frame(execd.STDIN_ACK, call_id, b'{"stdin": %d}' % took[0]))
            elif kind == execd.RESUME:
                have = b'{"stdin": %d, "eof": false, "put": %d}' % (took[0], took[0])
                w.write(frame(execd.RESUMED, call_id, have))

    await daemons.serve(reads_on)
    client = daemons.client()
    stdin = b"x" * (execd.STDIN_WINDOW + execd.CHUNK)
    call = asyncio.ensure_future(client.exec(["cat"], stdin, None, {}, None, 9))
    await until(lambda: took[0] == execd.STDIN_WINDOW)  # the rest waits for room
    clock.now += 2000  # past our timer

    result = await asyncio.wait_for(call, 30)  # only bounds a hang
    await until(lambda: execd.RELEASE in got)  # the call's last frame
    assert (result.returncode, ended, execd.KILL in got) == (0, [len(stdin)], False)
    assert connections[0] == 1 + dropped


async def test_a_timed_out_call_keeps_a_connection_for_time_its_own_loop_was_held(
    daemons: Daemons, clock: types.SimpleNamespace, timers: None
) -> None:
    """Regression: held past half the kill's wait, we gave up frames we had not read."""
    connections = [0]
    killed, answer, ended = asyncio.Event(), asyncio.Event(), asyncio.Event()

    async def answers_unread(r: asyncio.StreamReader, w: asyncio.StreamWriter) -> None:
        connections[0] += 1
        while True:
            kind, call_id, _ = await read_frame(r)
            if kind == execd.PING:
                killed.set()
                await answer.wait()  # as its answer waits in our socket meanwhile
                w.write(frame(execd.PONG, call_id))
                await ended.wait()
                w.write(frame(execd.EXIT, call_id, b'{"code": 7}'))

    await daemons.serve(answers_unread)
    client = daemons.client()
    argv = ["sh", "-c", "sleep 8; exit 7"]
    call = asyncio.ensure_future(client.exec(argv, None, None, {}, None, 9))
    await until(lambda: starts_written(client) == 1)
    link, opening = client._link, client._opening
    assert link is not None
    clock.now += 2000  # past its timeout: the wait for execd's word begins
    await asyncio.wait_for(killed.wait(), 30)  # only bounds a hang
    expired = clock.expired
    clock.now += 0.7 * execd.KILL_WAIT  # two seconds past its half, our loop held
    await until(lambda: clock.expired > expired)
    answer.set()  # what came meanwhile is read now
    await until(lambda: link._last_rx == clock.now)
    expired = clock.expired
    clock.now += 1  # and looked at a second on
    await until(lambda: clock.expired > expired)
    assert client._opening is opening  # it had answered: no other is asked for
    ended.set()

    result = await asyncio.wait_for(call, 30)  # only bounds a hang
    assert (result.returncode, connections[0]) == (7, 1)


async def test_a_timed_out_call_leaves_a_connection_slow_to_answer_to_the_pods_calls(
    daemons: Daemons,
    clock: types.SimpleNamespace,
    timers: None,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Regression: it closed one silent for half its wait, or left it unread."""
    opened = [0]
    killed: list[tuple[asyncio.StreamWriter, int]] = []

    async def connect(daemon: execd.Daemon, pace: execd.Pace) -> execd._Pipe:
        opened[0] += 1
        if opened[0] == 2:  # as an execd with no time for a new connection
            await asyncio.Event().wait()
        r, w = await asyncio.open_connection("127.0.0.1", daemons.ports[daemon])
        return Plain(r, w)

    async def answers_late(r: asyncio.StreamReader, w: asyncio.StreamWriter) -> None:
        while True:
            kind, call_id, _ = await read_frame(r)
            if kind == execd.PING:
                killed.append((w, call_id))
            elif kind == execd.START and killed:  # a call after it
                w.write(frame(execd.EXIT, call_id, b'{"code": 0}'))
            elif kind == execd.ACK:  # its output taken, execd sends the exit
                w.write(frame(execd.EXIT, call_id, b'{"code": 7}'))

    monkeypatch.setattr(execd, "_connect", connect)
    await daemons.serve(answers_late)
    client = daemons.client()
    said = b"y\n" * (execd.ACK_EVERY // 2)  # enough to be acked
    argv = ["sh", "-c", f"sleep 8; yes | head -n {len(said) // 2}; exit 7"]
    call = asyncio.ensure_future(client.exec(argv, None, None, {}, None, 9))
    await until(lambda: starts_written(client) == 1)
    clock.now += 2000  # past its timeout: the wait for execd's word begins
    await until(lambda: bool(killed))
    clock.now += execd.KILL_WAIT / 2  # half of it passes with not a frame
    await until(lambda: opened[0] == 2)  # another connection is asked for: none comes

    again = client.exec(["true"], None, None, {}, None, None)
    after = await asyncio.wait_for(again, 30)  # only bounds a hang
    w, call_id = killed[0]
    w.write(frame(execd.STDOUT, call_id, said))  # its answer, on the first
    result = await asyncio.wait_for(call, 30)  # only bounds a hang

    assert (after.returncode, result.returncode, opened[0]) == (0, 7, 2)
    assert result.stdout == said.decode()


async def test_a_timed_out_call_asks_for_a_new_connection_once_while_its_own_is_open(
    daemons: Daemons,
    clock: types.SimpleNamespace,
    timers: None,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Regression: an execd too starved to take one was dialled over and over."""
    opened = [0]
    killed: list[tuple[asyncio.StreamWriter, int]] = []

    async def connect(daemon: execd.Daemon, pace: execd.Pace) -> execd._Pipe:
        opened[0] += 1
        if opened[0] > 1:
            raise ConnectionRefusedError("execd takes no new connection")
        r, w = await asyncio.open_connection("127.0.0.1", daemons.ports[daemon])
        return Plain(r, w)

    async def answers_late(r: asyncio.StreamReader, w: asyncio.StreamWriter) -> None:
        while True:
            kind, call_id, _ = await read_frame(r)
            if kind == execd.PING:
                killed.append((w, call_id))

    monkeypatch.setattr(execd, "_connect", connect)
    await daemons.serve(answers_late)
    client = daemons.client()
    call = asyncio.ensure_future(client.exec(["sleep", "9"], None, None, {}, None, 9))
    await until(lambda: starts_written(client) == 1)
    clock.now += 2000  # past its timeout: the kill's wait begins
    await until(lambda: bool(killed))
    clock.now += execd.KILL_WAIT / 2  # half of it passes with not a frame
    await until(lambda: opened[0] >= 2)  # another connection is asked for, and refused
    for _ in range(int(execd.KILL_WAIT) - 1):  # by halves of a second to its end
        looks = clock.looks
        clock.now += 0.5
        await until(lambda: clock.looks > looks)  # its wait has seen that: none asked
    clock.now += 1  # the wait runs out, on time

    with pytest.raises(TimeoutError, match="Command timed out"):
        await asyncio.wait_for(call, 30)  # only bounds a hang
    assert client._opening is not None
    done, _ = await asyncio.wait({client._opening}, timeout=30)  # only bounds a hang
    assert done and opened[0] == 2


@pytest.mark.parametrize(
    "how",
    [
        "answers first",
        "answers then",
        "answers in time",
        "answers as the wait ends",
        "answers and drops",
    ],
)
async def test_a_connection_that_answers_as_another_is_reached_is_kept_if_it_is_open(
    daemons: Daemons,
    clock: types.SimpleNamespace,
    timers: None,
    monkeypatch: pytest.MonkeyPatch,
    how: str,
) -> None:
    """Regression: one that was only slow was replaced, and the pod's streams ended."""
    drops = how == "answers and drops"
    opened, connections = [0], [0]
    got: list[int] = []
    killed: list[tuple[asyncio.StreamWriter, int]] = []
    pipes: list[Plain] = []
    reached, read, unread = asyncio.Event(), asyncio.Event(), asyncio.Event()
    read.set()

    class ReadWhenTold(Plain):
        async def readexactly(self, n: int) -> bytes:
            data = await super().readexactly(n)
            if not read.is_set():  # it has come, and its reader's turn has not
                unread.set()
                await read.wait()
            return data

    async def connect(daemon: execd.Daemon, pace: execd.Pace) -> execd._Pipe:
        opened[0] += 1
        second = opened[0] == 2
        if second:  # execd has time for it when it runs again
            await reached.wait()
        r, w = await asyncio.open_connection("127.0.0.1", daemons.ports[daemon])
        if second and how == "answers then":  # a moment after, our loop held meanwhile
            asyncio.get_running_loop().call_soon(late)
        if second and how == "answers in time":
            asyncio.ensure_future(in_time())
        read.set()  # as this one is reached, if not before
        pipes.append(ReadWhenTold(r, w))
        return pipes[-1]

    def late() -> None:
        clock.now += 1.5
        killed[0][0].write(frame(execd.EXIT, killed[0][1], b'{"code": 7}'))

    async def in_time() -> None:  # half a second on, by the turns it is given to speak
        at = clock.now + 0.5
        while clock.now < at and not pipes[0]._writer.transport.is_closing():
            await asyncio.sleep(0)
        killed[0][0].write(frame(execd.EXIT, killed[0][1], b'{"code": 7}'))

    async def answers_late(r: asyncio.StreamReader, w: asyncio.StreamWriter) -> None:
        connections[0] += 1
        while True:
            kind, call_id, _ = await read_frame(r)
            got.append(kind)
            if kind == execd.PING and not killed:
                killed.append((w, call_id))
            if kind == execd.RESUME:
                resumed = b'{"stdin": 0, "eof": false, "put": 0}'
                w.write(frame(execd.RESUMED, call_id, resumed))
                w.write(frame(execd.EXIT, call_id, b'{"code": 7}'))

    monkeypatch.setattr(execd, "_connect", connect)
    await daemons.serve(answers_late)
    client = daemons.client()
    argv = ["sh", "-c", "sleep 8; exit 7"]
    call = asyncio.ensure_future(client.exec(argv, None, None, {}, None, 9))
    await until(lambda: starts_written(client) == 1)
    link = client._link
    assert link is not None
    (ours,) = link.calls.values()
    clock.now += 2000  # past its timeout: the kill's wait begins
    await until(lambda: bool(killed))
    asked = clock.now
    clock.now += execd.KILL_WAIT / 2  # half of it passes with not a frame
    await until(lambda: opened[0] == 2)  # another connection is asked for
    w, call_id = killed[0]
    if drops:  # one that has dropped since is not kept, whatever it said first
        w.write(frame(execd.STDOUT, call_id, b"so far"))
        w.close()
        await until(lambda: link.closed)
    elif how == "answers first":
        w.write(frame(execd.EXIT, call_id, b'{"code": 7}'))
        await until(lambda: ours.exited)
    elif how == "answers as the wait ends":  # with less than a turn left to speak in
        read.clear()
        w.write(frame(execd.EXIT, call_id, b'{"code": 7}'))
        await asyncio.wait_for(unread.wait(), 30)  # only bounds a hang
        clock.now = asked + execd.KILL_WAIT - 0.015
    reached.set()
    assert client._opening is not None
    done, _ = await asyncio.wait({client._opening}, timeout=30)  # only bounds a hang
    assert done, "the reconnect never ended"

    result = await asyncio.wait_for(call, 30)  # only bounds a hang
    await until(lambda: execd.RELEASE in got)  # the call's last frame
    assert (result.returncode, result.stdout) == (7, "so far" if drops else "")
    # Kept, the first is not asked to resume a call it has; dropped, the second is.
    assert (connections[0], opened[0], got.count(execd.RESUME)) == (1 + drops, 2, drops)
    assert pipes[1]._writer.transport.is_closing() is not drops  # let go, if not used


@pytest.mark.parametrize(
    # In kill's waits: how long each is held, and when the connection drops, if it does.
    ("reopening", "resuming", "drops"),
    [(2.0, 0.0, 0.0), (0.0, 2.0, 0.0), (0.6, 0.0, None), (0.5, 0.0, 0.8)],
    ids=["connection", "resume", "silent", "dropped late"],
)
async def test_a_timed_out_call_waits_for_execds_word_no_longer_than_for_its_kill(
    daemons: Daemons,
    clock: types.SimpleNamespace,
    timers: None,
    monkeypatch: pytest.MonkeyPatch,
    reopening: float,
    resuming: float,
    drops: float | None,
) -> None:
    """Regression: over a new connection the wait for execd had no end of its own."""
    opened, resumes, asked = [0], asyncio.Event(), asyncio.Event()
    killed, drop = asyncio.Event(), asyncio.Event()

    async def held(waits: float) -> None:  # until the clock has moved on by so many
        over = clock.now + waits * execd.KILL_WAIT
        while clock.now < over:  # with no end of its own: the call's wait is the test
            await asyncio.sleep(0.01)

    class Held(Plain):
        async def write(self, data: bytes) -> None:
            if data[0] == execd.RESUME:  # as behind another call's write
                resumes.set()
                await held(resuming)
                asked.set()
            await super().write(data)

    async def connect(daemon: execd.Daemon, pace: execd.Pace) -> execd._Pipe:
        opened[0] += 1
        if opened[0] == 2:  # as an execd out of reach
            await held(reopening)
        r, w = await asyncio.open_connection("127.0.0.1", daemons.ports[daemon])
        return Held(r, w)

    async def at_our_timer(r: asyncio.StreamReader, w: asyncio.StreamWriter) -> None:
        while (await read_frame(r))[0] != execd.PING:
            pass
        killed.set()
        if drops is None:
            await r.read()  # silent: at half the wait we give it up ourselves
        await drop.wait()
        w.transport.abort()

    monkeypatch.setattr(execd, "_connect", connect)
    await daemons.serve(at_our_timer)
    client = daemons.client()
    call = asyncio.ensure_future(client.exec(["sleep", "9"], None, None, {}, None, 9))
    await until(lambda: starts_written(client) == 1)
    clock.now += 2000  # past its timeout: the kill's wait begins
    await asyncio.wait_for(killed.wait(), 30)  # only bounds a hang
    began = clock.now
    clock.now = began + (0.5 if drops is None else drops) * execd.KILL_WAIT
    drop.set()
    await until(lambda: opened[0] == 2)
    if resuming:
        clock.now = began + reopening * execd.KILL_WAIT  # the connection is back
        await asyncio.wait_for(resumes.wait(), 30)  # only bounds a hang
    clock.now = began + 1.01 * execd.KILL_WAIT  # the wait is over, execd not asked

    with pytest.raises(TimeoutError, match="Command timed out"):
        await asyncio.wait_for(call, 30)  # only bounds a hang
    assert not asked.is_set()


async def test_a_call_times_out_in_its_time_though_its_resume_waits_its_turn(
    daemons: Daemons,
    clock: types.SimpleNamespace,
    timers: None,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Regression: the call waited for its RESUME's write, 45 s past its timer."""
    connections = [0]
    resumes = asyncio.Event()

    class Held(Plain):
        async def write(self, data: bytes) -> None:
            if data[0] == execd.RESUME:  # as behind another call's write
                resumes.set()
                await asyncio.Event().wait()
            await super().write(data)

    async def connect(daemon: execd.Daemon, pace: execd.Pace) -> execd._Pipe:
        r, w = await asyncio.open_connection("127.0.0.1", daemons.ports[daemon])
        return Held(r, w)

    async def drops_once(r: asyncio.StreamReader, w: asyncio.StreamWriter) -> None:
        connections[0] += 1
        if connections[0] == 1:
            await read_frame(r)  # START
            w.transport.abort()
        await r.read()

    monkeypatch.setattr(execd, "_connect", connect)
    await daemons.serve(drops_once)
    client = daemons.client()
    call = asyncio.ensure_future(client.exec(["sleep", "9"], None, None, {}, None, 9))
    await asyncio.wait_for(resumes.wait(), 30)  # the drop is read in the call's time
    link = client._link
    assert link is not None
    clock.now += 11  # past its timeout, short of a write's own 45 s
    await until(lambda: len(link._last) == 2)  # its PING, behind the RESUME
    clock.now += 1.01 * execd.KILL_WAIT

    with pytest.raises(TimeoutError, match="Command timed out"):
        await asyncio.wait_for(call, 30)  # only bounds a hang


async def test_a_timed_out_call_is_released_with_no_exit(
    daemons: Daemons, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(execd, "KILL_WAIT", 0.5)
    released = asyncio.Event()

    async def never_exits(r: asyncio.StreamReader, w: asyncio.StreamWriter) -> None:
        while True:
            if (await read_frame(r))[0] == execd.RELEASE:
                released.set()

    await daemons.serve(never_exits)
    with pytest.raises(TimeoutError):
        await daemons.client().exec(["sleep", "9"], None, None, {}, None, 1)
    await asyncio.wait_for(released.wait(), 30)


async def test_a_command_execd_killed_at_its_timeout_raises(
    tls_daemon: TlsDaemon,
) -> None:
    async def times_out(r: asyncio.StreamReader, w: asyncio.StreamWriter) -> None:
        _, call_id, _ = await read_frame(r)  # START
        w.write(frame(execd.EXIT, call_id, b'{"code": 137, "timeout": true}'))
        await r.read()

    sandbox = await tls_daemon(times_out)
    with pytest.raises(TimeoutError, match="Command timed out after 60s"):
        await asyncio.wait_for(
            sandbox.exec(["sleep", "99"], None, None, {}, None, 60), 30
        )


async def test_a_command_that_ended_by_itself_before_our_kill_keeps_its_result(
    daemons: Daemons, clock: types.SimpleNamespace, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Regression: the wait for our kill's exit dropped the command's own."""
    monkeypatch.setattr(execd, "KILL_WAIT", 3600.0)  # only its exit ends the wait

    async def ends_by_itself(r: asyncio.StreamReader, w: asyncio.StreamWriter) -> None:
        _, call_id, _ = await read_frame(r)  # START
        clock.now += 2000  # past its timeout
        w.write(frame(execd.STDOUT, call_id, b"its "))  # wakes us to that
        while (await read_frame(r))[0] != execd.PING:  # our timer's: we wait on
            pass
        w.write(frame(execd.STDOUT, call_id, b"la"))
        w.write(frame(execd.STDOUT, call_id, b"st\n"))
        w.write(frame(execd.EXIT, call_id, b'{"code": 137}'))  # no kill ended it
        await r.read()

    await daemons.serve(ends_by_itself)
    call = daemons.client().exec(["sh", "-c", "exit 137"], None, None, {}, None, 1000)
    result = await asyncio.wait_for(call, 30)  # only bounds a hang

    assert (result.returncode, result.stdout) == (137, "its last\n")


async def test_an_exit_that_came_before_its_connection_dropped_is_kept(
    daemons: Daemons, clock: types.SimpleNamespace, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Regression: with no connection to send a KILL on, the exit was dropped."""
    monkeypatch.setattr(execd, "KILL_WAIT", 0.0)  # nor time to wait: it is here

    async def exits_and_drops(r: asyncio.StreamReader, w: asyncio.StreamWriter) -> None:
        _, call_id, _ = await read_frame(r)  # START
        w.write(frame(execd.STDOUT, call_id, b"done\n"))
        w.write(frame(execd.EXIT, call_id, b'{"code": 137}'))
        w.close()

    await daemons.serve(exits_and_drops)
    client = daemons.client()
    argv = ["sh", "-c", "echo done; exit 137"]
    run = client.run(argv, env={}, cwd=None, user=None, stdin=None, timeout=1000)

    async def taken() -> list[tuple[int, object]]:
        async with contextlib.aclosing(run) as chunks:
            got = [await anext(chunks)]
            link = client._link
            assert link is not None
            await until(lambda: link.closed)  # the exit has come, then the drop
            clock.now += 2000  # past its timeout
            return got + [chunk async for chunk in chunks]

    got = await asyncio.wait_for(taken(), 30)  # only bounds a hang

    late = (execd.PING, None)  # our timer had passed
    assert got == [(execd.STDOUT, b"done\n"), late, (execd.EXIT, {"code": 137})]


async def test_a_command_that_ended_after_its_connection_dropped_keeps_its_result(
    daemons: Daemons, clock: types.SimpleNamespace
) -> None:
    """Regression: past our own timer when the drop was read, it timed out unasked."""
    connections = [0]

    async def ends_unheard(r: asyncio.StreamReader, w: asyncio.StreamWriter) -> None:
        connections[0] += 1
        if connections[0] == 1:
            await read_frame(r)  # START
            clock.now += 2000  # past its timeout, as when our loop is held
            w.close()  # execd hears nothing for so long: the command ends after this
            return
        while (resume := await read_frame(r))[0] != execd.RESUME:
            pass
        call_id = resume[1]
        w.write(frame(execd.RESUMED, call_id, b'{"stdin": 0, "eof": false, "put": 0}'))
        w.write(frame(execd.STDOUT, call_id, b"done\n"))
        w.write(frame(execd.EXIT, call_id, b'{"code": 0}'))
        await r.read()

    await daemons.serve(ends_unheard)
    argv = ["sh", "-c", "sleep 60; echo done"]
    call = daemons.client().exec(argv, None, None, {}, None, 1000)

    result = await asyncio.wait_for(call, 30)  # only bounds a hang

    assert (result.returncode, result.stdout) == (0, "done\n")


@pytest.mark.parametrize("back", [True, False], ids=["in it", "never: eager tasks"])
async def test_a_call_out_of_time_as_its_connection_reopens_has_our_wait_for_execd(
    daemons: Daemons,
    clock: types.SimpleNamespace,
    timers: None,
    monkeypatch: pytest.MonkeyPatch,
    back: bool,
) -> None:
    """Regression: execd went unasked; under eager tasks the call asked on and on."""
    if not back:  # Textual's tasks, under Inspect's full display
        if sys.version_info < (3, 12):
            pytest.skip("tasks start at once from Python 3.12 on")
        asyncio.get_running_loop().set_task_factory(asyncio.eager_task_factory)
    connections = [0]
    dropped, reopen = asyncio.Event(), asyncio.Event()

    async def connect(daemon: execd.Daemon, pace: execd.Pace) -> execd._Pipe:
        connections[0] += 1
        if connections[0] == 2:
            await reopen.wait()
        r, w = await asyncio.open_connection("127.0.0.1", daemons.ports[daemon])
        return Plain(r, w)

    async def ends_unheard(r: asyncio.StreamReader, w: asyncio.StreamWriter) -> None:
        if connections[0] == 1:
            await read_frame(r)  # START
            await dropped.wait()
            w.close()  # the command ends after this, in its time
            return
        while (resume := await read_frame(r))[0] != execd.RESUME:
            pass
        w.write(
            frame(execd.RESUMED, resume[1], b'{"stdin": 0, "eof": false, "put": 0}')
        )
        w.write(frame(execd.STDOUT, resume[1], b"done\n"))
        w.write(frame(execd.EXIT, resume[1], b'{"code": 0}'))
        await r.read()

    monkeypatch.setattr(execd, "_connect", connect)
    await daemons.serve(ends_unheard)
    client = daemons.client()
    argv = ["sh", "-c", "sleep 0.5; echo done"]
    call = asyncio.ensure_future(client.exec(argv, None, None, {}, None, 1))
    await until(lambda: bool(client._link and client._link.calls))
    dropped.set()
    await until(lambda: connections[0] == 2)  # the drop is read in the call's time
    expired = clock.expired
    clock.now += 2000  # which ends with the connection not back
    await until(lambda: clock.expired > expired)
    if not back:
        clock.now += execd.KILL_WAIT  # nor is it back in our wait for execd's word
        with pytest.raises(TimeoutError, match="Command timed out"):
            await asyncio.wait_for(call, 30)  # only bounds a hang
        return
    reopen.set()

    result = await asyncio.wait_for(call, 30)  # only bounds a hang

    assert (result.returncode, result.stdout) == (0, "done\n")


@pytest.mark.parametrize(
    ("had", "answer", "raised", "said"),
    [
        # execd let it go, its client away too long: how it ended is not known
        (b"", b"call abandoned after 6m0s", error.ExecdResultUnknownError, "abandoned"),
        # execd never had it: nothing ran, in all its time
        (None, b"unknown call", TimeoutError, "Command timed out"),
        # execd says so of a call whose output we have: what became of it is not known
        (b"so far", b"unknown call", error.ExecdResultUnknownError, "unknown call"),
    ],
    ids=["abandoned", "never started", "forgotten"],
)
async def test_a_timed_out_call_execd_cannot_resume_ends_as_execd_says(
    daemons: Daemons,
    clock: types.SimpleNamespace,
    timers: None,
    had: bytes | None,
    answer: bytes,
    raised: type[Exception],
    said: str,
) -> None:
    """Regression: execd's word that it had let the call go was read as a timeout."""
    connections = [0]

    async def cannot_resume(r: asyncio.StreamReader, w: asyncio.StreamWriter) -> None:
        connections[0] += 1
        if connections[0] == 1:
            if had is None:
                await r.readexactly(execd.HEADER.size)  # of its START: no call yet
            else:
                _, call_id, _ = await read_frame(r)  # START
                w.write(frame(execd.STDOUT, call_id, had) if had else b"")
            clock.now += 2000  # past its timeout, as when our loop is held
            w.close()
            return
        while (resume := await read_frame(r))[0] != execd.RESUME:
            pass
        w.write(frame(execd.ERROR, resume[1], answer))
        await r.read()

    await daemons.serve(cannot_resume)
    call = daemons.client().exec(["sleep", "60"], None, None, {}, None, 1000)

    with pytest.raises(raised, match=said):
        await asyncio.wait_for(call, 30)  # only bounds a hang
    assert connections[0] == 2  # execd was asked


async def test_a_timed_out_call_whose_daemon_was_replaced_is_timed_out(
    daemons: Daemons, clock: types.SimpleNamespace, timers: None
) -> None:
    """Only this fails where a replaced daemon's error leaves the wait: we timed out."""
    first: asyncio.Server

    async def dies_then(r: asyncio.StreamReader, w: asyncio.StreamWriter) -> None:
        while (await read_frame(r))[0] != execd.PING:
            pass
        first.close()  # execd is gone, and the next start makes another
        w.transport.abort()

    async def knows_no_call(r: asyncio.StreamReader, w: asyncio.StreamWriter) -> None:
        await r.read()

    first = await daemons.serve(dies_then)
    await daemons.serve(knows_no_call)
    client = daemons.client()
    call = asyncio.ensure_future(client.exec(["sleep", "9"], None, None, {}, None, 9))
    await until(lambda: starts_written(client) == 1)
    clock.now += 2000  # past its timeout: the kill's wait finds the drop, then no execd

    # Its timeout passed first: the daemon's end is not what it reports.
    with pytest.raises(TimeoutError, match="Command timed out"):
        await asyncio.wait_for(call, 30)  # only bounds a hang


async def test_a_call_started_again_ends_with_our_wait_where_no_word_comes(
    daemons: Daemons, clock: types.SimpleNamespace, timers: None
) -> None:
    """Only this fails where the error that had it started again stays execd's word."""
    connections = [0]
    got: list[int] = []

    async def says_no_more(r: asyncio.StreamReader, w: asyncio.StreamWriter) -> None:
        connections[0] += 1
        if connections[0] == 1:
            await r.readexactly(execd.HEADER.size)  # of its START: no call yet
            w.close()
            return
        while True:
            kind, call_id, _ = await read_frame(r)
            got.append(kind)
            if kind == execd.RESUME:
                w.write(frame(execd.ERROR, call_id, b"unknown call"))

    await daemons.serve(says_no_more)
    call = asyncio.ensure_future(
        daemons.client().exec(["sleep", "60"], None, None, {}, None, 9)
    )
    await until(lambda: execd.START in got)  # started again, in its time
    clock.now += 10  # past its timer
    await until(lambda: execd.PING in got)
    clock.now += execd.KILL_WAIT  # our wait for execd's word ends

    with pytest.raises(TimeoutError, match="Command timed out"):
        await asyncio.wait_for(call, 30)  # only bounds a hang


async def test_a_word_the_reader_drops_does_not_keep_a_timed_out_call_waiting(
    daemons: Daemons,
    clock: types.SimpleNamespace,
    timers: None,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Only this fails where a word counts as come before the reader has queued it."""
    monkeypatch.setattr(execd, "MAX_QUEUED", 2)  # frames a call may have queued
    connections = [0]
    asked, floods, resumed = asyncio.Event(), asyncio.Event(), asyncio.Event()

    async def drops_its_word(r: asyncio.StreamReader, w: asyncio.StreamWriter) -> None:
        connections[0] += 1
        while connections[0] > 1:  # not execd: it never sends the exit again
            kind, call_id, _ = await read_frame(r)
            if kind == execd.RESUME:
                have = b'{"stdin": 0, "eof": false, "put": 0}'
                w.write(frame(execd.RESUMED, call_id, have))
                resumed.set()
        _, call_id, _ = await read_frame(r)  # START
        while (await read_frame(r))[0] != execd.PING:  # our timer's
            pass
        asked.set()
        await floods.wait()
        w.write(frame(execd.STDOUT, call_id, b"x" * execd.ACK_EVERY))  # its ack waits
        await until(lambda: bool(link._last))
        w.write(frame(execd.STDOUT, call_id, b"y") * 2)  # all the call may have queued
        w.write(frame(execd.EXIT, call_id, b'{"code": 0}'))  # dropped: the reader ends
        await r.read()

    await daemons.serve(drops_its_word)
    client = daemons.client()
    call = asyncio.ensure_future(client.exec(["yes"], None, None, {}, None, 9))
    await until(lambda: starts_written(client) == 1)
    link = await client._get()
    clock.now += 10  # past our timer
    await asyncio.wait_for(asked.wait(), 30)  # only bounds a hang
    await link._wlock.acquire()  # as another call's write has the turn
    floods.set()
    await until(lambda: link.closed)  # the exit is dropped, and the connection with it
    link._wlock.release()
    await asyncio.wait_for(resumed.wait(), 30)  # only bounds a hang
    clock.now += 2 * execd.KILL_WAIT  # our wait for execd's word is over

    with pytest.raises(TimeoutError, match="Command timed out"):
        await asyncio.wait_for(call, 30)  # only bounds a hang
    assert connections[0] == 2


async def test_an_exit_read_with_the_end_of_execds_session_is_kept(
    tls: tuple[ssl.SSLContext, str],
    clock: types.SimpleNamespace,
    tmp_path: pathlib.Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Regression: read once our loop had been held past the timeout, it was dropped."""
    context, pin = tls

    async def exits(r: asyncio.StreamReader, w: asyncio.StreamWriter) -> None:
        await read_frame(r)  # AUTH
        w.write(frame(execd.OK, 0))
        _, call_id, _ = await read_frame(r)  # START
        clock.now += 2000  # past its timeout: we read nothing meanwhile
        w.write(frame(execd.STDOUT, call_id, b"done\n"))
        w.write(frame(execd.EXIT, call_id, b'{"code": 0}'))
        w.close()  # as execd ends a silent connection

    monkeypatch.chdir(tmp_path)  # a socket's path must be short
    # A Unix socket has each write as it returns: our next read holds all three.
    server = await asyncio.start_unix_server(exits, "execd", ssl=context)

    async def start(replace: bool) -> execd.Daemon:
        return execd.Daemon("", pin, b"key", stdio=lambda: anyio.connect_unix("execd"))

    call = execd.ExecdClient(start).exec(["echo", "done"], None, None, {}, None, 1000)
    result = await asyncio.wait_for(call, 30)  # only bounds a hang

    assert (result.returncode, result.stdout) == (0, "done\n")
    server.close()


async def test_a_connection_is_not_given_up_for_time_our_own_loop_was_held(
    daemons: Daemons,
    clock: types.SimpleNamespace,
    interval: collections.abc.Callable[[], None],
) -> None:
    """Regression: held past DEAD_AFTER, we closed a connection before reading it."""
    connections, pings = [0], [0]

    async def answers(r: asyncio.StreamReader, w: asyncio.StreamWriter) -> None:
        connections[0] += 1
        _, call_id, _ = await read_frame(r)  # START
        while pings[0] < 8:
            if (await read_frame(r))[0] == execd.PING:
                pings[0] += 1
                if pings[0] % 2:  # every other one: the next interval has no frame
                    w.write(frame(execd.PONG, 0))
        w.write(frame(execd.EXIT, call_id, b'{"code": 0}'))
        await r.read()

    await daemons.serve(answers)
    client = daemons.client()
    call = asyncio.ensure_future(client.exec(["true"], None, None, {}, None, None))
    await until(lambda: starts_written(client) == 1)
    link = client._link
    assert link is not None
    ended = [0]

    def pinged() -> bool:  # execd has the interval's ping, and we its PONG if one came
        heard = pings[0] % 2 == 0 or link._last_rx == clock.now
        return link.closed or pings[0] == ended[0] and heard

    async def intervals() -> None:
        for _ in range(8):
            ended[0] += 1
            interval()
            await until(pinged)

    clock.now += 2 * execd.DEAD_AFTER  # nothing of ours ran, though execd is there
    # Then three intervals with no frame, all DEAD_AFTER holds, none next to another.
    await asyncio.wait_for(intervals(), 30)  # only bounds a hang

    assert not link.closed and connections == [1]
    assert (await asyncio.wait_for(call, 30)).success  # only bounds a hang


async def test_a_connection_is_given_up_after_three_intervals_with_no_frame(
    daemons: Daemons,
    clock: types.SimpleNamespace,
    interval: collections.abc.Callable[[], None],
) -> None:
    """Only this fails where the keepalive never gives a silent connection up."""
    connections, pings = [0], [0]

    async def falls_silent(r: asyncio.StreamReader, w: asyncio.StreamWriter) -> None:
        connections[0] += 1
        kind, call_id, _ = await read_frame(r)  # START, then its RESUME
        if kind == execd.RESUME:
            resumed = b'{"stdin": 0, "eof": false, "put": 0}'
            w.write(frame(execd.RESUMED, call_id, resumed))
            w.write(frame(execd.EXIT, call_id, b'{"code": 0}'))
        while True:
            if (await read_frame(r))[0] == execd.PING:
                pings[0] += 1
                if pings[0] == 1:  # its last frame on this connection
                    w.write(frame(execd.PONG, 0))

    await daemons.serve(falls_silent)
    client = daemons.client()
    call = asyncio.ensure_future(client.exec(["true"], None, None, {}, None, None))
    await until(lambda: starts_written(client) == 1)
    link = client._link
    assert link is not None
    ended = [0]

    def pinged() -> bool:  # execd has the interval's ping, and we the one PONG it sends
        heard = pings[0] > 1 or link._last_rx == clock.now
        return link.closed or pings[0] == ended[0] and heard

    async def intervals(more: int) -> None:
        for _ in range(more):
            ended[0] += 1
            interval()
            await until(pinged)

    await asyncio.wait_for(intervals(4), 30)  # the PONG's, and two with no frame
    assert not link.closed
    await asyncio.wait_for(intervals(1), 30)  # the third: DEAD_AFTER is three

    assert link.closed
    assert (await asyncio.wait_for(call, 30)).success  # resumed on a new connection
    assert connections == [2]


@pytest.mark.parametrize(
    ("word", "said"),
    [(execd.EXIT, b'{"code": 3}'), (execd.ERROR, b"call abandoned after 6m0s")],
    ids=["an exit", "an error"],
)
async def test_execds_word_that_comes_as_our_writes_wait_behind_a_stuck_one_is_taken(
    daemons: Daemons,
    clock: types.SimpleNamespace,
    timers: None,
    monkeypatch: pytest.MonkeyPatch,
    word: int,
    said: bytes,
) -> None:
    """Regression: our KILL, or an ack, waited on another call's write: a timeout."""
    stuck, exits = asyncio.Event(), asyncio.Event()
    last = b"y" * execd.ACK_EVERY  # enough to ack

    class Stuck(Plain):
        async def write(self, data: bytes) -> None:
            if len(data) > execd.CHUNK:  # the upload's stdin: its peer won't read it
                stuck.set()
                await asyncio.Event().wait()
            await super().write(data)

    async def connect(daemon: execd.Daemon, pace: execd.Pace) -> execd._Pipe:
        r, w = await asyncio.open_connection("127.0.0.1", daemons.ports[daemon])
        return Stuck(r, w)

    async def ends(r: asyncio.StreamReader, w: asyncio.StreamWriter) -> None:
        call_id, argv = 0, b""
        while b"exit 3" not in argv:  # the command's START, not the upload's
            _, call_id, argv = await read_frame(r)
        await stuck.wait()
        clock.now += 10  # past its timeout
        w.write(frame(execd.STDOUT, call_id, b"x"))  # wakes us to that
        await exits.wait()
        w.write(frame(execd.STDOUT, call_id, last))
        w.write(frame(word, call_id, said))
        await r.read()

    monkeypatch.setattr(execd, "_connect", connect)
    await daemons.serve(ends)
    client = daemons.client()
    run = client.exec(["sh", "-c", "exit 3"], None, None, {}, None, 9)
    command = asyncio.ensure_future(run)
    cat = client.exec(["cat"], b"x" * execd.CHUNK, None, {}, None, None)
    upload = asyncio.ensure_future(cat)
    try:
        await until(lambda: client._link is not None and bool(client._link._last))
        link = client._link
        assert link is not None
        exits.set()
        await until(lambda: any(call.ends for call in link.calls.values()))
        clock.now += execd.KILL_WAIT  # all its ack may wait: the stuck write stays
        if word == execd.ERROR:
            with pytest.raises(error.ExecdResultUnknownError, match="abandoned"):
                await asyncio.wait_for(command, 30)  # only bounds a hang
            return
        result = await asyncio.wait_for(command, 30)  # only bounds a hang
    finally:
        upload.cancel()

    assert (result.returncode, result.stdout) == (3, "x" + last.decode())


async def test_an_exit_that_follows_more_output_than_we_hold_is_kept(
    daemons: Daemons, clock: types.SimpleNamespace, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Only this fails where HOLD is less than both streams' unacked output."""
    monkeypatch.setattr(execd, "KILL_WAIT", 3600.0)  # only its exit ends the wait
    full = b"y" * execd.ACK_EVERY  # enough to ack
    sent = asyncio.Event()
    sent.set()

    class Waits(Plain):
        async def write(self, data: bytes) -> None:
            await sent.wait()  # as behind another call's write
            await super().write(data)

    async def connect(daemon: execd.Daemon, pace: execd.Pace) -> execd._Pipe:
        r, w = await asyncio.open_connection("127.0.0.1", daemons.ports[daemon])
        return Waits(r, w)

    async def ends(r: asyncio.StreamReader, w: asyncio.StreamWriter) -> None:
        _, call_id, _ = await read_frame(r)  # START
        clock.now += 2000  # past its timeout
        w.write(frame(execd.STDOUT, call_id, b"x"))  # wakes us to that
        while (await read_frame(r))[0] != execd.PING:  # our timer's: we wait on
            pass
        for _ in range(3):
            w.write(frame(execd.STDOUT, call_id, full))
            while (await read_frame(r))[0] != execd.ACK:  # taken: the next may come
                pass
        sent.clear()
        for kind in (execd.STDOUT, execd.STDERR):
            for _ in range(4):  # within what execd sends of a stream unacked
                w.write(frame(kind, call_id, full))
        w.write(frame(execd.EXIT, call_id, b'{"code": 3}'))
        await r.read()

    monkeypatch.setattr(execd, "_connect", connect)
    await daemons.serve(ends)
    client = daemons.client()
    run = client.exec(["sh", "-c", "exit 3"], None, None, {}, None, 1000)
    command = asyncio.ensure_future(run)
    await until(
        lambda: client._link is not None
        and any(call.exited for call in client._link.calls.values())
    )
    sent.set()
    result = await asyncio.wait_for(command, 30)  # only bounds a hang

    got = (result.returncode, len(result.stdout), len(result.stderr))
    assert got == (3, 1 + 7 * len(full), 4 * len(full))


async def test_an_exit_behind_a_drop_its_call_heard_of_twice_is_kept(
    daemons: Daemons,
    clock: types.SimpleNamespace,
    timers: None,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Regression: our kill's wait took the second word of an old drop for a new one."""
    monkeypatch.setattr(execd, "KILL_WAIT", 3600.0)  # only its exit ends the wait
    connections: list[asyncio.StreamWriter] = []
    started, resuming, answer = asyncio.Event(), asyncio.Event(), asyncio.Event()
    opened = 0

    class SecondIsLost(Plain):
        nth = 0

        async def write(self, data: bytes) -> None:
            if self.nth == 2 and data[0] == execd.RESUME:  # heard of by its send too
                resuming.set()
                await until(self._writer.transport.is_closing)
            await super().write(data)

    async def connect(daemon: execd.Daemon, pace: execd.Pace) -> execd._Pipe:
        nonlocal opened
        r, w = await asyncio.open_connection("127.0.0.1", daemons.ports[daemon])
        opened += 1
        pipe = SecondIsLost(r, w)
        pipe.nth = opened
        return pipe

    async def resumes_on_the_third(
        r: asyncio.StreamReader, w: asyncio.StreamWriter
    ) -> None:
        connections.append(w)
        nth = len(connections)
        if nth == 1:
            await read_frame(r)  # START
            started.set()
        if nth < 3:  # the test drops the first two
            await r.read()
            return
        _, call_id, _ = await read_frame(r)  # RESUME
        await answer.wait()
        w.write(frame(execd.RESUMED, call_id, b'{"stdin": 0, "eof": false, "put": 0}'))
        w.write(frame(execd.EXIT, call_id, b'{"code": 7}'))
        await r.read()

    monkeypatch.setattr(execd, "_connect", connect)
    await daemons.serve(resumes_on_the_third)
    client = daemons.client()
    call = asyncio.ensure_future(client.exec(["sleep", "1"], None, None, {}, None, 9))
    await asyncio.wait_for(started.wait(), 30)
    connections[0].transport.abort()
    await asyncio.wait_for(resuming.wait(), 30)
    link = client._link
    assert link is not None
    clock.now += 11  # past its timeout: its PING waits behind the RESUME
    await until(lambda: len(link._last) == 2)
    connections[1].transport.abort()
    await until(lambda: not link._last)  # its RESUME's send has failed, and said so
    answer.set()

    result = await asyncio.wait_for(call, 30)  # only bounds a hang

    assert (result.returncode, opened) == (7, 3)  # and no connection for the old word


@pytest.mark.parametrize("held", [False, True], ids=["seen", "our loop held"])
async def test_a_killed_commands_last_output_does_not_count_against_its_limit(
    daemons: Daemons,
    clock: types.SimpleNamespace,
    monkeypatch: pytest.MonkeyPatch,
    held: bool,
) -> None:
    """Regression: a timed-out command's last byte raised OutputLimitExceededError."""
    monkeypatch.setattr(execd, "KILL_WAIT", 3600.0)  # only its exit ends the wait
    limit = execd.limits.MAX_EXEC_OUTPUT_SIZE
    exited = asyncio.Event()

    async def times_out(r: asyncio.StreamReader, w: asyncio.StreamWriter) -> None:
        _, call_id, _ = await read_frame(r)  # START
        left = limit - 1  # all but its last byte comes in its time
        while left:
            w.write(frame(execd.STDOUT, call_id, b"x" * min(left, execd.ACK_EVERY)))
            left -= min(left, execd.ACK_EVERY)
            # Taken: the next may come. The last one is not waited for.
            while left and (await read_frame(r))[0] != execd.ACK:
                pass
        if held:  # our timer passes unseen, the call waiting for more
            link = client._link
            assert link is not None
            await until(lambda: link.calls[call_id].taken[0] == limit - 1)
            clock.now += 2000  # past its timeout
            w.write(frame(execd.STDOUT, call_id, b"xx"))
        else:
            clock.now += 2000  # past its timeout
            w.write(frame(execd.STDOUT, call_id, b"x"))  # its limit: wakes us to that
            while (await read_frame(r))[0] != execd.PING:
                pass
            w.write(frame(execd.STDOUT, call_id, b"x"))
        w.write(frame(execd.EXIT, call_id, b'{"code": 137, "timeout": true}'))
        exited.set()
        await r.read()

    await daemons.serve(times_out)
    client = daemons.client()
    with pytest.raises(TimeoutError, match="Command timed out"):
        call = client.exec(["yes"], None, None, {}, None, 1000)
        await asyncio.wait_for(call, 30)  # only bounds a hang
    assert exited.is_set()  # on execd's word, its limit passed


@pytest.mark.parametrize("ends", [False, True], ids=["no word", "its own exit"])
async def test_a_command_that_writes_on_past_our_timer_has_its_limit_and_our_wait(
    daemons: Daemons, clock: types.SimpleNamespace, timers: None, ends: bool
) -> None:
    """Only this fails where a command that writes on past our timer has no bound."""
    limit = execd.limits.MAX_EXEC_OUTPUT_SIZE
    # Each stream its own byte, and each frame enough to be acked.
    more = {execd.STDOUT: b"o" * execd.ACK_EVERY, execd.STDERR: b"e" * execd.ACK_EVERY}
    over = 2 * (limit // execd.ACK_EVERY + 1)  # frames: more than is kept of either
    got: list[int] = []
    sent: list[int] = []

    async def writes_on(r: asyncio.StreamReader, w: asyncio.StreamWriter) -> None:
        _, call_id, _ = await read_frame(r)  # START
        while True:
            kind, _, _ = await read_frame(r)
            got.append(kind)
            if kind not in (execd.PING, execd.ACK):
                continue
            if ends and len(sent) >= over:  # it ends by itself
                w.write(frame(execd.EXIT, call_id, b'{"code": 0}'))
                await r.read()
            # To both streams in turn, as each is acked; three at first, so some wait.
            for _ in range(3 if kind == execd.PING else 1):
                clock.now += execd.KILL_WAIT / (1.5 * over)  # our wait ends past them
                sent.append(execd.STDOUT + len(sent) % 2)
                w.write(frame(sent[-1], call_id, more[sent[-1]]))

    await daemons.serve(writes_on)
    client = daemons.client()
    argv = ["sh", "-c", "yes | tee /dev/stderr"]
    call = asyncio.ensure_future(client.exec(argv, None, None, {}, None, 9))
    await until(lambda: starts_written(client) == 1)
    clock.now += 2000  # past our timer: it writes on, by execd's leave for all we know
    if ends:  # too much output, as before our timer, and no more of it kept
        with pytest.raises(inspect_ai.util.OutputLimitExceededError) as too_much:
            await asyncio.wait_for(call, 30)  # only bounds a hang
        assert too_much.value.truncated_output == "o" * limit + "e" * limit
        return

    # Its output does not put off the end of our wait for execd's word.
    with pytest.raises(TimeoutError, match="Command timed out"):
        await asyncio.wait_for(call, 30)  # only bounds a hang
    await until(lambda: execd.RELEASE in got)  # the call's last frame
    assert len(sent) > over and execd.KILL in got


async def test_a_deadline_that_passed_unseen_is_seen_to_before_more_output_is_taken(
    daemons: Daemons, clock: types.SimpleNamespace, timers: None
) -> None:
    """Only this fails where our loop, held past its wait, takes the queue first."""

    async def writes_on(r: asyncio.StreamReader, w: asyncio.StreamWriter) -> None:
        _, call_id, _ = await read_frame(r)  # START
        while (await read_frame(r))[0] != execd.PING:  # our timer's
            pass
        w.write(frame(execd.STDOUT, call_id, b"more"))
        await r.read()

    await daemons.serve(writes_on)
    client = daemons.client()
    run = client.run(["yes"], env={}, cwd=None, user=None, stdin=None, timeout=9)

    async def taken() -> list[tuple[int, object]]:
        async with contextlib.aclosing(run) as chunks:
            first = asyncio.ensure_future(anext(chunks))
            await until(lambda: starts_written(client) == 1)
            link = client._link
            assert link is not None
            (call,) = link.calls.values()
            clock.now += 2000  # past its timeout
            got = [await first]  # our timer's turn: its caller is slow to ask on
            await until(lambda: call.got[0] > 0)  # more output has come meanwhile
            clock.now += execd.KILL_WAIT + 1  # and the half and the end of our wait
            return got + [chunk async for chunk in chunks]

    got = await asyncio.wait_for(taken(), 30)  # only bounds a hang

    assert got == [(execd.PING, None)]  # a writer that never stops would put it off


async def test_our_timer_follows_execds_own(
    daemons: Daemons,
    clock: types.SimpleNamespace,
    monkeypatch: pytest.MonkeyPatch,
    no_timer_lag: float,
) -> None:
    """Regression: ours fired first, on a command whose timeout was not up."""
    # Any lag we ship, as a minute: the stand-in has the test's budget to answer in it.
    monkeypatch.setattr(execd, "TIMER_LAG", 60.0 * (no_timer_lag > 0))
    got: list[int] = []

    async def still_runs(r: asyncio.StreamReader, w: asyncio.StreamWriter) -> None:
        _, call_id, _ = await read_frame(r)  # START
        clock.now += 1030  # past its timeout, within our lag
        w.write(frame(execd.STDOUT, call_id, b"x" * execd.ACK_EVERY))  # we ack, or ask
        while not {execd.ACK, execd.PING} & set(got):
            got.append((await read_frame(r))[0])
        w.write(frame(execd.EXIT, call_id, b'{"code": 0}'))
        while execd.RELEASE not in got:
            got.append((await read_frame(r))[0])

    await daemons.serve(still_runs)
    call = daemons.client().exec(["sleep", "999"], None, None, {}, None, 1000)
    result = await asyncio.wait_for(call, 30)  # only bounds a hang
    await until(lambda: execd.RELEASE in got)

    # No PING: our timer had not passed.
    assert (result.returncode, execd.PING in got) == (0, False)


async def test_a_reconnect_waits_only_for_what_is_left_of_the_timeout(
    daemons: Daemons, clock: types.SimpleNamespace
) -> None:
    """Regression: a command cut off late in its timeout waited that long again."""
    started = asyncio.Event()
    peers: list[asyncio.StreamWriter] = []

    async def takes_the_start(r: asyncio.StreamReader, w: asyncio.StreamWriter) -> None:
        peers.append(w)
        await read_frame(r)  # START
        started.set()
        await r.read()

    server = await daemons.serve(takes_the_start)
    run = daemons.client().exec(["sleep", "999"], None, None, {}, None, 1000)
    call = asyncio.ensure_future(run)
    await asyncio.wait_for(started.wait(), 30)
    clock.now += 2000  # past its timeout: only then is it cut off
    server.close()
    peers[0].transport.abort()

    with pytest.raises(TimeoutError, match="Command timed out after 1000s"):
        await asyncio.wait_for(call, 30)  # only bounds a hang


RESTARTED = error.ContainerRestartedError(
    pod_name="p", container_name="default", restart_count=1, last_reason="Error"
)


@pytest.mark.parametrize(
    ("failure", "raised"),
    [
        pytest.param(
            kubernetes.client.exceptions.ApiException(status=404),
            error.ExecdResultUnknownError,
            id="the pod is deleted",
        ),
        (RESTARTED, error.ContainerRestartedError),
    ],
)
async def test_a_failed_restart_after_start_is_not_retryable(
    daemons: Daemons, failure: Exception, raised: type[Exception]
) -> None:
    """Regression: a start that could never succeed was tried again for 5 minutes."""

    async def start_fails(replace: bool) -> execd.Daemon:
        raise failure

    async def dies_after_start(
        r: asyncio.StreamReader, w: asyncio.StreamWriter
    ) -> None:
        await read_frame(r)  # START
        sandbox._start = start_fails
        server.close()
        w.close()

    server = await daemons.serve(dies_after_start)
    sandbox = daemons.client()

    # PodError is retried too, which would run the command again.
    with pytest.raises(raised):
        call = sandbox.exec(["touch", "/once"], None, None, {}, None, None)
        await asyncio.wait_for(call, 30)  # only bounds a hang


@pytest.mark.parametrize(
    "failure",
    [
        kubernetes.client.exceptions.ApiException(status=503),
        # As at the pod's PID limit: the start fails, and the daemon runs on.
        error.PodError("execd did not start"),
    ],
)
async def test_a_start_that_fails_while_reconnecting_does_not_lose_the_command(
    daemons: Daemons, monkeypatch: pytest.MonkeyPatch, failure: Exception
) -> None:
    """Regression: one failed pod read ended the reconnect, and with it the command."""
    dropped = probed = False
    connect = execd._connect

    async def refused_until_probed(
        daemon: execd.Daemon, pace: execd.Pace
    ) -> execd._Pipe:
        if dropped and not probed:
            raise ConnectionRefusedError
        return await connect(daemon, pace)

    async def unavailable(replace: bool) -> execd.Daemon:
        nonlocal probed
        probed = True
        raise failure

    async def drops_then_resumes(
        r: asyncio.StreamReader, w: asyncio.StreamWriter
    ) -> None:
        nonlocal dropped
        kind, call_id, _ = await read_frame(r)
        if kind == execd.START:  # the command runs on in execd: the connection drops
            dropped, sandbox._start = True, unavailable
            w.close()
            return
        w.write(frame(execd.RESUMED, call_id, b'{"stdin": 0, "eof": true, "put": 0}'))
        w.write(frame(execd.EXIT, call_id, b'{"code": 7}'))
        await r.read()

    await daemons.serve(drops_then_resumes)
    sandbox = daemons.client()
    monkeypatch.setattr(execd, "_connect", refused_until_probed)

    call = sandbox.exec(["touch", "/once"], None, None, {}, None, None)
    result = await asyncio.wait_for(call, 30)

    assert (result.returncode, probed) == (7, True)


@pytest.mark.parametrize(
    "status",
    [
        b"[]",
        b"null",
        b"{}",
        b'{"code": "0"}',
        b'{"code": 0, "error": 5}',
        b'{"code": -1}',
        b'{"code": 256}',
    ],
)
async def test_an_exit_status_that_is_not_one_is_a_lost_result(
    daemons: Daemons, status: bytes
) -> None:
    """Regression: a stand-in's exit raised AttributeError, or read as a timeout."""

    async def exits(r: asyncio.StreamReader, w: asyncio.StreamWriter) -> None:
        _, call_id, _ = await read_frame(r)  # START
        w.write(frame(execd.EXIT, call_id, status))
        await r.read()

    await daemons.serve(exits)

    with pytest.raises(error.ExecdResultUnknownError):
        call = daemons.client().exec(["true"], None, None, {}, None, None)
        await asyncio.wait_for(call, 30)


@pytest.mark.parametrize("ack", [b"[]", b"{}", b"0", b'{"stdin": "1"}'])
async def test_a_stdin_ack_that_is_not_one_ends_the_connection_quietly(
    daemons: Daemons, ack: bytes, caplog: pytest.LogCaptureFixture
) -> None:
    """Regression: it ended the reader with an exception nothing retrieved."""
    served = 0

    async def acks(r: asyncio.StreamReader, w: asyncio.StreamWriter) -> None:
        nonlocal served
        served += 1
        _, call_id, _ = await read_frame(r)  # START, then RESUME
        if served == 1:
            w.write(frame(execd.STDIN_ACK, call_id, ack))
        else:
            w.write(
                frame(execd.RESUMED, call_id, b'{"stdin": 1, "eof": true, "put": 1}')
            )
            w.write(frame(execd.EXIT, call_id, b'{"code": 0}'))
        await r.read()

    await daemons.serve(acks)

    call = daemons.client().exec(["cat"], b"x", None, {}, None, None)
    result = await asyncio.wait_for(call, 30)

    assert (result.returncode, served) == (0, 2)
    gc.collect()  # asyncio reports the reader's exception when the task is freed
    assert "exception was never retrieved" not in caplog.text


async def test_a_port_held_by_another_process_fails_at_once(
    daemons: Daemons, monkeypatch: pytest.MonkeyPatch
) -> None:
    async def squatted(daemon: execd.Daemon, pace: execd.Pace) -> execd._Pipe:
        raise execd.NotOurDaemon("certificate mismatch")

    async def port_taken(replace: bool) -> execd.Daemon:
        raise execd.DaemonRunning("address already in use")

    monkeypatch.setattr(execd, "_connect", squatted)
    sandbox = execd.ExecdClient(port_taken)
    sandbox._daemon = execd.Daemon("127.0.0.1", "ours", b"key")

    with pytest.raises(RuntimeError, match="held by a process other than execd"):
        await asyncio.wait_for(sandbox.exec(["true"], None, None, {}, None, None), 30)


async def test_a_frame_the_cap_refuses_is_asked_for_again(daemons: Daemons) -> None:
    flooded = asyncio.Event()

    async def one_too_many(r: asyncio.StreamReader, w: asyncio.StreamWriter) -> None:
        _, call_id, _ = await read_frame(r)  # START
        with contextlib.suppress(ConnectionError):
            for _ in range(execd.MAX_QUEUED + 1):
                w.write(frame(execd.STDOUT, call_id, b"x"))
                await w.drain()
        flooded.set()

    await daemons.serve(one_too_many)
    stream = await daemons.client().open_stream(["cat"], None)
    await asyncio.wait_for(flooded.wait(), 30)
    await until(lambda: stream._link.closed)

    assert stream._link.closed
    # What a resume would ask for: the refused byte is not counted as received.
    assert stream._call.got[0] == execd.MAX_QUEUED


@pytest.mark.parametrize(
    ("kind", "size"),
    [(execd.ERROR, execd.MAX_CONTROL + 1), (execd.STDIN_ACK, execd.MAX_ACK + 1)],
)
async def test_a_large_control_frame_drops_the_connection(
    daemons: Daemons, kind: int, size: int
) -> None:
    async def large(r: asyncio.StreamReader, w: asyncio.StreamWriter) -> None:
        _, call_id, _ = await read_frame(r)  # START
        # JSON, so only its size can drop the connection
        w.write(frame(kind, call_id, b'{"stdin": 0}'.ljust(size)))
        await r.read()

    await daemons.serve(large)
    stream = await daemons.client().open_stream(["cat"], None)
    await until(lambda: stream._link.closed)

    assert stream._link.closed
    assert held(stream) == 0


async def test_closing_a_stream_ends_a_send_waiting_for_room(daemons: Daemons) -> None:
    async def never_acks_stdin(
        r: asyncio.StreamReader, w: asyncio.StreamWriter
    ) -> None:
        while True:
            await read_frame(r)

    await daemons.serve(never_acks_stdin)
    stream = await daemons.client().open_stream(["cat"], None)
    send = asyncio.create_task(stream.send(b"x" * (2 * execd.STDIN_WINDOW)))
    await until(lambda: stream._sent >= execd.STDIN_WINDOW)

    await stream.aclose()

    with pytest.raises(anyio.BrokenResourceError):
        await asyncio.wait_for(send, 30)


async def test_a_send_cancelled_partway_ends_the_stream(daemons: Daemons) -> None:
    """Regression: the part it had sent stayed, and the next item followed it."""
    took = [0]

    async def never_acks_stdin(
        r: asyncio.StreamReader, w: asyncio.StreamWriter
    ) -> None:
        while True:
            kind, _, payload = await read_frame(r)
            if kind == execd.STDIN:
                took[0] += len(payload)

    await daemons.serve(never_acks_stdin)
    stream = await daemons.client().open_stream(["cat"], None)
    send = asyncio.create_task(stream.send(b"x" * (2 * execd.STDIN_WINDOW)))
    # All of it written: it waits for room, and no write of it ends as it is cancelled.
    await until(lambda: took[0] >= execd.STDIN_WINDOW)

    send.cancel()

    with pytest.raises(asyncio.CancelledError):
        await send
    with pytest.raises(anyio.ClosedResourceError):
        await asyncio.wait_for(stream.send(b"next"), 30)


async def test_a_daemon_that_is_not_ours_is_replaced(
    daemons: Daemons, monkeypatch: pytest.MonkeyPatch
) -> None:
    async def answers(r: asyncio.StreamReader, w: asyncio.StreamWriter) -> None:
        while True:
            kind, call_id, _ = await read_frame(r)
            if kind == execd.START:
                w.write(frame(execd.EXIT, call_id, b'{"code": 0}'))

    await daemons.serve(answers)
    await daemons.serve(answers)
    sandbox = daemons.client()
    starts = []
    start = sandbox._start

    async def recorded(replace: bool) -> execd.Daemon:
        starts.append(replace)
        return await start(replace)

    sandbox._start = recorded
    await sandbox.exec(["true"], None, None, {}, None, 30)
    first, connect = sandbox._daemon, execd._connect

    async def another_execd_on_first(
        daemon: execd.Daemon, pace: execd.Pace
    ) -> execd._Pipe:
        # Our start's reply was lost, and that daemon now holds the port.
        if daemon is first:
            raise execd.NotOurDaemon("certificate mismatch")
        return await connect(daemon, pace)

    monkeypatch.setattr(execd, "_connect", another_execd_on_first)
    assert sandbox._link is not None
    await sandbox._link.close()

    await sandbox.exec(["true"], None, None, {}, None, 30)

    assert starts == [True, True]


async def test_many_small_frames_arrive_without_dropping_the_connection(
    daemons: Daemons,
) -> None:
    lines = 4 * execd.MAX_QUEUED

    async def chatty(r: asyncio.StreamReader, w: asyncio.StreamWriter) -> None:
        _, call_id, _ = await read_frame(r)  # START
        w.write(b"".join(frame(execd.STDOUT, call_id, b"x") for _ in range(lines)))
        w.write(frame(execd.EXIT, call_id, b'{"code": 0}'))
        while True:
            await read_frame(r)

    await daemons.serve(chatty)
    sandbox = daemons.client()

    result = await sandbox.exec(["yes"], None, None, {}, None, 30)

    assert len(result.stdout) == lines
    assert sandbox._link is not None and not sandbox._link.closed


async def test_callers_share_one_reconnect(daemons: Daemons) -> None:
    connections = 0

    async def idle(r: asyncio.StreamReader, w: asyncio.StreamWriter) -> None:
        nonlocal connections
        connections += 1
        await r.read()

    await daemons.serve(idle)
    sandbox = daemons.client()
    stale = await asyncio.wait_for(sandbox._get(), 30)
    await stale.close()

    reopens = asyncio.gather(*(sandbox._get(stale) for _ in range(5)))
    links = await asyncio.wait_for(reopens, 30)  # only bounds a hang

    assert (len(set(links)), connections) == (1, 2)


async def test_only_a_resume_waits_out_a_reconnect(
    daemons: Daemons, monkeypatch: pytest.MonkeyPatch
) -> None:
    async def answers(r: asyncio.StreamReader, w: asyncio.StreamWriter) -> None:
        while True:
            kind, call_id, _ = await read_frame(r)
            if kind == execd.START:
                w.write(frame(execd.EXIT, call_id, b'{"code": 0}'))

    await daemons.serve(answers)
    client = daemons.client()
    await client.exec(["true"], None, None, {}, None, 30)
    stale = client._link
    assert stale is not None
    await stale.close()

    back = asyncio.Event()
    connect = execd._connect

    async def refused_until_back(daemon: execd.Daemon, pace: execd.Pace) -> execd._Pipe:
        if not back.is_set():
            raise ConnectionRefusedError
        return await connect(daemon, pace)

    async def still_running(replace: bool) -> execd.Daemon:
        raise execd.DaemonRunning("address already in use")

    monkeypatch.setattr(execd, "_connect", refused_until_back)
    monkeypatch.setattr(execd, "FIRST_OPEN_FOR", 0.5)  # past the reconnect's first try
    client._start = still_running
    resume = asyncio.create_task(client._get(stale))

    with pytest.raises(ConnectionError, match="ConnectionRefusedError"):
        await asyncio.wait_for(client.exec(["true"], None, None, {}, None, None), 30)
    back.set()
    assert await asyncio.wait_for(resume, 30) is not stale


async def test_a_call_cancelled_as_its_connection_reopens_starts_nothing(
    daemons: Daemons, monkeypatch: pytest.MonkeyPatch
) -> None:
    started = 0

    async def answers(r: asyncio.StreamReader, w: asyncio.StreamWriter) -> None:
        nonlocal started
        while True:
            kind, call_id, _ = await read_frame(r)
            if kind == execd.START:
                started += 1
                w.write(frame(execd.EXIT, call_id, b'{"code": 0}'))

    await daemons.serve(answers)
    client = daemons.client()
    await client.exec(["true"], None, None, {}, None, 30)
    assert client._link is not None
    await client._link.close()
    connect, reopened = execd._connect, asyncio.Event()

    async def held(daemon: execd.Daemon, pace: execd.Pace) -> execd._Pipe:
        await reopened.wait()
        return await connect(daemon, pace)

    monkeypatch.setattr(execd, "_connect", held)
    call = asyncio.create_task(client.exec(["true"], None, None, {}, None, None))
    await until(lambda: client._opening is not None and not client._opening.done())
    assert client._opening is not None
    client._opening.add_done_callback(lambda _: call.cancel())
    reopened.set()

    with pytest.raises(asyncio.CancelledError):
        await call
    # Its START follows any the cancelled call sent.
    await client.exec(["true"], None, None, {}, None, 30)
    assert started == 2


async def test_a_daemon_that_cannot_be_reached_is_not_restarted_in_a_loop(
    clock: types.SimpleNamespace, monkeypatch: pytest.MonkeyPatch
) -> None:
    async def refused(daemon: execd.Daemon, pace: execd.Pace) -> execd._Pipe:
        await asyncio.sleep(0)  # as a dial yields: an unpaced loop can then be ended
        raise ConnectionRefusedError

    replaced: list[bool] = []

    async def start(replace: bool) -> execd.Daemon:
        replaced.append(replace)
        return execd.Daemon("127.0.0.1", f"cert-{len(replaced)}", b"key")

    monkeypatch.setattr(execd, "_connect", refused)
    monkeypatch.setattr(execd, "FIRST_OPEN_FOR", 1.0)

    with pytest.raises(ConnectionError):
        call = execd.ExecdClient(start).exec(["true"], None, None, {}, None, None)
        await asyncio.wait_for(call, 30)  # only bounds a hang

    # Paced: a handful in the second, where an unpaced loop never sees it pass.
    assert 1 < len(replaced) <= 10
    # Only the first replaces what it finds: the rest would kill the daemon it started.
    assert replaced[0] and not any(replaced[1:])


async def test_a_restart_that_fails_on_a_first_open_ends_it_at_once(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def refused(daemon: execd.Daemon, pace: execd.Pace) -> execd._Pipe:
        raise ConnectionRefusedError

    starts = 0

    async def start(replace: bool) -> execd.Daemon:
        nonlocal starts
        starts += 1
        if starts > 1:
            raise RuntimeError("the node is gone")
        return execd.Daemon("127.0.0.1", "cert", b"key")

    monkeypatch.setattr(execd, "_connect", refused)

    # What the start said, at once: not "execd unreachable" 30 s later.
    with pytest.raises(RuntimeError, match="the node is gone"):
        call = execd.ExecdClient(start).exec(["true"], None, None, {}, None, None)
        await asyncio.wait_for(call, 30)  # only bounds a hang


async def test_unasked_resumed_replies_send_no_stdin_twice(daemons: Daemons) -> None:
    stdin = b"x" * (2 * execd.STDIN_WINDOW)
    received = 0

    async def floods_resumed(r: asyncio.StreamReader, w: asyncio.StreamWriter) -> None:
        nonlocal received
        _, call_id, _ = await read_frame(r)  # START
        resumed = json.dumps({"stdin": 0, "eof": False, "put": 0}).encode()
        while True:
            kind, _, payload = await read_frame(r)
            if kind == execd.STDIN and not payload:
                w.write(frame(execd.EXIT, call_id, b'{"code": 0}'))
                return
            if not received:  # before any ack, so the upload can't have finished
                w.write(
                    b"".join(frame(execd.RESUMED, call_id, resumed) for _ in range(64))
                )
            received += len(payload) if kind == execd.STDIN else 0
            put = json.dumps({"stdin": received}).encode()
            w.write(frame(execd.STDIN_ACK, call_id, put))

    await daemons.serve(floods_resumed)

    await daemons.client().exec(["cat"], stdin, None, {}, None, 30)

    assert received == len(stdin)


async def test_concurrent_sends_on_a_stream_stay_whole(
    daemons: Daemons, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(execd, "STDIN_WINDOW", 1 << 30)  # only the socket holds sends
    size = 16 << 20  # more than the socket buffers, so the first send waits partway
    received = bytearray()
    go = asyncio.Event()

    async def records_stdin(r: asyncio.StreamReader, w: asyncio.StreamWriter) -> None:
        await read_frame(r)  # START
        await go.wait()  # unread, the sends back up
        while len(received) < 2 * size:
            kind, _, payload = await read_frame(r)
            if kind == execd.STDIN:
                received.extend(payload)

    await daemons.serve(records_stdin)
    stream = await daemons.client().open_stream(["cat"], None)

    sends = asyncio.gather(stream.send(b"A" * size), stream.send(b"B" * size))
    for _ in range(10):  # both sends under way
        await asyncio.sleep(0)
    go.set()
    await asyncio.wait_for(sends, 30)
    await until(lambda: len(received) == 2 * size)

    assert bytes(received) in (b"A" * size + b"B" * size, b"B" * size + b"A" * size)


async def test_a_stream_cancelled_as_it_starts_is_killed(
    tls_daemon: TlsDaemon,
) -> None:
    got: list[int] = []
    reads = asyncio.Event()

    async def records(r: asyncio.StreamReader, w: asyncio.StreamWriter) -> None:
        await reads.wait()  # unread, the START backs up: its write waits
        while True:
            got.append((await read_frame(r))[0])

    client = await tls_daemon(records)
    link = await client._get()
    scope = anyio.CancelScope()
    argv = ["echo", "x" * (16 << 20)]  # more than the socket buffers hold

    async def opens() -> None:
        with scope:
            await client.open_stream(argv, None)

    opening = asyncio.ensure_future(opens())
    unsent = link.pipe._writer.transport.get_write_buffer_size  # type: ignore[union-attr]
    await until(lambda: unsent() > 0)  # its START is on its way
    scope.cancel()  # anyio cancels again at each await, unlike asyncio
    await asyncio.wait_for(opening, 30)
    reads.set()
    await until(lambda: execd.RELEASE in got)

    assert scope.cancelled_caught
    assert got == [execd.START, execd.KILL, execd.RELEASE]


async def test_a_call_cancelled_while_another_writes_is_killed(
    daemons: Daemons,
) -> None:
    got: list[int] = []

    async def records(r: asyncio.StreamReader, w: asyncio.StreamWriter) -> None:
        while True:
            got.append((await read_frame(r))[0])

    await daemons.serve(records)
    client = daemons.client()
    scope = anyio.CancelScope()

    async def call() -> None:
        with scope:
            await client.exec(["sleep", "60"], None, None, {}, None, None)

    task = asyncio.create_task(call())
    await until(lambda: execd.START in got)
    link = client._link
    assert link is not None
    async with link._wlock:  # another call's write
        scope.cancel()  # anyio cancels again at each await, unlike asyncio
        await asyncio.wait_for(task, 30)  # it ends at once: its last frames wait
    await until(lambda: execd.RELEASE in got)

    assert execd.KILL in got
    assert not link.calls


async def test_a_call_cancelled_as_it_exits_is_released(daemons: Daemons) -> None:
    got: list[int] = []
    go = asyncio.Event()

    async def exits(r: asyncio.StreamReader, w: asyncio.StreamWriter) -> None:
        while True:
            kind, call_id, _ = await read_frame(r)
            got.append(kind)
            if kind == execd.START:
                await go.wait()
                w.write(frame(execd.EXIT, call_id, b'{"code": 0}'))

    await daemons.serve(exits)
    client = daemons.client()
    scope = anyio.CancelScope()

    async def call() -> None:
        with scope:
            await client.exec(["true"], None, None, {}, None, None)

    task = asyncio.create_task(call())
    await until(lambda: execd.START in got)
    link = client._link
    assert link is not None
    async with link._wlock:  # another call's write
        go.set()
        await until(lambda: waiting(link))  # it has exited: its RELEASE waits
        scope.cancel()
        await asyncio.wait_for(task, 30)
    await until(lambda: execd.RELEASE in got)

    assert execd.KILL not in got  # it exited: a KILL would end what it left running


async def test_a_call_left_as_its_upload_writes_sends_no_more_stdin(
    tls_daemon: TlsDaemon,
) -> None:
    """Regression: before Python 3.12 the upload's cancel was lost, and it sent on."""
    got: list[int] = []

    async def leaves(r: asyncio.StreamReader, w: asyncio.StreamWriter) -> None:
        _, first, _ = await read_frame(r)  # the command that opens the connection
        w.write(frame(execd.EXIT, first, b'{"code": 0}'))
        while True:
            kind, call_id, _ = await read_frame(r)
            if call_id not in (first, 0):  # the call's own frames
                got.append(kind)
            if kind == execd.STDIN:
                call.cancel()

    client = await tls_daemon(leaves)
    opens = client.exec(["true"], None, None, {}, None, None)
    await asyncio.wait_for(opens, 30)  # only bounds a hang
    link = client._link
    assert link is not None
    stdin = b"x" * execd.STDIN_WINDOW
    # Room for it all: each megabyte's write returns at once, where the cancel was lost.
    link.pipe._writer.transport.set_write_buffer_limits(high=2 * len(stdin))  # type: ignore[union-attr]
    call = asyncio.ensure_future(client.exec(["cat"], stdin, None, {}, None, 60))
    await until(lambda: execd.RELEASE in got)

    assert execd.STDIN not in got[got.index(execd.KILL) :]
    done, _ = await asyncio.wait({call}, timeout=30)  # only bounds a hang
    assert done, "the call never ended"
    with pytest.raises(asyncio.CancelledError):
        call.result()


async def test_a_stream_closed_while_cancelled_is_killed(daemons: Daemons) -> None:
    got: list[int] = []

    async def records(r: asyncio.StreamReader, w: asyncio.StreamWriter) -> None:
        while True:
            kind, call_id, _ = await read_frame(r)
            if call_id:  # the stream's own: a PING has no call
                got.append(kind)

    await daemons.serve(records)
    opening = daemons.client().open_stream(["cat"], None)
    stream = await asyncio.wait_for(opening, 30)  # only bounds a hang

    async with stream._link._wlock:  # another call's write
        with anyio.CancelScope() as scope:
            scope.cancel()
            await stream.aclose()
    await until(lambda: execd.RELEASE in got)

    assert got == [execd.START, execd.KILL, execd.RELEASE]  # and no EOF before


async def test_stray_frames_end_the_connection(daemons: Daemons) -> None:
    async def pongs(r: asyncio.StreamReader, w: asyncio.StreamWriter) -> None:
        w.write(frame(execd.PONG, 0) * (execd.MAX_STRAY + 1))
        await r.read()

    await daemons.serve(pongs)
    stream = await daemons.client().open_stream(["cat"], None)

    await until(lambda: stream._link.closed)


async def test_stray_bytes_end_the_connection(
    daemons: Daemons, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(execd, "MAX_STRAY_BYTES", execd.CHUNK)

    async def big_strays(r: asyncio.StreamReader, w: asyncio.StreamWriter) -> None:
        await read_frame(r)  # START
        w.write(frame(execd.STDOUT, 12345, b"x" * execd.CHUNK) * 2)  # nobody's call
        await r.read()

    await daemons.serve(big_strays)
    stream = await daemons.client().open_stream(["cat"], None)

    await until(lambda: stream._link.closed)


@pytest.mark.parametrize(
    ("kind", "payload"),
    [
        (execd.STDOUT, b""),  # nothing new
        (99, b""),  # no such kind
        (execd.OK, b""),
        (execd.RESUMED, b'{"stdin": 0, "eof": false, "put": 0}'),  # unasked
    ],
)
async def test_frames_a_call_does_not_use_count_as_stray(
    daemons: Daemons, monkeypatch: pytest.MonkeyPatch, kind: int, payload: bytes
) -> None:
    monkeypatch.setattr(execd, "MAX_STRAY", 100)

    async def floods(r: asyncio.StreamReader, w: asyncio.StreamWriter) -> None:
        _, call_id, _ = await read_frame(r)  # START
        w.write(frame(kind, call_id, payload) * (execd.MAX_STRAY + 1))
        await r.read()

    await daemons.serve(floods)
    stream = await daemons.client().open_stream(["cat"], None)

    await until(lambda: stream._link.closed)


@pytest.mark.parametrize(
    ("limit", "value", "payload"),
    [("PACE_FRAMES", 50, b"x"), ("PACE_BYTES", 50 << 10, b"x" * (1 << 10))],
    ids=["frames", "bytes"],
)
async def test_what_a_pod_delivers_is_paced(
    daemons: Daemons,
    clock: types.SimpleNamespace,
    monkeypatch: pytest.MonkeyPatch,
    limit: str,
    value: int,
    payload: bytes,
) -> None:
    monkeypatch.setattr(execd, limit, value)

    async def floods(r: asyncio.StreamReader, w: asyncio.StreamWriter) -> None:
        _, call_id, _ = await read_frame(r)  # START
        w.write(frame(execd.STDOUT, call_id, payload) * 150)
        w.write(frame(execd.EXIT, call_id, b'{"code": 0}'))
        await r.read()

    await daemons.serve(floods)

    call = daemons.client().exec(["yes"], None, None, {}, None, None)
    await asyncio.wait_for(call, 30)

    # Three times the second's allowance: twice, reading waits for the next second.
    assert clock.now == 2.0


async def test_calls_that_each_print_and_exit_are_not_paced_as_a_flood(
    daemons: Daemons, clock: types.SimpleNamespace, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Regression: 32 callers on a pod reached the frame cap, and its calls stalled."""
    monkeypatch.setattr(execd, "PACE_FRAMES", 50)

    async def answers(r: asyncio.StreamReader, w: asyncio.StreamWriter) -> None:
        while True:
            kind, call_id, payload = await read_frame(r)
            if kind == execd.STDIN and payload:
                w.write(frame(execd.STDIN_ACK, call_id, b'{"stdin": 1}'))
            elif kind == execd.STDIN:  # stdin's end: the command prints and exits
                w.write(frame(execd.STDOUT, call_id, b"out\n"))
                w.write(frame(execd.STDERR, call_id, b"err\n"))
                w.write(frame(execd.EXIT, call_id, b'{"code": 0}'))

    await daemons.serve(answers)
    client = daemons.client()
    calls = [client.exec(["sh"], b"x", None, {}, None, None) for _ in range(60)]

    results = await asyncio.wait_for(asyncio.gather(*calls), 30)

    # Four frames a call, several times the cap, and no read waited for the next second.
    assert clock.now == 0.0
    assert {(r.stdout, r.stderr) for r in results} == {("out\n", "err\n")}


async def test_the_stray_count_spans_reconnects(
    daemons: Daemons, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(execd, "MAX_STRAY", 100)

    async def pongs(r: asyncio.StreamReader, w: asyncio.StreamWriter) -> None:
        w.write(frame(execd.PONG, 0) * 60)
        await r.read()

    await daemons.serve(pongs)
    client = daemons.client()
    first = await client._get()
    await until(lambda: client._strays.frames == 60)
    await first.close()

    second = await asyncio.wait_for(client._get(first), 30)

    await until(lambda: second.closed)  # 120 in one interval, over two connections


async def test_a_daemon_that_drops_each_connection_is_reconnected_with_backoff(
    daemons: Daemons, clock: types.SimpleNamespace
) -> None:
    connections = 0

    async def drops(r: asyncio.StreamReader, w: asyncio.StreamWriter) -> None:
        nonlocal connections
        connections += 1
        await read_frame(r)  # START, then RESUME
        w.close()

    await daemons.serve(drops)

    with pytest.raises(TimeoutError, match="Command timed out"):
        call = daemons.client().exec(["true"], None, None, {}, None, 1)
        await asyncio.wait_for(call, 30)  # only bounds a hang

    # Paced: a handful before the waits between them pass the second.
    assert connections <= 10


async def test_an_opened_connection_is_the_clients_at_once(daemons: Daemons) -> None:
    async def idle(r: asyncio.StreamReader, w: asyncio.StreamWriter) -> None:
        await r.read()

    await daemons.serve(idle)
    client = daemons.client()

    link = await client._open(time.monotonic() + 30)

    # Before its waiters wake: a caller arriving now must not open a second one.
    assert client._link is link


async def test_only_one_fingerprint_line_starts_execd(
    cluster: Cluster, monkeypatch: pytest.MonkeyPatch
) -> None:
    printed = b"0" * 64 + b" c\n"

    class Execute:
        def __init__(self, info: object) -> None:
            pass

        def run_argv(self, cmd: list[str]) -> tuple[int, bytes, bytes]:
            return 0, printed, b""

    monkeypatch.setattr(pod_module, "ExecuteOperation", Execute)
    pod = pod_module.Pod("p", "ns", None, "default", "u", 0, "raise")
    assert (await pod._start_execd(False)).fingerprint == "0" * 64

    printed = b"1" * 64 + b" " + b"c" * 4031  # both, but cut at run_argv's 4 KiB
    with pytest.raises(error.PodError, match="execd did not start"):
        await pod._start_execd(False)


def execd_starts(
    monkeypatch: pytest.MonkeyPatch, meanwhile: collections.abc.Callable[[], None]
) -> None:
    """Stand in for the exec that starts execd: meanwhile() runs as it does."""
    running = False

    class Execute:
        def __init__(self, info: object) -> None:
            pass

        def run_argv(self, cmd: list[str]) -> tuple[int, bytes, bytes]:
            nonlocal running
            if running and "--replace" not in cmd:  # as execd finds its port taken
                return 2, b"", b"listen tcp :14601: bind: address already in use\n"
            running = True
            meanwhile()
            return 0, b"0" * 64 + b" c\n", b""

    monkeypatch.setattr(pod_module, "ExecuteOperation", Execute)


async def test_execd_started_in_a_restarted_container_is_refused_in_raise_mode(
    cluster: Cluster, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Regression: a container that restarted as execd started served the sample."""
    execd_starts(monkeypatch, lambda: setattr(cluster, "restarts", 1))
    pod = pod_module.Pod("p", "ns", None, "default", "u", 0, "raise")

    with pytest.raises(error.ContainerRestartedError):
        await pod._start_execd(False)


async def test_a_restart_kubernetes_shows_after_execd_started_is_still_found(
    tls_daemon: TlsDaemon, cluster: Cluster, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Regression: over execd no later operation read the pod: the sample ran on."""
    starts = 0

    async def exits(r: asyncio.StreamReader, w: asyncio.StreamWriter) -> None:
        nonlocal starts
        while True:
            kind, call_id, _ = await read_frame(r)
            if kind == execd.START:
                starts += 1
                w.write(frame(execd.EXIT, call_id, b'{"code": 0}'))

    execd_starts(monkeypatch, lambda: None)
    pod = pod_module.Pod("p", "ns", None, "default", "u", 0, "raise")
    await pod._start_execd(False)  # again, in a container its checks read as the first
    pod._execd = await tls_daemon(exits)
    cluster.restarts = 1  # only now does Kubernetes show the restart

    with pytest.raises(error.ContainerRestartedError):
        await pod.exec(["true"], None, None, {}, None, None)
    assert starts == 0


async def test_a_check_that_fails_as_execd_has_just_restarted_fails_its_operation(
    tls_daemon: TlsDaemon, cluster: Cluster, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Only a late check's failed read is let pass: here it could hide a restart."""
    starts = 0

    async def exits(r: asyncio.StreamReader, w: asyncio.StreamWriter) -> None:
        nonlocal starts
        while True:
            kind, call_id, _ = await read_frame(r)
            if kind == execd.START:
                starts += 1
                w.write(frame(execd.EXIT, call_id, b'{"code": 0}'))

    monkeypatch.setattr(pod_module, "time", types.SimpleNamespace(monotonic=lambda: 0))
    execd_starts(monkeypatch, lambda: None)
    pod = pod_module.Pod("p", "ns", None, "default", "u", 0, "raise")
    await pod._start_execd(False)  # execd had died: perhaps with its container
    pod._execd = await tls_daemon(exits)
    cluster.unavailable = True  # the next read of the pod fails

    with pytest.raises(kubernetes.client.exceptions.ApiException):
        await asyncio.wait_for(pod.exec(["true"], None, None, {}, None, None), 30)
    assert starts == 0


async def test_a_restart_shown_after_a_start_that_lost_its_key_is_still_found(
    tls_daemon: TlsDaemon, cluster: Cluster, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Regression: the start replacing a daemon a failed pod read lost was unchecked."""
    starts = 0
    read_fails = iter([True])

    async def exits(r: asyncio.StreamReader, w: asyncio.StreamWriter) -> None:
        nonlocal starts
        while True:
            kind, call_id, _ = await read_frame(r)
            if kind == execd.START:
                starts += 1
                w.write(frame(execd.EXIT, call_id, b'{"code": 0}'))

    execd_starts(
        monkeypatch, lambda: setattr(cluster, "unavailable", next(read_fails, False))
    )
    pod = pod_module.Pod("p", "ns", None, "default", "u", 0, "raise")
    with pytest.raises(kubernetes.client.exceptions.ApiException):
        await pod._start_execd(False)  # execd had died: perhaps with its container
    await pod._start_execd(True)  # the client replaces the daemon whose key that lost
    pod._execd = await tls_daemon(exits)
    cluster.restarts = 1  # only now does Kubernetes show the restart

    with pytest.raises(error.ContainerRestartedError):
        await pod.exec(["true"], None, None, {}, None, None)
    assert starts == 0


async def test_a_restart_shown_late_is_found_though_no_operation_ran_meanwhile(
    tls_daemon: TlsDaemon, cluster: Cluster, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Regression: only operations in the 30 s after a restart of execd read the pod."""
    starts = 0
    now = 0.0

    async def exits(r: asyncio.StreamReader, w: asyncio.StreamWriter) -> None:
        nonlocal starts
        while True:
            kind, call_id, _ = await read_frame(r)
            if kind == execd.START:
                starts += 1
                w.write(frame(execd.EXIT, call_id, b'{"code": 0}'))

    monkeypatch.setattr(
        pod_module, "time", types.SimpleNamespace(monotonic=lambda: now)
    )
    execd_starts(monkeypatch, lambda: None)
    pod = pod_module.Pod("p", "ns", None, "default", "u", 0, "raise")
    await pod._start_execd(True)  # a first start, in a container that had restarted
    pod._execd = await tls_daemon(exits)
    cluster.restarts = 1  # only now does Kubernetes show the restart
    now = pod_module.RESTART_SHOWN_WITHIN  # and nothing ran in the meantime

    with pytest.raises(error.ContainerRestartedError):
        await pod.exec(["true"], None, None, {}, None, None)
    assert starts == 0


async def test_after_its_late_check_a_pod_is_read_again_only_30_s_later(
    tls_daemon: TlsDaemon, cluster: Cluster, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Regression: a pod deleted and replaced, but not stopped, served its sample on."""
    starts = 0
    now = 0.0

    async def exits(r: asyncio.StreamReader, w: asyncio.StreamWriter) -> None:
        nonlocal starts
        while True:
            kind, call_id, _ = await read_frame(r)
            if kind == execd.START:
                starts += 1
                w.write(frame(execd.EXIT, call_id, b'{"code": 0}'))

    monkeypatch.setattr(
        pod_module, "time", types.SimpleNamespace(monotonic=lambda: now)
    )
    execd_starts(monkeypatch, lambda: None)
    pod = pod_module.Pod("p", "ns", None, "default", "u", 0, "raise")
    await pod._start_execd(True)
    pod._execd = await tls_daemon(exits)
    now = pod_module.RESTART_SHOWN_WITHIN
    # The late check: no restart.
    await asyncio.wait_for(pod.exec(["true"], None, None, {}, None, None), 30)
    read = cluster.reads

    await asyncio.wait_for(pod.exec(["true"], None, None, {}, None, None), 30)

    # A read of the pod for each operation is what execd takes off the API server.
    assert cluster.reads == read
    cluster.uid = "v"  # Kubernetes shows its replacement; execd still answers
    now += pod_module.RESTART_SHOWN_WITHIN

    with pytest.raises(error.PodReplacedError):
        await asyncio.wait_for(pod.exec(["true"], None, None, {}, None, None), 30)
    assert starts == 2


async def test_a_late_check_costs_the_operations_around_it_no_more_than_its_wait(
    tls_daemon: TlsDaemon, cluster: Cluster, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Regressions: it failed or held its operation, was made twice, or not at all."""
    starts = 0
    now = 0.0

    async def exits(r: asyncio.StreamReader, w: asyncio.StreamWriter) -> None:
        nonlocal starts
        while True:
            kind, call_id, _ = await read_frame(r)
            if kind == execd.START:
                starts += 1
                w.write(frame(execd.EXIT, call_id, b'{"code": 0}'))

    def run() -> asyncio.Task[inspect_ai.util.ExecResult[str]]:
        operation = pod.exec(["true"], None, None, {}, None, None)
        return asyncio.ensure_future(asyncio.wait_for(operation, 30))

    monkeypatch.setattr(
        pod_module, "time", types.SimpleNamespace(monotonic=lambda: now)
    )
    execd_starts(monkeypatch, lambda: None)
    pod = pod_module.Pod("p", "ns", None, "default", "u", 0, "raise")
    await pod._start_execd(True)
    pod._execd = await tls_daemon(exits)
    read = cluster.reads
    now = pod_module.RESTART_SHOWN_WITHIN
    cluster.unavailable = True  # the next read of the pod fails
    await run()
    await run()
    # The first one's read failed and failed nothing; the second made no read.
    assert (cluster.reads, starts) == (read + 1, 2)
    now += pod_module.RESTART_SHOWN_WITHIN
    cluster.held = threading.Event()  # the next reads are answered once it is set
    left = run()
    await until(lambda: cluster.reads == read + 2)
    left.cancel()  # its read is still out: the check is owed as before
    with pytest.raises(asyncio.CancelledError):
        await left
    beside = [run(), run()]
    await until(lambda: cluster.reads == read + 4 or starts > 2)
    # Each waits for a read of its own: one already out is not taken for an answer.
    assert (cluster.reads, starts) == (read + 4, 2)
    cluster.held.set()
    await asyncio.gather(*beside)
    now += pod_module.RESTART_SHOWN_WITHIN
    monkeypatch.setattr(pod_module, "LATE_READ_WITHIN", 0.01)
    cluster.held = threading.Event()  # and this time it is not

    await run()

    assert starts == 5


async def test_execd_started_in_a_replacement_pod_is_reached_at_its_address(
    cluster: Cluster, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Regression: in warn mode the client dialed the address of the pod replaced."""
    execd_starts(monkeypatch, lambda: vars(cluster).update(uid="v", ip="10.0.0.2"))
    pod = pod_module.Pod("p", "ns", None, "default", "u", 0, "warn")

    daemon = await asyncio.wait_for(pod._start_execd(False), 30)

    assert (daemon.ip, daemon.pod) == ("10.0.0.2", "v")


def runs_in(pod: str, ran: list[str]) -> Handler:
    """A stand-in for a pod's execd, which notes each connection and command it gets."""

    async def runs(r: asyncio.StreamReader, w: asyncio.StreamWriter) -> None:
        ran.append(f"{pod} dialed")
        while True:
            kind, call_id, payload = await read_frame(r)
            if kind == execd.START:
                ran.append(pod)
                if json.loads(payload)["argv"] == ["true"]:  # any other runs on
                    w.write(frame(execd.EXIT, call_id, b'{"code": 0}'))

    return runs


async def test_a_replacement_found_in_warn_mode_moves_operations_to_its_execd(
    tls: tuple[ssl.SSLContext, str], tls_daemon: TlsDaemon, cluster: Cluster
) -> None:
    """Regression: commands went on to a replaced pod's execd while that pod ran."""
    ran: list[str] = []
    started: list[str] = []

    async def start(replace: bool) -> execd.Daemon:
        started.append(cluster.uid)
        return execd.Daemon("127.0.0.1", tls[1], b"key", cluster.uid)

    pod = pod_module.Pod("p", "ns", None, "default", "u", 0, "warn", execd="true")
    assert pod._execd is not None
    pod._execd._start = start
    with anyio.fail_after(30):  # only bounds a hang
        await tls_daemon(runs_in("replaced", ran))
        sleep = pod.exec(["sleep", "inf"], None, None, {}, None, None)
        running = asyncio.ensure_future(sleep)
        await until(lambda: ran == ["replaced dialed", "replaced"])
        # Force-deleted: Kubernetes shows the replacement, and the pod replaced runs on.
        await tls_daemon(runs_in("replacement", ran))
        cluster.uid = "v"

        await pod.check_for_pod_restart()
        with pytest.raises(error.ExecdStoppedError):  # and it is not run again
            await running
        await pod.exec(["true"], None, None, {}, None, None)
        await pod.check_for_pod_restart()  # nothing new: the replacement's execd stays
        await pod.exec(["true"], None, None, {}, None, None)

    assert started == ["u", "v"]
    assert ran[2:] == ["replacement dialed", "replacement", "replacement"]


async def test_a_command_goes_to_the_replacement_though_no_check_left_the_old_pod(
    tls: tuple[ssl.SSLContext, str], tls_daemon: TlsDaemon
) -> None:
    """Regression: a check cancelled as it found the replacement left the old in use."""
    ran: list[str] = []
    pod = "u"

    async def start(replace: bool) -> execd.Daemon:
        return execd.Daemon("127.0.0.1", tls[1], b"key", pod)

    client = execd.ExecdClient(start, lambda: pod)
    with anyio.fail_after(30):  # only bounds a hang
        await tls_daemon(runs_in("replaced", ran))
        await client.exec(["true"], None, None, {}, None, None)
        await tls_daemon(runs_in("replacement", ran))
        pod = "v"

        await client.exec(["true"], None, None, {}, None, None)

    assert ran[2:] == ["replacement dialed", "replacement"]


async def test_a_command_waiting_its_turn_is_not_sent_to_a_pod_replaced_meanwhile(
    tls: tuple[ssl.SSLContext, str], tls_daemon: TlsDaemon
) -> None:
    """Regression: a command queued as a check found the replacement ran in the old."""
    ran: list[str] = []
    pod = "u"

    async def start(replace: bool) -> execd.Daemon:
        return execd.Daemon("127.0.0.1", tls[1], b"key", pod)

    client = execd.ExecdClient(start, lambda: pod)
    with anyio.fail_after(30):  # only bounds a hang
        await tls_daemon(runs_in("replaced", ran))
        sleep = client.exec(["sleep", "inf"], None, None, {}, None, None)
        running = asyncio.ensure_future(sleep)
        await until(lambda: ran == ["replaced dialed", "replaced"])
        link = await client._get()
        async with link._wlock:  # another call's write
            call = client.exec(["true"], None, None, {}, None, None)
            queued = asyncio.ensure_future(call)
            await until(lambda: len(link.calls) == 2)  # it waits to send its START
            await tls_daemon(runs_in("replacement", ran))
            pod = "v"

        with pytest.raises(execd.NotSent):  # nothing ran: the provider sends it again
            await queued
        with pytest.raises(error.ExecdStoppedError):  # its connection went with that
            await running

    assert ran == ["replaced dialed", "replaced", "replacement dialed"]


async def test_a_command_is_not_sent_to_a_pod_replaced_in_the_turn_before_its_write(
    daemons: Daemons, timers: None
) -> None:
    """Regression: its pod was checked a loop turn before its START was written."""
    pod = "u"

    async def runs(r: asyncio.StreamReader, w: asyncio.StreamWriter) -> None:
        while True:
            kind, call_id, _ = await read_frame(r)
            if kind == execd.START:
                w.write(frame(execd.EXIT, call_id, b'{"code": 0}'))

    def replace() -> None:
        nonlocal pod
        pod = "v"

    await daemons.serve(runs, pod="u")
    client = daemons.client(lambda: pod)
    link = await client._get()
    async with link._wlock:  # another call's write
        call = client.exec(["true"], None, None, {}, None, None)
        queued = asyncio.ensure_future(call)
        await until(lambda: link.bulk.locked())  # its START waits
    asyncio.get_running_loop().call_soon(replace)  # after its turn has come

    with pytest.raises(execd.NotSent):  # nothing ran: the provider sends it again
        await asyncio.wait_for(queued, 30)  # only bounds a hang
    assert starts_written(client) == 0


async def test_a_command_waiting_its_turn_is_not_sent_once_a_restart_is_kept(
    daemons: Daemons, cluster: Cluster, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Regression: in "raise" mode commands ran, and ran on, in a pod found replaced."""
    starts = 0

    async def runs(r: asyncio.StreamReader, w: asyncio.StreamWriter) -> None:
        nonlocal starts
        while True:  # what is started runs on
            starts += (await read_frame(r))[0] == execd.START

    await daemons.serve(runs, pod="u")
    # The pod's own client, with the stand-in for the daemon it starts.
    monkeypatch.setattr(pod_module, "ExecdClient", lambda _, pod: daemons.client(pod))
    pod = pod_module.Pod("p", "ns", None, "default", "u", 0, "raise", execd="true")
    call = pod.exec(["sleep", "inf"], None, None, {}, None, None)
    running = asyncio.ensure_future(call)
    await until(lambda: starts == 1)
    assert pod._execd is not None
    link = await pod._execd._get()
    async with link._wlock:  # another call's write
        call = pod.exec(["true"], None, None, {}, None, None)
        queued = asyncio.ensure_future(call)
        await until(lambda: link.bulk.locked())  # its START waits
        cluster.uid = "v"
        with pytest.raises(error.PodReplacedError):
            await pod.check_for_pod_restart()
        assert link.closed  # by the check: the command running there ends with it

    for ended in running, queued:
        with pytest.raises(error.PodReplacedError):
            await asyncio.wait_for(ended, 30)  # only bounds a hang
    assert starts == 1


async def test_a_connection_opened_as_its_pod_is_replaced_is_not_used(
    tls: tuple[ssl.SSLContext, str],
    tls_daemon: TlsDaemon,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Regression: a connection opened to a replaced pod was kept: commands failed."""
    ran: list[str] = []
    pod = "u"
    asked, replaced = asyncio.Event(), asyncio.Event()

    async def answers_once_replaced(
        r: asyncio.StreamReader, w: asyncio.StreamWriter
    ) -> None:
        await read_frame(r)  # AUTH
        asked.set()
        await replaced.wait()
        w.write(frame(execd.OK, 0))
        await runs_in("replaced", ran)(r, w)

    async def start(replace: bool) -> execd.Daemon:
        return execd.Daemon("127.0.0.1", tls[1], b"key", pod)

    client = execd.ExecdClient(start, lambda: pod)
    listen = asyncio.start_server(answers_once_replaced, "127.0.0.1", 0, ssl=tls[0])
    with anyio.fail_after(30):  # only bounds a hang
        async with await listen as old:
            monkeypatch.setattr(execd, "EXECD_PORT", old.sockets[0].getsockname()[1])
            call = client.exec(["true"], None, None, {}, None, None)
            running = asyncio.ensure_future(call)
            await asked.wait()
            await tls_daemon(runs_in("replacement", ran))
            pod = "v"

            replaced.set()
            await running

    assert ran == ["replaced dialed", "replacement dialed", "replacement"]


async def test_execd_lost_to_a_failed_pod_read_is_replaced_at_the_next_start(
    cluster: Cluster, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Regression: in warn mode its key was lost, and its port stayed taken."""
    fails = iter([True])
    execd_starts(
        monkeypatch, lambda: setattr(cluster, "unavailable", next(fails, False))
    )
    pod = pod_module.Pod("p", "ns", None, "default", "u", 0, "warn")
    with pytest.raises(kubernetes.client.exceptions.ApiException):
        await pod._start_execd(False)

    assert (await pod._start_execd(False)).ip == "10.0.0.1"


async def test_a_start_that_finds_execds_port_taken_says_a_daemon_runs(
    cluster: Cluster, monkeypatch: pytest.MonkeyPatch
) -> None:
    execd_starts(monkeypatch, lambda: None)
    pod = pod_module.Pod("p", "ns", None, "default", "u", 0, "warn")
    await pod._start_execd(False)

    with pytest.raises(execd.DaemonRunning):  # so its client keeps the one it has
        await pod._start_execd(False)


async def test_the_read_of_execds_address_uses_a_client_of_its_own_thread(
    cluster: Cluster, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Regression: the event loop's thread-local client was used on a worker thread."""
    made: list[int] = []
    used: list[int] = []

    class Api:
        def read_namespaced_pod(self, **kwargs: object) -> types.SimpleNamespace:
            used.append(threading.get_ident())
            return cluster.read_namespaced_pod(**kwargs)

    def client(_: object) -> Api:
        made.append(threading.get_ident())
        return Api()

    monkeypatch.setattr(pod_module, "k8s_client", client)
    execd_starts(monkeypatch, lambda: None)
    pod = pod_module.Pod("p", "ns", None, "default", "u", 0, "raise")

    await pod._start_execd(False)

    assert made == used != []


async def test_a_resume_resends_only_stdin_execd_has_not_written(
    daemons: Daemons,
) -> None:
    resent: list[bytes] = []
    connections = 0

    async def acks_then_resumes_below_zero(
        r: asyncio.StreamReader, w: asyncio.StreamWriter
    ) -> None:
        nonlocal connections
        connections += 1
        _, call_id, _ = await read_frame(r)  # START, then RESUME
        if connections == 1:
            while await read_frame(r) != (execd.STDIN, call_id, b""):  # stdin's end
                pass
            w.write(frame(execd.STDIN_ACK, call_id, b'{"stdin": 3}'))  # all written
            w.close()  # dropped, so the client resumes
            return
        got = {"stdin": -5, "eof": False, "put": 0}
        w.write(frame(execd.RESUMED, call_id, json.dumps(got).encode()))
        while not resent or resent[-1]:  # to the empty frame that closes stdin
            kind, _, payload = await read_frame(r)
            if kind == execd.STDIN:
                resent.append(payload)
        w.write(frame(execd.EXIT, call_id, b'{"code": 0}'))
        await r.read()

    await daemons.serve(acks_then_resumes_below_zero)

    await daemons.client().exec(["cat"], "abc", None, {}, None, 30)

    assert resent == [b""]


async def test_an_unknown_call_whose_stdin_execd_wrote_is_not_started_again(
    daemons: Daemons,
) -> None:
    starts = 0

    async def acks_then_forgets(
        r: asyncio.StreamReader, w: asyncio.StreamWriter
    ) -> None:
        nonlocal starts
        while True:
            kind, call_id, payload = await read_frame(r)
            if kind == execd.START:
                starts += 1
                if starts > 1:  # started again: answer, so the test ends
                    w.write(frame(execd.EXIT, call_id, b'{"code": 0}'))
            elif (kind, payload, starts) == (execd.STDIN, b"", 1):
                w.write(frame(execd.STDIN_ACK, call_id, b'{"stdin": 3}'))
                w.close()  # dropped, so the client resumes
                return
            elif kind == execd.RESUME:
                w.write(frame(execd.ERROR, call_id, b"unknown call"))

    await daemons.serve(acks_then_forgets)

    with pytest.raises(error.ExecdResultUnknownError):
        await daemons.client().exec(["cat"], "abc", None, {}, None, 30)
    assert starts == 1


async def test_an_unknown_call_whose_output_arrived_is_not_started_again(
    tls_daemon: TlsDaemon,
) -> None:
    starts = 0

    async def prints_then_forgets(
        r: asyncio.StreamReader, w: asyncio.StreamWriter
    ) -> None:
        nonlocal starts
        while True:
            kind, call_id, _ = await read_frame(r)
            if (kind, starts) == (execd.START, 0):
                starts += 1
                w.write(frame(execd.STDOUT, call_id, b"x" * execd.ACK_EVERY))
            elif kind == execd.START:  # started again: answer, so the test ends
                starts += 1
                w.write(frame(execd.EXIT, call_id, b'{"code": 0}'))
            elif kind == execd.ACK:  # the client has the output: now it is dropped
                w.close()
                return
            elif kind == execd.RESUME:
                w.write(frame(execd.ERROR, call_id, b"unknown call"))

    client = await tls_daemon(prints_then_forgets)

    with pytest.raises(error.ExecdResultUnknownError):
        call = client.exec(["touch", "/once"], None, None, {}, None, None)
        await asyncio.wait_for(call, 30)
    assert starts == 1


@pytest.mark.parametrize("kind", [execd.STDERR, execd.STDOUT])
async def test_a_file_write_stops_at_the_output_limit(
    daemons: Daemons, monkeypatch: pytest.MonkeyPatch, kind: int
) -> None:
    monkeypatch.setattr(execd.limits, "MAX_EXEC_OUTPUT_SIZE", 1024)

    async def chatters(r: asyncio.StreamReader, w: asyncio.StreamWriter) -> None:
        _, call_id, _ = await read_frame(r)  # START
        w.write(frame(kind, call_id, b"x" * 2048))  # past the limit, then done
        w.write(frame(execd.EXIT, call_id, b'{"code": 0}'))
        await r.read()

    await daemons.serve(chatters)

    with pytest.raises(inspect_ai.util.OutputLimitExceededError):
        await daemons.client().write_file(b"data", pathlib.Path("/tmp/f"))


@pytest.mark.parametrize("kind", [execd.STDERR, execd.STDOUT])
async def test_a_command_stops_at_the_output_limit(daemons: Daemons, kind: int) -> None:
    async def chatters(r: asyncio.StreamReader, w: asyncio.StreamWriter) -> None:
        _, call_id, _ = await read_frame(r)  # START
        left = execd.limits.MAX_EXEC_OUTPUT_SIZE + 1  # a byte past it, and no exit
        while left:
            w.write(frame(kind, call_id, b"x" * min(left, execd.ACK_EVERY)))
            left -= min(left, execd.ACK_EVERY)
            # Taken: the next may come. The last, past the limit, is not waited for.
            while left and (await read_frame(r))[0] != execd.ACK:
                pass
        await r.read()

    await daemons.serve(chatters)
    yes = daemons.client().exec(["yes"], None, None, {}, None, None)

    with pytest.raises(inspect_ai.util.OutputLimitExceededError):
        await asyncio.wait_for(yes, 30)  # only bounds a hang


@pytest.mark.parametrize(
    ("next_daemon", "raised"),
    [
        ("answers", error.ExecdStoppedError),
        ("answers too late", error.ExecdStoppedError),
        ("starts only once the pod is found", error.ExecdResultUnknownError),
    ],
)
async def test_a_file_is_not_read_again_once_its_daemon_is_gone(
    tls: tuple[ssl.SSLContext, str],
    monkeypatch: pytest.MonkeyPatch,
    clock: types.SimpleNamespace,
    next_daemon: str,
    raised: type[Exception],
) -> None:
    """Regression: it was read again, from the container that had replaced its own."""
    context, pin = tls
    servers: list[asyncio.Server] = []
    starts: list[int] = []
    attempts = 0

    async def daemon(r: asyncio.StreamReader, w: asyncio.StreamWriter) -> None:
        if len(servers) == 2 and next_daemon == "answers too late" and attempts == 1:
            return w.close()  # started, and not reached while the read reconnects
        await read_frame(r)  # AUTH
        w.write(frame(execd.OK, 0))
        while True:
            kind, call_id, _ = await read_frame(r)
            if kind == execd.START:
                starts.append(call_id)
                if len(starts) == 1:  # gone, as with its container: its port refuses
                    servers[0].close()
                    return w.close()
                w.write(frame(execd.EXIT, call_id, b'{"code": 0}'))

    async def start(replace: bool) -> execd.Daemon:
        if len(servers) == 2:
            raise execd.DaemonRunning("address already in use")
        if servers and attempts == 1 and next_daemon.startswith("starts only once"):
            raise kubernetes.client.exceptions.ApiException(status=404)
        server = await asyncio.start_server(daemon, "127.0.0.1", 0, ssl=context)
        servers.append(server)
        monkeypatch.setattr(execd, "EXECD_PORT", server.sockets[0].getsockname()[1])
        return execd.Daemon("127.0.0.1", pin, b"key")

    client = execd.ExecdClient(start)

    with pytest.raises(error.ExecdResultUnknownError) as stopped:
        async for attempt in _sandbox_environment._retry():  # the provider's own
            with attempt:
                attempts += 1
                read = client.read_file(pathlib.Path("/x"), io.BytesIO())
                await asyncio.wait_for(read, 30)  # only bounds a hang
    assert (type(stopped.value), len(starts)) == (raised, 1)
    for server in servers:
        server.close()


async def test_a_file_write_finds_mkdir_and_cat_off_the_path(
    tls_daemon: TlsDaemon, tmp_path: pathlib.Path
) -> None:
    """They run as the container's user."""
    started: list[list[str]] = []

    async def exits(r: asyncio.StreamReader, w: asyncio.StreamWriter) -> None:
        _, call_id, payload = await read_frame(r)  # START
        started.append(json.loads(payload)["argv"])
        w.write(frame(execd.EXIT, call_id, b'{"code": 0}'))
        await r.read()

    client = await tls_daemon(exits)
    ran, stubs, dst = tmp_path / "ran", tmp_path / "stubs", tmp_path / "new" / "dst"
    stubs.mkdir()
    for name in ("mkdir", "cat"):
        (stubs / name).write_text(f"#!/bin/sh\necho {name} >> {ran}\n")
        (stubs / name).chmod(0o755)
    await asyncio.wait_for(client.write_file(b"data", dst), 30)
    env = {**os.environ, "PATH": f"{stubs}:{os.environ['PATH']}"}

    subprocess.run(started[0], input=b"data", env=env, capture_output=True, timeout=30)

    assert not ran.exists()
    assert dst.read_bytes() == b"data"


async def test_a_daemon_lost_in_a_replacement_pod_is_replaced(
    tls: tuple[ssl.SSLContext, str], tls_daemon: TlsDaemon
) -> None:
    """Regression: in "warn" mode its port stayed taken, and every operation failed."""
    uid = "u"

    async def exits(r: asyncio.StreamReader, w: asyncio.StreamWriter) -> None:
        while True:
            kind, call_id, _ = await read_frame(r)
            if kind == execd.START:
                w.write(frame(execd.EXIT, call_id, b'{"code": 0}'))

    async def start(replace: bool) -> execd.Daemon:
        if uid == "v" and not replace:  # execd runs there: its start's answer was lost
            raise execd.DaemonRunning("bind: address already in use")
        return execd.Daemon("127.0.0.1", tls[1], b"key", uid)

    with anyio.fail_after(30):  # only bounds a hang
        await tls_daemon(exits)  # both pods' execd, at the one address
        client = execd.ExecdClient(start, lambda: uid)
        await client.exec(["true"], None, None, {}, None, None)
        uid = "v"
        await client.leave_replaced()

        # Not the RuntimeError of a port held by a process other than execd.
        await client.exec(["true"], None, None, {}, None, None)


async def test_a_port_held_at_the_first_start_says_so() -> None:
    async def held(replace: bool) -> execd.Daemon:
        raise execd.DaemonRunning("bind: address already in use")  # even with --replace

    with pytest.raises(RuntimeError, match="held by a process other than execd"):
        await execd.ExecdClient(held).exec(["true"], None, None, {}, None, 30)


async def test_stray_frames_are_counted_per_ping_interval(
    daemons: Daemons, clock: types.SimpleNamespace, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Only this fails where the count of stray frames never starts again."""
    monkeypatch.setattr(execd, "MAX_STRAY", 100)
    more = asyncio.Event()

    async def pongs_across_intervals(
        r: asyncio.StreamReader, w: asyncio.StreamWriter
    ) -> None:
        _, call_id, _ = await read_frame(r)  # START
        for said in (b"here", b"still here"):  # the count restarts with each interval
            w.write(frame(execd.PONG, 0) * execd.MAX_STRAY)
            w.write(frame(execd.STDOUT, call_id, said))  # read once they are counted
            await more.wait()
        await r.read()

    await daemons.serve(pongs_across_intervals)
    stream = await daemons.client().open_stream(["cat"], None)

    assert await asyncio.wait_for(stream.receive(), 30) == b"here"
    clock.now += 2 * execd.PING_EVERY
    more.set()
    assert await asyncio.wait_for(stream.receive(), 30) == b"still here"


async def test_only_execd_itself_reports_an_unknown_user(daemons: Daemons) -> None:
    async def answers(r: asyncio.StreamReader, w: asyncio.StreamWriter) -> None:
        while True:
            kind, call_id, payload = await read_frame(r)
            if kind != execd.START:
                continue
            w.write(frame(execd.STDERR, call_id, b"execd: unknown user nobody2\n"))
            if json.loads(payload)["user"]:  # execd couldn't start it
                status = b'{"code": 126, "error": "unknown user nobody2"}'
            else:  # a command printing the same
                status = b'{"code": 0}'
            w.write(frame(execd.EXIT, call_id, status))

    await daemons.serve(answers)
    client = daemons.client()

    assert (await client.exec(["sh"], None, None, {}, None, 30)).success
    with pytest.raises(RuntimeError, match="does not appear to exist"):
        await client.exec(["true"], None, None, {}, "nobody2", 30)


async def test_a_user_execd_cannot_become_warns_and_returns_the_failed_result(
    tls_daemon: TlsDaemon, caplog: pytest.LogCaptureFixture
) -> None:
    why = "cannot run as 0: execd is not root"

    async def refuses(r: asyncio.StreamReader, w: asyncio.StreamWriter) -> None:
        _, call_id, _ = await read_frame(r)  # START
        w.write(frame(execd.STDERR, call_id, f"execd: {why}\n".encode()))
        status = json.dumps({"code": 126, "error": why}).encode()
        w.write(frame(execd.EXIT, call_id, status))
        await r.read()

    client = await tls_daemon(refuses)

    with caplog.at_level("WARNING"):
        call = client.exec(["true"], None, None, {}, "root", None)
        result = await asyncio.wait_for(call, 30)

    # Inspect tries user="root" and falls back on a failed result, not an exception.
    assert (result.returncode, result.stderr) == (126, f"execd: {why}\n")
    assert "the container is not running as root" in caplog.text


@pytest.mark.parametrize(
    ("why", "raises"),
    [("cannot run as 0: execd is not root", False), ("unknown user 0", True)],
)
async def test_a_user_execd_cannot_run_as_is_told_with_only_the_end_of_stderr(
    tls_daemon: TlsDaemon, caplog: pytest.LogCaptureFixture, why: str, raises: bool
) -> None:
    """Regression: a stand-in for execd had 10 MiB logged by each call."""

    async def floods(r: asyncio.StreamReader, w: asyncio.StreamWriter) -> None:
        _, call_id, _ = await read_frame(r)  # START
        w.write(frame(execd.STDERR, call_id, b"x" * execd.CHUNK + b"the end\n"))
        status = json.dumps({"code": 126, "error": why}).encode()
        w.write(frame(execd.EXIT, call_id, status))
        await r.read()

    client = await tls_daemon(floods)
    call = client.exec(["true"], None, None, {}, "root", None)

    with caplog.at_level("WARNING"):
        if raises:
            with pytest.raises(RuntimeError) as unknown_user:
                await asyncio.wait_for(call, 30)
            told = str(unknown_user.value)
        else:
            await asyncio.wait_for(call, 30)
            told = caplog.text

    assert "the end" in told and len(told) < 8192


async def test_the_timeout_runs_from_the_start_of_the_command(
    daemons: Daemons, monkeypatch: pytest.MonkeyPatch
) -> None:
    timeouts = []

    async def exits(r: asyncio.StreamReader, w: asyncio.StreamWriter) -> None:
        _, call_id, payload = await read_frame(r)  # START
        timeouts.append(json.loads(payload)["timeout"])
        w.write(frame(execd.EXIT, call_id, b'{"code": 0}'))
        await r.read()

    await daemons.serve(exits)
    client = daemons.client()
    start = client._start

    now = [0.0]
    monkeypatch.setattr(execd, "time", types.SimpleNamespace(monotonic=lambda: now[0]))

    async def slow_start(replace: bool) -> execd.Daemon:
        now[0] += 1.5
        return await start(replace)

    client._start = slow_start

    assert (await client.exec(["true"], None, None, {}, None, 1)).success
    assert timeouts == [1]  # execd kills it then, even with no client connected


async def test_a_command_times_out_while_its_daemon_is_restarted(
    daemons: Daemons, clock: types.SimpleNamespace, timers: None
) -> None:
    first: asyncio.Server
    restarting = asyncio.Event()

    async def start(replace: bool) -> execd.Daemon:
        if daemons.unstarted:
            return daemons.unstarted.pop(0)
        restarting.set()  # the restart never finishes
        return await asyncio.get_running_loop().create_future()

    async def dies_after_start(
        r: asyncio.StreamReader, w: asyncio.StreamWriter
    ) -> None:
        await read_frame(r)  # START
        first.close()
        w.close()

    first = await daemons.serve(dies_after_start)
    client = execd.ExecdClient(start)
    call = asyncio.ensure_future(client.exec(["true"], None, None, {}, None, 9))
    await asyncio.wait_for(restarting.wait(), 30)  # only bounds a hang
    expired = clock.expired
    clock.now += 2000  # past our timer: execd is asked for again, within our wait
    await until(lambda: clock.expired > expired)
    clock.now += execd.KILL_WAIT  # which ends with execd still away

    with pytest.raises(TimeoutError, match="Command timed out"):
        await asyncio.wait_for(call, 30)  # only bounds a hang


async def test_stdin_acks_that_report_progress_keep_the_connection(
    daemons: Daemons, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(execd, "MAX_STRAY", 100)

    async def acks_each(r: asyncio.StreamReader, w: asyncio.StreamWriter) -> None:
        _, call_id, _ = await read_frame(r)  # START
        got = 0
        while True:
            kind, _, payload = await read_frame(r)
            if kind == execd.STDIN:
                got += len(payload)
                put = json.dumps({"stdin": got}).encode()
                w.write(frame(execd.STDIN_ACK, call_id, put))

    await daemons.serve(acks_each)
    stream = await daemons.client().open_stream(["cat"], None)
    for _ in range(execd.MAX_STRAY + 1):
        await stream.send(b"x")
    await until(lambda: stream._call.stdin_put == execd.MAX_STRAY + 1)

    assert not stream._link.closed


async def test_stdin_acks_beyond_what_was_sent_count_as_stray(
    daemons: Daemons, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(execd, "MAX_STRAY", 100)

    async def overclaims(r: asyncio.StreamReader, w: asyncio.StreamWriter) -> None:
        _, call_id, _ = await read_frame(r)  # START
        for put in range(1, execd.MAX_STRAY + 2):  # nothing was sent
            w.write(
                frame(execd.STDIN_ACK, call_id, json.dumps({"stdin": put}).encode())
            )
        await r.read()

    await daemons.serve(overclaims)
    stream = await daemons.client().open_stream(["cat"], None)

    await until(lambda: stream._link.closed)


async def test_a_stream_refuses_input_once_its_command_exits(daemons: Daemons) -> None:
    async def exits(r: asyncio.StreamReader, w: asyncio.StreamWriter) -> None:
        _, call_id, _ = await read_frame(r)  # START
        w.write(frame(execd.EXIT, call_id, b'{"code": 0}'))
        await r.read()

    await daemons.serve(exits)
    stream = await daemons.client().open_stream(["cat"], None)
    await until(lambda: stream._call.exited)

    with pytest.raises(anyio.BrokenResourceError):
        await stream.send(b"lost")


@pytest.mark.parametrize(
    ("kind", "payload", "end"),
    [
        (execd.EXIT, b'{"code": 0}', anyio.EndOfStream),
        (execd.ERROR, b"unknown user", anyio.BrokenResourceError),
    ],
    ids=["exit", "error"],
)
async def test_a_stream_ends_cleanly_only_when_its_command_exits(
    daemons: Daemons, kind: int, payload: bytes, end: type[Exception]
) -> None:
    async def ends(r: asyncio.StreamReader, w: asyncio.StreamWriter) -> None:
        _, call_id, _ = await read_frame(r)  # START
        w.write(frame(execd.STDOUT, call_id, b"last words"))
        w.write(frame(kind, call_id, payload))
        await r.read()

    await daemons.serve(ends)
    stream = await daemons.client().open_stream(["cat"], None)

    assert await asyncio.wait_for(stream.receive(), 30) == b"last words"
    with pytest.raises(end):
        await asyncio.wait_for(stream.receive(), 30)


async def test_unasked_unknown_call_errors_start_nothing_again(
    daemons: Daemons,
) -> None:
    starts = 0

    async def denies_every_call(
        r: asyncio.StreamReader, w: asyncio.StreamWriter
    ) -> None:
        nonlocal starts
        while True:
            kind, call_id, _ = await read_frame(r)
            if kind == execd.START:
                starts += 1
            w.write(frame(execd.ERROR, call_id, b"unknown call"))

    await daemons.serve(denies_every_call)

    with pytest.raises(error.ExecdResultUnknownError):
        await daemons.client().exec(["touch", "/once"], None, None, {}, None, 30)
    assert starts == 1


@pytest.mark.parametrize(
    "operation",
    [
        pytest.param(
            lambda c: c.exec(["touch", "/once"], None, None, {}, None, 30), id="exec"
        ),
        pytest.param(
            lambda c: c.write_file(b"x", pathlib.Path("/tmp/x")), id="write_file"
        ),
    ],
)
async def test_a_call_execd_abandoned_is_not_started_again(
    daemons: Daemons,
    operation: collections.abc.Callable[
        [execd.ExecdClient], collections.abc.Awaitable[object]
    ],
) -> None:
    """Regression: for a file operation it raised a PodError, which is retried."""
    starts = 0

    async def abandons(r: asyncio.StreamReader, w: asyncio.StreamWriter) -> None:
        nonlocal starts
        while True:
            kind, call_id, _ = await read_frame(r)
            if (kind, starts) == (execd.START, 0):
                starts += 1
                w.close()  # dropped, so the client resumes
                return
            elif kind == execd.START:  # started again: answer, so the test ends
                starts += 1
                w.write(frame(execd.EXIT, call_id, b'{"code": 0}'))
            elif kind == execd.RESUME:  # as execd answers for a call it gave up on
                w.write(frame(execd.ERROR, call_id, b"call abandoned"))

    await daemons.serve(abandons)

    with pytest.raises(error.ExecdResultUnknownError):
        await asyncio.wait_for(operation(daemons.client()), 30)
    assert starts == 1


async def test_pacing_lets_other_work_run() -> None:
    ran = asyncio.Event()
    asyncio.get_running_loop().call_soon(ran.set)

    await execd.Pace().take(1)

    assert ran.is_set()  # under its allowance too: a pass at a time


async def test_a_costly_pass_gives_way_to_a_timer_already_due() -> None:
    """Regression: three KeyUpdate passes ran before a task whose sleep had ended."""
    due = asyncio.Event()
    asyncio.get_running_loop().call_later(0, due.set)

    await execd.Pace().take(0, frames=0, tls=0.005)

    assert due.is_set()


def stub_pipe(
    fraction: float, reading: list[bool], pace: execd.Pace | None = None
) -> execd._Pipe:
    """A pipe whose peer sends that fraction of what each read takes."""

    async def read(n: int) -> bytes:
        assert reading[-1], "read while paused"
        return b"x" * int(n * fraction)

    transport = types.SimpleNamespace(
        resume_reading=lambda: reading.append(True),
        pause_reading=lambda: reading.append(False),
    )
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    return execd._Pipe(
        types.SimpleNamespace(read=read),  # type: ignore[arg-type]
        types.SimpleNamespace(transport=transport),  # type: ignore[arg-type]
        context,
        pace or execd.Pace(),
    )


async def test_a_trickle_of_short_reads_waits_its_turn(
    clock: types.SimpleNamespace,
) -> None:
    reading: list[bool] = []
    pipe = stub_pipe(0.5, reading)

    for _ in range(execd.SMALL_READS + 20):
        await pipe._raw()

    # Past the burst, about one a millisecond.
    assert 0.015 <= clock.now <= 0.02
    assert not reading[-1]  # between reads, bytes wait in the kernel


async def test_full_reads_spend_no_turns() -> None:
    pipe = stub_pipe(1.0, [])

    for _ in range(execd.SMALL_READS + 1):
        await pipe._raw()

    assert pipe._small_at == float("-inf")  # a stream at full speed doesn't wait


async def test_what_a_pass_delivers_pays_for_its_decryption(
    clock: types.SimpleNamespace,
) -> None:
    pace = execd.Pace()
    pipe = stub_pipe(1.0, [], pace)
    # One read's bytes, and less CPU than delivering them is excused.
    read, spent = execd.RAW_READ, 40e-6
    clock.cpu = lambda: spent

    # Cheaper than its credit, finishing a record begun before: nothing carried over.
    await pipe._charge(0.0, delivered=read, used=read // 2)
    await pipe._charge(0.0)  # that CPU again, for nothing delivered
    await pipe._charge(spent, used=read)  # no CPU, but a read of padding

    assert pace.tls == pytest.approx(spent + read * execd.TLS_PER_BYTE)


@pytest.fixture
def tls(tmp_path: pathlib.Path) -> tuple[ssl.SSLContext, str]:
    """A server's TLS context, with a self-signed certificate, and the pin for it."""
    if shutil.which("openssl") is None:
        pytest.skip("needs openssl")
    key, cert = tmp_path / "key.pem", tmp_path / "cert.pem"
    subprocess.run(
        ["openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt"]
        + ["ec_paramgen_curve:P-256", "-nodes", "-days", "1", "-subj", "/CN=x"]
        + ["-keyout", str(key), "-out", str(cert)],
        check=True,
        capture_output=True,
        timeout=30,
    )
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(cert, key)
    der = ssl.PEM_cert_to_DER_cert(cert.read_text())
    return context, hashlib.sha256(der).hexdigest()


@pytest.fixture
async def tls_daemon(
    tls: tuple[ssl.SSLContext, str], monkeypatch: pytest.MonkeyPatch
) -> collections.abc.AsyncGenerator[TlsDaemon, None]:
    """Serves a stand-in for execd over TLS; gives the client that pins it."""
    context, pin = tls
    servers: list[asyncio.Server] = []

    async def serve(handler: Handler) -> execd.ExecdClient:
        async def connection(r: asyncio.StreamReader, w: asyncio.StreamWriter) -> None:
            await read_frame(r)  # AUTH
            w.write(frame(execd.OK, 0))
            await handler(r, w)

        server = await asyncio.start_server(connection, "127.0.0.1", 0, ssl=context)
        servers.append(server)
        monkeypatch.setattr(execd, "EXECD_PORT", server.sockets[0].getsockname()[1])

        async def start(replace: bool) -> execd.Daemon:
            return execd.Daemon("127.0.0.1", pin, b"key")

        return execd.ExecdClient(start)

    yield serve
    for server in servers:
        server.close()


def test_a_daemons_key_stays_out_of_its_repr() -> None:
    # A traceback that shows locals, or a log of the daemon, would give the key away.
    assert "s3cret" not in repr(execd.Daemon("10.0.0.1", "f" * 64, b"s3cret"))


async def test_only_the_pinned_certificate_is_trusted(
    tls: tuple[ssl.SSLContext, str], monkeypatch: pytest.MonkeyPatch
) -> None:
    context, pin = tls
    server = await asyncio.start_server(lambda r, w: None, "127.0.0.1", 0, ssl=context)
    monkeypatch.setattr(execd, "EXECD_PORT", server.sockets[0].getsockname()[1])

    with pytest.raises(execd.NotOurDaemon):
        await execd._connect(execd.Daemon("127.0.0.1", "0" * 64, b"key"), execd.Pace())
    pipe = await execd._connect(execd.Daemon("127.0.0.1", pin, b"key"), execd.Pace())
    await pipe.close()
    server.close()


async def test_a_daemon_with_no_reachable_address_is_reached_through_its_stdio(
    tls: tuple[ssl.SSLContext, str],
) -> None:
    context, pin = tls
    closed = asyncio.Event()

    async def exits(r: asyncio.StreamReader, w: asyncio.StreamWriter) -> None:
        await read_frame(r)  # AUTH
        w.write(frame(execd.OK, 0))
        _, call_id, _ = await read_frame(r)  # START
        w.write(frame(execd.STDOUT, call_id, b"ran"))
        w.write(frame(execd.EXIT, call_id, b'{"code": 0}'))
        w.write(execd.HEADER.pack(execd.STDOUT, call_id, execd.MAX_FRAME + 1))
        if not await r.read():  # no frame of execd's: the client ends the connection
            closed.set()

    server = await asyncio.start_server(exits, "127.0.0.1", 0, ssl=context)

    async def start(replace: bool) -> execd.Daemon:
        address = server.sockets[0].getsockname()  # as `execd connect` joins a stdio
        return execd.Daemon("", pin, b"key", stdio=lambda: anyio.connect_tcp(*address))

    call = execd.ExecdClient(start).exec(["true"], None, None, {}, None, None)
    result = await asyncio.wait_for(call, 30)  # only bounds a hang

    assert result.stdout == "ran"
    await asyncio.wait_for(closed.wait(), 30)
    server.close()


async def test_writes_to_a_stdio_exec_go_a_message_at_a_time(
    clock: types.SimpleNamespace,
) -> None:
    """Regression: a message a write, of any size: AWS's guest agent reordered them."""
    sent: list[bytes] = []
    at: list[float] = []

    class Records(anyio.abc.ByteStream):
        """An exec's stdio that keeps each message written to it, and when."""

        async def send(self, item: bytes) -> None:
            sent.append(item)
            at.append(clock.now)

        async def receive(self, max_bytes: int = 65536) -> bytes:
            await asyncio.Event().wait()
            return b""

        async def send_eof(self) -> None:
            pass

        async def aclose(self) -> None:
            pass

    stdio = execd._Stdio(Records())
    stdio.write(b"first")
    await until(lambda: sent == [b"first"])
    stdio.write(b"while it ")
    stdio.write(b"is on its way")
    await until(lambda: len(sent) == 2)
    upload = bytes(range(251)) * 612  # 150 KiB, and no two messages of it alike
    stdio.write(upload)
    with anyio.fail_after(30):
        await stdio.drain()  # in this task: a write waits here until most has gone
    assert len(upload) - sum(map(len, sent[2:])) <= 65536
    await until(lambda: sum(map(len, sent[2:])) == len(upload))
    stdio.abort()

    assert sent[1] == b"while it is on its way"
    assert b"".join(sent[2:]) == upload and max(map(len, sent)) <= 65536
    # On the fake clock: every message a millisecond or more after the one before.
    assert all(later - earlier >= 0.001 for earlier, later in zip(at, at[1:]))


async def test_a_turn_of_a_busy_loop_counts_toward_the_gap_between_messages(
    clock: types.SimpleNamespace, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Regression: each gap's timer took a busy loop up to three turns a message."""
    at: list[float] = []
    slept: list[float] = []
    sleep = execd.asyncio.sleep

    async def timed(seconds: float) -> None:
        slept.append(seconds)
        await sleep(seconds)

    monkeypatch.setattr(execd.asyncio, "sleep", timed)

    class Records(anyio.abc.ByteStream):
        """An exec's stdio that keeps when each message was written to it."""

        async def send(self, item: bytes) -> None:
            at.append(clock.now)

        async def receive(self, max_bytes: int = 65536) -> bytes:
            await asyncio.Event().wait()
            return b""

        async def send_eof(self) -> None:
            pass

        async def aclose(self) -> None:
            pass

    async def busy() -> None:
        while True:  # every turn of the loop lasts twice the gap
            clock.now += 2 * execd.MESSAGE_GAP
            await asyncio.sleep(0)

    others = asyncio.create_task(busy())
    stdio = execd._Stdio(Records())
    stdio.write(bytes(3 * execd.MESSAGE_SIZE))
    await until(lambda: len(at) == 3)
    stdio.abort()
    others.cancel()

    # On the fake clock: the gap is kept, and no timer was slept to keep it.
    assert all(later - earlier >= 0.001 for earlier, later in zip(at, at[1:]))
    assert not any(slept)


async def test_a_write_an_ended_exec_refuses_is_a_dropped_connection(
    tls: tuple[ssl.SSLContext, str],
) -> None:
    context, pin = tls

    class Ended(anyio.abc.ByteStream):
        """An exec's stdio that refuses writes once it has ended, with nothing read."""

        def __init__(self, inner: anyio.abc.ByteStream) -> None:
            self.inner, self.ended = inner, False

        async def send(self, item: bytes) -> None:
            if self.ended:
                raise anyio.BrokenResourceError
            await self.inner.send(item)

        async def receive(self, max_bytes: int = 65536) -> bytes:
            return await self.inner.receive(max_bytes)

        async def send_eof(self) -> None:
            pass

        async def aclose(self) -> None:
            await self.inner.aclose()

    async def runs(r: asyncio.StreamReader, w: asyncio.StreamWriter) -> None:
        with contextlib.suppress(asyncio.IncompleteReadError):
            await read_frame(r)  # AUTH
            w.write(frame(execd.OK, 0))
            while True:
                kind, call_id, _ = await read_frame(r)
                if kind == execd.RESUME:  # of a START the ended exec never took
                    w.write(frame(execd.ERROR, call_id, b"unknown call"))
                elif kind == execd.START:
                    w.write(frame(execd.EXIT, call_id, b'{"code": 0}'))
                elif kind == execd.RELEASE:
                    released.set()

    released = asyncio.Event()
    server = await asyncio.start_server(runs, "127.0.0.1", 0, ssl=context)
    execs: list[Ended] = []

    async def stdio() -> Ended:
        address = server.sockets[0].getsockname()
        execs.append(Ended(await anyio.connect_tcp(*address)))
        return execs[-1]

    daemon = execd.Daemon("", pin, b"key", stdio=stdio)

    async def start(replace: bool) -> execd.Daemon:
        return daemon

    client = execd.ExecdClient(start)
    await asyncio.wait_for(client.exec(["true"], None, None, {}, None, None), 30)
    # Its last frame has left: the write the exec refuses is the next call's START.
    await asyncio.wait_for(released.wait(), 30)
    execs[0].ended = True

    call = client.exec(["true"], None, None, {}, None, None)
    result = await asyncio.wait_for(call, 30)  # only bounds a hang

    # Resumed through another exec, as a call over a port that was reset is.
    assert (result.returncode, len(execs)) == (0, 2)
    server.close()


async def test_an_exec_that_just_ends_is_a_connection_execd_closed(
    tls: tuple[ssl.SSLContext, str],
) -> None:
    context, pin = tls

    async def ends(r: asyncio.StreamReader, w: asyncio.StreamWriter) -> None:
        w.write_eof()  # as `execd connect` ends where no daemon listens
        await r.read()
        w.close()

    async def runs(r: asyncio.StreamReader, w: asyncio.StreamWriter) -> None:
        await read_frame(r)  # AUTH
        w.write(frame(execd.OK, 0))
        _, call_id, _ = await read_frame(r)  # START
        w.write(frame(execd.EXIT, call_id, b'{"code": 0}'))
        await r.read()

    gone = await asyncio.start_server(ends, "127.0.0.1", 0)
    server = await asyncio.start_server(runs, "127.0.0.1", 0, ssl=context)
    starts: list[bool] = []

    async def start(replace: bool) -> execd.Daemon:
        address = (server if starts else gone).sockets[0].getsockname()
        starts.append(replace)
        return execd.Daemon("", pin, b"key", stdio=lambda: anyio.connect_tcp(*address))

    call = execd.ExecdClient(start).exec(["true"], None, None, {}, None, None)
    result = await asyncio.wait_for(call, 30)  # only bounds a hang

    # Read as a port that closed: execd is started again, with no --replace.
    assert (result.returncode, starts[:2]) == (0, [True, False])
    gone.close()
    server.close()


async def test_a_connection_closed_under_a_silent_exec_closes_the_exec(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(execd, "CONNECT_TIMEOUT", None)  # or a stalled machine ends it
    closed = asyncio.Event()
    senders: list[asyncio.Task[None] | None] = []

    class Silent(anyio.abc.ByteStream):
        """An exec that takes what is written to it and answers nothing."""

        async def send(self, item: bytes) -> None:
            senders.append(asyncio.current_task())

        async def receive(self, max_bytes: int = 65536) -> bytes:
            await asyncio.Event().wait()
            return b""

        async def send_eof(self) -> None:
            pass

        async def aclose(self) -> None:
            closed.set()

    async def stdio() -> Silent:
        return Silent()

    connecting = asyncio.ensure_future(
        execd._connect(execd.Daemon("", "0" * 64, b"key", stdio=stdio), execd.Pace())
    )
    await until(lambda: bool(senders))  # the handshake's first bytes have gone
    connecting.cancel()

    # The exec is closed, and nothing is left that would write to it.
    await asyncio.wait_for(closed.wait(), 30)
    await until(lambda: senders[0] is not None and senders[0].done())


@pytest.fixture
async def refused(
    monkeypatch: pytest.MonkeyPatch,
) -> collections.abc.AsyncIterator[list[bytes]]:
    """The requests of the real Kubernetes client to an API server that refuses each."""
    requests: list[bytes] = []

    async def refuse(r: asyncio.StreamReader, w: asyncio.StreamWriter) -> None:
        requests.append(await r.readuntil(b"\r\n\r\n"))
        w.write(b"HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\n\r\n")
        w.close()

    server = await asyncio.start_server(refuse, "127.0.0.1", 0)
    host = "http://127.0.0.1:%d" % server.sockets[0].getsockname()[1]
    api = kubernetes.client.CoreV1Api(
        kubernetes.client.ApiClient(kubernetes.client.Configuration(host=host))
    )
    monkeypatch.setattr(op, "k8s_client", lambda _: api)
    yield requests
    server.close()


async def test_the_exec_that_reaches_execd_asks_for_no_stderr(
    refused: list[bytes],
) -> None:
    pod = pod_module.Pod("p", "ns", None, "default", "u", 0, "raise", "stdio")

    with pytest.raises(ConnectionError):  # which the client's reconnect waits out
        await asyncio.wait_for(pod._execd_stdio(), 30)

    # Nothing would pace that channel, were a guest to flood it.
    target = urllib.parse.urlsplit(refused[0].split()[1].decode())
    assert urllib.parse.parse_qs(target.query)["stderr"][0].lower() == "false"


async def test_the_client_offers_one_key_exchange_group(
    tls: tuple[ssl.SSLContext, str], monkeypatch: pytest.MonkeyPatch
) -> None:
    """Regression: a stand-in chose a group whose handshake held the loop 150 ms."""
    context, pin = tls
    context.set_ecdh_curve("secp384r1")  # the only group this server takes
    server = await asyncio.start_server(lambda r, w: None, "127.0.0.1", 0, ssl=context)
    monkeypatch.setattr(execd, "EXECD_PORT", server.sockets[0].getsockname()[1])

    with pytest.raises(ConnectionResetError):  # no group in common: it hangs up
        await execd._connect(execd.Daemon("127.0.0.1", pin, b"key"), execd.Pace())
    server.close()


async def test_what_tls_decryption_costs_is_paced(
    tls_daemon: TlsDaemon, clock: types.SimpleNamespace
) -> None:
    async def answers(r: asyncio.StreamReader, w: asyncio.StreamWriter) -> None:
        _, call_id, _ = await read_frame(r)  # START
        w.write(frame(execd.STDOUT, call_id, b"x" * (256 << 10)))
        w.write(frame(execd.EXIT, call_id, b'{"code": 0}'))
        await r.read()

    client = await tls_daemon(answers)
    await client._get()  # opened at full speed: the costs below are the reads'
    began = clock.now
    clock.cpu = itertools.count().__next__  # a second of CPU for each pass

    call = client.exec(["yes"], None, None, {}, None, None)
    await asyncio.wait_for(call, 30)

    # Each pass is over the second's allowance: the next waits for the next second.
    assert clock.now - began >= 2


async def test_a_read_of_costly_records_takes_a_pass_for_each_slice(
    tls: tuple[ssl.SSLContext, str],
    clock: types.SimpleNamespace,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Regression: 64 KiB of TLS KeyUpdates, one pass, held the loop 45 ms."""
    context, pin = tls
    size = 3 * execd.RAW_READ // 4
    sent = asyncio.Event()

    async def sends(r: asyncio.StreamReader, w: asyncio.StreamWriter) -> None:
        w.write(b"x" * size)
        await w.drain()
        sent.set()
        await r.read()

    server = await asyncio.start_server(sends, "127.0.0.1", 0, ssl=context)
    monkeypatch.setattr(execd, "EXECD_PORT", server.sockets[0].getsockname()[1])
    pipe = await execd._connect(execd.Daemon("127.0.0.1", pin, b"key"), execd.Pace())
    await asyncio.wait_for(sent.wait(), 30)  # so that one read takes it all
    looks = itertools.count()
    clock.cpu = lambda: next(looks) * 0.02  # each look at the clock: 20 ms more
    began = clock.now

    await asyncio.wait_for(pipe.readexactly(size), 30)  # only bounds a hang

    await pipe.close()
    server.close()
    # A pass for each slice of that one read: together past a second's 50 ms of TLS.
    assert clock.now - began > 0.5


async def test_a_read_of_records_that_deliver_their_bytes_goes_to_tls_in_thirds(
    tls: tuple[ssl.SSLContext, str],
    clock: types.SimpleNamespace,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Regression: in 8 KiB slices, a 100 MiB read slept out each second."""
    context, pin = tls
    size = 3 * execd.RAW_READ // 4
    sent = asyncio.Event()

    async def sends(r: asyncio.StreamReader, w: asyncio.StreamWriter) -> None:
        w.write(b"x" * size)
        await w.drain()
        sent.set()
        await r.read()

    server = await asyncio.start_server(sends, "127.0.0.1", 0, ssl=context)
    monkeypatch.setattr(execd, "EXECD_PORT", server.sockets[0].getsockname()[1])
    pipe = await execd._connect(execd.Daemon("127.0.0.1", pin, b"key"), execd.Pace())
    await asyncio.wait_for(sent.wait(), 30)  # so that one read takes it all
    looks = itertools.count()
    clock.cpu = lambda: next(looks) * 0.005  # each look at the clock: 5 ms more
    began = clock.now

    await asyncio.wait_for(pipe.readexactly(size), 30)  # only bounds a hang

    await pipe.close()
    server.close()
    # Three passes; in 8 KiB slices seven, whose looks at the clock pass 50 ms.
    assert clock.now - began < 0.5


async def test_a_stream_is_charged_only_for_tls_s_own_bytes(
    tls: tuple[ssl.SSLContext, str],
    clock: types.SimpleNamespace,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    context, pin = tls

    async def answers(r: asyncio.StreamReader, w: asyncio.StreamWriter) -> None:
        await read_frame(r)  # AUTH
        w.write(frame(execd.OK, 0))
        _, call_id, _ = await read_frame(r)  # START
        w.write(frame(execd.STDOUT, call_id, b"x" * (256 << 10)))
        w.write(frame(execd.EXIT, call_id, b'{"code": 0}'))
        await r.read()

    server = await asyncio.start_server(answers, "127.0.0.1", 0, ssl=context)
    monkeypatch.setattr(execd, "EXECD_PORT", server.sockets[0].getsockname()[1])
    clock.cpu = lambda: 0.0  # charge bytes only
    monkeypatch.setattr(execd, "PACE_TLS", 50e-6)  # as padding, 256 KiB costs 180 µs

    async def start(replace: bool) -> execd.Daemon:
        return execd.Daemon("127.0.0.1", pin, b"key")

    await execd.ExecdClient(start).exec(["yes"], None, None, {}, None, 30)

    # Records' headers and tags are within it: no pass waited for the next second.
    assert clock.now < 1
    server.close()


async def test_a_handshake_s_decryption_is_paced_too(
    tls: tuple[ssl.SSLContext, str],
    clock: types.SimpleNamespace,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    context, pin = tls
    server = await asyncio.start_server(lambda r, w: None, "127.0.0.1", 0, ssl=context)
    monkeypatch.setattr(execd, "EXECD_PORT", server.sockets[0].getsockname()[1])
    cpu = iter([0.0, 5.0])  # the first pass takes 5 s
    clock.cpu = lambda: next(cpu, 5.0)
    monkeypatch.setattr(execd, "PACE_TLS", 10.0)  # counted, without a wait
    monkeypatch.setattr(execd, "RAW_READ", 64)  # the server's flight takes many passes
    pace = execd.Pace()

    pipe = await execd._connect(execd.Daemon("127.0.0.1", pin, b"key"), pace)

    await pipe.close()
    server.close()
    assert pace.tls > 5.0  # the first pass's CPU, and the bytes the rest took
