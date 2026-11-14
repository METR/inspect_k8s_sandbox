import asyncio
import contextlib
import gc
import hashlib
import io
import json
import shutil
import ssl
import subprocess
import threading
import time
import types
from collections.abc import AsyncGenerator, Awaitable, Callable
from pathlib import Path

import anyio
import pytest
from inspect_ai.util import OutputLimitExceededError
from kubernetes.client.exceptions import ApiException
from pytest import MonkeyPatch

from k8s_sandbox._helm import Release, ValuesSource
from k8s_sandbox._pod import error, execd, op
from k8s_sandbox._pod import pod as pod_module
from k8s_sandbox._pod.error import ExecdResultUnknownError, PodError
from k8s_sandbox._pod.pod import Pod
from k8s_sandbox._pod.snapshot import _parse_pod

Handler = Callable[[asyncio.StreamReader, asyncio.StreamWriter], Awaitable[None]]
TlsDaemon = Callable[[Handler], Awaitable[execd.ExecdClient]]


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

    async def serve(self, handler: Handler) -> asyncio.Server:
        """One that answers AUTH, then hands the connection to handler."""

        async def connection(r: asyncio.StreamReader, w: asyncio.StreamWriter) -> None:
            await read_frame(r)  # AUTH
            w.write(frame(execd.OK, 0))
            await handler(r, w)

        server = await asyncio.start_server(connection, "127.0.0.1", 0)
        daemon = execd.Daemon("127.0.0.1", f"cert-{len(self.ports)}", b"key")
        self.ports[daemon] = server.sockets[0].getsockname()[1]
        self.unstarted.append(daemon)
        return server

    def client(self) -> execd.ExecdClient:
        async def start(replace: bool) -> execd.Daemon:
            return self.unstarted.pop(0)

        return execd.ExecdClient(start)


class Plain(execd._Pipe):
    """execd's pipe over plain TCP: these tests are about the protocol, not TLS."""

    def __init__(self, r: asyncio.StreamReader, w: asyncio.StreamWriter) -> None:
        self._reader, self._writer = r, w

    async def readexactly(self, n: int) -> bytes:
        try:
            return await self._reader.readexactly(n)
        except asyncio.IncompleteReadError:  # as execd's own pipe ends
            raise ConnectionResetError("execd closed the connection") from None

    async def write(self, data: bytes) -> None:
        self._writer.write(data)
        await self._writer.drain()


@pytest.fixture
def daemons(monkeypatch: MonkeyPatch) -> Daemons:
    stand_ins = Daemons()

    async def connect(daemon: execd.Daemon, pace: execd.Pace) -> execd._Pipe:
        r, w = await asyncio.open_connection("127.0.0.1", stand_ins.ports[daemon])
        return Plain(r, w)

    monkeypatch.setattr(execd, "_connect", connect)
    return stand_ins


async def until(condition: Callable[[], bool]) -> None:
    """Wait for a condition; the budget only bounds a hang."""

    async def poll() -> None:
        while not condition():
            await asyncio.sleep(0.01)

    await asyncio.wait_for(poll(), 30)


def held(stream: execd.ExecdStream) -> int:
    queued = list(stream._call.queue._queue)  # type: ignore[attr-defined]
    return sum(len(item[1]) for item in queued if isinstance(item, tuple))


async def test_an_annotated_pod_runs_every_operation_over_execd(
    daemons: Daemons, monkeypatch: MonkeyPatch
) -> None:
    starts = 0

    async def exits(r: asyncio.StreamReader, w: asyncio.StreamWriter) -> None:
        nonlocal starts
        while True:
            kind, call_id, _ = await read_frame(r)
            if kind == execd.START:
                starts += 1
                w.write(frame(execd.EXIT, call_id, b'{"code": 0}'))

    await daemons.serve(exits)
    # As in test_helm.py: no cluster config needed.
    monkeypatch.setattr("k8s_sandbox._helm.get_default_namespace", lambda _: "default")
    release = Release(__file__, None, ValuesSource.none(), None)
    release._ready_pods = [
        _parse_pod(
            {
                "metadata": {
                    "name": "p",
                    "uid": "u",
                    "labels": {"inspect/service": "default"},
                    "annotations": {execd.ANNOTATION: "true"},
                },
                "spec": {"containers": [{"name": "default"}]},
                "status": {"phase": "Running", "podIP": "10.0.0.1"},
            }
        )
    ]
    pod = (await release.get_sandbox_pods())["default"]
    assert pod._execd is not None
    pod._execd._start = daemons.client()._start

    await pod.exec(["true"], None, None, {}, None, 10)
    await pod.write_file(b"x", Path("/tmp/x"))
    await pod.read_file(Path("/tmp/x"), io.BytesIO())
    await (await pod.exec_stdio(["cat"], None)).aclose()

    await until(lambda: starts == 4)


class Cluster:
    """What Kubernetes shows of pod p: running, its container restarted this often."""

    restarts = 0
    uid, ip = "u", "10.0.0.1"
    unavailable = False  # its next read fails

    def read_namespaced_pod(self, **_: object) -> types.SimpleNamespace:
        if self.unavailable:
            self.unavailable = False
            raise ApiException(status=503)
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
def cluster(monkeypatch: MonkeyPatch) -> Cluster:
    shown = Cluster()
    monkeypatch.setattr(op, "k8s_client", lambda _: shown)
    monkeypatch.setattr(pod_module, "k8s_client", lambda _: shown)
    return shown


@pytest.mark.parametrize(
    "operation",
    [
        pytest.param(lambda p: p.exec(["true"], None, None, {}, None, None), id="exec"),
        pytest.param(lambda p: p.write_file(b"x", Path("/tmp/x")), id="write_file"),
        pytest.param(lambda p: p.read_file(Path("/x"), io.BytesIO()), id="read_file"),
    ],
)
async def test_a_restart_found_in_raise_mode_fails_operations_over_execd(
    tls_daemon: TlsDaemon,
    cluster: Cluster,
    operation: Callable[[pod_module.Pod], Awaitable[object]],
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

    assert held(stream) <= 2 * (execd.STREAM_WINDOW + execd.CHUNK)
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
    assert held(stream) <= 4 * execd.MAX_CONTROL
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

    with pytest.raises(ExecdResultUnknownError):
        await daemons.client().exec(["touch", "/once"], None, None, {}, None, 10)
    assert len(starts) == 1


async def test_stdin_in_flight_stays_within_the_window(
    daemons: Daemons,
) -> None:
    most_in_flight = 0

    async def acks_when_the_client_waits(
        r: asyncio.StreamReader, w: asyncio.StreamWriter
    ) -> None:
        nonlocal most_in_flight
        _, call_id, _ = await read_frame(r)  # START
        frames: asyncio.Queue[tuple[int, int, bytes]] = asyncio.Queue()

        async def pump() -> None:
            while True:
                frames.put_nowait(await read_frame(r))

        reader = asyncio.create_task(pump())
        received = written = 0
        while True:
            try:
                kind, _, payload = await asyncio.wait_for(frames.get(), 0.3)
            except asyncio.TimeoutError:
                # The client has stopped sending: all it has sent is in.
                most_in_flight = max(most_in_flight, received - written)
                written = received
                put = json.dumps({"stdin": written}).encode()
                w.write(frame(execd.STDIN_ACK, call_id, put))
                continue
            if kind == execd.STDIN and not payload:
                most_in_flight = max(most_in_flight, received - written)
                w.write(frame(execd.EXIT, call_id, b'{"code": 0}'))
                reader.cancel()
                return
            received += len(payload) if kind == execd.STDIN else 0

    await daemons.serve(acks_when_the_client_waits)
    stdin = b"x" * (3 * execd.STDIN_WINDOW)

    result = await daemons.client().exec(["cat"], stdin, None, {}, None, 30)

    assert result.returncode == 0
    assert most_in_flight <= execd.STDIN_WINDOW


async def test_connection_lost_after_start_is_not_retryable(
    daemons: Daemons, monkeypatch: MonkeyPatch
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
    with pytest.raises(ExecdResultUnknownError):
        await sandbox.exec(["touch", "/once"], None, None, {}, None, 10)


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
            sandbox.exec(["touch", "/once"], None, None, {}, None, 10)
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


async def test_a_peer_that_stops_reading_cannot_hang_a_timed_out_command(
    daemons: Daemons, monkeypatch: MonkeyPatch
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
        with pytest.raises((TimeoutError, ExecdResultUnknownError)):
            await sandbox.exec(["cat"], b"x" * (64 << 20), None, {}, None, 1)

    task = asyncio.ensure_future(times_out())
    done, _ = await asyncio.wait({task}, timeout=15)
    for peer in peers:  # frees a hung client, so a failure ends here
        peer.transport.abort()
    assert done, "the blocked write held up the timeout"
    await task


async def test_a_timed_out_call_frees_what_execd_holds(daemons: Daemons) -> None:
    released = asyncio.Event()

    async def full_after_kill(r: asyncio.StreamReader, w: asyncio.StreamWriter) -> None:
        _, call_id, _ = await read_frame(r)  # START
        while True:
            kind, _, _ = await read_frame(r)
            if kind == execd.KILL:  # the killed command's last output fills the window
                for _ in range(4):
                    w.write(frame(execd.STDOUT, call_id, b"x" * execd.CHUNK))
            elif kind == execd.ACK:  # room for the rest of it: the call exits
                w.write(frame(execd.EXIT, call_id, b'{"code": 137}'))
            elif kind == execd.RELEASE:
                released.set()

    await daemons.serve(full_after_kill)
    with pytest.raises(TimeoutError, match="Command timed out"):  # not KILL_WAIT later
        await asyncio.wait_for(
            daemons.client().exec(["yes"], None, None, {}, None, 1), 5
        )
    await asyncio.wait_for(released.wait(), 5)


async def test_a_timed_out_call_takes_no_more_than_its_hold(daemons: Daemons) -> None:
    acked = 0

    async def sends_while_acked(
        r: asyncio.StreamReader, w: asyncio.StreamWriter
    ) -> None:
        nonlocal acked
        _, call_id, _ = await read_frame(r)  # START
        more = frame(execd.STDOUT, call_id, b"x" * (execd.CHUNK * 3 // 2))
        while True:
            kind, _, payload = await read_frame(r)
            if kind == execd.ACK:
                acked = max(acked, sum(json.loads(payload).values()))
            if kind in (execd.KILL, execd.ACK):  # never exits; sends again when acked
                w.write(more)

    await daemons.serve(sends_while_acked)
    with pytest.raises(TimeoutError, match="Command timed out"):  # not KILL_WAIT later
        await asyncio.wait_for(
            daemons.client().exec(["yes"], None, None, {}, None, 1), 5
        )
    assert 0 < acked <= execd.HOLD


async def test_a_timed_out_call_whose_connection_drops_returns_at_once(
    daemons: Daemons,
) -> None:
    async def drops_on_kill(r: asyncio.StreamReader, w: asyncio.StreamWriter) -> None:
        while (await read_frame(r))[0] != execd.KILL:
            pass
        w.transport.abort()

    await daemons.serve(drops_on_kill)
    with pytest.raises(TimeoutError, match="Command timed out"):  # not KILL_WAIT later
        await asyncio.wait_for(
            daemons.client().exec(["sleep", "9"], None, None, {}, None, 1), 5
        )


async def test_a_timed_out_call_is_released_with_no_exit(
    daemons: Daemons, monkeypatch: MonkeyPatch
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
    await asyncio.wait_for(released.wait(), 5)


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


async def test_a_failed_restart_after_start_is_not_retryable(
    daemons: Daemons, monkeypatch: MonkeyPatch
) -> None:
    async def start_fails(replace: bool) -> execd.Daemon:
        raise PodError("execd did not start")

    async def dies_after_start(
        r: asyncio.StreamReader, w: asyncio.StreamWriter
    ) -> None:
        await read_frame(r)  # START
        sandbox._start = start_fails
        server.close()
        w.close()

    server = await daemons.serve(dies_after_start)
    sandbox = daemons.client()
    monkeypatch.setattr(execd, "RECONNECT_FOR", 0.5)

    # PodError is retried too, which would run the command again.
    with pytest.raises(ExecdResultUnknownError):
        call = sandbox.exec(["touch", "/once"], None, None, {}, None, None)
        await asyncio.wait_for(call, 30)  # only bounds a hang


async def test_a_start_that_fails_while_reconnecting_does_not_lose_the_command(
    daemons: Daemons, monkeypatch: MonkeyPatch
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
        raise ApiException(status=503)

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
    "status", [b"[]", b"null", b"{}", b'{"code": "0"}', b'{"code": 0, "error": 5}']
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

    with pytest.raises(ExecdResultUnknownError):
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
    daemons: Daemons, monkeypatch: MonkeyPatch
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
        await asyncio.sleep(3600)

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

    async def never_acks_stdin(
        r: asyncio.StreamReader, w: asyncio.StreamWriter
    ) -> None:
        while True:
            await read_frame(r)

    await daemons.serve(never_acks_stdin)
    stream = await daemons.client().open_stream(["cat"], None)
    send = asyncio.create_task(stream.send(b"x" * (2 * execd.STDIN_WINDOW)))
    await until(lambda: stream._sent >= execd.STDIN_WINDOW)  # it waits for room

    send.cancel()

    with pytest.raises(asyncio.CancelledError):
        await send
    with pytest.raises(anyio.ClosedResourceError):
        await asyncio.wait_for(stream.send(b"next"), 30)


async def test_a_daemon_that_is_not_ours_is_replaced(
    daemons: Daemons, monkeypatch: MonkeyPatch
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
    await sandbox.exec(["true"], None, None, {}, None, 10)
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

    await sandbox.exec(["true"], None, None, {}, None, 10)

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

    result = await sandbox.exec(["yes"], None, None, {}, None, 10)

    assert len(result.stdout) == lines
    assert sandbox._link is not None and not sandbox._link.closed


async def test_callers_share_one_reconnect(
    daemons: Daemons, monkeypatch: MonkeyPatch
) -> None:
    async def answers(r: asyncio.StreamReader, w: asyncio.StreamWriter) -> None:
        while True:
            kind, call_id, _ = await read_frame(r)
            if kind == execd.START:
                w.write(frame(execd.EXIT, call_id, b'{"code": 0}'))

    await daemons.serve(answers)
    sandbox = daemons.client()
    await sandbox.exec(["true"], None, None, {}, None, 10)
    stale = sandbox._link
    assert stale is not None
    await stale.close()

    async def refused(daemon: execd.Daemon, pace: execd.Pace) -> execd._Pipe:
        raise ConnectionRefusedError

    async def still_running(replace: bool) -> execd.Daemon:
        raise execd.DaemonRunning("address already in use")

    monkeypatch.setattr(execd, "_connect", refused)
    monkeypatch.setattr(execd, "RECONNECT_FOR", 0.5)
    sandbox._start = still_running
    opens = 0
    open_ = sandbox._open

    async def counted(deadline: float) -> execd.Link:
        nonlocal opens
        opens += 1
        return await open_(deadline)

    sandbox._open = counted  # type: ignore[method-assign]

    results = await asyncio.gather(
        *(sandbox._get(stale) for _ in range(5)), return_exceptions=True
    )

    assert all(isinstance(r, ConnectionError) for r in results)
    assert opens == 1


async def test_only_a_resume_waits_out_a_reconnect(
    daemons: Daemons, monkeypatch: MonkeyPatch
) -> None:
    async def answers(r: asyncio.StreamReader, w: asyncio.StreamWriter) -> None:
        while True:
            kind, call_id, _ = await read_frame(r)
            if kind == execd.START:
                w.write(frame(execd.EXIT, call_id, b'{"code": 0}'))

    await daemons.serve(answers)
    client = daemons.client()
    await client.exec(["true"], None, None, {}, None, 10)
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
    daemons: Daemons, monkeypatch: MonkeyPatch
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
    await client.exec(["true"], None, None, {}, None, 10)
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
    await client.exec(["true"], None, None, {}, None, 10)
    assert started == 2


async def test_a_daemon_that_cannot_be_reached_is_not_restarted_in_a_loop(
    monkeypatch: MonkeyPatch,
) -> None:
    async def refused(daemon: execd.Daemon, pace: execd.Pace) -> execd._Pipe:
        raise ConnectionRefusedError

    starts = 0

    async def start(replace: bool) -> execd.Daemon:
        nonlocal starts
        starts += 1
        return execd.Daemon("127.0.0.1", f"cert-{starts}", b"key")

    monkeypatch.setattr(execd, "_connect", refused)
    monkeypatch.setattr(execd, "FIRST_OPEN_FOR", 1.0)

    with pytest.raises(ConnectionError):
        await execd.ExecdClient(start).exec(["true"], None, None, {}, None, None)

    # Paced: a handful in the second, where an unpaced loop runs hundreds.
    assert starts <= 10


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
    daemons: Daemons, monkeypatch: MonkeyPatch
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
    daemons: Daemons, monkeypatch: MonkeyPatch
) -> None:
    got: list[int] = []

    async def records(r: asyncio.StreamReader, w: asyncio.StreamWriter) -> None:
        while True:
            got.append((await read_frame(r))[0])

    await daemons.serve(records)
    send = execd.Link.send
    scope = anyio.CancelScope()
    writers: list[asyncio.Task[None]] = []

    async def writes(link: execd.Link) -> None:  # another call's
        async with link._wlock:
            await asyncio.sleep(0.1)

    async def cancelled_after_start(
        link: execd.Link, kind: int, call_id: int, payload: bytes = b""
    ) -> None:
        await send(link, kind, call_id, payload)
        if kind == execd.START:
            writers.append(asyncio.create_task(writes(link)))
            scope.cancel()  # anyio cancels again at each await, unlike asyncio
            await asyncio.sleep(1)

    monkeypatch.setattr(execd.Link, "send", cancelled_after_start)

    with scope:
        await daemons.client().open_stream(["cat"], None)
    await writers[0]
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
        await asyncio.sleep(0.1)
    await task
    await until(lambda: execd.RELEASE in got)

    assert execd.KILL in got
    assert not link.calls


async def test_a_call_cancelled_as_it_exits_is_released(
    daemons: Daemons, monkeypatch: MonkeyPatch
) -> None:
    got: list[int] = []
    go, releasing = asyncio.Event(), asyncio.Event()

    async def exits(r: asyncio.StreamReader, w: asyncio.StreamWriter) -> None:
        while True:
            kind, call_id, _ = await read_frame(r)
            got.append(kind)
            if kind == execd.START:
                await go.wait()
                w.write(frame(execd.EXIT, call_id, b'{"code": 0}'))

    await daemons.serve(exits)
    send = execd.Link.send

    async def signals_release(
        link: execd.Link, kind: int, call_id: int, payload: bytes = b""
    ) -> None:
        if kind == execd.RELEASE:
            releasing.set()
        await send(link, kind, call_id, payload)

    monkeypatch.setattr(execd.Link, "send", signals_release)
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
        await releasing.wait()
        scope.cancel()
        await asyncio.sleep(0.1)
    await task
    await until(lambda: execd.RELEASE in got)

    assert execd.KILL not in got  # it exited: a KILL would end what it left running


async def test_a_stream_closed_while_cancelled_is_killed(daemons: Daemons) -> None:
    got: list[int] = []

    async def records(r: asyncio.StreamReader, w: asyncio.StreamWriter) -> None:
        while True:
            got.append((await read_frame(r))[0])

    await daemons.serve(records)
    stream = await daemons.client().open_stream(["cat"], None)
    writing = asyncio.Event()

    async def writes() -> None:  # another call's
        async with stream._link._wlock:
            writing.set()
            await asyncio.sleep(0.1)

    writer = asyncio.create_task(writes())
    await writing.wait()
    with anyio.CancelScope() as scope:
        scope.cancel()
        await stream.aclose()
    await writer
    await until(lambda: execd.RELEASE in got)

    assert got[-3:] == [execd.STDIN, execd.KILL, execd.RELEASE]


async def test_stray_frames_end_the_connection(daemons: Daemons) -> None:
    async def pongs(r: asyncio.StreamReader, w: asyncio.StreamWriter) -> None:
        w.write(frame(execd.PONG, 0) * (execd.MAX_STRAY + 1))
        await r.read()

    await daemons.serve(pongs)
    stream = await daemons.client().open_stream(["cat"], None)

    await until(lambda: stream._link.closed)


async def test_stray_bytes_end_the_connection(
    daemons: Daemons, monkeypatch: MonkeyPatch
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
    daemons: Daemons, monkeypatch: MonkeyPatch, kind: int, payload: bytes
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
    daemons: Daemons, monkeypatch: MonkeyPatch, limit: str, value: int, payload: bytes
) -> None:
    monkeypatch.setattr(execd, limit, value)

    async def floods(r: asyncio.StreamReader, w: asyncio.StreamWriter) -> None:
        _, call_id, _ = await read_frame(r)  # START
        w.write(frame(execd.STDOUT, call_id, payload) * 150)
        w.write(frame(execd.EXIT, call_id, b'{"code": 0}'))
        await r.read()

    await daemons.serve(floods)
    start = time.monotonic()

    await daemons.client().exec(["yes"], None, None, {}, None, 30)

    # Three times the second's allowance, so two waits; unpaced, it takes milliseconds.
    assert time.monotonic() - start >= 2


async def test_the_stray_count_spans_reconnects(
    daemons: Daemons, monkeypatch: MonkeyPatch
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

    second = await client._get(first)

    await until(lambda: second.closed)  # 120 in one interval, over two connections


async def test_a_daemon_that_drops_each_connection_is_reconnected_with_backoff(
    daemons: Daemons,
) -> None:
    connections = 0

    async def drops(r: asyncio.StreamReader, w: asyncio.StreamWriter) -> None:
        nonlocal connections
        connections += 1
        await read_frame(r)  # START, then RESUME
        w.close()

    await daemons.serve(drops)

    with pytest.raises(TimeoutError):
        await daemons.client().exec(["true"], None, None, {}, None, 1)

    # Paced: a handful in the second, where an unpaced loop makes hundreds.
    assert connections <= 10


async def test_an_opened_connection_is_the_clients_at_once(daemons: Daemons) -> None:
    async def idle(r: asyncio.StreamReader, w: asyncio.StreamWriter) -> None:
        await r.read()

    await daemons.serve(idle)
    client = daemons.client()

    link = await client._open(time.monotonic() + 10)

    # Before its waiters wake: a caller arriving now must not open a second one.
    assert client._link is link


async def test_only_one_fingerprint_line_starts_execd(monkeypatch: MonkeyPatch) -> None:
    printed = b"0" * 64 + b"\n"

    class Execute:
        def __init__(self, info: object) -> None:
            pass

        def run_argv(self, cmd: list[str]) -> tuple[int, bytes, bytes]:
            return 0, printed, b""

    async def run(f: Callable[[], object]) -> object:
        return f()

    async def no_restart() -> None:
        return None

    monkeypatch.setattr(pod_module, "ExecuteOperation", Execute)
    monkeypatch.setattr(pod_module, "k8s_client", lambda _: None)
    ip = types.SimpleNamespace(ip="10.0.0.1")
    monkeypatch.setattr(pod_module, "read_pod", lambda *_: ip)
    pod = Pod("p", "ns", None, "default", "u", 0, "raise")
    monkeypatch.setattr(pod, "check_for_pod_restart", no_restart)
    monkeypatch.setattr(pod, "_run_async", run)
    assert (await pod._start_execd(False)).fingerprint == "0" * 64

    printed = b"1" * 64 + b" " * 4032  # one token, but cut at run_argv's 4 KiB
    with pytest.raises(PodError, match="execd did not start"):
        await pod._start_execd(False)


def execd_starts(monkeypatch: MonkeyPatch, meanwhile: Callable[[], None]) -> None:
    """Stand in for the exec that starts execd: meanwhile() runs as it does."""
    running = False

    class Execute:
        def __init__(self, info: object) -> None:
            pass

        def run_argv(self, cmd: list[str]) -> tuple[int, bytes, bytes]:
            nonlocal running
            if running and "--replace" not in cmd:  # as execd finds its port taken
                return 2, b"", b"listen tcp :24601: bind: address already in use\n"
            running = True
            meanwhile()
            return 0, b"0" * 64 + b"\n", b""

    monkeypatch.setattr(pod_module, "ExecuteOperation", Execute)


async def test_execd_started_in_a_restarted_container_is_refused_in_raise_mode(
    cluster: Cluster, monkeypatch: MonkeyPatch
) -> None:
    """Regression: a container that restarted as execd started served the sample."""
    execd_starts(monkeypatch, lambda: setattr(cluster, "restarts", 1))
    pod = pod_module.Pod("p", "ns", None, "default", "u", 0, "raise")

    with pytest.raises(error.ContainerRestartedError):
        await pod._start_execd(False)


async def test_a_restart_kubernetes_shows_after_execd_started_is_still_found(
    tls_daemon: TlsDaemon, cluster: Cluster, monkeypatch: MonkeyPatch
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


async def test_execd_started_in_a_replacement_pod_is_reached_at_its_address(
    cluster: Cluster, monkeypatch: MonkeyPatch
) -> None:
    """Regression: in warn mode the client dialed the address of the pod replaced."""
    execd_starts(monkeypatch, lambda: vars(cluster).update(uid="v", ip="10.0.0.2"))
    pod = pod_module.Pod("p", "ns", None, "default", "u", 0, "warn")

    assert (await pod._start_execd(False)).ip == "10.0.0.2"


async def test_execd_lost_to_a_failed_pod_read_is_replaced_at_the_next_start(
    cluster: Cluster, monkeypatch: MonkeyPatch
) -> None:
    """Regression: in warn mode its key was lost, and its port stayed taken."""
    fails = iter([True])
    execd_starts(
        monkeypatch, lambda: setattr(cluster, "unavailable", next(fails, False))
    )
    pod = pod_module.Pod("p", "ns", None, "default", "u", 0, "warn")
    with pytest.raises(ApiException):
        await pod._start_execd(False)

    assert (await pod._start_execd(False)).ip == "10.0.0.1"


async def test_the_read_of_execds_address_uses_a_client_of_its_own_thread(
    cluster: Cluster, monkeypatch: MonkeyPatch
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
    daemons: Daemons, monkeypatch: MonkeyPatch
) -> None:
    upload = execd.ExecdClient._upload

    async def bounded(
        client: execd.ExecdClient,
        link: execd.Link,
        call: execd.Call,
        data: bytes | None,
        offset: int,
    ) -> None:
        if offset >= 0:  # below zero, it would hold the loop for ever
            await upload(client, link, call, data, offset)

    monkeypatch.setattr(execd.ExecdClient, "_upload", bounded)
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
        got = {"stdin": -(10**30), "eof": False, "put": 0}
        w.write(frame(execd.RESUMED, call_id, json.dumps(got).encode()))
        while not resent or resent[-1]:  # to the empty frame that closes stdin
            kind, _, payload = await read_frame(r)
            if kind == execd.STDIN:
                resent.append(payload)
        w.write(frame(execd.EXIT, call_id, b'{"code": 0}'))
        await r.read()

    await daemons.serve(acks_then_resumes_below_zero)

    await daemons.client().exec(["cat"], "abc", None, {}, None, 10)

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

    with pytest.raises(ExecdResultUnknownError):
        await daemons.client().exec(["cat"], "abc", None, {}, None, 10)
    assert starts == 1


@pytest.mark.parametrize("kind", [execd.STDERR, execd.STDOUT])
async def test_a_file_write_stops_at_the_output_limit(
    daemons: Daemons, monkeypatch: MonkeyPatch, kind: int
) -> None:
    monkeypatch.setattr(execd.limits, "MAX_EXEC_OUTPUT_SIZE", 1024)

    async def chatters(r: asyncio.StreamReader, w: asyncio.StreamWriter) -> None:
        _, call_id, _ = await read_frame(r)  # START
        w.write(frame(kind, call_id, b"x" * 2048))  # past the limit, then done
        w.write(frame(execd.EXIT, call_id, b'{"code": 0}'))
        await r.read()

    await daemons.serve(chatters)

    with pytest.raises(OutputLimitExceededError):
        await daemons.client().write_file(b"data", Path("/tmp/f"))


async def test_a_port_held_at_the_first_start_says_so() -> None:
    async def held(replace: bool) -> execd.Daemon:
        raise execd.DaemonRunning("bind: address already in use")  # even with --replace

    with pytest.raises(RuntimeError, match="held by a process other than execd"):
        await execd.ExecdClient(held).exec(["true"], None, None, {}, None, 10)


async def test_stray_frames_are_counted_per_ping_interval(
    daemons: Daemons, monkeypatch: MonkeyPatch
) -> None:
    monkeypatch.setattr(execd, "MAX_STRAY", 100)
    monkeypatch.setattr(execd, "PING_EVERY", 0.01)

    async def pongs_across_pings(
        r: asyncio.StreamReader, w: asyncio.StreamWriter
    ) -> None:
        _, call_id, _ = await read_frame(r)  # START
        w.write(frame(execd.PONG, 0) * execd.MAX_STRAY)
        for _ in range(2):  # the count restarts with each interval
            while (await read_frame(r))[0] != execd.PING:
                pass
        w.write(frame(execd.PONG, 0) * execd.MAX_STRAY)
        w.write(frame(execd.STDOUT, call_id, b"still here"))
        await r.read()

    await daemons.serve(pongs_across_pings)
    stream = await daemons.client().open_stream(["cat"], None)

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


async def test_the_timeout_runs_from_the_start_of_the_command(
    daemons: Daemons, monkeypatch: MonkeyPatch
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
    daemons: Daemons,
) -> None:
    client = daemons.client()
    first: asyncio.Server

    async def stuck(replace: bool) -> execd.Daemon:
        await asyncio.sleep(3600)
        raise AssertionError

    async def dies_after_start(
        r: asyncio.StreamReader, w: asyncio.StreamWriter
    ) -> None:
        await read_frame(r)  # START
        client._start = stuck  # the restart never finishes
        first.close()
        w.close()

    first = await daemons.serve(dies_after_start)

    with pytest.raises(TimeoutError, match="Command timed out"):  # not the 30 s bound
        await asyncio.wait_for(client.exec(["true"], None, None, {}, None, 1), 30)


async def test_stdin_acks_that_report_progress_keep_the_connection(
    daemons: Daemons, monkeypatch: MonkeyPatch
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
    daemons: Daemons, monkeypatch: MonkeyPatch
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

    with pytest.raises(ExecdResultUnknownError):
        await daemons.client().exec(["touch", "/once"], None, None, {}, None, 5)
    assert starts == 1


async def test_a_call_execd_abandoned_is_not_started_again(daemons: Daemons) -> None:
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

    with pytest.raises(ExecdResultUnknownError):
        await daemons.client().exec(["touch", "/once"], None, None, {}, None, 10)
    assert starts == 1


async def test_pacing_lets_other_work_run() -> None:
    ran = asyncio.Event()
    asyncio.get_running_loop().call_soon(ran.set)

    await execd.Pace().take(1)

    assert ran.is_set()  # under its allowance too: a pass at a time


async def test_a_second_allows_fifty_milliseconds_of_tls(
    monkeypatch: MonkeyPatch,
) -> None:
    slept: list[float] = []

    async def sleep(seconds: float) -> None:
        slept.append(seconds)

    monkeypatch.setattr(execd.asyncio, "sleep", sleep)
    pace = execd.Pace()

    await pace.take(0, frames=0, tls=0.04)
    await pace.take(0, frames=0, tls=0.02)

    # Past 50 ms, the rest of the second: more lets a stand-in's TLS floods cost more.
    assert slept[0] == 0 and slept[1] > 0.5


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


async def test_a_trickle_of_short_reads_waits_its_turn() -> None:
    reading: list[bool] = []
    pipe = stub_pipe(0.5, reading)
    began = time.monotonic()

    for _ in range(execd.SMALL_READS + 20):
        await pipe._raw()

    # Past the burst, about one a millisecond.
    assert 0.015 <= time.monotonic() - began < 0.15
    assert not reading[-1]  # between reads, bytes wait in the kernel


async def test_full_reads_spend_no_turns() -> None:
    pipe = stub_pipe(1.0, [])

    for _ in range(execd.SMALL_READS + 1):
        await pipe._raw()

    assert pipe._small_at == float("-inf")  # a stream at full speed doesn't wait


async def test_what_a_pass_delivers_pays_for_its_decryption(
    monkeypatch: MonkeyPatch,
) -> None:
    pace = execd.Pace()
    pipe = stub_pipe(1.0, [], pace)
    monkeypatch.setattr(execd.time, "thread_time", lambda: 1.0)
    monkeypatch.setattr(execd, "PACE_TLS", 10.0)  # counted, without a wait

    # Cheaper than its credit, finishing a record begun before: nothing carried over.
    await pipe._charge(0.0, delivered=4 * 10**9, used=2 * 10**9)
    await pipe._charge(0.0)  # a second of CPU for nothing delivered
    await pipe._charge(1.0, used=10**9)  # no CPU, but a GB of padding

    assert pace.tls == 1.7


@pytest.fixture
def tls(tmp_path: Path) -> tuple[ssl.SSLContext, str]:
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
    )
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(cert, key)
    der = ssl.PEM_cert_to_DER_cert(cert.read_text())
    return context, hashlib.sha256(der).hexdigest()


@pytest.fixture
async def tls_daemon(
    tls: tuple[ssl.SSLContext, str], monkeypatch: MonkeyPatch
) -> AsyncGenerator[TlsDaemon, None]:
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
    tls: tuple[ssl.SSLContext, str], monkeypatch: MonkeyPatch
) -> None:
    context, pin = tls
    server = await asyncio.start_server(lambda r, w: None, "127.0.0.1", 0, ssl=context)
    monkeypatch.setattr(execd, "EXECD_PORT", server.sockets[0].getsockname()[1])

    with pytest.raises(execd.NotOurDaemon):
        await execd._connect(execd.Daemon("127.0.0.1", "0" * 64, b"key"), execd.Pace())
    pipe = await execd._connect(execd.Daemon("127.0.0.1", pin, b"key"), execd.Pace())
    await pipe.close()
    server.close()


async def test_the_client_offers_one_key_exchange_group(
    tls: tuple[ssl.SSLContext, str], monkeypatch: MonkeyPatch
) -> None:
    """Regression: a stand-in chose a group whose handshake held the loop 150 ms."""
    context, pin = tls
    context.set_ecdh_curve("secp384r1")  # the only group this server takes
    server = await asyncio.start_server(lambda r, w: None, "127.0.0.1", 0, ssl=context)
    monkeypatch.setattr(execd, "EXECD_PORT", server.sockets[0].getsockname()[1])

    with pytest.raises(OSError):  # no group in common: the handshake ends
        await execd._connect(execd.Daemon("127.0.0.1", pin, b"key"), execd.Pace())
    server.close()


async def test_what_tls_decryption_costs_is_paced(
    tls: tuple[ssl.SSLContext, str], monkeypatch: MonkeyPatch
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

    async def start(replace: bool) -> execd.Daemon:
        return execd.Daemon("127.0.0.1", pin, b"key")

    client = execd.ExecdClient(start)
    began = time.monotonic()
    await client._get()  # opened at full speed: the costs below are the reads'
    cpu = iter([0.0, 10.0, 10.0, 20.0])  # the first two passes take 10 s each
    monkeypatch.setattr(execd.time, "thread_time", lambda: next(cpu, 20.0))

    await client.exec(["yes"], None, None, {}, None, 30)

    # Each is over a second's allowance, so two waits; unpaced, it takes milliseconds.
    assert time.monotonic() - began >= 2
    server.close()


async def test_a_stream_is_charged_only_for_tls_s_own_bytes(
    tls: tuple[ssl.SSLContext, str], monkeypatch: MonkeyPatch
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
    monkeypatch.setattr(execd.time, "thread_time", lambda: 0.0)  # charge bytes only
    charged: list[float] = []

    async def take(_: execd.Pace, n: int, frames: int = 1, tls: float = 0.0) -> None:
        charged.append(tls)

    monkeypatch.setattr(execd.Pace, "take", take)

    async def start(replace: bool) -> execd.Daemon:
        return execd.Daemon("127.0.0.1", pin, b"key")

    client = execd.ExecdClient(start)
    await client._get()
    charged.clear()  # the handshake's and AUTH's

    await client.exec(["yes"], None, None, {}, None, 30)

    # Records' headers and tags; as padding, the 256 KiB would cost over 100 µs.
    assert 0 < sum(charged) < 50e-6
    server.close()


async def test_a_handshake_s_decryption_is_paced_too(
    tls: tuple[ssl.SSLContext, str], monkeypatch: MonkeyPatch
) -> None:
    context, pin = tls
    server = await asyncio.start_server(lambda r, w: None, "127.0.0.1", 0, ssl=context)
    monkeypatch.setattr(execd, "EXECD_PORT", server.sockets[0].getsockname()[1])
    cpu = iter([0.0, 5.0])  # the first pass takes 5 s
    monkeypatch.setattr(execd.time, "thread_time", lambda: next(cpu, 5.0))
    monkeypatch.setattr(execd, "PACE_TLS", 10.0)  # counted, without a wait
    monkeypatch.setattr(execd, "RAW_READ", 64)  # the server's flight takes many passes
    pace = execd.Pace()

    pipe = await execd._connect(execd.Daemon("127.0.0.1", pin, b"key"), pace)

    await pipe.close()
    server.close()
    assert pace.tls > 5.0  # the first pass's CPU, and the bytes the rest took
