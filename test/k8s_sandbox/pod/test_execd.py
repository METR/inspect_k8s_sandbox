import asyncio
import contextlib
import hashlib
import io
import json
import shutil
import ssl
import subprocess
import time
import types
from collections.abc import Awaitable, Callable
from pathlib import Path

import anyio
import pytest
from inspect_ai.util import OutputLimitExceededError
from pytest import MonkeyPatch

from k8s_sandbox._helm import Release, ValuesSource
from k8s_sandbox._pod import execd
from k8s_sandbox._pod import pod as pod_module
from k8s_sandbox._pod.error import ExecResultUnknownError, PodError
from k8s_sandbox._pod.pod import Pod
from k8s_sandbox._pod.snapshot import _parse_pod

Handler = Callable[[asyncio.StreamReader, asyncio.StreamWriter], Awaitable[None]]


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
        return await self._reader.readexactly(n)

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

    with pytest.raises(ExecResultUnknownError):
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
    with pytest.raises(ExecResultUnknownError):
        await sandbox.exec(["touch", "/once"], None, None, {}, None, 10)


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
    monkeypatch.setattr(execd, "DEAD_AFTER", 0.5)
    monkeypatch.setattr(execd, "KILL_WAIT", 0.5)
    sandbox = daemons.client()

    async def times_out() -> None:
        with pytest.raises((TimeoutError, ExecResultUnknownError)):
            await sandbox.exec(["cat"], b"x" * (64 << 20), None, {}, None, 1)

    task = asyncio.ensure_future(times_out())
    done, _ = await asyncio.wait({task}, timeout=15)
    for peer in peers:  # frees a hung client, so a failure ends here
        peer.transport.abort()
    assert done, "the blocked write held up the timeout"
    await task


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

    # PodError is retried too, which would run the command again.
    with pytest.raises(ExecResultUnknownError):
        await sandbox.exec(["touch", "/once"], None, None, {}, None, 10)


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

    async def cancelled_after_start(
        link: execd.Link, kind: int, call_id: int, payload: bytes = b""
    ) -> None:
        await send(link, kind, call_id, payload)
        if kind == execd.START:
            raise asyncio.CancelledError

    monkeypatch.setattr(execd.Link, "send", cancelled_after_start)

    with pytest.raises(asyncio.CancelledError):
        await daemons.client().open_stream(["cat"], None)
    await until(lambda: execd.KILL in got)


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

    with pytest.raises(ExecResultUnknownError):
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

    with pytest.raises(ExecResultUnknownError):
        await daemons.client().exec(["touch", "/once"], None, None, {}, None, 5)
    assert starts == 1


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


async def test_what_tls_records_cost_is_paced(
    tls: tuple[ssl.SSLContext, str], monkeypatch: MonkeyPatch
) -> None:
    context, pin = tls
    monkeypatch.setattr(execd, "PACE_OVERHEAD", 2048)
    monkeypatch.setattr(execd, "RAW_READ", 512)  # so no batch is near the allowance

    async def tiny_records(r: asyncio.StreamReader, w: asyncio.StreamWriter) -> None:
        await read_frame(r)  # AUTH
        w.write(frame(execd.OK, 0))
        _, call_id, _ = await read_frame(r)  # START
        out = frame(execd.STDOUT, call_id, b"x" * 200)
        for byte in out + frame(execd.EXIT, call_id, b'{"code": 0}'):
            w.write(bytes([byte]))  # a record each: 22 bytes that aren't plaintext
        await r.read()

    server = await asyncio.start_server(tiny_records, "127.0.0.1", 0, ssl=context)
    monkeypatch.setattr(execd, "EXECD_PORT", server.sockets[0].getsockname()[1])

    async def start(replace: bool) -> execd.Daemon:
        return execd.Daemon("127.0.0.1", pin, b"key")

    began = time.monotonic()
    await execd.ExecdClient(start).exec(["yes"], None, None, {}, None, 30)

    # Over twice the second's allowance, so two waits; unpaced, it takes milliseconds.
    assert time.monotonic() - began >= 2
    server.close()
