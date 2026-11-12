import asyncio
import contextlib
import hashlib
import io
import json
import pathlib
import shutil
import ssl
import subprocess
import time
from collections.abc import Awaitable, Callable
from pathlib import Path

import anyio
import pytest
from pytest import MonkeyPatch

from k8s_sandbox._helm import Release, ValuesSource
from k8s_sandbox._pod import execd
from k8s_sandbox._pod.error import ExecResultUnknownError, PodError
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


@pytest.fixture
def daemons(monkeypatch: MonkeyPatch) -> Daemons:
    stand_ins = Daemons()

    async def connect(daemon: execd.Daemon) -> execd._Pipe:
        # Plain TCP: these tests are about the protocol, not TLS.
        r, w = await asyncio.open_connection("127.0.0.1", stand_ins.ports[daemon])
        return execd._Pipe(r, w)

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
    daemons: Daemons,
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

    async def counts_acks(r: asyncio.StreamReader, w: asyncio.StreamWriter) -> None:
        nonlocal acks
        _, call_id, payload = await read_frame(r)  # START
        start.update(json.loads(payload))
        piece = frame(execd.STDOUT, call_id, b"x" * (64 << 10))
        w.write(piece * (execd.STREAM_WINDOW // (64 << 10)))  # then execd waits
        while True:
            acks += (await read_frame(r))[0] == execd.ACK

    await daemons.serve(counts_acks)
    stream = await daemons.client().open_stream(["cat"], None)
    await until(lambda: held(stream) == execd.STREAM_WINDOW)
    await asyncio.sleep(0.1)  # time for an ack sent on arrival to land
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
        await asyncio.wait_for(stream.send(b"x" * (2 * execd.STDIN_WINDOW)), 5)


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
    async def stops_reading(r: asyncio.StreamReader, w: asyncio.StreamWriter) -> None:
        await read_frame(r)  # START
        await asyncio.sleep(3600)  # frozen: its receive window fills

    await daemons.serve(stops_reading)
    monkeypatch.setattr(execd, "DEAD_AFTER", 0.5)
    monkeypatch.setattr(execd, "KILL_WAIT", 0.5)
    sandbox = daemons.client()

    async def times_out() -> None:
        with pytest.raises((TimeoutError, ExecResultUnknownError)):
            await sandbox.exec(["cat"], b"x" * (64 << 20), None, {}, None, 1)

    await asyncio.wait_for(times_out(), 10)  # a hang fails here, outside the raises


async def test_a_flood_of_small_frames_stays_bounded(daemons: Daemons) -> None:
    flooded = asyncio.Event()

    async def tiny_frames(r: asyncio.StreamReader, w: asyncio.StreamWriter) -> None:
        _, call_id, _ = await read_frame(r)  # START
        with contextlib.suppress(ConnectionError):
            for _ in range(4 * execd.MAX_QUEUED):
                w.write(frame(execd.STDOUT, call_id))  # empty: no bytes to count
                await w.drain()
        flooded.set()

    await daemons.serve(tiny_frames)
    stream = await daemons.client().open_stream(["cat"], None)
    await asyncio.wait_for(flooded.wait(), 30)
    await until(lambda: stream._link.closed)

    assert stream._call.queue.qsize() <= execd.MAX_QUEUED + 1  # + the drop notice
    assert stream._link.closed


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
    async def squatted(daemon: execd.Daemon) -> execd._Pipe:
        raise execd.NotOurDaemon("certificate mismatch")

    async def port_taken(replace: bool) -> execd.Daemon:
        raise execd.DaemonRunning("address already in use")

    monkeypatch.setattr(execd, "_connect", squatted)
    sandbox = execd.ExecdClient(port_taken)
    sandbox._daemon = execd.Daemon("127.0.0.1", "ours", b"key")

    with pytest.raises(RuntimeError, match="held by a process other than execd"):
        await asyncio.wait_for(sandbox.exec(["true"], None, None, {}, None, None), 5)


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


async def test_a_large_control_frame_drops_the_connection(daemons: Daemons) -> None:
    async def large_error(r: asyncio.StreamReader, w: asyncio.StreamWriter) -> None:
        _, call_id, _ = await read_frame(r)  # START
        w.write(frame(execd.ERROR, call_id, b"x" * (execd.MAX_CONTROL + 1)))
        await asyncio.sleep(3600)

    await daemons.serve(large_error)
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
        await asyncio.wait_for(send, 5)


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

    async def another_execd_on_first(daemon: execd.Daemon) -> execd._Pipe:
        # Our start's reply was lost, and that daemon now holds the port.
        if daemon is first:
            raise execd.NotOurDaemon("certificate mismatch")
        return await connect(daemon)

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

    async def refused(daemon: execd.Daemon) -> execd._Pipe:
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
    async def refused(daemon: execd.Daemon) -> execd._Pipe:
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
    stdin = b"x" * (3 * execd.CHUNK)
    received = 0

    async def floods_resumed(r: asyncio.StreamReader, w: asyncio.StreamWriter) -> None:
        nonlocal received
        _, call_id, _ = await read_frame(r)  # START
        resumed = json.dumps({"stdin": 0, "eof": False, "put": 0}).encode()
        w.write(b"".join(frame(execd.RESUMED, call_id, resumed) for _ in range(64)))
        while True:
            kind, _, payload = await read_frame(r)
            if kind == execd.STDIN and not payload:
                w.write(frame(execd.EXIT, call_id, b'{"code": 0}'))
                return
            received += len(payload) if kind == execd.STDIN else 0
            put = json.dumps({"stdin": received}).encode()
            w.write(frame(execd.STDIN_ACK, call_id, put))

    await daemons.serve(floods_resumed)

    await daemons.client().exec(["cat"], stdin, None, {}, None, 30)

    assert received == len(stdin)


async def test_concurrent_sends_on_a_stream_stay_whole(daemons: Daemons) -> None:
    received = bytearray()
    done = asyncio.Event()

    async def records_stdin(r: asyncio.StreamReader, w: asyncio.StreamWriter) -> None:
        _, call_id, _ = await read_frame(r)  # START
        while len(received) < 4 * execd.CHUNK:
            kind, _, payload = await read_frame(r)
            if kind == execd.STDIN:
                received.extend(payload)
                w.write(frame(execd.STDIN_ACK, call_id, b'{"stdin": 0}'))
        done.set()

    await daemons.serve(records_stdin)
    stream = await daemons.client().open_stream(["cat"], None)

    await asyncio.gather(
        stream.send(b"A" * (2 * execd.CHUNK)), stream.send(b"B" * (2 * execd.CHUNK))
    )
    await asyncio.wait_for(done.wait(), 30)

    assert bytes(received) in (
        b"A" * (2 * execd.CHUNK) + b"B" * (2 * execd.CHUNK),
        b"B" * (2 * execd.CHUNK) + b"A" * (2 * execd.CHUNK),
    )


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
    daemons: Daemons,
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

    async def slow_start(replace: bool) -> execd.Daemon:
        await asyncio.sleep(1.5)
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
    t = time.monotonic()

    with pytest.raises(TimeoutError):
        await asyncio.wait_for(client.exec(["true"], None, None, {}, None, 1), 30)
    assert time.monotonic() - t < 10


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


@pytest.mark.skipif(shutil.which("openssl") is None, reason="needs openssl")
async def test_only_the_pinned_certificate_is_trusted(
    tmp_path: pathlib.Path, monkeypatch: MonkeyPatch
) -> None:
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
    server = await asyncio.start_server(lambda r, w: None, "127.0.0.1", 0, ssl=context)
    monkeypatch.setattr(execd, "EXECD_PORT", server.sockets[0].getsockname()[1])
    pin = hashlib.sha256(ssl.PEM_cert_to_DER_cert(cert.read_text())).hexdigest()

    with pytest.raises(execd.NotOurDaemon):
        await execd._connect(execd.Daemon("127.0.0.1", "0" * 64, b"key"))
    await (await execd._connect(execd.Daemon("127.0.0.1", pin, b"key"))).close()
    server.close()
