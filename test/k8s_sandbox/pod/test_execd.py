import asyncio
import contextlib
import json
from collections.abc import Awaitable, Callable

import anyio
import pytest
from pytest import MonkeyPatch

from k8s_sandbox._pod import execd
from k8s_sandbox._pod.error import ExecResultUnknownError, PodError

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
            w.write(frame(execd.OK, 0, b'{"pid": 1}'))
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


def held(stream: execd.ExecdStream) -> int:
    queued = list(stream._call.queue._queue)  # type: ignore[attr-defined]
    return sum(len(item[1]) for item in queued if isinstance(item, tuple))


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
    await asyncio.wait_for(flooded.wait(), 10)
    await asyncio.sleep(0.1)

    assert held(stream) <= execd.HOLD
    assert stream._link.closed


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
            except TimeoutError:
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
    await asyncio.wait_for(flooded.wait(), 10)
    await asyncio.sleep(0.1)

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
