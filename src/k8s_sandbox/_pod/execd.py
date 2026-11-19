"""Commands and file transfer over TLS to execd in the sandbox."""

from __future__ import annotations

import asyncio
import contextlib
import hashlib
import json
import logging
import os
import shlex
import ssl
import struct
import time
from collections.abc import AsyncGenerator, Awaitable, Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import IO, Any, cast

import anyio
from anyio.abc import ByteStream
from inspect_ai.util import ExecResult, OutputLimitExceededError
from inspect_ai.util import SandboxEnvironmentLimits as limits
from kubernetes.client.exceptions import ApiException

from k8s_sandbox._error import K8sError
from k8s_sandbox._logger import log_trace, log_warn
from k8s_sandbox._pod.buffer import LimitedBuffer
from k8s_sandbox._pod.error import (
    ExecdResultUnknownError,
    ExecdStoppedError,
    ExecResultUnknownError,
    PodError,
)
from k8s_sandbox._pod.execute import (
    _STDERR_TAIL_BYTES,
    EXEC_USER_URL,
    _land_pending_cancel,
)
from k8s_sandbox._pod.op import SYSTEM_PATH, raise_for_known_read_write_errors
from k8s_sandbox._pod.read import read_command

logger = logging.getLogger(__name__)

ANNOTATION = "inspect-k8s-sandbox/execd"
TRANSPORTS = ("true", "stdio")  # its values: execd's port, or one exec's stdio
EXECD_PATH = "/execd/execd"  # directly under /: root can't rename a mountpoint there
EXECD_PORT = 14601  # below every runtime's ephemeral ports: gVisor's start at 16000
EXECD_SOCKET = "inspect-k8s-sandbox-execd"  # abstract: where a pod has no network card

AUTH, START, STDIN, KILL, RESUME, RELEASE, PING, ACK = 1, 2, 3, 4, 5, 6, 7, 8
OK, STDOUT, STDERR, EXIT, PONG, ERROR, RESUMED, STDIN_ACK = (
    16,
    17,
    18,
    19,
    20,
    21,
    22,
    23,
)
HEADER = struct.Struct(">BQI")
CHUNK = 1 << 20
# execd sends at most CHUNK of output per frame; anything larger is not execd.
MAX_FRAME = 2 * CHUNK
MAX_CONTROL = 4096  # any other frame: a little JSON or a short message
MAX_ACK = 64  # execd's {"stdin": n}; each one is parsed, even a stray
ACK_EVERY = 1 << 20  # execd pauses a command past 4 MiB unacked per stream
HOLD = 2 * ((4 << 20) + CHUNK)  # untaken output; past it, the peer isn't execd
MAX_QUEUED = 4096  # frames, of any kind
MAX_STRAY = 1 << 16  # frames that report nothing new, per ping interval
MAX_STRAY_BYTES = 256 << 20  # their payload: output still in flight for calls given up
MAX_OWED = 1024  # calls over whose RELEASE no PONG has followed: a PING asks at half
STREAM_WINDOW = 1 << 20  # execd's unacked output per stream for exec_stdio
# What a pod delivers a second; past any, reading waits: no stand-in holds the loop.
PACE_FRAMES = 4096
PACE_BYTES = 128 << 20
PACE_TLS = 0.05  # CPU seconds in TLS: tiny records and messages cost more than bytes
TLS_PER_BYTE = 0.7e-9  # CPU seconds a byte delivered excuses: its decryption, no more
RAW_READ = 64 << 10  # TCP bytes decrypted between pace checks
SLICE = RAW_READ // 3 + 1  # to TLS at once: 8 KiB slowed bulk reads, 64 held the loop
PASS_CPU = 0.002  # CPU seconds after which a pass leaves the rest of them to the next
SMALL_READS = 8  # a read short of RAW_READ spends one of these; one comes back each ms
# shortcut for aws/containers-roadmap#2913: drop the gap and the cap with its fix
MESSAGE_GAP = 0.001
MESSAGE_SIZE = 64 << 10
STDIN_WINDOW = 8 << 20  # unwritten stdin in flight, so execd's queue stays small
PING_EVERY = 15.0
DEAD_AFTER = 45.0  # no frame at all for this long means the connection is gone
RECONNECT_FOR = 300.0
# A new sandbox's daemon that can't be reached this long won't be: say so soon.
FIRST_OPEN_FOR = 30.0
CONNECT_TIMEOUT = 10.0
KILL_WAIT = 10.0  # for execd's word on a call our timer has passed: then we kill
SPEAKS_WITHIN = 1.0  # a connection given up as silent, once execd answers another
TIMER_LAG = 1.0  # ours follows execd's own, which counts from the command's start


@dataclass(frozen=True)
class Daemon:
    """A started daemon: where it listens, its certificate, its key and its pod."""

    ip: str
    fingerprint: str
    key: bytes = field(repr=False)
    pod: str = ""  # the pod's UID
    # Opens an exec joined to the daemon's socket, for a pod with no network card.
    stdio: Callable[[], Awaitable[ByteStream]] | None = None


class Dropped(Exception):
    """The connection carrying a call ended before the call did."""


class NotSent(ConnectionError):
    """Nothing of a frame was written: its connection had closed."""


class DaemonRunning(Exception):
    """A start found the port taken: the daemon already started still runs."""


def _port_held() -> RuntimeError:
    return RuntimeError(
        f"execd's TCP port {EXECD_PORT} or socket in the sandbox is held by a process "
        "other than execd"
    )


class NotOurDaemon(ConnectionRefusedError):
    """The server on the port isn't the daemon this client started."""


class _Pipe:
    """TLS over TCP, decrypted here so that what a peer's records cost is paced."""

    def __init__(
        self,
        reader: asyncio.StreamReader | _Stdio,
        writer: asyncio.StreamWriter | _Stdio,
        context: ssl.SSLContext,
        pace: Pace,
    ) -> None:
        self._reader = reader
        self._writer = writer
        self._in, self._out = ssl.MemoryBIO(), ssl.MemoryBIO()
        self.tls = context.wrap_bio(self._in, self._out)
        self._pace = pace
        self._plain = bytearray()
        self._ended = False  # execd's close_notify is read: no more follows
        self._rest = b""  # TCP bytes a pass left undecrypted
        self._small_at = float("-inf")  # when the next small read may start
        self._transport = cast(asyncio.Transport, writer.transport)  # TCP: it reads too
        self._transport.pause_reading()  # read only while a pass waits for bytes

    async def handshake(self) -> None:
        while True:
            began, held = time.thread_time(), self._in.pending
            try:
                self.tls.do_handshake()
                break
            except ssl.SSLWantReadError:
                await self._charge(began, used=held - self._in.pending)
                await self._flush()
                self._in.write(await self._raw())
        await self._charge(began, used=held - self._in.pending)
        await self._flush()
        self._rest = self._in.read()  # what came with the handshake is read as the rest

    async def write(self, data: bytes) -> None:
        self.tls.write(data)
        await self._flush()

    async def readexactly(self, n: int) -> bytes:
        while len(self._plain) < n:
            if self._ended:  # only now: the frames read with its end are execd's last
                raise ConnectionResetError("execd ended the TLS session")
            raw = self._rest or await self._raw()
            began, had, held = time.thread_time(), len(self._plain), self._in.pending
            for i in range(0, len(raw), SLICE):
                self._in.write(raw[i : i + SLICE])
                with contextlib.suppress(ssl.SSLWantReadError):
                    while True:
                        chunk = self.tls.read(RAW_READ)  # a record at a time
                        if not chunk:
                            self._ended = True
                            break
                        self._plain += chunk
                if i + SLICE < len(raw) and time.thread_time() - began > PASS_CPU:
                    self._rest = raw[i + SLICE :]
                    break
            else:
                self._rest = b""
            # TCP bytes this pass took
            used = held + len(raw) - len(self._rest) - self._in.pending
            await self._charge(began, len(self._plain) - had, used)
        data = bytes(self._plain[:n])
        del self._plain[:n]
        return data

    async def _charge(self, began: float, delivered: int = 0, used: int = 0) -> None:
        spent = time.thread_time() - began - delivered * TLS_PER_BYTE
        padding = (used - delivered) * TLS_PER_BYTE  # bytes that delivered nothing
        await self._pace.take(0, frames=0, tls=max(spent, padding, 0.0))

    async def _raw(self) -> bytes:
        if (wait := self._small_at - time.monotonic()) > 0:
            await asyncio.sleep(wait)
        self._transport.resume_reading()
        try:
            raw = await self._reader.read(RAW_READ)
        finally:
            self._transport.pause_reading()
        if not raw:
            raise ConnectionResetError("execd closed the connection")
        if len(raw) < RAW_READ:  # bytes come slower than they're read: wait for more
            burst = time.monotonic() - SMALL_READS / 1000
            self._small_at = max(self._small_at, burst) + 0.001
        return raw

    async def _flush(self) -> None:
        self._writer.write(self._out.read())
        await self._writer.drain()

    async def close(self) -> None:
        self._writer.transport.abort()  # a peer that stopped reading can't hold it open


_closing: set[asyncio.Future[None]] = set()  # held until their execs have closed


class _Stdio:
    """An exec's stdio, as the reader, writer and transport _Pipe has of TCP."""

    def __init__(self, stdio: ByteStream) -> None:
        self._stdio = stdio
        self._out = bytearray()
        self._written, self._taken = asyncio.Event(), asyncio.Event()
        self._closed = False
        self.transport = self
        self._sender = asyncio.ensure_future(self._send())

    async def read(self, n: int) -> bytes:
        try:
            return await self._stdio.receive(n)
        except (
            anyio.EndOfStream,
            anyio.BrokenResourceError,
            anyio.ClosedResourceError,
        ):
            return b""  # as a socket reads its end

    def write(self, data: bytes) -> None:
        self._out += data
        self._written.set()

    async def drain(self) -> None:
        while len(self._out) > RAW_READ and not self._closed:
            self._taken.clear()
            await self._taken.wait()
        if self._closed:
            raise ConnectionResetError("the exec that reaches execd ended")

    async def _send(self) -> None:
        """A message at a time: what is written meanwhile goes in the next ones."""
        try:
            while True:
                await self._written.wait()
                self._written.clear()
                while self._out:
                    data = bytes(self._out[:MESSAGE_SIZE])
                    del self._out[:MESSAGE_SIZE]
                    self._taken.set()
                    await self._stdio.send(data)
                    # A timer takes a busy loop up to three turns a message: yield once.
                    due = time.monotonic() + MESSAGE_GAP
                    await asyncio.sleep(0)
                    if (left := due - time.monotonic()) > 0:
                        await asyncio.sleep(left)
        except (anyio.BrokenResourceError, anyio.ClosedResourceError):
            self.abort()  # the reader sees the end, as of a port reset under a write

    def pause_reading(self) -> None:
        """Nothing to pause: an exec is read only when read() asks."""

    resume_reading = pause_reading

    def is_closing(self) -> bool:
        return self._closed

    def abort(self) -> None:
        if not self._closed:
            self._closed = True
            self._sender.cancel()
            self._taken.set()
            closing = asyncio.ensure_future(self._stdio.aclose())
            _closing.add(closing)
            closing.add_done_callback(_closing.discard)


async def _connect(daemon: Daemon, pace: Pace) -> _Pipe:
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    # The certificate is self-signed: it is trusted by its fingerprint, below.
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    context.minimum_version = ssl.TLSVersion.TLSv1_3
    # One group: a stand-in can't pick a 150 ms one. Python 3.10 can't set X25519.
    context.set_ecdh_curve("prime256v1")

    # Before the timeout: its exec waits its turn among the pod's operations.
    stdio = None if daemon.stdio is None else _Stdio(await daemon.stdio())

    async def handshake() -> _Pipe:
        reader, writer = (
            (stdio, stdio)
            if stdio
            else await asyncio.open_connection(daemon.ip, EXECD_PORT)
        )
        pipe = _Pipe(reader, writer, context, pace)
        try:
            await pipe.handshake()
        except BaseException:
            await pipe.close()
            raise
        return pipe

    pipe = await asyncio.wait_for(handshake(), CONNECT_TIMEOUT)
    cert = pipe.tls.getpeercert(binary_form=True) or b""
    if hashlib.sha256(cert).hexdigest() != daemon.fingerprint:
        await pipe.close()
        # Not the daemon this client started, so it gets no key: start another.
        raise NotOurDaemon("the server on the execd port is not our daemon")
    return pipe


@dataclass
class Call:
    id: int
    daemon: Daemon
    queue: asyncio.Queue[tuple[int, bytes] | Exception] = field(
        default_factory=asyncio.Queue
    )
    got: list[int] = field(default_factory=lambda: [0, 0])
    taken: list[int] = field(default_factory=lambda: [0, 0])  # by the caller
    acked: int = 0
    stdin_put: int = 0  # stdin execd has written to the process
    stdin_sent: int = 0  # stdin sent to execd: more can't have been written
    stdin_room: asyncio.Event = field(default_factory=asyncio.Event)
    closed: bool = False  # left by its caller
    exited: bool = False
    words: int = 0  # EXIT and ERROR frames queued that its loop has yet to take
    resuming: bool = False  # a RESUME awaits its one RESUMED
    ends: int = 0  # bytes of EXIT and ERROR frames queued: execd sends one per resume
    hold: int = HOLD
    ack_every: int = ACK_EVERY
    # When its START was last written: execd counts the timeout from the start.
    started: float = field(default_factory=lambda: time.monotonic())
    starts: int = 0  # how often: one that is written is with execd, or will be


@dataclass
class Strays:
    """Frames that report nothing new, per pod: a reconnect doesn't reset the count."""

    since: float = float("-inf")
    frames: int = 0
    size: int = 0

    def over(self, n: int) -> bool:
        now = time.monotonic()
        if now - self.since > PING_EVERY:
            self.since, self.frames, self.size = now, 0, 0
        self.frames += 1
        self.size += n
        return self.frames > MAX_STRAY or self.size > MAX_STRAY_BYTES


@dataclass
class Pace:
    """What a pod sent this second: frames for its calls, their bytes, TLS's cost."""

    since: float = float("-inf")
    frames: int = 0
    size: int = 0
    tls: float = 0.0

    async def take(self, n: int, frames: int = 1, tls: float = 0.0) -> None:
        now = time.monotonic()
        if now - self.since >= 1.0:
            self.since, self.frames, self.size, self.tls = now, 0, 0, 0.0
        self.frames += frames
        self.size += n
        self.tls += tls
        if self.frames > PACE_FRAMES or self.size > PACE_BYTES or self.tls > PACE_TLS:
            await asyncio.sleep(self.since + 1.0 - now)
        else:  # a timer after a costly pass: tasks whose own timers came due run first
            await asyncio.sleep(0.001 if tls > PASS_CPU else 0)


class Link:
    """One authenticated connection; a reader task routes frames to calls by id."""

    def __init__(
        self,
        pipe: _Pipe,
        daemon: Daemon,
        strays: Strays,
        pace: Pace,
        owed: dict[int, tuple[int, ...]],
        pod: Callable[[], str],
    ) -> None:
        self.pipe = pipe
        self.daemon = daemon
        self._pod = pod  # the pod's UID now
        self.strays = strays
        self.pace = pace
        self.owed = owed
        self.confirmed = asyncio.Event()  # set by each PONG, and when this closes
        self._released: list[int] = []  # ids, since the last PING
        self._pinged: list[list[int]] = []  # those each unanswered PING followed
        self.calls: dict[int, Call] = {}
        self.closed = False
        self.ready: asyncio.Future[None] = asyncio.get_running_loop().create_future()
        self._wlock = asyncio.Lock()
        self.bulk = asyncio.Lock()
        self._last_rx = time.monotonic()
        self._tasks = [
            asyncio.create_task(self._read()),
            asyncio.create_task(self._ping()),
        ]
        self._last: set[asyncio.Task[None]] = set()  # held until sent

    async def send(
        self, kind: int, call_id: int, payload: bytes = b"", by: float | None = None
    ) -> None:
        # Only a START or STDIN waits its turn: any other frame has one ahead at most.
        turn = self.bulk if kind in (START, STDIN) else contextlib.nullcontext()
        async with turn, self._wlock:
            if self.pipe._writer.transport.is_closing():  # close() aborts it too
                raise NotSent("execd connection closed")
            data = HEADER.pack(kind, call_id, len(payload)) + payload

            async def write() -> bool:
                if kind == START:
                    # In the write's own step: wait_for may run it a turn on.
                    if self.daemon.pod != self._pod():  # replaced meanwhile
                        await self.close()
                        raise NotSent("execd connection closed")
                    now = time.monotonic()
                    if by is not None and now >= by:
                        return False
                    c = self.calls[call_id]
                    c.started, c.starts = now, c.starts + 1
                await self.pipe.write(data)
                return True

            try:
                sent = await asyncio.wait_for(write(), DEAD_AFTER)
            except asyncio.TimeoutError:
                # a peer that stopped reading must not hold the lock other calls need
                await self.close()
                raise ConnectionError("execd stopped reading") from None
            if not sent:  # a START whose turn came once its call's time was up
                raise asyncio.TimeoutError
            if kind == RELEASE:
                self._released.append(call_id)
            elif kind == PING:
                self._pinged.append(self._released)
                self._released = []

    def send_last(
        self, call_id: int, *kinds: int, payload: bytes = b""
    ) -> asyncio.Task[None]:
        """Send a call's frames in a task of their own, held until they are sent."""

        async def send() -> None:
            with contextlib.suppress(OSError):
                for kind in kinds:
                    await self.send(kind, call_id, payload)

        task = asyncio.create_task(send())
        self._last.add(task)
        task.add_done_callback(self._last.discard)
        return task

    async def _read(self) -> None:
        reader = self.pipe
        frames = 0
        try:
            while True:
                frames += 1
                if frames % 256 == 0:  # let callers take what is queued
                    await asyncio.sleep(0)
                kind, call_id, n = HEADER.unpack(await reader.readexactly(HEADER.size))
                if n > (MAX_FRAME if kind in (STDOUT, STDERR) else MAX_CONTROL) or (
                    kind == STDIN_ACK and n > MAX_ACK
                ):
                    return
                payload = await reader.readexactly(n)
                self._last_rx = time.monotonic()
                c = self.calls.get(call_id)
                if kind == EXIT and c is not None:
                    c.exited = True
                    c.stdin_room.set()  # a send waiting for room sees the exit
                put = json.loads(payload)["stdin"] if kind == STDIN_ACK else 0
                if kind == PONG and self._pinged:  # execd read what its PING followed
                    for released in self._pinged.pop(0):
                        self.owed.pop(released, None)
                    self.confirmed.set()
                if kind == OK and not self.ready.done():
                    self.ready.set_result(None)
                elif (
                    kind == STDIN_ACK
                    and c is not None
                    and c.stdin_put < put <= c.stdin_sent
                ):
                    # A call's first ack is not counted, as its streams' first frames.
                    await self.pace.take(n, frames=int(c.stdin_put > 0))
                    c.stdin_put = put
                    c.stdin_room.set()
                elif c is not None and (
                    kind in (EXIT, ERROR)
                    or (kind in (STDOUT, STDERR) and n)
                    or (kind == RESUMED and c.resuming)
                ):
                    # Counted: a stream's frames after its first; calls bound the rest.
                    more = kind in (STDOUT, STDERR) and c.got[kind - STDOUT] > 0
                    await self.pace.take(n, frames=int(more))
                    # Checked before counting it, so a resume asks for it again.
                    if c.queue.qsize() >= MAX_QUEUED:  # tiny or control frames, too
                        return
                    if kind in (EXIT, ERROR):
                        c.ends += n
                        if c.ends > 4 * MAX_CONTROL:
                            return
                        c.words += 1
                    if kind in (STDOUT, STDERR):
                        if sum(c.got) + n - sum(c.taken) > c.hold:
                            return
                        c.got[kind - STDOUT] += n
                    if kind == RESUMED:
                        c.resuming = False
                    c.queue.put_nowait((kind, payload))
                elif self.strays.over(n):  # a pong, a repeated ack, anything unused
                    return
        except (OSError, ValueError, LookupError, TypeError):  # not execd's frames
            pass
        finally:
            await self.close()

    async def _ping(self) -> None:
        # Intervals with no frame, not seconds: while our own loop is held, none passes.
        quiet, last = 0, self._last_rx
        while not self.closed:
            await asyncio.sleep(PING_EVERY)
            quiet, last = (quiet + 1 if self._last_rx == last else 0), self._last_rx
            if quiet * PING_EVERY >= DEAD_AFTER:
                await self.close()
                return
            try:
                await self.send(PING, 0)
            except OSError:
                await self.close()
                return

    async def close(self) -> None:
        if self.closed:
            return
        self.closed = True
        self.confirmed.set()
        if not self.ready.done():
            self.ready.set_exception(Dropped("connection closed before auth"))
            self.ready.exception()  # retrieved: an open that timed out no longer waits
        for c in self.calls.values():
            c.queue.put_nowait(Dropped(self))
            c.stdin_room.set()  # a sender waiting for room sees the close
        current = asyncio.current_task()
        for t in self._tasks:
            if t is not current:
                t.cancel()
        with contextlib.suppress(Exception):
            await self.pipe.close()


class ExecdClient:
    """Runs commands through one pod's execd, on one connection reopened as needed."""

    def __init__(
        self,
        start: Callable[[bool], Awaitable[Daemon]],
        pod: Callable[[], str] = lambda: "",
    ) -> None:
        # start(replace) execs execd; replace stops a daemon this client never reached
        self._start = start
        self._pod = pod  # the pod's UID now: a replaced pod may run on, with its daemon
        self._daemon: Daemon | None = None
        self._link: Link | None = None
        self._opening: asyncio.Future[Link] | None = None  # one at a time, shared
        self._since = float("inf")  # the last ask of the calls that share the opening
        self._strays = Strays()
        self._pace = Pace()
        self._opened = float("-inf")
        self._backoff = 0.0
        self._failed: BaseException | None = None  # why the open under way last failed
        self._owed: dict[int, tuple[int, ...]] = {}  # a call's last frames, by its id

    async def _open(self, deadline: float, until: float = float("inf")) -> Link:
        """Open a connection; until: the end of a call asking for a silent one."""
        # A connection dropped soon after it opened waits as a failed attempt would.
        recent = time.monotonic() - self._opened < PING_EVERY
        delay = self._backoff if recent else 0.0
        while True:
            # Paced, so a daemon that can't be reached isn't restarted in a tight loop.
            await asyncio.sleep(delay)
            delay = min(max(delay * 2, 0.2), 5.0)
            link = None
            try:
                if self._daemon is None:
                    try:
                        self._daemon = await self._start(True)  # none here is ours
                    except DaemonRunning as e:  # even past --replace: not execd
                        raise _port_held() from e
                daemon = self._daemon
                pipe = await _connect(daemon, self._pace)
                old = self._link
                # One still open that speaks in our own turns is kept: slow, not lost.
                grace = 1000 * min(SPEAKS_WITHIN, (until - time.monotonic()) / 2)
                while old and not old.pipe._writer.transport.is_closing():
                    if old._last_rx > self._since:
                        await pipe.close()
                        return old
                    if grace <= 0:
                        break
                    # Whole ms, 10 a turn: a loop's timer takes up to the next ms.
                    await asyncio.sleep(min(int(grace), 10) / 1000)
                    grace -= 10
                link = Link(
                    pipe, daemon, self._strays, self._pace, self._owed, self._pod
                )
                await link.send(AUTH, 0, daemon.key)
                await asyncio.wait_for(asyncio.shield(link.ready), CONNECT_TIMEOUT)
                if daemon.pod != self._pod():  # replaced as this opened
                    raise Dropped("the daemon's pod was replaced")
                # Set now: a caller arriving before the waiters wake opens no other.
                self._link, self._opened, self._backoff = link, time.monotonic(), delay
                if old is not None:  # execd serves its newest alone: its calls resume
                    await old.close()
                async with link.bulk:  # no START or STDIN goes between what is owed
                    await self._replay(link)
                return link
            except (Dropped, OSError, asyncio.TimeoutError) as e:
                self._failed = e
                if link is not None:
                    await link.close()
                # One still open was silent, not lost: asked about once, it serves on.
                old = self._link
                silent = old and not old.pipe._writer.transport.is_closing()
                if silent or time.monotonic() > deadline:
                    raise ConnectionError(f"execd unreachable: {e!r}") from e
                # a start tells gone from unreachable; a daemon not ours is replaced
                not_ours = isinstance(e, NotOurDaemon)
                try:
                    self._daemon = await self._start(not_ours)
                except DaemonRunning:
                    if not_ours:  # what holds the port isn't execd: it won't let go
                        raise _port_held() from e
                except Exception as failed:
                    # Only a deleted pod: a start can fail and its daemon run on.
                    gone = isinstance(failed, ApiException) and failed.status == 404
                    if self._link is None or gone or isinstance(failed, K8sError):
                        raise
                    self._failed = failed  # the daemon may run on: its calls can resume

    async def leave_replaced(self) -> None:
        """Forget a daemon whose pod was replaced, and drop its connection."""
        if self._daemon is not None and self._daemon.pod != self._pod():
            self._daemon = None
            if self._link is not None:
                await self._link.close()

    def _over(self, link: Link, call_id: int, *kinds: int) -> None:
        """Send a call's last frames, now and until a PONG follows its RELEASE."""
        self._owed[call_id] = kinds
        if len(self._owed) % (MAX_OWED // 2) == 0:  # the next PING may be 15 s off
            kinds += (PING,)
        to = link if not link.closed else self._link
        if to is not None and not to.closed:
            to.send_last(call_id, *kinds)

    async def _replay(self, link: Link) -> None:
        """Send again, on each new connection, the last frames no PONG has followed."""
        with contextlib.suppress(OSError):  # dropped again: the next one sends them
            for call_id, kinds in list(self._owed.items()):
                for kind in kinds:  # a daemon ignores ids not its own
                    await link.send(kind, call_id)
            if self._owed:
                await link.send(PING, 0)

    def _opens(
        self, wait: float, since: float = float("inf"), until: float = float("inf")
    ) -> asyncio.Future[Link]:
        """The open under way, begun here if none is; since, until: of a call asking."""
        if self._opening is None or self._opening.done():
            self._failed, self._since = None, since
            opening = self._open(time.monotonic() + wait, until)
            self._opening = asyncio.ensure_future(opening)
            # Retrieved here, as no caller may still wait when it fails.
            self._opening.add_done_callback(lambda f: f.cancelled() or f.exception())
        return self._opening

    async def _get(self, stale: Link | None = None) -> Link:
        await self.leave_replaced()  # its check may have been cancelled, or not be back
        link = self._link
        if link is not None and link is not stale and not link.closed:
            return link
        # Shared: callers wait on one open; a new call gives up on a reopen sooner.
        opening = self._opens(FIRST_OPEN_FOR if link is None else RECONNECT_FOR)
        new_call = stale is None and link is not None
        await asyncio.wait({opening}, timeout=FIRST_OPEN_FOR if new_call else None)
        if not opening.done():
            raise ConnectionError(f"execd unreachable: {self._failed!r}")
        self._link = opening.result()
        return self._link

    async def run(
        self,
        argv: list[str],
        *,
        env: dict[str, str],
        cwd: str | None,
        user: str | None,
        stdin: bytes | None,
        timeout: float | None,
    ) -> AsyncGenerator[tuple[int, Any], None]:
        """Yield output, (PING, None) at our timer, then (EXIT, status) if one comes."""
        tag = os.urandom(8).hex()
        request: dict[str, Any] = {
            "argv": argv,
            "env": env,
            "cwd": cwd or "",
            "user": _named(user),
            "stdin": stdin is not None,
            "tag": tag,
            "timeout": timeout or 0,  # execd kills it then, even if we're cut off
        }
        start = json.dumps(request).encode()
        link = await self._get()
        # One end across connections.
        end = time.monotonic() + DEAD_AFTER + PING_EVERY + CONNECT_TIMEOUT
        while len(self._owed) >= MAX_OWED:  # execd's PONGs are on their way
            if not link.closed:  # else it is set for good, and the next one is opened
                link.confirmed.clear()
            try:
                await asyncio.wait_for(link.confirmed.wait(), end - time.monotonic())
                if link.closed:
                    link = await asyncio.wait_for(self._get(), end - time.monotonic())
            except asyncio.TimeoutError:  # a peer that answers no PING is not execd
                raise ConnectionError("execd has not confirmed its calls") from None
        # No START is written past it.
        late = None if timeout is None else time.monotonic() + timeout
        call = Call(int.from_bytes(os.urandom(8), "big") >> 1, link.daemon)
        link.calls[call.id] = call

        # Past our timer (asked) we wait for execd's word until end; at probe, ask anew.
        never = float("inf")
        asked = end = probe = never

        def left() -> float | None:  # until our timer, counted as execd does; then end
            if timeout is None:
                return None
            ours = end if end < never else call.started + timeout + TIMER_LAG
            return max(0.0, ours - time.monotonic())

        def turn() -> float | None:  # until our loop has a deadline to see to
            wait = left()
            return wait if wait is None else min(wait, probe - time.monotonic())

        def ask() -> None:  # our timer has passed: execd is asked for its word
            nonlocal asked, end, probe
            asked = time.monotonic()
            end, probe = asked + KILL_WAIT, asked + KILL_WAIT / 2
            # No KILL: execd's own timeout ends it. Not waited for.
            link.send_last(call.id, PING)

        sender: asyncio.Task[None] | None = None
        finished = False
        try:
            try:
                try:
                    first = link.send(START, call.id, start, late)
                    await asyncio.wait_for(first, timeout)
                except NotSent:
                    raise
                except asyncio.TimeoutError:
                    if not call.starts:  # out of time behind a write: not a drop
                        raise
                except OSError:  # it may have left: the resume asks execd
                    call.queue.put_nowait(Dropped(link))
                sender = asyncio.create_task(self._upload(link, call, stdin, 0))
                while True:
                    try:
                        # Past our timer execd's word that has come is always taken.
                        wait = None if call.words and end < never else turn()
                        item = await _next(call.queue, wait)
                    except asyncio.TimeoutError:
                        now = time.monotonic()
                        if end == never:  # our timer
                            ask()
                            yield PING, None
                        elif now >= end:
                            if not call.words:  # else once more, for the word that came
                                break
                        elif now - probe >= 1:  # our loop was held: what came is unread
                            probe = now + 1
                        elif now >= probe:
                            probe = never  # asked once
                            if link._last_rx < asked:
                                # Silent since: one opened in its place closes it.
                                self._opens(RECONNECT_FOR, asked, end)
                                # Joined: what answered an earlier ask is not ours.
                                self._since = max(self._since, asked)
                        continue
                    if isinstance(item, Dropped):
                        if item.args != (link,):  # a connection the call has left since
                            continue
                        sender.cancel()
                        link.calls.pop(call.id, None)
                        # No shield: _get waits without cancelling the shared reopen.
                        try:
                            link = await asyncio.wait_for(self._get(stale=link), left())
                            self._resume(link, call)
                        except Exception as e:
                            if end < never:  # execd out of reach: our timer's word
                                break
                            if not isinstance(e, asyncio.TimeoutError):
                                raise
                            call.queue.put_nowait(item)  # asked again past our timer
                        continue
                    assert isinstance(item, tuple)
                    kind, payload = item
                    if kind in (STDOUT, STDERR):
                        if end == never and left() == 0.0:  # our timer passed, unseen
                            ask()
                            yield PING, None
                        yield kind, payload
                        await _taken(link, call, kind, len(payload), turn())
                    elif kind == EXIT:
                        finished = True  # no KILL: it has ended
                        self._over(link, call.id, RELEASE)
                        status = json.loads(payload)
                        code, why = status.get("code"), status.get("error", "")
                        if (
                            type(code) is not int
                            or not 0 <= code <= 255
                            or type(why) is not str
                        ):
                            raise ValueError(f"not an exit status: {payload!r}")
                        yield EXIT, status
                        return
                    elif kind == RESUMED:  # send the stdin it didn't get
                        got = json.loads(payload)
                        call.stdin_put = max(call.stdin_put, got["put"])
                        if stdin is not None and not got["eof"]:
                            # Clamped: a stand-in can't loop or resend what's written.
                            offset = int(
                                min(max(got["stdin"], call.stdin_put), len(stdin))
                            )
                            sender.cancel()
                            sender = asyncio.create_task(
                                self._upload(link, call, stdin, offset)
                            )
                    elif (
                        kind == ERROR
                        and payload == b"unknown call"
                        and call.resuming
                        and not any(call.got)
                        and not call.stdin_put
                    ):
                        # The same daemon never got the START: nothing ran, so start it.
                        call.resuming = False
                        call.words -= 1
                        written = call.starts
                        try:
                            again = link.send(START, call.id, start, late)
                            # Past it none is written, so its turn is not waited for.
                            within = None if late is None else late - time.monotonic()
                            await asyncio.wait_for(again, within)
                        except asyncio.TimeoutError:
                            if call.starts == written:  # out of time: nothing starts
                                raise
                        except OSError:  # dropped again: the next resume asks once more
                            call.queue.put_nowait(Dropped(link))
                            continue
                        sender = asyncio.create_task(self._upload(link, call, stdin, 0))
                    elif kind == ERROR:
                        raise ExecdResultUnknownError(
                            f"execd: {payload.decode(errors='replace')}",
                            pod=link.daemon.ip,
                        )
            except asyncio.TimeoutError as e:  # the builtin one, also on Python 3.10
                raise TimeoutError(f"Command timed out after {timeout}s.") from e
            except (K8sError, ExecResultUnknownError):
                raise  # a restart found while reconnecting, or already the answer
            except Exception as e:  # a lost connection, or a restart that failed
                if sender is None and isinstance(e, NotSent):
                    raise  # the START never left, so nothing ran: it is retried
                stopped = self._daemon is not call.daemon  # another was started since
                raise (ExecdStoppedError if stopped else ExecdResultUnknownError)(
                    f"execd connection lost during the command: {e!r}",
                    pod=link.daemon.ip,
                ) from e
        finally:
            call.closed = True  # the cancel alone can be lost before Python 3.12
            if sender is not None:
                sender.cancel()
            try:
                if not finished:  # left by its caller, or timed out
                    self._over(link, call.id, KILL, RELEASE)
            finally:
                link.calls.pop(call.id, None)

    async def _upload(
        self, link: Link, call: Call, stdin: bytes | None, offset: int
    ) -> None:
        if stdin is None:
            return
        with contextlib.suppress(OSError):  # the reader sees the drop
            for i in range(offset, len(stdin), CHUNK):
                await _window(link, call, i)
                # Before the send: its ack can be read before this task runs again.
                call.stdin_sent = max(call.stdin_sent, min(i + CHUNK, len(stdin)))
                await link.send(STDIN, call.id, stdin[i : i + CHUNK])
            await link.send(STDIN, call.id)  # an empty frame closes stdin

    def _resume(self, link: Link, call: Call) -> None:
        """Ask execd, over a new connection, to send the call on from what we have."""
        if link.daemon is not call.daemon:
            raise ExecdStoppedError(
                "execd stopped while it ran the command", pod=call.daemon.ip
            )
        link.calls[call.id] = call
        at = json.dumps({"stdout": call.got[0], "stderr": call.got[1]})
        call.resuming = True  # before the RESUMED can arrive

        async def send() -> None:
            try:
                await link.send(RESUME, call.id, at.encode())
            except OSError:  # dropped again before it left: once more
                call.queue.put_nowait(Dropped(link))

        # In a task of its own: the call reads on, within its time, while this waits.
        task = asyncio.create_task(send())
        link._last.add(task)
        task.add_done_callback(link._last.discard)
        log_warn("execd connection lost: resuming", pod=call.daemon.ip)

    async def exec(
        self,
        cmd: list[str],
        stdin: str | bytes | None,
        cwd: str | None,
        env: dict[str, str],
        user: str | None,
        timeout: int | None,
    ) -> ExecResult[str]:
        """Pod.exec(), over execd: the same results and errors."""
        data = stdin.encode() if isinstance(stdin, str) else stdin
        out = {STDOUT: LimitedBuffer(limits.MAX_EXEC_OUTPUT_SIZE)}
        out[STDERR] = LimitedBuffer(limits.MAX_EXEC_OUTPUT_SIZE)
        status = None
        asked = False  # our timer has passed: execd is asked for its word
        timeout = timeout or None  # 0 is none, as coreutils' `timeout 0` is
        run = self.run(cmd, env=env, cwd=cwd, user=user, stdin=data, timeout=timeout)
        async with contextlib.aclosing(run) as chunks:
            async for kind, payload in chunks:
                if kind == EXIT:
                    status = payload
                    break
                if kind == PING:
                    asked = True
                    continue
                out[kind].append(payload)
                if out[kind].truncated and not asked:
                    break
        timed_out = status is None or status.get("timeout")  # our timer's, or execd's
        truncated = out[STDOUT].truncated or out[STDERR].truncated
        # Too much past our timer may be a killed command's last: then it timed out.
        if truncated and not (asked and timed_out):
            raise OutputLimitExceededError(
                limit_str=limits.MAX_EXEC_OUTPUT_SIZE_STR,
                truncated_output=str(out[STDOUT]) + str(out[STDERR]),
            )
        if status is None or timed_out:
            raise TimeoutError(f"Command timed out after {timeout}s.")
        code = status["code"]
        result = ExecResult(
            success=code == 0,
            returncode=code,
            stdout=str(out[STDOUT]),
            stderr=str(out[STDERR]),
        )
        if code == 126 and "permission denied" in result.stderr.casefold():
            raise PermissionError(f"Permission denied executing command. {result}")
        error = status.get("error", "")  # execd's, only if the command never started
        if error.startswith("unknown user"):
            raise RuntimeError(
                f"The user parameter '{user}' provided to exec() does not appear to "
                f"exist in the container. Docs: {EXEC_USER_URL}\n"
                f"{result.stderr[-_STDERR_TAIL_BYTES:]}"
            )
        if error.startswith("cannot run as"):
            logger.warning(
                "exec(user=%r) failed: the container is not running as root, so it "
                "cannot switch users. Docs: %s\n%s",
                user,
                EXEC_USER_URL,
                result.stderr[-_STDERR_TAIL_BYTES:],
            )
        return result

    async def write_file(self, data: bytes, dst: Path) -> None:
        """Pod.write_file(), over execd: cat, which gets EOF here; the same errors."""
        script = (
            f"PATH={SYSTEM_PATH}; mkdir -p -- {shlex.quote(dst.parent.as_posix())} "
            f"&& cat > {shlex.quote(dst.as_posix())}"
        )
        stderr = LimitedBuffer(limits.MAX_EXEC_OUTPUT_SIZE)
        code = await self._file_op(["/bin/sh", "-c", script], data, None, stderr)
        if code != 0:
            said = str(stderr)  # once: 10 MiB of it holds the event loop 100 ms
            raise_for_known_read_write_errors(said)
            raise PodError(
                "Unrecognised error writing file to pod.",
                returncode=code,
                stderr=said,
            )

    async def read_file(self, src: Path, dst: IO[bytes]) -> None:
        """Pod.read_file(), over execd: the same command, limit and errors."""
        stderr = LimitedBuffer(limits.MAX_EXEC_OUTPUT_SIZE)
        code = await self._file_op(read_command(src), None, dst, stderr)
        if code != 0:
            said = str(stderr)  # once: 10 MiB of it holds the event loop 100 ms
            raise_for_known_read_write_errors(said)
            raise PodError(
                "Unrecognised error reading file from pod.",
                returncode=code,
                stderr=said,
            )
        dst.flush()

    async def _file_op(
        self,
        cmd: list[str],
        stdin: bytes | None,
        dst: IO[bytes] | None,
        stderr: LimitedBuffer,
    ) -> int:
        start = None if dst is None else dst.tell()
        unread = 0  # a write's stdout
        run = self.run(cmd, env={}, cwd=None, user=None, stdin=stdin, timeout=None)
        async with contextlib.aclosing(run) as chunks:
            async for kind, payload in chunks:
                if kind == EXIT:
                    if payload.get("error"):  # execd's: nothing ran to tell of the file
                        raise PodError(
                            "execd could not start the file operation.",
                            error=payload["error"],
                        )
                    return payload["code"]
                if kind == STDERR:
                    stderr.append(payload)
                elif dst is not None and start is not None:
                    dst.write(payload)
                    if dst.tell() - start > limits.MAX_READ_FILE_SIZE:
                        raise OutputLimitExceededError(
                            limit_str=limits.MAX_READ_FILE_SIZE_STR,
                            truncated_output=None,
                        )
                else:
                    unread += len(payload)
                # As exec() does: past it, output could arrive for ever.
                if stderr.truncated or unread > limits.MAX_EXEC_OUTPUT_SIZE:
                    raise OutputLimitExceededError(
                        limit_str=limits.MAX_EXEC_OUTPUT_SIZE_STR,
                        truncated_output=None,
                    )
        raise PodError("execd ended the file operation without an exit code")

    async def open_stream(
        self,
        argv: list[str],
        user: str | None,
        restarted: Callable[[], Exception | None] | None = None,
    ) -> ExecdStream:
        """Start a command whose stdin and stdout are a byte stream (exec_stdio)."""
        user = _named(user)
        link = await self._get()
        call = Call(
            int.from_bytes(os.urandom(8), "big") >> 1,
            link.daemon,
            hold=2 * (STREAM_WINDOW + CHUNK),
            ack_every=STREAM_WINDOW // 4,
        )
        link.calls[call.id] = call
        request = {
            "argv": argv,
            "env": {},
            "cwd": "",
            "user": user,
            "stdin": True,
            "tag": os.urandom(8).hex(),
            "stream": True,  # never resumed: execd kills it if the connection drops
        }
        try:
            await link.send(START, call.id, json.dumps(request).encode())
        except BaseException:
            link.calls.pop(call.id, None)
            link.send_last(call.id, KILL, RELEASE)  # the START may have gone out
            raise
        return ExecdStream(link, call, restarted)


def _named(user: str | None) -> str:
    """The user to ask execd for: "" is none to execd, and no user to a caller."""
    if user == "":  # runuser refuses it over Kubernetes exec
        raise RuntimeError(f"exec() was given an empty user. Docs: {EXEC_USER_URL}")
    return user or ""


async def _next(
    queue: asyncio.Queue[tuple[int, bytes] | Exception], timeout: float | None
) -> tuple[int, bytes] | Exception:
    """queue.get() within timeout; before 3.12 wait_for costs a loop turn per item."""
    if timeout is not None and timeout <= 0:  # at a deadline: its loop sees to it
        raise asyncio.TimeoutError
    if not queue.empty():
        return queue.get_nowait()
    return await asyncio.wait_for(queue.get(), timeout)


async def _window(link: Link, call: Call, sent: int) -> None:
    """Wait until the call has room for more stdin in flight."""
    while True:
        if link.closed or call.closed or call.exited:
            raise ConnectionError("execd connection closed, or the command exited")
        if sent - call.stdin_put < STDIN_WINDOW:
            return
        call.stdin_room.clear()
        await call.stdin_room.wait()


async def _taken(
    link: Link, call: Call, kind: int, n: int, within: float | None = None
) -> None:
    """Count output the caller took, and acknowledge it, so execd sends more."""
    call.taken[kind - STDOUT] += n
    if sum(call.taken) - call.acked >= call.ack_every:
        call.acked = sum(call.taken)
        offsets = {"stdout": call.taken[0], "stderr": call.taken[1]}
        # In a task of its own: out of time it is waited for no longer, and still goes.
        ack = link.send_last(call.id, ACK, payload=json.dumps(offsets).encode())
        with contextlib.suppress(asyncio.TimeoutError):
            await asyncio.wait_for(asyncio.shield(ack), within)


class ExecdStream(ByteStream):
    """A command's stdin and stdout over execd; a dropped connection ends it."""

    def __init__(
        self,
        link: Link,
        call: Call,
        restarted: Callable[[], Exception | None] | None,
    ) -> None:
        self._link = link
        self._call = call
        self._restarted = restarted  # the restart found since the stream opened, if any
        self._stdout = bytearray()
        self._ended: BaseException | None = None
        self._closed = False
        self._sent = 0
        self._send_lock = asyncio.Lock()  # one item's chunks at a time
        self._wrote = False
        self._stderr = b""

    async def receive(self, max_bytes: int = 65536) -> bytes:
        if max_bytes < 1:
            raise ValueError("max_bytes must be at least 1")
        await anyio.lowlevel.checkpoint()  # held output would be given out with no wait
        if self._closed:
            raise anyio.ClosedResourceError
        self._drop_if_restarted()
        while not self._stdout:
            if self._closed:
                raise anyio.ClosedResourceError
            if self._ended is not None:
                raise self._ended
            item = await self._call.queue.get()
            if isinstance(item, Exception):
                self._ended = anyio.BrokenResourceError("execd connection lost")
            elif item[0] in (STDOUT, STDERR):
                if item[0] == STDOUT:
                    self._stdout += item[1]
                    self._wrote = True
                else:
                    self._stderr = (self._stderr + item[1])[-_STDERR_TAIL_BYTES:]
                await _taken(self._link, self._call, item[0], len(item[1]))
            elif item[0] == EXIT:
                self._ended = anyio.EndOfStream()
                if not self._wrote:  # it failed to start, as PodStdio reports it
                    log_warn(
                        "An exec_stdio command ended before writing to stdout.",
                        status=item[1].decode(errors="replace"),
                        stderr=self._stderr,
                    )
                elif self._stderr:
                    log_trace(
                        "An exec_stdio command wrote to stderr.", stderr=self._stderr
                    )
            elif item[0] == ERROR:
                self._ended = anyio.BrokenResourceError(
                    item[1].decode(errors="replace")
                )
        self._drop_if_restarted()  # also for output that came while this waited
        data = bytes(self._stdout[:max_bytes])
        del self._stdout[:max_bytes]
        return data

    def _drop_if_restarted(self) -> None:
        """Fail as a lost connection does if a restart was found, as PodStdio does."""
        if self._restarted is not None and (error := self._restarted()) is not None:
            self._call.queue.put_nowait(Dropped())  # a waiting receive() ends too
            raise anyio.BrokenResourceError(repr(error)) from error

    async def send(self, item: bytes) -> None:
        if self._closed:
            raise anyio.ClosedResourceError
        async with self._send_lock:
            await _land_pending_cancel()  # also one that came as it waited for the lock
            self._drop_if_restarted()
            try:
                for i in range(0, len(item), CHUNK):
                    await _window(self._link, self._call, self._sent)
                    self._sent += min(CHUNK, len(item) - i)
                    self._call.stdin_sent = self._sent  # before the send, as _upload
                    await self._link.send(STDIN, self._call.id, item[i : i + CHUNK])
            except OSError as e:
                raise anyio.BrokenResourceError(repr(e)) from e
            except asyncio.CancelledError:
                await self.aclose()  # an item cut short would corrupt the next
                raise

    async def send_eof(self) -> None:
        with contextlib.suppress(OSError):
            await self._link.send(STDIN, self._call.id)

    async def aclose(self) -> None:
        if self._closed:
            return
        self._closed = True
        self._call.closed = True
        self._call.stdin_room.set()  # a send waiting for room sees the close
        self._call.queue.put_nowait(Dropped())  # and so does a receive
        self._link.calls.pop(self._call.id, None)
        self._link.send_last(self._call.id, KILL, RELEASE)
