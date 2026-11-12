"""Commands and file transfer over TLS to execd in the sandbox, never exec stdin."""

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
from typing import IO, Any

import anyio
from anyio.abc import ByteStream
from inspect_ai.util import ExecResult, OutputLimitExceededError
from inspect_ai.util import SandboxEnvironmentLimits as limits

from k8s_sandbox._error import K8sError
from k8s_sandbox._logger import log_trace, log_warn
from k8s_sandbox._pod.buffer import LimitedBuffer
from k8s_sandbox._pod.error import ExecResultUnknownError, PodError
from k8s_sandbox._pod.execute import _STDERR_TAIL_BYTES, EXEC_USER_URL
from k8s_sandbox._pod.op import SYSTEM_PATH, raise_for_known_read_write_errors
from k8s_sandbox._pod.read import read_command

logger = logging.getLogger(__name__)

ANNOTATION = "inspect-k8s-sandbox/execd"
EXECD_PATH = "/execd/execd"  # directly under /: root can't rename a mountpoint there
EXECD_PORT = 24601

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
ACK_EVERY = 4 << 20  # execd pauses a command past 32 MiB unacked per stream
HOLD = 2 * ((32 << 20) + CHUNK)  # untaken output; past it, the peer isn't execd
MAX_QUEUED = 4096  # frames, of any kind
MAX_STRAY = 1 << 16  # frames that report nothing new, per ping interval
MAX_STRAY_BYTES = 4 * HOLD  # their payload: output still in flight for calls given up
STREAM_WINDOW = 1 << 20  # execd's unacked output per stream for exec_stdio
# What a pod delivers per second: past either, reading waits, so a stand-in can't hold
# the runner's loop. execd sends output in reads of up to 256 KiB.
PACE_FRAMES = 4096
PACE_BYTES = 128 << 20
STDIN_WINDOW = 8 << 20  # unwritten stdin in flight, so execd's queue stays small
PING_EVERY = 15.0
DEAD_AFTER = 45.0  # no frame at all for this long means the connection is gone
RECONNECT_FOR = 300.0
# A new sandbox's daemon that can't be reached this long won't be: say so soon.
FIRST_OPEN_FOR = 30.0
CONNECT_TIMEOUT = 10.0
KILL_WAIT = 10.0  # for a killed command's exit


@dataclass(frozen=True)
class Daemon:
    """A started daemon: where it listens, its certificate and its key."""

    ip: str
    fingerprint: str
    key: bytes


class Dropped(Exception):
    """The connection carrying a call ended before the call did."""


class DaemonRunning(Exception):
    """A start found the port taken: the daemon already started still runs."""


def _port_held() -> RuntimeError:
    return RuntimeError(
        f"TCP port {EXECD_PORT} in the sandbox is held by a process other than execd"
    )


class NotOurDaemon(ConnectionRefusedError):
    """The server on the port isn't the daemon this client started."""


class _Pipe:
    def __init__(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        self.reader = reader
        self._writer = writer

    async def write(self, data: bytes) -> None:
        self._writer.write(data)
        await self._writer.drain()

    async def close(self) -> None:
        self._writer.transport.abort()  # a peer that stopped reading can't hold it open


async def _connect(daemon: Daemon) -> _Pipe:
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    # The certificate is self-signed: it is trusted by its fingerprint, below.
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    context.minimum_version = ssl.TLSVersion.TLSv1_3
    reader, writer = await asyncio.wait_for(
        asyncio.open_connection(daemon.ip, EXECD_PORT, ssl=context, limit=MAX_FRAME),
        CONNECT_TIMEOUT,
    )
    cert = writer.get_extra_info("ssl_object").getpeercert(binary_form=True)
    if hashlib.sha256(cert).hexdigest() != daemon.fingerprint:
        writer.close()
        # Not the daemon this client started, so it gets no key: start another.
        raise NotOurDaemon("the server on the execd port is not our daemon")
    return _Pipe(reader, writer)


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
    closed: bool = False  # by its caller
    exited: bool = False
    resuming: bool = False  # a RESUME awaits its one RESUMED
    hold: int = HOLD
    ack_every: int = ACK_EVERY


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
    """Frames a pod delivered for its calls this second, and their bytes."""

    since: float = float("-inf")
    frames: int = 0
    size: int = 0

    async def take(self, n: int) -> None:
        now = time.monotonic()
        if now - self.since >= 1.0:
            self.since, self.frames, self.size = now, 0, 0
        self.frames += 1
        self.size += n
        if self.frames > PACE_FRAMES or self.size > PACE_BYTES:
            await asyncio.sleep(self.since + 1.0 - now)


class Link:
    """One authenticated connection; a reader task routes frames to calls by id."""

    def __init__(self, pipe: _Pipe, daemon: Daemon, strays: Strays, pace: Pace) -> None:
        self.pipe = pipe
        self.daemon = daemon
        self.strays = strays
        self.pace = pace
        self.calls: dict[int, Call] = {}
        self.closed = False
        self.ready: asyncio.Future[None] = asyncio.get_running_loop().create_future()
        self._wlock = asyncio.Lock()
        self._last_rx = time.monotonic()
        self._tasks = [
            asyncio.create_task(self._read()),
            asyncio.create_task(self._ping()),
        ]

    async def send(self, kind: int, call_id: int, payload: bytes = b"") -> None:
        async with self._wlock:
            data = HEADER.pack(kind, call_id, len(payload)) + payload
            try:
                await asyncio.wait_for(self.pipe.write(data), DEAD_AFTER)
            except asyncio.TimeoutError:
                # a peer that stopped reading must not hold the lock other calls need
                await self.close()
                raise ConnectionError("execd stopped reading") from None

    async def _read(self) -> None:
        reader = self.pipe.reader
        frames = 0
        try:
            while True:
                frames += 1
                if frames % 256 == 0:  # let callers take what is queued
                    await asyncio.sleep(0)
                kind, call_id, n = HEADER.unpack(await reader.readexactly(HEADER.size))
                if n > (MAX_FRAME if kind in (STDOUT, STDERR) else MAX_CONTROL):
                    return
                payload = await reader.readexactly(n)
                self._last_rx = time.monotonic()
                c = self.calls.get(call_id)
                if kind == EXIT and c is not None:
                    c.exited = True
                    c.stdin_room.set()  # a send waiting for room sees the exit
                put = json.loads(payload)["stdin"] if kind == STDIN_ACK else 0
                if kind == OK and not self.ready.done():
                    self.ready.set_result(None)
                elif (
                    kind == STDIN_ACK
                    and c is not None
                    and c.stdin_put < put <= c.stdin_sent
                ):
                    await self.pace.take(n)
                    c.stdin_put = put
                    c.stdin_room.set()
                elif c is not None and (
                    kind in (EXIT, ERROR)
                    or (kind in (STDOUT, STDERR) and n)
                    or (kind == RESUMED and c.resuming)
                ):
                    await self.pace.take(n)
                    # Checked before counting it, so a resume asks for it again.
                    if c.queue.qsize() >= MAX_QUEUED:  # tiny or control frames, too
                        return
                    if kind in (STDOUT, STDERR):
                        if sum(c.got) + n - sum(c.taken) > c.hold:
                            return
                        c.got[kind - STDOUT] += n
                    if kind == RESUMED:
                        c.resuming = False
                    c.queue.put_nowait((kind, payload))
                elif self.strays.over(n):  # a pong, a repeated ack, anything unused
                    return
        except (asyncio.IncompleteReadError, OSError, ValueError):
            pass
        finally:
            await self.close()

    async def _ping(self) -> None:
        while not self.closed:
            await asyncio.sleep(PING_EVERY)
            if time.monotonic() - self._last_rx > DEAD_AFTER:
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
        if not self.ready.done():
            self.ready.set_exception(Dropped("connection closed before auth"))
        for c in self.calls.values():
            c.queue.put_nowait(Dropped())
            c.stdin_room.set()  # a sender waiting for room sees the close
        current = asyncio.current_task()
        for t in self._tasks:
            if t is not current:
                t.cancel()
        with contextlib.suppress(Exception):
            await self.pipe.close()


class ExecdClient:
    """Runs commands through one pod's execd, on one connection reopened as needed."""

    def __init__(self, start: Callable[[bool], Awaitable[Daemon]]) -> None:
        # start(replace) execs execd; replace stops a daemon this client never reached
        self._start = start
        self._daemon: Daemon | None = None
        self._link: Link | None = None
        self._opening: asyncio.Future[Link] | None = None  # one at a time, shared
        self._strays = Strays()
        self._pace = Pace()
        self._opened = float("-inf")
        self._backoff = 0.0

    async def _open(self, deadline: float) -> Link:
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
                        self._daemon = await self._start(self._link is None)
                    except DaemonRunning as e:  # even past --replace: not execd
                        raise _port_held() from e
                daemon = self._daemon
                link = Link(await _connect(daemon), daemon, self._strays, self._pace)
                await link.send(AUTH, 0, daemon.key)
                await asyncio.wait_for(asyncio.shield(link.ready), CONNECT_TIMEOUT)
                # Set now: a caller arriving before the waiters wake opens no other.
                self._link, self._opened, self._backoff = link, time.monotonic(), delay
                return link
            except (Dropped, OSError, asyncio.TimeoutError) as e:
                if link is not None:
                    await link.close()
                if time.monotonic() > deadline:
                    raise ConnectionError(f"execd unreachable: {e!r}") from e
                # a start tells gone from unreachable; a daemon not ours is replaced
                not_ours = isinstance(e, NotOurDaemon)
                try:
                    self._daemon = await self._start(self._link is None or not_ours)
                except DaemonRunning:
                    if not_ours:  # what holds the port isn't execd: it won't let go
                        raise _port_held() from e

    async def _get(self, stale: Link | None = None) -> Link:
        link = self._link
        if link is not None and link is not stale and not link.closed:
            return link
        if self._opening is None or self._opening.done():
            wait = FIRST_OPEN_FOR if link is None else RECONNECT_FOR
            self._opening = asyncio.ensure_future(self._open(time.monotonic() + wait))
        # Shared: every caller waits on the one reconnect, not on a queue of them.
        self._link = await asyncio.shield(self._opening)
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
        """Yield (STDOUT|STDERR, bytes), then (EXIT, status), None if it timed out."""
        tag = os.urandom(8).hex()
        request: dict[str, Any] = {
            "argv": argv,
            "env": env,
            "cwd": cwd or "",
            "user": user or "",
            "stdin": stdin is not None,
            "tag": tag,
            "timeout": timeout or 0,  # execd kills it then, even if we're cut off
        }
        start = json.dumps(request).encode()
        link = await self._get()
        deadline = None if timeout is None else time.monotonic() + timeout
        call = Call(int.from_bytes(os.urandom(8), "big") >> 1, link.daemon)
        link.calls[call.id] = call
        sender: asyncio.Task[None] | None = None
        finished = False
        try:
            try:
                await link.send(START, call.id, start)
                sender = asyncio.create_task(self._upload(link, call, stdin, 0))
                while True:
                    left = (
                        None
                        if deadline is None
                        else max(0.0, deadline - time.monotonic())
                    )
                    try:
                        item = await _next(call.queue, left)
                    except asyncio.TimeoutError:
                        await self._kill(link, call)
                        finished = True
                        yield EXIT, None
                        return
                    if isinstance(item, Dropped):
                        sender.cancel()
                        link.calls.pop(call.id, None)
                        # Shielded: other calls may wait on the same reconnect.
                        reconnect = asyncio.shield(self._get(stale=link))
                        link = await asyncio.wait_for(reconnect, left)
                        if link.daemon is not call.daemon:
                            raise ExecResultUnknownError(
                                "execd stopped while it ran the command",
                                pod=link.daemon.ip,
                            )
                        link.calls[call.id] = call
                        offsets = {"stdout": call.got[0], "stderr": call.got[1]}
                        call.resuming = True  # before the RESUMED can arrive
                        await link.send(RESUME, call.id, json.dumps(offsets).encode())
                        continue
                    assert isinstance(item, tuple)
                    kind, payload = item
                    if kind in (STDOUT, STDERR):
                        yield kind, payload
                        await _taken(link, call, kind, len(payload))
                    elif kind == EXIT:
                        finished = True
                        with contextlib.suppress(OSError):
                            await link.send(RELEASE, call.id)
                        yield EXIT, json.loads(payload)  # {"code": n[, "error": ...]}
                        return
                    elif kind == RESUMED:  # send the stdin it didn't get
                        got = json.loads(payload)
                        call.stdin_put = max(call.stdin_put, got["put"])
                        if stdin is not None and not got["eof"]:
                            # Clamped: a stand-in's offset could loop over nothing.
                            offset = min(max(int(got["stdin"]), 0), len(stdin))
                            sender.cancel()
                            sender = asyncio.create_task(
                                self._upload(link, call, stdin, offset)
                            )
                    elif (
                        kind == ERROR
                        and payload == b"unknown call"
                        and call.resuming
                        and not any(call.got)
                    ):
                        # The same daemon never got the START: nothing ran, so start it.
                        call.resuming = False
                        await link.send(START, call.id, start)
                        sender = asyncio.create_task(self._upload(link, call, stdin, 0))
                    elif kind == ERROR:
                        raise ExecResultUnknownError(
                            f"execd: {payload.decode(errors='replace')}",
                            pod=link.daemon.ip,
                        )
            except asyncio.TimeoutError as e:  # the builtin one, also on Python 3.10
                raise TimeoutError(f"Command timed out after {timeout}s.") from e
            except (K8sError, ExecResultUnknownError):
                raise  # a restart found while reconnecting, or already the answer
            except Exception as e:  # a lost connection, or a restart that failed
                raise ExecResultUnknownError(
                    f"execd connection lost during the command: {e!r}",
                    pod=link.daemon.ip,
                ) from e
        finally:
            if sender is not None:
                sender.cancel()
            if not finished and not link.closed:
                # Abandoned by the caller (an output limit, a cancel): stop it.
                with contextlib.suppress(OSError):
                    await link.send(KILL, call.id)
                    await link.send(RELEASE, call.id)
            link.calls.pop(call.id, None)

    async def _upload(
        self, link: Link, call: Call, stdin: bytes | None, offset: int
    ) -> None:
        if stdin is None:
            return
        with contextlib.suppress(OSError):  # the reader sees the drop
            for i in range(offset, len(stdin), CHUNK):
                await _window(link, call, i)
                await link.send(STDIN, call.id, stdin[i : i + CHUNK])
                call.stdin_sent = max(call.stdin_sent, i + len(stdin[i : i + CHUNK]))
            await link.send(STDIN, call.id)  # an empty frame closes stdin

    async def _kill(self, link: Link, call: Call) -> None:
        """Kill the call's processes and wait briefly for its exit."""
        try:
            await link.send(KILL, call.id)
            end = time.monotonic() + KILL_WAIT
            while time.monotonic() < end:
                item = await _next(call.queue, end - time.monotonic())
                if isinstance(item, tuple) and item[0] == EXIT:
                    break
            await link.send(RELEASE, call.id)
        except (OSError, asyncio.TimeoutError):
            pass

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
        run = self.run(cmd, env=env, cwd=cwd, user=user, stdin=data, timeout=timeout)
        async with contextlib.aclosing(run) as chunks:
            async for kind, payload in chunks:
                if kind == EXIT:
                    status = payload
                    break
                out[kind].append(payload)
                if out[kind].truncated:
                    raise OutputLimitExceededError(
                        limit_str=limits.MAX_EXEC_OUTPUT_SIZE_STR,
                        truncated_output=str(out[STDOUT]) + str(out[STDERR]),
                    )
        if status is None:
            raise TimeoutError(f"Command timed out after {timeout}s.")
        code = int(status["code"])
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
                f"exist in the container. Docs: {EXEC_USER_URL}\n{result.stderr}"
            )
        if error.startswith("cannot run as"):
            logger.warning(
                "exec(user=%r) failed: the container is not running as root, so it "
                "cannot switch users. Docs: %s\n%s",
                user,
                EXEC_USER_URL,
                result.stderr,
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
            raise_for_known_read_write_errors(str(stderr))
            raise PodError(
                "Unrecognised error writing file to pod.",
                returncode=code,
                stderr=str(stderr),
            )

    async def read_file(self, src: Path, dst: IO[bytes]) -> None:
        """Pod.read_file(), over execd: the same command, limit and errors."""
        stderr = LimitedBuffer(limits.MAX_EXEC_OUTPUT_SIZE)
        code = await self._file_op(read_command(src), None, dst, stderr)
        if code != 0:
            raise_for_known_read_write_errors(str(stderr))
            raise PodError(
                "Unrecognised error reading file from pod.",
                returncode=code,
                stderr=str(stderr),
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
        try:
            run = self.run(cmd, env={}, cwd=None, user=None, stdin=stdin, timeout=None)
            async with contextlib.aclosing(run) as chunks:
                async for kind, payload in chunks:
                    if kind == EXIT:
                        return int(payload["code"])
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
        except ExecResultUnknownError as e:
            # Unlike a command, a file operation may be run again.
            raise PodError(str(e)) from e
        raise PodError("execd ended the file operation without an exit code")

    async def open_stream(self, argv: list[str], user: str | None) -> ExecdStream:
        """Start a command whose stdin and stdout are a byte stream (exec_stdio)."""
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
            "user": user or "",
            "stdin": True,
            "tag": os.urandom(8).hex(),
            "stream": True,  # never resumed: execd kills it if the connection drops
        }
        try:
            await link.send(START, call.id, json.dumps(request).encode())
        except BaseException:
            link.calls.pop(call.id, None)
            with contextlib.suppress(OSError):  # the START may have gone out
                await link.send(KILL, call.id)
                await link.send(RELEASE, call.id)
            raise
        return ExecdStream(link, call)


async def _next(
    queue: asyncio.Queue[tuple[int, bytes] | Exception], timeout: float | None
) -> tuple[int, bytes] | Exception:
    """queue.get() within timeout; before 3.12 wait_for costs a loop turn per item."""
    if timeout != 0 and not queue.empty():
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


async def _taken(link: Link, call: Call, kind: int, n: int) -> None:
    """Count output the caller took, and acknowledge it, so execd sends more."""
    call.taken[kind - STDOUT] += n
    if sum(call.taken) - call.acked >= call.ack_every:
        call.acked = sum(call.taken)
        offsets = {"stdout": call.taken[0], "stderr": call.taken[1]}
        with contextlib.suppress(OSError):
            await link.send(ACK, call.id, json.dumps(offsets).encode())


class ExecdStream(ByteStream):
    """A command's stdin and stdout over execd; a dropped connection ends it."""

    def __init__(self, link: Link, call: Call) -> None:
        self._link = link
        self._call = call
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
        if self._closed:
            raise anyio.ClosedResourceError
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
        data = bytes(self._stdout[:max_bytes])
        del self._stdout[:max_bytes]
        return data

    async def send(self, item: bytes) -> None:
        if self._closed:
            raise anyio.ClosedResourceError
        async with self._send_lock:
            try:
                for i in range(0, len(item), CHUNK):
                    await _window(self._link, self._call, self._sent)
                    await self._link.send(STDIN, self._call.id, item[i : i + CHUNK])
                    self._sent += len(item[i : i + CHUNK])
                    self._call.stdin_sent = self._sent
            except OSError as e:
                raise anyio.BrokenResourceError(repr(e)) from e

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
        with contextlib.suppress(OSError):
            await self._link.send(
                STDIN, self._call.id
            )  # EOF: the command may end itself
            await self._link.send(KILL, self._call.id)
            await self._link.send(RELEASE, self._call.id)
