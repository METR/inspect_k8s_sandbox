"""Commands and file transfer over the pod network, to execd in the sandbox container.

A pod annotated ``inspect-k8s-sandbox/execd: "true"`` has execd (``execd/`` in this
repo) at EXECD_PATH and admits TCP to EXECD_PORT from this client. The first operation
starts the daemon with one exec that carries no stdin, then connects to it over TLS,
pinned to the certificate fingerprint the start printed, and authenticates with a key
whose hash the start passed. Every command, file write and read then goes over that
connection: none crosses exec stdin. A refused connection means the daemon is gone (a
root agent can kill it), so the next one starts another, with a new key.

All calls share one connection; each call's frames carry its id. A call's processes
belong to the daemon, which buffers their output until it is acknowledged, so a
connection that drops while the daemon lives loses nothing: the call resumes on a new
one from the byte offsets already received.
"""

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

from k8s_sandbox._pod.buffer import LimitedBuffer
from k8s_sandbox._pod.error import ExecResultUnknownError, PodError
from k8s_sandbox._pod.op import SYSTEM_PATH, raise_for_known_read_write_errors

logger = logging.getLogger(__name__)

ANNOTATION = "inspect-k8s-sandbox/execd"
EXECD_PATH = "/opt/execd/execd"
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
# execd holds output until acked, and pauses the command past 32 MiB per stream.
ACK_EVERY = 4 << 20
# Output a call may hold here that its caller hasn't taken: past it, the peer ignores
# the acks (it isn't execd), and the connection is dropped.
HOLD = 2 * ((32 << 20) + CHUNK)
MAX_QUEUED = 4096  # frames, of any kind
# Stdin a call may have in flight beyond what execd has written to the process, so the
# daemon's queue (in the sandbox's memory) stays small for any size of input.
STDIN_WINDOW = 8 << 20
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
        raise ConnectionRefusedError("the server on the execd port is not our daemon")
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
    stdin_room: asyncio.Event = field(default_factory=asyncio.Event)


class Link:
    """One authenticated connection; a reader task routes frames to calls by id."""

    def __init__(self, pipe: _Pipe, daemon: Daemon) -> None:
        self.pipe = pipe
        self.daemon = daemon
        self.calls: dict[int, Call] = {}
        self.closed = False
        self.ready: asyncio.Future[dict[str, Any]] = (
            asyncio.get_running_loop().create_future()
        )
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
            except TimeoutError:
                # A peer that stopped reading must not hold the lock, and with it
                # every other call's frames, timeouts and pings.
                await self.close()
                raise ConnectionError("execd stopped reading") from None

    async def _read(self) -> None:
        reader = self.pipe.reader
        try:
            while True:
                kind, call_id, n = HEADER.unpack(await reader.readexactly(HEADER.size))
                if n > MAX_FRAME:
                    return
                payload = await reader.readexactly(n)
                self._last_rx = time.monotonic()
                if kind == OK and not self.ready.done():
                    self.ready.set_result(json.loads(payload))
                elif (c := self.calls.get(call_id)) is not None and kind == STDIN_ACK:
                    c.stdin_put = max(c.stdin_put, json.loads(payload)["stdin"])
                    c.stdin_room.set()
                elif (c := self.calls.get(call_id)) is not None and kind != PONG:
                    if kind in (STDOUT, STDERR):
                        c.got[kind - STDOUT] += len(payload)
                        if sum(c.got) - sum(c.taken) > HOLD:
                            return
                    if c.queue.qsize() >= MAX_QUEUED:  # tiny or control frames, too
                        return
                    c.queue.put_nowait((kind, payload))
        except (asyncio.IncompleteReadError, ConnectionError, OSError, ValueError):
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
            except (ConnectionError, OSError):
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
        # Starts a daemon (one exec) and says where it is; it also checks the pod for
        # a restart, which a new daemon would otherwise hide. Its argument says to
        # replace any daemon already running: one this client never reached.
        self._start = start
        self._daemon: Daemon | None = None
        self._link: Link | None = None
        self._lock = asyncio.Lock()

    async def _open(self, deadline: float) -> Link:
        delay = 0.2
        while True:
            try:
                if self._daemon is None:
                    self._daemon = await self._start(self._link is None)
                daemon = self._daemon
                link = Link(await _connect(daemon), daemon)
                await link.send(AUTH, 0, daemon.key)
                await asyncio.wait_for(asyncio.shield(link.ready), CONNECT_TIMEOUT)
                return link
            except (Dropped, ConnectionError, OSError, TimeoutError) as e:
                if time.monotonic() > deadline:
                    raise ConnectionError(f"execd unreachable: {e!r}") from e
                # Gone (a root agent can kill it, or its container restarted) or out of
                # reach: a start tells which, as a live daemon keeps its port.
                with contextlib.suppress(DaemonRunning):
                    self._daemon = await self._start(self._link is None)
                    continue
                await asyncio.sleep(delay)
                delay = min(delay * 2, 5.0)

    async def _get(self, stale: Link | None = None) -> Link:
        async with self._lock:
            if self._link is None or self._link is stale or self._link.closed:
                wait = FIRST_OPEN_FOR if self._link is None else RECONNECT_FOR
                self._link = await self._open(time.monotonic() + wait)
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
        """Yield (STDOUT or STDERR, bytes) as they come, then (EXIT, code).

        The code is None if the call timed out (it is killed first). Once the START
        may have been sent, a lost connection or daemon raises ExecResultUnknownError,
        which is not retried: the command may have run.
        """
        tag = os.urandom(8).hex()
        request: dict[str, Any] = {
            "argv": argv,
            "env": env,
            "cwd": cwd or "",
            "user": user or "",
            "stdin": stdin is not None,
            "tag": tag,
        }
        start = json.dumps(request).encode()
        deadline = None if timeout is None else time.monotonic() + timeout
        link = await self._get()
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
                        item = await asyncio.wait_for(call.queue.get(), left)
                    except TimeoutError:
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
                        await link.send(RESUME, call.id, json.dumps(offsets).encode())
                        continue
                    assert isinstance(item, tuple)
                    kind, payload = item
                    if kind in (STDOUT, STDERR):
                        yield kind, payload
                        await _taken(link, call, kind, len(payload))
                    elif kind == EXIT:
                        finished = True
                        with contextlib.suppress(ConnectionError, OSError):
                            await link.send(RELEASE, call.id)
                        yield EXIT, int(json.loads(payload)["code"])
                        return
                    elif kind == RESUMED:  # send whatever stdin the daemon did not get
                        got = json.loads(payload)
                        call.stdin_put = max(call.stdin_put, got["put"])
                        if stdin is not None and not got["eof"]:
                            sender = asyncio.create_task(
                                self._upload(link, call, stdin, int(got["stdin"]))
                            )
                    elif (
                        kind == ERROR
                        and payload == b"unknown call"
                        and not any(call.got)
                    ):
                        # The same daemon never got the START: nothing ran, so start it.
                        await link.send(START, call.id, start)
                        sender = asyncio.create_task(self._upload(link, call, stdin, 0))
                    elif kind == ERROR:
                        raise ExecResultUnknownError(
                            f"execd: {payload.decode(errors='replace')}",
                            pod=link.daemon.ip,
                        )
            except TimeoutError:
                raise
            except OSError as e:  # ConnectionError too
                raise ExecResultUnknownError(
                    f"execd connection lost during the command: {e!r}",
                    pod=link.daemon.ip,
                ) from e
        finally:
            if sender is not None:
                sender.cancel()
            if not finished and not link.closed:
                # Abandoned by the caller (an output limit, a cancel): stop it.
                with contextlib.suppress(ConnectionError, OSError):
                    await link.send(KILL, call.id)
                    await link.send(RELEASE, call.id)
            link.calls.pop(call.id, None)

    async def _upload(
        self, link: Link, call: Call, stdin: bytes | None, offset: int
    ) -> None:
        if stdin is None:
            return
        with contextlib.suppress(ConnectionError, OSError):  # the reader sees the drop
            for i in range(offset, len(stdin), CHUNK):
                await _window(link, call, i)
                await link.send(STDIN, call.id, stdin[i : i + CHUNK])
            await link.send(STDIN, call.id)  # an empty frame closes stdin

    async def _kill(self, link: Link, call: Call) -> None:
        """Kill the call's processes and wait briefly for its exit."""
        try:
            await link.send(KILL, call.id)
            end = time.monotonic() + KILL_WAIT
            while time.monotonic() < end:
                item = await asyncio.wait_for(call.queue.get(), end - time.monotonic())
                if isinstance(item, tuple) and item[0] == EXIT:
                    break
            await link.send(RELEASE, call.id)
        except (ConnectionError, OSError, TimeoutError):
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
        code = None
        run = self.run(cmd, env=env, cwd=cwd, user=user, stdin=data, timeout=timeout)
        async with contextlib.aclosing(run) as chunks:
            async for kind, payload in chunks:
                if kind == EXIT:
                    code = payload
                    break
                out[kind].append(payload)
                if out[kind].truncated:
                    raise OutputLimitExceededError(
                        limit_str=limits.MAX_EXEC_OUTPUT_SIZE_STR,
                        truncated_output=str(out[STDOUT]) + str(out[STDERR]),
                    )
        if code is None:
            raise TimeoutError(f"Command timed out after {timeout}s.")
        result = ExecResult(
            success=code == 0,
            returncode=code,
            stdout=str(out[STDOUT]),
            stderr=str(out[STDERR]),
        )
        # execd's own errors start "execd: " (it reports them as a shell would).
        if code == 126 and "permission denied" in result.stderr.casefold():
            raise PermissionError(f"Permission denied executing command. {result}")
        if result.stderr.startswith("execd: unknown user"):
            raise RuntimeError(
                f"The user parameter '{user}' provided to exec() does not appear to "
                f"exist in the container.\n{result.stderr}"
            )
        if result.stderr.startswith("execd: cannot run as"):
            logger.warning(
                "exec(user=%r) failed: the container is not running as root, so it "
                "cannot switch users.\n%s",
                user,
                result.stderr,
            )
        return result

    async def write_file(self, data: bytes, dst: Path) -> None:
        """Pod.write_file(), over execd: the same command and errors."""
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
        cmd = [
            "/bin/sh",
            "-c",
            f'PATH={SYSTEM_PATH}; exec head -c "$1" -- "$2"',
            "sh",
            str(limits.MAX_READ_FILE_SIZE + 1),
            src.as_posix(),
        ]
        stderr = LimitedBuffer(limits.MAX_EXEC_OUTPUT_SIZE)
        code = await self._file_op(cmd, None, dst, stderr)
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
        try:
            run = self.run(cmd, env={}, cwd=None, user=None, stdin=stdin, timeout=None)
            async with contextlib.aclosing(run) as chunks:
                async for kind, payload in chunks:
                    if kind == EXIT:
                        return payload
                    if kind == STDERR:
                        stderr.append(payload)
                    elif dst is not None and start is not None:
                        dst.write(payload)
                        if dst.tell() - start > limits.MAX_READ_FILE_SIZE:
                            raise OutputLimitExceededError(
                                limit_str=limits.MAX_READ_FILE_SIZE_STR,
                                truncated_output=None,
                            )
        except ExecResultUnknownError as e:
            # Unlike a command, a file operation may be run again.
            raise PodError(str(e)) from e
        raise PodError("execd ended the file operation without an exit code")

    async def open_stream(self, argv: list[str], user: str | None) -> ExecdStream:
        """Start a command whose stdin and stdout are a byte stream (exec_stdio)."""
        link = await self._get()
        call = Call(int.from_bytes(os.urandom(8), "big") >> 1, link.daemon)
        link.calls[call.id] = call
        request = {
            "argv": argv,
            "env": {},
            "cwd": "",
            "user": user or "",
            "stdin": True,
            "tag": os.urandom(8).hex(),
        }
        await link.send(START, call.id, json.dumps(request).encode())
        return ExecdStream(link, call)


async def _window(link: Link, call: Call, sent: int) -> None:
    """Wait until the call has room for more stdin in flight."""
    while sent - call.stdin_put >= STDIN_WINDOW:
        call.stdin_room.clear()
        if link.closed:
            raise ConnectionError("execd connection closed")
        await call.stdin_room.wait()


async def _taken(link: Link, call: Call, kind: int, n: int) -> None:
    """Count output the caller took, and acknowledge it, so execd sends more."""
    call.taken[kind - STDOUT] += n
    if sum(call.taken) - call.acked >= ACK_EVERY:
        call.acked = sum(call.taken)
        offsets = {"stdout": call.taken[0], "stderr": call.taken[1]}
        with contextlib.suppress(ConnectionError, OSError):
            await link.send(ACK, call.id, json.dumps(offsets).encode())


class ExecdStream(ByteStream):
    """A command's stdin and stdout over execd.

    It is not resumed: a dropped connection ends it, as a lost exec stream does.
    """

    def __init__(self, link: Link, call: Call) -> None:
        self._link = link
        self._call = call
        self._stdout = bytearray()
        self._ended: BaseException | None = None
        self._closed = False
        self._sent = 0

    async def receive(self, max_bytes: int = 65536) -> bytes:
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
                await _taken(self._link, self._call, item[0], len(item[1]))
            elif item[0] == EXIT:
                self._ended = anyio.EndOfStream()
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
        try:
            for i in range(0, len(item), CHUNK):
                await _window(self._link, self._call, self._sent)
                await self._link.send(STDIN, self._call.id, item[i : i + CHUNK])
                self._sent += len(item[i : i + CHUNK])
        except (ConnectionError, OSError) as e:
            raise anyio.BrokenResourceError(repr(e)) from e

    async def send_eof(self) -> None:
        with contextlib.suppress(ConnectionError, OSError):
            await self._link.send(STDIN, self._call.id)

    async def aclose(self) -> None:
        if self._closed:
            return
        self._closed = True
        self._link.calls.pop(self._call.id, None)
        with contextlib.suppress(ConnectionError, OSError):
            await self._link.send(KILL, self._call.id)
            await self._link.send(RELEASE, self._call.id)
