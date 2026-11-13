"""Commands and file transfer over TLS to execd in the sandbox, never exec stdin."""

from __future__ import annotations

import asyncio
import contextlib
import hashlib
import json
import logging
import re
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

from k8s_sandbox._logger import log_trace, log_warn
from k8s_sandbox._pod.buffer import LimitedBuffer
from k8s_sandbox._pod.error import ExecResultUnknownError, PodError
from k8s_sandbox._pod.execute import (
    _STDERR_TAIL_BYTES,
    EXEC_USER_URL,
    _land_pending_cancel,
)
from k8s_sandbox._pod.op import SYSTEM_PATH, raise_for_known_read_write_errors
from k8s_sandbox._pod.read import read_command

logger = logging.getLogger(__name__)

ANNOTATION = "inspect-k8s-sandbox/execd"
EXECD_PATH = "/execd/execd"  # directly under /: root can't rename a mountpoint there
EXECD_PORT = 24601

# Frames: a type and a length, then the payload. A connection carries one call.
AUTH, START, STDIN = 1, 2, 3
STDOUT, STDERR, EXIT, PING = 17, 18, 19, 20
HEADER = struct.Struct(">BI")
CHUNK = 256 << 10  # the most output execd puts in a frame, and stdin the client does
MOST = {STDOUT: CHUNK, STDERR: CHUNK, EXIT: 4096, PING: 0}  # a frame's payload
RAW_READ = 64 << 10  # TCP bytes taken at a time
DEAD_AFTER = 45.0  # execd pings every 15 s: this long without a byte, it is gone
CONNECT_TIMEOUT = 10.0
KILL_WAIT = 10.0  # past a call's timeout, for execd to say it killed the command


@dataclass(frozen=True)
class Daemon:
    """A started daemon: where it listens, its certificate and its key."""

    ip: str
    port: int
    fingerprint: str
    key: bytes = field(repr=False)


class DaemonRunning(Exception):
    """A start found the port taken: the daemon already started still runs."""


def start_command(key: bytes, replace: bool) -> list[str]:
    """The exec that starts execd; with REPLACE, it first stops one that runs."""
    cmd = [EXECD_PATH, "listen", "--port", str(EXECD_PORT)]
    cmd += ["--key-sha256", hashlib.sha256(key).hexdigest()]
    return cmd + ["--replace"] if replace else cmd


def started(ip: str, key: bytes, code: int, stdout: bytes, stderr: bytes) -> Daemon:
    """The daemon that a start exec's exit code and output tell of."""
    if b"address already in use" in stderr:
        raise DaemonRunning(stderr.decode(errors="replace"))
    # Exactly the fingerprint execd prints: anything else, cut output too, fails.
    if code != 0 or not re.fullmatch(rb"[0-9a-f]{64}\n", stdout):
        raise PodError("execd did not start", returncode=code, stderr=stderr)
    return Daemon(ip, EXECD_PORT, stdout.decode().strip(), key)


class NotOurDaemon(ConnectionRefusedError):
    """The server on the port isn't the daemon this client started."""


class NotExecd(RuntimeError):
    """What answers on a pod's execd port sent what execd never does."""


_TLS = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
# The certificate is self-signed: it is trusted by its fingerprint, in _connect.
_TLS.check_hostname = False
_TLS.verify_mode = ssl.CERT_NONE
_TLS.minimum_version = ssl.TLSVersion.TLSv1_3


class _Conn:
    """One call's connection; TLS is decrypted here, so what a peer sends is counted."""

    def __init__(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        client: ExecdClient,
    ) -> None:
        self._reader = reader
        self._writer = writer
        self.client = client
        self._in, self._out = ssl.MemoryBIO(), ssl.MemoryBIO()
        self.tls = _TLS.wrap_bio(self._in, self._out)
        self._opened = time.monotonic()
        self._raw = 0  # TCP bytes read
        self._reads = self._records = self._frames = 0
        self._header = b""  # the start of a TLS record's header, cut by a read's end
        self._body = 0  # how much of a TLS record the next reads hold
        self.pinned = False  # whether its certificate is the daemon's
        self._plain = bytearray()  # decrypted, and not yet a whole frame

    async def handshake(self) -> None:
        while True:
            try:
                self.tls.do_handshake()
                break
            except ssl.SSLWantReadError:
                await self._flush()
                await self._fill()
            except ssl.SSLError as e:  # what answers doesn't speak TLS, as execd does
                raise NotOurDaemon(f"the server on the execd port: {e}") from e
        await self._flush()

    def write(self, kind: int, payload: bytes = b"") -> None:
        """Queue a frame, without waiting for the socket to take it."""
        self.client.check()
        self.tls.write(HEADER.pack(kind, len(payload)) + payload)
        self._writer.write(self._out.read())

    async def send(self, kind: int, payload: bytes = b"") -> None:
        self.write(kind, payload)
        await self._writer.drain()

    async def frame(self) -> tuple[int, bytes]:
        """Read the next frame; one execd would not send breaks the client."""
        while True:
            await self._hold(HEADER.size)
            kind, n = HEADER.unpack_from(self._plain)
            if n > MOST.get(kind, -1):
                raise self._broken(f"a frame of type {kind} and {n} bytes")
            await self._hold(HEADER.size + n)
            self.client.check()  # another connection broke it while this one waited
            payload = bytes(self._plain[HEADER.size : HEADER.size + n])
            del self._plain[: HEADER.size + n]
            self._frames += 1
            if kind != PING:
                return kind, payload

    def status(self, payload: bytes) -> dict[str, Any]:
        """Parse an EXIT: {"code": n[, "error": why][, "timeout": true]}."""
        with contextlib.suppress(ValueError, LookupError, TypeError, RecursionError):
            status = json.loads(payload)
            fields = (
                status["code"],
                status.get("error", ""),
                status.get("timeout", False),
            )
            if tuple(map(type, fields)) == (int, str, bool):
                return status
        raise self._broken("an EXIT that is not a status")

    async def _hold(self, n: int) -> None:
        """Decrypt until N bytes are held; a wait that is cancelled loses none."""
        while len(self._plain) < n:
            try:
                piece = self.tls.read(n - len(self._plain))  # a record at a time
            except ssl.SSLWantReadError:
                await self._fill()
                continue
            if not piece:
                raise ConnectionResetError("execd ended the TLS session")
            self._plain += piece

    async def _fill(self) -> None:
        """Give TLS more of what the peer sent, if it is still within execd's bounds."""
        # Ten times execd's most: two frames a millisecond, and what full ones carry.
        spare = 10 * (64 + 2000 * (time.monotonic() - self._opened))
        for count, unit, what in (
            (self._frames, CHUNK, "frames"),
            (self._records, 16384, "TLS records"),
            (self._reads, 1448, "TCP reads"),
        ):
            if count > spare + 10 * self._raw / unit:
                raise self._broken(f"{count} {what} in {self._raw} bytes")
        for last in (False, True):
            try:
                read = self._reader.read(RAW_READ)
                raw = await asyncio.wait_for(read, DEAD_AFTER / 2)
                break
            except asyncio.TimeoutError:
                # A busy loop can time out a read whose bytes have come: look again.
                if last:
                    raise ConnectionResetError("execd went silent") from None
        if not raw:
            raise ConnectionResetError("execd closed the connection")
        self._raw += len(raw)
        self._reads += 1
        records = self._header + raw
        at = self._body
        while at + 5 <= len(records):  # a header ends with its record's length
            self._records += 1
            at += 5 + int.from_bytes(records[at + 3 : at + 5], "big")
        self._header, self._body = records[at:], max(0, at - len(records))
        self._in.write(raw)

    def _broken(self, what: str) -> Exception:
        self.close()
        if not self.pinned:  # anyone can answer on the port: only our daemon is trusted
            return NotOurDaemon(f"the server on the execd port sent {what}")
        self.client.broken = (
            f"The server on the sandbox's execd port is not execd: it sent {what}. "
            "Its sandbox can no longer be used."
        )
        return NotExecd(self.client.broken)

    async def _flush(self) -> None:
        self._writer.write(self._out.read())
        await self._writer.drain()

    def close(self) -> None:
        self._writer.transport.abort()  # a peer that stopped reading can't hold it open


async def _connect(daemon: Daemon, client: ExecdClient, start: bytes) -> _Conn:
    """Open a connection, check it is the daemon's, send the key and queue START."""

    async def connect() -> _Conn:
        reader, writer = await asyncio.open_connection(daemon.ip, daemon.port)
        conn = _Conn(reader, writer, client)
        try:
            await conn.handshake()
            cert = conn.tls.getpeercert(binary_form=True) or b""
            if hashlib.sha256(cert).hexdigest() != daemon.fingerprint:
                # Not the daemon this client started, so it gets no key: start another.
                raise NotOurDaemon("the server on the execd port is not our daemon")
            conn.pinned = True
            await conn.send(AUTH, daemon.key)
            # Not waited on: the call's reads find a daemon that stops reading.
            conn.write(START, start)
        except BaseException:
            conn.close()
            raise
        return conn

    return await asyncio.wait_for(connect(), CONNECT_TIMEOUT)


async def _upload(conn: _Conn, stdin: bytes) -> None:
    with contextlib.suppress(OSError, NotExecd):  # the reader sees either
        for i in range(0, len(stdin), CHUNK):
            await conn.send(STDIN, stdin[i : i + CHUNK])
            await asyncio.sleep(0)  # so other work runs between chunks
        await conn.send(STDIN)  # an empty frame closes stdin


class ExecdClient:
    """Runs commands through one pod's execd, each on a connection of its own."""

    def __init__(self, start: Callable[[bool], Awaitable[Daemon]]) -> None:
        # start(replace) execs execd; replace stops one that isn't this client's
        self._start = start
        self._daemon: Daemon | None = None
        self._starting = asyncio.Lock()
        self.broken: str | None = None  # why nothing is sent or started again

    async def _open(self, request: dict[str, Any]) -> _Conn:
        """Connect and start a call; nothing was sent to a command if this raises."""
        start = json.dumps(request).encode()
        daemon = self._daemon or await self._restart(None)
        try:
            return await self._dial(daemon, start)
        except (OSError, asyncio.TimeoutError) as e:
            # A start tells a daemon that is gone from one that can't be reached.
            daemon = await self._restart(daemon, e)
        try:
            return await self._dial(daemon, start)
        except (OSError, asyncio.TimeoutError) as e:
            raise ConnectionError(f"execd unreachable: {e!r}") from e

    def check(self) -> None:
        if self.broken:
            raise NotExecd(self.broken)

    async def _dial(self, daemon: Daemon, start: bytes) -> _Conn:
        self.check()
        return await _connect(daemon, self, start)

    async def _restart(
        self, old: Daemon | None, why: BaseException | None = None
    ) -> Daemon:
        """Start a daemon in OLD's place, unless another call already has."""
        async with self._starting:
            self.check()  # broken while this call connected or waited: no new start
            if self._daemon is old:
                # Any execd there before this client's first, or that isn't its own.
                replace = old is None or isinstance(why, NotOurDaemon)
                try:
                    self._daemon = await self._start(replace)
                except DaemonRunning as e:
                    if replace:  # even past --replace: not execd
                        raise RuntimeError(
                            f"TCP port {EXECD_PORT} in the sandbox is held by a "
                            "process other than execd"
                        ) from e
                    raise ConnectionError(f"execd unreachable: {why!r}") from e
            assert self._daemon is not None
            return self._daemon

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
        """Yield (STDOUT|STDERR, bytes), then (EXIT, execd's status)."""
        request: dict[str, Any] = {
            "argv": argv,
            "env": env,
            "cwd": cwd or "",
            "user": user or "",
            "stdin": stdin is not None,
            "timeout": timeout or 0,  # execd kills it then, and says so
        }
        conn = await self._open(request)
        sender: asyncio.Task[None] | None = None
        try:
            if stdin is not None:
                sender = asyncio.create_task(_upload(conn, stdin))
            # Only for an execd that doesn't end the command at its timeout.
            end = time.monotonic() + timeout + KILL_WAIT if timeout else None
            while True:
                left = None if end is None else max(0.0, end - time.monotonic())
                kind, payload = await asyncio.wait_for(conn.frame(), left)
                if kind == EXIT:
                    yield EXIT, conn.status(payload)
                    return
                yield kind, payload
        except asyncio.TimeoutError as e:  # the builtin one, also on Python 3.10
            raise TimeoutError(f"Command timed out after {timeout}s.") from e
        except NotExecd:
            raise
        except Exception as e:  # a lost connection: the command may have run
            raise ExecResultUnknownError(
                f"execd connection lost during the command: {e!r}"
            ) from e
        finally:
            if sender is not None:
                sender.cancel()
            conn.close()  # execd kills a command whose connection closes first

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
        out = {k: LimitedBuffer(limits.MAX_EXEC_OUTPUT_SIZE) for k in (STDOUT, STDERR)}
        status: dict[str, Any] = {}
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
        if status.get("timeout"):
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
        try:
            wrote = await self.exec(
                ["/bin/sh", "-c", script], data, None, {}, None, None
            )
        except ExecResultUnknownError as e:
            raise PodError(str(e)) from e  # unlike a command, it may be run again
        if not wrote.success:
            raise_for_known_read_write_errors(wrote.stderr)
            raise PodError(
                "Unrecognised error writing file to pod.",
                returncode=wrote.returncode,
                stderr=wrote.stderr,
            )

    async def read_file(self, src: Path, dst: IO[bytes]) -> None:
        """Pod.read_file(), over execd: the same command, limits and errors."""
        start, stderr = dst.tell(), LimitedBuffer(limits.MAX_EXEC_OUTPUT_SIZE)
        code = None
        run = self.run(
            read_command(src), env={}, cwd=None, user=None, stdin=None, timeout=None
        )
        try:
            async with contextlib.aclosing(run) as chunks:
                async for kind, payload in chunks:
                    if kind == EXIT:
                        code = payload["code"]
                    elif kind == STDERR:
                        stderr.append(payload)
                    else:
                        dst.write(payload)
                    if stderr.truncated:  # as exec() does: it could come for ever
                        raise OutputLimitExceededError(
                            limit_str=limits.MAX_EXEC_OUTPUT_SIZE_STR,
                            truncated_output=None,
                        )
                    if dst.tell() - start > limits.MAX_READ_FILE_SIZE:
                        raise OutputLimitExceededError(
                            limit_str=limits.MAX_READ_FILE_SIZE_STR,
                            truncated_output=None,
                        )
        except ExecResultUnknownError as e:
            raise PodError(str(e)) from e  # unlike a command, it may be run again
        if code != 0:
            raise_for_known_read_write_errors(str(stderr))
            raise PodError(
                "Unrecognised error reading file from pod.",
                returncode=code,
                stderr=str(stderr),
            )
        dst.flush()

    async def open_stream(
        self,
        argv: list[str],
        user: str | None,
        restarted: Callable[[], Exception | None],
    ) -> ExecdStream:
        """Start a command whose stdin and stdout are a byte stream (exec_stdio)."""
        request = {
            "argv": argv,
            "user": user or "",
            "stdin": True,
            "stream": True,  # when its connection ends, execd kills only the command
        }
        return ExecdStream(await self._open(request), restarted)


class ExecdStream(ByteStream):
    """A command's stdin and stdout over execd; it ends with its connection."""

    def __init__(self, conn: _Conn, restarted: Callable[[], Exception | None]) -> None:
        self._conn = conn
        self._restarted = restarted  # the restart found since it opened, if any
        self._stdout = bytearray()
        self._ended: BaseException | None = None
        self._closed = False
        self._send_lock = asyncio.Lock()  # one item's chunks at a time
        self._wrote = False
        self._stderr = b""

    async def receive(self, max_bytes: int = 65536) -> bytes:
        if max_bytes < 1:
            raise ValueError("max_bytes must be at least 1")
        await _land_pending_cancel()  # before it takes output its caller won't get
        if self._closed:
            raise anyio.ClosedResourceError
        self._drop_if_restarted()
        while not self._stdout:
            if self._closed:  # while it waited
                raise anyio.ClosedResourceError
            if self._ended is not None:
                raise self._ended
            try:
                kind, payload = await self._conn.frame()
            except OSError as e:
                self._ended = anyio.BrokenResourceError(f"execd connection lost: {e!r}")
                continue
            if kind == STDOUT:
                self._stdout += payload
                self._wrote = True
            elif kind == STDERR:
                self._stderr = (self._stderr + payload)[-_STDERR_TAIL_BYTES:]
            else:  # EXIT
                self._conn.status(payload)
                self._ended = anyio.EndOfStream()
                if not self._wrote:  # it failed to start, as PodStdio reports it
                    log_warn(
                        "An exec_stdio command ended before writing to stdout.",
                        status=payload.decode(errors="replace"),
                        stderr=self._stderr,
                    )
                elif self._stderr:
                    log_trace(
                        "An exec_stdio command wrote to stderr.", stderr=self._stderr
                    )
        # Once its pod can't be used, not even output already read is given out.
        self._conn.client.check()
        self._drop_if_restarted()
        data = bytes(self._stdout[:max_bytes])
        del self._stdout[:max_bytes]
        return data

    def _drop_if_restarted(self) -> None:
        """End the stream if a restart was found since it opened, as PodStdio does."""
        if (error := self._restarted()) is not None:
            self._conn.close()
            raise anyio.BrokenResourceError(repr(error)) from error

    async def send(self, item: bytes) -> None:
        async with self._send_lock:
            await _land_pending_cancel()  # also one that came as it waited for the lock
            if self._closed:
                raise anyio.ClosedResourceError
            self._drop_if_restarted()
            if self._ended is not None:
                raise anyio.BrokenResourceError("the command has ended")
            try:
                for i in range(0, len(item), CHUNK):
                    await self._conn.send(STDIN, item[i : i + CHUNK])
            except OSError as e:
                raise anyio.BrokenResourceError(repr(e)) from e

    async def send_eof(self) -> None:
        async with self._send_lock:
            self._drop_if_restarted()
            with contextlib.suppress(OSError):
                await self._conn.send(STDIN)

    async def aclose(self) -> None:
        self._closed = True
        self._conn.close()  # execd ends the command's stdin and kills it
