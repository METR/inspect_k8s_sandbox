import asyncio
import contextlib
import hashlib
import io
import json
import shutil
import ssl
import subprocess
import types
from collections.abc import Awaitable, Callable
from pathlib import Path
from typing import Any

import anyio
import pytest
from inspect_ai.util import OutputLimitExceededError
from pytest import MonkeyPatch

from k8s_sandbox._helm import Release, ValuesSource
from k8s_sandbox._pod import execd
from k8s_sandbox._pod import pod as pod_module
from k8s_sandbox._pod.error import (
    ContainerRestartedError,
    ExecResultUnknownError,
    PodError,
)
from k8s_sandbox._pod.pod import Pod
from k8s_sandbox._pod.snapshot import _parse_pod

Handler = Callable[[asyncio.StreamReader, asyncio.StreamWriter], Awaitable[None]]


async def read_frame(reader: asyncio.StreamReader) -> tuple[int, bytes]:
    kind, n = execd.HEADER.unpack(await reader.readexactly(execd.HEADER.size))
    return kind, await reader.readexactly(n)


def frame(kind: int, payload: bytes = b"") -> bytes:
    return execd.HEADER.pack(kind, len(payload)) + payload


EXIT_0 = frame(execd.EXIT, b'{"code": 0}')


@pytest.fixture(scope="module")
def tls(tmp_path_factory: pytest.TempPathFactory) -> tuple[ssl.SSLContext, str]:
    """A server's TLS context, with a self-signed certificate, and the pin for it."""
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
    der = ssl.PEM_cert_to_DER_cert(cert.read_text())
    return context, hashlib.sha256(der).hexdigest()


class Daemons:
    """Stand-ins for execd, over TLS, which the client starts in turn."""

    def __init__(self, tls: tuple[ssl.SSLContext, str], monkeypatch: MonkeyPatch):
        self._context, self._pin = tls
        self._monkeypatch = monkeypatch
        self._unstarted: list[tuple[execd.Daemon, int] | Exception] = []
        self.starts: list[bool] = []  # each start's `replace`
        self.connections = 0  # that sent the key

    async def serve(self, handler: Handler, pin: str | None = None) -> asyncio.Server:
        """Add one that takes AUTH, then hands the connection to handler."""

        async def connection(r: asyncio.StreamReader, w: asyncio.StreamWriter) -> None:
            with contextlib.suppress(asyncio.IncompleteReadError, ConnectionError):
                assert await read_frame(r) == (execd.AUTH, b"key")
                self.connections += 1
                await handler(r, w)

        server = await asyncio.start_server(
            connection, "127.0.0.1", 0, ssl=self._context
        )
        daemon = execd.Daemon("127.0.0.1", pin or self._pin, b"key")
        self._unstarted.append((daemon, server.sockets[0].getsockname()[1]))
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
            daemon, port = started
            self._monkeypatch.setattr(execd, "EXECD_PORT", port)
            return daemon

        return execd.ExecdClient(start)


@pytest.fixture
def daemons(tls: tuple[ssl.SSLContext, str], monkeypatch: MonkeyPatch) -> Daemons:
    return Daemons(tls, monkeypatch)


async def exits(r: asyncio.StreamReader, w: asyncio.StreamWriter) -> None:
    await read_frame(r)  # START
    w.write(EXIT_0)


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


async def test_an_annotated_pod_runs_every_operation_over_execd(
    daemons: Daemons, monkeypatch: MonkeyPatch
) -> None:
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


async def test_a_lost_exec_raises_the_restart_that_explains_it(
    daemons: Daemons, monkeypatch: MonkeyPatch
) -> None:
    async def dies_after_start(
        r: asyncio.StreamReader, w: asyncio.StreamWriter
    ) -> None:
        await read_frame(r)
        w.close()

    await daemons.serve(dies_after_start)
    pod = Pod("p", "ns", None, "default", "u", 0, "raise", execd=True)
    assert pod._execd is not None
    pod._execd._start = daemons.client()._start
    restarted = ContainerRestartedError(
        pod_name="p", container_name="default", restart_count=1, last_reason="OOMKilled"
    )

    def check(info: object) -> None:
        raise restarted

    monkeypatch.setattr(pod_module, "check_for_pod_restart", check)

    with pytest.raises(ContainerRestartedError):
        await pod.exec(["true"], None, None, {}, None, 10)


async def test_a_daemon_that_is_gone_is_started_again(daemons: Daemons) -> None:
    first = await daemons.serve(exits)
    await daemons.serve(exits)
    client = daemons.client()
    await run(client)
    first.close()  # the daemon is gone: its port refuses connections
    await first.wait_closed()

    assert (await run(client)).success

    assert daemons.starts == [True, False]  # the second can't stop one that answers


async def test_a_daemon_that_cannot_be_reached_fails_the_call_after_one_start(
    daemons: Daemons,
) -> None:
    server = await daemons.serve(exits)
    daemons.fail_start(execd.DaemonRunning("bind: address already in use"))
    client = daemons.client()
    await run(client)
    server.close()  # as a network that drops the connection would
    await server.wait_closed()

    # Retryable, and bounded: no loop of starts and connects holds the caller.
    with pytest.raises(ConnectionError, match="execd unreachable"):
        await run(client)

    assert daemons.starts == [True, False]


async def test_a_port_held_at_the_first_start_says_so(daemons: Daemons) -> None:
    daemons.fail_start(execd.DaemonRunning("bind: address already in use"))

    with pytest.raises(RuntimeError, match="held by a process other than execd"):
        await run(daemons.client())


async def test_a_daemon_that_is_not_ours_gets_no_key_and_is_replaced(
    daemons: Daemons,
) -> None:
    await daemons.serve(exits, pin="0" * 64)  # another certificate than it reported
    await daemons.serve(exits)

    assert (await run(daemons.client())).success

    assert daemons.starts == [True, True]
    assert daemons.connections == 1  # the first got no key


async def test_a_port_held_by_another_server_fails_at_once(daemons: Daemons) -> None:
    await daemons.serve(exits, pin="0" * 64)
    daemons.fail_start(execd.DaemonRunning("bind: address already in use"))

    with pytest.raises(RuntimeError, match="held by a process other than execd"):
        await run(daemons.client())


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
    assert requests[0]["timeout"] == 5  # execd kills it then, connected or not


async def test_a_command_execd_never_ends_times_out_and_is_dropped(
    daemons: Daemons, monkeypatch: MonkeyPatch
) -> None:
    dropped = asyncio.Event()

    async def never_ends(r: asyncio.StreamReader, w: asyncio.StreamWriter) -> None:
        await read_frame(r)  # START, and no stdin after it
        with contextlib.suppress(ConnectionError):
            while True:  # as execd finds a client gone
                w.write(frame(execd.PING))
                await w.drain()
                await asyncio.sleep(0.01)
        dropped.set()

    await daemons.serve(never_ends)
    monkeypatch.setattr(execd, "KILL_WAIT", -0.7)  # 0.3 s in all: stdin backs up
    stdin = b"x" * (64 << 20)  # more than TCP holds: only an abort drops it unsent

    with pytest.raises(TimeoutError, match="Command timed out after 1s"):
        run = daemons.client().exec(["cat"], stdin, None, {}, None, 1)
        await asyncio.wait_for(run, 30)
    await asyncio.wait_for(dropped.wait(), 30)  # which makes execd kill the command


async def test_a_daemon_that_goes_silent_is_a_lost_connection(
    daemons: Daemons, monkeypatch: MonkeyPatch
) -> None:
    async def silent(r: asyncio.StreamReader, w: asyncio.StreamWriter) -> None:
        await gone(r)

    await daemons.serve(silent)
    monkeypatch.setattr(execd, "DEAD_AFTER", 0.05)

    with pytest.raises(ExecResultUnknownError, match="went silent"):
        await asyncio.wait_for(run(daemons.client()), 30)


async def test_pings_are_not_output(daemons: Daemons) -> None:
    async def pings(r: asyncio.StreamReader, w: asyncio.StreamWriter) -> None:
        await read_frame(r)
        ping = frame(execd.PING)
        w.write(ping + frame(execd.STDOUT, b"out") + ping + EXIT_0)

    await daemons.serve(pings)

    assert (await run(daemons.client())).stdout == "out"


@pytest.mark.parametrize("kind", [execd.STDERR, execd.STDOUT])
async def test_a_file_write_stops_at_the_output_limit(
    daemons: Daemons, monkeypatch: MonkeyPatch, kind: int
) -> None:
    monkeypatch.setattr(execd.limits, "MAX_EXEC_OUTPUT_SIZE", 1024)

    async def chatters(r: asyncio.StreamReader, w: asyncio.StreamWriter) -> None:
        await read_frame(r)
        w.write(frame(kind, b"x" * 2048) + EXIT_0)  # past the limit, then done

    await daemons.serve(chatters)

    with pytest.raises(OutputLimitExceededError):
        await daemons.client().write_file(b"data", Path("/tmp/f"))


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


def frozen_clock(monkeypatch: MonkeyPatch) -> None:
    """Stop the clock the bounds run on: they then allow for a new connection's age."""
    monkeypatch.setattr(execd, "time", types.SimpleNamespace(monotonic=lambda: 0.0))


@pytest.mark.parametrize(
    "sent",
    [
        frame(execd.STDERR, b"x") * 20_000,  # execd: one a millisecond
        frame(99),
        frame(execd.STDOUT, b"x" * (execd.CHUNK + 1)),
        frame(execd.EXIT, b" " * 4097),
        frame(execd.PING, b"x"),
    ],
    ids=["many-frames", "unknown-type", "large-output", "large-exit", "large-ping"],
)
async def test_what_execd_never_sends_breaks_its_daemon_for_good(
    daemons: Daemons, monkeypatch: MonkeyPatch, sent: bytes
) -> None:
    async def not_execd(r: asyncio.StreamReader, w: asyncio.StreamWriter) -> None:
        await read_frame(r)
        w.write(sent + EXIT_0)

    await daemons.serve(not_execd)
    client = daemons.client()
    frozen_clock(monkeypatch)

    with pytest.raises(execd.NotExecd):
        await run(client)
    with pytest.raises(execd.NotExecd):
        await run(client)

    assert daemons.connections == 1  # the second call reached no server
    assert daemons.starts == [True]  # and no daemon was started in its place


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


async def test_more_tcp_reads_than_execd_makes_break_its_daemon(
    daemons: Daemons, monkeypatch: MonkeyPatch
) -> None:
    daemon_port = (await daemons.serve(exits)).sockets[0].getsockname()[1]

    async def trickle(r: asyncio.StreamReader, w: asyncio.StreamWriter) -> None:
        daemon, to_daemon = await asyncio.open_connection("127.0.0.1", daemon_port)

        async def to_client() -> None:
            while byte := await daemon.read(1):  # a byte a segment
                w.write(byte)
                await w.drain()
                await asyncio.sleep(0)

        task = asyncio.create_task(to_client())
        while data := await r.read(65536):
            to_daemon.write(data)
        task.cancel()

    proxy = await asyncio.start_server(trickle, "127.0.0.1", 0)
    client = daemons.client()
    start = client._start

    async def start_behind_proxy(replace: bool) -> execd.Daemon:
        daemon = await start(replace)
        monkeypatch.setattr(execd, "EXECD_PORT", proxy.sockets[0].getsockname()[1])
        return daemon

    client._start = start_behind_proxy
    frozen_clock(monkeypatch)

    with pytest.raises(execd.NotExecd, match="TCP reads"):
        await run(client)
    proxy.close()


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
    stream = await daemons.client().open_stream(["cat"], None)

    await stream.send(b"abc")
    assert await stream.receive() == b"abc"
    await stream.send_eof()

    with pytest.raises(anyio.EndOfStream):
        await stream.receive()
    with pytest.raises(anyio.BrokenResourceError):  # not lost in silence
        await stream.send(b"late")


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
    stream = await daemons.client().open_stream(["cat"], None)

    await stream.aclose()

    await asyncio.wait_for(dropped.wait(), 30)  # which makes execd end the command
    assert requests[0]["stream"]  # so execd kills only the command itself
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
    stream = await daemons.client().open_stream(["cat"], None)

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
    stream = await daemons.client().open_stream(["cat"], None)
    send = asyncio.create_task(stream.send(b"x" * (64 << 20)))  # more than TCP holds
    await until(stream._send_lock.locked)

    await stream.aclose()

    with pytest.raises(anyio.BrokenResourceError):
        await asyncio.wait_for(send, 30)


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
