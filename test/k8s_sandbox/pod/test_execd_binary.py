"""The real client against execd's built binary, in a container."""

import asyncio
import collections.abc
import dataclasses
import hashlib
import os
import pathlib
import shutil
import ssl
import subprocess
import sys
import uuid

import anyio
import anyio.abc
import anyio.streams.stapled
import anyio.streams.tls
import pytest

from k8s_sandbox._pod import execd

EXECD = pathlib.Path(__file__).parents[3] / "execd"
PORT = execd.EXECD_PORT
IMAGE = "public.ecr.aws/docker/library/python:3.12-slim-bookworm"
# Run in the container: whether execd serves a TLS handshake from each address given.
PROBE = """
import socket, ssl, sys
context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
context.check_hostname, context.verify_mode = False, ssl.CERT_NONE
for host in sys.argv[2:]:
    try:
        context.wrap_socket(socket.create_connection((host, int(sys.argv[1])), 30))
        print(host, "served")
    except OSError:
        print(host, "closed")
"""


def docker(
    *args: str, stdin: str | None = None, timeout: float = 30
) -> subprocess.CompletedProcess[str]:
    command = ["docker", *args]
    # The timeout only bounds a hang: a build pulls images, and takes longer.
    return subprocess.run(
        command, input=stdin, capture_output=True, text=True, timeout=timeout
    )


@dataclasses.dataclass
class Sandbox:
    """A container with execd at its path, as a pod has it."""

    name: str
    ip: str

    def sh(self, script: str, *args: str) -> subprocess.CompletedProcess[str]:
        return docker("exec", self.name, "sh", "-c", script, "sh", *args)

    async def until(self, script: str) -> None:
        """Wait until a shell test passes in it; the budget only bounds a hang."""

        async def poll() -> None:
            while (await asyncio.to_thread(self.sh, script)).returncode != 0:
                await asyncio.sleep(0.05)

        await asyncio.wait_for(poll(), 30)


@pytest.fixture(scope="module")
def sandbox() -> collections.abc.Iterator[Sandbox]:
    if shutil.which("docker") is None or sys.platform != "linux":
        pytest.skip("needs Docker on Linux, where a container's address is routed")
    name = f"execd-test-{uuid.uuid4().hex[:8]}"
    built = docker("build", "-q", "-t", f"{name}:execd", str(EXECD), timeout=600)
    assert built.returncode == 0, built.stderr
    dockerfile = f"FROM {name}:execd AS execd\nFROM {IMAGE}\n"
    dockerfile += f"COPY --from=execd /execd {execd.EXECD_PATH}\n"
    built = docker("build", "-q", "-t", name, "-", stdin=dockerfile, timeout=600)
    assert built.returncode == 0, built.stderr
    try:
        started = docker("run", "-d", "--name", name, name, "sleep", "3600")
        assert started.returncode == 0, started.stderr
        address = "{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}"
        yield Sandbox(name, docker("inspect", "-f", address, name).stdout.strip())
    finally:
        docker("rm", "-f", name)
        docker("rmi", "-f", name, f"{name}:execd")


class Relay:
    """Carries the client's connections to execd, and drops them when told to."""

    def __init__(self, ip: str) -> None:
        self.ip = ip
        self.open: list[asyncio.StreamWriter] = []

    async def carry(self, r: asyncio.StreamReader, w: asyncio.StreamWriter) -> None:
        execd_r, execd_w = await asyncio.open_connection(self.ip, PORT)
        self.open += [w, execd_w]

        async def copy(src: asyncio.StreamReader, dst: asyncio.StreamWriter) -> None:
            try:
                while data := await src.read(1 << 16):
                    dst.write(data)
                    await dst.drain()
            except OSError:
                pass
            dst.close()

        await asyncio.gather(copy(r, execd_w), copy(execd_r, w))

    def drop(self) -> None:
        for w in self.open:
            w.transport.abort()
        self.open.clear()


@pytest.fixture
async def relay(
    sandbox: Sandbox, monkeypatch: pytest.MonkeyPatch
) -> collections.abc.AsyncIterator[Relay]:
    carrier = Relay(sandbox.ip)
    server = await asyncio.start_server(carrier.carry, "127.0.0.1", 0)
    monkeypatch.setattr(execd, "EXECD_PORT", server.sockets[0].getsockname()[1])
    yield carrier
    carrier.drop()
    server.close()


class Execs:
    """`docker exec`s joined to execd's socket, as the execs to a pod with no card."""

    def __init__(self, name: str) -> None:
        self.name = name
        self.open: list[anyio.abc.Process] = []

    async def connect(self, *user: str) -> anyio.abc.ByteStream:
        bridge = [execd.EXECD_PATH, "connect", execd.EXECD_SOCKET]
        argv = ["docker", "exec", "-i", *user, self.name, *bridge]
        self.open.append(await anyio.open_process(argv, stderr=subprocess.DEVNULL))
        stdin, stdout = self.open[-1].stdin, self.open[-1].stdout
        assert stdin is not None and stdout is not None
        return anyio.streams.stapled.StapledByteStream(stdin, stdout)

    def drop(self) -> None:
        for process in self.open:
            if process.returncode is None:
                process.kill()


@pytest.fixture
async def execs(sandbox: Sandbox) -> collections.abc.AsyncIterator[Execs]:
    carrier = Execs(sandbox.name)
    yield carrier
    carrier.drop()
    for process in carrier.open:
        await process.aclose()


async def start_execd(sandbox: Sandbox, replace: bool, *at: str) -> tuple[str, bytes]:
    """`docker exec` starts execd, as an exec into a pod does: its fingerprint, key."""
    key = os.urandom(32)
    listen = [execd.EXECD_PATH, "listen", *at]
    listen += ["--key-sha256", hashlib.sha256(key).hexdigest()]
    listen += ["--replace"] if replace else []
    started = await asyncio.to_thread(docker, "exec", sandbox.name, *listen)
    if "address already in use" in started.stderr:
        raise execd.DaemonRunning(started.stderr)
    assert started.returncode == 0, started.stderr
    return started.stdout.strip(), key


@pytest.fixture
def client(sandbox: Sandbox, relay: Relay) -> execd.ExecdClient:
    """The real client, reaching execd at its port."""

    async def start(replace: bool) -> execd.Daemon:
        at = await start_execd(sandbox, replace, "--port", str(PORT))
        return execd.Daemon("127.0.0.1", *at)

    return execd.ExecdClient(start)


@pytest.fixture
def stdio_client(sandbox: Sandbox, execs: Execs) -> execd.ExecdClient:
    """The real client, reaching execd through an exec's stdio."""

    async def start(replace: bool) -> execd.Daemon:
        at = await start_execd(sandbox, replace, "--socket", execd.EXECD_SOCKET)
        return execd.Daemon("", *at, execs.connect)

    return execd.ExecdClient(start)


async def test_a_command_whose_connection_drops_is_resumed_and_runs_once(
    sandbox: Sandbox, relay: Relay, client: execd.ExecdClient
) -> None:
    runs = f"/tmp/{uuid.uuid4().hex}"
    script = 'echo before; echo run >> "$0"; until [ -e "$0.go" ]; do sleep 0.05; done'
    argv = ["sh", "-c", script + "; echo after", runs]
    call = asyncio.ensure_future(client.exec(argv, None, None, {}, None, None))
    await sandbox.until(f"test -e {runs}")

    relay.drop()
    sandbox.sh(f"touch {runs}.go")
    result = await asyncio.wait_for(call, 30)  # only bounds a hang

    # All of its output, once: what came before the drop and what came after.
    assert (result.returncode, result.stdout) == (0, "before\nafter\n")
    assert sandbox.sh(f"cat {runs}").stdout == "run\n"


async def test_a_command_whose_exec_ends_is_resumed_through_another_and_runs_once(
    sandbox: Sandbox, execs: Execs, stdio_client: execd.ExecdClient
) -> None:
    runs = f"/tmp/{uuid.uuid4().hex}"
    script = 'echo run >> "$0"; until [ -e "$0.go" ]; do sleep 0.05; done; echo ran'
    call = asyncio.ensure_future(
        stdio_client.exec(["sh", "-c", script, runs], None, None, {}, None, None)
    )
    await sandbox.until(f"test -e {runs}")

    execs.drop()
    sandbox.sh(f"touch {runs}.go")
    result = await asyncio.wait_for(call, 30)  # only bounds a hang

    assert (result.returncode, result.stdout) == (0, "ran\n")
    assert sandbox.sh(f"cat {runs}").stdout == "run\n"


async def test_a_wrong_key_is_answered_with_nothing(
    sandbox: Sandbox, client: execd.ExecdClient
) -> None:
    await client.exec(["true"], None, None, {}, None, None)  # execd runs, with a key
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname, context.verify_mode = False, ssl.CERT_NONE
    r, w = await asyncio.open_connection(sandbox.ip, PORT, ssl=context)

    w.write(execd.HEADER.pack(execd.AUTH, 0, 32) + bytes(32))
    answer = await asyncio.wait_for(r.read(execd.HEADER.size), 30)

    w.close()
    assert answer == b""  # closed, with no OK


async def test_a_connection_from_the_sandbox_itself_is_closed(
    sandbox: Sandbox, client: execd.ExecdClient
) -> None:
    await client.exec(["true"], None, None, {}, None, None)  # execd runs

    dial = ["python3", "-c", PROBE, str(PORT), "127.0.0.1", sandbox.ip]
    probe = await asyncio.to_thread(docker, "exec", sandbox.name, *dial)

    assert probe.stdout.split() == ["127.0.0.1", "closed", sandbox.ip, "closed"]


async def test_another_users_process_is_refused_at_execds_socket(
    execs: Execs, stdio_client: execd.ExecdClient
) -> None:
    call = stdio_client.exec(["true"], None, None, {}, None, None)  # execd runs
    await asyncio.wait_for(call, 30)  # only bounds a hang
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname, context.verify_mode = False, ssl.CERT_NONE
    theirs = await execs.connect("-u", "65534")

    # Closed, where its own user is served; the budgets only bound a hang.
    with anyio.fail_after(30), pytest.raises(anyio.EndOfStream):
        await anyio.streams.tls.TLSStream.wrap(
            theirs, server_side=False, ssl_context=context, standard_compatible=False
        )
    with anyio.fail_after(30):
        assert await execs.open[-1].wait() == 0  # the bridge itself ran, and connected


async def test_a_timed_out_command_is_killed(
    sandbox: Sandbox, client: execd.ExecdClient
) -> None:
    pid = f"/tmp/{uuid.uuid4().hex}"
    argv = ["sh", "-c", 'echo $$ > "$0"; exec sleep 600', pid]

    with pytest.raises(TimeoutError):
        await client.exec(argv, None, None, {}, None, 1)

    await sandbox.until(f"test -s {pid} && ! kill -0 $(cat {pid})")


async def test_a_streams_command_is_killed_when_its_connection_drops(
    sandbox: Sandbox, relay: Relay, client: execd.ExecdClient
) -> None:
    pid = f"/tmp/{uuid.uuid4().hex}"
    await client.open_stream(["sh", "-c", 'echo $$ > "$0"; exec sleep 600', pid], None)
    await sandbox.until(f"test -s {pid}")

    relay.drop()

    await sandbox.until(f"test -s {pid} && ! kill -0 $(cat {pid})")
