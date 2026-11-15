"""The real client against execd's built binary, in a container."""

import asyncio
import collections.abc
import contextlib
import dataclasses
import hashlib
import os
import pathlib
import shutil
import ssl
import subprocess
import sys
import typing
import uuid

import kubernetes.client.exceptions
import pytest

from k8s_sandbox._pod import error, execd, op
from k8s_sandbox._pod import pod as pod_module
from test.k8s_sandbox.pod import test_execd

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
        small = ["--memory", "64m", "--memory-swap", "64m", "--cpus", "1"]
        started = docker("run", "-d", "--name", name, *small, name, "sleep", "3600")
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


@pytest.fixture
def client(sandbox: Sandbox, relay: Relay) -> execd.ExecdClient:
    """The real client; `docker exec` starts execd, as an exec into a pod does."""

    async def start(replace: bool) -> execd.Daemon:
        key = os.urandom(32)
        listen = [execd.EXECD_PATH, "listen", "--port", str(PORT)]
        listen += ["--key-sha256", hashlib.sha256(key).hexdigest()]
        listen += ["--replace"] if replace else []
        started = await asyncio.to_thread(docker, "exec", sandbox.name, *listen)
        if "address already in use" in started.stderr:
            raise execd.DaemonRunning(started.stderr)
        assert started.returncode == 0, started.stderr
        return execd.Daemon("127.0.0.1", started.stdout.split()[0], key)

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


async def test_an_upload_whose_connection_drops_arrives_whole_and_once(
    sandbox: Sandbox,
    relay: Relay,
    client: execd.ExecdClient,
    caplog: pytest.LogCaptureFixture,
) -> None:
    held = f"/tmp/{uuid.uuid4().hex}"
    # It reads no stdin until let go, so the drop finds the upload part sent.
    script = 'echo x >> "$0"; until [ -e "$0.go" ]; do sleep 0.05; done; md5sum'
    data = os.urandom(2 * execd.STDIN_WINDOW)
    call = asyncio.ensure_future(
        client.exec(["sh", "-c", script, held], data, None, {}, None, None)
    )
    await sandbox.until(f"test -e {held}")

    async def resuming() -> None:
        while "resuming" not in caplog.text:
            await asyncio.sleep(0.01)

    relay.drop()
    await asyncio.wait_for(resuming(), 30)  # execd holds stdin it has yet to write
    await asyncio.to_thread(sandbox.sh, f"touch {held}.go")
    result = await asyncio.wait_for(call, 30)  # only bounds a hang

    assert result.stdout.split() == [hashlib.md5(data).hexdigest(), "-"]
    ran = await asyncio.to_thread(sandbox.sh, f"cat {held}")
    assert ran.stdout == "x\n"  # by the one command


def test_execd_started_again_names_the_same_container(sandbox: Sandbox) -> None:
    name = f"{sandbox.name}-again"
    listen = [execd.EXECD_PATH, "listen", "--port", str(PORT), "--replace"]
    listen += ["--key-sha256", "00" * 32]
    try:
        started = docker("run", "-d", "--name", name, sandbox.name, "sleep", "3600")
        assert started.returncode == 0, started.stderr
        first = docker("exec", name, *listen).stdout.split()[1]
        again = docker("exec", name, *listen).stdout.split()[1]
    finally:
        docker("rm", "-f", name)

    assert again == first  # or a restart of execd alone would pass for the container's


async def test_a_command_for_another_user_does_not_run_with_groups_it_cannot_take(
    sandbox: Sandbox,
    relay: Relay,
    client: execd.ExecdClient,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Run all the same, it would be that user with execd's own groups."""
    name = f"{sandbox.name}-nosetgid"
    address = "{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}"
    run = ["run", "-d", "--name", name, "--cap-drop", "SETGID", sandbox.name]
    try:
        assert docker(*run, "sleep", "3600").returncode == 0
        # Root's own group is theirs, so only their groups are out of execd's reach.
        user = "echo o:x:4242:0::/:/bin/sh >>/etc/passwd"
        assert docker("exec", name, "sh", "-c", user).returncode == 0
        monkeypatch.setattr(sandbox, "name", name)
        ip = docker("inspect", "-f", address, name).stdout.strip()
        monkeypatch.setattr(relay, "ip", ip)

        ran = client.exec(["echo", "ran"], None, None, {}, "o", None)
        result = await asyncio.wait_for(ran, 30)  # only bounds a hang
    finally:
        docker("rm", "-f", name)

    assert (result.returncode, result.stdout) == (126, "")


@pytest.mark.parametrize(
    ("mode", "read_fails"),
    [("raise", ()), ("raise", (True,)), ("raise", (False, True)), ("warn", ())],
)
async def test_a_restart_kubernetes_has_not_shown_is_found_where_execd_starts(
    sandbox: Sandbox,
    monkeypatch: pytest.MonkeyPatch,
    mode: typing.Literal["raise", "warn"],
    read_fails: tuple[bool, ...],
) -> None:
    """Regression: operations ran in a restarted container Kubernetes had not shown."""
    name = f"{sandbox.name}-{mode}-{len(read_fails)}"
    address = "{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}"
    shown = test_execd.Cluster()  # the pod as Kubernetes shows it: never restarted
    outages = iter(read_fails)

    class Execute:
        def __init__(self, info: object) -> None:
            pass

        def run_argv(self, cmd: list[str]) -> tuple[int, bytes, bytes]:
            ran = docker("exec", name, *cmd)
            shown.unavailable = next(outages, False)  # the pod read after this start
            return ran.returncode, ran.stdout.encode(), ran.stderr.encode()

    monkeypatch.setattr(pod_module, "ExecuteOperation", Execute)
    monkeypatch.setattr(pod_module, "k8s_client", lambda _: shown)
    monkeypatch.setattr(op, "k8s_client", lambda _: shown)
    pod = pod_module.Pod("p", "ns", None, "default", "u", 0, mode, execd=True)

    async def command() -> None:
        async def run() -> None:
            await asyncio.wait_for(pod.exec(["true"], None, None, {}, None, None), 30)

        try:
            await run()
        except execd.NotSent:  # it never left: the provider sends it again
            await run()

    try:
        started = docker("run", "-d", "--name", name, sandbox.name, "sleep", "3600")
        assert started.returncode == 0, started.stderr
        shown.ip = docker("inspect", "-f", address, name).stdout.strip()
        if read_fails[:1] == (True,):  # execd starts, though the read after it fails
            with pytest.raises(kubernetes.client.exceptions.ApiException):
                await command()
        else:
            await command()
        restarted = await asyncio.to_thread(docker, "restart", "-t", "0", name)
        assert restarted.returncode == 0, restarted.stderr
        shown.ip = docker("inspect", "-f", address, name).stdout.strip()

        if mode == "raise":
            with pytest.raises(error.ContainerRestartedError, match="execd started"):
                await command()
        else:  # it goes on there
            with contextlib.suppress(error.ExecdStoppedError):
                await command()  # execd may be found gone only under it
            await command()
    finally:
        docker("rm", "-f", name)


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


async def test_commands_printing_at_once_fit_in_a_small_sandbox(
    client: execd.ExecdClient,
) -> None:
    """Regression: execd's garbage took the container past 64 MiB: it was killed."""
    size = 9 << 20
    argv = ["head", "-c", str(size), "/dev/zero"]
    prints = [client.exec(argv, None, None, {}, None, None) for _ in range(8)]

    results = await asyncio.wait_for(asyncio.gather(*prints), 30)

    assert [len(result.stdout) for result in results] == [size] * 8
