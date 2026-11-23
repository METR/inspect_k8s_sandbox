"""The real client against execd's built binary, in a container."""

import asyncio
import collections.abc
import contextlib
import dataclasses
import hashlib
import io
import os
import pathlib
import shutil
import ssl
import subprocess
import sys
import typing
import uuid

import anyio
import anyio.abc
import anyio.streams.stapled
import anyio.streams.tls
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
    options: tuple[str, ...] = ()  # of the `docker exec` that starts execd

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


async def start_execd(
    sandbox: Sandbox, replace: bool, *at: str
) -> tuple[str, bytes, bytes]:
    """`docker exec` starts execd, as an exec into a pod does: what it says, its key."""
    key = os.urandom(32)
    listen = [execd.EXECD_PATH, "listen", *at]
    listen += ["--key-sha256", hashlib.sha256(key).hexdigest()]
    listen += ["--replace"] if replace else []
    command = ["exec", *sandbox.options, sandbox.name, *listen]
    started = await asyncio.to_thread(docker, *command)
    if "address already in use" in started.stderr:
        raise execd.DaemonRunning(started.stderr)
    assert started.returncode == 0, started.stderr
    fingerprint, container = started.stdout.split()
    return fingerprint, key, container.encode()


@pytest.fixture
def client(sandbox: Sandbox, relay: Relay) -> execd.ExecdClient:
    """The real client, reaching execd at its port."""

    async def start(replace: bool) -> execd.Daemon:
        at = await start_execd(sandbox, replace, "--port", str(PORT))
        return execd.Daemon("127.0.0.1", *at[:2])

    return execd.ExecdClient(start)


@pytest.fixture
def stdio_client(sandbox: Sandbox, execs: Execs) -> execd.ExecdClient:
    """The real client, reaching execd through an exec's stdio."""

    async def start(replace: bool) -> execd.Daemon:
        at = await start_execd(sandbox, replace, "--socket", execd.EXECD_SOCKET)
        return execd.Daemon("", *at[:2], stdio=execs.connect, container=at[2])

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


@pytest.mark.parametrize(("limit", "left", "beside"), [(64, 32, 6), (32, 12, 2)])
async def test_commands_that_each_leave_a_process_do_not_take_every_descriptor(
    sandbox: Sandbox,
    relay: Relay,
    client: execd.ExecdClient,
    monkeypatch: pytest.MonkeyPatch,
    limit: int,
    left: int,
    beside: int,
) -> None:
    """Regression: in a Kata guest, with 1,024, the 506th such command failed."""
    name = f"{sandbox.name}-nofile"
    address = "{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}"
    nofile = f"nofile={limit}:{limit}"
    run = ["run", "-d", "--name", name, "--ulimit", nofile, sandbox.name]
    gate = f"/tmp/{uuid.uuid4().hex}"
    # A process that holds its command's stdout and stderr until it is let go.
    held = 'until [ -e "$0" ]; do sleep 0.05; done; echo >>"$0.gone"'
    # One that then writes to the stdout it kept, and says how the write ended.
    late = 'trap "" PIPE; until [ -e "$0.go" ]; do sleep 0.05; done; echo late'
    late += '; echo $? >"$0.wrote"'

    async def leave(script: str) -> int:
        argv = ["sh", "-c", f"({script}) &", gate]
        ran = client.exec(argv, None, None, {}, None, None)
        return (await asyncio.wait_for(ran, 30)).returncode  # only bounds a hang

    try:
        assert docker(*run, "sleep", "3600").returncode == 0
        monkeypatch.setattr(sandbox, "name", name)
        ip = docker("inspect", "-f", address, name).stdout.strip()
        monkeypatch.setattr(relay, "ip", ip)
        # All kept, their pipes were every descriptor of 64; half of 32 left too few.
        for _ in range(left):
            assert await leave(held) == 0
        # With all but 24 of 64 kept, four of these ran; with all but 18 of 32, one.
        up = 'echo >>"$0.up"; for _ in $(seq 200); do [ "$(wc -l <"$0.up")" = "$1" ]'
        up += " && exit 0; sleep 0.05; done; exit 1"  # each waits 10 s for all to be up
        argv = ["sh", "-c", up, gate, str(beside)]
        runs = (client.exec(argv, None, None, {}, None, None) for _ in range(beside))
        ran = await asyncio.wait_for(asyncio.gather(*runs), 30)  # only bounds a hang
        assert [r.returncode for r in ran] == [0] * beside
        sandbox.sh(f"touch {gate}")
        await sandbox.until(f'[ "$(wc -l <{gate}.gone)" = {left} ]')
        assert await leave(late) == 0
        sandbox.sh(f"touch {gate}.go")
        await sandbox.until(f"test -s {gate}.wrote")
        wrote = sandbox.sh(f"cat {gate}.wrote").stdout
    finally:
        docker("rm", "-f", name)

    assert wrote == "0\n"  # the places of the pipes execd let go went to new ones


async def test_an_id_no_uid_holds_is_not_narrowed_to_one(
    sandbox: Sandbox, client: execd.ExecdClient
) -> None:
    """Narrowed to 32 bits, a uid or gid of 4294967296 or -4294967296 is root's."""
    users = "cp -p /etc/passwd /etc/passwd.kept && cp -p /etc/group /etc/group.kept"
    users += " && echo wideuid:x:4294967296:4242::/:/bin/sh >>/etc/passwd"
    users += " && echo negative:x:-4294967296:4242::/:/bin/sh >>/etc/passwd"
    users += " && echo widegid:x:4243:4294967296::/:/bin/sh >>/etc/passwd"
    users += " && echo o:x:4242:4242::/:/bin/sh >>/etc/passwd"
    users += " && echo wide:x:4294967296:o >>/etc/group"
    users += " && echo last:x:4294967295:o >>/etc/group"  # setgroups takes no (gid_t)-1
    users += " && sed -i s/^root:x:0:0:/root:x:0:4294967296:/ /etc/passwd"

    async def run(user: str, *argv: str) -> str:
        ran = client.exec(list(argv), None, None, {}, user, None)
        return (await asyncio.wait_for(ran, 30)).stdout  # only bounds a hang

    try:
        assert sandbox.sh(users).returncode == 0
        for user in ("wideuid", "negative", "widegid"):
            with pytest.raises(RuntimeError, match="does not appear to exist"):
                await run(user, "id")
        groups = await run("o", "id", "-G")
        own = await run("root", "id", "-u")  # execd's own user: nothing to switch
    finally:  # the module's other tests share this container
        kept = "mv /etc/passwd.kept /etc/passwd && mv /etc/group.kept /etc/group"
        assert sandbox.sh(kept).returncode == 0

    assert (groups, own) == ("4242\n", "0\n")  # o without root's group; root still runs


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
    pod = pod_module.Pod("p", "ns", None, "default", "u", 0, mode, execd="true")

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


async def test_a_file_operation_execd_cannot_start_is_no_word_on_the_file(
    sandbox: Sandbox, client: execd.ExecdClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Regression: with the working directory gone, any file read as missing."""
    gone = f"/tmp/{uuid.uuid4().hex}"
    assert sandbox.sh(f"mkdir {gone}").returncode == 0
    monkeypatch.setattr(sandbox, "options", ("--workdir", gone))
    removed = client.exec(["rmdir", gone], None, "/", {}, None, None)
    await asyncio.wait_for(removed, 30)  # execd starts there; only bounds a hang

    with pytest.raises(error.PodError, match="cd: "):
        read = client.read_file(pathlib.Path("/etc/hostname"), io.BytesIO())
        await asyncio.wait_for(read, 30)  # only bounds a hang


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

    # Closed, before the handshake or in it, where its own user is served.
    closed = (anyio.EndOfStream, anyio.BrokenResourceError)
    with anyio.fail_after(30), pytest.raises(closed):  # the budgets only bound a hang
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


async def test_a_killed_commands_handler_runs_whichever_thread_sigterm_is_for(
    sandbox: Sandbox, client: execd.ExecdClient
) -> None:
    """Regression: sent to a stopped process as a whole, SIGTERM went to any thread."""
    mark = f"/tmp/{uuid.uuid4().hex}"
    head = "import os, pathlib, signal, sys, threading\nwait = threading.Event().wait\n"
    head += "mark = pathlib.Path(sys.argv[1])\n"
    head += "def took(*_): mark.touch(); os._exit(0)\n"
    first = head + "signal.signal(signal.SIGTERM, took)\n"
    first += "for _ in range(64): threading.Thread(target=wait, daemon=True).start()\n"
    other = head + "signal.pthread_sigmask(signal.SIG_BLOCK, {signal.SIGTERM})\n"
    other += "def take(): signal.sigwait({signal.SIGTERM}); took()\n"
    other += "threading.Thread(target=take, daemon=True).start()\n"
    ready = "pathlib.Path(sys.argv[1] + '.ready').touch()\nwait()"
    for script in (first, first, first, other):  # by chance the first takes it at times
        argv = ["python3", "-c", script + ready, mark]
        call = asyncio.ensure_future(client.exec(argv, None, None, {}, None, None))
        await sandbox.until(f"test -e {mark}.ready")
        call.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await call
        await sandbox.until(f"test -e {mark} && rm {mark} {mark}.ready")


async def test_a_timed_out_command_holding_every_pid_does_not_end_execd(
    sandbox: Sandbox,
    relay: Relay,
    client: execd.ExecdClient,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Regression: with no PID left for a thread, Go ended execd in the kill's grace."""
    name = f"{sandbox.name}-pids"
    address = "{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}"
    run = ["run", "-d", "--name", name, "--pids-limit=1024", "--cpus=2", sandbox.name]
    hold = "import os, signal, time\nsignal.signal(signal.SIGTERM, signal.SIG_IGN)\n"
    hold += "try:\n    while os.fork(): pass\n"
    hold += "except BlockingIOError: os.write(1, b'full')\ntime.sleep(99)"
    try:
        assert docker(*run, "sleep", "3600").returncode == 0
        monkeypatch.setattr(sandbox, "name", name)
        relay.ip = docker("inspect", "-f", address, name).stdout.strip()
        many = ("-e", "GOMAXPROCS=64")  # as on a large node: no cap fails anywhere
        monkeypatch.setattr(sandbox, "options", many)
        pid = await client.exec(["sh", "-c", "echo $PPID"], None, None, {}, None, 30)
        with pytest.raises(TimeoutError) as timed:
            await client.exec(["python3", "-c", hold], None, None, {}, None, 3)
        assert "full" in getattr(timed.value, "truncated_output")  # no PID was left
        await sandbox.until("true")  # else the sandbox is still full, or Docker stuck
        after = sandbox.sh(f"cat /proc/{pid.stdout.strip()}/cmdline 2>/dev/null")
        assert "serve" in after.stdout, after.stderr or "execd ended"
    finally:
        docker("rm", "-f", name)


async def test_a_command_that_kills_every_process_ends_137_and_the_next_one_runs(
    stdio_client: execd.ExecdClient,
) -> None:
    ran = f"/tmp/{uuid.uuid4().hex}"
    argv = ["sh", "-c", 'echo ran >> "$0"; kill -9 -1', ran]
    with anyio.fail_after(30):  # only bounds a hang
        killed = await stdio_client.exec(argv, None, None, {}, None, None)
        after = await stdio_client.exec(["cat", ran], None, None, {}, None, None)
    assert (killed.returncode, after.returncode, after.stdout) == (137, 0, "ran\n")


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
