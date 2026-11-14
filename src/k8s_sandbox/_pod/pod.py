from __future__ import annotations

import asyncio
import dataclasses
import hashlib
import logging
import os
import re
import threading
import time
from pathlib import Path
from typing import IO, Awaitable, Callable, Literal, TypeVar

from inspect_ai.util import ExecResult

from k8s_sandbox._kubernetes_api import k8s_client
from k8s_sandbox._pod.error import (
    ContainerRestartedError,
    ContainerStoppedError,
    ExecResultUnknownError,
    PodError,
    PodReplacedError,
)
from k8s_sandbox._pod.execd import (
    EXECD_PATH,
    EXECD_PORT,
    Daemon,
    DaemonRunning,
    ExecdClient,
    ExecdStream,
)
from k8s_sandbox._pod.execute import ROOT_USERS, ExecuteOperation, PodStdio
from k8s_sandbox._pod.executor import PodOpExecutor
from k8s_sandbox._pod.op import API_TIMEOUT, PodInfo, check_for_pod_restart
from k8s_sandbox._pod.read import ReadFileOperation
from k8s_sandbox._pod.snapshot import read_pod
from k8s_sandbox._pod.write import WriteFileOperation

T = TypeVar("T")

logger = logging.getLogger(__name__)

RESTART_SHOWN_WITHIN = 30.0  # of execd's death: Kubernetes can show a restart late


def _file_op_restart_check_enabled() -> bool:
    # Gates the pre-op `read_namespaced_pod` call inside read_file / write_file
    # (only — exec is unaffected and always checks). At high concurrency
    # (200+ ops) the per-op reads can overwhelm the K8s API server; exec's
    # check is the high-signal way we learn a sandbox pod was replaced and
    # stays unconditional, while file-op API errors are self-revealing.
    return os.environ.get("INSPECT_POD_RESTART_CHECK", "true").lower() != "false"


class Pod:
    def __init__(
        self,
        name: str,
        namespace: str,
        context_name: str | None,
        default_container_name: str,
        uid: str,
        initial_restart_count: int,
        restarted_container_behavior: Literal["warn", "raise"],
        execd: bool = False,
    ) -> None:
        self._info = PodInfo(
            name,
            namespace,
            context_name,
            default_container_name,
            uid,
            initial_restart_count,
            restarted_container_behavior,
        )
        # Whether exec() can start runuser directly, per pod, container start and user.
        self._switch: dict[tuple[str, int, str], bool] = {}
        # What a check in "raise" mode detected, which every later operation raises.
        self._restart_error: PodReplacedError | ContainerRestartedError | None = None
        self._restart_lock = threading.Lock()
        # Operations go over the pod network to execd, if the pod has it (see execd.py).
        self._execd = ExecdClient(self._start_execd) if execd else None
        self._execd_lost = False  # a daemon started whose key a failure then lost
        self._execd_restarted = float("-inf")
        self._execd_started: float | None = None  # a start whose late check is owed

    async def _start_execd(self, replace: bool) -> Daemon:
        """Start execd; restarts are checked here, since a restart stops the daemon."""
        await self.check_for_pod_restart()
        info = self._info
        key = os.urandom(32)
        cmd = [EXECD_PATH, "listen", "--port", str(EXECD_PORT)]
        cmd += ["--key-sha256", hashlib.sha256(key).hexdigest()]
        cmd += ["--replace"] if replace or self._execd_lost else []
        code, stdout, stderr = await self._run_async(
            lambda: ExecuteOperation(info).run_argv(cmd)
        )
        if b"address already in use" in stderr:
            raise DaemonRunning(stderr.decode(errors="replace"))
        # Exactly the fingerprint execd prints: anything else, cut output too, fails.
        if code != 0 or not re.fullmatch(rb"[0-9a-f]{64}\n", stdout):
            raise PodError("execd did not start", returncode=code, stderr=stderr)
        self._execd_lost = True  # until it is returned: a failure below loses its key
        if not replace:  # the daemon reached before died, perhaps with its container
            self._execd_restarted = time.monotonic()
        # Again: a container that restarted since the first check runs this daemon.
        await self.check_for_pod_restart()
        # Read last: a pod that replaced the one first checked has another address.
        pod = await self._run_async(
            lambda: read_pod(
                k8s_client(info.context_name), info.name, info.namespace, API_TIMEOUT
            )
        )
        if pod.ip is None:
            raise PodError("The pod has no IP address for execd", pod=info.name)
        self._execd_lost = False
        self._execd_started = time.monotonic()
        return Daemon(pod.ip, stdout.decode().strip(), key)

    @property
    def info(self) -> PodInfo:
        """The current cached pod identity.

        Note that ``uid`` and ``initial_restart_count`` may be replaced by
        ``check_for_pod_restart`` if a replacement or restart is observed in
        ``"warn"`` mode.
        """
        return self._info

    async def check_for_pod_restart(
        self,
    ) -> PodReplacedError | ContainerRestartedError | None:
        """Check whether the pod has been replaced or its container has restarted.

        What a detection does is governed by ``restarted_container_behavior``:

        - ``"warn"``: log a warning, refresh the cached identity (``uid`` and/or
          ``initial_restart_count``) so subsequent operations target the new pod
          without reporting the same condition, and return the detected error.
        - ``"raise"``: raise ``PodReplacedError`` or ``ContainerRestartedError``, and
          raise it again on every later check, without reading the pod: the pod or
          container the sample had is gone.
        """
        return await self._run_async(self._check_for_pod_restart_sync)

    def _check_for_pod_restart_sync(
        self,
    ) -> PodReplacedError | ContainerRestartedError | None:
        try:
            check_for_pod_restart(self._info)
        except (PodReplacedError, ContainerRestartedError) as e:
            if self._info.restarted_container_behavior == "raise":
                # A copy, without the frames of the operations it passes through.
                self._keep(type(e)(**vars(e)))
                raise
            if isinstance(e, PodReplacedError):
                self._info = dataclasses.replace(
                    self._info,
                    uid=e.new_uid,
                    initial_restart_count=e.new_restart_count,
                )
            else:
                self._info = dataclasses.replace(
                    self._info,
                    initial_restart_count=e.restart_count,
                )
            logger.warning(str(e))
            return e
        return None

    async def exec(
        self,
        cmd: list[str],
        stdin: str | bytes | None,
        cwd: str | None,
        env: dict[str, str],
        user: str | None,
        timeout: int | None,
    ) -> ExecResult[str]:
        """
        Execute a command in a pod.

        This method will return when and only when the supplied command exits, even if
        the command has launched background processes (e.g. with `bash -c "foo &"`).
        Any background processes will continue to run and will not be subject to the
        optional timeout.

        When executing a command over connect_get_namespaced_pod_exec, the websocket
        connection is not "naturally" closed until both:
        - The command has exited.
        - The stdout and stderr streams have been closed (including by any commands
          which have inherited them).
        This is behaviour of the CRI-O implementation which is running on the Kubernetes
        nodes.

        To support the required functionality, the supplied command is executed in a
        shell (/bin/sh).

        To allow this method to return when the supplied command has completed, even if
        backgrounded processes which inherit stdout or stderr are still running, the
        shell writes a marker holding the command's exit code to stdout and stderr once
        the command exits, and we then close the websocket connection.

        Args:
          cmd (list[str]): The command and arguments to execute.
          stdin (str | bytes | None): The optional standard input to pipe into cmd.
            The stdin file descriptor will be closed after the input has been written.
          cwd (str | None): The working directory to change to before executing cmd.
            Relative directories will be resolved relative to the pod's default working
            directory. If None, the default working directory is used. If the provided
            directory does not exist, an unsuccessful ExecResult will be returned and
            cmd will not be run.
          env (dict[str, str]): The environment variables to set before running cmd.
          user (str | None): The user to run the command as. If None, the default user
            for the pod will be used. The container must be running as root to run as a
            different user and runuser must be available at /sbin/runuser (a pod with
            execd needs no runuser).
          timeout (int | None): The optional timeout for cmd to complete in. Defaults to
            no timeout. If provided, SIGTERM will be sent to cmd once the timeout has
            elapsed. This is enforced by the `timeout` command on the pod. This will not
            terminate background processes started by cmd. On a pod with execd, cmd and
            its background processes get SIGKILL instead.
        """
        if (execd := self._execd) is not None:
            return await self._over_execd(
                lambda: execd.exec(cmd, stdin, cwd, env, user, timeout)
            )
        warned_restart = await self.check_for_pod_restart()
        info = self._info
        executor = ExecuteOperation(info)
        # One probe per container saves later execs as that user two process starts.
        key = (info.uid, info.initial_restart_count, user or "")
        try:
            if user and user not in ROOT_USERS and key not in self._switch:
                try:
                    self._switch[key] = await self._run_async(
                        lambda: executor.probe_switch(user)
                    )
                except (PodError, PodReplacedError, ContainerRestartedError):
                    # The shell's own check would wait on the same container, unbounded.
                    raise
                except Exception:
                    logger.debug("Probing exec(user=%r) failed", user, exc_info=True)
            # A probe answers only for the container it ran in, which may be gone now.
            switch = (
                self._switch.get(key, False) if user and self._info == info else False
            )
            result = await self._run_async(
                lambda: executor.exec(cmd, stdin, cwd, env, user, timeout, switch)
            )
        except ExecResultUnknownError:
            # A restart or replacement under the command explains a lost result better.
            if warned_restart is not None:
                raise warned_restart
            await self._diagnose_restart_after_failure()
            raise
        if not result.success:
            if warned_restart is not None:
                raise warned_restart
            await self._diagnose_restart_after_failure()
        return result

    async def exec_stdio(
        self, cmd: list[str], user: str | None
    ) -> PodStdio | ExecdStream:
        """Start a command as exec() does, and join a stream to its stdin and stdout."""
        if self._execd is not None:
            await self._check_before_execd()
            return await self._execd.open_stream(cmd, user, lambda: self._restart_error)
        await self.check_for_pod_restart()
        operation = ExecuteOperation(self._info)
        stack, ws_client = await self._run_async(
            lambda: operation.open_stdio(cmd, user),
            # The websocket opened for a caller that won't get it.
            discard=lambda opened: opened[0].close(),
        )
        return PodStdio(
            stack,
            ws_client,
            stopped=self._stdio_stopped,
            restarted=lambda: self._restart_error,
        )

    def _stdio_stopped(self) -> None:
        if self._info.restarted_container_behavior == "raise":
            self._keep_stopped()

    async def _diagnose_restart_after_failure(self) -> None:
        try:
            restart = await self.check_for_pod_restart()
        except (PodReplacedError, ContainerRestartedError):
            raise
        except Exception:
            logger.warning(
                "Restart re-check failed; keeping the failed operation's result",
                exc_info=True,
            )
            # Unless an operation kept one meanwhile.
            self._raise_restart()
            return
        if restart is not None:
            raise restart

    async def write_file(self, data: bytes, dst: Path) -> None:
        """
        Write ``data`` from the client to a path on the pod (dst).

        Existing files on the pod will be overwritten.

        Args:
          data (bytes): The contents to write to the pod.
          dst (Path): The path to write the file to on the pod. Relative paths will be
            resolved relative to the pod's default working directory.
        """
        if (execd := self._execd) is not None:
            return await self._over_execd(lambda: execd.write_file(data, dst))
        if _file_op_restart_check_enabled():
            await self.check_for_pod_restart()
        writer = WriteFileOperation(self._info)
        await self._after_failure_check(lambda: writer.write_file(data, dst))

    async def read_file(self, src: Path, dst: IO[bytes]) -> None:
        """
        Copy a file from the pod (src) to a file-like object (dst) on the client.

        The file-like object will not be seeked before or after the read. The file-like
        object must be opened for writing in binary mode.

        Args:
          src (Path): The path to the file on the pod. Relative paths will be resolved
            relative to the pod's default working directory.
          dst (IO[bytes]): A file-like object to write the file to on the client system.
        """
        if (execd := self._execd) is not None:
            return await self._over_execd(lambda: execd.read_file(src, dst))
        if _file_op_restart_check_enabled():
            await self.check_for_pod_restart()
        reader = ReadFileOperation(self._info)
        await self._after_failure_check(lambda: reader.read_file(src, dst))

    async def _after_failure_check(self, callable: Callable[[], None]) -> None:
        """Run a file operation, and in "raise" mode check for a restart if it fails."""
        try:
            await self._run_async(callable)
        except (PodReplacedError, ContainerRestartedError):
            raise
        except Exception:
            if self._info.restarted_container_behavior == "raise":
                await self._diagnose_restart_after_failure()
            raise

    async def _run_async(
        self, callable: Callable[[], T], discard: Callable[[T], object] | None = None
    ) -> T:
        """Run a synchronous function asynchronously."""

        def run() -> T:
            self._raise_restart()
            try:
                result = callable()
            except ContainerStoppedError as e:
                if self._info.restarted_container_behavior == "raise":
                    error = self._keep_stopped()
                    raise type(error)(**vars(error)) from e
                raise
            except Exception:
                # A restart found while it ran explains its failure better.
                self._raise_restart()
                raise
            try:
                self._raise_restart()
            except (PodReplacedError, ContainerRestartedError):
                if discard is not None:
                    discard(result)
                raise
            return result

        # Suspended first, as queueing would: a retrying caller must not hold the loop.
        if self._restart_error is not None:
            await asyncio.sleep(0)
            self._raise_restart()
        executor = PodOpExecutor.get_instance()
        try:
            result = await executor.queue_operation(run, discard=discard)
        except (PodReplacedError, ContainerRestartedError):
            raise
        except Exception:
            # Also if it was found before this resumed.
            self._raise_restart()
            raise
        try:
            self._raise_restart()
        except (PodReplacedError, ContainerRestartedError):
            if discard is not None:
                # Not on the event loop: closing a connection can wait on the server.
                threading.Thread(target=discard, args=(result,), daemon=True).start()
            raise
        return result

    async def _over_execd(self, operation: Callable[[], Awaitable[T]]) -> T:
        """Run an operation over execd, raising a kept restart as _run_async() does."""
        await self._check_before_execd()
        try:
            result = await operation()
        except Exception:
            self._raise_restart()
            raise
        self._raise_restart()
        return result

    async def _check_before_execd(self) -> None:
        """Raise a kept restart; look for one that shows only after execd restarted."""
        if self._restart_error is not None:
            await asyncio.sleep(0)  # as _run_async() suspends a caller in a loop
            self._raise_restart()
        now, started = time.monotonic(), self._execd_started
        late = started is not None and now - started >= RESTART_SHOWN_WITHIN
        if late or now - self._execd_restarted < RESTART_SHOWN_WITHIN:
            await self.check_for_pod_restart()
            if late and self._execd_started == started:
                self._execd_started = None  # a restart before that start shows by now

    def _keep_stopped(self) -> PodReplacedError | ContainerRestartedError:
        """Keep the restart of a container that stopped under an operation."""
        info = self._info
        # Gone, though Kubernetes may not show it stopped yet.
        return self._keep(
            ContainerRestartedError(
                pod_name=info.name,
                container_name=info.default_container_name,
                restart_count=info.initial_restart_count + 1,
                last_reason="stopped under an operation",
            )
        )

    def _keep(
        self, error: PodReplacedError | ContainerRestartedError
    ) -> PodReplacedError | ContainerRestartedError:
        """Keep ERROR unless a restart was kept already, and return the one kept."""
        with self._restart_lock:
            if self._restart_error is None:
                self._restart_error = error
            return self._restart_error

    def _raise_restart(self) -> None:
        if (error := self._restart_error) is not None:
            # A copy: raised again, one exception would collect every raise's frames.
            raise type(error)(**vars(error))
