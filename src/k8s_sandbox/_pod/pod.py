from __future__ import annotations

import asyncio
import dataclasses
import logging
import os
import threading
from pathlib import Path
from typing import IO, Callable, Literal, TypeVar

from inspect_ai.util import ExecResult

from k8s_sandbox._pod.error import (
    ContainerRestartedError,
    ContainerStoppedError,
    ExecResultUnknownError,
    PodError,
    PodReplacedError,
)
from k8s_sandbox._pod.execute import ROOT_USERS, ExecuteOperation, PodStdio
from k8s_sandbox._pod.executor import PodOpExecutor
from k8s_sandbox._pod.op import PodInfo, check_for_pod_restart
from k8s_sandbox._pod.read import ReadFileOperation
from k8s_sandbox._pod.write import WriteFileOperation

T = TypeVar("T")

logger = logging.getLogger(__name__)


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
        # Whether exec() can start runuser directly to run as a user, per pod,
        # container start and user (see exec()).
        self._switch: dict[tuple[str, int, str], bool] = {}
        # What a check in "raise" mode detected, which every later operation raises.
        self._restart_error: PodReplacedError | ContainerRestartedError | None = None
        self._restart_lock = threading.Lock()

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

        The exit code comes from the exec's status channel, which reports /bin/sh's own
        exit status. To allow this method to return when the supplied command has
        completed, even if backgrounded processes which inherit stdout or stderr are
        still running, the shell writes a marker to both stdout and stderr once the
        command exits. The marker holds a random value made up for this exec, so the
        command's output cannot imitate it, and the command's exit code. If the
        websocket connection is still open shortly after both markers arrive, we close
        it and use the marker's exit code.

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
            different user and the runuser command must be available in the container.
          timeout (int | None): The optional timeout for cmd to complete in. Defaults to
            no timeout. If provided, SIGTERM will be sent to cmd once the timeout has
            elapsed. This is enforced by the `timeout` command on the pod. This will not
            terminate background processes started by cmd.
        """
        warned_restart = await self.check_for_pod_restart()
        info = self._info
        executor = ExecuteOperation(info)
        # Probing once per container spares later execs that switch user two process
        # starts each.
        key = (info.uid, info.initial_restart_count, user or "")
        try:
            if user and user not in ROOT_USERS and key not in self._switch:
                try:
                    self._switch[key] = await self._run_async(
                        lambda: executor.probe_switch(user)
                    )
                except (PodError, PodReplacedError, ContainerRestartedError):
                    # A probe that timed out: the shell's own check would wait on the
                    # same container, unbounded. Or a container that stopped under it.
                    raise
                except Exception:
                    logger.debug("Probing exec(user=%r) failed", user, exc_info=True)
            # A probe answers for the container it ran in: if this one was replaced or
            # restarted meanwhile, let its shell check for itself this time.
            switch = (
                self._switch.get(key, False) if user and self._info == info else False
            )
            result = await self._run_async(
                lambda: executor.exec(cmd, stdin, cwd, env, user, timeout, switch)
            )
        except ExecResultUnknownError:
            # A container restarted or replaced under the command explains the lost
            # result better.
            if warned_restart is not None:
                raise warned_restart
            await self._diagnose_restart_after_failure()
            raise
        if not result.success:
            if warned_restart is not None:
                raise warned_restart
            await self._diagnose_restart_after_failure()
        return result

    async def exec_stdio(self, cmd: list[str], user: str | None) -> PodStdio:
        """Start a command as exec() would, and join a stream to its stdin and stdout.

        Closing the stream ends the command's stdin and stdout. Until then the stream
        holds the exec's connection, so callers must close it.

        In "raise" mode a restart found already, or one Kubernetes shows, raises here
        as for exec(), rather than starting the command in the replacement. A stream
        that ends with 255 after the command wrote stdout, Kata's status for a command
        whose VM stopped, keeps a restart for every later operation: so the command must
        not exit 255 itself once it has written. A stream open when a restart is found
        drops, as one whose connection was lost.
        """
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
        if _file_op_restart_check_enabled():
            await self.check_for_pod_restart()
        reader = ReadFileOperation(self._info)
        await self._after_failure_check(lambda: reader.read_file(src, dst))

    async def _after_failure_check(self, callable: Callable[[], None]) -> None:
        """Run a file operation, and in "raise" mode check for a restart if it fails.

        Also when ``INSPECT_POD_RESTART_CHECK=false``: the replacement of a restarted
        container has none of the files the sample wrote, and the provider's retry of a
        lost connection must not reach it unchecked. "warn" mode leaves the failure, and
        any retry, as they were.
        """
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
        """Run a synchronous function asynchronously.

        Once a check in "raise" mode has detected a restart, raise it instead: before
        running the function, and after, if it was detected meanwhile, whether the
        function returned or failed. In "raise" mode a container that stopped under
        the function counts as restarted. DISCARD closes a result the caller won't
        get, such as an open connection: one a restart was found in, or one that came
        once the caller stopped waiting.
        """

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

        # Not queued behind other operations if it was found already, but suspended
        # first, as queueing would have: a caller retrying in a loop must not hold the
        # event loop.
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
            # A copy: one exception raised again collects each raise's frames, and
            # concurrent raises would share them.
            raise type(error)(**vars(error))
