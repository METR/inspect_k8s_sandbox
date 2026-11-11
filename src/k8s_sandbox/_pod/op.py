import hashlib
import json
import logging
import shlex
import threading
from abc import ABC
from contextlib import contextmanager
from dataclasses import dataclass
from typing import Callable, Generator, Literal

from kubernetes.stream import stream  # type: ignore
from kubernetes.stream.ws_client import RESIZE_CHANNEL, WSClient  # type: ignore
from websocket import WebSocketException

from k8s_sandbox._kubernetes_api import k8s_client
from k8s_sandbox._pod.error import (
    ContainerRestartedError,
    ContainerStoppedError,
    PodError,
    PodReplacedError,
)
from k8s_sandbox._pod.get_returncode import (
    get_returncode,
    raise_if_stopped_before_lost,
)
from k8s_sandbox._pod.snapshot import read_pod

# The duration to wait for an initial response from the k8s API server.
# The initial response is received before the command is necessarily complete, so
# long-running commands will not be affected by this timeout.
# https://github.com/kubernetes-client/python/blob/master/examples/watch/timeout-settings.md
API_TIMEOUT = 60

# Interval between WebSocket keepalive frames. Containerd's CRI streaming server
# enforces a stream_idle_timeout (default 4h [1]) that closes connections with no
# data activity. Sending a resize-channel data frame resets the idle timer via
# resetTimeout() in the server's wsstream conn.go read loop [2]. 30 seconds is well
# under any realistic idle timeout while adding negligible overhead.
#
# [1] https://github.com/kubernetes/kubernetes/blob/db9fcfeed29b860d8dd7188bc1903c4709977890/staging/src/k8s.io/kubelet/pkg/cri/streaming/server.go#L100-L105
# [2] https://github.com/kubernetes/kubernetes/blob/77b02b7ad40d36cd803856de5ba5922c947cb0aa/staging/src/k8s.io/apimachinery/pkg/util/httpstream/wsstream/conn.go#L348-L356
_KEEPALIVE_INTERVAL_SECONDS = 30
# Maximum size of a single WebSocket stdin frame. Larger single writes (tens of
# MiB) make the kubelet/API-server/TLS layer reset the connection
# (ConnectionResetError / ssl.SSLEOFError), so stdin is written in chunks.
STDIN_CHUNK_SIZE = 1024**2  # 1 MiB
# AWS Nitro Sandboxes (EKS's `isolated-sandbox` runtime) can reorder an exec's stdin
# that arrives faster than the runtime forwards it, silently (staging, 2026-11: 0 of
# 2,500 payloads of 64 KiB corrupted, 4 of 500 at 128 KiB, every one at 16 MiB). So a
# bigger payload goes one piece of at most this size per exec, each piece checked
# against the sha256 the container computes (PodOperation._stage).
STDIN_PIECE_SIZE = 64 * 1024
# How many times a piece is sent before its corruption is an error.
_PIECE_ATTEMPTS = 3
# The helpers operations run besides the caller's command (`id` for exec(user=...),
# `base64` and `timeout` for exec(), `head` and `mkdir` for read_file() and
# write_file()) run as the container's user, so they are looked up only in these system
# directories, not through the image's PATH: busybox images have them only in /bin,
# and Debian 10 and Alpine have some only in /usr/bin. The caller's command keeps the
# container's PATH.
SYSTEM_PATH = "/usr/bin:/bin"

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class PodInfo:
    """
    Information required to interact with a Kubernetes pod.

    This class is immutable and thread-safe.
    """

    name: str
    namespace: str
    context_name: str | None
    """The name of the kubeconfig context. If None, use the current context."""
    default_container_name: str
    uid: str
    initial_restart_count: int
    restarted_container_behavior: Literal["warn", "raise"]


class PodOperation(ABC):
    """
    A base class for a synchronous operation on a pod.

    The purpose of splitting these operations into separate classes is to encapsulate
    and isolate their respective behaviour.
    """

    _failed_to_discard_duplicate_channel = False

    def __init__(self, pod: PodInfo):
        self._pod = pod

    def _write_stdin_chunked(self, ws_client: WSClient, data: str | bytes) -> None:
        """Write ``data`` to the stdin channel in ``STDIN_CHUNK_SIZE`` frames.

        Used by both exec and write_file (see ``STDIN_CHUNK_SIZE`` for why we
        chunk). The slice type is preserved: ``str`` -> text frames, ``bytes``
        -> binary frames.
        """
        for i in range(0, len(data), STDIN_CHUNK_SIZE):
            ws_client.write_stdin(data[i : i + STDIN_CHUNK_SIZE])

    def _stage(self, data: bytes, as_user: Callable[[list[str]], list[str]]) -> str:
        """Write `data` to a file named `data` in a new temporary directory in a pod.

        Returns the directory. Each exec sends at most STDIN_PIECE_SIZE bytes of stdin,
        and a piece whose sha256 comes back different is sent again. `as_user` wraps
        each command so that it runs as the caller's user.
        """
        directory: str | None = None
        for start in range(0, len(data), STDIN_PIECE_SIZE):
            piece = data[start : start + STDIN_PIECE_SIZE]
            name = f"{start // STDIN_PIECE_SIZE:08d}"
            for _ in range(_PIECE_ATTEMPTS):
                into = "$(mktemp -d)" if directory is None else shlex.quote(directory)
                script = (
                    f'd={into} && head -c {len(piece)} > "$d/{name}" && echo "$d" '
                    f'&& sha256sum < "$d/{name}"'
                )
                directory, digest = self._run_piece(as_user, script, piece)
                if digest == hashlib.sha256(piece).hexdigest():
                    break
            else:
                raise PodError(
                    f"A stdin piece arrived corrupted {_PIECE_ATTEMPTS} times.",
                    pod=self._pod.name,
                    piece=name,
                )
        assert directory is not None
        # The pieces' zero-padded names keep the glob in order.
        script = (
            f'd={shlex.quote(directory)} && cat "$d"/0* > "$d/data" && rm -f "$d"/0* '
            '&& echo "$d" && sha256sum < "$d/data"'
        )
        _, digest = self._run_piece(as_user, script, b"")
        if digest != hashlib.sha256(data).hexdigest():
            raise PodError(
                "A staged stdin payload was joined corrupted.", pod=self._pod.name
            )
        return directory

    def _run_piece(
        self, as_user: Callable[[list[str]], list[str]], script: str, piece: bytes
    ) -> tuple[str, str]:
        """Run `script` on `piece`; return the directory and the hash it prints."""
        command = as_user(["/bin/sh", "-c", f"PATH={SYSTEM_PATH}; {script}"])
        exec_command = contextmanager(self.create_websocket_client_for_exec)
        with exec_command(
            command=command, stderr=True, stdin=True, stdout=True, binary=False
        ) as ws_client:
            if piece:
                ws_client.write_stdin(piece)
            try:
                ws_client.run_forever()
            except (OSError, WebSocketException) as e:
                raise_if_stopped_before_lost(ws_client, e, self._pod.name)
                raise
            returncode = get_returncode(ws_client)
            # None of the commands exits 255: Kata gives it when the VM stopped.
            if returncode == 255:
                raise ContainerStoppedError(
                    "The container stopped while staging stdin.",
                    pod=self._pod.name,
                    returncode=returncode,
                )
            if returncode != 0:
                stderr = ws_client.read_stderr()
                raise_for_known_read_write_errors(stderr)
                raise PodError(
                    "Unrecognised error staging stdin.",
                    returncode=returncode,
                    stderr=stderr,
                )
            directory, digest = (ws_client.read_stdout().split() + ["", ""])[:2]
        return directory, digest

    def create_websocket_client_for_exec(
        self, send_keepalive: bool = True, **kwargs
    ) -> Generator[WSClient, None, None]:
        client = k8s_client(self._pod.context_name)
        # Note: ApiException is intentionally not caught; it should fail the eval.
        ws_client: WSClient = stream(
            client.connect_get_namespaced_pod_exec,
            name=self._pod.name,
            namespace=self._pod.namespace,
            container=self._pod.default_container_name,
            _preload_content=False,
            # This is the timeout for the API request, not the command itself.
            _request_timeout=API_TIMEOUT,
            **kwargs,
        )
        stop_keepalive = threading.Event()
        keepalive = threading.Thread(
            target=_send_keepalive,
            args=(ws_client, stop_keepalive),
            daemon=True,
            name="ws-keepalive",
        )
        try:
            self._discard_duplicate_channel(ws_client)
            if send_keepalive:
                keepalive.start()
            yield ws_client
        finally:
            stop_keepalive.set()
            ws_client.close()
            # Once the server has closed the connection, websocket-client's close()
            # returns without closing the socket, which then waits for the garbage
            # collector.
            if ws_client.sock:
                ws_client.sock.shutdown()

    def _discard_duplicate_channel(self, ws_client: WSClient) -> None:
        # Avoid issuing a warning multiple times.
        if PodOperation._failed_to_discard_duplicate_channel:
            return
        # WSClient stores all stdout and stderr in WSClient._all in addition to the
        # relevant channels. Set the _all channel to IgnoredIO to reduce memory usage.
        # https://github.com/kubernetes-client/python/issues/2302
        # Handle ImportError as we're importing a private class.
        try:
            from kubernetes.stream.ws_client import _IgnoredIO  # type: ignore
        except ImportError as e:
            logger.warning(
                f"Failed to set Kubernetes' WSClient._all channel to _IgnoredIO: {e}"
            )
            PodOperation._failed_to_discard_duplicate_channel = True
            return
        # Whilst we can set the _all attribute whether it exists or not, we should
        # log a warning if it doesn't exist as this may indicate a change in the
        # Kubernetes library.
        if not hasattr(ws_client, "_all"):
            logger.warning(
                "Failed to set Kubernetes' WSClient._all channel to _IgnoredIO: there "
                "was no _all attribute on the WSClient object."
            )
            PodOperation._failed_to_discard_duplicate_channel = True
            return
        ws_client._all = _IgnoredIO()


def check_for_pod_restart(pod: PodInfo) -> None:
    """Check whether the pod has been replaced or its container has restarted.

    Always raises a typed exception when a change is detected; callers
    (typically ``Pod._check_for_pod_restart_sync``) are responsible for
    applying the ``restarted_container_behavior`` policy and refreshing any
    cached identity.

    Raises:
        PodReplacedError: the pod's UID has changed since ``pod.uid``.
        ContainerRestartedError: the default container's restart count has
            increased since ``pod.initial_restart_count``, or, in ``"raise"``
            mode, it is not running.
        RuntimeError: the named container is no longer present on the pod
            (treated as a permanent misconfiguration).
    """
    api = k8s_client(pod.context_name)
    snapshot = read_pod(
        api, name=pod.name, namespace=pod.namespace, request_timeout=API_TIMEOUT
    )
    if snapshot.uid != pod.uid:
        # Capture the new pod's restart count for the default container so the
        # caller can refresh its full cached identity atomically.
        raise PodReplacedError(
            pod_name=pod.name,
            old_uid=pod.uid,
            new_uid=snapshot.uid,
            new_restart_count=snapshot.restart_count_for(pod.default_container_name),
        )
    if snapshot.container_statuses is None:
        # Kubelet hasn't published container statuses yet (briefly possible
        # right after pod scheduling). Nothing to compare against — skip the
        # restart-count check.
        return
    status = snapshot.status_for(pod.default_container_name)
    if status is None:
        raise RuntimeError(
            f"Pod '{snapshot.name}' does not have a container named "
            f"'{pod.default_container_name}'"
        )
    if status.restart_count > pod.initial_restart_count:
        raise ContainerRestartedError(
            pod_name=pod.name,
            container_name=status.name,
            restart_count=status.restart_count,
            last_reason=status.last_terminated_reason or "unknown",
        )
    if not status.running and pod.restarted_container_behavior == "raise":
        # The container stopped, and the kubelet is starting another, which an
        # operation can reach before its restart count is published (seconds later
        # when the restart replaces a Kata VM). "warn" reports it when the count moves.
        raise ContainerRestartedError(
            pod_name=pod.name,
            container_name=status.name,
            restart_count=status.restart_count + 1,
            last_reason=status.last_terminated_reason or "unknown",
        )


def _send_keepalive(ws_client: WSClient, stop: threading.Event) -> None:
    """Send periodic resize-channel frames to prevent idle timeout.

    Containerd's CRI streaming server closes WebSocket connections that receive no
    data frames within stream_idle_timeout (default 4h). Standard WebSocket pings do
    NOT reset this timer because the Python kubernetes client negotiates the
    v4.channel.k8s.io subprotocol [1], whose server-side handler uses
    golang.org/x/net/websocket. That library's Receive() silently consumes ping/pong
    control frames in an internal loop [2][3] without returning to the caller, so the
    resetTimeout() call in wsstream/conn.go (which sits *before* Receive()) is never
    re-executed.

    Writing to the resize channel (channel 4) sends a real data frame that causes
    Receive() to return, triggering resetTimeout() [4]. The resize handler silently
    ignores the payload since no TTY is allocated for non-interactive exec sessions.

    [1] https://github.com/kubernetes-client/python/blob/6fb1fd723eeb8880626118aeb95ebb1a7c73d5ad/kubernetes/base/stream/ws_client.py#L468-L472
    [2] https://github.com/golang/net/blob/2914f46773171f4fa13e276df1135bafef677801/websocket/websocket.go#L339-L349
    [3] https://github.com/golang/net/blob/2914f46773171f4fa13e276df1135bafef677801/websocket/hybi.go#L290-L302
    [4] https://github.com/kubernetes/kubernetes/blob/77b02b7ad40d36cd803856de5ba5922c947cb0aa/staging/src/k8s.io/apimachinery/pkg/util/httpstream/wsstream/conn.go#L348-L356

    Nothing is sent on v5.channel.k8s.io, which kubernetes>=36 negotiates first: there,
    resize frames on an exec without a TTY stop the server reading the exec's stdin.
    """
    if getattr(ws_client, "subprotocol", None) == "v5.channel.k8s.io":
        return
    payload = json.dumps({"Width": 80, "Height": 24}).encode()  # Size is arbitrary
    while not stop.wait(_KEEPALIVE_INTERVAL_SECONDS):
        try:
            if ws_client.is_open():
                ws_client.write_channel(RESIZE_CHANNEL, payload)
            else:
                break
        except Exception:
            logger.debug(
                "Failed to send k8s websocket keepalive frame, bailing out",
                exc_info=True,
            )
            break


def raise_for_known_read_write_errors(stderr: str) -> None:
    # The Inspect Sandbox interface asks us to raise specific exceptions for recognised
    # error messages.
    casefolded = stderr.casefold()
    if "no such file or directory" in casefolded:
        raise FileNotFoundError(stderr)
    if "permission denied" in casefolded:
        raise PermissionError(stderr)
    if "is a directory" in casefolded:
        raise IsADirectoryError(stderr)
