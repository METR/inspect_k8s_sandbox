from typing import Any

import yaml
from kubernetes.stream.ws_client import (  # type: ignore[import-untyped]
    ERROR_CHANNEL,
    WSClient,
)

from k8s_sandbox._pod.error import (
    ContainerStoppedError,
    ExecutableNotFoundError,
    GetReturncodeError,
)


def get_returncode(ws_client: WSClient) -> int:
    """
    Extracts the returncode from a websocket client.

    Similar to the `WSClient.returncode` property, but with additional and more
    informative error handling.
    """
    assert not ws_client.is_open(), "ws_client must be closed to get return code."
    # Note: ERROR_CHANNEL is not the same as stderr. Aka status channel.
    return returncode_from_status(ws_client.read_channel(ERROR_CHANNEL))


def returncode_from_status(channel_value: Any) -> int:
    """The returncode in an exec's status, the message on its ERROR_CHANNEL."""
    if not channel_value:
        raise GetReturncodeError(
            "Failed to get returncode from k8s error channel because it was empty."
        )
    loaded = yaml.safe_load(channel_value)
    if "status" not in loaded:
        raise GetReturncodeError(
            "Failed to get returncode from k8s error channel because it did not "
            f"contain a `status` key. Error channel: {channel_value}",
        )
    if loaded["status"] == "Success":
        return 0
    for cause in loaded["details"]["causes"]:
        if cause.get("reason") == "ExitCode":
            return int(cause["message"])
    if "error finding executable" in loaded["message"]:
        raise ExecutableNotFoundError(loaded["message"])
    raise GetReturncodeError(
        "Failed to get returncode from k8s error channel because `status`!='Success' "
        "and there was no entry in `details.causes` with `reason`=='ExitCode'. "
        f"Error channel: {channel_value}",
    )


def raise_if_stopped_before_lost(
    ws_client: WSClient, lost: BaseException, pod: str
) -> None:
    """Raise ContainerStoppedError if the exec's status was 255 before it was lost."""
    if ERROR_CHANNEL not in ws_client._channels:
        return
    if ws_client.is_open():
        ws_client.close()
    try:
        returncode = get_returncode(ws_client)
    except Exception:
        return
    if returncode == 255:
        raise ContainerStoppedError(
            "The container stopped before the connection was lost.",
            pod=pod,
            returncode=returncode,
        ) from lost
