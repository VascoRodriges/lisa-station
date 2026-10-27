"""Untrusted device status validation shared by the future HA transport.

No shell commands, audio, or mode mutations. The first agent supports read-only
diagnostics; even successful per-process self-tests must never light up the
whole-device privacy indicator.
"""

import json
from dataclasses import dataclass
from enum import Enum


class ProtocolError(ValueError):
    """The device did not provide a supported, internally consistent status."""


class RequestedMode(str, Enum):
    ALICE = "alice"
    LISA = "lisa"
    PAUSED = "paused"


@dataclass(frozen=True)
class FoundationStatus:
    stock_workers: int
    stock_launchers: int
    stopped_launchers: int
    physical_mute: bool | None
    root_readonly: bool | None

    @property
    def isolation_confirmed(self) -> None:
        # HA must display unknown, not an optimistic privacy state.
        return None

    @property
    def can_change_mode(self) -> bool:
        return False


def parse_status(payload: bytes | str) -> FoundationStatus:
    """Reject wrong versions, contradictory claims and oversized responses."""
    if len(payload) > 8192:
        raise ProtocolError("status_too_large")
    try:
        data = json.loads(payload)
    except (ValueError, UnicodeError) as error:
        raise ProtocolError("invalid_json") from error
    if not isinstance(data, dict):
        raise ProtocolError("not_an_object")
    expected = {
        "schema_version": 1,
        "agent_kind": "controller_foundation",
        "device_model": "yandex,station-midi",
        "managed": False,
        "actual_mode": "unmanaged",
        "requested_mode": None,
        "isolation": "unverified",
        "apply_supported": False,
        "audio_opened": False,
    }
    for key, value in expected.items():
        if key not in data or type(data[key]) is not type(value) or data[key] != value:
            raise ProtocolError("unsupported_or_inconsistent_" + key)
    counts = {}
    for key in ("stock_workers", "stock_launchers", "stopped_launchers"):
        value = data.get(key)
        if type(value) is not int or not 0 <= value <= 1024:
            raise ProtocolError("invalid_" + key)
        counts[key] = value
    if counts["stopped_launchers"] > counts["stock_launchers"]:
        raise ProtocolError("invalid_stopped_launchers")
    flags = {}
    for key in ("physical_mute", "root_readonly"):
        value = data.get(key)
        if key not in data or (value is not None and type(value) is not bool):
            raise ProtocolError("invalid_" + key)
        flags[key] = value
    if data.get("capabilities") != ["status", "sandbox-selftest"]:
        raise ProtocolError("unsupported_capabilities")
    return FoundationStatus(**counts, **flags)


def require_mode_support(status: FoundationStatus, requested: RequestedMode) -> None:
    """UI/planner gate: no successful-looking mode request on a status-only agent."""
    if not isinstance(requested, RequestedMode):
        raise ProtocolError("invalid_requested_mode")
    if not status.can_change_mode:
        raise ProtocolError("mode_backend_not_installed")
