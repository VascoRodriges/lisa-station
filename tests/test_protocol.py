"""A partial or contradictory observation must never imply Yandex isolation."""

import json

import pytest

from custom_components.lisa_station.protocol import (
    ProtocolError,
    RequestedMode,
    parse_status,
    require_mode_support,
)


def test_no_workers_does_not_prove_isolation(status_payload):
    status_payload["stock_workers"] = 0
    status = parse_status(json.dumps(status_payload))
    assert status.isolation_confirmed is None
    assert not status.can_change_mode
    for mode in RequestedMode:
        with pytest.raises(ProtocolError, match="mode_backend_not_installed"):
            require_mode_support(status, mode)


@pytest.mark.parametrize(
    "changes",
    [
        {"isolation": "verified"},
        {"apply_supported": True},
        {"actual_mode": "lisa"},
        {"managed": True},
        {"audio_opened": True},
        {"schema_version": 2},
        {"schema_version": True},
        {"stock_workers": True},
        {"stopped_launchers": 2},
        {"physical_mute": 0},
        {"physical_mute": "false"},
    ],
)
def test_inconsistent_or_incompatible_status_rejected(status_payload, changes):
    with pytest.raises(ProtocolError):
        parse_status(json.dumps(status_payload | changes))


@pytest.mark.parametrize("payload", [b"{}", b"[]", b"invalid", b"\xff", b"x" * 8193])
def test_malformed_or_oversized_status_rejected(payload):
    with pytest.raises(ProtocolError):
        parse_status(payload)


def test_unknown_mute_stays_unknown(status_payload):
    status_payload["physical_mute"] = None
    assert parse_status(json.dumps(status_payload)).physical_mute is None
