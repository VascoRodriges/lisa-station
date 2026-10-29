"""Independent-service evidence cannot imply vendor admission or isolation."""

from copy import deepcopy

import pytest

from controller.qualify_auxiliary import evaluate_events
from tests.test_bootstrap import events as policy_events


def events():
    rows = []
    for index, operation in enumerate(
        ["dns-start", "dns-status", "dns-status", "dns-status", "policy-status", "dns-start", "dns-stop"]
    ):
        row = deepcopy(policy_events()[15])
        row.update(
            operation="lab-" + operation,
            result="denied" if index == 4 else "ok",
            requested_mode="unknown" if index < 2 else "paused",
            dns_operation_ok=None if index == 4 else True,
            namespace_owned=False,
            policy_ready=False,
        )
        rows.append(row)
    return (
        rows[:6]
        + [
            dict(
                event="profile-child",
                uid=65534,
                gid=65534,
                capabilities_zero=True,
                no_new_privs=True,
                clock_writes_denied=True,
            )
        ]
        + [
            dict(event="dns-query", family=family, transport=transport, ok=True)
            for family in (4, 6)
            for transport in ("udp", "tcp")
        ]
        + [rows[-1], dict(event="auxiliary-cleanup", stock_services_changed=False, firewall_changed=False)]
    )


def test_complete_independence_evidence():
    assert evaluate_events(events())


@pytest.mark.parametrize(
    "index,key,value",
    [
        (0, "requested_mode", "paused"),
        (1, "result", "denied"),
        (2, "requested_mode", "unknown"),
        (2, "dns_operation_ok", 1),
        (3, "namespace_owned", True),
        (3, "policy_ready", True),
        (4, "result", "ok"),
        (4, "dns_operation_ok", False),
        (5, "elapsed_ms", 7000),
        (5, "elapsed_ms", True),
        (5, "vendor_started", True),
        (5, "stock_fallback", True),
        (5, "isolation_verified", True),
        (6, "capabilities_zero", 1),
        (6, "no_new_privs", False),
        (6, "clock_writes_denied", False),
        (7, "ok", 1),
        (8, "transport", "udp"),
        (10, "family", 4),
        (11, "result", "denied"),
        (12, "stock_services_changed", True),
        (12, "firewall_changed", 0),
    ],
)
def test_incomplete_or_fabricated_evidence_rejected(index, key, value):
    rows = events()
    rows[index][key] = value
    assert not evaluate_events(rows)


@pytest.mark.parametrize("value", [None, {}, [], [None] * 13])
def test_invalid_shape_rejected(value):
    assert not evaluate_events(value)


def test_order_and_event_count_required():
    rows = events()
    rows[7], rows[11] = rows[11], rows[7]
    assert not evaluate_events(rows)
    assert not evaluate_events(events()[:-1])
