"""A policy-only trial cannot attest to stock vendor isolation or cold boot."""

import pytest

from controller.qualify_bootstrap import SCRIPT, evaluate_events


def events():
    operations = [
        ("bootstrap", "denied"),
        ("lab-policy-status", "denied"),
        ("lab-policy", "ok"),
        ("lab-policy", "ok"),
        ("lab-policy-status", "ok"),
        ("lab-policy", "ok"),
        ("lab-policy", "incomplete"),
        ("lab-policy", "ok"),
        ("lab-policy", "incomplete"),
        ("lab-policy", "ok"),
        ("lab-policy", "incomplete"),
        ("lab-policy", "ok"),
        ("lab-policy", "denied"),
        ("lab-policy", "denied"),
        ("lab-policy", "ok"),
        ("lab-policy-status", "ok"),
    ]
    rows = []
    for i, (operation, result) in enumerate(operations):
        rows.append(
            dict(
                event="station-boot",
                operation=operation,
                result=result,
                lab_policy_only=i != 0,
                policy_ready=result == "ok",
                elapsed_ms=200,
                requested_mode="unknown" if i == 0 else "alice" if i == 13 else "paused",
                known_legacy_actors=None if i in {0, 13} else 7,
                tagged_actors=None if i in {0, 13} else 0,
                namespace_owned=i not in {0, 1, 12, 13},
                unrelated_controls_verified=True if operation == "lab-policy" and result == "ok" else None,
                vendor_started=False,
                stock_fallback=False,
                isolation_verified=False,
            )
        )
    return rows + [dict(event="boot-policy-cleanup", ok=True, vendor_started=False)]


def test_complete_owned_policy_recovery():
    assert evaluate_events(events())


@pytest.mark.parametrize(
    "index,key,value",
    [
        (0, "known_legacy_actors", 0),
        (0, "lab_policy_only", True),
        (2, "namespace_owned", False),
        (2, "unrelated_controls_verified", False),
        (2, "elapsed_ms", 4000),
        (2, "elapsed_ms", True),
        (2, "tagged_actors", 1),
        (2, "known_legacy_actors", 0),
        (2, "known_legacy_actors", True),
        (2, "isolation_verified", True),
        (2, "vendor_started", True),
        (2, "stock_fallback", True),
        (4, "unrelated_controls_verified", True),
        (5, "result", "incomplete"),
        (6, "result", "ok"),
        (8, "result", "ok"),
        (10, "result", "ok"),
        (12, "namespace_owned", True),
        (13, "policy_ready", True),
        (13, "requested_mode", "paused"),
        (13, "tagged_actors", 0),
        (16, "ok", False),
    ],
)
def test_refuse_overstated_or_incomplete_evidence(index, key, value):
    rows = events()
    rows[index][key] = value
    assert not evaluate_events(rows)


def test_refuse_missing_cleanup_or_replaced_protocol_event():
    assert not evaluate_events(events()[:-1])
    rows = events()
    rows[5] = dict(rows[4])
    assert not evaluate_events(rows)


def test_fixture_never_stops_stock_services_or_flushes_global_tables():
    assert 'sleep 70; sh "$1/cleanup.sh" "$1"' in SCRIPT
    assert "test ! -d /bkupgrade/data/opt/lisa-station/state" in SCRIPT
    assert "iptables -F\n" not in SCRIPT
    assert "killall" not in SCRIPT and "kill -" not in SCRIPT
    assert "if($i>=57342&&$i<=57345)" in SCRIPT
    assert "expect lab-policy incomplete" in SCRIPT
