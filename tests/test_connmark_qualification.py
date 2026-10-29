"""Require labelled flow evidence, orphan packet counters and unaffected controls."""

from copy import deepcopy

import pytest

from controller.qualify_connmark import SCRIPT, evaluate_events


def fixture():
    events = []
    common = [
        "baseline",
        "open_exchange",
        "unrelated_control_closed",
        "stray_to_closed_endpoint",
        "kernel_reply_denied",
        "unrelated_control_orphan",
        "kernel_reply_after_lab_restore",
        "unrelated_control_restored",
    ]
    for family in ("ipv4", "ipv6", "ipv4-mapped-ipv6"):
        for protocol in ("tcp", "udp"):
            base = dict(family=family, protocol=protocol)
            names = common + (
                ["own_socket_lookup", "own_socket_destroy", "reset_denied"]
                if protocol == "tcp"
                else ["unconnected_send_denied"]
            )
            events += [dict(base, event="label-check", check=name, ok=True) for name in names]
            events += [dict(base, event="label-attributed", group=57340, mark=1073741824)]
            events += [dict(base, event="label-ready", source_port=40000, destination_port=40001)]
            events += [dict(base, event=event) for event in ("label-closed", "label-orphan")]
            events += [
                dict(base, event="label-counter", phase="closed", packets=1),
                dict(base, event="label-counter", phase="orphan", packets=2),
            ]
            events += [
                dict(
                    base,
                    event="label-summary",
                    checks=len(names),
                    failures=0,
                    audio_opened=False,
                    vendor_processes_changed=False,
                )
            ]
    return events + [dict(event="label-cleanup", ok=True)]


def test_complete_own_flow_protocol():
    assert len(fixture()) == 103
    assert evaluate_events(fixture())


@pytest.mark.parametrize(
    "name",
    [
        "unrelated_control_closed",
        "unrelated_control_orphan",
        "unrelated_control_restored",
        "kernel_reply_denied",
        "kernel_reply_after_lab_restore",
        "own_socket_destroy",
        "unconnected_send_denied",
    ],
)
def test_every_boundary_and_control_required(name):
    rows = fixture()
    next(row for row in rows if row.get("check") == name)["ok"] = False
    assert not evaluate_events(rows)


@pytest.mark.parametrize(
    "event,key,value",
    [
        ("label-check", "ok", 1),
        ("label-attributed", "group", 0),
        ("label-attributed", "mark", 0),
        ("label-attributed", "group", True),
        ("label-ready", "source_port", 0),
        ("label-ready", "destination_port", True),
        ("label-counter", "packets", 0),
        ("label-counter", "packets", True),
        ("label-counter", "phase", "unknown"),
        ("label-summary", "checks", 0),
        ("label-summary", "failures", 1),
        ("label-summary", "failures", False),
        ("label-summary", "audio_opened", True),
        ("label-summary", "vendor_processes_changed", True),
        ("label-cleanup", "ok", False),
    ],
)
def test_reject_missing_or_overstated_proof(event, key, value):
    rows = fixture()
    next(row for row in rows if row["event"] == event)[key] = value
    assert not evaluate_events(rows)


def test_orphan_counter_must_increase():
    rows = fixture()
    next(row for row in rows if row.get("phase") == "orphan")["packets"] = 1
    assert not evaluate_events(rows)


def test_duplicate_proof_cannot_replace_case():
    rows = fixture()
    checks = [i for i, row in enumerate(rows) if row["event"] == "label-check"]
    rows[checks[1]] = deepcopy(rows[checks[0]])
    assert not evaluate_events(rows)


def test_incomplete_or_extra_event():
    assert not evaluate_events(fixture()[:-1])
    assert not evaluate_events(fixture() + [dict(event="label-cleanup", ok=True)])


def test_loopback_fixture_has_scoped_restoration_and_no_global_flush():
    assert "mkdir /data/opt/lisa-lab/trial.lock" in SCRIPT
    assert "test ! -d /bkupgrade/data/opt/lisa-station/state" in SCRIPT
    assert "CONNMARK --set-xmark 0x40000000/0x40000000" in SCRIPT
    assert '--sport "$destination" --dport "$source" -j RETURN' in SCRIPT
    assert 'sleep 60; sh "$1/cleanup.sh" "$1"' in SCRIPT
    assert " -F\n" not in SCRIPT
    assert "killall" not in SCRIPT
