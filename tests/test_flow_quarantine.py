"""Reject false quarantine evidence even if the native process returned zero."""

from copy import deepcopy

import pytest

from controller.qualify_flow_quarantine import evaluate_events


def events():
    tcp = (
        "baseline",
        "own_inode_confirmed",
        "client_destroyed",
        "reset_quarantined",
        "control_after_destroy",
        "closed_tuple_absent",
        "stray_sent_to_closed_endpoint",
        "post_close_kernel_reply_quarantined",
        "control_after_stray",
        "reset_arrives_after_rule_removal",
        "control_after_restore",
    )
    udp = (
        "baseline",
        "input_quarantined",
        "control_after_input",
        "output_quarantined",
        "control_after_output",
        "target_after_restore",
        "control_after_restore",
    )
    result = []
    for family in ("ipv4", "ipv6", "ipv4-mapped-ipv6"):
        for protocol, names in (("tcp", tcp), ("udp", udp)):
            base = dict(family=family, protocol=protocol)
            result.extend(dict(base, event="flow-check", check=name, ok=True) for name in names)
            result.append(dict(base, event="flow-ready", source_port=40001, destination_port=40002))
            result.append(
                dict(
                    base,
                    event="flow-summary",
                    checks=len(names),
                    failures=0,
                    microphone_opened=False,
                    vendor_processes_changed=False,
                )
            )
            if protocol == "tcp":
                result += [dict(base, event="flow-destroyed"), dict(base, event="flow-orphan-triggered")]
                result.append(
                    dict(base, event="flow-counters", phase="destroyed", socket_associated=1, no_socket=0)
                )
                result.append(
                    dict(
                        base,
                        event="flow-counters",
                        phase="orphan",
                        socket_associated=1 if family == "ipv6" else 3,
                        no_socket=2 if family == "ipv6" else 0,
                    )
                )
            else:
                result += [dict(base, event="flow-input-blocked"), dict(base, event="flow-output-blocked")]
                result.append(dict(base, event="flow-input-counter", packets=1))
                result.append(
                    dict(base, event="flow-counters", phase="blocked", socket_associated=1, no_socket=0)
                )
    return result + [dict(event="flow-cleanup", ok=True)]


def test_complete_quarantine_evidence():
    assert evaluate_events(events())


@pytest.mark.parametrize("value", ("1", True, -1, None))
def test_invalid_packet_counter_rejected(value):
    rows = events()
    next(row for row in rows if row["event"] == "flow-counters")["socket_associated"] = value
    assert not evaluate_events(rows)


@pytest.mark.parametrize("family", ("ipv4", "ipv6", "ipv4-mapped-ipv6"))
def test_missing_kernel_reply_evidence_rejected(family):
    rows = deepcopy(events())
    for row in rows:
        if row.get("family") == family and row.get("phase") == "orphan":
            row.update(socket_associated=1, no_socket=0)
    assert not evaluate_events(rows)


@pytest.mark.parametrize("fault", ("input_counter", "control", "summary", "cleanup", "partial", "extra"))
def test_incomplete_or_failed_quarantine_rejected(fault):
    rows = deepcopy(events())
    if fault == "input_counter":
        next(row for row in rows if row["event"] == "flow-input-counter")["packets"] = 0
    elif fault == "control":
        next(row for row in rows if row.get("check") == "control_after_restore")["ok"] = False
    elif fault == "summary":
        next(row for row in rows if row["event"] == "flow-summary")["microphone_opened"] = True
    elif fault == "cleanup":
        rows[-1]["ok"] = False
    elif fault == "partial":
        rows.pop(0)
    elif fault == "extra":
        rows.append(dict(event="unexpected"))
    assert not evaluate_events(rows)
