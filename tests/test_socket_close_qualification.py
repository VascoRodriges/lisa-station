"""A partial or misleading native report must not qualify socket destruction."""

from copy import deepcopy

import pytest

from controller.qualify_socket_close import evaluate_events


def events():
    # The matrix here is independent of the evaluator's expected names.
    names = (
        "own_loopback_pairs",
        "lookup_matches_own_inode",
        "destroy_requires_cookie",
        "wrong_cookie_rejected",
        "restricted_root_denied",
        "exact_cookie_destroyed",
        "target_endpoints_closed",
        "stale_destroy_rejected",
        "unrelated_connection_survives",
    )
    rows = [
        dict(event="socket-close-check", family=family, check=name, ok=True)
        for family in ("ipv4", "ipv6", "ipv4-mapped-ipv6")
        for name in names
    ]
    return rows + [
        dict(
            event="socket-close-summary",
            checks=27,
            failures=0,
            microphone_opened=False,
            vendor_processes_changed=False,
        )
    ]


def test_complete_socket_close_qualification():
    assert evaluate_events(events())


@pytest.mark.parametrize("mutation", ("missing", "duplicate", "failed", "truthy", "summary", "audio"))
def test_partial_or_false_report_rejected(mutation):
    rows = deepcopy(events())
    if mutation == "missing":
        rows.pop(0)
    elif mutation == "duplicate":
        rows[0] = deepcopy(rows[1])
    elif mutation == "failed":
        rows[0]["ok"] = False
    elif mutation == "truthy":
        rows[0]["ok"] = "true"
    elif mutation == "summary":
        rows[-1]["checks"] = 12
    elif mutation == "audio":
        rows[-1]["microphone_opened"] = True
    assert not evaluate_events(rows)
