"""Require complete observed flow/transition coverage without a privacy claim."""

from copy import deepcopy

import pytest

from controller.qualify_closed_flows import (
    RESUME_CHECKS,
    evaluate_events,
    evaluate_resume_events,
    expected_checks,
)


def events():
    checks = [
        dict(event="closed-flow-check", check=name, case=index, ok=True)
        for name, index in sorted(expected_checks())
    ]
    return checks + [
        dict(
            event="closed-flow-summary",
            checks=56,
            failures=0,
            ok=True,
            audio_captured=False,
            vendor_processes_changed=False,
            isolation_verified=False,
        ),
        dict(event="closed-flow-cleanup", ok=True),
    ]


def test_complete_closed_flow_trial():
    assert evaluate_events(events())


@pytest.mark.parametrize(
    "fault",
    (
        "missing",
        "duplicate",
        "failed_check",
        "wrong_case",
        "bool_case",
        "count",
        "capture",
        "vendor_change",
        "isolation",
        "cleanup",
        "extra",
    ),
)
def test_incomplete_closed_flow_trial_rejected(fault):
    rows = deepcopy(events())
    if fault == "missing":
        rows.pop(0)
    elif fault == "duplicate":
        rows[0] = deepcopy(rows[1])
    elif fault == "failed_check":
        rows[0]["ok"] = False
    elif fault == "wrong_case":
        rows[0]["case"] = 7
    elif fault == "bool_case":
        row = next(row for row in rows if row.get("case") == 1)
        row["case"] = True
    elif fault == "count":
        rows[-2]["checks"] = 55
    elif fault == "capture":
        rows[-2]["audio_captured"] = True
    elif fault == "vendor_change":
        rows[-2]["vendor_processes_changed"] = True
    elif fault == "isolation":
        rows[-2]["isolation_verified"] = True
    elif fault == "cleanup":
        rows[-1]["ok"] = False
    elif fault == "extra":
        rows.append(dict(event="unexpected"))
    assert not evaluate_events(rows)


def resume_events():
    return [
        dict(event="closed-flow-restart", coordinator_killed=True, drop_removed=True),
        *[dict(event="closed-flow-check", check=name, case=6, ok=True) for name in RESUME_CHECKS],
        dict(
            event="closed-flow-resume-summary",
            checks=8,
            failures=0,
            ok=True,
            audio_captured=False,
            vendor_processes_changed=False,
            isolation_verified=False,
        ),
        dict(event="closed-flow-cleanup", ok=True),
    ]


def test_fresh_coordinator_restores_closed_flow_scope():
    assert evaluate_resume_events(resume_events())


@pytest.mark.parametrize(
    "fault", ("not_killed", "no_rule_loss", "failed", "duplicate", "revision_missing", "scope", "cleanup")
)
def test_incomplete_coordinator_restart_rejected(fault):
    rows = resume_events()
    if fault == "not_killed":
        rows[0]["coordinator_killed"] = False
    elif fault == "no_rule_loss":
        rows[0]["drop_removed"] = False
    elif fault == "failed":
        rows[1]["ok"] = False
    elif fault == "duplicate":
        rows[1] = deepcopy(rows[2])
    elif fault == "revision_missing":
        rows = [row for row in rows if row.get("check") != "resume_revision_unchanged"]
    elif fault == "scope":
        rows[-2]["isolation_verified"] = True
    elif fault == "cleanup":
        rows[-1]["ok"] = False
    assert not evaluate_resume_events(rows)
