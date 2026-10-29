"""Marking admission must precede every real role and survive common close."""

from copy import deepcopy

import pytest

from controller.qualify_labelled_split import evaluate_events, trial_script
from tests.test_split_roles import events as split_events


def events():
    rows = split_events()
    for row in rows:
        if row.get("event") != "station-service":
            continue
        operation = row["operation"]
        labelled = operation.startswith(("start-", "inspect-")) or operation in {
            "check-roles-policy",
            "close-roles",
        }
        if labelled:
            row["operation"] = "labelled-" + operation
        row["label_admission_verified"] = (
            labelled and operation.startswith(("start-", "inspect-")) and row["result"] == "ok"
        )
        row["label_policy_verified"] = (
            operation in {"check-roles-policy", "close-roles"} and row["result"] == "ok"
        )

    def service(operation, result):
        return dict(
            event="station-service",
            operation=operation,
            result=result,
            label_admission_verified=operation == "arm-labels" and result == "ok",
            label_policy_verified=False,
            isolation_verified=False,
        )

    rows[:0] = [
        service("labelled-start-telemetry", "denied"),
        service("arm-labels", "denied"),
        service("arm-labels", "ok"),
        service("start-telemetry", "denied"),
    ]
    bus = next(i for i, row in enumerate(rows) if row.get("event") == "split-diagnostics-bus")
    rows.insert(bus + 1, service("arm-labels", "busy"))
    failed = next(
        i
        for i, row in enumerate(rows)
        if row.get("operation") == "labelled-check-roles-policy" and row["result"] == "failed"
    )
    rows.insert(
        failed, dict(event="label-flows-observed", entries=4, label=1073741824, arm_before_start=True)
    )
    rows.insert(failed + 2, service("check-roles-policy", "failed"))
    return rows


def test_labelled_complete_role_history():
    assert len(events()) == 44
    assert evaluate_events(events())
    assert not evaluate_events(events(), False)


@pytest.mark.parametrize(
    "fault",
    [
        "missing",
        "arm",
        "late_arm",
        "start",
        "inspect",
        "close",
        "policy",
        "flows",
        "unlabelled",
        "early_start",
        "scope",
        "legacy_policy",
        "isolation",
        "entries",
        "audio",
    ],
)
def test_incomplete_or_downgraded_history_refused(fault):
    rows = events()

    def first(operation):
        return next(row for row in rows if row.get("operation") == operation and row.get("result") == "ok")

    if fault == "missing":
        rows.pop(0)
    elif fault == "arm":
        first("arm-labels")["label_admission_verified"] = False
    elif fault == "late_arm":
        row = first("arm-labels")
        rows.remove(row)
        rows.insert(5, row)
    elif fault == "start":
        first("labelled-start-collector")["label_admission_verified"] = False
    elif fault == "inspect":
        first("labelled-inspect-platform")["label_admission_verified"] = False
    elif fault == "close":
        first("labelled-close-roles")["label_policy_verified"] = False
    elif fault == "policy":
        first("labelled-check-roles-policy")["label_policy_verified"] = False
    elif fault == "flows":
        next(row for row in rows if row.get("event") == "label-flows-observed")["arm_before_start"] = False
    elif fault == "unlabelled":
        first("labelled-start-collector")["operation"] = "start-collector"
    elif fault == "early_start":
        rows[0]["result"] = "ok"
    elif fault == "scope":
        first("labelled-close-roles")["closed_scope"] = "single_role"
    elif fault == "legacy_policy":
        next(row for row in rows if row.get("operation") == "check-roles-policy")["result"] = "ok"
    elif fault == "isolation":
        first("labelled-close-roles")["isolation_verified"] = True
    elif fault == "entries":
        next(row for row in rows if row.get("event") == "label-flows-observed")["entries"] = True
    elif fault == "audio":
        rows[-1]["capture_tool_used"] = True
    assert not evaluate_events(rows)


def test_template_installs_marking_before_arming_and_role_start():
    script = trial_script("HELPER")
    assert script.index('-t mangle -I OUTPUT 1 -j "$MARK"') < script.index('HELPER --lab-arm-labels "$CANON"')
    assert script.index('HELPER --lab-arm-labels "$CANON"\n') < script.index(
        'HELPER --lab-labelled-start-collector "$CANON"'
    )
    assert "--lab-labelled-close-roles" in script
    assert "label-$version-$hook" in script and "mark-hook-$version" in script
    assert 'if [ -f "$STATE/mark-chain-$version" ]' in script
    assert "sleep 95;" in script
    assert "iptables -F\n" not in script


def test_evaluation_does_not_rewrite_caller_records():
    rows = events()
    original = deepcopy(rows)
    assert evaluate_events(rows)
    assert rows == original
