"""Require observed diagnostic confinement, lifecycle and explicit restoration."""

from copy import deepcopy

import pytest

from controller.qualify_diagnostics import evaluate_events


def events():
    def service(operation, result, revision=0, guarded=False, phase="none"):
        return dict(
            event="station-service",
            operation=operation,
            result=result,
            revision=revision,
            child_pid=20002 if guarded else 0,
            guardian_pid=20001 if guarded else 0,
            diagnostics_jail_verified=guarded,
            transition_phase=phase,
            isolation_verified=False,
        )

    return [
        service("start-diagnostics", "busy"),
        service("start-diagnostics", "ok", 1, True),
        service("start-diagnostics", "busy"),
        *[service("inspect-diagnostics", "ok", 1, True) for _ in range(3)],
        dict(event="diagnostics-bus-owner", samples=3, matches_child=True),
        service("check-diagnostics-policy", "failed"),
        service("check-diagnostics-policy", "ok"),
        dict(event="policy-controls", ipv4=True, ipv6=True),
        service("close-diagnostics", "ok", 2, phase="complete"),
        dict(event="diagnostics-stopped", actors_absent=True),
        service("reconcile-diagnostics", "ok", phase="complete"),
        service("start-diagnostics", "denied", phase="complete"),
        dict(
            event="diagnostics-restored", stock_identity=True, private_logs_discarded=True, audio_opened=False
        ),
    ]


def test_complete_diagnostic_guard_trial():
    assert evaluate_events(events())


@pytest.mark.parametrize(
    "fault",
    (
        "missing",
        "duplicate_unmanaged",
        "no_jail",
        "different_child",
        "different_guardian",
        "revision",
        "v6_not_checked",
        "control_blocked",
        "close_incomplete",
        "still_running",
        "not_restored",
        "logs_retained",
        "audio",
        "isolation",
        "restart_allowed",
        "extra",
        "bus_owner",
        "bus_samples",
    ),
)
def test_incomplete_diagnostic_guard_trial_rejected(fault):
    rows = deepcopy(events())
    if fault == "missing":
        rows.pop(3)
    elif fault == "duplicate_unmanaged":
        rows[0]["result"] = "ok"
    elif fault == "no_jail":
        rows[3]["diagnostics_jail_verified"] = False
    elif fault == "different_child":
        rows[4]["child_pid"] += 1
    elif fault == "different_guardian":
        rows[4]["guardian_pid"] += 1
    elif fault == "revision":
        rows[3]["revision"] = 2
    elif fault == "v6_not_checked":
        rows[7]["result"] = "ok"
    elif fault == "control_blocked":
        rows[9]["ipv6"] = False
    elif fault == "close_incomplete":
        rows[10]["transition_phase"] = "network_denied"
    elif fault == "still_running":
        rows[11]["actors_absent"] = False
    elif fault == "not_restored":
        rows[-1]["stock_identity"] = False
    elif fault == "logs_retained":
        rows[-1]["private_logs_discarded"] = False
    elif fault == "audio":
        rows[-1]["audio_opened"] = True
    elif fault == "isolation":
        rows[1]["isolation_verified"] = True
    elif fault == "restart_allowed":
        rows[-2]["result"] = "ok"
    elif fault == "extra":
        rows.append(dict(event="unexpected"))
    elif fault == "bus_owner":
        rows[6]["matches_child"] = False
    elif fault == "bus_samples":
        rows[6]["samples"] = 2
    assert not evaluate_events(rows)
