"""Require observed guarded startup and explicit closed recovery/restoration."""

from copy import deepcopy

import pytest

from controller.qualify_guardian_startup import evaluate_events


def events():
    def service(operation, result, revision=0):
        return dict(
            event="station-service",
            operation=operation,
            result=result,
            revision=revision,
            guardian_pid=10000 if result == "ok" and operation == "start-quasar" else 0,
            child_pid=10001 if result == "ok" and operation == "start-quasar" else 0,
            isolation_verified=False,
        )

    workers = [
        dict(pid=200 + i, gid=57342, no_new_privs=None, seccomp=2, cap_eff="0000003ffff7cfff")
        for i in range(4)
    ]
    return [
        service("start-quasar", "ok", 1),
        service("start-quasar", "busy"),
        *[dict(event="startup-sample", sample=i + 1, workers=deepcopy(workers)) for i in range(4)],
        service("request-paused", "ok", 2),
        dict(event="guardian-stopped", actors_absent=True),
        service("reconcile-quasar", "ok"),
        service("start-quasar", "denied"),
        dict(event="restored", workers=4, boot_changed=False, capture_tool_used=False),
    ]


def test_complete_guardian_trial():
    assert evaluate_events(events())


def closed_events():
    rows = events()
    rows[6].update(operation="close-quasar", transition_phase="complete")
    common = dict(
        event="station-service",
        operation="check-quasar-policy",
        revision=0,
        guardian_pid=0,
        child_pid=0,
        isolation_verified=False,
    )
    rows[6:6] = [
        dict(common, result="failed"),
        dict(common, result="ok"),
        dict(event="policy-controls", ipv4=True, ipv6=True),
    ]
    return rows


def test_complete_closed_policy_trial():
    assert evaluate_events(closed_events(), True)


@pytest.mark.parametrize(
    "fault", ("missing_v6_not_rejected", "no_complete_phase", "control_blocked", "unverified_scope")
)
def test_incomplete_closed_policy_trial_rejected(fault):
    rows = closed_events()
    if fault == "missing_v6_not_rejected":
        rows[6]["result"] = "ok"
    elif fault == "no_complete_phase":
        rows[9]["transition_phase"] = "network_denied"
    elif fault == "control_blocked":
        rows[8]["ipv6"] = False
    elif fault == "unverified_scope":
        rows[9]["isolation_verified"] = True
    assert not evaluate_events(rows, True)


@pytest.mark.parametrize(
    "fault", ("duplicate", "revision", "denied", "absence", "capture", "pid", "isolation", "partial", "extra")
)
def test_failed_or_misleading_guardian_trial_rejected(fault):
    rows = events()
    if fault == "duplicate":
        rows[1]["result"] = "ok"
    elif fault == "revision":
        rows[6]["revision"] = 1
    elif fault == "denied":
        rows[-2]["result"] = "ok"
    elif fault == "absence":
        rows[7]["actors_absent"] = False
    elif fault == "capture":
        rows[-1]["capture_tool_used"] = True
    elif fault == "pid":
        rows[0]["guardian_pid"] = 1
    elif fault == "isolation":
        rows[0]["isolation_verified"] = True
    elif fault == "partial":
        rows.pop(0)
    elif fault == "extra":
        rows.append(dict(event="unknown"))
    assert not evaluate_events(rows)
