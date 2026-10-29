"""Synthetic proof of distinct roles, private epochs and explicit stock restore."""

from copy import deepcopy

import pytest

from controller.qualify_split import evaluate_events, trial_script

ROLES = ("telemetry", "collector", "platform", "diagnostics")


def events():
    identities = {role: (30001 + index * 2, 30002 + index * 2) for index, role in enumerate(ROLES)}

    def service(operation, result="ok", role=None, revision=1):
        child, guardian = identities.get(role, (0, 0))
        inspected = operation.startswith("inspect-")
        return dict(
            event="station-service",
            operation=operation,
            result=result,
            child_pid=child,
            guardian_pid=guardian,
            revision=revision,
            inspection_live=inspected,
            inspection_identity=inspected,
            inspection_view=inspected and role != "platform",
            inspection_resources=inspected,
            platform_workers_verified=inspected and role == "platform",
            closed_scope="guarded_roles"
            if operation in {"close-roles", "check-roles-policy"}
            else "single_role",
            transition_phase="complete" if operation == "close-roles" else "none",
            isolation_verified=False,
        )

    rows = [
        service("start-telemetry", role="telemetry"),
        service("start-collector", role="collector"),
        service("start-platform", role="platform"),
        service("start-platform", "busy"),
        service("start-diagnostics", role="diagnostics"),
        dict(event="split-diagnostics-bus", matched=True),
    ]
    workers = [
        dict(pid=40001, gid=57342, no_new_privs=None, seccomp=2, cap_eff="0000000000000000"),
        dict(pid=40002, gid=57342, no_new_privs=1, seccomp=2, cap_eff="0000000000000000"),
        dict(pid=30001, gid=57345, no_new_privs=1, seccomp=2, cap_eff="0000000000000000"),
        dict(pid=30003, gid=57344, no_new_privs=None, seccomp=2, cap_eff="0000000000000000"),
    ]
    for index in range(4):
        rows.append(dict(event="startup-sample", sample=index + 1, workers=deepcopy(workers)))
        rows.extend(service("inspect-" + role, role=role) for role in ROLES)
    rows.extend(
        [
            service("check-roles-policy", "failed"),
            service("check-roles-policy"),
            dict(event="policy-controls", ipv4=True, ipv6=True),
            service("close-roles", revision=2),
            dict(event="guardian-stopped", actors_absent=True),
        ]
    )
    rows.extend(service("reconcile-" + role) for role in ("quasar", "collector", "telemetry", "diagnostics"))
    rows.extend(
        [
            service("start-platform", "denied"),
            dict(event="restored", workers=4, boot_changed=False, capture_tool_used=False),
        ]
    )
    return rows


def test_complete_split_role_lifecycle():
    assert len(events()) == 37
    assert evaluate_events(events())
    assert not evaluate_events(events(), False)


@pytest.mark.parametrize(
    "fault",
    (
        "missing",
        "alias",
        "child",
        "guardian",
        "identity",
        "resource",
        "view",
        "platform",
        "revision",
        "scope",
        "isolation",
        "policy",
        "family",
        "phase",
        "stop",
        "reconcile",
        "fence",
        "restore",
        "bus",
        "audio",
    ),
)
def test_partial_split_role_proof_refused(fault):
    rows = events()

    def service(name):
        return next(row for row in rows if row.get("operation") == name)

    if fault == "missing":
        rows.pop(10)
    elif fault == "alias":
        rows[1]["child_pid"] = rows[0]["child_pid"]
    elif fault == "child":
        service("inspect-collector")["child_pid"] += 1
    elif fault == "guardian":
        service("inspect-platform")["guardian_pid"] += 1
    elif fault == "identity":
        service("inspect-telemetry")["inspection_identity"] = False
    elif fault == "resource":
        service("inspect-collector")["inspection_resources"] = False
    elif fault == "view":
        service("inspect-platform")["inspection_view"] = True
    elif fault == "platform":
        service("inspect-platform")["platform_workers_verified"] = False
    elif fault == "revision":
        service("inspect-diagnostics")["revision"] = 2
    elif fault == "scope":
        service("close-roles")["closed_scope"] = "single_role"
    elif fault == "isolation":
        service("close-roles")["isolation_verified"] = True
    elif fault == "policy":
        service("check-roles-policy")["result"] = "ok"
    elif fault == "family":
        next(row for row in rows if row["event"] == "policy-controls")["ipv6"] = False
    elif fault == "phase":
        service("close-roles")["transition_phase"] = "actors_stopped"
    elif fault == "stop":
        next(row for row in rows if row["event"] == "guardian-stopped")["actors_absent"] = False
    elif fault == "reconcile":
        service("reconcile-telemetry")["result"] = "failed"
    elif fault == "fence":
        rows[-2]["result"] = "ok"
    elif fault == "restore":
        rows[-1]["boot_changed"] = True
    elif fault == "bus":
        rows[5]["matched"] = False
    elif fault == "audio":
        rows[-1]["capture_tool_used"] = True
    assert not evaluate_events(rows)


@pytest.mark.parametrize(
    ("key", "value"),
    [
        ("gid", 0),
        ("pid", 1),
        ("pid", True),
        ("no_new_privs", 0),
        ("no_new_privs", True),
        ("seccomp", 0),
        ("cap_eff", "0000000000001000"),
        ("cap_eff", "invalid"),
    ],
)
def test_unprotected_or_invalid_worker_snapshot_refused(key, value):
    rows = events()
    rows[6]["workers"][0][key] = value
    assert not evaluate_events(rows)


def test_unexpected_sdk_holder_or_worker_generation_refused():
    rows = events()
    rows[6]["workers"][2]["pid"] += 20
    assert not evaluate_events(rows)
    rows = events()
    rows[11]["workers"][0]["pid"] += 20
    assert not evaluate_events(rows)


def test_split_script_owns_restore_for_every_role():
    script = trial_script("TEST_BACKEND")
    assert "PROBE" not in script
    assert "@COLLECTOR@" in script and "@TELEMETRY@" in script and "@LAUNCH@" in script
    assert "--lab-start-quasar" not in script
    assert "--maind-pids" in script
    assert "--lab-start-platform" in script
    assert '--lab-inspect-platform "$CANON"' in script
    assert '--lab-close-roles "$CANON"' in script
    assert "for role in collector telemetry diagnostics;" in script
    assert "start 9>&-" in script
    assert "sleep 95;" in script
    assert "if($i>=57342 && $i<=57345)" in script
    assert '/system/vendor/quasar/quasar.cfg >> "$STATE/launch.sha256"' in script
    assert "for group in 57342 57343 57344 57345;" in script
