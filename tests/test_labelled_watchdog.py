"""Independent recovery requires a real kill point and all scoped barriers."""

import pytest

from controller.qualify_labelled_watchdog import evaluate_events, trial_script
from tests.test_labelled_split import events as labelled_events


def events():
    rows = labelled_events()
    for row in rows:
        if row.get("operation") == "check-roles-policy":
            row["closed_scope"] = "guarded_roles"
    close = next(i for i, row in enumerate(rows) if row.get("operation") == "labelled-close-roles")
    return rows[:close] + [
        dict(event="labelled-fault-injected", point="after_all_barriers_before_close", signal=9),
        dict(
            event="labelled-watchdog-recovered",
            inner_exit=137,
            elapsed_seconds=99,
            lock_released=True,
            ordinary_workers=4,
            ordinary_diagnostics=True,
            capture_tool_used=False,
        ),
    ]


def test_complete_watchdog_evidence():
    assert len(events()) == 38
    assert evaluate_events(events())
    assert not evaluate_events(events(), False)


@pytest.mark.parametrize(
    "fault",
    [
        "missing",
        "signal",
        "early",
        "exit",
        "fast",
        "slow",
        "lock",
        "workers",
        "diagnostics",
        "audio",
        "admission",
        "identity",
        "group",
        "barrier",
        "controls",
        "scope",
    ],
)
def test_missing_or_overstated_recovery_refused(fault):
    rows = events()
    if fault == "missing":
        rows.pop()
    elif fault == "signal":
        rows[-2]["signal"] = 15
    elif fault == "early":
        rows[-2]["point"] = "before_roles"
    elif fault == "exit":
        rows[-1]["inner_exit"] = 0
    elif fault == "fast":
        rows[-1]["elapsed_seconds"] = 1
    elif fault == "slow":
        rows[-1]["elapsed_seconds"] = 1000
    elif fault == "lock":
        rows[-1]["lock_released"] = False
    elif fault == "workers":
        rows[-1]["ordinary_workers"] = True
    elif fault == "diagnostics":
        rows[-1]["ordinary_diagnostics"] = False
    elif fault == "audio":
        rows[-1]["capture_tool_used"] = True
    elif fault == "admission":
        rows[2]["label_admission_verified"] = False
    elif fault == "identity":
        next(row for row in rows if row.get("operation") == "labelled-inspect-platform")["child_pid"] = 123
    elif fault == "group":
        next(row for row in rows if row.get("event") == "startup-sample")["workers"][0]["gid"] = 0
    elif fault == "barrier":
        rows[-4]["label_policy_verified"] = False
    elif fault == "controls":
        rows[-3]["ipv6"] = False
    elif fault == "scope":
        rows[-4]["closed_scope"] = "single_role"
    assert not evaluate_events(rows)


def test_outer_observer_never_calls_restore_itself():
    script = trial_script("HELPER")
    outer = script.split("\nLISA_LABELLED_INNER_END\n", 1)[1]
    assert 'sh "$STAGE/trial.sh"' in outer
    assert "restore.sh" not in outer
    assert '"$result" = 137' in outer
    assert "ordinary_workers" in outer
    assert script.index('HELPER --lab-labelled-check-roles-policy "$CANON"\n') < script.index("kill -KILL $$")
    assert script.index("kill -KILL $$") < script.index('HELPER --lab-labelled-close-roles "$CANON" >')
