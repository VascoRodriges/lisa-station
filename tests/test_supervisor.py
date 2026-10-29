"""Scoped fault closure must have barrier, permit, persistence and inventory evidence."""

import pytest
from test_emergency import evidence as base_evidence

from controller.qualify_supervisor import evaluate_events, trial_script


def evidence():
    base = base_evidence()
    rows = base[:3]
    rows += [
        dict(event="supervisor-reader-proof", mode_unchanged=True, permit_retained=True, fault_absent=True),
        base[3],
        dict(event="recovery-watch", state="busy"),
        dict(event="supervisor-scope-busy"),
        dict(
            event="supervisor-fault",
            result="closed",
            reason="journals",
            barrier_verified=True,
            permit_revoked=True,
            fault_synced=True,
            actors_absent=True,
            automatic_open=False,
            audio_opened=False,
            isolation_verified=False,
        ),
        dict(
            event="recovery-watch-summary",
            busy_polls=3,
            idle_polls=3,
            recovered=0,
            faults=1,
            stopped=False,
            automatic_open=False,
            audio_opened=False,
        ),
    ]
    final = base[6].copy()
    final.update(operation="supervise", mode_revision=0, requested_mode="unknown")
    rows += [
        final,
        base[7],
        dict(
            event="emergency-resume",
            result="ok",
            cache_reconstructed=True,
            fault_valid=True,
            policy_closed=True,
            permit_absent=True,
            control_ipv4=True,
            control_ipv6=True,
            automatic_open=False,
            audio_opened=False,
            isolation_verified=False,
        ),
        dict(
            event="supervisor-preserved",
            damaged_mode=True,
            damaged_primary=True,
            fault_persisted=True,
            permit_absent=True,
        ),
    ]
    rows += base[9:]
    restarted = rows[9].copy()
    restarted["operation"] = "supervise-recover"
    rows[11:12] = [
        dict(event="recovery-watch", state="ready", deadline_seconds=120),
        rows[7].copy(),
        dict(
            event="recovery-watch-summary",
            busy_polls=0,
            idle_polls=0,
            recovered=0,
            faults=1,
            stopped=False,
            automatic_open=False,
            audio_opened=False,
        ),
        restarted,
        dict(event="supervisor-restart-exit", code=4),
    ]
    return rows


def test_complete_supervisor_evidence_and_both_contention_orders():
    assert len(evidence()) == 39
    assert evaluate_events(evidence())
    rows = evidence()
    rows[5], rows[6] = rows[6], rows[5]
    assert evaluate_events(rows)


@pytest.mark.parametrize(
    "index,key,value",
    [
        (1, "permit_valid", False),
        (2, "mark", 3 << 24),
        (3, "mode_unchanged", False),
        (3, "permit_retained", False),
        (3, "fault_absent", False),
        (4, "deadline_seconds", 0),
        (5, "state", "recovered"),
        (6, "event", "scope-unknown"),
        (7, "result", "incomplete"),
        (7, "reason", "scope"),
        (7, "barrier_verified", False),
        (7, "permit_revoked", False),
        (7, "fault_synced", False),
        (7, "actors_absent", False),
        (7, "barrier_verified", 1),
        (7, "isolation_verified", True),
        (7, "automatic_open", True),
        (8, "busy_polls", 0),
        (8, "idle_polls", 0),
        (8, "faults", True),
        (8, "recovered", 1),
        (9, "requested_mode", "alice"),
        (9, "mode_revision", 2),
        (9, "policy_closed", True),
        (10, "code", 0),
        (11, "cache_reconstructed", False),
        (11, "permit_absent", False),
        (12, "damaged_mode", False),
        (12, "damaged_primary", False),
        (12, "fault_persisted", False),
        (13, "result", "ok"),
        (13, "mutation_steps", 1),
        (14, "code", 0),
        (16, "ok", False),
        (17, "source_port", True),
        (21, "ok", False),
        (22, "ok", False),
        (24, "ok", False),
        (26, "ok", False),
        (28, "ok", False),
        (29, "ok", False),
        (31, "ok", False),
        (32, "ok", False),
        (33, "failures", 1),
        (34, "ok", 1),
    ],
)
def test_false_or_incomplete_scope_claim_rejected(index, key, value):
    rows = evidence()
    if index >= 12:
        index += 4
    elif index == 11:
        index = 12
        key = "barrier_verified" if key == "cache_reconstructed" else "permit_revoked"
    rows[index][key] = value
    assert not evaluate_events(rows)


def test_no_missing_or_duplicate_contention_proof():
    assert not evaluate_events(evidence()[:6] + evidence()[7:])
    rows = evidence()
    rows[6] = rows[5]
    assert not evaluate_events(rows)


def test_script_holds_real_reader_and_serializes_all_corruptions():
    script = trial_script()
    assert '--lab-supervise "$CANON" 120' in script
    assert 'exec 8<>"$STATE/run/epoch.lock"; flock -x 8' in script
    hold = script.index('exec 7<>"$STATE/state/transition.lock"')
    release = script.index("exec 7>&-", hold)
    for name in ["mode.state.new", "epoch.owner.new", "epoch.state.new"]:
        assert name in script[hold:release]
    assert script.index('--lab-supervise-recover "$CANON"') < script.index('cp "$STATE/mode.before"')
    assert 'rm "$STATE/state/fault.request"' not in script


@pytest.mark.parametrize("rows", [None, {}, [], [None] * 39])
def test_bad_shape_rejected(rows):
    assert not evaluate_events(rows)


@pytest.mark.parametrize(
    "index,key,value",
    [
        (13, "idle_polls", 1),
        (13, "recovered", 1),
        (14, "mode_revision", 2),
        (14, "requested_mode", "alice"),
        (15, "code", 0),
    ],
)
def test_restarted_loop_stays_closed_without_fabricating_intent(index, key, value):
    rows = evidence()
    rows[index][key] = value
    assert not evaluate_events(rows)
