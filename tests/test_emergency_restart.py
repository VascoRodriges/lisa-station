"""Restart evidence must preserve the fault and every interrupted checkpoint."""

import pytest
from test_emergency import evidence as base_evidence

from controller.qualify_emergency_restart import evaluate_events, trial_script


def evidence():
    base = base_evidence()
    rows = base[:4]
    for step in range(1, 10):
        rows.append(
            dict(
                event="emergency-checkpoint",
                step=step,
                fault_present=True,
                permit_absent=step == 9,
                policy_closed=step >= 7,
                control_ipv4=True,
                control_ipv6=True,
            )
        )
        rows.append(
            dict(event="emergency-watch-exit", code=137)
            if step == 1
            else dict(event="restart-worker-exit", step=step, code=137)
        )
        if step == 8:
            rows.append(
                dict(
                    event="epoch-attributed",
                    family="ipv4",
                    protocol="udp",
                    phase="retained",
                    epoch=2,
                    mark=2 << 24,
                    ok=True,
                )
            )

    def resumed(ok):
        return dict(
            event="emergency-resume",
            result="ok" if ok else "denied",
            cache_reconstructed=ok,
            fault_valid=ok,
            policy_closed=True if ok else None,
            permit_absent=True,
            control_ipv4=True,
            control_ipv6=True,
            automatic_open=False,
            audio_opened=False,
            isolation_verified=False,
        )

    rows.append(resumed(True))
    for case in ["public_mode", "hardlink"]:
        rows.append(resumed(False))
        rows.append(dict(event="restart-owner-refused", case=case, code=4, rules_unchanged=True))
    rows.append(resumed(True))
    rows += base[8:]
    return rows


def test_complete_nine_checkpoint_reconstruction():
    assert len(evidence()) == 52
    assert evaluate_events(evidence())
    rows = evidence()
    rows.insert(4, dict(event="recovery-watch", state="busy"))
    assert evaluate_events(rows)


@pytest.mark.parametrize("step", range(1, 10))
@pytest.mark.parametrize("key,value", [("fault_present", False), ("control_ipv6", False), ("step", True)])
def test_every_checkpoint_is_required_and_typed(step, key, value):
    rows = evidence()
    row = next(row for row in rows if row["event"] == "emergency-checkpoint" and row["step"] == step)
    row[key] = value
    assert not evaluate_events(rows)


@pytest.mark.parametrize(
    "index,key,value",
    [
        (0, "control_ipv4", False),
        (1, "policy_open", False),
        (2, "mark", 3 << 24),
        (4, "permit_absent", True),
        (4, "policy_closed", True),
        (5, "code", 4),
        (6, "policy_closed", True),
        (16, "policy_closed", False),
        (20, "mark", 3 << 24),
        (21, "permit_absent", False),
        (22, "code", 0),
        (23, "cache_reconstructed", False),
        (23, "fault_valid", False),
        (23, "permit_absent", False),
        (24, "result", "ok"),
        (25, "rules_unchanged", False),
        (26, "policy_closed", True),
        (27, "code", 0),
        (28, "automatic_open", True),
        (28, "isolation_verified", True),
        (29, "damaged_primary", False),
        (30, "boot_choice", "alice"),
        (30, "mutation_steps", 1),
        (31, "code", 0),
        (33, "ok", False),
        (45, "ok", False),
        (50, "failures", 1),
        (51, "ok", 1),
    ],
)
def test_false_reconstruction_or_flow_claim_rejected(index, key, value):
    rows = evidence()
    rows[index][key] = value
    assert not evaluate_events(rows)


def test_missing_reordered_and_extra_checkpoint_rejected():
    rows = evidence()
    assert not evaluate_events(rows[:6] + rows[8:])
    rows[6], rows[8] = rows[8], rows[6]
    assert not evaluate_events(rows)
    rows = evidence()
    rows.insert(4, dict(event="recovery-watch", state="unexpected"))
    assert not evaluate_events(rows)


def test_script_uses_real_crashes_and_only_restores_throwaway_primary_bytes():
    script = trial_script()
    assert '--lab-watch-emergency-crash "$CANON" 120 1' in script
    assert '--lab-emergency-resume "$CANON" "$step"' in script
    assert '[ "$result" = 137 ]' in script
    assert script.count("printf c >&3") == 1
    assert 'rm "$STATE/state/fault.request"' not in script
    assert script.index('--lab-emergency-resume "$CANON"') < script.index('cp "$STATE/owner.initial"')


@pytest.mark.parametrize("rows", [None, {}, [], [None] * 52])
def test_bad_shape_rejected(rows):
    assert not evaluate_events(rows)
