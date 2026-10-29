"""A closed-mode change must retain denial and invalidate a cancelled opener."""

import pytest

from controller.qualify_closed_rollover import evaluate_events, trial_script


def events():
    def stage(
        op,
        revision,
        epoch,
        mode,
        requested,
        phase,
        closed,
        opened,
        pending,
        permit,
        choice,
        steps,
        result="ok",
    ):
        return dict(
            event="epoch-mutation",
            operation=op,
            result=result,
            phase=phase,
            revision=revision,
            epoch=epoch,
            mode_revision=mode,
            requested_mode=requested,
            boot_choice=choice,
            opening_pending=pending,
            permit_valid=permit,
            policy_closed=closed,
            policy_open=opened,
            mutation_steps=steps,
            control_ipv4=True,
            control_ipv6=True,
            vendor_started=False,
            stock_fallback=False,
            audio_opened=False,
            isolation_verified=False,
        )

    return [
        stage("reserve", 1, 1, 1, "paused", "closed", True, False, False, False, "paused", 36),
        stage("close-lisa", 1, 1, 2, "lisa", "closed", True, False, False, False, "paused", 2),
        stage("close-lisa", 1, 1, 3, "lisa", "closed", True, False, False, False, "paused", 2),
        stage("close", 1, 1, 4, "paused", "closed", True, False, False, False, "paused", 2),
        stage("open", 5, 2, 5, "alice", "open", False, True, False, True, "alice", 32),
        stage("close", 5, 2, 6, "paused", "closed", True, False, False, False, "paused", 18),
        stage("close-lisa", 5, 2, 7, "lisa", "closed", True, False, False, False, "paused", 2),
        dict(event="mutation-fault", step=3),
        dict(event="rollover-fault-exit", exit_code=137),
        stage("status", 8, 3, 7, "lisa", "arming", False, False, True, False, "paused", 0),
        stage("close", 8, 3, 8, "paused", "closed", True, False, True, False, "paused", 10),
        stage("open", 8, 3, 8, "paused", "closed", True, False, True, False, "paused", 0, "denied"),
        dict(event="rollover-stale-exit", exit_code=4),
        stage("open", 9, 4, 9, "alice", "open", False, True, False, True, "alice", 32),
        stage("close", 9, 4, 10, "paused", "closed", True, False, False, False, "paused", 18),
        dict(event="rollover-cleanup", ok=True),
    ]


def test_complete_closed_rollover_and_cancel_evidence():
    assert evaluate_events(events())


@pytest.mark.parametrize(
    "index,key,value",
    [
        (1, "policy_open", True),
        (1, "permit_valid", True),
        (1, "boot_choice", "alice"),
        (2, "mode_revision", 2),
        (3, "policy_closed", 1),
        (4, "isolation_verified", True),
        (7, "step", 1),
        (8, "exit_code", 0),
        (9, "opening_pending", False),
        (10, "mode_revision", 7),
        (10, "opening_pending", False),
        (10, "permit_valid", True),
        (11, "result", "ok"),
        (11, "mutation_steps", 1),
        (11, "policy_open", True),
        (12, "exit_code", 0),
        (13, "mode_revision", 8),
        (13, "revision", 8),
        (14, "control_ipv6", False),
        (14, "control_ipv4", False),
        (14, "audio_opened", True),
        (15, "ok", 1),
    ],
)
def test_incomplete_or_fabricated_state_rejected(index, key, value):
    rows = events()
    rows[index][key] = value
    assert not evaluate_events(rows)


def test_missing_or_reordered_events_rejected():
    assert not evaluate_events(events()[:-1])
    rows = events()
    rows[10], rows[11] = rows[11], rows[10]
    assert not evaluate_events(rows)


@pytest.mark.parametrize("value", [None, {}, [], [None] * 16])
def test_invalid_shape_rejected(value):
    assert not evaluate_events(value)


def test_rollover_fixture_has_no_unclosed_heredoc():
    script = trial_script()
    assert "\nCLEANUP\nwait_event()" in script
    assert 'COORD --lab-open "$CANON" 7 3' in script


def test_changed_opening_boundary_requires_review(monkeypatch):
    monkeypatch.setattr("controller.qualify_closed_rollover.OPENING_BODY", "exit 0")
    with pytest.raises(RuntimeError):
        trial_script()
