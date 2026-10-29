"""A watcher must respect live workers and recover abandoned transitions."""

import pytest

from controller.qualify_recovery_watch import evaluate_events, trial_script


def events():
    def stage(
        op, result, revision, epoch, mode, requested, phase, closed, opened, pending, permit, choice, steps
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

    def attribute(phase, epoch):
        return dict(
            event="epoch-attributed",
            family="ipv4",
            protocol="udp",
            phase=phase,
            epoch=epoch,
            mark=epoch << 24,
            ok=True,
        )

    def native(event, **kwargs):
        return dict(event=event, family="ipv4", protocol="udp", old_epoch=2, new_epoch=4, **kwargs)

    def check(name):
        return native("epoch-check", check=name, ok=True)

    def ready(phase):
        a, b = {"old": (20000, 20001), "closed": (0, 0), "recovery": (20000, 20001), "new": (20002, 20003)}[
            phase
        ]
        return native("epoch-ready", phase=phase, source_port=a, destination_port=b)

    rows = [
        stage("reserve", "ok", 1, 1, 1, "paused", "closed", True, False, False, False, "paused", 36),
        dict(event="watch-busy-proof", worker_alive=True, intent_unchanged=True, opening_pending=True),
        stage("open-hold", "ok", 2, 2, 2, "alice", "open", False, True, False, True, "alice", 32),
        stage("status", "ok", 2, 2, 2, "alice", "open", False, True, False, True, "alice", 0),
        attribute("old", 2),
        stage("close", "ok", 2, 2, 3, "paused", "closed", True, False, False, False, "paused", 18),
        dict(event="mutation-fault", step=20),
        dict(event="watch-worker-exit", code=137),
        stage("status", "ok", 4, 3, 5, "paused", "closed", True, False, True, False, "paused", 0),
        stage("status", "ok", 4, 3, 5, "paused", "closed", True, False, True, False, "paused", 0),
        attribute("recovered", 2),
        stage("open", "denied", 4, 3, 5, "paused", "closed", True, False, True, False, "paused", 0),
        dict(event="watch-stale-exit", code=4),
        stage("open", "ok", 6, 4, 6, "alice", "open", False, True, False, True, "alice", 32),
        attribute("new", 4),
        stage("close", "ok", 6, 4, 7, "paused", "closed", True, False, False, False, "paused", 18),
        check("baseline"),
        check("old_open_exchange"),
        ready("old"),
        check("old_closed"),
        check("unrelated_closed"),
        ready("closed"),
        check("old_during_recovery"),
        check("unrelated_recovery"),
        ready("recovery"),
        check("new_socket"),
        check("new_open_exchange"),
        check("old_still_denied"),
        check("unrelated_reopened"),
        ready("new"),
        check("new_closed"),
        check("old_remains_closed"),
        check("unrelated_final"),
        native("epoch-summary", checks=13, failures=0, audio_opened=False, vendor_processes_changed=False),
        dict(event="recovery-watch", state="ready", deadline_seconds=120),
        dict(event="recovery-watch", state="busy"),
        dict(
            event="recovery-watch",
            state="recovered",
            reason="cancel_open",
            base_revision=4,
            mode_revision=5,
            target="paused",
            policy_closed=True,
            permit_revoked=True,
        ),
        dict(
            event="recovery-watch-summary",
            busy_polls=2,
            recovered=1,
            idle_polls=3,
            faults=0,
            stopped=True,
            automatic_open=False,
            audio_opened=False,
        ),
        stage("watch", "ok", 6, 4, 7, "paused", "closed", True, False, False, False, "paused", 0),
        dict(event="watch-cleanup", ok=True),
    ]
    rows[15] = dict(event="mutation-fault", step=1)
    rows.insert(16, dict(event="watch-close-worker-exit", code=137))
    rows.insert(17, stage("status", "ok", 6, 4, 7, "lisa", "closed", True, False, False, False, "paused", 0))
    rows.insert(
        39,
        dict(
            event="recovery-watch",
            state="recovered",
            reason="finish_close",
            base_revision=6,
            mode_revision=7,
            target="lisa",
            policy_closed=True,
            permit_revoked=True,
        ),
    )
    rows[40]["recovered"] = 2
    rows[41]["requested_mode"] = "lisa"
    return rows


def test_complete_automatic_worker_recovery_evidence():
    assert evaluate_events(events())


@pytest.mark.parametrize(
    "index,key,value",
    [
        (1, "worker_alive", False),
        (1, "intent_unchanged", 1),
        (2, "mode_revision", 3),
        (3, "permit_valid", False),
        (6, "step", 1),
        (7, "code", 0),
        (8, "requested_mode", "alice"),
        (8, "opening_pending", False),
        (8, "permit_valid", True),
        (8, "control_ipv4", False),
        (9, "mode_revision", 6),
        (10, "mark", 3 << 24),
        (11, "result", "ok"),
        (11, "mutation_steps", 1),
        (12, "code", 0),
        (13, "isolation_verified", True),
        (15, "control_ipv6", False),
        (18, "source_port", True),
        (22, "ok", False),
        (23, "ok", False),
        (24, "source_port", 20002),
        (26, "ok", False),
        (27, "ok", 1),
        (31, "ok", False),
        (33, "failures", False),
        (33, "audio_opened", True),
        (34, "deadline_seconds", 0),
        (35, "state", "recovered"),
        (36, "mode_revision", 6),
        (36, "permit_revoked", 1),
        (37, "busy_polls", 0),
        (37, "idle_polls", 0),
        (37, "recovered", 0),
        (37, "recovered", 3),
        (37, "faults", 1),
        (37, "stopped", False),
        (37, "automatic_open", True),
        (37, "audio_opened", True),
        (38, "policy_closed", False),
        (39, "ok", 1),
    ],
)
def test_false_or_incomplete_recovery_claim_rejected(index, key, value):
    rows = events()
    index = 17 if index == 15 else index + (3 if index >= 37 else 2 if index >= 16 else 0)
    rows[index][key] = value
    assert not evaluate_events(rows)


def test_missing_or_reordered_evidence_rejected():
    assert not evaluate_events(events()[:-1])
    rows = events()
    rows[8], rows[11] = rows[11], rows[8]
    assert not evaluate_events(rows)


@pytest.mark.parametrize("value", [None, {}, [], [None] * 43])
def test_invalid_shape_rejected(value):
    assert not evaluate_events(value)


def test_fixture_cleans_up_its_watch_and_worker_before_rules():
    script = trial_script()
    assert "\nCLEANUP\nwait_event()" in script
    assert 'cleanup() { stop_auxiliaries; sh "$STATE/cleanup.sh" "$STATE"; }' in script
    assert "watch-child held-child worker-child" in script


def test_changed_body_requires_review(monkeypatch):
    monkeypatch.setattr("controller.qualify_recovery_watch.BODY", "exit 0")
    with pytest.raises(RuntimeError):
        trial_script()


@pytest.mark.parametrize(
    "index,key,value",
    [
        (15, "step", 20),
        (16, "code", 0),
        (17, "requested_mode", "paused"),
        (17, "permit_valid", True),
        (17, "policy_closed", False),
        (39, "reason", "cancel_open"),
        (39, "base_revision", 5),
        (39, "mode_revision", 8),
        (39, "target", "paused"),
        (39, "policy_closed", False),
        (39, "permit_revoked", 1),
        (41, "requested_mode", "paused"),
    ],
)
def test_abandoned_close_must_finish_original_target(index, key, value):
    rows = events()
    rows[index][key] = value
    assert not evaluate_events(rows)
