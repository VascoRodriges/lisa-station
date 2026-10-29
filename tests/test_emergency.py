"""Emergency evidence must show selective denial and a retained fault latch."""

import pytest

from controller.qualify_emergency import evaluate_events, trial_script


def evidence():
    def stage(op, result, revision, epoch, choice, closed, opened, permit, steps):
        return dict(
            event="epoch-mutation",
            operation=op,
            result=result,
            phase="unknown" if revision == 0 else "closed" if revision == 1 else "open",
            revision=revision,
            epoch=epoch,
            mode_revision=1 if revision == 1 else 2,
            requested_mode="paused" if revision == 1 else "alice",
            boot_choice=choice,
            opening_pending=False,
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

    rows = [
        stage("reserve", "ok", 1, 1, "paused", True, False, False, 36),
        stage("open", "ok", 2, 2, "alice", False, True, True, 32),
        dict(
            event="epoch-attributed",
            family="ipv4",
            protocol="udp",
            phase="old",
            epoch=2,
            mark=2 << 24,
            ok=True,
        ),
        dict(event="recovery-watch", state="ready", deadline_seconds=120),
        dict(
            event="emergency-fault",
            latched=True,
            policy_closed=True,
            primary_preserved=True,
            automatic_open=False,
        ),
        dict(
            event="recovery-watch-summary",
            busy_polls=0,
            idle_polls=4,
            recovered=0,
            faults=1,
            stopped=False,
            automatic_open=False,
            audio_opened=False,
        ),
        stage("watch-emergency", "denied", 0, 0, "paused", None, None, False, 0),
        dict(event="emergency-watch-exit", code=4),
        dict(
            event="emergency-preserved",
            damaged_primary=True,
            intent_unchanged=True,
            fault_persisted=True,
            permit_absent=True,
        ),
        stage("open", "denied", 2, 2, "paused", False, False, False, 0),
        dict(event="emergency-open-exit", code=4),
    ]
    common = dict(family="ipv4", protocol="udp", old_epoch=2, new_epoch=3)
    names = ["baseline", "old_open_exchange", "old_closed", "unrelated_closed"]
    names += [f"group_{group}_{kind}" for group in range(57342, 57346) for kind in ["socket", "denied"]]
    names += ["old_root_reply_denied", "old_remains_closed", "unrelated_final"]
    for index, name in enumerate(names):
        rows.append(dict(event="epoch-check", **common, check=name, ok=True))
        if index in {1, 3, 12}:
            rows.append(
                dict(
                    event="epoch-ready",
                    **common,
                    phase={1: "old", 3: "closed", 12: "emergency"}[index],
                    source_port=20000 if index == 1 else 0,
                    destination_port=20001 if index == 1 else 0,
                )
            )
    rows.append(
        dict(
            event="epoch-summary",
            **common,
            checks=15,
            failures=0,
            audio_opened=False,
            vendor_processes_changed=False,
        )
    )
    rows.append(dict(event="emergency-cleanup", ok=True))
    return rows


def test_complete_emergency_evidence():
    assert evaluate_events(evidence())


def test_legitimate_worker_contention_is_optional_and_correlated():
    rows = evidence()
    rows[5]["busy_polls"] = 3
    assert not evaluate_events(rows)
    rows.insert(4, dict(event="recovery-watch", state="busy"))
    assert evaluate_events(rows)
    rows[6]["busy_polls"] = 0
    assert not evaluate_events(rows)


@pytest.mark.parametrize(
    "index,key,value",
    [
        (0, "control_ipv6", False),
        (1, "policy_open", False),
        (2, "mark", 3 << 24),
        (3, "deadline_seconds", 0),
        (4, "latched", False),
        (4, "policy_closed", False),
        (4, "primary_preserved", False),
        (4, "automatic_open", True),
        (5, "idle_polls", 0),
        (5, "faults", True),
        (5, "recovered", 1),
        (5, "stopped", True),
        (6, "policy_closed", True),
        (7, "code", 0),
        (8, "damaged_primary", False),
        (8, "intent_unchanged", False),
        (8, "fault_persisted", False),
        (8, "permit_absent", False),
        (9, "result", "ok"),
        (9, "boot_choice", "alice"),
        (9, "mutation_steps", 1),
        (10, "code", 0),
        (12, "ok", False),
        (13, "source_port", True),
        (16, "source_port", 1),
        (17, "ok", False),
        (18, "ok", 1),
        (19, "ok", False),
        (20, "ok", False),
        (21, "ok", False),
        (22, "ok", False),
        (23, "ok", False),
        (24, "ok", False),
        (25, "ok", False),
        (26, "destination_port", 1),
        (27, "ok", False),
        (28, "ok", False),
        (29, "checks", 14),
        (29, "audio_opened", True),
        (30, "ok", 1),
    ],
)
def test_incomplete_or_false_emergency_claim_rejected(index, key, value):
    rows = evidence()
    rows[index][key] = value
    assert not evaluate_events(rows)


@pytest.mark.parametrize("rows", [None, {}, [], [None] * 31])
def test_bad_shapes_rejected(rows):
    assert not evaluate_events(rows)


def test_cleanup_is_inside_watchdog_script_and_uses_separate_owner():
    script = trial_script()
    start = script.index('cat > "$STATE/cleanup.sh"')
    end = script.index("\nCLEANUP\n", start)
    assert start < script.index("emergency_owned=0") < end
    assert "LISA_EMERGENCY_V1" in script[start:end]
    assert "LISACE_" in script[start:end] and "LISACF_" in script[start:end]
    assert 'rm "$STATE/state/fault.request"' not in script
    assert 'cleanup() { stop_auxiliaries; sh "$STATE/cleanup.sh" "$STATE"; }' in script


def test_cleanup_retries_xtables_and_forgets_confirmed_absent_private_chain():
    script = trial_script()
    start = script.index('cat > "$STATE/cleanup.sh"')
    end = script.index("\nCLEANUP\n", start)
    cleanup = script[start:end]
    assert '"$tool" -w 5 -S' in cleanup
    assert '"$tool" -w 5 -F' in cleanup
    assert 'rm -f "$STATE/emergency-chain-$version-$name"' in cleanup
