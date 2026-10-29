"""Require actual guarded mixer evidence without conflating it with privacy."""

from copy import deepcopy

import pytest

from controller.qualify_hardware import evaluate_events, trial_script
from tests.test_bootstrap import events as policy_events


def events():
    rows = policy_events()
    hardware = []
    for index, operation in enumerate(["start", "start", "status", "start", "status", "status", "stop"]):
        row = deepcopy(rows[15])
        row.update(
            operation="lab-hardware-" + operation,
            requested_mode=["paused"] * 4 + ["alice", "lisa", "lisa"],
            hardware_operation_ok=index != 0,
            known_legacy_actors=7 - (index != 0),
            result="ok" if index else "denied",
        )
        row["requested_mode"] = row["requested_mode"][index]
        hardware.append(row)
    return (
        rows[:-1]
        + hardware[:4]
        + [dict(event="hardware-mixer", mapped_change_verified=True, level_restored=True, pcm_opened=False)]
        + hardware[4:]
        + [
            dict(
                event="hardware-restored", stock_mixer_running=True, volume_preserved=True, pcm_opened=False
            ),
            rows[-1],
        ]
    )


def test_guarded_hardware_and_restoration():
    assert evaluate_events(events())


@pytest.mark.parametrize(
    "index,key,value",
    [
        (16, "result", "ok"),
        (17, "hardware_operation_ok", False),
        (17, "hardware_operation_ok", 1),
        (17, "policy_ready", False),
        (17, "namespace_owned", False),
        (17, "isolation_verified", True),
        (17, "stock_fallback", True),
        (17, "vendor_started", True),
        (17, "elapsed_ms", 4000),
        (17, "known_legacy_actors", 7),
        (17, "tagged_actors", 1),
        (20, "mapped_change_verified", False),
        (20, "level_restored", False),
        (20, "pcm_opened", True),
        (21, "requested_mode", "paused"),
        (22, "requested_mode", "alice"),
        (23, "result", "denied"),
        (24, "pcm_opened", True),
        (24, "volume_preserved", False),
        (24, "stock_mixer_running", False),
    ],
)
def test_missing_boundaries_are_not_qualification(index, key, value):
    rows = events()
    rows[index][key] = value
    assert not evaluate_events(rows)


def test_changed_boot_fixture_is_not_silently_reused(monkeypatch):
    monkeypatch.setattr("controller.qualify_hardware.POLICY_SCRIPT", "exit 0")
    with pytest.raises(RuntimeError):
        trial_script()


def test_trial_never_restarts_voice_or_captures_pcm():
    script = trial_script()
    assert "/etc/init.d/S46hardvold stop" in script
    assert "/etc/init.d/S46hardvold start" in script
    assert "S99quasar" not in script and "arecord" not in script
