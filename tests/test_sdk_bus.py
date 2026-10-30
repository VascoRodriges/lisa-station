from copy import deepcopy

import pytest

from controller.qualify_sdk_bus import diagnostic_script, evaluate_events


def evidence():
    rows = []
    for role in ["own-elf", "platform"]:
        rows.append(dict(
            event="sdk-bus-diagnostic", role=role, boundary_ok=True,
            exec_verified=True, binding_mapped=True, drained=True,
            threads=9 if role == "own-elf" else 16, syscalls=900, denied=3,
            socket_attempts=2, lost_registers=0, bounded_stop=False,
            exit_code=-1, exit_signal=6, private_objects_mask=1 if role == "own-elf" else 0,
            path_control=role == "own-elf", private_stderr_bytes=328,
            private_stderr_truncated=False, synthetic_identity=True,
            audio_opened=False, functionality_verified=False,
        ))
        rows.append(dict(
            event="sdk-bus-relay", role=role, boundary_ok=True, actor_checks=11,
            result=0, origin=0, protocol_traffic=role == "own-elf",
        ))
    return rows + [
        dict(selftest="sdk-private-bus", ok=True, sdk_executed=True, audio_opened=False, functionality_verified=False),
        dict(event="private-bus-parent", checks=5, failures=0, unrelated_internet_controls=True),
        dict(event="private-bus-exit", code=0), dict(event="private-bus-cleanup", ok=True),
    ]


def test_accepts_boundary_proof_with_expected_sdk_dependency_failure():
    assert evaluate_events(evidence())
    rows = evidence()
    rows[2].update(exit_code=0, exit_signal=0)
    assert evaluate_events(rows)


@pytest.mark.parametrize("index", range(8))
def test_requires_complete_ordered_unique_events(index):
    rows = evidence()
    del rows[index]
    assert not evaluate_events(rows)
    rows = evidence()
    rows.insert(index, deepcopy(rows[index]))
    assert not evaluate_events(rows)
    rows = evidence()
    rows[index]["unexpected"] = True
    assert not evaluate_events(rows)
    rows = evidence()
    rows[index] = None
    assert not evaluate_events(rows)


@pytest.mark.parametrize("index", [0, 2])
@pytest.mark.parametrize("key,value", [
    ("boundary_ok", False), ("exec_verified", False), ("binding_mapped", False),
    ("drained", False), ("synthetic_identity", False), ("audio_opened", True),
    ("functionality_verified", True), ("threads", True), ("threads", 80),
    ("syscalls", 20001), ("syscalls", 0), ("denied", -1), ("socket_attempts", "2"),
    ("lost_registers", -1), ("bounded_stop", 0), ("exit_signal", 0), ("exit_code", 0),
    ("private_objects_mask", 64), ("private_stderr_bytes", 65537),
    ("private_stderr_truncated", 1), ("path_control", 1),
])
def test_rejects_unsafe_or_malformed_sdk_evidence(index, key, value):
    rows = evidence()
    rows[index][key] = value
    assert not evaluate_events(rows)


@pytest.mark.parametrize("index,key,value", [
    (0, "threads", 8), (0, "exit_signal", 9), (0, "path_control", False),
    (0, "private_objects_mask", 0), (0, "bounded_stop", True),
    (1, "protocol_traffic", False), (1, "origin", 1), (1, "result", 4),
    (3, "boundary_ok", False), (3, "actor_checks", 10), (3, "result", 1),
    (3, "result", True), (3, "origin", 2), (3, "protocol_traffic", 0),
    (4, "functionality_verified", True), (4, "audio_opened", True), (4, "sdk_executed", False),
    (5, "unrelated_internet_controls", False), (5, "failures", 1),
    (6, "code", False), (7, "ok", False),
])
def test_rejects_incomplete_control_and_overstated_scope(index, key, value):
    rows = evidence()
    rows[index][key] = value
    assert not evaluate_events(rows)


@pytest.mark.parametrize("value", [None, {}, True, [None] * 8])
def test_rejects_invalid_container(value):
    assert not evaluate_events(value)


def test_watchdog_covers_new_sdk_owned_leaders_and_empty_underlays():
    script = diagnostic_script()
    assert "PROBE --run-sdk " in script and "PROBE --run " not in script
    assert script.count("root[012]-sdk.child;") == 2
    assert script.count('rmdir "$STATE/root$epoch-sdk"') == 1
    assert script.count('rmdir "$state/root$epoch-sdk"') == 1
    assert script.count("sdk-stage") == 4
    assert '"event":"sdk-bus-state"' in script
    assert "rm -r" not in script
