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
            result=0, origin=0, protocol_traffic=True, auth_verified=True,
        ))
        rows.append(dict(event="sdk-match-observer", role=role, snapshot_captured=True,
                         own_fixture_match=role == "own-elf", sdk_subscription_removed=True,
                         observer_closed=True, queries=3, peak_rules=2, private_metadata_only=True))
    return rows + [
        dict(event="sdk-subscription-policy", checks=26, failures=0, driver_signal_received=True,
             peer_signal_blocked=True, rule_limit=4, connections_closed=True, own_controls_only=True),
        dict(selftest="sdk-private-bus", ok=True, sdk_executed=True, audio_opened=False, functionality_verified=False),
        dict(event="private-bus-parent", checks=5, failures=0, unrelated_internet_controls=True),
        dict(event="private-bus-exit", code=0), dict(event="private-bus-cleanup", ok=True),
    ]


def test_accepts_boundary_proof_with_expected_sdk_dependency_failure():
    assert evaluate_events(evidence())
    rows = evidence()
    rows[3].update(exit_code=0, exit_signal=0)
    assert evaluate_events(rows)


@pytest.mark.parametrize("index", range(11))
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


@pytest.mark.parametrize("index", [0, 3])
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
    (4, "boundary_ok", False), (4, "actor_checks", 10), (4, "result", 1),
    (4, "result", True), (4, "origin", 2), (4, "protocol_traffic", 0),
    (4, "auth_verified", False), (4, "auth_verified", 1), (1, "auth_verified", False),
    (4, "protocol_traffic", False),
    (6, "checks", 23), (6, "failures", 1), (6, "driver_signal_received", False),
    (6, "peer_signal_blocked", False), (6, "rule_limit", 2), (6, "rule_limit", True),
    (6, "connections_closed", False), (6, "own_controls_only", False),
    (7, "functionality_verified", True), (7, "audio_opened", True), (7, "sdk_executed", False),
    (8, "unrelated_internet_controls", False), (8, "failures", 1),
    (9, "code", False), (10, "ok", False),
])
def test_rejects_incomplete_control_and_overstated_scope(index, key, value):
    rows = evidence()
    rows[index][key] = value
    assert not evaluate_events(rows)


@pytest.mark.parametrize("index", [2, 5])
@pytest.mark.parametrize("key,value", [
    ("snapshot_captured", False), ("sdk_subscription_removed", False), ("observer_closed", False),
    ("private_metadata_only", False), ("queries", 0), ("queries", 41), ("queries", True),
    ("peak_rules", 0), ("peak_rules", 5), ("peak_rules", True), ("peak_rules", "2"),
])
def test_requires_current_private_snapshot_and_teardown(index, key, value):
    rows = evidence()
    rows[index][key] = value
    assert not evaluate_events(rows)


def test_requires_independent_known_own_fixture_before_sdk():
    rows = evidence()
    rows[2]["own_fixture_match"] = False
    assert not evaluate_events(rows)
    rows = evidence()
    rows[5]["own_fixture_match"] = True
    assert not evaluate_events(rows)


@pytest.mark.parametrize("count", [1, 3, 4])
def test_requires_two_own_rules_before_actual_sdk(count):
    rows = evidence()
    rows[2]["peak_rules"] = count
    assert not evaluate_events(rows)


@pytest.mark.parametrize("count", [1, 2, 3, 4])
def test_accepts_only_bounded_platform_peak_without_claiming_full_compatibility(count):
    rows = evidence()
    rows[5]["peak_rules"] = count
    assert evaluate_events(rows)


@pytest.mark.parametrize("value", [None, {}, True, [None] * 11])
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


def bluez_evidence():
    rows = evidence()
    for index, role in [(2, "own-elf"), (6, "platform")]:
        rows.insert(index, dict(event="sdk-empty-provider", role=role, primary_owner=True,
                                calls=1, closed=True, empty_tree_only=True, hardware_opened=False))
    rows[8]["checks"] = 29
    return rows


def test_explicit_empty_service_requires_its_own_complete_protocol():
    assert evaluate_events(bluez_evidence(), empty_bluez=True)
    assert not evaluate_events(bluez_evidence())
    assert not evaluate_events(evidence(), empty_bluez=True)
    script = diagnostic_script(empty_bluez=True)
    assert "PROBE --run-sdk-bluez " in script and "PROBE --run-sdk " not in script
    assert "PROBE --run-sdk-bluez " not in diagnostic_script()


@pytest.mark.parametrize("index", range(13))
def test_empty_service_requires_all_ordered_unique_typed_events(index):
    rows = bluez_evidence()
    del rows[index]
    assert not evaluate_events(rows, empty_bluez=True)
    rows = bluez_evidence()
    rows.insert(index, deepcopy(rows[index]))
    assert not evaluate_events(rows, empty_bluez=True)
    rows = bluez_evidence()
    rows[index]["unexpected"] = True
    assert not evaluate_events(rows, empty_bluez=True)
    rows = bluez_evidence()
    rows[index] = None
    assert not evaluate_events(rows, empty_bluez=True)


@pytest.mark.parametrize("index", [2, 6])
@pytest.mark.parametrize("key,value", [
    ("primary_owner", False), ("primary_owner", 1), ("closed", False), ("closed", 1),
    ("empty_tree_only", False), ("hardware_opened", True), ("hardware_opened", 0),
    ("calls", 0), ("calls", 5), ("calls", True), ("calls", "1"),
    ("role", "unknown"),
])
def test_empty_service_rejects_missing_ownership_exchange_or_teardown(index, key, value):
    rows = bluez_evidence()
    rows[index][key] = value
    assert not evaluate_events(rows, empty_bluez=True)


@pytest.mark.parametrize("count", [2, 3, 4])
def test_own_empty_service_requires_exactly_one_verified_call(count):
    rows = bluez_evidence()
    rows[2]["calls"] = count
    assert not evaluate_events(rows, empty_bluez=True)
    rows = bluez_evidence()
    rows[6]["calls"] = count
    assert evaluate_events(rows, empty_bluez=True)


@pytest.mark.parametrize("count", [26, 28, 30, True, "29"])
def test_empty_service_requires_additional_schema_denial_controls(count):
    rows = bluez_evidence()
    rows[8]["checks"] = count
    assert not evaluate_events(rows, empty_bluez=True)


def adapter_evidence():
    rows = bluez_evidence()
    for index in [2, 6]:
        rows[index]["event"] = "sdk-adapter-provider"
        del rows[index]["empty_tree_only"]
        rows[index]["synthetic_adapter"] = True
    return rows


def test_synthetic_adapter_has_a_distinct_opt_in_and_evidence_kind():
    assert evaluate_events(adapter_evidence(), synthetic_adapter=True)
    assert not evaluate_events(adapter_evidence(), empty_bluez=True)
    assert not evaluate_events(bluez_evidence(), synthetic_adapter=True)
    assert not evaluate_events(adapter_evidence())
    assert not evaluate_events(adapter_evidence(), empty_bluez=True, synthetic_adapter=True)
    with pytest.raises(ValueError):
        diagnostic_script(empty_bluez=True, synthetic_adapter=True)
    script = diagnostic_script(synthetic_adapter=True)
    assert "PROBE --run-sdk-adapter " in script and "PROBE --run-sdk-bluez " not in script


@pytest.mark.parametrize("index", [2, 6])
@pytest.mark.parametrize("key,value", [
    ("synthetic_adapter", False), ("synthetic_adapter", 1), ("hardware_opened", True),
    ("primary_owner", False), ("closed", False), ("calls", 0), ("calls", 5), ("calls", True),
])
def test_synthetic_adapter_still_requires_owned_bounded_hardware_free_teardown(index, key, value):
    rows = adapter_evidence()
    rows[index][key] = value
    assert not evaluate_events(rows, synthetic_adapter=True)


@pytest.mark.parametrize("index", range(13))
def test_synthetic_adapter_requires_all_original_boundary_events(index):
    rows = adapter_evidence()
    del rows[index]
    assert not evaluate_events(rows, synthetic_adapter=True)
