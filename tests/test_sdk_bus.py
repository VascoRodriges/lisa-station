from copy import deepcopy

import pytest

from controller.qualify_sdk_bus import allocation_diagnostic, diagnostic_script, evaluate_events


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


def test_scalar_notices_distinguish_budget_from_kernel_duplication_failure():
    budget = b"byte-factory channel-budget exhausted slots=1\n"
    duplicate = b"byte-factory duplicate failure error=24\n"
    assert allocation_diagnostic(budget) == dict(kind="channel-budget", slots=1)
    assert allocation_diagnostic(duplicate) == dict(kind="duplication", errno=24)
    assert allocation_diagnostic(budget + duplicate) == dict(kind="multiple", slots=1, errno=24)
    assert allocation_diagnostic(b"System.Error.EMFILE: Too many open files\n") == dict(kind="unobserved")
    assert allocation_diagnostic(b"unrelated\xff\n" + budget) == dict(kind="channel-budget", slots=1)


@pytest.mark.parametrize("data", [
    None, "text", b"x" * 65537,
    b"byte-factory channel-budget exhausted slots=0\n",
    b"byte-factory channel-budget exhausted slots=5\n",
    b"byte-factory channel-budget exhausted slots=01\n",
    b"byte-factory channel-budget exhausted slots=1 extra\n",
    b"byte-factory duplicate failure error=0\n",
    b"byte-factory duplicate failure error=024\n",
    b"byte-factory duplicate failure error=4096\n",
    b"byte-factory duplicate failure error=24\n" * 2,
    b"byte-factory channel-budget exhausted slots=1\n" * 2,
])
def test_malformed_or_repeated_notices_never_infer_an_allocation_cause(data):
    assert allocation_diagnostic(data) == dict(kind="invalid")


@pytest.mark.parametrize("truncated", [True, 1, None])
def test_incomplete_allocation_diagnostics_are_not_inferred(truncated):
    assert allocation_diagnostic(b"byte-factory channel-budget exhausted slots=1\n", truncated=truncated) == dict(kind="invalid")


def dual_evidence():
    original = adapter_evidence()
    rows = [dict(event="sdk-policy-epoch", ok=True, checks=29, provider_closed=True,
                 observer_only=True, observer_closed=True, bus_reaped=True, private_view_released=True)]
    for start in [0, 4]:
        rows.append(dict(original[start], source_channels=2, source_admission_checks=5 if start == 0 else 0))
        rows.extend(dict(original[start + 1], slot=slot) for slot in [0, 1])
        rows.append(dict(original[start + 2]))
        rows.append(dict(original[start + 3], event="sdk-group-observer", sdk_names=2,
                         active_names=0, group_finished=True, peak_rules=3 if start == 0 else 2))
    return rows + original[8:]


def test_dual_channels_require_separate_policy_and_two_relay_proofs():
    assert evaluate_events(dual_evidence(), dual_channels=True)
    assert not evaluate_events(dual_evidence(), synthetic_adapter=True)
    assert not evaluate_events(adapter_evidence(), dual_channels=True)
    assert not evaluate_events(dual_evidence(), dual_channels=True, synthetic_adapter=True)
    with pytest.raises(ValueError):
        diagnostic_script(dual_channels=True, empty_bluez=True)
    script = diagnostic_script(dual_channels=True)
    assert "PROBE --run-sdk-two " in script
    assert script.count("/root[012]-channel[01]-relay.child") == 2
    assert script.count("for channel in 0 1; do") == 2
    assert "rm -r" not in script


@pytest.mark.parametrize("index", range(16))
def test_dual_channels_require_all_ordered_unique_typed_events(index):
    rows = dual_evidence()
    del rows[index]
    assert not evaluate_events(rows, dual_channels=True)
    rows = dual_evidence()
    rows.insert(index, deepcopy(rows[index]))
    assert not evaluate_events(rows, dual_channels=True)
    rows = dual_evidence()
    rows[index]["unexpected"] = True
    assert not evaluate_events(rows, dual_channels=True)


@pytest.mark.parametrize("index,key,value", [
    (0, "ok", False), (0, "checks", 28), (0, "provider_closed", False),
    (0, "observer_only", False), (0, "observer_closed", False), (0, "bus_reaped", False),
    (0, "private_view_released", False), (1, "source_channels", 1), (6, "source_channels", True),
    (1, "source_admission_checks", 4), (6, "source_admission_checks", 5), (1, "source_admission_checks", True),
    (2, "slot", 1), (3, "slot", 0), (3, "auth_verified", False), (8, "auth_verified", False),
    (2, "boundary_ok", False), (3, "actor_checks", 10), (7, "protocol_traffic", False),
    (5, "sdk_names", 1), (10, "sdk_names", 3), (10, "sdk_names", True),
    (5, "active_names", 1), (10, "active_names", False), (5, "group_finished", False),
    (5, "group_finished", 1), (5, "peak_rules", 2), (10, "peak_rules", 9),
    (10, "sdk_subscription_removed", False), (10, "observer_closed", False),
])
def test_dual_channels_reject_unowned_or_unretired_source_evidence(index, key, value):
    rows = dual_evidence()
    rows[index][key] = value
    assert not evaluate_events(rows, dual_channels=True)


def driver_error_evidence():
    rows = dual_evidence()
    for index, role in [(6, "own-elf"), (12, "platform")]:
        rows.insert(index, dict(event="sdk-driver-denials", role=role, records=1, sdk_history_only=True,
                                private_saved=True, pipe_attested=True, pipe_closed=True, own_denial_verified=role == "own-elf"))
    return rows


def test_driver_error_audit_requires_own_denial_and_explicit_profile():
    assert evaluate_events(driver_error_evidence(), error_audit=True)
    assert not evaluate_events(dual_evidence(), error_audit=True)
    assert not evaluate_events(driver_error_evidence(), dual_channels=True)
    assert not evaluate_events(driver_error_evidence(), error_audit=True, dual_channels=True)
    with pytest.raises(ValueError):
        diagnostic_script(error_audit=True, dual_channels=True)
    script = diagnostic_script(error_audit=True)
    assert "PROBE --run-sdk-error-audit " in script
    assert script.count("/root[012]-channel[01]-relay.child") == 2
    assert script.count("for channel in 0 1; do") == 2
    assert "rm -r" not in script


@pytest.mark.parametrize("index,key,value", [
    (6, "records", 0), (6, "records", 2), (6, "records", True),
    (12, "records", 0), (12, "records", 5), (12, "records", 1.0),
    (6, "private_saved", False), (12, "private_saved", 1),
    (6, "own_denial_verified", False), (6, "own_denial_verified", 1),
    (12, "own_denial_verified", True), (12, "own_denial_verified", 0),
    (6, "pipe_attested", False), (12, "pipe_closed", False), (12, "sdk_history_only", False),
    (3, "auth_verified", False), (9, "boundary_ok", False),
    (11, "group_finished", False), (11, "sdk_subscription_removed", False),
])
def test_driver_error_audit_rejects_unbound_incomplete_or_untyped_proofs(index, key, value):
    rows = driver_error_evidence()
    rows[index][key] = value
    assert not evaluate_events(rows, error_audit=True)


@pytest.mark.parametrize("index", range(18))
def test_driver_error_audit_requires_ordered_complete_unique_typed_events(index):
    rows = driver_error_evidence()
    del rows[index]
    assert not evaluate_events(rows, error_audit=True)
    rows = driver_error_evidence()
    rows.insert(index, deepcopy(rows[index]))
    assert not evaluate_events(rows, error_audit=True)
    rows = driver_error_evidence()
    rows[index]["unexpected"] = True
    assert not evaluate_events(rows, error_audit=True)


@pytest.mark.parametrize("count", [1, 2, 3, 4])
def test_driver_error_audit_bounds_actual_records(count):
    rows = driver_error_evidence()
    rows[12]["records"] = count
    assert evaluate_events(rows, error_audit=True)
