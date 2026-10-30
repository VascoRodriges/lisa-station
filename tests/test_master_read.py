from copy import deepcopy

import pytest

from controller.qualify_master_read import SCRIPT, evaluate_events


def evidence():
    rows = [dict(event="master-read-epoch", case=i, ok=True, backend_checks=16 if i == 7 else 17,
                 client_checks=17, reads=1 if i == 7 else 2, ioctl_reads=3 if i == 7 else 6,
                 malformed_rejected=0 < i < 7, backend_killed=i == 7, client_closed=True,
                 backend_admitted=True, client_admitted=True, sources_closed=True, values_agree=True,
                 views_released=True, pcm_opened=False) for i in range(8)]
    return rows + [dict(selftest="master-read-broker", checks=9, inspection_checks=28, failures=0, ok=True, own_client_only=True,
                        unrelated_socket_creation=True, audio_opened=False, production_changed=False),
                   dict(event="master-read-exit", code=0), dict(event="master-read-cleanup", ok=True)]


def test_accepts_read_only_hardware_and_fault_closure_proofs():
    assert evaluate_events(evidence())
    assert 'PROBE --run "$STATE"' in SCRIPT
    assert "PROBE --factory-selftest" not in SCRIPT
    assert 'root[0-9].child' in SCRIPT and 'root1[0-5].child' in SCRIPT
    assert 'MONITOR --same-image "$pid" PROBE' in SCRIPT
    assert 'MONITOR --scope-absent PROBE' in SCRIPT
    assert "stat -L" not in SCRIPT
    assert 'for suffix in child child.new' in SCRIPT
    assert 'test ! -e /bkupgrade/data/opt/lisa-station/state' in SCRIPT
    assert 'test ! -e /run/lisa-station' in SCRIPT
    assert "rm -r" not in SCRIPT


@pytest.mark.parametrize("value", [None, {}, [], [None] * 11, [True] * 11])
def test_rejects_non_evidence(value):
    assert not evaluate_events(value)


@pytest.mark.parametrize("index", range(11))
def test_requires_every_ordered_unique_event_and_no_unknown_fields(index):
    rows = evidence()
    del rows[index]
    assert not evaluate_events(rows)
    rows = evidence()
    rows.insert(index, deepcopy(rows[index]))
    assert not evaluate_events(rows)
    rows = evidence()
    rows[index]["unexpected"] = True
    assert not evaluate_events(rows)


@pytest.mark.parametrize("index,key,value", [
    (0, "backend_admitted", False), (0, "client_admitted", False), (0, "sources_closed", False),
    (0, "values_agree", False), (1, "malformed_rejected", False), (0, "malformed_rejected", True),
    (7, "backend_killed", False), (6, "backend_killed", True), (7, "reads", 2), (0, "ioctl_reads", 5),
    (7, "backend_checks", 17), (7, "client_closed", False), (2, "views_released", False),
    (3, "pcm_opened", True), (2, "case", 1), (4, "client_checks", 16), (0, "ok", 1),
    (0, "backend_admitted", 1), (0, "reads", 2.0), (0, "case", False),
    (8, "own_client_only", False), (8, "unrelated_socket_creation", False), (8, "audio_opened", True),
    (8, "production_changed", True), (8, "failures", 1), (8, "checks", 8), (8, "inspection_checks", 27),
    (9, "code", False), (9, "code", 2), (10, "ok", False),
])
def test_rejects_unproven_scope_or_untyped_results(index, key, value):
    rows = evidence()
    rows[index][key] = value
    assert not evaluate_events(rows)
