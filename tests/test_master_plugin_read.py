from copy import deepcopy

import pytest
from test_master_read import evidence as base_evidence

from controller.qualify_master_plugin_read import SCRIPT, evaluate_events


def evidence():
    rows = base_evidence()
    rows.insert(8, dict(event="master-plugin-read", clients=8, plugin_admission_controls=16, library_version="1.2.1.2",
                        configuration_loader=True, metadata_checked=True, backend_death_error=True, sdk_executed=False, audio_opened=False, ok=True))
    return rows


def test_requires_distinct_plugin_composition_not_legacy_broker_proof():
    assert evaluate_events(evidence())
    assert not evaluate_events(base_evidence())
    old_direct_entry = evidence()
    del old_direct_entry[8]["configuration_loader"]
    assert not evaluate_events(old_direct_entry)
    assert 'PROBE --run "$STATE" PLUGIN' in SCRIPT
    assert "/master-plugin-read." in SCRIPT
    assert 'test ! -e /bkupgrade/data/opt/lisa-station/state' in SCRIPT
    assert "rm -r" not in SCRIPT


@pytest.mark.parametrize("index", range(12))
def test_requires_each_ordered_event_and_exact_fields(index):
    rows = evidence()
    del rows[index]
    assert not evaluate_events(rows)
    rows = evidence()
    rows.insert(index, deepcopy(rows[index]))
    assert not evaluate_events(rows)
    rows = evidence()
    rows[index]["unexpected"] = True
    assert not evaluate_events(rows)


@pytest.mark.parametrize("field,value", [("clients", 7), ("clients", 8.0), ("plugin_admission_controls", 15),
                                       ("metadata_checked", 1), ("metadata_checked", False), ("backend_death_error", False),
                                       ("sdk_executed", True), ("audio_opened", True), ("library_version", "1.2.1"), ("ok", False),
                                       ("configuration_loader", False), ("configuration_loader", 1)])
def test_rejects_missing_plugin_or_runtime_proof(field, value):
    rows = evidence()
    rows[8][field] = value
    assert not evaluate_events(rows)
