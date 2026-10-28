"""Synthetic profiles and evidence, never copied device configuration or audio."""

from copy import deepcopy

import pytest

from controller.qualify_telemetry import evaluate_boundary_events, evaluate_events, trial_script
from controller.telemetry_profile import prepare_telemetry_profile
from tests.test_collector_guard import events as collector_events


def stock():
    return {
        "patterns": {"TMP": "/tmp", "DATA": "/data/quasar"},
        "unrelated": {"keep": "synthetic"},
        "metricad": {"port": 9887},
        "metrica2d": {"port": 9904},
        "telemetry": {
            "Logging": {"file": {"enabled": True, "fileName": "${LOGS}/telemetry.log"}},
            "Minidump": {"enabled": True},
        },
        "teleme3d": {
            "eventBlacklist": ["systemMetrics", "unrelated-event"],
            "dbPath": "${TMP}/teleme3d",
            "dbSizeLimitMB": 5,
            "reservedSizeMB": 3,
            "metricaSessionIdPersistentPart": "${DATA}/data/metrica/session_id_part.txt",
            "metricaSessionIdTemporaryPart": "${TMP}/metrica/session_id_part.txt",
            "noSyncClock": False,
            "persistentAppmetrica": {"mode": "white", "events": {"processStart": True}},
            "persistentBatcher": {
                "enabled": True,
                "storagePath": "${DATA}/appmetrica/persistedBatch",
                "maxStorageSizeMb": 1,
                "syncPeriodSec": 360,
                "maxBatchCollectingWhenNoInternetTimeSec": 360,
                "lookForNetworkConnection": True,
            },
        },
    }


def test_profile_separates_all_working_storage_preserving_private_source():
    source = stock()
    before = deepcopy(source)
    result = prepare_telemetry_profile(source)
    assert source == before
    assert result["unrelated"] == source["unrelated"]
    assert result["metricad"] == source["metricad"]
    assert result["metrica2d"] == source["metrica2d"]
    telemetry = result["teleme3d"]
    for key in ("dbPath", "metricaSessionIdPersistentPart", "metricaSessionIdTemporaryPart"):
        assert telemetry[key].startswith("/tmp/lisa-telemetry/")
    batch = telemetry["persistentBatcher"]
    assert batch["storagePath"] == "/tmp/lisa-telemetry/persistedBatch"
    assert batch["syncPeriodSec"] == 360
    assert batch["lookForNetworkConnection"] is True
    assert telemetry["noSyncClock"] is False
    assert telemetry["persistentAppmetrica"] == source["teleme3d"]["persistentAppmetrica"]
    assert telemetry["eventBlacklist"] == source["teleme3d"]["eventBlacklist"]
    assert result["telemetry"]["Logging"]["file"]["fileName"] == "/tmp/lisa-telemetry/telemetry.log"
    assert result["telemetry"]["Minidump"]["enabled"] is False


def test_lab_adjustments_do_not_escape_into_normal_profile():
    result = prepare_telemetry_profile(stock(), lab_clone=True)
    assert (result["metricad"]["port"], result["metrica2d"]["port"]) == (57345, 57346)
    assert result["teleme3d"]["persistentBatcher"]["syncPeriodSec"] == 1
    assert result["teleme3d"]["noSyncClock"] is True
    assert result["teleme3d"]["persistentAppmetrica"] == {"mode": "black", "events": {}}
    assert result["teleme3d"]["eventBlacklist"] == ["unrelated-event"]


@pytest.mark.parametrize(
    ("path", "value"),
    [
        (("patterns", "TMP"), "/other"),
        (("patterns", "DATA"), "/other"),
        (("teleme3d", "dbPath"), "/old-db"),
        (("teleme3d", "metricaSessionIdPersistentPart"), "/unknown"),
        (("teleme3d", "metricaSessionIdTemporaryPart"), "/unknown"),
        (("teleme3d", "dbSizeLimitMB"), True),
        (("teleme3d", "dbSizeLimitMB"), 13),
        (("teleme3d", "reservedSizeMB"), 5),
        (("teleme3d", "reservedSizeMB"), -1),
        (("teleme3d", "noSyncClock"), 1),
        (("teleme3d", "eventBlacklist"), "systemMetrics"),
        (("teleme3d", "persistentAppmetrica", "mode"), "unknown"),
        (("teleme3d", "persistentAppmetrica", "events"), {"event": 1}),
        (("teleme3d", "persistentBatcher", "enabled"), False),
        (("teleme3d", "persistentBatcher", "storagePath"), "/unknown"),
        (("teleme3d", "persistentBatcher", "maxStorageSizeMb"), 0),
        (("teleme3d", "persistentBatcher", "syncPeriodSec"), 0),
        (("teleme3d", "persistentBatcher", "maxBatchCollectingWhenNoInternetTimeSec"), True),
        (("teleme3d", "persistentBatcher", "lookForNetworkConnection"), "yes"),
        (("telemetry", "Logging", "file", "fileName"), "/unknown"),
        (("telemetry", "Logging", "file", "enabled"), False),
        (("telemetry", "Minidump", "enabled"), 1),
        (("metricad", "port"), 80),
        (("metricad", "port"), True),
        (("metricad", "port"), 57345),
        (("metrica2d", "port"), 57346),
    ],
)
def test_unreviewed_layout_rejected(path, value):
    source = stock()
    node = source
    for key in path[:-1]:
        node = node[key]
    node[path[-1]] = value
    with pytest.raises(ValueError):
        prepare_telemetry_profile(source, lab_clone=True)


def test_missing_config_and_invalid_mode_rejected():
    with pytest.raises(ValueError):
        prepare_telemetry_profile({})
    with pytest.raises(ValueError):
        prepare_telemetry_profile(stock(), lab_clone=1)


def events():
    rows = collector_events()
    for row in rows:
        for key in ("event", "operation"):
            if key in row:
                row[key] = row[key].replace("collector", "telemetry")
        row["telemetry_jail_verified"] = row.pop("collector_jail_verified", False)
        if row.get("operation") == "inspect-telemetry":
            row["telemetry_batch_materialized"], row["telemetry_batch_paths"] = False, 0
    rows.insert(6, dict(event="telemetry-observer-ready", child_pid=30002, start_ticks=90001))
    rows.insert(
        12,
        dict(
            event="telemetry-epoch-closed",
            child_pid=30002,
            start_ticks=90001,
            actor_stopped=True,
            observer_fds_closed=True,
            batch_materialized=True,
            batch_paths=1,
            payload_read=False,
        ),
    )
    return rows


def test_complete_trial_with_shutdown_batch():
    assert evaluate_events(events())


def test_runtime_batch_and_empty_shutdown_observation():
    rows = events()
    rows[3]["telemetry_batch_materialized"], rows[3]["telemetry_batch_paths"] = True, 2
    rows[12]["batch_materialized"], rows[12]["batch_paths"] = False, 0
    assert evaluate_events(rows)


@pytest.mark.parametrize(
    ("index", "key", "value"),
    [
        (3, "telemetry_batch_materialized", 1),
        (3, "telemetry_batch_paths", True),
        (3, "telemetry_batch_paths", 1),
        (6, "child_pid", 30003),
        (6, "start_ticks", True),
        (12, "start_ticks", 90002),
        (12, "actor_stopped", False),
        (12, "observer_fds_closed", False),
        (12, "payload_read", True),
        (12, "batch_paths", 0),
        (12, "batch_paths", 8),
        (12, "batch_paths", True),
        (-1, "private_epoch_discarded", False),
        (1, "isolation_verified", True),
    ],
)
def test_incomplete_or_inconsistent_evidence_rejected(index, key, value):
    rows = events()
    rows[index][key] = value
    assert not evaluate_events(rows)


def test_unmaterialized_batch_and_missing_observer_rejected():
    rows = events()
    rows[12]["batch_materialized"], rows[12]["batch_paths"] = False, 0
    assert not evaluate_events(rows)
    assert evaluate_boundary_events(rows)
    rows = events()
    del rows[6]
    assert not evaluate_events(rows)


def test_trial_keeps_independent_restore_and_original_processes():
    script = trial_script()
    assert "--fluent-bitd" not in script
    assert "--telemetry" in script
    assert "57344" not in script
    assert "LISACQ_" in script
    assert "sleep 60;" in script
    assert 'kill -CONT "$process"' in script
    assert 'wait "$observer"' in script
    assert script.index("--lab-observe-telemetry-close") < script.index('--lab-close-telemetry "$CANON"')
    assert script.index('ip6tables -R "$CHAIN"') < script.index('--lab-close-telemetry "$CANON"')
    assert "-j REJECT" in script
