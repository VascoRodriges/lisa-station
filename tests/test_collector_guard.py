"""The profile is private, narrowly transformed and never a privacy attestation."""

from copy import deepcopy

import pytest

from controller.collector_profile import prepare_collector_profile
from controller.qualify_collector import evaluate_events


def stock():
    return {
        "patterns": {"DATA": "/data/quasar", "TMP": "/tmp"},
        "account_state": {"synthetic_value": "preserve-this-fixture"},
        "teleme3d": {"dbPath": "${TMP}/teleme3d"},
        "fluent-bitd": {
            "fluent-bit": {
                "enabled": True,
                "tailPaths": ["${LOGS}/*.log", "/var/log/messages"],
                "variables": {"tailDbFile": "${TMP}/fluent-bit.db", "unrelated": "unchanged"},
            },
            "Logging": {"file": {"enabled": True, "fileName": "${LOGS}/fluent-bitd.log"}},
            "Minidump": {"enabled": True, "fileName": "synthetic-dump"},
            "port": 9832,
        },
    }


def test_profile_excludes_system_log_without_mutating_private_source():
    source = stock()
    original = deepcopy(source)
    profile = prepare_collector_profile(source)
    assert source == original
    changed = profile["fluent-bitd"]
    assert changed["fluent-bit"]["tailPaths"] == ["${LOGS}/*.log"]
    assert changed["fluent-bit"]["variables"]["tailDbFile"] == "/tmp/lisa-collector/tail.db"
    assert changed["Logging"]["file"]["fileName"] == "/tmp/lisa-collector/collector.log"
    assert changed["Minidump"]["enabled"] is False
    assert changed["port"] == original["fluent-bitd"]["port"]
    assert profile["account_state"] == original["account_state"]
    assert profile["teleme3d"] == original["teleme3d"]
    assert changed["fluent-bit"]["variables"]["unrelated"] == "unchanged"
    assert prepare_collector_profile(source, lab_clone=True)["fluent-bitd"]["port"] == 57344


@pytest.mark.parametrize(
    "fault",
    (
        "missing",
        "paths_type",
        "unknown_path",
        "duplicate_path",
        "no_vendor_logs",
        "no_system_log",
        "db",
        "tmp",
        "data",
        "logger",
        "logger_disabled",
        "crash_type",
        "port_type",
        "port_range",
        "lab_port",
        "lab_type",
    ),
)
def test_unreviewed_profiles_rejected(fault):
    source = stock()
    section = source["fluent-bitd"]
    if fault == "missing":
        source.pop("fluent-bitd")
    elif fault == "paths_type":
        section["fluent-bit"]["tailPaths"] = "not-a-list"
    elif fault == "unknown_path":
        section["fluent-bit"]["tailPaths"].append("/unreviewed/log")
    elif fault == "duplicate_path":
        section["fluent-bit"]["tailPaths"].append("/var/log/messages")
    elif fault == "no_vendor_logs":
        section["fluent-bit"]["tailPaths"] = ["/var/log/messages"]
    elif fault == "no_system_log":
        section["fluent-bit"]["tailPaths"] = ["${LOGS}/*.log"]
    elif fault == "db":
        section["fluent-bit"]["variables"]["tailDbFile"] = "/unknown.db"
    elif fault in {"tmp", "data"}:
        source["patterns"][fault.upper()] = "/unreviewed"
    elif fault == "logger":
        section["Logging"]["file"]["fileName"] = "/unknown.log"
    elif fault == "logger_disabled":
        section["Logging"]["file"]["enabled"] = False
    elif fault == "crash_type":
        section["Minidump"]["enabled"] = 1
    elif fault == "port_type":
        section["port"] = True
    elif fault == "port_range":
        section["port"] = 80
    elif fault == "lab_port":
        section["port"] = 57344
    with pytest.raises(ValueError):
        prepare_collector_profile(source, lab_clone="invalid" if fault == "lab_type" else True)


def events():
    def service(operation, result, guarded=False, revision=0, phase="none"):
        return dict(
            event="station-service",
            operation=operation,
            result=result,
            collector_jail_verified=guarded,
            child_pid=30002 if guarded else 0,
            guardian_pid=30001 if guarded else 0,
            revision=revision,
            transition_phase=phase,
            isolation_verified=False,
        )

    return [
        service("start-collector", "busy"),
        service("start-collector", "ok", True, 1),
        service("start-collector", "busy"),
        *[service("inspect-collector", "ok", True, 1) for _ in range(3)],
        service("check-collector-policy", "failed"),
        service("check-collector-policy", "ok"),
        dict(event="policy-controls", ipv4=True, ipv6=True),
        service("close-collector", "ok", revision=2, phase="complete"),
        dict(event="collector-stopped", actors_absent=True),
        service("reconcile-collector", "ok", phase="complete"),
        service("start-collector", "denied", phase="complete"),
        dict(
            event="collector-restored",
            same_stock_process=True,
            private_epoch_discarded=True,
            audio_opened=False,
        ),
    ]


def test_complete_collector_trial():
    assert evaluate_events(events())


@pytest.mark.parametrize(
    "fault",
    (
        "missing",
        "duplicate_allowed",
        "jail",
        "child",
        "guardian",
        "revision",
        "v6",
        "controls",
        "phase",
        "running",
        "stock",
        "epoch",
        "audio",
        "isolation",
        "restart",
    ),
)
def test_partial_collector_trial_rejected(fault):
    rows = events()
    if fault == "missing":
        rows.pop(3)
    elif fault == "duplicate_allowed":
        rows[2]["result"] = "ok"
    elif fault == "jail":
        rows[3]["collector_jail_verified"] = False
    elif fault == "child":
        rows[4]["child_pid"] += 1
    elif fault == "guardian":
        rows[4]["guardian_pid"] += 1
    elif fault == "revision":
        rows[3]["revision"] = 2
    elif fault == "v6":
        rows[6]["result"] = "ok"
    elif fault == "controls":
        rows[8]["ipv6"] = False
    elif fault == "phase":
        rows[9]["transition_phase"] = "network_denied"
    elif fault == "running":
        rows[10]["actors_absent"] = False
    elif fault == "stock":
        rows[-1]["same_stock_process"] = False
    elif fault == "epoch":
        rows[-1]["private_epoch_discarded"] = False
    elif fault == "audio":
        rows[-1]["audio_opened"] = True
    elif fault == "isolation":
        rows[1]["isolation_verified"] = True
    elif fault == "restart":
        rows[-2]["result"] = "ok"
    assert not evaluate_events(rows)
