"""Synthetic inode/holder graphs must not turn a live census into privacy proof."""

import json
from copy import deepcopy

import pytest

from controller.relay_inventory import assess, parse_evidence

BOOT = "12345678-1234-1234-1234-123456789abc"


def descriptor(pid, fd, inode, kind, flags=0, unlinked=False):
    return dict(
        event="relay-holder",
        pid=pid,
        start_ticks=pid * 10,
        device=17,
        inode=inode,
        source="descriptor",
        descriptor=fd,
        flags=flags,
        low=0,
        high=0,
        offset=0,
        kinds=kind,
        readable=not flags & 0x200000 and flags & 3 != 1,
        writable=not flags & 0x200000 and flags & 3 != 0,
        shared=False,
        unlinked=unlinked,
        deleted_hint=False,
        confirmed=True,
    )


def mapping(pid, inode, kind, shared=True):
    row = descriptor(pid, 0, inode, kind)
    row.update(
        source="mapping",
        low=0x1000,
        high=0x2000,
        writable=True,
        shared=shared,
        unlinked=None,
        deleted_hint=True,
    )
    return row


def records():
    processes = [
        dict(
            event="relay-process",
            pid=pid,
            start_ticks=pid * 10,
            exe_device=16,
            exe_inode=900 + pid,
            role=role,
        )
        for pid, role in ((101, "vendor-worker"), (102, "other"))
    ]
    return [
        dict(event="relay-evidence-start", boot_id=BOOT),
        *processes,
        descriptor(101, 10, 200, 4),
        descriptor(102, 20, 200, 4, flags=1),
        mapping(101, 201, 16),
        descriptor(101, 11, 202, 2, flags=1, unlinked=True),
        dict(
            event="relay-evidence-summary",
            processes=2,
            observations=4,
            confirmed=4,
            unreadable=0,
            unidentified=0,
            changed_processes=0,
            boot_stable=True,
            atomic_snapshot=False,
            audio_opened=False,
            payload_read=False,
            apply_supported=False,
        ),
    ]


def encode(rows):
    return "\n".join(json.dumps(row) for row in rows)


def evidence():
    return parse_evidence(encode(records()))


def test_file_relay_and_mapping_only_queue_are_retained():
    report = assess(evidence(), evidence())
    log = next(r for r in report["resources"] if r["inode"] == 200)
    assert log["cross_role_ingress"]
    assert log["other_writers"] == [102]
    assert log["vendor_readers"] == [101]
    assert "shared_system_log_ingress" in report["blockers"]
    assert report["resource_counts"]["collector-sqlite"] == 1
    assert report["deleted_mapping_hints"] == report["unlinked_descriptor_holders"] == 1
    assert report["stable_holder_observations"] == 4
    assert not report["production_plan_ready"]
    assert not report["apply_supported"]
    assert not report["isolation_verified"]


@pytest.mark.parametrize(
    "fault",
    (
        "boot",
        "event",
        "audio",
        "payload",
        "apply",
        "atomic",
        "unstable_boot",
        "process_count",
        "holder_count",
        "confirmed_count",
        "duplicate_process",
        "duplicate_descriptor",
        "duplicate_mapping",
        "unknown_role",
        "missing_process",
        "ticks",
        "integer_bool",
        "boolean_integer",
        "unknown_kind",
        "mixed_unknown",
        "access_mode",
        "access_claim",
        "fd_mapping_fields",
        "fd_shared",
        "fd_unlinked",
        "map_unlinked",
        "map_range",
        "map_descriptor",
        "source",
    ),
)
def test_malformed_or_overstated_relay_evidence_rejected(fault):
    rows = records()
    if fault == "boot":
        rows[0]["boot_id"] = "invalid"
    elif fault == "event":
        rows[0]["event"] = "other"
    elif fault in {"audio", "payload", "apply", "atomic"}:
        key = dict(
            audio="audio_opened", payload="payload_read", apply="apply_supported", atomic="atomic_snapshot"
        )
        rows[-1][key[fault]] = True
    elif fault == "unstable_boot":
        rows[-1]["boot_stable"] = False
    elif fault in {"process_count", "holder_count", "confirmed_count"}:
        key = dict(process_count="processes", holder_count="observations", confirmed_count="confirmed")
        rows[-1][key[fault]] += 1
    elif fault == "duplicate_process":
        rows.insert(2, deepcopy(rows[1]))
    elif fault == "duplicate_descriptor":
        rows.insert(-1, deepcopy(rows[3]))
    elif fault == "duplicate_mapping":
        rows.insert(-1, deepcopy(rows[5]))
    elif fault == "unknown_role":
        rows[1]["role"] = "safe"
    elif fault == "missing_process":
        rows[3]["pid"] = 999
    elif fault == "ticks":
        rows[3]["start_ticks"] += 1
    elif fault == "integer_bool":
        rows[3]["inode"] = True
    elif fault == "boolean_integer":
        rows[3]["confirmed"] = 1
    elif fault == "unknown_kind":
        rows[3]["kinds"] = 4096
    elif fault == "mixed_unknown":
        rows[3]["kinds"] = 257
    elif fault == "access_mode":
        rows[3]["flags"] = 3
    elif fault == "access_claim":
        rows[3]["writable"] = True
    elif fault == "fd_mapping_fields":
        rows[3]["offset"] = 10
    elif fault == "fd_shared":
        rows[3]["shared"] = True
    elif fault == "fd_unlinked":
        rows[3]["unlinked"] = None
    elif fault == "map_unlinked":
        rows[5]["unlinked"] = True
    elif fault == "map_range":
        rows[5]["low"] = rows[5]["high"]
    elif fault == "map_descriptor":
        rows[5]["descriptor"] = 10
    elif fault == "source":
        rows[5]["source"] = "payload"
    with pytest.raises(ValueError):
        parse_evidence(encode(rows))


def test_unconfirmed_or_changed_holder_is_not_stable():
    before, after = evidence(), evidence()
    after["holders"][0]["confirmed"] = False
    after["holders"][1]["inode"] += 100
    report = assess(before, after)
    assert report["stable_holder_observations"] == 2
    assert "changed_actor_or_resource" in report["blockers"]
    assert not any(r["cross_role_ingress"] for r in report["resources"])


@pytest.mark.parametrize("key", ("start_ticks", "exe_inode", "exe_device", "role"))
def test_reused_process_identity_is_not_trusted(key):
    before, after = evidence(), evidence()
    after["processes"][101][key] = "other" if key == "role" else after["processes"][101][key] + 1
    report = assess(before, after)
    assert report["stable_holder_observations"] == 1
    assert "changed_actor_or_resource" in report["blockers"]


def test_private_writable_mapping_does_not_become_a_file_writer():
    before = evidence()
    before["holders"][2]["pid"] = 102
    before["holders"][2]["start_ticks"] = 1020
    before["holders"][2]["shared"] = False
    report = assess(before, deepcopy(before))
    queue = next(r for r in report["resources"] if r["inode"] == 201)
    assert queue["other_writers"] == []
    assert queue["holder_observations"] == 1


def test_path_descriptor_retains_resource_without_claiming_read_write():
    rows = records()
    rows[3] = descriptor(101, 10, 200, 4, flags=0x200000)
    frame = parse_evidence(encode(rows))
    log = next(r for r in assess(frame, deepcopy(frame))["resources"] if r["inode"] == 200)
    assert log["vendor_readers"] == log["vendor_writers"] == []
    assert log["holder_observations"] == 2


def test_unknown_writable_resource_cannot_silently_disappear():
    before = evidence()
    before["holders"][2]["kinds"] = 256
    report = assess(before, deepcopy(before))
    assert "unclassified_vendor_writable_resource" in report["blockers"]


def test_changed_boot_rejected():
    before, after = evidence(), evidence()
    after["boot_id"] = "87654321-1234-1234-1234-123456789abc"
    with pytest.raises(ValueError):
        assess(before, after)


def test_empty_or_unreadable_snapshot_does_not_authorize_a_transition():
    empty = dict(boot_id=BOOT, processes={}, holders=[], unreadable=1, unidentified=1, changed_processes=0)
    report = assess(empty, deepcopy(empty))
    assert "unreadable_metadata" in report["blockers"]
    assert "unidentified_processes_not_attributed" in report["blockers"]
    assert "queue_epoch_policy_not_installed" in report["blockers"]
    assert not report["isolation_verified"]
    assert not report["production_plan_ready"]
    assert not report["mutation_performed"]
