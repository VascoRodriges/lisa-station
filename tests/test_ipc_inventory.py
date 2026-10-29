"""Synthetic UNIX socket metadata: no bus names, commands or real identities."""

import json

import pytest

from controller.ipc_inventory import assess, parse_evidence

BOOT = "12345678-1234-1234-1234-123456789abc"


def frame():
    def socket(inode, peer):
        return dict(
            event="ipc-socket",
            inode=inode,
            cookie=[inode, 1],
            type=1,
            state=1,
            peer=peer,
            peer_reported=True,
            queue_reported=True,
            receive_before=0,
            receive_after=0,
            write_before=0,
            write_after=0,
            stable=True,
        )

    def holder(pid, inode, role):
        return dict(
            event="ipc-holder",
            pid=pid,
            start_ticks=pid * 10,
            exe_device=1,
            exe_inode=pid * 2,
            role=role,
            descriptor=4,
            inode=inode,
            confirmed=True,
        )

    return [
        dict(event="ipc-evidence-start", boot_id=BOOT),
        socket(1001, 1002),
        socket(1002, 1001),
        holder(2001, 1001, "vendor-worker"),
        holder(2002, 1002, "other"),
        dict(
            event="ipc-evidence-summary",
            sockets=2,
            stable_sockets=2,
            holders=2,
            confirmed=2,
            unreadable=0,
            unidentified=0,
            boot_stable=True,
            atomic_snapshot=False,
            payload_read=False,
            names_read=False,
            audio_opened=False,
            apply_supported=False,
        ),
    ]


def evidence(rows):
    return parse_evidence("\n".join(json.dumps(row) for row in rows))


def test_reciprocal_peer_remains_a_relay_requiring_review():
    report = assess(evidence(frame()))
    assert report["summary"]["cross_role_endpoints"] == 1
    link = report["links"][0]
    assert link["reciprocal_holder_candidate"] is True
    assert link["action"] == "review-relay-policy-and-retained-data"
    for key in (
        "production_plan_ready",
        "atomic_snapshot",
        "isolation_verified",
        "apply_supported",
        "payload_read",
        "names_read",
    ):
        assert report[key] is False


@pytest.mark.parametrize(
    ("index", "key", "value"),
    [
        (0, "boot_id", "invalid"),
        (1, "cookie", [1]),
        (1, "cookie", [True, 1]),
        (1, "cookie", [2**32, 1]),
        (1, "cookie", [2**32 - 1, 2**32 - 1]),
        (1, "inode", 0),
        (1, "state", 0),
        (1, "type", True),
        (1, "type", 3),
        (1, "peer_reported", False),
        (1, "queue_reported", 1),
        (1, "receive_before", -1),
        (1, "receive_after", 2**32),
        (3, "confirmed", 1),
        (3, "pid", 0),
        (3, "start_ticks", True),
        (3, "exe_inode", 0),
        (3, "descriptor", -1),
        (3, "role", "unknown"),
        (3, "inode", 9999),
        (-1, "sockets", 1),
        (-1, "confirmed", 0),
        (-1, "holders", 3),
        (-1, "stable_sockets", True),
        (-1, "boot_stable", False),
        (-1, "atomic_snapshot", True),
        (-1, "names_read", True),
        (-1, "payload_read", True),
        (-1, "audio_opened", True),
        (-1, "apply_supported", True),
    ],
)
def test_invalid_evidence_rejected(index, key, value):
    rows = frame()
    rows[index][key] = value
    with pytest.raises(ValueError):
        evidence(rows)


@pytest.mark.parametrize(
    "fault",
    ("socket", "holder", "ordering", "identity", "stale", "queue", "after", "end", "unknown", "oversized"),
)
def test_inconsistent_frame_rejected(fault):
    rows = frame()
    if fault == "socket":
        rows.insert(2, dict(rows[1]))
    elif fault == "holder":
        rows.insert(4, dict(rows[3]))
    elif fault == "ordering":
        rows[2], rows[3] = rows[3], rows[2]
    elif fault == "identity":
        rows[4]["pid"] = rows[3]["pid"]
        rows[4]["descriptor"] += 1
    elif fault == "stale":
        rows[1]["stable"] = False
        rows[-1]["stable_sockets"] -= 1
    elif fault == "queue":
        rows[1]["queue_reported"] = False
        rows[1]["receive_before"] = 1
    elif fault == "after":
        rows[1]["stable"] = False
        rows[1]["receive_after"] = 1
    elif fault == "end":
        rows.pop()
    elif fault == "unknown":
        rows[3]["event"] = "unknown"
    if fault == "oversized":
        with pytest.raises(ValueError):
            parse_evidence(" " * (16 * 1024 * 1024 + 1))
    else:
        with pytest.raises(ValueError):
            evidence(rows)


@pytest.mark.parametrize(
    "fault",
    (
        "source",
        "peer",
        "shared_source",
        "shared_peer",
        "nonreciprocal",
        "datagram",
        "pending",
        "missing_peer",
        "no_peer",
        "queue_unavailable",
        "unknown_processes",
    ),
)
def test_graph_keeps_missing_or_ambiguous_coverage_explicit(fault):
    rows = frame()
    if fault in ("source", "peer"):
        rows[3 if fault == "source" else 4]["confirmed"] = False
        rows[-1]["confirmed"] -= 1
    elif fault in ("shared_source", "shared_peer"):
        copy = dict(rows[3 if fault == "shared_source" else 4])
        copy["pid"] += 100
        rows.insert(-1, copy)
        rows[-1]["holders"] += 1
        rows[-1]["confirmed"] += 1
    elif fault == "nonreciprocal":
        rows[2]["peer"] = 9999
    elif fault == "datagram":
        rows[1]["type"] = rows[2]["type"] = 2
    elif fault == "pending":
        rows[2]["receive_after"] = 1
    elif fault == "missing_peer":
        rows[1]["peer"] = 9999
    elif fault == "no_peer":
        rows[1]["peer_reported"], rows[1]["peer"] = False, 0
    elif fault == "queue_unavailable":
        rows[2]["queue_reported"] = False
    elif fault == "unknown_processes":
        rows[-1]["unidentified"] = 1
    report = assess(evidence(rows))
    assert report["isolation_verified"] is False
    assert report["production_plan_ready"] is False
    if fault == "unknown_processes":
        assert report["summary"]["unidentified"] == 1
    else:
        assert report["links"][0]["unresolved"]
        assert report["links"][0]["reciprocal_holder_candidate"] is False


def test_internal_vendor_edge_still_requires_composite_close():
    rows = frame()
    rows[4]["role"] = "audio-diagnostics"
    report = assess(evidence(rows))
    assert report["summary"]["cross_role_endpoints"] == 0
    assert len(report["links"]) == 2
    assert all(link["action"] == "compose-tracked-role-close" for link in report["links"])
