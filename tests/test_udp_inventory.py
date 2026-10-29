"""UDP metadata cannot silently grow into destination attribution or policy."""

import json
from copy import deepcopy

import pytest

from controller.udp_inventory import analyze, parse_evidence, summary

BOOT = "11111111-2222-4333-8444-555555555555"


def fixture(diag=False, connected=False):
    rows = [dict(event="udp-evidence-start", boot_id=BOOT, diag_available=diag, diag_error=0 if diag else -2)]
    rows += [
        dict(
            event="udp-socket",
            inode=100,
            family=4,
            state=1 if connected else 7,
            uid=0,
            local=dict(address="127.0.0.1", port=40000),
            remote=dict(address="127.0.0.1" if connected else "0.0.0.0", port=40001 if connected else 0),
            interface=0 if diag else None,
            cookie=[1, 2] if diag else [2**32 - 1] * 2,
            v6only=None,
            receive_queue=0 if diag else None,
            write_queue=0 if diag else None,
            stable=True,
        )
    ]
    rows += [
        dict(
            event="udp-holder",
            pid=101,
            descriptor=4,
            start_ticks=1001,
            exe_device=1,
            exe_inode=20,
            inode=100,
            role="vendor-worker",
            confirmed=True,
        )
    ]
    rows += [
        dict(
            event="udp-evidence-summary",
            sockets=1,
            stable_sockets=1,
            holders=1,
            confirmed_holders=1,
            unreadable=0,
            boot_stable=True,
            atomic_snapshot=False,
            payload_read=False,
            apply_supported=False,
        )
    ]
    return rows


def parse(rows):
    return parse_evidence("\n".join(json.dumps(row) for row in rows))


@pytest.mark.parametrize("diag", [False, True])
@pytest.mark.parametrize("connected", [False, True])
def test_evidence_stays_read_only(diag, connected):
    report = analyze(parse(fixture(diag, connected)))
    assert report["vendor_sockets"] == 1
    assert report["connected_vendor_sockets"] == int(connected)
    reasons = report["unresolved"][0]["reasons"]
    assert ("kernel_cookie_unavailable" in reasons) == (not diag)
    assert ("sendto_destinations_unattributed" in reasons) == (not connected)
    for field in ("apply_supported", "production_plan_ready", "isolation_verified", "payload_read"):
        assert report[field] is False
    public = summary(report)
    assert "unresolved" not in public
    assert "127.0.0.1" not in json.dumps(public)
    assert "40000" not in json.dumps(public)


@pytest.mark.parametrize(
    "index,key,value",
    [
        (0, "boot_id", "not-a-boot"),
        (0, "diag_available", 1),
        (0, "diag_error", True),
        (0, "diag_error", -71),
        (1, "cookie", [1, 2]),
        (1, "cookie", [False, 2]),
        (1, "receive_queue", 0),
        (1, "write_queue", 0),
        (1, "interface", 0),
        (1, "v6only", False),
        (1, "stable", 1),
        (1, "state", True),
        (1, "family", 5),
        (1, "inode", 0),
        (2, "pid", True),
        (2, "descriptor", -1),
        (2, "start_ticks", 0),
        (2, "confirmed", 1),
        (2, "inode", 101),
        (2, "role", "unknown"),
        (2, "exe_inode", 0),
        (3, "sockets", 2),
        (3, "stable_sockets", 0),
        (3, "confirmed_holders", 0),
        (3, "unreadable", -1),
        (3, "atomic_snapshot", True),
        (3, "apply_supported", True),
        (3, "payload_read", True),
        (3, "boot_stable", False),
    ],
)
def test_reject_bad_metadata(index, key, value):
    rows = fixture()
    rows[index][key] = value
    with pytest.raises(ValueError):
        parse(rows)


def test_unconnected_peer_cannot_be_invented():
    rows = fixture()
    rows[1]["remote"] = dict(address="198.51.100.1", port=443)
    with pytest.raises(ValueError, match="invented"):
        parse(rows)


def test_connected_kernel_missing_cookie():
    rows = fixture(True, True)
    rows[1]["cookie"] = [2**32 - 1] * 2
    with pytest.raises(ValueError, match="capability"):
        parse(rows)


@pytest.mark.parametrize("index", [1, 2])
def test_duplicate_socket_or_fd(index):
    rows = fixture()
    rows.insert(index + 1, deepcopy(rows[index]))
    with pytest.raises(ValueError, match="duplicate"):
        parse(rows)


def test_shared_holder_remains_explicit():
    rows = fixture(True, True)
    other = {**rows[2], "pid": 102, "role": "other"}
    rows.insert(3, other)
    rows[-1].update(holders=2, confirmed_holders=2)
    report = analyze(parse(rows))
    assert "cross_role_holders" in report["unresolved"][0]["reasons"]
    assert report["apply_supported"] is False


def test_unconfirmed_ownership_is_not_lost():
    rows = fixture()
    rows[2]["confirmed"] = False
    rows[-1]["confirmed_holders"] = 0
    report = analyze(parse(rows))
    assert "changed_or_unconfirmed_holder" in report["unresolved"][0]["reasons"]


def test_confirmed_changed_socket_is_inconsistent():
    rows = fixture()
    rows[1]["stable"] = False
    rows[-1]["stable_sockets"] = 0
    with pytest.raises(ValueError, match="inconsistent"):
        parse(rows)


def test_unknown_v6only_remains_unknown():
    rows = fixture(True)
    rows[1].update(family=6, local=dict(address="::", port=40000), remote=dict(address="::", port=0))
    report = analyze(parse(rows))
    assert "v6only_unknown" in report["unresolved"][0]["reasons"]


def test_truncation_and_oversized_frames():
    with pytest.raises(ValueError):
        parse(fixture()[:-1])
    with pytest.raises(ValueError, match="oversized"):
        parse_evidence(" " * (8 * 1024 * 1024 + 1))
