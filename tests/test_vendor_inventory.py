"""Scope evidence never turns ambiguous peers or partial observations into policy."""

import json
from copy import deepcopy

import pytest

from controller.vendor_inventory import analyze, parse_evidence, summary, udp_candidates

BOOT = "11111111-2222-4333-8444-555555555555"


def socket(inode, owner, local, sport, remote, dport, protocol="tcp", family=4):
    return dict(
        inode=inode,
        owners=[owner],
        local=dict(address=local, port=sport),
        remote=dict(address=remote, port=dport),
        protocol=protocol,
        family=family,
        state=1 if protocol == "tcp" else 7,
        uid=0,
        owner_race=False,
    )


def fixture():
    before = dict(
        boot_id=BOOT,
        owner_races=[],
        processes={
            101: dict(role="vendor-worker", start_ticks=1001, state="S"),
            102: dict(role="vendor-worker", start_ticks=1002, state="S"),
            103: dict(role="audio-diagnostics", start_ticks=1003, state="S"),
            104: dict(role="other", start_ticks=1004, state="S"),
        },
        sockets=[
            socket(300, 101, "203.0.113.10", 41000, "198.51.100.20", 443),
            socket(301, 101, "127.0.0.1", 42000, "127.0.0.1", 43000),
            socket(302, 102, "127.0.0.1", 43000, "127.0.0.1", 42000),
            socket(600, 101, "0.0.0.0", 50100, "0.0.0.0", 0, "udp"),
        ],
        conntrack=[
            dict(
                protocol="udp",
                family=4,
                src="203.0.113.10",
                sport=50100,
                dst="198.51.100.20",
                dport=443,
                reply=dict(src="198.51.100.20", sport=443, dst="203.0.113.10", dport=50100),
            )
        ],
        resource_links=[dict(pid=103, descriptor=4, kind="kernel-log", flags=1)],
    )
    proofs = [
        dict(
            event="tcp-owner-evidence",
            pid=row["owners"][0],
            descriptor=3 + index,
            start_ticks=before["processes"][row["owners"][0]]["start_ticks"],
            role="vendor-worker",
            inode=row["inode"],
            family=4,
            local=row["local"],
            remote=row["remote"],
            uid=0,
            interface=0,
            cookie=[100 + index, 200 + index],
            confirmed=True,
        )
        for index, row in enumerate(before["sockets"][:3])
    ]
    evidence = dict(
        boot_id=BOOT, addresses=["203.0.113.10", "127.0.0.1", "::1"], proofs=deepcopy(proofs), unreadable=0
    )
    return before, evidence, deepcopy(before)


def evidence_text():
    _, frame, _ = fixture()
    rows = [dict(event="tcp-evidence-start", boot_id=BOOT)]
    rows += [
        dict(event="host-address", family=6 if ":" in value else 4, address=value)
        for value in frame["addresses"]
    ]
    rows += frame["proofs"]
    rows += [
        dict(
            event="tcp-evidence-summary",
            observations=3,
            confirmed=3,
            unreadable=0,
            boot_stable=True,
            atomic_snapshot=False,
            audio_opened=False,
            apply_supported=False,
        )
    ]
    return "\n".join(json.dumps(row) for row in rows)


def test_observed_boundary_is_separate_from_vendor_internal_sockets():
    result = analyze(*fixture())
    assert [row["inode"] for row in result["boundary_tcp_candidates"]] == [300]
    assert result["boundary_tcp_candidates"][0]["cookie"] == [100, 200]
    assert result["internal_tcp_inodes"] == [301, 302]
    assert result["unresolved_tcp"] == []
    assert result["udp_observations"][0]["confirmed"] is False
    assert result["resource_relays"][0]["role"] == "audio-diagnostics"
    assert result["resource_relays"][0]["writable"] is True
    assert all(
        result[key] is False
        for key in ("production_plan_ready", "apply_supported", "isolation_verified", "audio_opened")
    )
    assert "198.51.100.20" not in json.dumps(summary(result))


def test_evidence_parser_counts_and_normalizes():
    frame = parse_evidence(evidence_text())
    assert len(frame["proofs"]) == 3
    assert frame["proofs"][0]["cookie"] == [100, 200]


@pytest.mark.parametrize(
    "fault",
    (
        "no_summary",
        "count",
        "bool_count",
        "no_host_addresses",
        "missing_cookie",
        "cookie_range",
        "bool_inode",
        "pid",
        "fd",
        "ticks",
        "duplicate_fd",
        "role",
        "family",
        "port",
        "capture",
        "apply",
        "boot",
        "atomic",
    ),
)
def test_bad_native_evidence_rejected(fault):
    rows = [json.loads(line) for line in evidence_text().splitlines()]
    proof = next(row for row in rows if row["event"] == "tcp-owner-evidence")
    if fault == "no_summary":
        rows.pop()
    elif fault == "count":
        rows[-1]["confirmed"] = 2
    elif fault == "bool_count":
        rows[-1]["observations"] = True
    elif fault == "no_host_addresses":
        rows = [row for row in rows if row["event"] != "host-address"]
    elif fault == "missing_cookie":
        proof["cookie"] = [2**32 - 1] * 2
    elif fault == "cookie_range":
        proof["cookie"] = [2**32, 0]
    elif fault == "bool_inode":
        proof["inode"] = True
    elif fault == "pid":
        proof["pid"] = 0
    elif fault == "fd":
        proof["descriptor"] = -1
    elif fault == "ticks":
        proof["start_ticks"] = 0
    elif fault == "duplicate_fd":
        rows.insert(-1, deepcopy(proof))
    elif fault == "role":
        proof["role"] = "guessed-vendor"
    elif fault == "family":
        proof["family"] = 6
    elif fault == "port":
        proof["local"]["port"] = 0
    elif fault == "capture":
        rows[-1]["audio_opened"] = True
    elif fault == "apply":
        rows[-1]["apply_supported"] = True
    elif fault == "boot":
        rows[-1]["boot_stable"] = False
    elif fault == "atomic":
        rows[-1]["atomic_snapshot"] = True
    with pytest.raises(ValueError):
        parse_evidence("\n".join(json.dumps(row) for row in rows))


@pytest.mark.parametrize(
    "fault,reason",
    (
        ("shared", "socket_shared_outside_vendor"),
        ("raced", "socket_changed_during_collection"),
        ("removed", "socket_changed_during_collection"),
        ("inode", "native_fd_proof_missing"),
        ("ticks", "native_fd_proof_missing"),
        ("uid", "native_fd_proof_missing"),
        ("role", "native_fd_proof_missing"),
        ("tuple", "native_fd_proof_missing"),
        ("unconfirmed", "native_fd_proof_missing"),
        ("state", "tcp_state_unsupported"),
        ("interface", "endpoint_scope_unsupported"),
        ("cookie_conflict", "native_cookie_conflict"),
    ),
)
def test_boundary_candidate_needs_all_matching_ownership_evidence(fault, reason):
    before, native, after = fixture()
    proof = native["proofs"][0]
    if fault == "shared":
        before["sockets"][0]["owners"].append(104)
        after["sockets"][0]["owners"].append(104)
    elif fault == "raced":
        after["sockets"][0]["owner_race"] = True
    elif fault == "removed":
        after["sockets"].pop(0)
    elif fault == "inode":
        proof["inode"] += 10
    elif fault == "ticks":
        proof["start_ticks"] += 1
    elif fault == "uid":
        proof["uid"] += 1
    elif fault == "role":
        proof["role"] = "other"
    elif fault == "tuple":
        proof["remote"] = dict(address="198.51.100.21", port=443)
    elif fault == "unconfirmed":
        proof["confirmed"] = False
    elif fault == "state":
        before["sockets"][0]["state"] = 2
    elif fault == "interface":
        proof["interface"] = 1
    elif fault == "cookie_conflict":
        before["sockets"][0]["owners"].append(102)
        after["sockets"][0]["owners"].append(102)
        extra = deepcopy(proof)
        extra.update(pid=102, start_ticks=1002, descriptor=19, cookie=[999, 998])
        native["proofs"].append(extra)
    result = analyze(before, native, after)
    assert not result["boundary_tcp_candidates"]
    assert dict(inode=300, reason=reason) in result["unresolved_tcp"]


def test_internal_label_requires_verified_peer_too():
    before, native, after = fixture()
    native["proofs"][2]["confirmed"] = False
    result = analyze(before, native, after)
    assert not result["internal_tcp_inodes"]
    assert dict(inode=301, reason="local_peer_unverified") in result["unresolved_tcp"]


def test_mixed_local_connection_is_relay_candidate():
    before, native, after = fixture()
    before["processes"][102]["role"] = after["processes"][102]["role"] = "dns"
    native["proofs"][2]["role"] = "dns"
    result = analyze(before, native, after)
    assert any(row["scope"] == "local-relay" for row in result["boundary_tcp_candidates"])
    assert "local_relay_requires_audit" in result["blockers"]


def test_actor_restart_and_boot_change_remain_distinct():
    before, native, after = fixture()
    after["processes"][103]["start_ticks"] += 1
    assert "vendor_actor_set_changed" in analyze(before, native, after)["blockers"]
    after["boot_id"] = "changed-boot"
    with pytest.raises(ValueError, match="boot"):
        analyze(before, native, after)


def test_inbound_and_nat_conntrack_legs_are_oriented_locally():
    flow = dict(
        protocol="udp",
        family=4,
        src="198.51.100.20",
        sport=40000,
        dst="203.0.113.30",
        dport=5050,
        reply=dict(src="203.0.113.10", sport=50100, dst="198.51.100.20", dport=40000),
    )
    rows = [socket(600, 101, "0.0.0.0", 50100, "0.0.0.0", 0, "udp")]
    result = udp_candidates(flow, rows, ["203.0.113.10"])
    assert len(result) == 1
    assert result[0]["local"] == dict(address="203.0.113.10", port=50100)
    assert result[0]["remote"] == dict(address="198.51.100.20", port=40000)


@pytest.mark.parametrize("kind", ("shared_port", "dual_stack"))
def test_udp_ambiguity_is_not_a_verified_peer(kind):
    before, native, after = fixture()
    extra = socket(601, 104, "0.0.0.0", 50100, "0.0.0.0", 0, "udp")
    if kind == "dual_stack":
        extra = socket(601, 104, "::", 50100, "::", 0, "udp", 6)
    after["sockets"].append(extra)
    result = analyze(before, native, after)
    row = result["udp_observations"][0]
    assert len(row["candidates"]) == 2 and row["confirmed"] is False
    assert row["reason"] == ("udp_dual_stack_unknown" if kind == "dual_stack" else "udp_ambiguous_ownership")


def test_unowned_conntrack_is_retained_without_turning_it_into_a_rule():
    before, native, after = fixture()
    after["conntrack"][0]["sport"] = 50101
    after["conntrack"][0]["reply"]["dport"] = 50101
    result = analyze(before, native, after)
    assert len(result["unattributed_conntrack"]) == 1
    assert "unattributed_conntrack_records" in result["blockers"]
    assert not result["udp_observations"]
