"""Conservative, read-only vendor scope audit. Never publishes a usable flow plan.

Raw addresses/FDs/cookies remain in private build reports. Per-FD observations
are not a frozen actor census, UDP ownership proof or an isolation certificate.
"""

import argparse
import hashlib
import ipaddress
import json
import subprocess
from collections import Counter
from pathlib import Path

from controller.inventory_connections import SCRIPT, parse_inventory

VENDOR_ROLES = {"vendor-worker", "vendor-launcher", "vendor-helper", "audio-diagnostics"}
ROLES = VENDOR_ROLES | {"dns", "time", "other", "unknown"}
SERVICE_ACTIONS = {
    "vendor-launcher": "deny-start-and-stop",
    "vendor-worker": "deny-start-and-stop",
    "vendor-helper": "inventory-and-stop",
    "audio-diagnostics": "deny-start-stop-and-audit-log-relays",
    "dns": "select-independent-profile",
    "time": "select-independent-profile",
}


def _integer(value, minimum=0, maximum=2**64 - 1):
    if type(value) is not int or not minimum <= value <= maximum:
        raise ValueError("invalid evidence integer")
    return value


def _endpoint(value, family):
    address = ipaddress.ip_address(value["address"])
    if address.version != family:
        raise ValueError("evidence family mismatch")
    return dict(address=str(address), port=_integer(value["port"], 1, 65535))


def parse_evidence(text):
    rows = [json.loads(line) for line in text.splitlines()]
    if not 2 <= len(rows) <= 4162 or any(not isinstance(row, dict) for row in rows):
        raise ValueError("invalid evidence frame")
    start, end = rows[0], rows[-1]
    if start.get("event") != "tcp-evidence-start" or end.get("event") != "tcp-evidence-summary":
        raise ValueError("incomplete evidence frame")
    boot = start.get("boot_id")
    if not isinstance(boot, str) or not boot:
        raise ValueError("missing evidence boot")
    if not (
        end.get("boot_stable") is True
        and end.get("atomic_snapshot") is False
        and end.get("audio_opened") is False
        and end.get("apply_supported") is False
    ):
        raise ValueError("unsupported evidence scope")
    addresses, proofs, descriptors = set(), [], set()
    for row in rows[1:-1]:
        family = _integer(row.get("family"), 4, 6)
        if family not in (4, 6):
            raise ValueError("invalid evidence family")
        if row.get("event") == "host-address":
            address = ipaddress.ip_address(row["address"])
            if address.version != family:
                raise ValueError("host address family mismatch")
            addresses.add(str(address))
            continue
        if row.get("event") != "tcp-owner-evidence" or row.get("role") not in ROLES:
            raise ValueError("unknown evidence record")
        proof = dict(row)
        for name, minimum, maximum in (
            ("pid", 2, 2**31 - 1),
            ("descriptor", 0, 2**31 - 1),
            ("start_ticks", 1, 2**64 - 1),
            ("inode", 1, 2**64 - 1),
            ("uid", 0, 2**32 - 1),
            ("interface", 0, 2**32 - 1),
        ):
            _integer(proof.get(name), minimum, maximum)
        key = proof["pid"], proof["descriptor"]
        if key in descriptors or type(proof.get("confirmed")) is not bool:
            raise ValueError("duplicate or invalid FD observation")
        descriptors.add(key)
        proof["local"], proof["remote"] = (
            _endpoint(proof["local"], family),
            _endpoint(proof["remote"], family),
        )
        cookie = proof.get("cookie")
        if not isinstance(cookie, list) or len(cookie) != 2:
            raise ValueError("invalid TCP cookie")
        for word in cookie:
            _integer(word, 0, 2**32 - 1)
        if proof["confirmed"] and cookie == [2**32 - 1] * 2:
            raise ValueError("confirmed cookie missing")
        proofs.append(proof)
    if (
        not addresses
        or _integer(end.get("observations")) != len(proofs)
        or _integer(end.get("confirmed")) != sum(p["confirmed"] for p in proofs)
    ):
        raise ValueError("evidence count mismatch")
    _integer(end.get("unreadable"))
    return dict(boot_id=boot, addresses=sorted(addresses), proofs=proofs, unreadable=end["unreadable"])


def _address(value):
    address = ipaddress.ip_address(value)
    return (
        address.ipv4_mapped if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped else address
    )


def _wire(row):
    local, remote = row["local"], row["remote"]
    source, destination = _address(local["address"]), _address(remote["address"])
    if source.version != destination.version:
        raise ValueError("mixed wire families")
    return (
        row.get("protocol", "tcp"),
        source.version,
        str(source),
        local["port"],
        str(destination),
        remote["port"],
    )


def _processes(snapshot):
    return {int(pid): process for pid, process in snapshot["processes"].items()}


def _vendor_socket(row, processes):
    return any(processes[pid]["role"] in VENDOR_ROLES for pid in row["owners"])


def _exclusive(row, processes):
    return bool(row["owners"]) and all(processes[pid]["role"] in VENDOR_ROLES for pid in row["owners"])


def _fingerprint(row):
    return row["family"], _wire(row), row["state"], row["uid"], row["inode"], tuple(row["owners"])


def _supported_endpoint(proof):
    addresses = [_address(proof[key]["address"]) for key in ("local", "remote")]
    return not proof["interface"] and all(
        not (a.is_unspecified or a.is_multicast or a.is_link_local) for a in addresses
    )


def local_directions(flow, addresses):
    """Retain NAT legs and both endpoints for local-to-local traffic."""
    local_addresses = {_address(value) for value in addresses}
    oriented = set()
    for leg in (flow, flow["reply"]):
        source, destination = _address(leg["src"]), _address(leg["dst"])
        if source in local_addresses:
            oriented.add((str(source), leg["sport"], str(destination), leg["dport"]))
        if destination in local_addresses:
            oriented.add((str(destination), leg["dport"], str(source), leg["sport"]))
    return sorted(oriented)


def udp_candidates(flow, sockets, addresses):
    """Preserve ambiguity, including unknown IPV6_V6ONLY on wildcard sockets."""
    candidates = []
    for source, sport, destination, dport in local_directions(flow, addresses):
        for row in sockets:
            if row["protocol"] != "udp" or row["local"]["port"] != sport:
                continue
            bound, peer = _address(row["local"]["address"]), _address(row["remote"]["address"])
            local = _address(source)
            uncertain = bound.version == 6 and bound.is_unspecified and local.version == 4
            if not uncertain and (
                bound.version != local.version or not (bound.is_unspecified or str(bound) == source)
            ):
                continue
            if row["remote"]["port"] and (row["remote"]["port"] != dport or str(peer) != destination):
                continue
            candidates.append(
                dict(
                    inode=row["inode"],
                    local=dict(address=source, port=sport),
                    remote=dict(address=destination, port=dport),
                    dual_stack_unknown=uncertain,
                )
            )
    return candidates


def analyze(before, evidence, after):
    if not before["boot_id"] == evidence["boot_id"] == after["boot_id"]:
        raise ValueError("inventory boot changed")
    first, last = _processes(before), _processes(after)

    def actors(processes):
        return {
            pid: (p["start_ticks"], p["role"]) for pid, p in processes.items() if p["role"] in VENDOR_ROLES
        }

    blockers = {"snapshot_not_frozen", "boot_profile_relay_queue_barriers_pending"}
    if actors(first) != actors(last):
        blockers.add("vendor_actor_set_changed")
    if evidence["unreadable"]:
        blockers.add("native_census_unreadable")
    after_rows = {row["inode"]: row for row in after["sockets"] if row["inode"]}
    reverse_rows = {}
    for row in after["sockets"]:
        if row["protocol"] == "tcp" and row["state"] == 1:
            reverse_rows.setdefault(_wire(row), []).append(row)
    by_inode = {}
    for proof in evidence["proofs"]:
        by_inode.setdefault(proof["inode"], []).append(proof)
    candidates, unresolved, internal, validated = [], [], [], []
    local_addresses = {_address(value) for value in evidence["addresses"]}
    for row in before["sockets"]:
        if row["protocol"] != "tcp" or not _vendor_socket(row, first):
            continue
        if row["state"] == 10 and row["remote"]["port"] == 0:
            continue  # Listening endpoints need actor/startup coverage, not peer invention.
        reason = None
        match = after_rows.get(row["inode"])
        if row["state"] != 1:
            reason = "tcp_state_unsupported"
        elif (
            not match or _fingerprint(row) != _fingerprint(match) or row["owner_race"] or match["owner_race"]
        ):
            reason = "socket_changed_during_collection"
        elif not _exclusive(row, first) or not _exclusive(match, last):
            reason = "socket_shared_outside_vendor"
        proofs = []
        if not reason:
            for pid in row["owners"]:
                observed = [
                    p
                    for p in by_inode.get(row["inode"], [])
                    if p["pid"] == pid
                    and p["confirmed"]
                    and p["role"] == first[pid]["role"] == last[pid]["role"]
                    and p["start_ticks"] == first[pid]["start_ticks"] == last[pid]["start_ticks"]
                    and p["family"] == row["family"]
                    and p["uid"] == row["uid"]
                    and _wire(p) == _wire(row)
                ]
                if not observed:
                    reason = "native_fd_proof_missing"
                    break
                if len({tuple(p["cookie"]) for p in observed}) != 1:
                    reason = "native_cookie_conflict"
                    break
                proofs.append(observed[0])
            if len({tuple(p["cookie"]) for p in proofs}) > 1:
                reason = "native_cookie_conflict"
            if proofs and not all(_supported_endpoint(p) for p in proofs):
                reason = "endpoint_scope_unsupported"
        if reason:
            blockers.add(reason)
            unresolved.append(dict(inode=row["inode"], reason=reason))
            continue
        validated.append((row, proofs))
    validated_inodes = {row["inode"] for row, _ in validated}
    for row, proofs in validated:
        protocol, family, source, sport, destination, dport = _wire(row)
        peers = reverse_rows.get((protocol, family, destination, dport, source, sport), [])
        local = _address(destination) in local_addresses or _address(destination).is_loopback
        if local and peers and all(_exclusive(peer, last) for peer in peers):
            if all(peer["inode"] in validated_inodes for peer in peers):
                internal.append(row["inode"])
            else:
                blockers.add("local_peer_unverified")
                unresolved.append(dict(inode=row["inode"], reason="local_peer_unverified"))
            continue
        scope = "local-relay" if local else "external"
        if local:
            blockers.add("local_relay_requires_audit")
        candidates.append(
            dict(
                inode=row["inode"],
                family=row["family"],
                local=row["local"],
                remote=row["remote"],
                scope=scope,
                owners=proofs,
                cookie=proofs[0]["cookie"],
                observation_confirmed=True,
            )
        )
    udp = []
    matched_vendor_udp = set()
    for flow in after["conntrack"]:
        if flow["protocol"] != "udp":
            continue
        possible = udp_candidates(flow, after["sockets"], evidence["addresses"])
        vendor = [
            candidate
            for candidate in possible
            if candidate["inode"] in after_rows and _vendor_socket(after_rows[candidate["inode"]], last)
        ]
        if not vendor:
            continue
        matched_vendor_udp.update(c["inode"] for c in vendor)
        reason = "udp_peer_proof_pending" if len(possible) == 1 else "udp_ambiguous_ownership"
        if any(c["dual_stack_unknown"] for c in possible):
            reason = "udp_dual_stack_unknown"
        blockers.add(reason)
        udp.append(
            dict(original=flow, candidates=possible, vendor_candidates=vendor, reason=reason, confirmed=False)
        )
    vendor_udp = [row for row in after["sockets"] if row["protocol"] == "udp" and _vendor_socket(row, last)]
    if any(row["inode"] not in matched_vendor_udp for row in vendor_udp):
        blockers.add("vendor_udp_without_attributed_peer")
    unattributed = []
    tcp_tuples = {_wire(row) for row in after["sockets"] if row["protocol"] == "tcp" and row["inode"]}
    for flow in after["conntrack"]:
        if flow["protocol"] == "udp":
            known = bool(udp_candidates(flow, after["sockets"], evidence["addresses"]))
        else:
            known = any(
                ("tcp", _address(source).version, source, sport, destination, dport) in tcp_tuples
                for source, sport, destination, dport in local_directions(flow, evidence["addresses"])
            )
        if not known:
            unattributed.append(flow)
    if unattributed:
        blockers.add("unattributed_conntrack_records")
    resources = []
    for resource in after.get("resource_links", []):
        if last[resource["pid"]]["role"] in VENDOR_ROLES:
            resources.append(
                dict(resource, role=last[resource["pid"]]["role"], writable=bool(resource["flags"] & 3))
            )
    if resources:
        blockers.add("vendor_file_and_kernel_log_relays_pending")
    roles = Counter(p["role"] for p in last.values())
    return dict(
        boot_id=after["boot_id"],
        metadata_audit_completed=True,
        services=[
            dict(role=role, count=roles[role], required_action=action)
            for role, action in SERVICE_ACTIONS.items()
        ],
        boundary_tcp_candidates=candidates,
        unresolved_tcp=unresolved,
        internal_tcp_inodes=sorted(internal),
        udp_observations=udp,
        vendor_udp_socket_count=len(vendor_udp),
        resource_relays=resources,
        unattributed_conntrack=unattributed,
        blockers=sorted(blockers),
        atomic_snapshot=False,
        apply_supported=False,
        production_plan_ready=False,
        isolation_verified=False,
        audio_opened=False,
    )


def summary(report):
    return dict(
        services=report["services"],
        boundary_tcp_candidates=len(report["boundary_tcp_candidates"]),
        internal_tcp_inodes=len(report["internal_tcp_inodes"]),
        unresolved_tcp=len(report["unresolved_tcp"]),
        vendor_udp_sockets=report["vendor_udp_socket_count"],
        udp_observations=len(report["udp_observations"]),
        unattributed_conntrack=len(report["unattributed_conntrack"]),
        resource_relay_classes=dict(
            Counter((r["role"] + ":" + r["kind"]) for r in report["resource_relays"])
        ),
        blockers=report["blockers"],
        apply_supported=False,
        production_plan_ready=False,
        isolation_verified=False,
        audio_opened=False,
    )


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("host")
    parser.add_argument("--ssh-config", type=Path)
    args = parser.parse_args()
    if args.host.startswith("-"):
        parser.error("host must be an SSH alias")
    root = Path(__file__).resolve().parents[1]
    binary = (root / "build/tcp-evidence-probe.armhf").read_bytes()
    digest = hashlib.sha256(binary).hexdigest()
    ssh = [
        "ssh",
        "-o",
        "BatchMode=yes",
        "-o",
        "ConnectTimeout=20",
        "-o",
        "ServerAliveInterval=8",
        "-o",
        "ServerAliveCountMax=3",
    ]
    if args.ssh_config:
        ssh += ["-F", str(args.ssh_config)]
    ssh += [args.host]

    def remote(command, **kwargs):
        return subprocess.run(ssh + [command], capture_output=True, timeout=70, check=True, **kwargs)

    target = "/data/opt/lisa-controller-lab/tcp-evidence-" + digest[:16]
    remote("umask 077; cat > " + target + ".new && chmod 700 " + target + ".new", input=binary)
    if remote("sha256sum " + target + ".new").stdout.decode().split()[0] != digest:
        raise RuntimeError("uploaded evidence helper digest mismatch")
    remote("mv " + target + ".new " + target)
    before = parse_inventory(remote("sh -s", input=SCRIPT.encode()).stdout.decode())
    evidence_text = remote(target + " --read-only-census").stdout.decode()
    evidence = parse_evidence(evidence_text)
    after = parse_inventory(remote("sh -s", input=SCRIPT.encode()).stdout.decode())
    report = analyze(before, evidence, after)
    private = dict(binary_sha256=digest, before=before, evidence=evidence, after=after, assessment=report)
    (root / "build/vendor-scope-inventory.json").write_text(
        json.dumps(private, indent=2) + "\n", encoding="utf-8"
    )
    print(json.dumps(summary(report), indent=2))


if __name__ == "__main__":
    main()
