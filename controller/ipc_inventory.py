"""Read-only UNIX peer/holder graph; private reports, aggregate CLI output only.

Peer metadata is not a method policy, an atomic census or proof that another
process has no copied data, queued descriptors or external egress.
"""

import argparse
import hashlib
import json
import subprocess
import uuid
from collections import Counter, defaultdict
from pathlib import Path

from controller.relay_inventory import VENDOR, integer


def parse_evidence(text):
    if not isinstance(text, str) or len(text) > 16 * 1024 * 1024:
        raise ValueError("oversized IPC frame")
    rows = [json.loads(line) for line in text.splitlines()]
    if not 2 <= len(rows) <= 24578 or any(not isinstance(row, dict) for row in rows):
        raise ValueError("invalid IPC frame")
    start, end = rows[0], rows[-1]
    if start.get("event") != "ipc-evidence-start" or end.get("event") != "ipc-evidence-summary":
        raise ValueError("incomplete IPC frame")
    boot = start.get("boot_id")
    if not isinstance(boot, str) or str(uuid.UUID(boot)) != boot:
        raise ValueError("invalid IPC boot identity")
    if end.get("boot_stable") is not True or any(
        end.get(key) is not False
        for key in ("atomic_snapshot", "payload_read", "names_read", "audio_opened", "apply_supported")
    ):
        raise ValueError("unsupported IPC evidence scope")
    sockets, holders, processes, descriptors = {}, [], {}, set()
    for row in rows[1:-1]:
        inode = integer(row.get("inode"), 1, 2**32 - 1)
        if row.get("event") == "ipc-socket":
            if holders or inode in sockets:
                raise ValueError("duplicate or unordered IPC socket")
            cookie = row.get("cookie")
            if not isinstance(cookie, list) or len(cookie) != 2:
                raise ValueError("invalid IPC cookie")
            for value in cookie:
                integer(value, 0, 2**32 - 1)
            if cookie == [2**32 - 1, 2**32 - 1]:
                raise ValueError("missing IPC cookie")
            if integer(row.get("type"), 1, 5) not in (1, 2, 5):
                raise ValueError("unsupported IPC type")
            integer(row.get("state"), 1, 12)
            for key in ("peer_reported", "queue_reported", "stable"):
                if type(row.get(key)) is not bool:
                    raise ValueError("invalid IPC boolean")
            peer = integer(row.get("peer"), 0, 2**32 - 1)
            if peer and not row["peer_reported"]:
                raise ValueError("inconsistent IPC peer")
            for key in ("receive_before", "receive_after", "write_before", "write_after"):
                value = integer(row.get(key), 0, 2**32 - 1)
                if value and (not row["queue_reported"] or (key.endswith("after") and not row["stable"])):
                    raise ValueError("inconsistent IPC queue")
            sockets[inode] = dict(row)
        elif row.get("event") == "ipc-holder":
            if inode not in sockets or type(row.get("confirmed")) is not bool:
                raise ValueError("missing IPC socket evidence")
            pid = integer(row.get("pid"), 1, 2**31 - 1)
            descriptor = integer(row.get("descriptor"), 0, 2**31 - 1)
            key = pid, descriptor
            if key in descriptors:
                raise ValueError("duplicate IPC descriptor")
            descriptors.add(key)
            identity = (
                integer(row.get("start_ticks"), 1),
                integer(row.get("exe_device")),
                integer(row.get("exe_inode"), 1),
                row.get("role"),
            )
            if identity[-1] not in VENDOR | {"other"} or processes.get(pid, identity) != identity:
                raise ValueError("inconsistent IPC process identity")
            processes[pid] = identity
            if row["confirmed"] and not sockets[inode]["stable"]:
                raise ValueError("stale IPC holder promoted")
            holders.append(dict(row))
        else:
            raise ValueError("unknown IPC event")
    expected = {
        "sockets": len(sockets),
        "stable_sockets": sum(row["stable"] for row in sockets.values()),
        "holders": len(holders),
        "confirmed": sum(row["confirmed"] for row in holders),
    }
    for key, count in expected.items():
        if integer(end.get(key)) != count:
            raise ValueError("IPC evidence count mismatch")
    if len(sockets) > 8192 or len(holders) > 16384:
        raise ValueError("IPC evidence limit exceeded")
    return dict(
        boot_id=boot,
        sockets=sockets,
        holders=holders,
        unreadable=integer(end.get("unreadable")),
        unidentified=integer(end.get("unidentified")),
    )


def assess(evidence):
    sockets = evidence["sockets"]
    holders = defaultdict(list)
    for row in evidence["holders"]:
        holders[row["inode"]].append(row)
    links = []
    for inode, owners in holders.items():
        if not any(owner["role"] in VENDOR for owner in owners):
            continue
        socket = sockets[inode]
        peer = sockets.get(socket["peer"])
        peers = holders.get(socket["peer"], [])
        reasons = []
        if not socket["stable"] or not all(owner["confirmed"] for owner in owners):
            reasons.append("unstable-source-evidence")
        if not socket["peer_reported"] or not socket["peer"]:
            reasons.append("no-fixed-peer-listener-or-unconnected-datagram")
        if not peer or not peers:
            reasons.append("peer-holder-unresolved")
        elif not peer["stable"] or not all(owner["confirmed"] for owner in peers):
            reasons.append("unstable-peer-evidence")
        if len({owner["pid"] for owner in owners}) != 1:
            reasons.append("source-shared-between-processes")
        if len({owner["pid"] for owner in peers}) > 1:
            reasons.append("peer-shared-between-processes")
        if peer and (peer["type"] != socket["type"] or peer["peer"] != inode or not peer["peer_reported"]):
            reasons.append("nonreciprocal-peer")
        if socket["type"] == 2:
            reasons.append("datagram-peer-does-not-cover-arbitrary-sendto")
        if not socket["queue_reported"] or (peer and not peer["queue_reported"]):
            reasons.append("queue-metadata-unavailable")
        pending = any(
            endpoint and (endpoint["receive_before"] or endpoint["receive_after"])
            for endpoint in (socket, peer)
        )
        if pending:
            reasons.append("observed-receive-queue-nonempty")
        cross_role = any(owner["role"] not in VENDOR for owner in peers)
        links.append(
            dict(
                inode=inode,
                peer_inode=socket["peer"],
                source_holders=owners,
                peer_holders=peers,
                cross_role=cross_role,
                reciprocal_holder_candidate=not reasons,
                unresolved=reasons,
                action="review-relay-policy-and-retained-data"
                if cross_role
                else "compose-tracked-role-close",
            )
        )
    counts = Counter(reason for link in links for reason in link["unresolved"])
    return dict(
        schema_version=1,
        boot_id=evidence["boot_id"],
        links=links,
        summary=dict(
            unix_sockets=len(sockets),
            vendor_endpoints=len(links),
            cross_role_endpoints=sum(link["cross_role"] for link in links),
            reciprocal_holder_candidates=sum(link["reciprocal_holder_candidate"] for link in links),
            unresolved=dict(counts),
            unreadable=evidence["unreadable"],
            unidentified=evidence["unidentified"],
        ),
        atomic_snapshot=False,
        names_read=False,
        payload_read=False,
        audio_opened=False,
        production_plan_ready=False,
        apply_supported=False,
        isolation_verified=False,
    )


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("host")
    parser.add_argument("--ssh-config", type=Path)
    args = parser.parse_args()
    if args.host.startswith("-"):
        parser.error("host must be an SSH alias")
    root = Path(__file__).resolve().parents[1]
    binary = (root / "build/unix-peer-probe.armhf").read_bytes()
    digest = hashlib.sha256(binary).hexdigest()
    target = "/data/opt/lisa-controller-lab/unix-peer-probe-" + digest[:16]
    ssh = ["ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=20"]
    if args.ssh_config:
        ssh += ["-F", str(args.ssh_config)]
    ssh += [args.host]

    def remote(command, **kwargs):
        return subprocess.run(ssh + [command], capture_output=True, timeout=30, **kwargs)

    remote("umask 077; cat > " + target + ".new && chmod 700 " + target + ".new", input=binary, check=True)
    if remote("sha256sum " + target + ".new", check=True).stdout.decode().split()[0] != digest:
        raise RuntimeError("IPC probe digest mismatch")
    remote("mv " + target + ".new " + target, check=True)
    identity = "pidof maind; pidof quasar_launcher2 alsa-audio-monitord; cat /proc/sys/kernel/random/boot_id; sha256sum /system/vendor/quasar/quasar.cfg /system/vendor/quasar/launch.json"
    before = remote(identity, check=True).stdout
    evidence = parse_evidence(remote(target + " --inventory", check=True).stdout.decode())
    after = remote(identity, check=True).stdout
    report = assess(evidence)
    report["binary_sha256"] = digest
    report["stock_process_boot_and_config_unchanged"] = before == after
    (root / "build/ipc-inventory.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(
        json.dumps(
            dict(report["summary"], stock_unchanged=before == after, isolation_verified=False), indent=2
        )
    )
    if before != after:
        raise SystemExit("device changed during IPC audit; inspect private report")


if __name__ == "__main__":
    main()
