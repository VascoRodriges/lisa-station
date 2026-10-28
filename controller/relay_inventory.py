"""Read-only queue/log/mapping ownership audit; never reads observed payloads.

Real identities stay in ignored build reports. This does not freeze actors,
quarantine queues, authorize a transition, or attest to complete relay coverage.
"""

import argparse
import hashlib
import json
import subprocess
import uuid
from collections import Counter, defaultdict
from pathlib import Path

VENDOR = {"vendor-worker", "vendor-launcher", "vendor-helper", "audio-diagnostics"}
KINDS = {
    1: "vendor-log",
    2: "launcher-log",
    4: "system-log",
    8: "telemetry-lmdb",
    16: "collector-sqlite",
    32: "rms-shared",
    64: "vendor-data",
    128: "named-anonymous-buffer",
    256: "unclassified-vendor-writable",
    512: "device-memory",
    1024: "runtime-device-state",
}
ACTIONS = {
    1: "private-log-epoch-and-close-inherited-handles",
    2: "private-launcher-log-epoch-and-close-inherited-handles",
    4: "exclude-shared-system-log-from-vendor-collector",
    8: "stop-all-holders-before-vendor-queue-quarantine",
    16: "stop-all-holders-before-coherent-sqlite-queue-quarantine",
    32: "stop-diagnostics-and-writers-before-shared-object-lifecycle-change",
    64: "semantic-review-required-do-not-purge-mixed-device-state",
    128: "close-descriptors-and-mappings-through-tracked-process-lifecycle",
    256: "classify-before-allowing-a-closed-transition",
    512: "release-hardware-mappings-through-tracked-process-lifecycle",
    1024: "semantic-review-required-do-not-purge-runtime-device-state",
}


def integer(value, minimum=0, maximum=2**64 - 1):
    if type(value) is not int or not minimum <= value <= maximum:
        raise ValueError("invalid relay integer")
    return value


def parse_evidence(text):
    if len(text) > 16 * 1024 * 1024:
        raise ValueError("oversized relay frame")
    rows = [json.loads(line) for line in text.splitlines()]
    if not 2 <= len(rows) <= 33794 or any(not isinstance(row, dict) for row in rows):
        raise ValueError("invalid relay frame")
    start, end = rows[0], rows[-1]
    if start.get("event") != "relay-evidence-start" or end.get("event") != "relay-evidence-summary":
        raise ValueError("incomplete relay frame")
    boot = start.get("boot_id")
    if not isinstance(boot, str) or str(uuid.UUID(boot)) != boot:
        raise ValueError("invalid relay boot")
    if not (
        end.get("boot_stable") is True
        and all(
            end.get(name) is False
            for name in ("atomic_snapshot", "audio_opened", "payload_read", "apply_supported")
        )
    ):
        raise ValueError("unsupported relay evidence scope")
    processes, holders, keys = {}, [], set()
    for row in rows[1:-1]:
        pid = integer(row.get("pid"), 1, 2**31 - 1)
        ticks = integer(row.get("start_ticks"), 1)
        if row.get("event") == "relay-process":
            if pid in processes or row.get("role") not in VENDOR | {"other"}:
                raise ValueError("duplicate or unknown relay process")
            processes[pid] = dict(
                start_ticks=ticks,
                exe_device=integer(row.get("exe_device")),
                exe_inode=integer(row.get("exe_inode"), 1),
                role=row["role"],
            )
            continue
        if row.get("event") != "relay-holder" or pid not in processes:
            raise ValueError("missing relay holder identity")
        if processes[pid]["start_ticks"] != ticks:
            raise ValueError("relay holder ticks mismatch")
        for name in ("readable", "writable", "shared", "deleted_hint", "confirmed"):
            if type(row.get(name)) is not bool:
                raise ValueError("invalid relay boolean")
        integer(row.get("device"))
        integer(row.get("inode"), 1)
        kinds = integer(row.get("kinds"), 1, 2047)
        if kinds & 256 and kinds != 256:
            raise ValueError("inconsistent unclassified resource")
        descriptor = integer(row.get("descriptor"), 0, 2**31 - 1)
        flags = integer(row.get("flags"), 0, 2**32 - 1)
        low, high, offset = (integer(row.get(key)) for key in ("low", "high", "offset"))
        if row.get("source") == "descriptor":
            if (
                type(row.get("unlinked")) is not bool
                or low
                or high
                or offset
                or row["shared"]
                or row["deleted_hint"]
                or flags & 3 == 3
                or row["readable"] != (not flags & 0x200000 and flags & 3 != 1)
                or row["writable"] != (not flags & 0x200000 and flags & 3 != 0)
            ):
                raise ValueError("invalid descriptor access evidence")
            key = pid, "descriptor", descriptor
        elif row.get("source") == "mapping":
            if row.get("unlinked") is not None or descriptor or flags or not 0 < low < high:
                raise ValueError("invalid mapping evidence")
            key = pid, "mapping", low, high
        else:
            raise ValueError("invalid relay source")
        if key in keys:
            raise ValueError("duplicate relay observation")
        keys.add(key)
        holders.append(dict(row))
    if (
        integer(end.get("processes"), 0, 1024) != len(processes)
        or integer(end.get("observations"), 0, 32768) != len(holders)
        or integer(end.get("confirmed"), 0, 32768) != sum(h["confirmed"] for h in holders)
    ):
        raise ValueError("relay evidence count mismatch")
    return dict(
        boot_id=boot,
        processes=processes,
        holders=holders,
        unreadable=integer(end.get("unreadable")),
        unidentified=integer(end.get("unidentified")),
        changed_processes=integer(end.get("changed_processes")),
    )


def _fingerprint(row):
    return tuple(
        row[key]
        for key in (
            "pid",
            "start_ticks",
            "device",
            "inode",
            "source",
            "descriptor",
            "flags",
            "low",
            "high",
            "offset",
            "kinds",
            "readable",
            "writable",
            "shared",
            "unlinked",
            "deleted_hint",
        )
    )


def assess(before, after):
    if before["boot_id"] != after["boot_id"]:
        raise ValueError("relay boot changed")
    actors_before = {p: r for p, r in before["processes"].items() if r["role"] in VENDOR}
    actors_after = {p: r for p, r in after["processes"].items() if r["role"] in VENDOR}
    identities = {p for p in before["processes"] if before["processes"][p] == after["processes"].get(p)}
    previous = {_fingerprint(row): row for row in before["holders"]}
    current = {_fingerprint(row): row for row in after["holders"]}
    stable = [
        row
        for key, row in current.items()
        if row["pid"] in identities and row["confirmed"] and key in previous and previous[key]["confirmed"]
    ]
    changed_holders = len(set(previous) | set(current)) - len(stable)
    grouped = defaultdict(list)
    for row in stable:
        grouped[row["device"], row["inode"]].append(row)
    resources, class_counts = [], Counter()
    for (device, inode), holders in sorted(grouped.items()):
        mask = 0
        for row in holders:
            mask |= row["kinds"]
        kinds = [name for bit, name in KINDS.items() if mask & bit]
        class_counts.update(kinds)
        readers = {h["pid"] for h in holders if h["readable"]}
        writers = {
            h["pid"] for h in holders if h["writable"] and (h["source"] == "descriptor" or h["shared"])
        }
        vendor_readers, vendor_writers = readers & actors_after.keys(), writers & actors_after.keys()
        other_readers, other_writers = readers - actors_after.keys(), writers - actors_after.keys()
        resources.append(
            dict(
                device=device,
                inode=inode,
                kinds=kinds,
                vendor_readers=sorted(vendor_readers),
                vendor_writers=sorted(vendor_writers),
                other_readers=sorted(other_readers),
                other_writers=sorted(other_writers),
                cross_role_ingress=bool(vendor_readers and other_writers),
                cross_role_egress=bool(vendor_writers and other_readers),
                holder_observations=len(holders),
                required_actions=[action for bit, action in ACTIONS.items() if mask & bit],
            )
        )
    blockers = [
        "snapshot_not_frozen",
        "unix_and_dbus_peer_policy_pending",
        "queue_epoch_policy_not_installed",
        "boot_and_old_flow_barriers_not_composed",
    ]
    if actors_before or actors_after:
        blockers.append("vendor_actors_running")
    if stable:
        blockers.append("retained_file_or_mapping_holders")
    if (
        actors_before != actors_after
        or changed_holders
        or before["changed_processes"]
        or after["changed_processes"]
    ):
        blockers.append("changed_actor_or_resource")
    if before["unreadable"] or after["unreadable"]:
        blockers.append("unreadable_metadata")
    if before["unidentified"] or after["unidentified"]:
        blockers.append("unidentified_processes_not_attributed")
    if any(r["cross_role_ingress"] and "system-log" in r["kinds"] for r in resources):
        blockers.append("shared_system_log_ingress")
    if class_counts["unclassified-vendor-writable"]:
        blockers.append("unclassified_vendor_writable_resource")
    return dict(
        boot_id=before["boot_id"],
        known_vendor_processes=len(actors_after),
        resource_counts=dict(sorted(class_counts.items())),
        stable_holder_observations=len(stable),
        changed_holder_observations=changed_holders,
        unlinked_descriptor_holders=sum(h["unlinked"] is True for h in stable),
        deleted_mapping_hints=sum(h["deleted_hint"] for h in stable),
        resources=resources,
        holders=stable,
        blockers=blockers,
        atomic_snapshot=False,
        production_plan_ready=False,
        apply_supported=False,
        isolation_verified=False,
        audio_opened=False,
        payload_read=False,
        mutation_performed=False,
    )


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("host")
    parser.add_argument("--ssh-config", type=Path)
    args = parser.parse_args()
    if args.host.startswith("-"):
        parser.error("host must be an SSH alias")
    root = Path(__file__).resolve().parents[1]
    binary = (root / "build/relay-evidence-probe.armhf").read_bytes()
    digest = hashlib.sha256(binary).hexdigest()
    ssh = ["ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=20", "-o", "ServerAliveInterval=8"]
    if args.ssh_config:
        ssh += ["-F", str(args.ssh_config)]
    ssh += [args.host]

    def remote(command, **kwargs):
        return subprocess.run(ssh + [command], capture_output=True, timeout=45, check=True, **kwargs)

    target = "/data/opt/lisa-controller-lab/relay-evidence-" + digest[:16]
    remote("umask 077; cat > " + target + ".new && chmod 700 " + target + ".new", input=binary)
    if remote("sha256sum " + target + ".new").stdout.decode().split()[0] != digest:
        raise RuntimeError("relay helper digest mismatch")
    remote("mv " + target + ".new " + target)
    frames = [parse_evidence(remote(target + " --inventory").stdout.decode()) for _ in range(2)]
    report = assess(*frames)
    report["binary_sha256"] = digest
    (root / "build/relay-inventory.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(
        json.dumps(
            {k: v for k, v in report.items() if k not in {"resources", "holders", "boot_id"}}, indent=2
        )
    )


if __name__ == "__main__":
    main()
