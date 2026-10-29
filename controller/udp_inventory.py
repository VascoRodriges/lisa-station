"""Read-only UDP holder evidence, with explicit missing kernel capabilities.

No sendto destination attribution or production flow plan is inferred. Real
addresses and numeric process identities remain in ignored build reports.
"""

import argparse
import hashlib
import ipaddress
import json
import subprocess
import uuid
from collections import Counter, defaultdict
from pathlib import Path

from controller.relay_inventory import VENDOR, integer


def parse_evidence(text):
    if len(text) > 8 * 1024 * 1024:
        raise ValueError("oversized UDP evidence")
    rows = [json.loads(line) for line in text.splitlines()]
    if not 2 <= len(rows) <= 6146 or any(not isinstance(row, dict) for row in rows):
        raise ValueError("invalid UDP evidence frame")
    start, end = rows[0], rows[-1]
    if start.get("event") != "udp-evidence-start" or end.get("event") != "udp-evidence-summary":
        raise ValueError("incomplete UDP evidence")
    boot = start.get("boot_id")
    if not isinstance(boot, str) or str(uuid.UUID(boot)) != boot:
        raise ValueError("invalid UDP boot")
    available = start.get("diag_available")
    error = start.get("diag_error")
    if (
        type(available) is not bool
        or type(error) is not int
        or (error != 0 if available else error not in {-2, -95, -93})
    ):
        raise ValueError("invalid UDP capability")
    if end.get("boot_stable") is not True or any(
        end.get(key) is not False for key in ("atomic_snapshot", "payload_read", "apply_supported")
    ):
        raise ValueError("unsupported UDP scope")
    sockets, holders, descriptors = {}, [], set()
    for row in rows[1:-1]:
        inode = integer(row.get("inode"), 1, 2**32 - 1)
        if row.get("event") == "udp-socket":
            if inode in sockets:
                raise ValueError("duplicate UDP socket")
            family = integer(row.get("family"), 4, 6)
            if (
                family not in {4, 6}
                or type(row.get("stable")) is not bool
                or row.get("state") not in {1, 7}
                or type(row.get("state")) is not int
            ):
                raise ValueError("invalid UDP socket metadata")
            integer(row.get("uid"), 0, 2**32 - 1)
            for name in ("local", "remote"):
                address = ipaddress.ip_address(row[name]["address"])
                if address.version != family or str(address) != row[name]["address"]:
                    raise ValueError("invalid UDP endpoint")
                integer(row[name]["port"], 1 if name == "local" or row["state"] == 1 else 0, 65535)
            if row["state"] == 7 and (
                row["remote"]["port"] or not ipaddress.ip_address(row["remote"]["address"]).is_unspecified
            ):
                raise ValueError("invented unconnected UDP peer")
            cookie = row.get("cookie")
            if not isinstance(cookie, list) or len(cookie) != 2:
                raise ValueError("invalid UDP cookie")
            for word in cookie:
                integer(word, 0, 2**32 - 1)
            if (cookie == [2**32 - 1] * 2) == available:
                raise ValueError("UDP cookie capability mismatch")
            for key in ("interface", "receive_queue", "write_queue"):
                if available:
                    integer(row.get(key), 0, 2**32 - 1)
                elif row.get(key) is not None:
                    raise ValueError("invented UDP kernel metadata")
            if row.get("v6only") is not None and (
                type(row["v6only"]) is not bool or family != 6 or not available
            ):
                raise ValueError("invented v6only flag")
            sockets[inode] = dict(row)
        elif row.get("event") == "udp-holder":
            if (
                inode not in sockets
                or row.get("role") not in VENDOR | {"other"}
                or type(row.get("confirmed")) is not bool
            ):
                raise ValueError("invalid UDP holder")
            for key, minimum, maximum in (
                ("pid", 2, 2**31 - 1),
                ("descriptor", 0, 2**31 - 1),
                ("start_ticks", 1, 2**64 - 1),
                ("exe_device", 0, 2**64 - 1),
                ("exe_inode", 0, 2**64 - 1),
            ):
                integer(row.get(key), minimum, maximum)
            key = row["pid"], row["descriptor"]
            if key in descriptors or (
                row["confirmed"] and (not sockets[inode]["stable"] or not row["exe_inode"])
            ):
                raise ValueError("duplicate or inconsistent UDP holder")
            descriptors.add(key)
            holders.append(dict(row))
        else:
            raise ValueError("unknown UDP record")
    for key, expected in (
        ("sockets", len(sockets)),
        ("stable_sockets", sum(row["stable"] for row in sockets.values())),
        ("holders", len(holders)),
        ("confirmed_holders", sum(row["confirmed"] for row in holders)),
    ):
        if integer(end.get(key)) != expected:
            raise ValueError("UDP evidence count mismatch")
    integer(end.get("unreadable"))
    return dict(
        boot_id=boot,
        diag_available=available,
        diag_error=error,
        sockets=sockets,
        holders=holders,
        unreadable=end["unreadable"],
    )


def analyze(frame):
    owners = defaultdict(list)
    for holder in frame["holders"]:
        owners[holder["inode"]].append(holder)
    vendor = {
        inode: row
        for inode, row in frame["sockets"].items()
        if any(h["role"] in VENDOR for h in owners[inode])
    }
    unresolved = []
    for inode, row in vendor.items():
        reasons = []
        if not frame["diag_available"]:
            reasons.append("kernel_cookie_unavailable")
        if row["state"] == 7:
            reasons.append("sendto_destinations_unattributed")
        if not row["stable"] or not all(h["confirmed"] for h in owners[inode]):
            reasons.append("changed_or_unconfirmed_holder")
        if any(h["role"] not in VENDOR for h in owners[inode]):
            reasons.append("cross_role_holders")
        if row["family"] == 6 and row["v6only"] is None:
            reasons.append("v6only_unknown")
        unresolved.append(
            dict(inode=inode, reasons=reasons, holder_roles=sorted({h["role"] for h in owners[inode]}))
        )
    return dict(
        diag_available=frame["diag_available"],
        diag_error=frame["diag_error"],
        sockets=len(frame["sockets"]),
        vendor_sockets=len(vendor),
        connected_vendor_sockets=sum(row["state"] == 1 for row in vendor.values()),
        unconnected_vendor_sockets=sum(row["state"] == 7 for row in vendor.values()),
        confirmed_holder_observations=sum(h["confirmed"] for h in frame["holders"]),
        unreadable=frame["unreadable"],
        unresolved=unresolved,
        blockers=[
            "sequential_census_not_complete_attribution",
            "old_flow_and_packet_queue_composition_pending",
        ],
        production_plan_ready=False,
        apply_supported=False,
        isolation_verified=False,
        payload_read=False,
    )


def summary(report):
    return {
        **{key: value for key, value in report.items() if key != "unresolved"},
        "unresolved_reasons": dict(
            Counter(reason for row in report["unresolved"] for reason in row["reasons"])
        ),
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("host")
    parser.add_argument("--ssh-config", type=Path)
    args = parser.parse_args()
    if args.host.startswith("-"):
        parser.error("host must be an SSH alias")
    root = Path(__file__).resolve().parents[1]
    binary = (root / "build/udp-evidence-probe.armhf").read_bytes()
    digest = hashlib.sha256(binary).hexdigest()
    ssh = ["ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=20"]
    if args.ssh_config:
        ssh += ["-F", str(args.ssh_config)]
    ssh += [args.host]

    def remote(command, **kwargs):
        return subprocess.run(ssh + [command], capture_output=True, check=True, timeout=60, **kwargs)

    target = "/data/opt/lisa-controller-lab/udp-evidence-" + digest[:16]
    remote("umask 077; cat > " + target + ".new && chmod 700 " + target + ".new", input=binary)
    if remote("sha256sum " + target + ".new").stdout.decode().split()[0] != digest:
        raise RuntimeError("UDP helper digest mismatch")
    remote("mv " + target + ".new " + target)
    frame = parse_evidence(remote(target + " --read-only-census").stdout.decode())
    report = analyze(frame)
    (root / "build/udp-inventory.json").write_text(
        json.dumps(dict(binary_sha256=digest, evidence=frame, assessment=report), indent=2) + "\n"
    )
    print(json.dumps(summary(report), indent=2))


if __name__ == "__main__":
    main()
