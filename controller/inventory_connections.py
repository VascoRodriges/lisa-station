"""Read-only socket/owner inventory. Real tuples remain in ignored build/ reports.

This is an administrative audit, not a frozen migration snapshot or an isolation
claim. It never reads socket payloads, process environments or command lines.
"""

import argparse
import ipaddress
import json
import re
import subprocess
from collections import Counter, defaultdict
from pathlib import Path

SCRIPT = r"""
set -eu
export LC_ALL=C
[ "$(id -u)" = 0 ]
tr '\000' '\n' < /proc/device-tree/compatible | grep -qx yandex,station-midi
printf 'B\t'; cat /proc/sys/kernel/random/boot_id
for directory in /proc/[0-9]*; do
    pid=${directory##*/}
    exe=$(readlink "$directory/exe" 2>/dev/null) || continue
    case "$exe" in
        /system/vendor/quasar/maind) role=vendor-worker;;
        /system/vendor/quasar/quasar_launcher2) role=vendor-launcher;;
        /system/vendor/quasar/*) role=vendor-helper;;
        /usr/bin/alsa-audio-monitord) role=audio-diagnostics;;
        /usr/sbin/unbound) role=dns;;
        /usr/sbin/chronyd) role=time;;
        *) role=other;;
    esac
    stat=$(cat "$directory/stat" 2>/dev/null) || continue
    tail=${stat##*) }
    set -- $tail; [ "$#" -ge 20 ] || exit 3
    state=$1; shift 19; ticks=$1
    printf 'P\t%s\t%s\t%s\t%s\n' "$pid" "$ticks" "$state" "$role"
    for descriptor in "$directory"/fd/*; do
        link=$(readlink "$descriptor" 2>/dev/null) || continue
        case "$link" in
            socket:\[*\])
                inode=${link#socket:\[}; inode=${inode%\]}
                printf 'S\t%s\t%s\n' "$pid" "$inode";;
        esac
        resource=
        case "$role" in vendor-*|audio-diagnostics)
            case "$link" in
                /dev/kmsg) resource=kernel-log;;
                /bkupgrade/data/quasar/daemons_logs/*) resource=vendor-log;;
                /bkupgrade/data/quasar/data/*) resource=vendor-data;;
                /tmp/messages*) resource=system-log;;
            esac;;
        esac
        if [ -n "$resource" ]; then
            flags=$(awk '/^flags:/{print $2}' "$directory/fdinfo/${descriptor##*/}" 2>/dev/null) || { printf 'R\t%s\n' "$pid"; continue; }
            printf 'F\t%s\t%s\t%s\t%s\n' "$pid" "${descriptor##*/}" "$resource" "$flags"
        fi
    done
    after=$(cat "$directory/stat" 2>/dev/null) || { printf 'R\t%s\n' "$pid"; continue; }
    tail=${after##*) }; set -- $tail; [ "$#" -ge 20 ] || exit 3
    shift 19; [ "$ticks" = "$1" ] || printf 'R\t%s\n' "$pid"
done
for table in tcp tcp6 udp udp6; do
    printf 'N\t%s\n' "$table"
    head -n 4097 /proc/net/$table
done
printf 'N\tconntrack\n'
head -n 4097 /proc/net/nf_conntrack
printf 'E\t'; cat /proc/sys/kernel/random/boot_id
"""


def endpoint(value, ipv6):
    address, port = value.split(":")
    if not re.fullmatch(r"[0-9A-F]{32}" if ipv6 else r"[0-9A-F]{8}", address):
        raise ValueError("invalid proc address")
    if not re.fullmatch(r"[0-9A-F]{4}", port):
        raise ValueError("invalid proc port")
    # The verified ARM kernel exposes each address word in little-endian order.
    raw = bytes.fromhex(address)
    raw = b"".join(raw[index : index + 4][::-1] for index in range(0, len(raw), 4))
    return {"address": str(ipaddress.ip_address(raw)), "port": int(port, 16)}


def proc_socket(line, table):
    values = line.split()
    if len(values) < 10 or not re.fullmatch(r"\d+:", values[0]):
        raise ValueError("invalid proc socket row")
    return dict(
        protocol="tcp" if table.startswith("tcp") else "udp",
        family=6 if table.endswith("6") else 4,
        local=endpoint(values[1], table.endswith("6")),
        remote=endpoint(values[2], table.endswith("6")),
        state=int(values[3], 16),
        uid=int(values[7]),
        inode=int(values[9]),
    )


def conntrack_tuple(line):
    """Keep original and reply directions distinct, including NAT translations."""
    values = line.split()
    if len(values) < 6 or values[0] not in ("ipv4", "ipv6") or values[2] not in ("tcp", "udp"):
        return None
    fields = defaultdict(list)
    for value in values[5:]:
        key, separator, item = value.partition("=")
        if separator and key in ("src", "dst", "sport", "dport"):
            fields[key].append(item)
    if len(fields) != 4 or any(len(items) != 2 for items in fields.values()):
        raise ValueError("incomplete conntrack tuple")
    family = 4 if values[0] == "ipv4" else 6
    legs = []
    for index in range(2):
        leg = {key: items[index] for key, items in fields.items()}
        for key in ("src", "dst"):
            address = ipaddress.ip_address(leg[key])
            if address.version != family:
                raise ValueError("conntrack family mismatch")
            leg[key] = str(address)
        for key in ("sport", "dport"):
            leg[key] = int(leg[key])
            if not 0 <= leg[key] <= 65535:
                raise ValueError("invalid conntrack port")
        legs.append(leg)
    return dict(protocol=values[2], family=family, **legs[0], reply=legs[1])


def parse_inventory(text):
    processes, inodes, tables, races, resources = {}, defaultdict(set), {}, set(), []
    boot, end, current = None, None, None
    for line in text.splitlines():
        fields = line.split("\t")
        kind = fields[0]
        if kind == "B" and len(fields) == 2 and boot is None:
            boot = fields[1]
        elif kind == "E" and len(fields) == 2 and end is None:
            end, current = fields[1], None
        elif kind == "P" and len(fields) == 5:
            pid = int(fields[1])
            if pid in processes:
                raise ValueError("duplicate process")
            processes[pid] = dict(start_ticks=int(fields[2]), state=fields[3], role=fields[4])
        elif kind == "S" and len(fields) == 3:
            inodes[int(fields[2])].add(int(fields[1]))
        elif kind == "R" and len(fields) == 2:
            races.add(int(fields[1]))
        elif kind == "F" and len(fields) == 5:
            if fields[3] not in {"kernel-log", "vendor-log", "vendor-data", "system-log"} or not re.fullmatch(
                r"[0-7]+", fields[4]
            ):
                raise ValueError("invalid resource metadata")
            resource = dict(
                pid=int(fields[1]), descriptor=int(fields[2]), kind=fields[3], flags=int(fields[4], 8)
            )
            if resource["pid"] not in processes or resource["descriptor"] < 0:
                raise ValueError("resource owner absent")
            resources.append(resource)
        elif kind == "N" and len(fields) == 2 and fields[1] not in tables:
            current = fields[1]
            tables[current] = []
        elif current is not None:
            tables[current].append(line)
        else:
            raise ValueError("unexpected inventory record")
    if not boot or boot != end or set(tables) != {"tcp", "tcp6", "udp", "udp6", "conntrack"}:
        raise ValueError("incomplete inventory or changed boot")
    if any(len(rows) >= 4097 for rows in tables.values()):
        raise ValueError("inventory truncated")
    sockets = []
    for table in ("tcp", "tcp6", "udp", "udp6"):
        rows = tables[table]
        if not rows or "local_address" not in rows[0]:
            raise ValueError("missing socket table header")
        for line in rows[1:]:
            row = proc_socket(line, table)
            owners = sorted(inodes.get(row["inode"], set())) if row["inode"] else []
            if any(pid not in processes for pid in owners):
                raise ValueError("socket owner absent from process inventory")
            row["owners"] = owners
            row["roles"] = sorted({processes[pid]["role"] for pid in owners})
            row["owner_race"] = bool(races.intersection(owners))
            sockets.append(row)
    flows = [flow for line in tables["conntrack"] if (flow := conntrack_tuple(line))]
    # UDP often has no connected peer in /proc/net/udp. Retain all candidate
    # source-port matches, including wildcard binds; never assert unique ownership.
    for flow in flows:
        flow["candidate_inodes"] = sorted(
            {
                row["inode"]
                for row in sockets
                if row["protocol"] == flow["protocol"]
                and row["family"] == flow["family"]
                and row["local"]["port"] == flow["sport"]
                and (
                    row["local"]["address"] == flow["src"]
                    or ipaddress.ip_address(row["local"]["address"]).is_unspecified
                )
                and (
                    row["remote"]["port"] == 0
                    or (row["remote"]["port"] == flow["dport"] and row["remote"]["address"] == flow["dst"])
                )
            }
        )
    return dict(
        boot_id=boot,
        processes=processes,
        sockets=sockets,
        conntrack=flows,
        owner_races=sorted(races),
        resource_links=resources,
        atomic_snapshot=False,
        isolation_proven=False,
    )


def summary(report):
    role_counts = Counter()
    for row in report["sockets"]:
        for role in row["roles"]:
            role_counts[role] += 1
    return dict(
        process_count=len(report["processes"]),
        socket_count=len(report["sockets"]),
        sockets_by_role=dict(role_counts),
        conntrack_flow_count=len(report["conntrack"]),
        udp_flows_without_candidate=sum(
            flow["protocol"] == "udp" and not flow["candidate_inodes"] for flow in report["conntrack"]
        ),
        sockets_without_observed_owner=sum(not row["owners"] for row in report["sockets"]),
        observed_owner_races=len(report["owner_races"]),
        atomic_snapshot=False,
        isolation_proven=False,
    )


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("host", help="Trusted SSH alias for an owned compatible speaker")
    parser.add_argument("--ssh-config", type=Path)
    args = parser.parse_args()
    if args.host.startswith("-"):
        parser.error("host must be an SSH alias")
    ssh = [
        "ssh",
        "-o",
        "BatchMode=yes",
        "-o",
        "ConnectTimeout=8",
        "-o",
        "ServerAliveInterval=5",
        "-o",
        "ServerAliveCountMax=2",
    ]
    if args.ssh_config:
        ssh += ["-F", str(args.ssh_config)]
    result = subprocess.run(
        ssh + [args.host, "sh -s"], input=SCRIPT.encode(), capture_output=True, timeout=45, check=True
    )
    report = parse_inventory(result.stdout.decode())
    root = Path(__file__).resolve().parents[1]
    (root / "build").mkdir(exist_ok=True)
    (root / "build/connection-inventory.json").write_text(
        json.dumps(report, indent=2) + "\n",
        encoding="utf-8",
    )
    print(json.dumps(summary(report), indent=2))


if __name__ == "__main__":
    main()
