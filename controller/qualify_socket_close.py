"""Qualify exact TCP destruction using only this probe's own loopback sockets."""

import argparse
import hashlib
import json
import re
import subprocess
from pathlib import Path


def evaluate_events(events):
    """Require the complete matrix, not just a zero process exit status."""
    names = {
        "own_loopback_pairs",
        "lookup_matches_own_inode",
        "destroy_requires_cookie",
        "wrong_cookie_rejected",
        "restricted_root_denied",
        "exact_cookie_destroyed",
        "target_endpoints_closed",
        "stale_destroy_rejected",
        "unrelated_connection_survives",
    }
    expected = {(family, name) for family in ("ipv4", "ipv6", "ipv4-mapped-ipv6") for name in names}
    checks = [event for event in events if event.get("event") == "socket-close-check"]
    summaries = [event for event in events if event.get("event") == "socket-close-summary"]
    return (
        len(checks) == len(expected)
        and {(event.get("family"), event.get("check")) for event in checks} == expected
        and all(event.get("ok") is True for event in checks)
        and len(summaries) == 1
        and summaries[0].get("checks") == len(expected)
        and summaries[0].get("failures") == 0
        and summaries[0].get("microphone_opened") is False
        and summaries[0].get("vendor_processes_changed") is False
        and len(events) == len(expected) + 1
    )


def rules_only(data):
    return re.sub(
        rb"\[\d+:\d+\]",
        b"[]",
        b"\n".join(line for line in data.splitlines() if not line.startswith(b"#")),
    )


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("host", help="Trusted SSH alias for an owned compatible speaker")
    parser.add_argument("--ssh-config", type=Path)
    parser.add_argument("--run-own-loopback-selftest", action="store_true", required=True)
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    binary = (root / "build/socket-close-probe.armhf").read_bytes()
    digest = hashlib.sha256(binary).hexdigest()
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
    if args.host.startswith("-"):
        parser.error("host must be an SSH alias")
    ssh += [args.host]

    def remote(command, **kwargs):
        return subprocess.run(ssh + [command], capture_output=True, timeout=35, **kwargs)

    remote(
        '[ "$(id -u)" = 0 ] && '
        "tr '\\000' '\\n' < /proc/device-tree/compatible | grep -qx yandex,station-midi",
        check=True,
    )
    identity_command = "pidof maind; pidof quasar_launcher2; cat /proc/sys/kernel/random/boot_id"
    before = remote(identity_command, check=True).stdout
    firewall = remote("iptables-save; ip6tables-save", check=True).stdout
    target = "/data/opt/lisa-controller-lab/socket-close-" + digest[:16]
    remote(
        "umask 077; mkdir -p /data/opt/lisa-controller-lab; cat > "
        + target
        + ".new && chmod 700 "
        + target
        + ".new",
        input=binary,
        check=True,
    )
    assert remote("sha256sum " + target + ".new", check=True).stdout.decode().split()[0] == digest
    remote("mv " + target + ".new " + target, check=True)
    # Reuse the established group only if it has no configured or running users.
    script = r"""
set -eu
if awk -F: '$3==57341 { found=1 } END { exit !found }' /etc/group; then exit 3; fi
for status in /proc/[0-9]*/status; do
    [ -r "$status" ] || continue
    if awk '/^Gid:|^Groups:/ { for(i=2;i<=NF;i++) if($i==57341) found=1 } END { exit !found }' "$status"; then
        exit 3
    fi
done
exec PROBE --selftest
"""
    result = remote("sh -s", input=script.replace("PROBE", target).encode())
    after = remote(identity_command, check=True).stdout
    firewall_after = remote("iptables-save; ip6tables-save", check=True).stdout
    events = [json.loads(line) for line in result.stdout.decode().splitlines()]
    report = {
        "returncode": result.returncode,
        "binary_sha256": digest,
        "qualified": result.returncode == 0 and evaluate_events(events),
        "events": events,
        "stock_identity_unchanged": before == after,
        "firewall_rules_unchanged": rules_only(firewall) == rules_only(firewall_after),
        "whole_device_isolation_proven": False,
        "error": result.stderr.decode(errors="replace")[-1000:],
    }
    (root / "build/socket-close-qualification.json").write_text(
        json.dumps(report, indent=2) + "\n",
        encoding="utf-8",
    )
    print(json.dumps(report, indent=2))
    assert report["qualified"] and report["stock_identity_unchanged"] and report["firewall_rules_unchanged"]


if __name__ == "__main__":
    main()
