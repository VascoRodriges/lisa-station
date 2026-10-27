"""Opt-in loopback qualification of a scoped on-speaker firewall mechanism.

This is not a privacy-mode installer. No vendor process is changed. Only new
connections from an otherwise unused numeric group are temporarily filtered.
Own chain cleanup runs on exit and from an independent bounded watchdog.
"""

import argparse
import hashlib
import json
import re
import subprocess
from pathlib import Path

SCRIPT = r"""
set -eu
BASE=/data/opt/lisa-controller-lab
CHAIN=LISAQ57341_$$
[ "$(id -u)" = 0 ]
command -v flock >/dev/null
tr '\000' '\n' < /proc/device-tree/compatible | grep -qx 'yandex,station-midi'
if awk -F: '$3==57341 { found=1 } END { exit !found }' /etc/group; then
    echo test_group_exists >&2; exit 3
fi
for status in /proc/[0-9]*/status; do
    [ -r "$status" ] || continue
    if awk '/^Gid:|^Groups:/ { for(i=2;i<=NF;i++) if($i==57341) found=1 } END { exit !found }' "$status"; then
        echo test_group_in_use >&2; exit 3
    fi
done
if iptables -S "$CHAIN" >/dev/null 2>&1 || ip6tables -S "$CHAIN" >/dev/null 2>&1; then
    echo qualification_chain_exists >&2; exit 3
fi
mkdir "$BASE/owner-qualification.lock" || exit 4
STATE=$(mktemp -d "$BASE/owner-qualification.XXXXXX")
chmod 700 "$STATE"
echo "$CHAIN" > "$STATE/chain"
cat > "$STATE/cleanup.sh" <<'CLEANUP'
#!/bin/sh
set -u
STATE=$1
CHAIN=$(cat "$STATE/chain")
exec 9>"$STATE/cleanup.lock"
flock -x 9
[ ! -f "$STATE/cleaned" ] || exit 0
ok=1
for version in 4 6; do
    tool=iptables; [ "$version" = 4 ] || tool=ip6tables
    if [ -f "$STATE/hook$version" ] && "$tool" -C OUTPUT -j "$CHAIN" >/dev/null 2>&1; then
        "$tool" -D OUTPUT -j "$CHAIN" || ok=0
    fi
    if [ -f "$STATE/chain$version" ] && "$tool" -S "$CHAIN" >/dev/null 2>&1; then
        "$tool" -F "$CHAIN" || ok=0
        "$tool" -X "$CHAIN" || ok=0
    fi
    if "$tool" -S "$CHAIN" >/dev/null 2>&1; then ok=0; fi
done
if [ "$ok" = 1 ]; then
    rm -f "$STATE/cleanup.failed"
    touch "$STATE/cleaned"
    rmdir /data/opt/lisa-controller-lab/owner-qualification.lock || exit 9
else
    touch "$STATE/cleanup.failed"
    exit 9
fi
CLEANUP
cleanup() { sh "$STATE/cleanup.sh" "$STATE"; }
trap 'cleanup' EXIT
trap 'exit 125' HUP INT TERM
nohup sh -c 'sleep 40; sh "$1/cleanup.sh" "$1"' watchdog "$STATE" </dev/null >"$STATE/watchdog.log" 2>&1 &
echo '{"phase":"baseline"}'
PROBE baseline
for version in 4 6; do
    tool=iptables; [ "$version" = 4 ] || tool=ip6tables
    touch "$STATE/chain$version"; "$tool" -N "$CHAIN"
    "$tool" -A "$CHAIN" -m owner --gid-owner 57341 -j DROP
done
for family in 4 6; do
    for transport in tcp udp; do
        for identity in root grouped; do
            stem="$STATE/held-$family-$transport-$identity"
            mkfifo "$stem.control"
            PROBE existing "$family" "$transport" "$identity" <"$stem.control" >"$stem.events" &
            child=$!
            exec 3>"$stem.control"
            tries=0
            while ! grep -q '"event":"existing-ready"' "$stem.events"; do
                kill -0 "$child" || { cat "$stem.events"; exit 8; }
                [ "$tries" -lt 100 ] || exit 8
                sleep .05; tries=$((tries+1))
            done
            for version in 4 6; do
                tool=iptables; [ "$version" = 4 ] || tool=ip6tables
                touch "$STATE/hook$version"; "$tool" -I OUTPUT 1 -j "$CHAIN"
            done
            printf g >&3
            result=0; wait "$child" || result=$?
            exec 3>&-
            cat "$stem.events"
            [ "$result" = 0 ] || exit "$result"
            for version in 4 6; do
                tool=iptables; [ "$version" = 4 ] || tool=ip6tables
                "$tool" -D OUTPUT -j "$CHAIN"; rm "$STATE/hook$version"
            done
        done
    done
done
for version in 4 6; do
    tool=iptables; [ "$version" = 4 ] || tool=ip6tables
    touch "$STATE/hook$version"; "$tool" -I OUTPUT 1 -j "$CHAIN"
done
echo '{"phase":"blocked"}'
PROBE blocked
four=$(iptables -n -v -x -L "$CHAIN" | awk '$3=="DROP" {print $1}')
six=$(ip6tables -n -v -x -L "$CHAIN" | awk '$3=="DROP" {print $1}')
printf '{"event":"drop-counters","ipv4_packets":%s,"ipv6_packets":%s}\n' "$four" "$six"
cleanup
[ -f "$STATE/cleaned" ] && [ ! -f "$STATE/cleanup.failed" ]
echo '{"phase":"restored"}'
PROBE baseline
echo '{"event":"cleanup","ok":true,"microphone_opened":false,"vendor_processes_changed":false}'
"""


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("host", help="Existing trusted SSH host alias for the owned speaker")
    parser.add_argument("--ssh-config", type=Path)
    parser.add_argument("--apply-temporary-loopback-test-rules", action="store_true", required=True)
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    binary = (root / "build/net-owner-probe.armhf").read_bytes()
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
    ssh += [args.host]

    def remote(command, **kwargs):
        return subprocess.run(ssh + [command], capture_output=True, timeout=45, **kwargs)

    before = remote(
        "pidof maind; pidof quasar_launcher2; cat /proc/sys/kernel/random/boot_id", check=True
    ).stdout
    backup = remote("iptables-save; ip6tables-save", check=True).stdout
    (root / "build/qualification-firewall-backup.txt").write_bytes(backup)
    target = "/data/opt/lisa-controller-lab/net-owner-" + digest[:16]
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
    result = remote("sh -s", input=SCRIPT.replace("PROBE", target).encode())
    events = [json.loads(line) for line in result.stdout.decode().splitlines()]
    after = remote(
        "pidof maind; pidof quasar_launcher2; cat /proc/sys/kernel/random/boot_id", check=True
    ).stdout
    firewall_after = remote("iptables-save; ip6tables-save", check=True).stdout

    def rules_only(snapshot):
        return re.sub(
            rb"\[\d+:\d+\]",
            b"[]",
            b"\n".join(line for line in snapshot.splitlines() if not line.startswith(b"#")),
        )

    restored = rules_only(backup) == rules_only(firewall_after)
    report = {
        "returncode": result.returncode,
        "binary_sha256": digest,
        "events": events,
        "stock_identity_unchanged": before == after,
        "firewall_rules_restored": restored,
        "whole_device_isolation_proven": False,
        "error": result.stderr.decode(errors="replace")[-1000:],
    }
    (root / "build/net-owner-qualification.json").write_text(
        json.dumps(report, indent=2) + "\n", encoding="utf-8"
    )
    print(json.dumps(report, indent=2))
    assert result.returncode == 0 and before == after and restored
    probes = [row for row in events if row.get("event") == "owner-probe"]
    assert len(probes) == 24 and all(row["ok"] for row in probes)
    established = [row for row in events if row.get("event") == "existing-result"]
    assert len(established) == 8 and all(row["ok"] for row in established)
    counters = next(row for row in events if row.get("event") == "drop-counters")
    assert counters["ipv4_packets"] > 0 and counters["ipv6_packets"] > 0


if __name__ == "__main__":
    main()
