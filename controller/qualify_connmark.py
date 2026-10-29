"""Bounded own-loopback conntrack-label trial; never label real vendor traffic."""

import argparse
import hashlib
import json
import subprocess
from pathlib import Path

from controller.qualify_socket_close import rules_only

SCRIPT = r"""
set -eu
umask 077
BASE=/data/opt/lisa-controller-lab
[ "$(id -u)" = 0 ]
tr '\000' '\n' < /proc/device-tree/compatible | grep -qx yandex,station-midi
test ! -d /bkupgrade/data/opt/lisa-station/state
test ! -d /run/lisa-station
command -v flock >/dev/null
# Labels must be unused, not guessed from zero packets in our own test.
if iptables-save | grep -E 'CONNMARK|connmark' >/dev/null; then exit 3; fi
if ip6tables-save | grep -E 'CONNMARK|connmark' >/dev/null; then exit 3; fi
if ! awk '{for(i=1;i<=NF;i++) if($i~/^mark=/) {split($i,a,"="); if(int(a[2]/1073741824)%2) bad=1}} END{exit bad}' /proc/net/nf_conntrack; then
    echo 'The fixture label is still retained in conntrack; wait for expiry.' >&2; exit 3
fi
for file in /proc/[0-9]*/status; do
    if awk '/^Gid:|^Groups:/{for(i=2;i<=NF;i++)if($i==57340)found=1} END{exit !found}' "$file" 2>/dev/null; then exit 3; fi
done
mkdir /data/opt/lisa-lab/trial.lock
STATE=$(mktemp -d "$BASE/connmark.XXXXXX")
CHAIN=LISACM_$$
LABEL=LISACML_$$
printf '%s %s\n' "$CHAIN" "$LABEL" > "$STATE/chains"
cat > "$STATE/cleanup.sh" <<'CLEANUP'
#!/bin/sh
set -u
STATE=$1
exec 9>"$STATE/cleanup.lock"
flock -x 9
[ ! -f "$STATE/cleaned" ] || exit 0
set -- $(cat "$STATE/chains"); CHAIN=$1; LABEL=$2
case "$CHAIN:$LABEL" in LISACM_[0-9]*:LISACML_[0-9]*) ;; *) exit 9;; esac
ok=1
for version in 4 6; do
    tool=iptables; [ "$version" = 4 ] || tool=ip6tables
    for hook in INPUT OUTPUT; do
        if [ -f "$STATE/filter-$version-$hook" ] && "$tool" -C "$hook" -j "$CHAIN" >/dev/null 2>&1; then
            "$tool" -D "$hook" -j "$CHAIN" || ok=0
        fi
    done
    if [ -f "$STATE/label-hook-$version" ] && "$tool" -t mangle -C OUTPUT -j "$LABEL" >/dev/null 2>&1; then
        "$tool" -t mangle -D OUTPUT -j "$LABEL" || ok=0
    fi
    if [ -f "$STATE/filter-chain-$version" ]; then "$tool" -F "$CHAIN" && "$tool" -X "$CHAIN" || ok=0; fi
    if [ -f "$STATE/label-chain-$version" ]; then "$tool" -t mangle -F "$LABEL" && "$tool" -t mangle -X "$LABEL" || ok=0; fi
done
[ "$ok" = 1 ] || exit 9
touch "$STATE/cleaned"
rmdir /data/opt/lisa-lab/trial.lock
CLEANUP
cleanup() { sh "$STATE/cleanup.sh" "$STATE"; }
trap cleanup EXIT
trap 'exit 125' HUP INT TERM
nohup sh -c 'sleep 60; sh "$1/cleanup.sh" "$1"' watchdog "$STATE" </dev/null >"$STATE/watchdog.log" 2>&1 &
for version in 4 6; do
    tool=iptables; [ "$version" = 4 ] || tool=ip6tables
    if "$tool" -S "$CHAIN" >/dev/null 2>&1 || "$tool" -t mangle -S "$LABEL" >/dev/null 2>&1; then exit 3; fi
    touch "$STATE/filter-chain-$version"; "$tool" -N "$CHAIN"
    touch "$STATE/label-chain-$version"; "$tool" -t mangle -N "$LABEL"
    "$tool" -t mangle -A "$LABEL" -m owner --gid-owner 57340 -j CONNMARK --set-xmark 0x40000000/0x40000000
    touch "$STATE/label-hook-$version"; "$tool" -t mangle -I OUTPUT 1 -j "$LABEL"
    for hook in INPUT OUTPUT; do touch "$STATE/filter-$version-$hook"; "$tool" -I "$hook" 1 -j "$CHAIN"; done
done
wait_event() {
    tries=0
    while ! grep -q '"event":"'"$1"'"' "$stem.events"; do
        kill -0 "$child" || { cat "$stem.events"; exit 8; }
        [ "$tries" -lt 100 ] || { cat "$stem.events"; exit 8; }
        sleep .05; tries=$((tries+1))
    done
}
counter() {
    packets=$("$tool" -n -v -x -L "$CHAIN" | awk '$3=="DROP" {sum+=$1} END{print sum+0}')
    printf '{"event":"label-counter","family":"%s","protocol":"%s","phase":"%s","packets":%s}\n' "$family_name" "$transport" "$1" "$packets"
}
for family in 4 6 mapped; do
    version=4; address=127.0.0.1; family_name=ipv4; ct_family=ipv4
    if [ "$family" = 6 ]; then version=6; address=::1; family_name=ipv6; ct_family=ipv6; fi
    if [ "$family" = mapped ]; then family_name=ipv4-mapped-ipv6; fi
    ct_address=$address
    if [ "$family" = 6 ]; then ct_address=0000:0000:0000:0000:0000:0000:0000:0001; fi
    tool=iptables; [ "$version" = 4 ] || tool=ip6tables
    for transport in tcp udp; do
        stem="$STATE/$family-$transport"
        mkfifo "$stem.control"; exec 3<>"$stem.control"
        PROBE --own-connmark "$family" "$transport" <"$stem.control" >"$stem.events" 2>"$stem.error" &
        child=$!
        wait_event label-ready
        ready=$(grep '"event":"label-ready"' "$stem.events")
        source=$(printf '%s\n' "$ready" | sed -n 's/.*"source_port":\([0-9][0-9]*\).*/\1/p')
        destination=$(printf '%s\n' "$ready" | sed -n 's/.*"destination_port":\([0-9][0-9]*\).*/\1/p')
        [ "$source" -gt 0 ] && [ "$source" -le 65535 ] && [ "$destination" -gt 0 ] && [ "$destination" -le 65535 ] && [ "$source" != "$destination" ]
        awk -v fam="$ct_family" -v p="$transport" -v s="sport=$source" -v d="dport=$destination" -v a="src=$ct_address" -v b="dst=$ct_address" '
            $1==fam && $3==p {seen_s=seen_d=seen_a=seen_b=seen_m=0; for(i=6;i<=NF;i++) {seen_s+=($i==s);seen_d+=($i==d);seen_a+=($i==a);seen_b+=($i==b);seen_m+=($i=="mark=1073741824")} if(seen_s&&seen_d&&seen_a&&seen_b&&seen_m) found++} END{exit found!=1}' /proc/net/nf_conntrack
        printf '{"event":"label-attributed","family":"%s","protocol":"%s","group":57340,"mark":1073741824}\n' "$family_name" "$transport"
        "$tool" -A "$CHAIN" -m connmark --mark 0x40000000/0x40000000 -j DROP
        printf b >&3; wait_event label-closed; counter closed
        # Lab-only peer-direction exception lets an owned peer trigger an orphan
        # response. A production closed policy must not contain this exception.
        "$tool" -D INPUT -j "$CHAIN"; rm "$STATE/filter-$version-INPUT"
        "$tool" -I "$CHAIN" 1 -p "$transport" -s "$address" -d "$address" --sport "$destination" --dport "$source" -j RETURN
        printf o >&3; wait_event label-orphan; counter orphan
        "$tool" -F "$CHAIN"
        printf r >&3
        result=0; wait "$child" || result=$?
        exec 3>&-
        cat "$stem.events"; cat "$stem.error" >&2
        [ "$result" = 0 ] || exit "$result"
        touch "$STATE/filter-$version-INPUT"; "$tool" -I INPUT 1 -j "$CHAIN"
    done
done
cleanup
echo '{"event":"label-cleanup","ok":true}'
"""


def evaluate_events(events):
    if len(events) != 103 or any(not isinstance(row, dict) for row in events):
        return False
    common = {
        "baseline",
        "open_exchange",
        "unrelated_control_closed",
        "stray_to_closed_endpoint",
        "kernel_reply_denied",
        "unrelated_control_orphan",
        "kernel_reply_after_lab_restore",
        "unrelated_control_restored",
    }
    expected_events = {
        "label-attributed",
        "label-counter",
        "label-check",
        "label-ready",
        "label-closed",
        "label-orphan",
        "label-summary",
        "label-cleanup",
    }
    if any(row.get("event") not in expected_events for row in events):
        return False
    cleanup = [row for row in events if row["event"] == "label-cleanup"]
    if len(cleanup) != 1 or cleanup[0].get("ok") is not True or events[-1] != cleanup[0]:
        return False
    cases = {
        (family, protocol) for family in ("ipv4", "ipv6", "ipv4-mapped-ipv6") for protocol in ("tcp", "udp")
    }
    if any(
        (row.get("family"), row.get("protocol")) not in cases
        for row in events
        if row["event"] != "label-cleanup"
    ):
        return False
    for family, protocol in cases:
        rows = [row for row in events if (row.get("family"), row.get("protocol")) == (family, protocol)]
        checks = [row for row in rows if row["event"] == "label-check"]
        names = common | (
            {"own_socket_lookup", "own_socket_destroy", "reset_denied"}
            if protocol == "tcp"
            else {"unconnected_send_denied"}
        )
        if (
            len(checks) != len(names)
            or {row.get("check") for row in checks} != names
            or any(row.get("ok") is not True for row in checks)
        ):
            return False
        for event in ("label-attributed", "label-ready", "label-closed", "label-orphan", "label-summary"):
            items = [row for row in rows if row["event"] == event]
            if len(items) != 1:
                return False
            row = items[0]
            if event == "label-attributed" and (
                type(row.get("group")) is not int
                or row["group"] != 57340
                or type(row.get("mark")) is not int
                or row["mark"] != 1073741824
            ):
                return False
            if event == "label-ready" and (
                any(
                    type(row.get(key)) is not int or not 1 <= row[key] <= 65535
                    for key in ("source_port", "destination_port")
                )
                or row["source_port"] == row["destination_port"]
            ):
                return False
            if event == "label-summary" and (
                type(row.get("checks")) is not int
                or row["checks"] != len(names)
                or type(row.get("failures")) is not int
                or row["failures"] != 0
                or row.get("audio_opened") is not False
                or row.get("vendor_processes_changed") is not False
            ):
                return False
        counters = [row for row in rows if row["event"] == "label-counter"]
        if (
            len(counters) != 2
            or {row.get("phase") for row in counters} != {"closed", "orphan"}
            or any(type(row.get("packets")) is not int or row["packets"] < 1 for row in counters)
        ):
            return False
        by_phase = {row["phase"]: row["packets"] for row in counters}
        if by_phase["orphan"] <= by_phase["closed"]:
            return False
    return True


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("host")
    parser.add_argument("--ssh-config", type=Path)
    parser.add_argument("--apply-temporary-loopback-labels", required=True, action="store_true")
    args = parser.parse_args()
    if args.host.startswith("-"):
        parser.error("host must be an SSH alias")
    root = Path(__file__).resolve().parents[1]
    binary = (root / "build/connmark-probe.armhf").read_bytes()
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
        return subprocess.run(ssh + [command], capture_output=True, timeout=100, **kwargs)

    identity = "pidof quasar_launcher2; pidof maind; pidof alsa-audio-monitord; cat /proc/sys/kernel/random/boot_id; sha256sum /system/vendor/quasar/launch.json"
    before = remote(identity, check=True).stdout
    rules = remote("iptables-save; ip6tables-save", check=True).stdout
    target = "/data/opt/lisa-controller-lab/connmark-" + digest[:16]
    remote("umask 077; cat > " + target + ".new && chmod 700 " + target + ".new", input=binary, check=True)
    if remote("sha256sum " + target + ".new", check=True).stdout.decode().split()[0] != digest:
        raise RuntimeError("connmark helper digest mismatch")
    remote("mv " + target + ".new " + target, check=True)
    result = remote("sh -s", input=SCRIPT.replace("PROBE", target).encode())
    after = remote(identity, check=True).stdout
    after_rules = remote("iptables-save; ip6tables-save", check=True).stdout
    events = [json.loads(line) for line in result.stdout.decode().splitlines() if line.startswith("{")]
    report = dict(
        binary_sha256=digest,
        returncode=result.returncode,
        events=events,
        error=result.stderr.decode()[-2000:],
        firewall_rules_restored=rules_only(rules) == rules_only(after_rules),
        stock_identity_preserved=before == after,
        audio_captured=False,
        production_mode_changed=False,
        isolation_verified=False,
        qualified=result.returncode == 0
        and evaluate_events(events)
        and rules_only(rules) == rules_only(after_rules)
        and before == after,
    )
    (root / "build/connmark-qualification.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps({key: value for key, value in report.items() if key != "events"}, indent=2))
    if (
        not report["qualified"]
        or not report["firewall_rules_restored"]
        or not report["stock_identity_preserved"]
    ):
        raise SystemExit("connmark trial incomplete; inspect private report")


if __name__ == "__main__":
    main()
