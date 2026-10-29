"""Own loopback epochs: new traffic works while retired labelled flows stay closed."""

import argparse
import hashlib
import json
import subprocess
from pathlib import Path

from controller.qualify_socket_close import rules_only

SCRIPT = r"""
set -eu
umask 077
tr '\000' '\n' < /proc/device-tree/compatible | grep -qx yandex,station-midi
awk '$2=="/" && $4~/^ro,/ {ok=1} END {exit !ok}' /proc/mounts
test ! -d /bkupgrade/data/opt/lisa-station/state
test ! -d /run/lisa-station
rules4=$(iptables-save); rules6=$(ip6tables-save)
if printf '%s\n' "$rules4" | grep -E 'CONNMARK|connmark' >/dev/null; then exit 3; fi
if printf '%s\n' "$rules6" | grep -E 'CONNMARK|connmark' >/dev/null; then exit 3; fi
awk '{for(i=1;i<=NF;i++) if($i~/^mark=/) {split($i,a,"="); if(int(a[2]/16777216)) bad=1}} END{exit bad}' /proc/net/nf_conntrack
for file in /proc/[0-9]*/status; do
    if awk '/^Gid:|^Groups:/{for(i=2;i<=NF;i++)if($i>=57342&&$i<=57345)found=1} END{exit !found}' "$file" 2>/dev/null; then exit 3; fi
done
mkdir /data/opt/lisa-lab/trial.lock
STATE=$(mktemp -d /data/opt/lisa-controller-lab/epochs.XXXXXX)
SUFFIX=$(basename "$STATE" | tr 'a-z' 'A-Z' | tr -d '.')
CHAIN=LISACQ_$SUFFIX
MARK=LISACM_$SUFFIX
DENY=LISACL_$SUFFIX
printf '%s %s %s\n' "$CHAIN" "$MARK" "$DENY" > "$STATE/chains"
cat > "$STATE/cleanup.sh" <<'CLEANUP'
#!/bin/sh
set -eu
STATE=$1
exec 9>"$STATE/cleanup.lock"; flock -x 9
[ ! -e "$STATE/cleaned" ] || exit 0
if [ -f "$STATE/child" ]; then
    set -- $(cat "$STATE/child"); child=$1; ticks=$2
    now=$(awk '{print $22}' /proc/"$child"/stat 2>/dev/null || true)
    if [ "$now" = "$ticks" ] && [ "$(readlink /proc/"$child"/exe)" = PROBE ]; then
        kill -TERM "$child" || true
        tries=0
        while [ "$(awk '{print $22}' /proc/"$child"/stat 2>/dev/null || true)" = "$ticks" ]; do
            state=$(awk '{print $3}' /proc/"$child"/stat 2>/dev/null || true)
            [ "$state" != Z ] || break
            [ "$tries" -lt 50 ] || exit 9
            sleep .05; tries=$((tries+1))
        done
    fi
fi
set -- $(cat "$STATE/chains"); CHAIN=$1; MARK=$2; DENY=$3
case "$CHAIN:$MARK:$DENY" in LISACQ_EPOCHS[A-Z0-9]*:LISACM_EPOCHS[A-Z0-9]*:LISACL_EPOCHS[A-Z0-9]*) ;; *) exit 9;; esac
for version in 4 6; do
    tool=iptables; [ "$version" = 4 ] || tool=ip6tables
    for kind in group mark deny; do
        table=filter; name=$CHAIN
        [ "$kind" != mark ] || { table=mangle; name=$MARK; }
        [ "$kind" != deny ] || name=$DENY
        [ -f "$STATE/chain-$version-$kind" ] || continue
        "$tool" -t "$table" -S "$name" > "$STATE/cleanup-$version-$kind.rules"
        case "$kind" in
            group) pattern="^-N $name$|^-A $name -m owner --gid-owner (57342|57343|57344|57345) -j DROP$";;
            mark) pattern="^-N $name$|^-A $name -m owner --gid-owner (57342|57343|57344|57345) -m connmark --mark 0x0/0xff000000 -j CONNMARK --set-xmark 0x[1-9a-c]000000/0xff000000$";;
            deny) pattern="^-N $name$|^-A $name -m connmark ! --mark 0x0/0xff000000 -j DROP$|^-A $name -m connmark --mark 0x(0|[1-9a-c]000000)/0xff000000 -j RETURN$|^-A $name -j DROP$";;
        esac
        result=0; grep -Ev "$pattern" "$STATE/cleanup-$version-$kind.rules" >/dev/null || result=$?
        [ "$result" = 1 ] || exit 9
    done
    for hook in INPUT OUTPUT; do
        for name in "$CHAIN" "$DENY"; do
            if "$tool" -C "$hook" -j "$name" >/dev/null 2>&1; then "$tool" -D "$hook" -j "$name"; fi
        done
    done
    if "$tool" -t mangle -C OUTPUT -j "$MARK" >/dev/null 2>&1; then "$tool" -t mangle -D OUTPUT -j "$MARK"; fi
    for kind in group mark deny; do
        table=filter; name=$CHAIN
        [ "$kind" != mark ] || { table=mangle; name=$MARK; }
        [ "$kind" != deny ] || name=$DENY
        [ -f "$STATE/chain-$version-$kind" ] || continue
        "$tool" -t "$table" -F "$name"; "$tool" -t "$table" -X "$name"
    done
done
touch "$STATE/cleaned"
rmdir /data/opt/lisa-lab/trial.lock
CLEANUP
cleanup() { sh "$STATE/cleanup.sh" "$STATE"; }
trap cleanup EXIT
trap 'exit 125' HUP INT TERM
nohup sh -c 'sleep 150; sh "$1/cleanup.sh" "$1"' watchdog "$STATE" </dev/null >"$STATE/watchdog.log" 2>&1 &
for version in 4 6; do
    tool=iptables; [ "$version" = 4 ] || tool=ip6tables
    if "$tool" -S "$CHAIN" >/dev/null 2>&1 || "$tool" -S "$DENY" >/dev/null 2>&1 || "$tool" -t mangle -S "$MARK" >/dev/null 2>&1; then exit 3; fi
    touch "$STATE/chain-$version-group"; "$tool" -N "$CHAIN"
    touch "$STATE/chain-$version-mark"; "$tool" -t mangle -N "$MARK"
    touch "$STATE/chain-$version-deny"; "$tool" -N "$DENY"
    for gid in 57342 57343 57344 57345; do
        "$tool" -A "$CHAIN" -m owner --gid-owner "$gid" -j DROP
        "$tool" -t mangle -A "$MARK" -m owner --gid-owner "$gid" -m connmark --mark 0/0xff000000 -j CONNMARK --set-xmark 0x1000000/0xff000000
    done
    "$tool" -A "$DENY" -m connmark ! --mark 0/0xff000000 -j DROP
    "$tool" -t mangle -I OUTPUT 1 -j "$MARK"
    "$tool" -I OUTPUT 1 -j "$DENY"; "$tool" -I OUTPUT 1 -j "$CHAIN"
    "$tool" -I INPUT 1 -j "$DENY"
done
current=1
verify() { PROBE --verify-policy "$CHAIN" "$1" "$2"; }
set_mark() {
    verify "$current" closed >/dev/null
    current=$1; value=$(printf '0x%x' $((current*16777216)))
    for tool in iptables ip6tables; do
        position=1
        for gid in 57342 57343 57344 57345; do
            "$tool" -t mangle -R "$MARK" "$position" -m owner --gid-owner "$gid" -m connmark --mark 0/0xff000000 -j CONNMARK --set-xmark "$value/0xff000000"
            position=$((position+1))
        done
    done
    verify "$current" closed
}
open_epoch() {
    verify "$current" closed >/dev/null
    value=$(printf '0x%x' $((current*16777216)))
    for tool in iptables ip6tables; do
        # The existing closed DROP stays ahead until the full replacement exists.
        "$tool" -A "$DENY" -m connmark --mark 0/0xff000000 -j RETURN
        "$tool" -A "$DENY" -m connmark --mark "$value/0xff000000" -j RETURN
        "$tool" -A "$DENY" -j DROP
        "$tool" -D "$DENY" 1
        for gid in 57342 57343 57344 57345; do "$tool" -D "$CHAIN" -m owner --gid-owner "$gid" -j DROP; done
    done
    verify "$current" open
}
close_epoch() {
    verify "$current" open >/dev/null
    for tool in iptables ip6tables; do
        "$tool" -I "$DENY" 1 -m connmark ! --mark 0/0xff000000 -j DROP
        for gid in 57342 57343 57344 57345; do "$tool" -A "$CHAIN" -m owner --gid-owner "$gid" -j DROP; done
        "$tool" -D "$DENY" 2; "$tool" -D "$DENY" 2; "$tool" -D "$DENY" 2
    done
    verify "$current" closed
}
wait_event() {
    tries=0
    while ! grep -q '"phase":"'"$1"'"' "$stem.events"; do
        kill -0 "$child" || { cat "$stem.events"; exit 8; }
        [ "$tries" -lt 140 ] || { cat "$stem.events"; exit 8; }
        sleep .05; tries=$((tries+1))
    done
}
attributed() {
    phase=$1; epoch=$2; ready_phase=$3
    ready=$(grep '"phase":"'"$ready_phase"'"' "$stem.events")
    source=$(printf '%s\n' "$ready" | sed -n 's/.*"source_port":\([0-9][0-9]*\).*/\1/p')
    destination=$(printf '%s\n' "$ready" | sed -n 's/.*"destination_port":\([0-9][0-9]*\).*/\1/p')
    [ "$source" -gt 0 ] && [ "$source" -le 65535 ] && [ "$destination" -gt 0 ] && [ "$destination" -le 65535 ] && [ "$source" != "$destination" ]
    value=$((epoch*16777216))
    awk -v fam="$ct_family" -v p="$transport" -v s="sport=$source" -v d="dport=$destination" -v a="src=$address" -v b="dst=$address" -v m="mark=$value" '
        $1==fam && $3==p {seen_s=seen_d=seen_a=seen_b=seen_m=0; for(i=6;i<=NF;i++){seen_s+=($i==s);seen_d+=($i==d);seen_a+=($i==a);seen_b+=($i==b);seen_m+=($i==m)} if(seen_s&&seen_d&&seen_a&&seen_b&&seen_m)found++} END{exit found!=1}' /proc/net/nf_conntrack
    printf '{"event":"epoch-attributed","family":"%s","protocol":"%s","phase":"%s","epoch":%s,"mark":%s,"ok":true}\n' "$family_name" "$transport" "$phase" "$epoch" "$value"
}
sequence=0
for family in 4 6 mapped; do
    family_name=ipv4; ct_family=ipv4; address=127.0.0.1
    if [ "$family" = 6 ]; then family_name=ipv6; ct_family=ipv6; address=0000:0000:0000:0000:0000:0000:0000:0001; fi
    if [ "$family" = mapped ]; then family_name=ipv4-mapped-ipv6; fi
    for transport in tcp udp; do
        old=$((sequence+1)); new=$((sequence+2)); sequence=$new
        set_mark "$old"; open_epoch
        stem="$STATE/$family-$transport"; mkfifo "$stem.control"; exec 3<>"$stem.control"
        PROBE --own-epochs "$family" "$transport" "$old" "$new" <"$stem.control" >"$stem.events" 2>"$stem.error" &
        child=$!; ticks=$(awk '{print $22}' /proc/"$child"/stat); printf '%s %s\n' "$child" "$ticks" > "$STATE/child"
        wait_event old; attributed old "$old" old
        close_epoch; printf c >&3; wait_event closed
        set_mark "$new"; open_epoch; printf n >&3; wait_event new
        attributed retained "$old" old; attributed new "$new" new
        close_epoch; printf r >&3
        result=0; wait "$child" || result=$?; rm "$STATE/child"; exec 3>&-
        cat "$stem.events"; cat "$stem.error" >&2
        [ "$result" = 0 ] || exit "$result"
    done
done
cleanup
echo '{"event":"epoch-cleanup","ok":true}'
"""


def evaluate_events(events):
    if not isinstance(events, list) or len(events) != 145 or any(not isinstance(row, dict) for row in events):
        return False
    checks = [
        "baseline",
        "old_open_exchange",
        "old_closed",
        "unrelated_closed",
        "new_socket",
        "new_open_exchange",
        "old_still_denied",
        "unrelated_reopened",
        "new_closed",
        "old_remains_closed",
        "unrelated_final",
    ]
    for index, (family, protocol) in enumerate(
        (family, protocol) for family in ("ipv4", "ipv6", "ipv4-mapped-ipv6") for protocol in ("tcp", "udp")
    ):
        old = index * 2 + 1
        new = old + 1
        rows = events[index * 24 : (index + 1) * 24]
        policy = [row for row in rows if row.get("event") == "epoch-policy"]
        if len(policy) != 6:
            return False
        for row, (epoch, closed) in zip(
            policy,
            [(old, True), (old, False), (old, True), (new, True), (new, False), (new, True)],
            strict=True,
        ):
            if (
                row.get("epoch") != epoch
                or type(row.get("epoch")) is not int
                or row.get("closed") is not closed
                or row.get("ok") is not True
            ):
                return False
        attributed = [row for row in rows if row.get("event") == "epoch-attributed"]
        if len(attributed) != 3:
            return False
        for row, (phase, epoch) in zip(
            attributed, [("old", old), ("retained", old), ("new", new)], strict=True
        ):
            if (
                row
                != dict(
                    event="epoch-attributed",
                    family=family,
                    protocol=protocol,
                    phase=phase,
                    epoch=epoch,
                    mark=epoch << 24,
                    ok=True,
                )
                or type(row.get("epoch")) is not int
                or type(row.get("mark")) is not int
                or row.get("ok") is not True
            ):
                return False
        native = [row for row in rows if row.get("event") in {"epoch-check", "epoch-ready", "epoch-summary"}]
        if len(native) != 15 or any(
            row.get("family") != family
            or row.get("protocol") != protocol
            or type(row.get("old_epoch")) is not int
            or type(row.get("new_epoch")) is not int
            or row.get("old_epoch") != old
            or row.get("new_epoch") != new
            for row in native
        ):
            return False
        checked = [row for row in native if row["event"] == "epoch-check"]
        if [row.get("check") for row in checked] != checks or any(
            row.get("ok") is not True for row in checked
        ):
            return False
        ready = [row for row in native if row["event"] == "epoch-ready"]
        if [row.get("phase") for row in ready] != ["old", "closed", "new"]:
            return False
        for row in ready:
            ports = [row.get("source_port"), row.get("destination_port")]
            if any(type(port) is not int for port in ports) or (
                ports != [0, 0]
                if row["phase"] == "closed"
                else not all(0 < port < 65536 for port in ports) or ports[0] == ports[1]
            ):
                return False
        summary = native[-1]
        if (
            summary.get("event") != "epoch-summary"
            or type(summary.get("checks")) is not int
            or summary.get("checks") != 11
            or type(summary.get("failures")) is not int
            or summary["failures"] != 0
            or summary.get("audio_opened") is not False
            or summary.get("vendor_processes_changed") is not False
        ):
            return False
        expected_native = (
            ["epoch-check"] * 2
            + ["epoch-ready"]
            + ["epoch-check"] * 2
            + ["epoch-ready"]
            + ["epoch-check"] * 4
            + ["epoch-ready"]
            + ["epoch-check"] * 3
            + ["epoch-summary"]
        )
        expected = [
            "epoch-policy",
            "epoch-policy",
            "epoch-attributed",
            "epoch-policy",
            "epoch-policy",
            "epoch-policy",
            "epoch-attributed",
            "epoch-attributed",
            "epoch-policy",
        ] + expected_native
        if [row.get("event") for row in rows] != expected:
            return False
    return events[-1] == dict(event="epoch-cleanup", ok=True) and events[-1].get("ok") is True


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("host")
    parser.add_argument("--ssh-config", type=Path)
    parser.add_argument("--run-own-loopback-trial", action="store_true", required=True)
    args = parser.parse_args()
    if args.host.startswith("-"):
        parser.error("SSH alias required")
    root = Path(__file__).resolve().parents[1]
    ssh = ["ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=20"]
    if args.ssh_config:
        ssh += ["-F", str(args.ssh_config)]
    ssh += [args.host]

    def remote(command, **kwargs):
        return subprocess.run(ssh + [command], capture_output=True, timeout=220, **kwargs)

    binary = (root / "build/epoch-policy-probe.armhf").read_bytes()
    digest = hashlib.sha256(binary).hexdigest()
    target = "/data/opt/lisa-controller-lab/epoch-policy-probe-" + digest[:16]
    remote("umask 077; cat > " + target + ".new && chmod 700 " + target + ".new", input=binary, check=True)
    if remote("sha256sum " + target + ".new", check=True).stdout.decode().split()[0] != digest:
        raise RuntimeError("epoch helper digest mismatch")
    remote("mv " + target + ".new " + target, check=True)
    identity = "for p in $(pidof quasar_launcher2 maind alsa-audio-monitord hardvold chronyd unbound); do echo $p; awk '{print $22}' /proc/$p/stat; done; cat /proc/sys/kernel/random/boot_id; sha256sum /etc/init.d/rcS /etc/init.d/S99zdropbear /etc/chrony.conf /etc/unbound/unbound.conf /etc/resolv.conf"
    before = remote(identity, check=True).stdout
    rules = remote("iptables-save; ip6tables-save", check=True).stdout
    result = remote("sh -s", input=SCRIPT.replace("PROBE", target).encode())
    after = remote(identity, check=True).stdout
    after_rules = remote("iptables-save; ip6tables-save", check=True).stdout
    (root / "build/epoch-qualification.stdout.private.txt").write_bytes(result.stdout)
    events = [json.loads(line) for line in result.stdout.decode().splitlines()]
    report = dict(
        binary_sha256=digest,
        returncode=result.returncode,
        events=events,
        error=result.stderr.decode()[-3000:],
        protocol_qualified=result.returncode == 0 and evaluate_events(events),
        stock_identity_and_configs_preserved=before == after,
        firewall_restored=rules_only(rules) == rules_only(after_rules),
        production_mode_changed=False,
        audio_captured=False,
        isolation_verified=False,
    )
    (root / "build/epoch-qualification.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps({key: value for key, value in report.items() if key != "events"}, indent=2))
    if not all(
        report[key]
        for key in ("protocol_qualified", "stock_identity_and_configs_preserved", "firewall_restored")
    ):
        raise SystemExit("epoch trial incomplete; inspect private report and cleanup state")


if __name__ == "__main__":
    main()
