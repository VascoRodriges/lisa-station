"""Opt-in exact-flow quarantine test, confined to owned ephemeral loopback flows.

No vendor sockets are touched. An independent watchdog removes only this tool's
private chains/hooks. The tool verifies stock identity and firewall restoration.
"""

import argparse
import hashlib
import json
import subprocess
import time
from pathlib import Path

from controller.qualify_socket_close import rules_only

SCRIPT = r"""
set -eu
umask 077
BASE=/data/opt/lisa-controller-lab
CHAIN=LISAFQ_$$
[ "$(id -u)" = 0 ]
command -v flock >/dev/null
tr '\000' '\n' < /proc/device-tree/compatible | grep -qx yandex,station-midi
[ ! -d /data/opt/lisa-lab/trial.lock ]
[ ! -d "$BASE/owner-qualification.lock" ]
for tool in iptables ip6tables; do
    if "$tool" -S "$CHAIN" >/dev/null 2>&1; then exit 3; fi
done
mkdir "$BASE/flow-qualification.lock"
STATE=$(mktemp -d "$BASE/flow-qualification.XXXXXX")
printf '%s\n' "$CHAIN" > "$STATE/chain"
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
    for hook in INPUT OUTPUT; do
        if [ -f "$STATE/hook-$version-$hook" ] && "$tool" -C "$hook" -j "$CHAIN" >/dev/null 2>&1; then
            "$tool" -D "$hook" -j "$CHAIN" || ok=0
        fi
    done
    if [ -f "$STATE/chain-$version" ] && "$tool" -S "$CHAIN" >/dev/null 2>&1; then
        "$tool" -F "$CHAIN" || ok=0
        "$tool" -X "$CHAIN" || ok=0
    fi
    if "$tool" -S "$CHAIN" >/dev/null 2>&1; then ok=0; fi
done
if [ "$ok" = 1 ]; then
    rm -f "$STATE/cleanup.failed"
    touch "$STATE/cleaned"
    rmdir /data/opt/lisa-controller-lab/flow-qualification.lock || exit 9
else
    touch "$STATE/cleanup.failed"
    exit 9
fi
CLEANUP
cleanup() { sh "$STATE/cleanup.sh" "$STATE"; }
trap 'cleanup' EXIT
trap 'exit 125' HUP INT TERM
nohup sh -c 'sleep 60; sh "$1/cleanup.sh" "$1"' watchdog "$STATE" </dev/null >"$STATE/watchdog.log" 2>&1 &
wait_event() {
    tries=0
    while ! grep -q '"event":"'"$1"'"' "$stem.events"; do
        kill -0 "$child" || { cat "$stem.events"; exit 8; }
        [ "$tries" -lt 100 ] || { cat "$stem.events"; exit 8; }
        sleep .05; tries=$((tries+1))
    done
}
add_output_rules() {
    "$tool" -A "$CHAIN" -p "$transport" -s "$address" -d "$address" \
        --sport "$source" --dport "$destination" -m owner --socket-exists -j DROP
    "$tool" -A "$CHAIN" -p "$transport" -s "$address" -d "$address" \
        --sport "$source" --dport "$destination" -j DROP
    touch "$STATE/hook-$version-OUTPUT"
    "$tool" -I OUTPUT 1 -j "$CHAIN"
}
output_counters() {
    phase=$1
    counts=$("$tool" -n -v -x -L "$CHAIN" | awk '$3=="DROP" { print $1 }')
    set -- $counts
    [ "$#" = 2 ]
    printf '{"event":"flow-counters","family":"%s","protocol":"%s","phase":"%s","socket_associated":%s,"no_socket":%s}\n' \
        "$family_name" "$transport" "$phase" "$1" "$2"
}
for version in 4 6; do
    tool=iptables; [ "$version" = 4 ] || tool=ip6tables
    touch "$STATE/chain-$version"; "$tool" -N "$CHAIN"
done
for family in 4 6 mapped; do
    version=4; address=127.0.0.1; family_name=ipv4
    if [ "$family" = 6 ]; then version=6; address=::1; family_name=ipv6; fi
    if [ "$family" = mapped ]; then family_name=ipv4-mapped-ipv6; fi
    tool=iptables; [ "$version" = 4 ] || tool=ip6tables
    for transport in tcp udp; do
        stem="$STATE/$family-$transport"
        mkfifo "$stem.control"
        exec 3<>"$stem.control"
        : >"$stem.events"
        PROBE --own-loopback-flow "$family" "$transport" <"$stem.control" >"$stem.events" 2>"$stem.error" &
        child=$!
        wait_event flow-ready
        ready=$(grep '"event":"flow-ready"' "$stem.events")
        source=$(printf '%s\n' "$ready" | sed -n 's/.*"source_port":\([0-9][0-9]*\).*/\1/p')
        destination=$(printf '%s\n' "$ready" | sed -n 's/.*"destination_port":\([0-9][0-9]*\).*/\1/p')
        [ "$source" -gt 0 ] && [ "$source" -le 65535 ]
        [ "$destination" -gt 0 ] && [ "$destination" -le 65535 ] && [ "$source" != "$destination" ]
        if [ "$transport" = tcp ]; then
            add_output_rules
            printf d >&3; wait_event flow-destroyed; output_counters destroyed
            printf o >&3; wait_event flow-orphan-triggered; output_counters orphan
        else
            "$tool" -A "$CHAIN" -p udp -s "$address" -d "$address" \
                --sport "$source" --dport "$destination" -j DROP
            touch "$STATE/hook-$version-INPUT"; "$tool" -I INPUT 1 -j "$CHAIN"
            printf i >&3; wait_event flow-input-blocked
            count=$("$tool" -n -v -x -L "$CHAIN" | awk '$3=="DROP" { print $1 }')
            printf '{"event":"flow-input-counter","family":"%s","protocol":"udp","packets":%s}\n' "$family_name" "$count"
            "$tool" -D INPUT -j "$CHAIN"; rm "$STATE/hook-$version-INPUT"; "$tool" -F "$CHAIN"
            add_output_rules
            printf b >&3; wait_event flow-output-blocked; output_counters blocked
        fi
        "$tool" -D OUTPUT -j "$CHAIN"; rm "$STATE/hook-$version-OUTPUT"; "$tool" -F "$CHAIN"
        printf r >&3
        result=0; wait "$child" || result=$?
        exec 3>&-
        cat "$stem.events"
        cat "$stem.error" >&2
        [ "$result" = 0 ] || exit "$result"
    done
done
cleanup
[ -f "$STATE/cleaned" ] && [ ! -f "$STATE/cleanup.failed" ]
echo '{"event":"flow-cleanup","ok":true}'
"""


def evaluate_events(events):
    if len(events) != 91:
        return False
    for row in events:
        keys = (
            ("socket_associated", "no_socket")
            if row.get("event") == "flow-counters"
            else (("packets",) if row.get("event") == "flow-input-counter" else ())
        )
        if any(type(row.get(key)) is not int or row[key] < 0 for key in keys):
            return False
    families = {"ipv4", "ipv6", "ipv4-mapped-ipv6"}
    tcp = {
        "baseline",
        "own_inode_confirmed",
        "client_destroyed",
        "reset_quarantined",
        "control_after_destroy",
        "closed_tuple_absent",
        "stray_sent_to_closed_endpoint",
        "post_close_kernel_reply_quarantined",
        "control_after_stray",
        "reset_arrives_after_rule_removal",
        "control_after_restore",
    }
    udp = {
        "baseline",
        "input_quarantined",
        "control_after_input",
        "output_quarantined",
        "control_after_output",
        "target_after_restore",
        "control_after_restore",
    }
    expected = {
        (family, protocol, name)
        for family in families
        for protocol, names in (("tcp", tcp), ("udp", udp))
        for name in names
    }
    checks = [row for row in events if row.get("event") == "flow-check"]
    if (
        len(checks) != len(expected)
        or {(row.get("family"), row.get("protocol"), row.get("check")) for row in checks} != expected
        or not all(row.get("ok") is True for row in checks)
    ):
        return False
    for family in families:
        for protocol, names in (("tcp", tcp), ("udp", udp)):
            summaries = [
                row
                for row in events
                if row.get("event") == "flow-summary"
                and row.get("family") == family
                and row.get("protocol") == protocol
            ]
            if len(summaries) != 1 or not (
                summaries[0].get("checks") == len(names)
                and summaries[0].get("failures") == 0
                and summaries[0].get("microphone_opened") is False
                and summaries[0].get("vendor_processes_changed") is False
            ):
                return False
        counter_rows = [
            row
            for row in events
            if row.get("event") == "flow-counters"
            and row.get("family") == family
            and row.get("protocol") == "tcp"
        ]
        counters = {row.get("phase"): row for row in counter_rows}
        if len(counter_rows) != 2 or set(counters) != {"destroyed", "orphan"}:
            return False
        if counters["destroyed"].get("socket_associated", 0) + counters["destroyed"].get("no_socket", 0) <= 0:
            return False
        # IPv4 replies use the kernel's per-CPU TCP control socket; IPv6's
        # equivalent reply has no associated socket. Neither is the closed app.
        category = "no_socket" if family == "ipv6" else "socket_associated"
        if counters["orphan"][category] <= counters["destroyed"][category]:
            return False
        if any(
            counters["orphan"][key] < counters["destroyed"][key] for key in ("socket_associated", "no_socket")
        ):
            return False
        output = [
            row
            for row in events
            if row.get("event") == "flow-counters"
            and row.get("family") == family
            and row.get("protocol") == "udp"
        ]
        inputs = [
            row
            for row in events
            if row.get("event") == "flow-input-counter"
            and row.get("family") == family
            and row.get("protocol") == "udp"
        ]
        if (
            len(output) != 1
            or output[0].get("phase") != "blocked"
            or output[0].get("socket_associated", 0) <= 0
        ):
            return False
        if len(inputs) != 1 or inputs[0].get("packets", 0) <= 0:
            return False
    cleanups = [row for row in events if row.get("event") == "flow-cleanup"]
    return len(cleanups) == 1 and cleanups[0].get("ok") is True


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("host", help="Trusted SSH alias for an owned compatible speaker")
    parser.add_argument("--ssh-config", type=Path)
    parser.add_argument("--apply-temporary-exact-loopback-rules", action="store_true", required=True)
    parser.add_argument(
        "--exercise-watchdog",
        action="store_true",
        help="Also SIGKILL the test shell and verify independent rule cleanup",
    )
    args = parser.parse_args()
    if args.host.startswith("-"):
        parser.error("host must be an SSH alias")
    root = Path(__file__).resolve().parents[1]
    binary = (root / "build/flow-quarantine-probe.armhf").read_bytes()
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
        return subprocess.run(ssh + [command], capture_output=True, timeout=75, **kwargs)

    identity = "pidof maind; pidof quasar_launcher2; cat /proc/sys/kernel/random/boot_id"
    before = remote(identity, check=True).stdout
    firewall = remote("iptables-save; ip6tables-save", check=True).stdout
    (root / "build/flow-quarantine-firewall-before.txt").write_bytes(firewall)
    target = "/data/opt/lisa-controller-lab/flow-quarantine-" + digest[:16]
    remote(
        "umask 077; mkdir -p /data/opt/lisa-controller-lab; cat > "
        + target
        + ".new && chmod 700 "
        + target
        + ".new",
        input=binary,
        check=True,
    )
    if remote("sha256sum " + target + ".new", check=True).stdout.decode().split()[0] != digest:
        raise RuntimeError("uploaded probe digest mismatch")
    remote("mv " + target + ".new " + target, check=True)
    result = remote("sh -s", input=SCRIPT.replace("PROBE", target).encode())
    after = remote(identity, check=True).stdout
    firewall_after = remote("iptables-save; ip6tables-save", check=True).stdout
    events = [json.loads(line) for line in result.stdout.decode().splitlines()]
    report = dict(
        returncode=result.returncode,
        binary_sha256=digest,
        events=events,
        qualified=result.returncode == 0 and evaluate_events(events),
        stock_identity_unchanged=before == after,
        firewall_rules_restored=rules_only(firewall) == rules_only(firewall_after),
        whole_device_isolation_proven=False,
        error=result.stderr.decode(errors="replace")[-1500:],
    )
    if args.exercise_watchdog and report["qualified"] and report["firewall_rules_restored"]:
        # Only this fault trial uses the shorter watchdog. The shell is killed
        # immediately after its first exact-flow hook, before sending test data.
        fault_script = SCRIPT.replace("sleep 60;", "sleep 8;").replace(
            "            printf d >&3;",
            '            echo \'{"event":"watchdog-crash"}\'; kill -KILL $$\n            printf d >&3;',
        )
        fault = remote("sh -s", input=fault_script.replace("PROBE", target).encode())
        deadline = time.monotonic() + 18
        cleaned = False
        while time.monotonic() < deadline:
            state = remote("test ! -d /data/opt/lisa-controller-lab/flow-qualification.lock")
            if state.returncode == 0:
                cleaned = True
                break
            time.sleep(1)
        restored_firewall = remote("iptables-save; ip6tables-save", check=True).stdout
        restored_identity = remote(identity, check=True).stdout
        report["watchdog_crash_test"] = dict(
            crash_observed=b'{"event":"watchdog-crash"}' in fault.stdout and fault.returncode != 0,
            independent_cleanup=cleaned,
            stock_identity_unchanged=before == restored_identity,
            firewall_rules_restored=rules_only(firewall) == rules_only(restored_firewall),
        )
        report["qualified"] = report["qualified"] and all(report["watchdog_crash_test"].values())
    (root / "build/flow-quarantine-qualification.json").write_text(
        json.dumps(report, indent=2) + "\n",
        encoding="utf-8",
    )
    print(json.dumps({key: value for key, value in report.items() if key != "events"}, indent=2))
    print("native_checks", sum(row.get("event") == "flow-check" for row in events))
    if not (report["qualified"] and report["stock_identity_unchanged"] and report["firewall_rules_restored"]):
        raise SystemExit("flow quarantine qualification failed; inspect the local report")


if __name__ == "__main__":
    main()
