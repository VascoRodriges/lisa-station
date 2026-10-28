"""Bounded real ALSA-monitor jail/lifecycle trial with independent stock recovery."""

import argparse
import hashlib
import json
import subprocess
from pathlib import Path

from controller.qualify_socket_close import rules_only

RESTORATION_CHECK = r"""
set -eu
[ ! -e /data/opt/lisa-lab/trial.lock ]
count=0
for process in $(pidof alsa-audio-monitord || :); do
    state=$(awk '{print $3}' "/proc/$process/stat" 2>/dev/null) || continue
    case "$state" in ''|Z|X) continue;; esac
    count=$((count+1)); restored=$process
done
[ "$count" = 1 ]
[ "$(readlink "/proc/$restored/exe")" = /usr/bin/alsa-audio-monitord ]
[ "$(awk '/^Gid:/{print $2,$3,$4,$5}' "/proc/$restored/status")" = '0 0 0 0' ]
[ "$(awk '/^Seccomp:/{print $2}' "/proc/$restored/status")" = 0 ]
[ "$(readlink "/proc/$restored/ns/mnt")" = "$(readlink /proc/self/ns/mnt)" ]
for descriptor in /proc/$restored/fd/*; do
    target=$(readlink "$descriptor") || exit 9
    case "$target" in /bkupgrade/data/opt/lisa-controller-lab/*/restore.lock) exit 9;; esac
done
tries=0
while :; do
    owner=$(dbus-send --system --print-reply --reply-timeout=1000 --dest=org.freedesktop.DBus \
        /org/freedesktop/DBus org.freedesktop.DBus.GetConnectionUnixProcessID \
        string:org.yandex.AudioMonitor 2>/dev/null | awk '/uint32/ {print $2}')
    [ "$owner" != "$restored" ] || break
    [ "$tries" -lt 10 ] || exit 9
    sleep .2; tries=$((tries+1))
done
"""

SCRIPT = r"""
set -eu
umask 077
BASE=/data/opt/lisa-controller-lab
SERVICE=/etc/init.d/S47alsa-audio-monitor
live_diagnostics() {
    for process in $(pidof alsa-audio-monitord || :); do
        state=$(awk '{print $3}' "/proc/$process/stat" 2>/dev/null) || continue
        case "$state" in ''|Z|X) continue;; esac
        echo "$process"
    done
}
tagged() {
    for status in /proc/[0-9]*/status; do
        [ -r "$status" ] || continue
        path=${status%/status}
        state=$(awk '{print $3}' "$path/stat" 2>/dev/null) || continue
        case "$state" in ''|Z|X) continue;; esac
        if awk '/^Gid:|^Groups:/ {for(i=2;i<=NF;i++) if($i==57343) found=1} END {exit !found}' "$status"; then
            echo "${path#/proc/}"
        fi
    done
}
[ "$(id -u)" = 0 ]
command -v flock >/dev/null
[ -z "$(tagged)" ]
original=$(live_diagnostics)
case "$original" in ''|*' '*) exit 3;; esac
[ "$(readlink "/proc/$original/exe")" = /usr/bin/alsa-audio-monitord ]
CHAIN=LISACQ_$$
for tool in iptables ip6tables; do
    if "$tool" -S "$CHAIN" >/dev/null 2>&1; then exit 3; fi
done
mkdir /data/opt/lisa-lab/trial.lock
STATE=$(mktemp -d "$BASE/guardian-startup.XXXXXX")
CANON=$(readlink -f "$STATE")
mkdir "$STATE/state" "$STATE/run" "$STATE/diagnostics-root"
printf 'LISA_MODE_V1 1 alice\n' > "$STATE/state/mode.state"
printf 'LISA_VENDOR_PERMIT_V1 1 %s\n' "$(cat /proc/sys/kernel/random/boot_id)" > "$STATE/run/vendor.permit"
printf '%s\n' PROBE > "$STATE/helper"
printf '%s\n' "$CHAIN" > "$STATE/chain"
sha256sum /usr/bin/alsa-audio-monitord /etc/alsa-audio-diagnostics.conf \
    /etc/alsa-audio-diagnostics/devices/yandexmidi.json "$SERVICE" > "$STATE/config.sha256"
cat > "$STATE/restore.sh" <<'RESTORE'
#!/bin/sh
set -u
STATE=$1
exec 9>"$STATE/restore.lock"; flock -x 9
[ ! -f "$STATE/restored" ] || exit 0
helper=$(cat "$STATE/helper"); canonical=$(readlink -f "$STATE")
"$helper" --lab-request-paused "$canonical" >/dev/null 2>&1 || :
"$helper" --lab-stop-diagnostics "$canonical" >/dev/null 2>&1 || :
tries=0
while :; do
    active=0
    for status in /proc/[0-9]*/status; do
        [ -r "$status" ] || continue
        path=${status%/status}
        state=$(awk '{print $3}' "$path/stat" 2>/dev/null) || continue
        case "$state" in ''|Z|X) continue;; esac
        if awk '/^Gid:|^Groups:/ {for(i=2;i<=NF;i++) if($i==57343) found=1} END {exit !found}' "$status"; then active=1; fi
    done
    [ "$active" = 1 ] || break
    [ "$tries" -lt 100 ] || exit 9
    sleep .2; tries=$((tries+1))
done
chain=$(cat "$STATE/chain"); suffix=${chain#LISACQ_}
[ "$suffix" != "$chain" ] || exit 9
case "$suffix" in ''|*[!0-9]*) exit 9;; esac
for version in 4 6; do
    tool=iptables; [ "$version" = 4 ] || tool=ip6tables
    if [ -f "$STATE/hook-$version" ] && "$tool" -C OUTPUT -j "$chain" >/dev/null 2>&1; then
        "$tool" -D OUTPUT -j "$chain" || exit 9
    fi
    if [ -f "$STATE/chain-$version" ] && "$tool" -S "$chain" >/dev/null 2>&1; then
        "$tool" -F "$chain" || exit 9
        "$tool" -X "$chain" || exit 9
    fi
done
sha256sum -c "$STATE/config.sha256" >/dev/null || exit 9
if [ -f "$STATE/restore-stock" ]; then
    living=
    for process in $(pidof alsa-audio-monitord || :); do
        state=$(awk '{print $3}' "/proc/$process/stat" 2>/dev/null) || continue
        case "$state" in ''|Z|X) continue;; esac
        living="$living $process"
    done
    if [ -z "$living" ]; then sh /etc/init.d/S47alsa-audio-monitor start 9>&- >"$STATE/stock-start.out" 2>&1 || exit 9; fi
fi
touch "$STATE/restored"
rmdir /data/opt/lisa-lab/trial.lock || exit 9
RESTORE
restore() { sh "$STATE/restore.sh" "$STATE"; }
trap 'restore' EXIT
trap 'exit 125' HUP INT TERM
nohup sh -c 'sleep 55; sh "$1/restore.sh" "$1"' watchdog "$STATE" </dev/null >"$STATE/watchdog.log" 2>&1 &
# A live unmanaged monitor must not be duplicated.
code=0
PROBE --lab-start-diagnostics "$CANON" >"$STATE/unmanaged.json" || code=$?
[ "$code" != 0 ] && grep -q '"result":"busy"' "$STATE/unmanaged.json"
cat "$STATE/unmanaged.json"
# Its D-Bus name cannot be transferred by freezing it. Stop/restart only this
# diagnostic service through its stock script; core Alice workers stay running.
touch "$STATE/restore-stock"
sh "$SERVICE" stop >"$STATE/stock-stop.out" 2>&1
tries=0
while [ -n "$(live_diagnostics)" ]; do
    [ "$tries" -lt 40 ] || exit 8
    sleep .1; tries=$((tries+1))
done
PROBE --lab-start-diagnostics "$CANON"
code=0
PROBE --lab-start-diagnostics "$CANON" >"$STATE/duplicate.json" || code=$?
[ "$code" != 0 ] && grep -q '"result":"busy"' "$STATE/duplicate.json"
cat "$STATE/duplicate.json"
for sample in 1 2 3; do
    sleep 1
    PROBE --lab-inspect-diagnostics "$CANON" > "$STATE/inspect.json"
    cat "$STATE/inspect.json"
    child=$(sed -n 's/.*"child_pid":\([0-9][0-9]*\),.*/\1/p' "$STATE/inspect.json")
    owner=$(dbus-send --system --print-reply --reply-timeout=2000 --dest=org.freedesktop.DBus \
        /org/freedesktop/DBus org.freedesktop.DBus.GetConnectionUnixProcessID \
        string:org.yandex.AudioMonitor | awk '/uint32/ {print $2}')
    [ -n "$child" ] && [ "$owner" = "$child" ]
done
echo '{"event":"diagnostics-bus-owner","samples":3,"matches_child":true}'
printf '%s\n' "$CHAIN" > "$STATE/run/policy.chain"
touch "$STATE/chain-4"; iptables -N "$CHAIN"
iptables -A "$CHAIN" -m owner --gid-owner 57343 -j DROP
touch "$STATE/hook-4"; iptables -I OUTPUT 1 -j "$CHAIN"
code=0
PROBE --lab-check-diagnostics-policy "$CANON" >"$STATE/partial.json" || code=$?
[ "$code" != 0 ] && grep -q '"result":"failed"' "$STATE/partial.json"
cat "$STATE/partial.json"
touch "$STATE/chain-6"; ip6tables -N "$CHAIN"
ip6tables -A "$CHAIN" -m owner --gid-owner 57343 -j DROP
touch "$STATE/hook-6"; ip6tables -I OUTPUT 1 -j "$CHAIN"
PROBE --lab-check-diagnostics-policy "$CANON"
PROBE --lab-close-diagnostics "$CANON"
[ -z "$(tagged)" ]
echo '{"event":"diagnostics-stopped","actors_absent":true}'
tries=0
while ! PROBE --lab-reconcile-diagnostics "$CANON" >"$STATE/reconcile.json"; do
    [ "$tries" -lt 20 ] || exit 8
    sleep .05; tries=$((tries+1))
done
cat "$STATE/reconcile.json"
[ ! -e "$STATE/run/diagnostics.child" ] && [ ! -e "$STATE/run/vendor.permit" ]
printf 'LISA_MODE_V1 3 alice\n' > "$STATE/state/mode.state"
printf 'LISA_VENDOR_PERMIT_V1 3 %s\n' "$(cat /proc/sys/kernel/random/boot_id)" > "$STATE/run/vendor.permit"
code=0
PROBE --lab-start-diagnostics "$CANON" >"$STATE/denied.json" || code=$?
[ "$code" != 0 ] && grep -q '"result":"denied"' "$STATE/denied.json"
cat "$STATE/denied.json"
restore
tries=0
while [ "$(live_diagnostics | wc -w)" -ne 1 ]; do
    [ "$tries" -lt 30 ] || exit 9
    sleep .1; tries=$((tries+1))
done
restored=$(live_diagnostics)
[ "$(awk '/^Gid:/{print $2,$3,$4,$5}' "/proc/$restored/status")" = '0 0 0 0' ]
[ "$(awk '/^Seccomp:/{print $2}' "/proc/$restored/status")" = 0 ]
[ "$(readlink "/proc/$restored/ns/mnt")" = "$(readlink /proc/self/ns/mnt)" ]
[ -z "$(ls -A "$STATE/diagnostics-root")" ]
echo '{"event":"diagnostics-restored","stock_identity":true,"private_logs_discarded":true,"audio_opened":false}'
"""


def evaluate_events(events):
    if len(events) != 15:
        return False
    services = [row for row in events if row.get("event") == "station-service"]
    expected = [("start-diagnostics", "busy"), ("start-diagnostics", "ok"), ("start-diagnostics", "busy")]
    expected += [("inspect-diagnostics", "ok")] * 3
    expected += [
        ("check-diagnostics-policy", "failed"),
        ("check-diagnostics-policy", "ok"),
        ("close-diagnostics", "ok"),
        ("reconcile-diagnostics", "ok"),
        ("start-diagnostics", "denied"),
    ]
    if [(row.get("operation"), row.get("result")) for row in services] != expected:
        return False
    if not all(row.get("isolation_verified") is False for row in services):
        return False
    start = services[1]
    if start.get("child_pid", 0) < 2 or start.get("guardian_pid", 0) < 2 or start.get("revision") != 1:
        return False
    for row in [start, *services[3:6]]:
        if (
            row.get("diagnostics_jail_verified") is not True
            or row.get("child_pid") != start["child_pid"]
            or row.get("guardian_pid") != start["guardian_pid"]
            or row.get("revision") != 1
        ):
            return False
    closed = services[8]
    if closed.get("revision") != 2 or closed.get("transition_phase") != "complete":
        return False
    controls = [row for row in events if row.get("event") == "policy-controls"]
    stopped = [row for row in events if row.get("event") == "diagnostics-stopped"]
    restored = [row for row in events if row.get("event") == "diagnostics-restored"]
    bus = [row for row in events if row.get("event") == "diagnostics-bus-owner"]
    return (
        len(controls) == 1
        and controls[0].get("ipv4") is True
        and controls[0].get("ipv6") is True
        and len(stopped) == 1
        and stopped[0].get("actors_absent") is True
        and len(restored) == 1
        and restored[0].get("stock_identity") is True
        and restored[0].get("private_logs_discarded") is True
        and restored[0].get("audio_opened") is False
        and len(bus) == 1
        and bus[0].get("samples") == 3
        and bus[0].get("matches_child") is True
    )


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("host")
    parser.add_argument("--ssh-config", type=Path)
    parser.add_argument("--allow-temporary-diagnostics-restart", action="store_true", required=True)
    args = parser.parse_args()
    if args.host.startswith("-"):
        parser.error("host must be an SSH alias")
    root = Path(__file__).resolve().parents[1]
    binary = (root / "build/station-service.armhf").read_bytes()
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
        return subprocess.run(ssh + [command], capture_output=True, timeout=95, **kwargs)

    remote("test ! -d /bkupgrade/data/opt/lisa-station/state && test ! -d /run/lisa-station", check=True)
    identity = "pidof maind; pidof quasar_launcher2; cat /proc/sys/kernel/random/boot_id; sha256sum /usr/bin/alsa-audio-monitord /etc/alsa-audio-diagnostics.conf /etc/alsa-audio-diagnostics/devices/yandexmidi.json"
    before = remote(identity, check=True).stdout
    # This firmware omits the stat applet. Compare ls inode/type/owner/size only,
    # excluding mtime: the stock program ftruncates its existing shared object.
    shared_metadata = (
        "ls -lin /dev/shm/alsa-audio-monitor-v2 | "
        'awk \'$2=="-rw-r-----"&&$3==1&&$4==0&&$5==0&&$6==270408 '
        "{print $1,$2,$3,$4,$5,$6; found=1} END {exit !found}'"
    )
    shared_before = remote(shared_metadata, check=True).stdout
    firewall = remote("iptables-save; ip6tables-save", check=True).stdout
    (root / "build/diagnostics-firewall-before.txt").write_bytes(firewall)
    target = "/data/opt/lisa-controller-lab/station-service-" + digest[:16]
    remote("umask 077; cat > " + target + ".new && chmod 700 " + target + ".new", input=binary, check=True)
    if remote("sha256sum " + target + ".new", check=True).stdout.decode().split()[0] != digest:
        raise RuntimeError("uploaded helper digest mismatch")
    remote("mv " + target + ".new " + target, check=True)
    default = remote(target + " --start-diagnostics")
    denied = default.returncode != 0 and json.loads(default.stdout).get("result") == "denied"
    if not denied:
        raise SystemExit("uninstalled production diagnostics start did not deny")
    result = remote("sh -s", input=SCRIPT.replace("PROBE", target).encode())
    after = remote(identity, check=True).stdout
    shared_after = remote(shared_metadata, check=True).stdout
    firewall_after = remote("iptables-save; ip6tables-save", check=True).stdout
    restored = remote("sh -s", input=RESTORATION_CHECK.encode())
    events = [json.loads(line) for line in result.stdout.decode().splitlines()]
    report = dict(
        binary_sha256=digest,
        returncode=result.returncode,
        events=events,
        qualified=result.returncode == 0 and evaluate_events(events),
        core_alice_boot_and_config_unchanged=before == after,
        firewall_rules_restored=rules_only(firewall) == rules_only(firewall_after),
        stock_diagnostics_and_bus_restored=restored.returncode == 0,
        shared_object_metadata_unchanged=shared_before == shared_after,
        default_production_start_denied=denied,
        production_mode_changed=False,
        isolation_verified=False,
        audio_opened=False,
        error=result.stderr.decode(errors="replace")[-2000:],
    )
    (root / "build/diagnostics-qualification.json").write_text(
        json.dumps(report, indent=2) + "\n", encoding="utf-8"
    )
    print(json.dumps({key: value for key, value in report.items() if key != "events"}, indent=2))
    if not (
        report["qualified"]
        and report["core_alice_boot_and_config_unchanged"]
        and report["firewall_rules_restored"]
        and report["stock_diagnostics_and_bus_restored"]
        and report["shared_object_metadata_unchanged"]
    ):
        raise SystemExit("diagnostics qualification failed; inspect private report")


if __name__ == "__main__":
    main()
