"""Bounded collector clone trial; restore the same frozen stock processes.

Only the clone's ordinary IP egress is loopback-only during observation, then
fully denied before close. Local IPC remains an explicit dependency. No audio IO.
"""

import argparse
import hashlib
import json
import subprocess
from pathlib import Path

from controller.collector_profile import prepare_collector_profile
from controller.qualify_socket_close import rules_only

SCRIPT = r"""
set -eu
umask 077
role_processes() {
    for process in $(pidof maind || :); do
        state=$(awk '{print $3}' "/proc/$process/stat" 2>/dev/null) || continue
        case "$state" in ''|Z|X) continue;; esac
        if tr '\000' '\n' < "/proc/$process/cmdline" | grep -qx -- --fluent-bitd; then echo "$process"; fi
    done
}
tagged() {
    for status in /proc/[0-9]*/status; do
        [ -r "$status" ] || continue
        path=${status%/status}; state=$(awk '{print $3}' "$path/stat" 2>/dev/null) || continue
        case "$state" in ''|Z|X) continue;; esac
        if awk '/^Gid:|^Groups:/ {for(i=2;i<=NF;i++) if($i==57344) yes=1} END {exit !yes}' "$status"; then echo "${path#/proc/}"; fi
    done
}
[ "$(id -u)" = 0 ]
command -v flock >/dev/null
[ -z "$(tagged)" ]
original=$(role_processes); parent=$(pidof quasar_launcher2)
[ "$(echo "$original" | wc -w)" = 1 ] && [ "$(echo "$parent" | wc -w)" = 1 ]
[ "$(awk '{print $4}' "/proc/$original/stat")" = "$parent" ]
[ "$(awk '{print $3}' "/proc/$original/stat")" != T ]
[ "$(awk '{print $3}' "/proc/$parent/stat")" != T ]
awk '$2 ~ /:E000$/ {found=1} END {exit found}' /proc/net/tcp /proc/net/tcp6
CHAIN=LISACQ_$$
for tool in iptables ip6tables; do if "$tool" -S "$CHAIN" >/dev/null 2>&1; then exit 3; fi; done
mkdir /data/opt/lisa-lab/trial.lock
STATE=$(mktemp -d /data/opt/lisa-controller-lab/guardian-startup.XXXXXX)
CANON=$(readlink -f "$STATE")
mkdir "$STATE/state" "$STATE/run" "$STATE/collector-root"
cp PROFILE "$STATE/collector-profile.json"; chmod 600 "$STATE/collector-profile.json"
printf 'LISA_MODE_V1 1 alice\n' > "$STATE/state/mode.state"
printf 'LISA_VENDOR_PERMIT_V1 1 %s\n' "$(cat /proc/sys/kernel/random/boot_id)" > "$STATE/run/vendor.permit"
printf '%s\n' PROBE > "$STATE/helper"
printf '%s\n' "$CHAIN" > "$STATE/chain"
printf '%s %s\n' "$parent" "$(awk '{print $22}' "/proc/$parent/stat")" > "$STATE/parent"
printf '%s %s\n' "$original" "$(awk '{print $22}' "/proc/$original/stat")" > "$STATE/original"
sha256sum /system/vendor/quasar/quasar.cfg /system/vendor/quasar/launch.json > "$STATE/config.sha256"
cat > "$STATE/restore.sh" <<'RESTORE'
#!/bin/sh
set -u
STATE=$1
exec 9>"$STATE/restore.lock"; flock -x 9
[ ! -f "$STATE/restored" ] || exit 0
helper=$(cat "$STATE/helper"); canonical=$(readlink -f "$STATE")
"$helper" --lab-request-paused "$canonical" >/dev/null 2>&1 || :
"$helper" --lab-stop-collector "$canonical" >/dev/null 2>&1 || :
tries=0
while :; do
    active=0
    for status in /proc/[0-9]*/status; do
        [ -r "$status" ] || continue
        path=${status%/status}; state=$(awk '{print $3}' "$path/stat" 2>/dev/null) || continue
        case "$state" in ''|Z|X) continue;; esac
        if awk '/^Gid:|^Groups:/ {for(i=2;i<=NF;i++) if($i==57344) yes=1} END {exit !yes}' "$status"; then active=1; fi
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
    if [ -f "$STATE/hook-$version" ] && "$tool" -C OUTPUT -j "$chain" >/dev/null 2>&1; then "$tool" -D OUTPUT -j "$chain" || exit 9; fi
    if [ -f "$STATE/chain-$version" ] && "$tool" -S "$chain" >/dev/null 2>&1; then
        "$tool" -F "$chain" || exit 9; "$tool" -X "$chain" || exit 9
    fi
done
sha256sum -c "$STATE/config.sha256" >/dev/null || exit 9
if [ -f "$STATE/frozen" ]; then
    set -- $(cat "$STATE/original"); process=$1; ticks=$2
    [ "$(awk '{print $22}' "/proc/$process/stat")" = "$ticks" ] || exit 9
    [ "$(readlink "/proc/$process/exe")" = /system/vendor/quasar/maind ] || exit 9
    kill -CONT "$process" || exit 9
    set -- $(cat "$STATE/parent"); process=$1; ticks=$2
    [ "$(awk '{print $22}' "/proc/$process/stat")" = "$ticks" ] || exit 9
    [ "$(readlink "/proc/$process/exe")" = /system/vendor/quasar/quasar_launcher2 ] || exit 9
    kill -CONT "$process" || exit 9
fi
touch "$STATE/restored"; rmdir /data/opt/lisa-lab/trial.lock || exit 9
RESTORE
restore() { sh "$STATE/restore.sh" "$STATE"; }
trap 'restore' EXIT
trap 'exit 125' HUP INT TERM
nohup sh -c 'sleep 60; sh "$1/restore.sh" "$1"' watchdog "$STATE" </dev/null >"$STATE/watchdog.log" 2>&1 &
code=0
PROBE --lab-start-collector "$CANON" > "$STATE/unmanaged.json" || code=$?
[ "$code" != 0 ] && grep -q '"result":"busy"' "$STATE/unmanaged.json"
cat "$STATE/unmanaged.json"
touch "$STATE/frozen"
kill -STOP "$parent"; kill -STOP "$original"
for version in 4 6; do
    tool=iptables; network=127.0.0.0/8
    if [ "$version" = 6 ]; then tool=ip6tables; network=::1/128; fi
    touch "$STATE/chain-$version"; "$tool" -N "$CHAIN"
    "$tool" -A "$CHAIN" -m owner --gid-owner 57344 -d "$network" -j RETURN
    "$tool" -A "$CHAIN" -m owner --gid-owner 57344 -j DROP
    touch "$STATE/hook-$version"; "$tool" -I OUTPUT 1 -j "$CHAIN"
done
PROBE --lab-start-collector "$CANON"
code=0
PROBE --lab-start-collector "$CANON" > "$STATE/duplicate.json" || code=$?
[ "$code" != 0 ] && grep -q '"result":"busy"' "$STATE/duplicate.json"
cat "$STATE/duplicate.json"
tries=0
while ! PROBE --lab-inspect-collector "$CANON" > "$STATE/readiness.json"; do
    [ "$tries" -lt 15 ] || exit 8; sleep 1; tries=$((tries+1))
done
for sample in 1 2 3; do sleep 2; PROBE --lab-inspect-collector "$CANON"; done
printf '%s\n' "$CHAIN" > "$STATE/run/policy.chain"
iptables -D "$CHAIN" -m owner --gid-owner 57344 -d 127.0.0.0/8 -j RETURN
code=0
PROBE --lab-check-collector-policy "$CANON" > "$STATE/partial.json" || code=$?
[ "$code" != 0 ] && grep -q '"result":"failed"' "$STATE/partial.json"
cat "$STATE/partial.json"
ip6tables -D "$CHAIN" -m owner --gid-owner 57344 -d ::1/128 -j RETURN
PROBE --lab-check-collector-policy "$CANON"
PROBE --lab-close-collector "$CANON"
[ -z "$(tagged)" ]
echo '{"event":"collector-stopped","actors_absent":true}'
tries=0
while ! PROBE --lab-reconcile-collector "$CANON" > "$STATE/reconcile.json"; do
    [ "$tries" -lt 20 ] || exit 8; sleep .05; tries=$((tries+1))
done
cat "$STATE/reconcile.json"
printf 'LISA_MODE_V1 3 alice\n' > "$STATE/state/mode.state"
printf 'LISA_VENDOR_PERMIT_V1 3 %s\n' "$(cat /proc/sys/kernel/random/boot_id)" > "$STATE/run/vendor.permit"
code=0
PROBE --lab-start-collector "$CANON" > "$STATE/denied.json" || code=$?
[ "$code" != 0 ] && grep -q '"result":"denied"' "$STATE/denied.json"
cat "$STATE/denied.json"
restore
[ "$(role_processes)" = "$original" ]
[ "$(awk '{print $3}' "/proc/$original/stat")" != T ]
[ "$(awk '{print $3}' "/proc/$parent/stat")" != T ]
[ -z "$(ls -A "$STATE/collector-root")" ]
echo '{"event":"collector-restored","same_stock_process":true,"private_epoch_discarded":true,"audio_opened":false}'
"""


def evaluate_events(events):
    if len(events) != 14:
        return False
    services = [r for r in events if r.get("event") == "station-service"]
    expected = [("start-collector", "busy"), ("start-collector", "ok"), ("start-collector", "busy")]
    expected += [("inspect-collector", "ok")] * 3
    expected += [("check-collector-policy", "failed"), ("check-collector-policy", "ok")]
    expected += [("close-collector", "ok"), ("reconcile-collector", "ok"), ("start-collector", "denied")]
    if [(r.get("operation"), r.get("result")) for r in services] != expected:
        return False
    start = services[1]
    if start.get("child_pid", 0) < 2 or start.get("guardian_pid", 0) < 2:
        return False
    for row in [start, *services[3:6]]:
        if not (
            row.get("collector_jail_verified") is True
            and row.get("revision") == 1
            and row.get("child_pid") == start["child_pid"]
            and row.get("guardian_pid") == start["guardian_pid"]
        ):
            return False
    if not all(r.get("isolation_verified") is False for r in services):
        return False
    if services[8].get("revision") != 2 or services[8].get("transition_phase") != "complete":
        return False
    controls = [r for r in events if r.get("event") == "policy-controls"]
    stopped = [r for r in events if r.get("event") == "collector-stopped"]
    restored = [r for r in events if r.get("event") == "collector-restored"]
    return (
        len(controls) == 1
        and controls[0].get("ipv4") is True
        and controls[0].get("ipv6") is True
        and len(stopped) == 1
        and stopped[0].get("actors_absent") is True
        and len(restored) == 1
        and restored[0].get("same_stock_process") is True
        and restored[0].get("private_epoch_discarded") is True
        and restored[0].get("audio_opened") is False
    )


def run_trial(
    args,
    role,
    script,
    profile_factory,
    event_evaluator,
    boundary_evaluator=None,
    *,
    additional_profiles=None,
    report_name=None,
):
    if role not in {"collector", "telemetry"}:
        raise ValueError("unsupported epoch role")
    if args.host.startswith("-"):
        raise ValueError("host must be an SSH alias")
    root = Path(__file__).resolve().parents[1]
    ssh = ["ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=20", "-o", "ServerAliveInterval=8"]
    if args.ssh_config:
        ssh += ["-F", str(args.ssh_config)]
    ssh += [args.host]

    def remote(command, **kwargs):
        return subprocess.run(ssh + [command], capture_output=True, timeout=125, **kwargs)

    remote("test ! -d /bkupgrade/data/opt/lisa-station/state && test ! -d /run/lisa-station", check=True)
    identity = "pidof maind; pidof quasar_launcher2 alsa-audio-monitord; cat /proc/sys/kernel/random/boot_id; sha256sum /system/vendor/quasar/quasar.cfg /system/vendor/quasar/launch.json"
    before = remote(identity, check=True).stdout
    firewall = remote("iptables-save; ip6tables-save", check=True).stdout
    stock = json.loads(remote("cat /system/vendor/quasar/quasar.cfg", check=True).stdout)
    profile = json.dumps(profile_factory(stock, lab_clone=True), separators=(",", ":")).encode()
    binary = (root / "build/station-service.armhf").read_bytes()
    digest = hashlib.sha256(binary).hexdigest()
    profile_digest = hashlib.sha256(profile).hexdigest()
    target = "/data/opt/lisa-controller-lab/station-service-" + digest[:16]
    profile_target = "/data/opt/lisa-controller-lab/" + role + "-profile-" + profile_digest[:16]
    artifacts = [(target, binary, "700"), (profile_target, profile, "600")]
    if additional_profiles:
        if set(additional_profiles) != {"TELEMETRY"} or role != "collector" or report_name != "roles":
            raise ValueError("unsupported additional laboratory profile")
        for name, factory in additional_profiles.items():
            payload = json.dumps(factory(stock, lab_clone=True), separators=(",", ":")).encode()
            path = "/data/opt/lisa-controller-lab/extra-profile-" + hashlib.sha256(payload).hexdigest()[:16]
            artifacts.append((path, payload, "600"))
            script = script.replace("@" + name + "@", path)
    if report_name not in (None, "roles"):
        raise ValueError("unsupported qualification report")
    for path, payload, mode in artifacts:
        remote(
            "umask 077; cat > " + path + ".new && chmod " + mode + " " + path + ".new",
            input=payload,
            check=True,
        )
        if (
            remote("sha256sum " + path + ".new", check=True).stdout.decode().split()[0]
            != hashlib.sha256(payload).hexdigest()
        ):
            raise RuntimeError(role + " artifact digest mismatch")
        remote("mv " + path + ".new " + path, check=True)
    default = remote(target + " --start-" + role)
    denied = default.returncode != 0 and json.loads(default.stdout).get("result") == "denied"
    if not denied:
        raise RuntimeError("uninstalled " + role + " start did not deny")
    result = remote(
        "sh -s", input=script.replace("PROBE", target).replace("PROFILE", profile_target).encode()
    )
    after = remote(identity, check=True).stdout
    firewall_after = remote("iptables-save; ip6tables-save", check=True).stdout
    restored_check = (
        script.split('[ "$(id -u)" = 0 ]', 1)[0]
        + r"""
test ! -e /data/opt/lisa-lab/trial.lock
test -z "$(tagged)"
original=$(role_processes); parent=$(pidof quasar_launcher2)
[ "$(echo "$original" | wc -w)" = 1 ] && [ "$(echo "$parent" | wc -w)" = 1 ]
for process in "$original" "$parent"; do
    case "$(awk '{print $3}' "/proc/$process/stat")" in R|S) :;; *) exit 9;; esac
    [ "$(awk '/^Gid:/{print $2,$3,$4,$5}' "/proc/$process/status")" = '0 0 0 0' ]
    [ "$(awk '/^Seccomp:/{print $2}' "/proc/$process/status")" = 0 ]
done
"""
    )
    resumed = remote("sh -s", input=restored_check.encode()).returncode == 0
    events = [json.loads(line) for line in result.stdout.decode().splitlines()]
    report = dict(
        binary_sha256=digest,
        profile_sha256=profile_digest,
        returncode=result.returncode,
        events=events,
        qualified=result.returncode == 0 and event_evaluator(events),
        stock_process_boot_and_config_unchanged=before == after,
        firewall_rules_restored=rules_only(firewall) == rules_only(firewall_after),
        default_production_start_denied=denied,
        stock_processes_resumed=resumed,
        audio_opened=False,
        production_mode_changed=False,
        isolation_verified=False,
        error=result.stderr.decode(errors="replace")[-2000:],
    )
    if role == "telemetry":
        report["storage_boundary_qualified"] = result.returncode == 0 and bool(
            boundary_evaluator and boundary_evaluator(events)
        )
        report["batch_materialized"] = any(
            row.get("telemetry_batch_materialized") is True
            or (row.get("event") == "telemetry-epoch-closed" and row.get("batch_materialized") is True)
            for row in events
        )
    if report_name == "roles":
        report["closed_scope"] = "guarded_roles"
    (root / "build" / ((report_name or role) + "-qualification.json")).write_text(
        json.dumps(report, indent=2) + "\n", encoding="utf-8"
    )
    print(json.dumps({k: v for k, v in report.items() if k != "events"}, indent=2))
    if not (
        report["qualified"]
        and report["stock_process_boot_and_config_unchanged"]
        and report["firewall_rules_restored"]
        and report["stock_processes_resumed"]
    ):
        raise SystemExit(role + " qualification failed; inspect private report")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("host")
    parser.add_argument("--ssh-config", type=Path)
    parser.add_argument("--allow-temporary-collector-freeze", action="store_true", required=True)
    run_trial(parser.parse_args(), "collector", SCRIPT, prepare_collector_profile, evaluate_events)


if __name__ == "__main__":
    main()
