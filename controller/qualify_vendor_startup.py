"""Explicit bounded stock-startup qualification with an independent rollback.

No audio stream is captured by this tool. Stock Alice may be temporarily
unavailable while its launcher is frozen and workers are restarted.
"""

import argparse
import hashlib
import json
import subprocess
import threading
from pathlib import Path

SCRIPT = r"""
set -eu
BASE=/data/opt/lisa-controller-lab
LAUNCHER=/system/vendor/quasar/quasar_launcher2
live_maind() {
    for worker in $(pidof maind || :); do
        [ -r "/proc/$worker/stat" ] || continue
        case "$(awk '{print $3}' "/proc/$worker/stat")" in Z|X) continue;; esac
        [ "$(readlink "/proc/$worker/exe")" = /system/vendor/quasar/maind ] || continue
        echo "$worker"
    done
}
[ "$(id -u)" = 0 ]
command -v flock >/dev/null
for status in /proc/[0-9]*/status; do
    [ -r "$status" ] || continue
    if awk '/^Gid:|^Groups:/ {for(i=2;i<=NF;i++) if($i==57342) found=1} END {exit !found}' "$status"; then
        echo qualification_group_in_use >&2; exit 3
    fi
done
mkdir /data/opt/lisa-lab/trial.lock || exit 4
STATE=$(mktemp -d "$BASE/vendor-startup.XXXXXX")
chmod 700 "$STATE"
pid=$(pidof quasar_launcher2)
case "$pid" in ''|*' '*) rmdir /data/opt/lisa-lab/trial.lock; exit 3;; esac
[ "$(readlink "/proc/$pid/exe")" = "$LAUNCHER" ]
[ "$(awk '{print $3}' "/proc/$pid/stat")" != T ]
echo "$pid" > "$STATE/original.pid"
awk '{print $22}' "/proc/$pid/stat" > "$STATE/original.start"
sha256sum /system/vendor/quasar/launch.json > "$STATE/launch.sha256"
cat > "$STATE/restore.sh" <<'RESTORE'
#!/bin/sh
set -u
STATE=$1
exec 9>"$STATE/restore.lock"; flock -x 9
[ ! -f "$STATE/restored" ] || exit 0
owned() {
    for status in /proc/[0-9]*/status; do
        [ -r "$status" ] || continue
        path=${status%/status}
        case "$(awk '{print $3}' "$path/stat" 2>/dev/null)" in Z|X) continue;; esac
        if awk '/^Gid:/ {if($2==57342 && $3==57342 && $4==57342 && $5==57342) yes=1} END {exit !yes}' "$status"; then
            echo "${path#/proc/}"
        fi
    done
}
for child in $(owned); do
    [ "$(readlink "/proc/$child/exe")" != /system/vendor/quasar/quasar_launcher2 ] || kill -STOP "$child" 2>/dev/null || :
done
for child in $(owned); do kill -TERM "$child" 2>/dev/null || :; done
sleep 2
for child in $(owned); do kill -KILL "$child" 2>/dev/null || :; done
if ! sha256sum -c "$STATE/launch.sha256" >/dev/null; then
    echo configuration_changed_do_not_resume >&2; exit 9
fi
pid=$(cat "$STATE/original.pid"); born=$(cat "$STATE/original.start")
if [ -r "/proc/$pid/stat" ] && [ "$(readlink "/proc/$pid/exe")" = /system/vendor/quasar/quasar_launcher2 ] &&
   [ "$(awk '{print $22}' "/proc/$pid/stat")" = "$born" ]; then
    kill -CONT "$pid" || exit 9
elif ! pidof quasar_launcher2 >/dev/null; then
    sh /system/vendor/quasar/run.sh >/dev/null 2>&1
else
    echo unexpected_launcher_do_not_resume >&2; exit 9
fi
touch "$STATE/restored"
rmdir /data/opt/lisa-lab/trial.lock || exit 9
RESTORE
restore() { sh "$STATE/restore.sh" "$STATE"; }
trap 'restore' EXIT
trap 'exit 125' HUP INT TERM
nohup sh -c 'sleep WATCHDOG_SECONDS; sh "$1/restore.sh" "$1"' watchdog "$STATE" </dev/null >"$STATE/watchdog.log" 2>&1 &
kill -STOP "$pid"
for worker in $(live_maind); do
    [ "$(readlink "/proc/$worker/exe")" = /system/vendor/quasar/maind ] || exit 5
    kill -TERM "$worker" || :
done
tries=0
while [ -n "$(live_maind)" ] && [ "$tries" -lt 15 ]; do sleep 1; tries=$((tries+1)); done
if [ -n "$(live_maind)" ]; then
    echo stock_did_not_stop_gracefully >&2; exit 6
fi
PROBE --quasar </dev/null >/dev/null 2>&1 &
guarded=$!
echo "$guarded" > "$STATE/guarded.pid"
if [ VOICE_READY = 1 ]; then
    tries=0
    while [ "$(live_maind | wc -w)" -ne 4 ] && [ "$tries" -lt 20 ]; do sleep .5; tries=$((tries+1)); done
    [ "$(live_maind | wc -w)" -eq 4 ] || exit 7
    echo '{"event":"guarded-ready-for-voice","capture_tool_used":false}'
fi
for sample in 1 2 3 4; do
    sleep OBSERVE_INTERVAL
    printf '{"event":"startup-sample","sample":%s,"workers":[' "$sample"
    separator=
    for worker in $(live_maind); do
        [ -r "/proc/$worker/status" ] || continue
        gid=$(awk '/^Gid:/{print $2}' "/proc/$worker/status")
        nnp=$(awk '/^NoNewPrivs:/{print $2}' "/proc/$worker/status")
        nnp=${nnp:-null}
        seccomp=$(awk '/^Seccomp:/{print $2}' "/proc/$worker/status")
        caps=$(awk '/^CapEff:/{print $2}' "/proc/$worker/status")
        gid=${gid:-0}; seccomp=${seccomp:-null}; caps=${caps:-0}
        printf '%s{"pid":%s,"gid":%s,"no_new_privs":%s,"seccomp":%s,"cap_eff":"%s"}' "$separator" "$worker" "$gid" "$nnp" "$seccomp" "$caps"
        separator=,
    done
    echo ']}'
done
restore
tries=0
while [ "$(live_maind | wc -w)" -ne 4 ] && [ "$tries" -lt 12 ]; do sleep 1; tries=$((tries+1)); done
[ -f "$STATE/restored" ] && [ "$(live_maind | wc -w)" -eq 4 ]
echo '{"event":"restored","workers":4,"boot_changed":false,"capture_tool_used":false}'
"""


def evaluate_samples(samples):
    """Allow one startup warm-up, then require three stable protected snapshots.

    This firmware omits NoNewPrivs from /proc. The native wrapper checks it
    before exec and it is inherited; an explicit zero is still a failure.
    """
    if len(samples) != 4:
        return False
    observed = samples[-3:]
    forbidden_caps = (1 << 12) | (1 << 13) | (1 << 19)
    try:
        valid = all(
            len(row["workers"]) == 4
            and all(
                worker["gid"] == 57342
                and worker["no_new_privs"] in (None, 1)
                and worker["seccomp"] == 2
                and not int(worker["cap_eff"], 16) & forbidden_caps
                for worker in row["workers"]
            )
            for row in observed
        )
        stable = [{worker["pid"] for worker in row["workers"]} for row in observed]
        return valid and len(stable[0]) == 4 and stable[0] == stable[1] == stable[2]
    except (KeyError, TypeError, ValueError):
        return False


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("host")
    parser.add_argument("--ssh-config", type=Path)
    parser.add_argument("--allow-temporary-stock-restart", action="store_true", required=True)
    parser.add_argument("--observe-seconds", type=int, choices=(12, 60), default=12)
    parser.add_argument(
        "--live-observation", action="store_true", help="Stream readiness and technical status only"
    )
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    binary = (root / "build/vendor-launch-probe.armhf").read_bytes()
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

    def remote(command, timeout=45, **kwargs):
        return subprocess.run(ssh + [command], capture_output=True, timeout=timeout, **kwargs)

    identity_command = "pidof quasar_launcher2; cat /proc/sys/kernel/random/boot_id; sha256sum /system/vendor/quasar/launch.json"
    before = remote(identity_command, check=True).stdout
    backup = remote("cat /system/vendor/quasar/launch.json", check=True).stdout
    (root / "build/vendor-startup-launch-backup.json").write_bytes(backup)
    target = "/data/opt/lisa-controller-lab/vendor-launch-" + digest[:16]
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
    script = (
        SCRIPT.replace("PROBE", target)
        .replace("WATCHDOG_SECONDS", str(args.observe_seconds + 50))
        .replace("OBSERVE_INTERVAL", str(args.observe_seconds // 4))
        .replace("VOICE_READY", "1" if args.live_observation else "0")
    ).encode()
    if args.live_observation:
        process = subprocess.Popen(
            ssh + ["sh -s"], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE
        )
        errors = []
        reader = threading.Thread(target=lambda: errors.append(process.stderr.read()), daemon=True)
        reader.start()
        deadline = threading.Timer(args.observe_seconds + 65, process.terminate)
        deadline.start()
        output = []
        try:
            process.stdin.write(script)
            process.stdin.close()
            for line in process.stdout:
                output.append(line)
                print(line.decode().strip(), flush=True)
            process.wait(timeout=5)
            reader.join(timeout=2)
            result = subprocess.CompletedProcess(
                process.args, process.returncode, b"".join(output), b"".join(errors)
            )
        finally:
            deadline.cancel()
            if process.poll() is None:
                process.terminate()
    else:
        result = remote("sh -s", timeout=args.observe_seconds + 60, input=script)
    events = [json.loads(line) for line in result.stdout.decode().splitlines()]
    after = remote(identity_command, check=True).stdout
    recovery = (
        remote(
            "for worker in $(pidof maind || :); do awk '/^Gid:/{print $2}' /proc/$worker/status; done; test -d /data/opt/lisa-lab/trial.lock && echo locked || echo free",
            check=True,
        )
        .stdout.decode()
        .splitlines()
    )
    samples = [row for row in events if row.get("event") == "startup-sample"]
    qualified = evaluate_samples(samples)
    restored = (
        before == after
        and recovery[-1:] == ["free"]
        and len(recovery) == 5
        and all(gid == "0" for gid in recovery[:-1])
    )
    report = {
        "binary_sha256": digest,
        "startup_qualified": qualified,
        "original_launcher_boot_and_config_restored": restored,
        "events": events,
        "trial_returncode": result.returncode,
        "observation_seconds": args.observe_seconds,
        "no_new_privs_exposed_in_proc": any(
            worker["no_new_privs"] is not None for row in samples for worker in row["workers"]
        ),
        "error": result.stderr.decode(errors="replace")[-1200:],
        "whole_device_isolation_proven": False,
        "voice_functionality_tested": False,
    }
    (root / "build/vendor-startup-qualification.json").write_text(
        json.dumps(report, indent=2) + "\n", encoding="utf-8"
    )
    print(json.dumps(report, indent=2))
    assert restored, "Inspect rollback before any further device changes"
    if not qualified:
        raise SystemExit(4)


if __name__ == "__main__":
    main()
