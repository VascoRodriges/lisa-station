"""Audio-free and network-denied private SDK diagnostics, not functional acceptance."""

import argparse
import hashlib
import json
import subprocess
from pathlib import Path

from controller.lab_artifact import canonical_lab_artifact
from controller.qualify_socket_close import rules_only

SCRIPT = r"""
set -eu
umask 077
test ! -e /bkupgrade/data/opt/lisa-station/state
test ! -e /run/lisa-station
mkdir /data/opt/lisa-lab/trial.lock
STATE=$(mktemp -d /data/opt/lisa-controller-lab/platform-sdk.XXXXXX)
STATE=$(readlink -f "$STATE")
printf '%s' "$STATE" > /data/opt/lisa-lab/trial.lock/platform-sdk.owner
cleanup() {
    [ ! -f "$STATE/cleaned" ] || return 0
    if [ -f "$STATE/native.driver" ]; then
        set -- $(cat "$STATE/native.driver"); pid=$1; ticks=$2
        if [ "$(awk '{print $22}' /proc/"$pid"/stat 2>/dev/null || true)" = "$ticks" ] && [ "$(readlink /proc/"$pid"/exe 2>/dev/null || true)" = PROBE ]; then
            kill -TERM "$pid" || true
            wait "$pid" 2>/dev/null || true
        fi
    fi
    tries=0
    until PROBE --cleanup "$STATE"; do
        [ "$tries" -lt 40 ] || return 9
        sleep .05; tries=$((tries+1))
    done
    [ "$(cat /data/opt/lisa-lab/trial.lock/platform-sdk.owner)" = "$STATE" ]
    touch "$STATE/cleaned"
    rm /data/opt/lisa-lab/trial.lock/platform-sdk.owner
    rmdir /data/opt/lisa-lab/trial.lock
}
trap cleanup EXIT
trap 'exit 125' HUP INT TERM
printf '%s %s %s\n' "$$" "$(awk '{print $22}' /proc/$$/stat)" "$(readlink /proc/$$/exe)" > "$STATE/driver"
nohup sh -c '
    state=$1; sleep 90
    [ ! -f "$state/cleaned" ] || exit 0
    set -- $(cat "$state/driver"); pid=$1; ticks=$2; executable=$3
    if [ "$(awk "{print \$22}" /proc/"$pid"/stat 2>/dev/null || true)" = "$ticks" ] && [ "$(readlink /proc/"$pid"/exe 2>/dev/null || true)" = "$executable" ]; then kill -KILL "$pid"; sleep 1; fi
    tries=0
    until PROBE --cleanup "$state"; do
        [ "$tries" -lt 40 ] || exit 9
        sleep .05; tries=$((tries+1))
    done
    [ "$(cat /data/opt/lisa-lab/trial.lock/platform-sdk.owner)" = "$state" ]
    touch "$state/cleaned"
    rm /data/opt/lisa-lab/trial.lock/platform-sdk.owner
    rmdir /data/opt/lisa-lab/trial.lock
' watchdog "$STATE" </dev/null >"$STATE/watchdog.log" 2>&1 &
PROBE --station-inspect "$STATE" & native=$!
printf '%s %s\n' "$native" "$(awk '{print $22}' /proc/"$native"/stat 2>/dev/null || true)" > "$STATE/native.driver"
result=0; wait "$native" || result=$?
printf '{"event":"platform-sdk-exit","code":%s}\n' "$result"
cleanup
echo '{"event":"platform-sdk-cleanup","ok":true}'
[ "$result" = 0 ]
"""


def evaluate_events(events):
    if not isinstance(events, list) or len(events) != 5 or any(type(row) is not dict for row in events):
        return False
    for index, row in enumerate(events[:3]):
        constants = dict(
            event="platform-sdk-diagnostic",
            role=["own-elf", "platform", "media"][index],
            boundary_ok=True,
            exec_verified=True,
            drained=True,
            synthetic_identity=True,
            audio_opened=False,
            functionality_verified=False,
            path_control=index == 0,
        )
        integers = {
            "syscalls",
            "errors",
            "denied",
            "socket_attempts",
            "open_attempts",
            "clone_attempts",
            "threads",
            "exit_code",
            "exit_signal",
            "private_objects_mask",
            "private_stderr_bytes",
            "lost_registers",
        }
        if set(row) != set(constants) | integers | {"bounded_stop", "private_stderr_truncated"}:
            return False
        if any(type(row[k]) is not type(v) or row[k] != v for k, v in constants.items()):
            return False
        if any(type(row[k]) is not int for k in integers) or (
            type(row["bounded_stop"]) is not bool or type(row["private_stderr_truncated"]) is not bool
        ):
            return False
        if not (
            1 <= row["syscalls"] <= 20000
            and 0 <= row["denied"] <= row["errors"] <= row["syscalls"] + 80
            and all(
                0 <= row[k] <= row["syscalls"] for k in ["socket_attempts", "open_attempts", "clone_attempts"]
            )
            and 0 <= row["threads"] <= 79
            and row["threads"] <= row["clone_attempts"]
            and -1 <= row["exit_code"] <= 255
            and 0 <= row["exit_signal"] <= 64
            and (row["exit_code"] == -1) == (row["exit_signal"] > 0)
            and 0 <= row["private_objects_mask"] < 64
            and 0 <= row["private_stderr_bytes"] <= 65536
            and 0 <= row["lost_registers"] <= 80
        ):
            return False
        if index == 0 and not (
            row["exit_code"] == -1
            and row["exit_signal"] == 6
            and row["private_objects_mask"] == 32
            and row["bounded_stop"] is False
            and row["socket_attempts"] >= 4
            and row["denied"] >= 5
            and row["threads"] == 9
        ):
            return False
        if index and row["private_objects_mask"] & 32:
            return False
    return (
        events[3] == dict(event="platform-sdk-exit", code=0)
        and type(events[3].get("code")) is int
        and events[4] == dict(event="platform-sdk-cleanup", ok=True)
        and events[4].get("ok") is True
    )


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("host")
    parser.add_argument("--ssh-config", type=Path)
    parser.add_argument("--run-audio-free-sdk-diagnostic", action="store_true", required=True)
    args = parser.parse_args()
    if args.host.startswith("-"):
        parser.error("SSH alias required")
    root = Path(__file__).resolve().parents[1]
    ssh = ["ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=20"]
    if args.ssh_config:
        ssh += ["-F", str(args.ssh_config)]
    ssh += [args.host]

    def remote(command, **kwargs):
        return subprocess.run(ssh + [command], capture_output=True, timeout=120, **kwargs)

    remote(
        "test ! -e /data/opt/lisa-lab/trial.lock && test ! -e /bkupgrade/data/opt/lisa-station/state && test ! -e /run/lisa-station",
        check=True,
    )
    data = (root / "build/platform-sdk-probe.armhf").read_bytes()
    digest = hashlib.sha256(data).hexdigest()
    target = "/data/opt/lisa-controller-lab/platform-sdk-probe-" + digest[:16]
    remote("umask 077; cat > " + target + ".new && chmod 700 " + target + ".new", input=data, check=True)
    if remote("sha256sum " + target + ".new", check=True).stdout.decode().split()[0] != digest:
        raise RuntimeError("platform SDK diagnostic digest mismatch")
    remote("mv " + target + ".new " + target, check=True)
    target = canonical_lab_artifact(remote, target)
    identity = "pidof quasar_launcher2 maind alsa-audio-monitord hardvold chronyd unbound; cat /proc/sys/kernel/random/boot_id; sha256sum /etc/init.d/rcS /etc/init.d/S99zdropbear /etc/chrony.conf /etc/unbound/unbound.conf /etc/resolv.conf /system/vendor/quasar/quasar.cfg"
    before = remote(identity, check=True).stdout
    firewall = remote("iptables-save; ip6tables-save", check=True).stdout
    result = remote("sh -s", input=SCRIPT.replace("PROBE", target).encode())
    after = remote(identity, check=True).stdout
    after_firewall = remote("iptables-save; ip6tables-save", check=True).stdout
    (root / "build/platform-sdk.stdout.private.txt").write_bytes(result.stdout)
    (root / ("build/platform-sdk-" + digest[:16] + ".stdout.private.txt")).write_bytes(result.stdout)
    events = [json.loads(line) for line in result.stdout.decode().splitlines()]
    report = dict(
        binary_sha256=digest,
        returncode=result.returncode,
        events=events,
        qualified=result.returncode == 0 and evaluate_events(events),
        stock_identity_and_configs_preserved=before == after,
        firewall_unchanged=rules_only(firewall) == rules_only(after_firewall),
        audio_captured=False,
        proprietary_process_executed=any(
            row.get("exec_verified") is True and row.get("role") in {"platform", "media"} for row in events
        ),
        real_identity_seed_read=False,
        production_mode_changed=False,
        functionality_verified=False,
        isolation_verified=False,
        error=result.stderr.decode()[-3000:],
    )
    (root / "build/platform-sdk-qualification.json").write_text(json.dumps(report, indent=2) + "\n")
    (root / ("build/platform-sdk-" + digest[:16] + ".private.json")).write_text(
        json.dumps(report, indent=2) + "\n"
    )
    print(json.dumps({k: v for k, v in report.items() if k != "events"}, indent=2))
    if not all(
        report[k] for k in ["qualified", "stock_identity_and_configs_preserved", "firewall_unchanged"]
    ):
        raise SystemExit("platform SDK diagnostic qualification incomplete; inspect private evidence")


if __name__ == "__main__":
    main()
