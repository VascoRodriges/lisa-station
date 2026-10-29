"""Own-ELF private storage epochs; no proprietary process or audio access."""

import argparse
import hashlib
import json
import subprocess
from pathlib import Path

from controller.qualify_socket_close import rules_only

SCRIPT = r"""
set -eu
umask 077
test ! -e /bkupgrade/data/opt/lisa-station/state
test ! -e /run/lisa-station
mkdir /data/opt/lisa-lab/trial.lock
STATE=$(mktemp -d /data/opt/lisa-controller-lab/platform-storage.XXXXXX)
STATE=$(readlink -f "$STATE")
printf '%s' "$STATE" > /data/opt/lisa-lab/trial.lock/platform-storage.owner
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
    [ "$(cat /data/opt/lisa-lab/trial.lock/platform-storage.owner)" = "$STATE" ]
    touch "$STATE/cleaned"
    rm /data/opt/lisa-lab/trial.lock/platform-storage.owner
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
    [ "$(cat /data/opt/lisa-lab/trial.lock/platform-storage.owner)" = "$state" ]
    touch "$state/cleaned"
    rm /data/opt/lisa-lab/trial.lock/platform-storage.owner
    rmdir /data/opt/lisa-lab/trial.lock
' watchdog "$STATE" </dev/null >"$STATE/watchdog.log" 2>&1 &
PROBE --station-selftest "$STATE" & native=$!
printf '%s %s\n' "$native" "$(awk '{print $22}' /proc/"$native"/stat 2>/dev/null || true)" > "$STATE/native.driver"
result=0; wait "$native" || result=$?
printf '{"event":"platform-storage-exit","code":%s}\n' "$result"
cleanup
echo '{"event":"platform-storage-cleanup","ok":true}'
[ "$result" = 0 ]
"""


def evaluate_events(events):
    if not isinstance(events, list) or len(events) != 6 or any(type(row) is not dict for row in events):
        return False
    first, a, b, summary, exited, cleanup = events
    if set(first) != {"selftest", "checks", "ok", "synthetic_only"} or not (
        first.get("selftest") == "platform-seeds"
        and type(first.get("checks")) is int
        and first["checks"] == 50
        and first.get("ok") is True
        and first.get("synthetic_only") is True
    ):
        return False
    for index, row in enumerate([a, b], 1):
        if set(row) != {"event", "epoch", "checks", "failures", "synthetic_only", "audio_opened"} or not (
            row.get("event") == "platform-storage-epoch"
            and type(row.get("epoch")) is int
            and row["epoch"] == index
            and type(row.get("checks")) is int
            and 50 <= row["checks"] <= 512
            and type(row.get("failures")) is int
            and row["failures"] == 0
            and row.get("synthetic_only") is True
            and row.get("audio_opened") is False
        ):
            return False
    if not a["checks"] < b["checks"]:
        return False
    if set(summary) != {
        "selftest",
        "checks",
        "ok",
        "synthetic_only",
        "audio_opened",
        "vendor_processes_changed",
        "isolation_verified",
    } or not (
        summary.get("selftest") == "platform-storage"
        and type(summary.get("checks")) is int
        and b["checks"] < summary["checks"] <= 512
        and summary.get("ok") is True
        and summary.get("synthetic_only") is True
        and all(
            summary.get(k) is False
            for k in ["audio_opened", "vendor_processes_changed", "isolation_verified"]
        )
    ):
        return False
    return (
        exited == dict(event="platform-storage-exit", code=0)
        and type(exited.get("code")) is int
        and cleanup == dict(event="platform-storage-cleanup", ok=True)
        and cleanup.get("ok") is True
    )


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("host")
    parser.add_argument("--ssh-config", type=Path)
    parser.add_argument("--run-synthetic-storage-trial", action="store_true", required=True)
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
    data = (root / "build/platform-storage-probe.armhf").read_bytes()
    digest = hashlib.sha256(data).hexdigest()
    target = "/data/opt/lisa-controller-lab/platform-storage-probe-" + digest[:16]
    remote("umask 077; cat > " + target + ".new && chmod 700 " + target + ".new", input=data, check=True)
    if remote("sha256sum " + target + ".new", check=True).stdout.decode().split()[0] != digest:
        raise RuntimeError("platform storage digest mismatch")
    remote("mv " + target + ".new " + target, check=True)
    identity = "pidof quasar_launcher2 maind alsa-audio-monitord hardvold chronyd unbound; cat /proc/sys/kernel/random/boot_id; sha256sum /etc/init.d/rcS /etc/init.d/S99zdropbear /etc/chrony.conf /etc/unbound/unbound.conf /etc/resolv.conf"
    before = remote(identity, check=True).stdout
    firewall = remote("iptables-save; ip6tables-save", check=True).stdout
    result = remote("sh -s", input=SCRIPT.replace("PROBE", target).encode())
    after = remote(identity, check=True).stdout
    after_firewall = remote("iptables-save; ip6tables-save", check=True).stdout
    (root / "build/platform-storage.stdout.private.txt").write_bytes(result.stdout)
    events = [json.loads(line) for line in result.stdout.decode().splitlines()]
    report = dict(
        binary_sha256=digest,
        returncode=result.returncode,
        events=events,
        qualified=result.returncode == 0 and evaluate_events(events),
        stock_identity_and_configs_preserved=before == after,
        firewall_unchanged=rules_only(firewall) == rules_only(after_firewall),
        audio_captured=False,
        proprietary_process_executed=False,
        real_identity_seed_read=False,
        production_mode_changed=False,
        isolation_verified=False,
        error=result.stderr.decode()[-3000:],
    )
    (root / "build/platform-storage-qualification.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps({k: v for k, v in report.items() if k != "events"}, indent=2))
    if not all(
        report[k] for k in ["qualified", "stock_identity_and_configs_preserved", "firewall_unchanged"]
    ):
        raise SystemExit("platform storage qualification incomplete; inspect private evidence")


if __name__ == "__main__":
    main()
