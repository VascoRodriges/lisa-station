"""Bounded per-child preload binding on own channels, not a real bus or SDK."""

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
test "$(id -u)" = 0
test "$(tr '\000' '\n' < /proc/device-tree/compatible | head -n 1)" = yandex,station-midi
test "$(awk '$2 == "/" {print $4}' /proc/mounts | cut -d, -f1)" = ro
test ! -e /bkupgrade/data/opt/lisa-station/state
test ! -e /run/lisa-station
mkdir /data/opt/lisa-lab/trial.lock
STATE=$(mktemp -d /data/opt/lisa-controller-lab/unix-factory.XXXXXX)
STATE=$(readlink -f "$STATE")
printf '%s' "$STATE" > /data/opt/lisa-lab/trial.lock/unix-factory.owner
# Only this digest's new own-ELF workers are inspected. No stock PID is killed.
remaining() {
    for entry in /proc/[0-9]*/exe; do
        [ "$(readlink "$entry" 2>/dev/null || true)" != PROBE ] || return 1
    done
}
cleanup() {
    [ ! -f "$STATE/cleaned" ] || return 0
    if [ -f "$STATE/native.driver" ]; then
        set -- $(cat "$STATE/native.driver"); pid=$1; ticks=$2
        if [ "$(awk '{print $22}' /proc/"$pid"/stat 2>/dev/null || true)" = "$ticks" ] && [ "$(readlink /proc/"$pid"/exe 2>/dev/null || true)" = PROBE ]; then
            kill -KILL "$pid" || true
            wait "$pid" 2>/dev/null || true
        fi
    fi
    tries=0
    until remaining; do
        [ "$tries" -lt 100 ] || return 9
        sleep .05; tries=$((tries+1))
    done
    [ "$(cat /data/opt/lisa-lab/trial.lock/unix-factory.owner)" = "$STATE" ]
    touch "$STATE/cleaned"
    rm /data/opt/lisa-lab/trial.lock/unix-factory.owner
    rmdir /data/opt/lisa-lab/trial.lock
}
trap cleanup EXIT
trap 'exit 125' HUP INT TERM
remaining
printf '%s %s %s\n' "$$" "$(awk '{print $22}' /proc/$$/stat)" "$(readlink /proc/$$/exe)" > "$STATE/driver"
nohup sh -c '
    state=$1; sleep 90
    [ ! -f "$state/cleaned" ] || exit 0
    set -- $(cat "$state/driver"); pid=$1; ticks=$2; executable=$3
    if [ "$(awk "{print \$22}" /proc/"$pid"/stat 2>/dev/null || true)" = "$ticks" ] && [ "$(readlink /proc/"$pid"/exe 2>/dev/null || true)" = "$executable" ]; then kill -KILL "$pid"; sleep 1; fi
    if [ -f "$state/native.driver" ]; then
        set -- $(cat "$state/native.driver"); pid=$1; ticks=$2
        if [ "$(awk "{print \$22}" /proc/"$pid"/stat 2>/dev/null || true)" = "$ticks" ] && [ "$(readlink /proc/"$pid"/exe 2>/dev/null || true)" = PROBE ]; then kill -KILL "$pid"; sleep 1; fi
    fi
    for entry in /proc/[0-9]*/exe; do
        [ "$(readlink "$entry" 2>/dev/null || true)" != PROBE ] || exit 9
    done
    [ "$(cat /data/opt/lisa-lab/trial.lock/unix-factory.owner)" = "$state" ]
    touch "$state/cleaned"
    rm /data/opt/lisa-lab/trial.lock/unix-factory.owner
    rmdir /data/opt/lisa-lab/trial.lock
' watchdog "$STATE" </dev/null >"$STATE/watchdog.log" 2>&1 &
PROBE --factory-selftest FACTORY & native=$!
printf '%s %s\n' "$native" "$(awk '{print $22}' /proc/"$native"/stat 2>/dev/null || true)" > "$STATE/native.driver"
result=0; wait "$native" || result=$?
printf '{"event":"unix-factory-exit","code":%s}\n' "$result"
cleanup
echo '{"event":"unix-factory-cleanup","ok":true}'
[ "$result" = 0 ]
"""


def evaluate_events(events):
    if not isinstance(events, list) or len(events) != 10 or any(type(row) is not dict for row in events):
        return False
    for index, row in enumerate(events[:7]):
        expected = dict(
            event="unix-factory-case",
            case=index,
            actor_checks=69 if index == 0 else 12 if index == 6 else 0,
            failures=0,
            expected_rejection=1 <= index <= 5,
            exit_code=125 if 1 <= index <= 5 else 0,
            exit_signal=0,
            own_mock_only=True,
        )
        if row != expected or any(type(row.get(k)) is not type(v) for k, v in expected.items()):
            return False
    expected = dict(
        selftest="unix-factory",
        checks=44,
        actor_checks=81,
        cases=7,
        failures=0,
        ok=True,
        own_mock_only=True,
        audio_opened=False,
        isolation_verified=False,
    )
    if events[7] != expected or any(type(events[7].get(k)) is not type(v) for k, v in expected.items()):
        return False
    return (
        events[8] == dict(event="unix-factory-exit", code=0)
        and type(events[8].get("code")) is int
        and events[9] == dict(event="unix-factory-cleanup", ok=True)
        and events[9].get("ok") is True
    )


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("host")
    parser.add_argument("--ssh-config", type=Path)
    parser.add_argument("--run-own-factory-trial", action="store_true", required=True)
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
    artifacts = [
        ("unix-factory-probe", root / "build/unix-channel-probe.armhf"),
        ("unix-bus-factory", root / "build/unix-bus-factory.so"),
    ]
    resolved = []
    digests = []
    for name, path in artifacts:
        data = path.read_bytes()
        digest = hashlib.sha256(data).hexdigest()
        target = "/data/opt/lisa-controller-lab/" + name + "-" + digest[:16]
        remote("umask 077; cat > " + target + ".new && chmod 700 " + target + ".new", input=data, check=True)
        if remote("sha256sum " + target + ".new", check=True).stdout.decode().split()[0] != digest:
            raise RuntimeError("factory artifact digest mismatch")
        remote("mv " + target + ".new " + target, check=True)
        resolved.append(canonical_lab_artifact(remote, target))
        digests.append(digest)
    target, factory = resolved
    digest, library_digest = digests
    identity = "pidof quasar_launcher2 maind alsa-audio-monitord hardvold chronyd unbound; cat /proc/sys/kernel/random/boot_id; sha256sum /etc/init.d/rcS /etc/init.d/S99zdropbear /etc/chrony.conf /etc/unbound/unbound.conf /etc/resolv.conf"
    before = remote(identity, check=True).stdout
    firewall = remote("iptables-save; ip6tables-save", check=True).stdout
    result = remote("sh -s", input=SCRIPT.replace("PROBE", target).replace("FACTORY", factory).encode())
    after = remote(identity, check=True).stdout
    after_firewall = remote("iptables-save; ip6tables-save", check=True).stdout
    (root / "build/unix-factory.stdout.private.txt").write_bytes(result.stdout)
    events = [json.loads(line) for line in result.stdout.decode().splitlines()]
    report = dict(
        binary_sha256=digest,
        library_sha256=library_digest,
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
    (root / "build/unix-factory-qualification.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps({k: v for k, v in report.items() if k != "events"}, indent=2))
    if not all(
        report[k] for k in ["qualified", "stock_identity_and_configs_preserved", "firewall_unchanged"]
    ):
        raise SystemExit("UNIX factory qualification incomplete; inspect private evidence")


if __name__ == "__main__":
    main()
