"""Audio-free private standard-bus diagnostic; no host-bus or SDK forwarding."""

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
STATE=$(mktemp -d /data/opt/lisa-controller-lab/private-bus.XXXXXX)
STATE=$(readlink -f "$STATE")
printf '%s' "$STATE" > /data/opt/lisa-lab/trial.lock/private-bus.owner
# Only this digest's new own-ELF workers are inspected. No stock PID is killed.
remaining() {
    for entry in /proc/[0-9]*/exe; do
        [ "$(readlink "$entry" 2>/dev/null || true)" != PROBE ] || return 1
    done
    for stamp in "$STATE"/root[012].child; do
        [ -f "$stamp" ] || continue
        set -- $(cat "$stamp"); pid=$1; ticks=$2
        if [ "$(awk '{print $22}' /proc/"$pid"/stat 2>/dev/null || true)" = "$ticks" ]; then
            [ "$(awk '{print $3}' /proc/"$pid"/stat)" = Z ] || return 1
        fi
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
    [ "$(cat /data/opt/lisa-lab/trial.lock/private-bus.owner)" = "$STATE" ]
    for epoch in 0 1 2; do
        [ ! -d "$STATE/root$epoch" ] || rmdir "$STATE/root$epoch"
        [ ! -f "$STATE/root$epoch.child" ] || rm "$STATE/root$epoch.child"
        [ ! -e "$STATE/listener$epoch" ] || { [ -S "$STATE/listener$epoch" ] && rm "$STATE/listener$epoch"; }
    done
    touch "$STATE/cleaned"
    rm /data/opt/lisa-lab/trial.lock/private-bus.owner
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
    for stamp in "$state"/root[012].child; do
        [ -f "$stamp" ] || continue
        set -- $(cat "$stamp"); pid=$1; ticks=$2
        if [ "$(awk "{print \$22}" /proc/"$pid"/stat 2>/dev/null || true)" = "$ticks" ]; then
            [ "$(awk "{print \$3}" /proc/"$pid"/stat)" = Z ] || exit 9
        fi
    done
    [ "$(cat /data/opt/lisa-lab/trial.lock/private-bus.owner)" = "$state" ]
    for epoch in 0 1 2; do
        [ ! -d "$state/root$epoch" ] || rmdir "$state/root$epoch"
        [ ! -f "$state/root$epoch.child" ] || rm "$state/root$epoch.child"
        [ ! -e "$state/listener$epoch" ] || { [ -S "$state/listener$epoch" ] && rm "$state/listener$epoch"; }
    done
    touch "$state/cleaned"
    rm /data/opt/lisa-lab/trial.lock/private-bus.owner
    rmdir /data/opt/lisa-lab/trial.lock
' watchdog "$STATE" </dev/null >"$STATE/watchdog.log" 2>&1 &
PROBE --run "$STATE" FACTORY & native=$!
printf '%s %s\n' "$native" "$(awk '{print $22}' /proc/"$native"/stat 2>/dev/null || true)" > "$STATE/native.driver"
result=0; wait "$native" || result=$?
printf '{"event":"private-bus-exit","code":%s}\n' "$result"
cleanup
echo '{"event":"private-bus-cleanup","ok":true}'
[ "$result" = 0 ]
"""


def evaluate_events(events):
    """Require the complete ordered boundary evidence, without claiming SDK readiness."""
    expected = [dict(event="private-bus-control", checks=15, failures=0)]
    expected += [
        dict(
            event="private-bus-epoch",
            epoch=i,
            checks=count,
            failures=0,
            actual_daemon=i > 0,
            fd_negotiation_disabled=False,
        )
        for i, count in enumerate([7, 28, 49])
    ]
    expected += [
        dict(
            selftest="private-bus",
            checks=50,
            failures=0,
            ok=True,
            sdk_executed=False,
            audio_opened=False,
            isolation_verified=False,
        ),
        dict(event="private-bus-parent", checks=5, failures=0, unrelated_internet_controls=True),
        dict(event="private-bus-exit", code=0),
        dict(event="private-bus-cleanup", ok=True),
    ]
    return (
        type(events) is list
        and len(events) == len(expected)
        and all(
            type(row) is dict
            and row == wanted
            and all(type(row.get(key)) is type(value) for key, value in wanted.items())
            for row, wanted in zip(events, expected, strict=True)
        )
    )


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("host")
    parser.add_argument("--ssh-config", type=Path)
    parser.add_argument("--run-private-bus-diagnostic", action="store_true", required=True)
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
    resolved = []
    digests = []
    for name, filename in [
        ("private-bus-probe", "private-bus-probe.armhf"),
        ("private-bus-factory", "private-bus-factory.so"),
    ]:
        data = (root / "build" / filename).read_bytes()
        digest = hashlib.sha256(data).hexdigest()
        target = "/data/opt/lisa-controller-lab/" + name + "-" + digest[:16]
        remote("umask 077; cat > " + target + ".new && chmod 700 " + target + ".new", input=data, check=True)
        if remote("sha256sum " + target + ".new", check=True).stdout.decode().split()[0] != digest:
            raise RuntimeError("artifact digest mismatch")
        remote("mv " + target + ".new " + target, check=True)
        resolved.append(canonical_lab_artifact(remote, target))
        digests.append(digest)
    target, binding = resolved
    digest, binding_digest = digests
    identity = "pidof dbus-daemon quasar_launcher2 maind alsa-audio-monitord hardvold chronyd unbound; cat /proc/sys/kernel/random/boot_id; sha256sum /etc/init.d/rcS /etc/init.d/S99zdropbear /etc/chrony.conf /etc/unbound/unbound.conf /etc/resolv.conf"
    before = remote(identity, check=True).stdout
    firewall = remote("iptables-save; ip6tables-save", check=True).stdout
    result = remote("sh -s", input=SCRIPT.replace("PROBE", target).replace("FACTORY", binding).encode())
    after = remote(identity, check=True).stdout
    after_firewall = remote("iptables-save; ip6tables-save", check=True).stdout
    (root / "build/private-bus.stdout.private.txt").write_bytes(result.stdout)
    (root / "build/private-bus.stderr.private.txt").write_bytes(result.stderr)
    events = [json.loads(line) for line in result.stdout.decode().splitlines()]
    report = dict(
        binary_sha256=digest,
        binding_sha256=binding_digest,
        returncode=result.returncode,
        events=events,
        qualified=result.returncode == 0 and evaluate_events(events),
        stock_identity_and_configs_preserved=before == after,
        firewall_unchanged=rules_only(firewall) == rules_only(after_firewall),
        audio_captured=False,
        sdk_executed=False,
        host_bus_forwarded=False,
        production_mode_changed=False,
        isolation_verified=False,
        error=result.stderr.decode()[-3000:],
    )
    (root / "build/private-bus-qualification.json").write_text(
        json.dumps(report, indent=2) + "\n", encoding="utf-8"
    )
    print(json.dumps(report, indent=2))
    if (
        not report["qualified"]
        or not report["stock_identity_and_configs_preserved"]
        or not report["firewall_unchanged"]
    ):
        raise SystemExit("Private-bus diagnostic incomplete; inspect private evidence")


if __name__ == "__main__":
    main()
