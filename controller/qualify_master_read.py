"""Standalone actual Master GET lab with OWN clients; no SDK, setters or PCM."""

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
STATE=$(mktemp -d /data/opt/lisa-controller-lab/master-read.XXXXXX)
STATE=$(readlink -f "$STATE")
printf '%s' "$STATE" > /data/opt/lisa-lab/trial.lock/master-read.owner
cat > "$STATE/cleanup.sh" <<'CLEANUP'
#!/bin/sh
set -eu
STATE=$1
exec 9>"$STATE/cleanup.lock"; flock -x 9
[ ! -f "$STATE/cleaned" ] || exit 0
stop_owned() {
    stamp=$1
    [ ! -L "$stamp" ] || return 9
    [ -f "$stamp" ] || return 0
    set -- $(cat "$stamp"); [ "$#" = 2 ] || return 9
    pid=$1; ticks=$2
    [ "$(awk '{print $22}' /proc/"$pid"/stat 2>/dev/null || true)" = "$ticks" ] || return 0
    [ "$(awk '{print $3}' /proc/"$pid"/stat)" != Z ] || return 0
    MONITOR --same-image "$pid" PROBE || return 9
    kill -KILL "$pid" || true
}
stop_owned "$STATE/native.driver"
for stamp in "$STATE"/root[0-9].child "$STATE"/root1[0-5].child; do stop_owned "$stamp"; done
remaining() {
    MONITOR --scope-absent PROBE
}
tries=0
until remaining; do [ "$tries" -lt 100 ] || exit 9; sleep .05; tries=$((tries+1)); done
[ "$(cat /data/opt/lisa-lab/trial.lock/master-read.owner)" = "$STATE" ]
for index in 0 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15; do
    [ ! -d "$STATE/root$index" ] || rmdir "$STATE/root$index"
    for suffix in child child.new; do
        file="$STATE/root$index.$suffix"
        [ ! -e "$file" ] || { [ -f "$file" ] && [ ! -L "$file" ] && rm "$file"; }
    done
done
touch "$STATE/cleaned"
rm /data/opt/lisa-lab/trial.lock/master-read.owner
rmdir /data/opt/lisa-lab/trial.lock
CLEANUP
cleanup() { sh "$STATE/cleanup.sh" "$STATE"; }
trap cleanup EXIT
trap 'exit 125' HUP INT TERM
printf '%s %s %s\n' "$$" "$(awk '{print $22}' /proc/$$/stat)" "$(readlink /proc/$$/exe)" > "$STATE/driver"
nohup sh -c '
    state=$1; sleep 90
    [ ! -f "$state/cleaned" ] || exit 0
    set -- $(cat "$state/driver"); pid=$1; ticks=$2; image=$3
    if [ "$(awk "{print \$22}" /proc/"$pid"/stat 2>/dev/null || true)" = "$ticks" ] && [ "$(readlink /proc/"$pid"/exe 2>/dev/null || true)" = "$image" ]; then kill -KILL "$pid"; sleep 1; fi
    sh "$state/cleanup.sh" "$state"
' watchdog "$STATE" </dev/null >"$STATE/watchdog.log" 2>&1 &
PROBE --run "$STATE" & native=$!
result=0; wait "$native" || result=$?
printf '{"event":"master-read-exit","code":%s}\n' "$result"
cleanup
echo '{"event":"master-read-cleanup","ok":true}'
[ "$result" = 0 ]
"""


def evaluate_events(events):
    if type(events) is not list or len(events) != 11 or any(type(row) is not dict for row in events):
        return False
    expected = []
    for case in range(8):
        expected.append(dict(event="master-read-epoch", case=case, ok=True, backend_checks=16 if case == 7 else 17,
                             client_checks=17, reads=1 if case == 7 else 2, ioctl_reads=3 if case == 7 else 6,
                             malformed_rejected=0 < case < 7, backend_killed=case == 7, client_closed=True,
                             backend_admitted=True, client_admitted=True, sources_closed=True, values_agree=True,
                             views_released=True, pcm_opened=False))
    expected.extend([
        dict(selftest="master-read-broker", checks=9, inspection_checks=28, failures=0, ok=True, own_client_only=True,
             unrelated_socket_creation=True, audio_opened=False, production_changed=False),
        dict(event="master-read-exit", code=0), dict(event="master-read-cleanup", ok=True),
    ])
    return all(set(row) == set(target) and all(type(row[k]) is type(v) and row[k] == v for k, v in target.items())
               for row, target in zip(events, expected, strict=True))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("host")
    parser.add_argument("--ssh-config", type=Path)
    parser.add_argument("--run-read-only-master-lab", action="store_true", required=True)
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

    remote("test ! -e /data/opt/lisa-lab/trial.lock && test ! -e /bkupgrade/data/opt/lisa-station/state && test ! -e /run/lisa-station", check=True)
    data = (root / "build/master-read-probe.armhf").read_bytes()
    digest = hashlib.sha256(data).hexdigest()
    target = "/data/opt/lisa-controller-lab/master-read-probe-" + digest[:16]
    remote("umask 077; cat > " + target + ".new && chmod 700 " + target + ".new", input=data, check=True)
    if remote("sha256sum " + target + ".new", check=True).stdout.decode().split()[0] != digest:
        raise RuntimeError("artifact digest mismatch")
    remote("mv " + target + ".new " + target, check=True)
    target = canonical_lab_artifact(remote, target)
    identity = "pidof dbus-daemon quasar_launcher2 maind alsa-audio-monitord hardvold chronyd unbound; cat /proc/sys/kernel/random/boot_id; sha256sum /etc/init.d/rcS /etc/init.d/S99zdropbear /etc/chrony.conf /etc/unbound/unbound.conf /etc/resolv.conf"
    before = remote(identity, check=True).stdout
    firewall = remote("iptables-save; ip6tables-save", check=True).stdout
    result = remote("sh -s", input=SCRIPT.replace("PROBE", target).replace("MONITOR", target).encode())
    after = remote(identity, check=True).stdout
    after_firewall = remote("iptables-save; ip6tables-save", check=True).stdout
    (root / "build/master-read.stdout.private.txt").write_bytes(result.stdout)
    (root / "build/master-read.stderr.private.txt").write_bytes(result.stderr)
    events = [json.loads(line) for line in result.stdout.decode().splitlines()]
    report = dict(binary_sha256=digest, returncode=result.returncode, events=events,
                  qualified=result.returncode == 0 and evaluate_events(events), stock_identity_and_configs_preserved=before == after,
                  firewall_unchanged=rules_only(firewall) == rules_only(after_firewall), audio_captured=False,
                  sdk_executed=False, production_changed=False, isolation_verified=False)
    (root / "build/master-read-qualification.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(report, indent=2))
    if not all(report[k] for k in ["qualified", "stock_identity_and_configs_preserved", "firewall_unchanged"]):
        raise SystemExit("Master read lab incomplete; inspect private evidence")


if __name__ == "__main__":
    main()
