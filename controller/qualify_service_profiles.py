"""Run separate DNS/NTP profile probes without replacing stock services."""

import argparse
import base64
import hashlib
import json
import secrets
import subprocess
from pathlib import Path

from controller.service_profiles import compile_profiles

SCRIPT = r"""
set -eu
umask 077
[ "$(id -u)" = 0 ]
tr '\000' '\n' < /proc/device-tree/compatible | grep -qx yandex,station-midi
BASE=/data/opt/lisa-controller-lab
mkdir "$BASE/service-profiles.lock"
STATE=$(mktemp -d "$BASE/service-profiles.XXXXXX")
DIR=$(mktemp -d /tmp/lisa-service-probe.XXXXXX)
printf '%s\n' "$DIR" > "$STATE/directory"
cat > "$STATE/cleanup.sh" <<'CLEANUP'
#!/bin/sh
set -u
STATE=$1
exec 9>"$STATE/cleanup.lock"
flock -x 9
[ ! -f "$STATE/cleaned" ] || exit 0
DIR=$(cat "$STATE/directory")
case "$DIR" in /tmp/lisa-service-probe.*) ;; *) exit 9;; esac
if [ -f "$STATE/pid" ] && [ -f "$STATE/ticks" ]; then
    pid=$(cat "$STATE/pid"); ticks=$(cat "$STATE/ticks")
    stat=$(cat "/proc/$pid/stat" 2>/dev/null || true)
    tail=${stat##*) }; set -- $tail
    if [ "$#" -ge 20 ]; then
        shift 19
        if [ "$1" = "$ticks" ]; then
            kill -TERM "$pid" 2>/dev/null || true
            tries=0
            while kill -0 "$pid" 2>/dev/null && [ "$tries" -lt 15 ]; do
                sleep .1; tries=$((tries+1))
            done
            stat=$(cat "/proc/$pid/stat" 2>/dev/null || true)
            tail=${stat##*) }; set -- $tail
            if [ "$#" -ge 20 ]; then
                shift 19; [ "$1" != "$ticks" ] || kill -KILL "$pid" 2>/dev/null || true
            fi
        fi
    fi
fi
rm -f "$DIR/unbound.conf" "$DIR/chrony.conf"
rmdir "$DIR" || exit 9
rmdir /data/opt/lisa-controller-lab/service-profiles.lock || exit 9
touch "$STATE/cleaned"
CLEANUP
cleanup() { sh "$STATE/cleanup.sh" "$STATE"; }
trap 'cleanup' EXIT
trap 'exit 125' HUP INT TERM
nohup sh -c 'sleep 45; sh "$1/cleanup.sh" "$1"' watchdog "$STATE" </dev/null >"$STATE/watchdog.log" 2>&1 &
printf '%s' DNS_BASE64 | base64 -d | sed "s|/tmp/lisa-service-probe.TEMPLATE|$DIR|g" > "$DIR/unbound.conf"
printf '%s' TIME_BASE64 | base64 -d | sed "s|/tmp/lisa-service-probe.TEMPLATE|$DIR|g" > "$DIR/chrony.conf"
chmod 600 "$DIR/unbound.conf" "$DIR/chrony.conf"
chown -R 65534:65534 "$DIR"
unbound-checkconf "$DIR/unbound.conf" > "$STATE/checkconf.log" 2>&1
printf '{"event":"profile-syntax","dns":true}\n'
PROBE --dns "$DIR/unbound.conf" >"$STATE/dns.log" 2>&1 &
pid=$!
printf '%s\n' "$pid" > "$STATE/pid"
stat=$(cat "/proc/$pid/stat"); tail=${stat##*) }; set -- $tail; shift 19
printf '%s\n' "$1" > "$STATE/ticks"
tries=0
while [ "$(readlink /proc/$pid/exe 2>/dev/null || true)" != /usr/sbin/unbound ]; do
    kill -0 "$pid" || { cat "$STATE/dns.log" >&2; exit 5; }
    [ "$tries" -lt 60 ] || { cat "$STATE/dns.log" >&2; exit 5; }
    sleep .05; tries=$((tries+1))
done
sleep .2
uid=$(awk '/^Uid:/ {print $3}' "/proc/$pid/status")
caps=$(awk '/^CapEff:/ {print $2}' "/proc/$pid/status")
seccomp=$(awk '/^Seccomp:/ {print $2}' "/proc/$pid/status")
[ "$uid" = 65534 ] && [ "$caps" = 0000000000000000 ] && [ "$seccomp" = 2 ]
printf '{"event":"dns-runtime","uid":65534,"capabilities_zero":true,"seccomp":2}\n'
result=0
PROBE --dns-query DNS_PORT > "$STATE/queries.log" 2>&1 || result=$?
cat "$STATE/queries.log"
if [ "$result" != 0 ]; then cat "$STATE/dns.log" >&2; exit "$result"; fi
result=0
PROBE --time "$DIR/chrony.conf" > "$STATE/time.log" 2>&1 || result=$?
grep '^{' "$STATE/time.log"
if [ "$result" != 0 ]; then cat "$STATE/time.log" >&2; exit "$result"; fi
grep -q 'System clock wrong by.*(ignored)' "$STATE/time.log"
printf '{"event":"time-query","ok":true,"clock_control":false}\n'
cleanup
[ -f "$STATE/cleaned" ]
printf '{"event":"profile-cleanup","ok":true}\n'
"""


def evaluate_events(events):
    queries = [row for row in events if row.get("event") == "dns-query"]
    children = [row for row in events if row.get("event") == "profile-child"]
    if (
        len(queries) != 4
        or {(row.get("family"), row.get("transport")) for row in queries}
        != {(4, "udp"), (4, "tcp"), (6, "udp"), (6, "tcp")}
        or not all(row.get("ok") is True for row in queries)
    ):
        return False
    if len(children) != 2 or not all(
        row.get("uid") == 65534
        and row.get("gid") == 65534
        and all(
            row.get(flag) is True for flag in ("capabilities_zero", "no_new_privs", "clock_writes_denied")
        )
        for row in children
    ):
        return False
    required = {
        "profile-syntax": {"dns": True},
        "dns-runtime": {"uid": 65534, "capabilities_zero": True, "seccomp": 2},
        "time-query": {"ok": True, "clock_control": False},
        "profile-cleanup": {"ok": True},
    }
    for kind, values in required.items():
        found = [row for row in events if row.get("event") == kind]
        if len(found) != 1 or any(
            type(found[0].get(key)) is not type(value) or found[0][key] != value
            for key, value in values.items()
        ):
            return False
    return len(events) == 10


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("host")
    parser.add_argument("--ssh-config", type=Path)
    parser.add_argument("--dns-server", action="append", required=True)
    parser.add_argument("--ntp-server", action="append", required=True)
    parser.add_argument("--run-parallel-service-probes", action="store_true", required=True)
    args = parser.parse_args()
    if args.host.startswith("-"):
        parser.error("host must be an SSH alias")
    port = 20000 + secrets.randbelow(20000)
    profiles = compile_profiles(
        args.dns_server, args.ntp_server, probe_directory="/tmp/lisa-service-probe.TEMPLATE", dns_port=port
    )
    root = Path(__file__).resolve().parents[1]
    binary = (root / "build/service-profile-probe.armhf").read_bytes()
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
        return subprocess.run(ssh + [command], capture_output=True, timeout=70, **kwargs)

    identity = "pidof maind; pidof quasar_launcher2; pidof unbound; pidof chronyd; cat /proc/sys/kernel/random/boot_id"
    configs = "sha256sum /etc/chrony.conf /etc/unbound/unbound.conf /etc/resolv.conf"
    before = remote(identity, check=True).stdout
    before_configs = remote(configs, check=True).stdout
    target = "/data/opt/lisa-controller-lab/service-profile-" + digest[:16]
    remote("umask 077; cat > " + target + ".new && chmod 700 " + target + ".new", input=binary, check=True)
    if remote("sha256sum " + target + ".new", check=True).stdout.decode().split()[0] != digest:
        raise RuntimeError("uploaded probe digest mismatch")
    remote("mv " + target + ".new " + target, check=True)
    script = (
        SCRIPT.replace("DNS_BASE64", base64.b64encode(profiles.dns.encode()).decode())
        .replace("TIME_BASE64", base64.b64encode(profiles.time.encode()).decode())
        .replace("DNS_PORT", str(port))
        .replace("PROBE", target)
    )
    result = remote("sh -s", input=script.encode())
    after = remote(identity, check=True).stdout
    after_configs = remote(configs, check=True).stdout
    events = [json.loads(line) for line in result.stdout.decode().splitlines()]
    report = dict(
        returncode=result.returncode,
        binary_sha256=digest,
        events=events,
        qualified=result.returncode == 0 and evaluate_events(events),
        stock_identity_unchanged=before == after,
        stock_configs_unchanged=before_configs == after_configs,
        clock_control=False,
        production_mode_changed=False,
        audio_opened=False,
        error=result.stderr.decode(errors="replace")[-2000:],
    )
    (root / "build/service-profile-qualification.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report, indent=2))
    if not (report["qualified"] and report["stock_identity_unchanged"] and report["stock_configs_unchanged"]):
        raise SystemExit("service profile qualification failed")


if __name__ == "__main__":
    main()
