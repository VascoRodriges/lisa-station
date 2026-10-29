"""Independent DNS must survive absent/corrupt/busy vendor state, without fallback."""

import argparse
import base64
import hashlib
import json
import secrets
import subprocess
from pathlib import Path

from controller.qualify_socket_close import rules_only
from controller.service_profiles import compile_profiles

SCRIPT = r"""
set -eu
umask 077
test ! -d /bkupgrade/data/opt/lisa-station/state
test ! -d /run/lisa-station
mkdir /data/opt/lisa-lab/trial.lock
STATE=$(mktemp -d /data/opt/lisa-controller-lab/boot-policy.XXXXXX)
CANON=$(readlink -f "$STATE")
cat > "$STATE/cleanup.sh" <<'CLEANUP'
#!/bin/sh
set -eu
STATE=$1
exec 9>"$STATE/cleanup.lock"; flock -x 9
[ ! -e "$STATE/cleaned" ] || exit 0
PROBE --lab-dns-stop "$(readlink -f "$STATE")" > "$STATE/stop-cleanup.json"
touch "$STATE/cleaned"
rmdir /data/opt/lisa-lab/trial.lock
CLEANUP
cleanup() { sh "$STATE/cleanup.sh" "$STATE"; }
trap cleanup EXIT
trap 'exit 125' HUP INT TERM
nohup sh -c 'sleep 45; sh "$1/cleanup.sh" "$1"' watchdog "$STATE" </dev/null >"$STATE/watchdog.log" 2>&1 &
printf '%s' PROFILE_TOKEN | base64 -d | sed "s|/bkupgrade/data/opt/lisa-controller-lab/boot-policy.TEMPLATE/network|$CANON/network|g" > "$STATE/dns.profile"
sequence=0
expect() {
    sequence=$((sequence+1)); operation=$1; expected=$2; result=0
    PROBE --$operation "$CANON" > "$STATE/event-$sequence.json" || result=$?
    cat "$STATE/event-$sequence.json"
    grep -q '"result":"'"$expected"'"' "$STATE/event-$sequence.json"
    if [ "$expected" = ok ]; then [ "$result" = 0 ]; else [ "$result" != 0 ]; fi
}
# No mode directory or policy namespace exists at first start.
expect lab-dns-start ok
cp "$STATE/run/dns.child" "$STATE/first.child"
mkdir "$STATE/state"
printf 'broken\n' > "$STATE/state/mode.state"
expect lab-dns-status ok
printf 'LISA_MODE_V1 1 paused\n' > "$STATE/state/mode.state"
(exec 8>"$STATE/state/mode.lock"; flock -x 8; touch "$STATE/mode-held"; sleep 2) &
locker=$!
tries=0
while [ ! -e "$STATE/mode-held" ]; do [ "$tries" -lt 30 ]; sleep .05; tries=$((tries+1)); done
expect lab-dns-status ok
wait "$locker"
printf 'invalid policy namespace\n' > "$STATE/run/policy.chain"
expect lab-dns-status ok
expect lab-policy-status denied
expect lab-dns-start ok
cmp "$STATE/run/dns.child" "$STATE/first.child"
QUERY --dns-query DNS_PORT
[ ! -e "$STATE/run/vendor.permit" ]
expect lab-dns-stop ok
cleanup
echo '{"event":"auxiliary-cleanup","stock_services_changed":false,"firewall_changed":false}'
"""


def evaluate_events(events):
    if not isinstance(events, list) or len(events) != 13 or any(not isinstance(row, dict) for row in events):
        return False
    ops = [
        "lab-dns-start",
        "lab-dns-status",
        "lab-dns-status",
        "lab-dns-status",
        "lab-policy-status",
        "lab-dns-start",
        "lab-dns-stop",
    ]
    rows = [row for row in events if row.get("event") == "station-boot"]
    if len(rows) != 7:
        return False
    for index, row in enumerate(rows):
        ok = index != 4
        if (
            row.get("operation") != ops[index]
            or row.get("result") != ("ok" if ok else "denied")
            or row.get("requested_mode") != ("unknown" if index < 2 else "paused")
            or row.get("dns_operation_ok") is not (True if ok else None)
            or row.get("lab_policy_only") is not True
            or any(
                row.get(key) is not False
                for key in (
                    "namespace_owned",
                    "policy_ready",
                    "vendor_started",
                    "stock_fallback",
                    "isolation_verified",
                )
            )
            or type(row.get("elapsed_ms")) is not int
            or not 0 <= row["elapsed_ms"] < 7000
        ):
            return False
    expected = (
        ["station-boot"] * 6 + ["profile-child"] + ["dns-query"] * 4 + ["station-boot", "auxiliary-cleanup"]
    )
    if [row.get("event") for row in events] != expected:
        return False
    if events[6] != dict(
        event="profile-child",
        uid=65534,
        gid=65534,
        capabilities_zero=True,
        no_new_privs=True,
        clock_writes_denied=True,
    ):
        return False
    if any(
        events[6].get(key) is not True for key in ("capabilities_zero", "no_new_privs", "clock_writes_denied")
    ):
        return False
    if {(row.get("family"), row.get("transport")) for row in events[7:11]} != {
        (4, "udp"),
        (4, "tcp"),
        (6, "udp"),
        (6, "tcp"),
    } or any(row.get("ok") is not True for row in events[7:11]):
        return False
    return events[-1] == dict(
        event="auxiliary-cleanup", stock_services_changed=False, firewall_changed=False
    ) and all(events[-1].get(key) is False for key in ("stock_services_changed", "firewall_changed"))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("host")
    parser.add_argument("--ssh-config", type=Path)
    parser.add_argument("--dns-server", action="append", required=True)
    parser.add_argument("--run-independent-service-trial", action="store_true", required=True)
    args = parser.parse_args()
    if args.host.startswith("-"):
        parser.error("SSH alias required")
    port = 20000 + secrets.randbelow(20000)
    profile = compile_profiles(
        args.dns_server,
        ["198.51.100.1"],
        network_directory="/bkupgrade/data/opt/lisa-controller-lab/boot-policy.TEMPLATE/network",
        dns_port=port,
    ).dns
    root = Path(__file__).resolve().parents[1]
    ssh = ["ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=20"]
    if args.ssh_config:
        ssh += ["-F", str(args.ssh_config)]
    ssh += [args.host]

    def remote(command, **kwargs):
        return subprocess.run(ssh + [command], capture_output=True, timeout=70, **kwargs)

    targets = {}
    digests = {}
    for key, name in [("PROBE", "station-boot"), ("QUERY", "service-profile-probe")]:
        binary = (root / f"build/{name}.armhf").read_bytes()
        digest = hashlib.sha256(binary).hexdigest()
        target = "/data/opt/lisa-controller-lab/" + name + "-" + digest[:16]
        remote(
            "umask 077; cat > " + target + ".new && chmod 700 " + target + ".new", input=binary, check=True
        )
        if remote("sha256sum " + target + ".new", check=True).stdout.decode().split()[0] != digest:
            raise RuntimeError("auxiliary helper digest mismatch")
        remote("mv " + target + ".new " + target, check=True)
        targets[key] = target
        digests[name] = digest
    identity = "for p in $(pidof quasar_launcher2 maind alsa-audio-monitord hardvold chronyd unbound); do echo $p; awk '{print $22}' /proc/$p/stat; done; cat /proc/sys/kernel/random/boot_id; sha256sum /etc/init.d/rcS /etc/init.d/S99zdropbear /etc/chrony.conf /etc/unbound/unbound.conf /etc/resolv.conf"
    before = remote(identity, check=True).stdout
    rules = remote("iptables-save; ip6tables-save", check=True).stdout
    script = SCRIPT
    for key, value in targets.items():
        script = script.replace(key, value)
    script = script.replace("DNS_PORT", str(port)).replace(
        "PROFILE_TOKEN", base64.b64encode(profile.encode()).decode()
    )
    result = remote("sh -s", input=script.encode())
    after = remote(identity, check=True).stdout
    after_rules = remote("iptables-save; ip6tables-save", check=True).stdout
    events = [json.loads(line) for line in result.stdout.decode().splitlines()]
    report = dict(
        binary_sha256=digests,
        returncode=result.returncode,
        events=events,
        error=result.stderr.decode()[-2000:],
        protocol_qualified=result.returncode == 0 and evaluate_events(events),
        stock_identity_and_configs_preserved=before == after,
        firewall_unchanged=rules_only(rules) == rules_only(after_rules),
        production_mode_changed=False,
        audio_captured=False,
        isolation_verified=False,
    )
    (root / "build/auxiliary-qualification.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps({key: value for key, value in report.items() if key != "events"}, indent=2))
    if not all(
        report[key]
        for key in ("protocol_qualified", "stock_identity_and_configs_preserved", "firewall_unchanged")
    ):
        raise SystemExit("independent service trial incomplete; inspect private report")


if __name__ == "__main__":
    main()
