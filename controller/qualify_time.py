"""Single-clock-controller handoff with bounded local kernel-return evidence."""

import argparse
import base64
import hashlib
import json
import subprocess
from pathlib import Path

from controller.qualify_bootstrap import SCRIPT as POLICY_SCRIPT
from controller.qualify_bootstrap import evaluate_events as evaluate_policy
from controller.qualify_socket_close import rules_only
from controller.service_profiles import compile_profiles


def trial_script():
    anchors = (
        "for tool in iptables ip6tables; do\n    for rule",
        'cleanup\necho \'{"event":"boot-policy-cleanup"',
    )
    if any(POLICY_SCRIPT.count(marker) != 1 for marker in anchors):
        raise RuntimeError("bootstrap fixture changed; review clock handoff")
    script = POLICY_SCRIPT.replace(
        anchors[0],
        r"""if [ -f "$STATE/time-restore" ] && [ ! -f "$STATE/time-restored" ]; then
    canon=$(readlink -f "$STATE")
    PROBE --lab-time-stop "$canon" > "$STATE/time-stop-cleanup.json" || exit 9
    /etc/init.d/S49chrony start </dev/null > "$STATE/time-restore.log" 2>&1 9>&- || :
    tries=0
    while :; do
        set -- $(pidof chronyd)
        if [ "$#" = 1 ] && grep -q '^Seccomp:[[:space:]]*0$' "/proc/$1/status" &&
            grep -q '^CapEff:[[:space:]]*0000003fffffffff$' "/proc/$1/status"; then break; fi
        [ "$tries" -lt 30 ] || exit 9
        sleep .1; tries=$((tries+1))
    done
    sleep .3
    set -- $(pidof chronyd)
    [ "$#" = 1 ] || exit 9
    touch "$STATE/time-restored"
fi
if [ -f "$STATE/query-directory" ]; then
    q=$(cat "$STATE/query-directory")
    case "$q" in /tmp/lisa-service-probe.*) ;; *) exit 9;; esac
    rm -f "$q/chrony.conf" "$q/chronyd.pid"
    rmdir "$q" || exit 9
fi
for tool in iptables ip6tables; do
    for rule""",
    )
    return script.replace(
        anchors[1],
        r'''test -e /data/chrony_is_enabled
expect lab-time-start denied
printf '%s' CLOCK_PROFILE_TOKEN | base64 -d | sed "s|/bkupgrade/data/opt/lisa-controller-lab/boot-policy.TEMPLATE/network|$CANON/network|g" > "$STATE/time.profile"
cp PROOF_LIBRARY "$STATE/clock-proof.so"
[ "$(sha256sum "$STATE/clock-proof.so" | awk '{print $1}')" = PROOF_DIGEST ]
expect lab-time-start-proof denied
# Read-only source check before stopping the existing clock controller.
Q=$(mktemp -d /tmp/lisa-service-probe.XXXXXX)
printf '%s\n' "$Q" > "$STATE/query-directory"
printf '%s' READONLY_PROFILE_TOKEN | base64 -d | sed "s|/tmp/lisa-service-probe.TEMPLATE|$Q|g" > "$Q/chrony.conf"
chown -R 65534:65534 "$Q"
result=0
QUERY --time "$Q/chrony.conf" > "$STATE/query.log" 2>&1 || result=$?
grep '^{' "$STATE/query.log"
[ "$result" = 0 ]
awk '/System clock wrong by.*[(]ignored[)]/ {for(i=1;i<NF;i++)if($i=="by"){v=$(i+1);if(v ~ /^[+-]?[0-9]+([.][0-9]+)?$/ && v>=-0.1 && v<=0.1)ok=1}} END{exit !ok}' "$STATE/query.log"
echo '{"event":"time-preflight","clock_control":false,"offset_within_limit":true}'
set -- $(pidof chronyd)
[ "$#" = 1 ] && grep -q '^Seccomp:[[:space:]]*0$' "/proc/$1/status"
touch "$STATE/time-restore"
/etc/init.d/S49chrony stop > "$STATE/time-stop-stock.log" 2>&1
tries=0
while pidof chronyd >/dev/null; do
    [ "$tries" -lt 30 ] || exit 7
    sleep .1; tries=$((tries+1))
done
expect lab-time-start-proof ok
cp "$STATE/run/time.child" "$STATE/time-first.child"
expect lab-time-status ok
expect lab-time-start ok
cmp "$STATE/run/time.child" "$STATE/time-first.child"
tries=0
while ! grep -q 'Selected source ' "$STATE/network/time/chrony-proof.log" 2>/dev/null; do
    [ "$tries" -lt 180 ] || exit 7
    sleep .1; tries=$((tries+1))
done
expect lab-time-status ok
cat "$STATE/network/time/clock-calls.jsonl"
echo '{"event":"time-source","selected_source_observed":true}'
printf 'LISA_MODE_V1 4 alice\n' > "$STATE/state/mode.state"
expect lab-time-status ok
printf 'LISA_MODE_V1 5 lisa\n' > "$STATE/state/mode.state"
expect lab-time-status ok
cp "$STATE/time.profile" "$STATE/time.saved"
printf 'pool vendor.invalid\n' >> "$STATE/time.profile"
expect lab-time-start denied
mv "$STATE/time.saved" "$STATE/time.profile"
expect lab-time-status ok
[ ! -e "$STATE/run/vendor.permit" ]
expect lab-time-stop ok
cleanup
[ -f "$STATE/time-restored" ]
echo '{"event":"time-restored","stock_clock_running":true,"single_clock_controller":true}'
echo '{"event":"boot-policy-cleanup"''',
    )


def evaluate_events(events):
    if not isinstance(events, list) or any(not isinstance(row, dict) for row in events):
        return False
    clock = [row for row in events if str(row.get("operation", "")).startswith("lab-time-")]
    extra = {"profile-child", "time-preflight", "clock-call", "time-source", "time-restored"}
    other = [row for row in events if row not in clock and row.get("event") not in extra]
    if not evaluate_policy(other) or len(clock) != 11:
        return False
    operations = [
        "start",
        "start-proof",
        "start-proof",
        "status",
        "start",
        "status",
        "status",
        "status",
        "start",
        "status",
        "stop",
    ]
    modes = ["paused"] * 6 + ["alice"] + ["lisa"] * 4
    for i, row in enumerate(clock):
        ok = i not in {0, 1, 8}
        if (
            row.get("event") != "station-boot"
            or row.get("operation") != "lab-time-" + operations[i]
            or row.get("requested_mode") != modes[i]
            or row.get("result") != ("ok" if ok else "denied")
            or row.get("time_operation_ok") is not ok
            or row.get("lab_policy_only") is not True
            or row.get("namespace_owned") is not True
            or row.get("policy_ready") is not True
            or any(
                row.get(key) is not False
                for key in ("vendor_started", "stock_fallback", "isolation_verified")
            )
            or type(row.get("known_legacy_actors")) is not int
            or row["known_legacy_actors"] != other[15]["known_legacy_actors"]
            or type(row.get("tagged_actors")) is not int
            or row["tagged_actors"] != 0
            or type(row.get("elapsed_ms")) is not int
            or not 0 <= row["elapsed_ms"] < 7000
        ):
            return False
    calls = [row for row in events if row.get("event") == "clock-call"]
    if not 1 <= len(calls) <= 1024:
        return False
    for row in calls:
        if (
            set(row) != {"event", "api", "modes", "result", "errno"}
            or row.get("api") not in {"adjtimex", "settimeofday"}
            or any(type(row.get(key)) is not int for key in ("modes", "result", "errno"))
            or not 0 <= row["modes"] <= 0xFFFFFFFF
            or not -1 <= row["result"] <= 5
            or not 0 <= row["errno"] <= 4095
            or (row["result"] >= 0 and row["errno"] != 0)
        ):
            return False
    if not any(row["result"] >= 0 and row["modes"] for row in calls):
        return False
    adjusted = [row for row in calls if row["api"] == "adjtimex" and row["modes"] and row["result"] >= 0]
    # Linux TIME_ERROR=5 means unsynchronised. Initialisation writes can succeed
    # in that state; they alone do not qualify a synchronized NTP client.
    if not adjusted or adjusted[-1]["result"] not in {0, 1, 2, 3, 4}:
        return False
    kinds = [row.get("event") for row in events if row.get("event") != "clock-call"]
    expected = (
        ["station-boot"] * 18
        + ["profile-child", "time-preflight"]
        + ["station-boot"] * 4
        + ["time-source"]
        + ["station-boot"] * 5
        + ["time-restored", "boot-policy-cleanup"]
    )
    if kinds != expected:
        return False
    for name, expected in [
        (
            "profile-child",
            dict(
                event="profile-child",
                uid=65534,
                gid=65534,
                capabilities_zero=True,
                no_new_privs=True,
                clock_writes_denied=True,
            ),
        ),
        ("time-preflight", dict(event="time-preflight", clock_control=False, offset_within_limit=True)),
        ("time-source", dict(event="time-source", selected_source_observed=True)),
        (
            "time-restored",
            dict(event="time-restored", stock_clock_running=True, single_clock_controller=True),
        ),
    ]:
        rows = [row for row in events if row.get("event") == name]
        if rows != [expected] or any(
            rows[0].get(key) is not value for key, value in expected.items() if type(value) is bool
        ):
            return False
    return True


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("host")
    parser.add_argument("--ssh-config", type=Path)
    parser.add_argument("--ntp-server", action="append", required=True)
    parser.add_argument("--temporary-clock-handoff", action="store_true", required=True)
    args = parser.parse_args()
    if args.host.startswith("-"):
        parser.error("SSH alias required")
    clock_profile = compile_profiles(
        ["203.0.113.1"],
        args.ntp_server,
        network_directory="/bkupgrade/data/opt/lisa-controller-lab/boot-policy.TEMPLATE/network",
        lab_clock_control=True,
    ).time
    query_profile = compile_profiles(
        ["203.0.113.1"], args.ntp_server, probe_directory="/tmp/lisa-service-probe.TEMPLATE", dns_port=25053
    ).time
    root = Path(__file__).resolve().parents[1]
    ssh = ["ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=20"]
    if args.ssh_config:
        ssh += ["-F", str(args.ssh_config)]
    ssh += [args.host]

    def remote(command, **kwargs):
        return subprocess.run(ssh + [command], capture_output=True, timeout=110, **kwargs)

    targets = {}
    digests = {}
    for key, name, extension in [
        ("PROBE", "station-boot", "armhf"),
        ("QUERY", "service-profile-probe", "armhf"),
        ("PROOF_LIBRARY", "time-clock-proof", "so"),
    ]:
        binary = (root / f"build/{name}.{extension}").read_bytes()
        digest = hashlib.sha256(binary).hexdigest()
        target = (
            "/data/opt/lisa-controller-lab/" + name + "-" + digest[:16] + (".so" if extension == "so" else "")
        )
        remote(
            "umask 077; cat > " + target + ".new && chmod 700 " + target + ".new", input=binary, check=True
        )
        if remote("sha256sum " + target + ".new", check=True).stdout.decode().split()[0] != digest:
            raise RuntimeError("clock helper digest mismatch")
        remote("mv " + target + ".new " + target, check=True)
        targets[key] = target
        digests[name] = digest
    identity = "for p in $(pidof quasar_launcher2 maind alsa-audio-monitord hardvold unbound); do echo $p; awk '{print $22}' /proc/$p/stat; done; cat /proc/sys/kernel/random/boot_id; sha256sum /etc/init.d/rcS /etc/init.d/S99zdropbear /etc/chrony.conf /etc/init.d/S49chrony /data/chrony_is_enabled /system/vendor/quasar/launch.json"
    before = remote(identity, check=True).stdout
    rules = remote("iptables-save; ip6tables-save", check=True).stdout
    script = trial_script()
    for key in ("PROOF_LIBRARY", "PROBE", "QUERY"):
        script = script.replace(key, targets[key])
    script = script.replace("PROOF_DIGEST", digests["time-clock-proof"])
    script = script.replace("CLOCK_PROFILE_TOKEN", base64.b64encode(clock_profile.encode()).decode()).replace(
        "READONLY_PROFILE_TOKEN", base64.b64encode(query_profile.encode()).decode()
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
        other_identity_and_configs_preserved=before == after,
        firewall_rules_restored=rules_only(rules) == rules_only(after_rules),
        production_mode_changed=False,
        audio_captured=False,
        isolation_verified=False,
    )
    (root / "build/time-qualification.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps({key: value for key, value in report.items() if key != "events"}, indent=2))
    if not all(
        report[key]
        for key in ("protocol_qualified", "other_identity_and_configs_preserved", "firewall_rules_restored")
    ):
        raise SystemExit("clock handoff incomplete; inspect private report")


if __name__ == "__main__":
    main()
