"""Bounded closed-transition trial on own old loopback flows; stock Alice stays up."""

import argparse
import hashlib
import json
import re
import subprocess
import time
from pathlib import Path

from controller.qualify_socket_close import rules_only

SCRIPT = r"""
set -eu
umask 077
BASE=/data/opt/lisa-controller-lab
[ "$(id -u)" = 0 ]
command -v flock >/dev/null
tr '\000' '\n' < /proc/device-tree/compatible | grep -qx yandex,station-midi
[ ! -d "$BASE/flow-qualification.lock" ]
[ ! -d "$BASE/owner-qualification.lock" ]
CHAIN=LISAFT_$$
for tool in iptables ip6tables; do
    for suffix in I O; do
        if "$tool" -S "$CHAIN$suffix" >/dev/null 2>&1; then exit 3; fi
    done
done
mkdir /data/opt/lisa-lab/trial.lock
STATE=$(mktemp -d "$BASE/closed-flow.XXXXXX")
CANON=$(readlink -f "$STATE")
printf '%s\n' "$CHAIN" > "$STATE/chain"
cat > "$STATE/cleanup.sh" <<'CLEANUP'
#!/bin/sh
set -u
STATE=$1
exec 9>"$STATE/cleanup.lock"; flock -x 9
[ ! -f "$STATE/cleaned" ] || exit 0
base=$(cat "$STATE/chain"); suffix=${base#LISAFT_}
[ "$suffix" != "$base" ] || exit 9
case "$suffix" in ''|*[!0-9]*) exit 9;; esac
ok=1
for version in 4 6; do
    tool=iptables; [ "$version" = 4 ] || tool=ip6tables
    for hook in INPUT OUTPUT; do
        suffix=O; [ "$hook" = OUTPUT ] || suffix=I
        chain=$base$suffix
        if [ -f "$STATE/chain-$version-$suffix" ]; then
            while "$tool" -C "$hook" -j "$chain" >/dev/null 2>&1; do
                "$tool" -D "$hook" -j "$chain" || { ok=0; break; }
            done
            if "$tool" -S "$chain" >/dev/null 2>&1; then
                "$tool" -F "$chain" || ok=0
                "$tool" -X "$chain" || ok=0
            fi
        fi
        if "$tool" -S "$chain" >/dev/null 2>&1; then ok=0; fi
    done
done
[ "$ok" = 1 ] || exit 9
touch "$STATE/cleaned"
rmdir /data/opt/lisa-lab/trial.lock
CLEANUP
cleanup() { sh "$STATE/cleanup.sh" "$STATE"; }
trap 'cleanup' EXIT
trap 'exit 125' HUP INT TERM
nohup sh -c 'sleep 90; sh "$1/cleanup.sh" "$1"' watchdog "$STATE" </dev/null >"$STATE/watchdog.log" 2>&1 &
for version in 4 6; do
    tool=iptables; [ "$version" = 4 ] || tool=ip6tables
    for suffix in I O; do
        touch "$STATE/chain-$version-$suffix"
        "$tool" -N "$CHAIN$suffix"
    done
done
: >"$STATE/native.events"
: >"$STATE/native.error"
if [ FAULT = 1 ]; then
    PROBE --own-loopback-transition "$CANON" --pause-after-deny >"$STATE/native.events" 2>"$STATE/native.error" &
    child=$!
    tries=0
    while ! grep -q '"event":"closed-flow-denied-ready"' "$STATE/native.events"; do
        kill -0 "$child" || { cat "$STATE/native.events"; cat "$STATE/native.error" >&2; exit 8; }
        [ "$tries" -lt 160 ] || exit 8
        sleep .05; tries=$((tries+1))
    done
    printf '{"event":"closed-flow-watchdog-crash","fixture":"%s"}\n' "$CANON"
    kill -KILL $$
elif [ FAULT = 2 ]; then
    PROBE --own-loopback-transition "$CANON" --pause-after-stop >"$STATE/native.events" 2>"$STATE/native.error" &
    child=$!
    tries=0
    while ! grep -q '"event":"closed-flow-stopped-ready"' "$STATE/native.events"; do
        kill -0 "$child" || { cat "$STATE/native.events"; cat "$STATE/native.error" >&2; exit 8; }
        [ "$tries" -lt 160 ] || exit 8
        sleep .05; tries=$((tries+1))
    done
    kill -KILL "$child"
    wait "$child" 2>/dev/null || :
    iptables -D "${CHAIN}O" 1
    echo '{"event":"closed-flow-restart","coordinator_killed":true,"drop_removed":true}'
    result=0
    PROBE --resume-own-loopback-transition "$CANON" >"$STATE/resume.events" 2>"$STATE/resume.error" || result=$?
    cat "$STATE/resume.events"
    cat "$STATE/resume.error" >&2
    [ "$result" = 0 ] || exit "$result"
else
    result=0
    PROBE --own-loopback-transition "$CANON" >"$STATE/native.events" 2>"$STATE/native.error" || result=$?
    cat "$STATE/native.events"
    cat "$STATE/native.error" >&2
    [ "$result" = 0 ] || exit "$result"
fi
cleanup
echo '{"event":"closed-flow-cleanup","ok":true}'
"""

GLOBAL_CHECKS = (
    "private_fixture",
    "private_state_runtime",
    "open_state_runtime",
    "current_boot_read",
    "owned_chain_binding",
    "fixture_alice_intent",
    "fixture_permit",
    "evidence_persisted_before_close",
    "transaction_complete",
    "closed_fence_retained",
    "controls_survive_close",
    "repeat_reverifies_plan",
    "revision_not_incremented_twice",
    "missing_rule_detected",
    "resume_repairs_missing_drop",
    "unknown_rule_refuses_completion",
    "failure_keeps_closed",
    "explicit_fixture_repair_resumes",
    "controls_survive_repair",
    "evidence_survives_socket_destruction",
)


def expected_checks():
    result = {(name, 6) for name in GLOBAL_CHECKS}
    result |= {
        (name, index)
        for index in range(6)
        for name in ("baseline", "owned_snapshot", "control_after_close", "control_after_repair")
    }
    result |= {(name, index) for index in (1, 3, 5) for name in ("udp_output_denied", "udp_input_denied")}
    result |= {
        (name, index) for index in (0, 2, 4) for name in ("cookie_tcp_destroyed", "tcp_reset_quarantined")
    }
    return result


def evaluate_events(events):
    expected = expected_checks()
    checks = [row for row in events if row.get("event") == "closed-flow-check"]
    summaries = [row for row in events if row.get("event") == "closed-flow-summary"]
    cleanup = [row for row in events if row.get("event") == "closed-flow-cleanup"]
    if len(events) != len(expected) + 2 or len(checks) != len(expected):
        return False
    if {(row.get("check"), row.get("case")) for row in checks} != expected:
        return False
    if not all(row.get("ok") is True and type(row.get("case")) is int for row in checks):
        return False
    return (
        len(summaries) == 1
        and summaries[0].get("checks") == len(expected)
        and summaries[0].get("failures") == 0
        and summaries[0].get("ok") is True
        and summaries[0].get("audio_captured") is False
        and summaries[0].get("vendor_processes_changed") is False
        and summaries[0].get("isolation_verified") is False
        and len(cleanup) == 1
        and cleanup[0].get("ok") is True
    )


RESUME_CHECKS = (
    "resume_private_dirs",
    "resume_boot",
    "resume_saved_plan",
    "resume_stopped_fence",
    "resume_old_inodes_absent",
    "resume_transaction_complete",
    "resume_revision_unchanged",
    "resume_policy_verified",
)


def evaluate_resume_events(events):
    checks = [row for row in events if row.get("event") == "closed-flow-check"]
    summaries = [row for row in events if row.get("event") == "closed-flow-resume-summary"]
    restarts = [row for row in events if row.get("event") == "closed-flow-restart"]
    cleanup = [row for row in events if row.get("event") == "closed-flow-cleanup"]
    return (
        len(events) == 11
        and len(checks) == 8
        and {(row.get("check"), row.get("case")) for row in checks} == {(name, 6) for name in RESUME_CHECKS}
        and all(row.get("ok") is True and type(row.get("case")) is int for row in checks)
        and len(summaries) == 1
        and summaries[0].get("checks") == 8
        and summaries[0].get("failures") == 0
        and summaries[0].get("ok") is True
        and summaries[0].get("audio_captured") is False
        and summaries[0].get("vendor_processes_changed") is False
        and summaries[0].get("isolation_verified") is False
        and len(restarts) == 1
        and restarts[0].get("coordinator_killed") is True
        and restarts[0].get("drop_removed") is True
        and len(cleanup) == 1
        and cleanup[0].get("ok") is True
    )


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("host")
    parser.add_argument("--ssh-config", type=Path)
    parser.add_argument("--apply-temporary-exact-loopback-rules", action="store_true", required=True)
    parser.add_argument("--exercise-watchdog", action="store_true")
    parser.add_argument("--exercise-restart", action="store_true")
    args = parser.parse_args()
    if args.host.startswith("-"):
        parser.error("host must be an SSH alias")
    root = Path(__file__).resolve().parents[1]
    binary = (root / "build/closed-flow-probe.armhf").read_bytes()
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
        return subprocess.run(ssh + [command], capture_output=True, timeout=110, **kwargs)

    identity = "pidof maind; pidof quasar_launcher2; cat /proc/sys/kernel/random/boot_id"
    before = remote(identity, check=True).stdout
    firewall = remote("iptables-save; ip6tables-save", check=True).stdout
    (root / "build/closed-flow-firewall-before.txt").write_bytes(firewall)
    target = "/data/opt/lisa-controller-lab/closed-flow-probe-" + digest[:16]
    remote("umask 077; cat > " + target + ".new && chmod 700 " + target + ".new", input=binary, check=True)
    if remote("sha256sum " + target + ".new", check=True).stdout.decode().split()[0] != digest:
        raise RuntimeError("uploaded binary digest mismatch")
    remote("mv " + target + ".new " + target, check=True)
    result = remote("sh -s", input=SCRIPT.replace("PROBE", target).replace("FAULT", "0").encode())
    after = remote(identity, check=True).stdout
    firewall_after = remote("iptables-save; ip6tables-save", check=True).stdout
    events = [json.loads(line) for line in result.stdout.decode().splitlines()]
    report = dict(
        binary_sha256=digest,
        returncode=result.returncode,
        events=events,
        qualified=result.returncode == 0 and evaluate_events(events),
        stock_identity_unchanged=before == after,
        firewall_rules_restored=rules_only(firewall) == rules_only(firewall_after),
        isolation_verified=False,
        audio_captured=False,
        error=result.stderr.decode(errors="replace")[-2000:],
    )
    if args.exercise_restart and report["qualified"] and report["firewall_rules_restored"]:
        restart = remote("sh -s", input=SCRIPT.replace("PROBE", target).replace("FAULT", "2").encode())
        restart_events = [json.loads(line) for line in restart.stdout.decode().splitlines()]
        report["coordinator_restart_test"] = dict(
            qualified=restart.returncode == 0 and evaluate_resume_events(restart_events),
            events=restart_events,
            stock_identity_unchanged=before == remote(identity, check=True).stdout,
            firewall_rules_restored=rules_only(firewall)
            == rules_only(remote("iptables-save; ip6tables-save", check=True).stdout),
            error=restart.stderr.decode(errors="replace")[-1000:],
        )
        proof = report["coordinator_restart_test"]
        report["qualified"] = (
            report["qualified"]
            and proof["qualified"]
            and proof["stock_identity_unchanged"]
            and proof["firewall_rules_restored"]
        )
    if args.exercise_watchdog and report["qualified"] and report["firewall_rules_restored"]:
        script = SCRIPT.replace("sleep 90;", "sleep 8;").replace("PROBE", target).replace("FAULT", "1")
        fault = remote("sh -s", input=script.encode())
        rows = [json.loads(line) for line in fault.stdout.decode().splitlines()]
        crashes = [row for row in rows if row.get("event") == "closed-flow-watchdog-crash"]
        cleaned = False
        deadline = time.monotonic() + 20
        while time.monotonic() < deadline:
            if remote("test ! -d /data/opt/lisa-lab/trial.lock").returncode == 0:
                cleaned = True
                break
            time.sleep(1)
        evidence = False
        if len(crashes) == 1:
            fixture = crashes[0].get("fixture", "")
            if re.fullmatch(r"/bkupgrade/data/opt/lisa-controller-lab/closed-flow\.[A-Za-z0-9]{6}", fixture):
                evidence = (
                    remote(
                        "test -f " + fixture + "/state/flows.state && "
                        "grep -qx 'LISA_CLOSE_V1 1 paused network_denied' "
                        + fixture
                        + "/state/closed.request"
                    ).returncode
                    == 0
                )
        report["watchdog_crash_test"] = dict(
            crash_observed=len(crashes) == 1 and fault.returncode != 0,
            independent_cleanup=cleaned,
            durable_evidence_and_fence_retained=evidence,
            stock_identity_unchanged=before == remote(identity, check=True).stdout,
            firewall_rules_restored=rules_only(firewall)
            == rules_only(remote("iptables-save; ip6tables-save", check=True).stdout),
        )
        report["qualified"] = report["qualified"] and all(report["watchdog_crash_test"].values())
    (root / "build/closed-flow-qualification.json").write_text(
        json.dumps(report, indent=2) + "\n", encoding="utf-8"
    )
    public_summary = {key: value for key, value in report.items() if key != "events"}
    if "coordinator_restart_test" in public_summary:
        public_summary["coordinator_restart_test"] = {
            key: value for key, value in report["coordinator_restart_test"].items() if key != "events"
        }
    print(json.dumps(public_summary, indent=2))
    if not (report["qualified"] and report["stock_identity_unchanged"] and report["firewall_rules_restored"]):
        raise SystemExit("closed-flow qualification failed; inspect private report")


if __name__ == "__main__":
    main()
