"""Bounded real launcher trial through admission, guardian and closed recovery."""

import argparse
import hashlib
import json
import subprocess
from pathlib import Path

from controller.qualify_socket_close import rules_only
from controller.qualify_vendor_startup import SCRIPT as BASE_SCRIPT
from controller.qualify_vendor_startup import evaluate_samples


def trial_script(target, closed_policy=False):
    required = (
        "$BASE/vendor-startup.XXXXXX",
        '[ ! -f "$STATE/restored" ] || exit 0',
        'kill -STOP "$pid"\n',
        "PROBE --quasar </dev/null >/dev/null 2>&1 &",
        "done\nrestore\ntries=0",
        '[ "$tries" -lt 12 ]',
    )
    if any(BASE_SCRIPT.count(marker) != 1 for marker in required):
        raise RuntimeError("bounded startup template changed; review before running")
    script = BASE_SCRIPT.replace("set -eu\n", "set -eu\numask 077\n", 1).replace(
        "$BASE/vendor-startup.XXXXXX", "$BASE/guardian-startup.XXXXXX"
    )
    script = script.replace(
        """case "$(awk '{print $3}' "/proc/$worker/stat")" in Z|X) continue;; esac""",
        """case "$(awk '{print $3}' "/proc/$worker/stat" 2>/dev/null)" in ''|Z|X) continue;; esac""",
    ).replace('readlink "/proc/$worker/exe")', 'readlink "/proc/$worker/exe" 2>/dev/null)')
    # Stock tasks use allowedRestartIntervalSeconds=600. Repeated administrative
    # trials can reach that limit. Keep the original launcher/configuration and
    # observe recovery with a bound, rather than resetting its restart limiter.
    script = script.replace('[ "$tries" -lt 12 ]', '[ "$tries" -lt 625 ]')
    script = script.replace(
        '[ ! -f "$STATE/restored" ] || exit 0',
        """[ ! -f "$STATE/restored" ] || exit 0
if [ -f "$STATE/service" ] && [ -d "$STATE/state" ]; then
    service=$(cat "$STATE/service"); canonical=$(readlink -f "$STATE")
    "$service" --lab-request-paused "$canonical" >/dev/null 2>&1 || :
    "$service" --lab-stop-quasar "$canonical" >/dev/null 2>&1 || :
fi""",
    )
    script = script.replace(
        'kill -STOP "$pid"\n',
        """
CANON=$(readlink -f "$STATE")
mkdir "$STATE/state" "$STATE/run"
printf 'LISA_MODE_V1 1 alice\\n' > "$STATE/state/mode.state"
printf 'LISA_VENDOR_PERMIT_V1 1 %s\\n' "$(cat /proc/sys/kernel/random/boot_id)" > "$STATE/run/vendor.permit"
printf '%s\\n' NATIVE_SERVICE > "$STATE/service"
kill -STOP "$pid"
""",
    )
    script = script.replace(
        '''PROBE --quasar </dev/null >/dev/null 2>&1 &
guarded=$!
echo "$guarded" > "$STATE/guarded.pid"''',
        '''NATIVE_SERVICE --lab-start-quasar "$CANON"
duplicate=0
NATIVE_SERVICE --lab-start-quasar "$CANON" > "$STATE/duplicate.json" || duplicate=$?
[ "$duplicate" != 0 ] && grep -q '"result":"busy"' "$STATE/duplicate.json"
cat "$STATE/duplicate.json"''',
    )
    # Insert a closed request/reconcile before the final explicit restore, not
    # inside the trap function. The independent restore remains available.
    closing = """
tries=0
while ! NATIVE_SERVICE --lab-request-paused "$CANON" > "$STATE/pause.json"; do
    [ "$tries" -lt 20 ] || exit 8
    sleep .05; tries=$((tries+1))
done
cat "$STATE/pause.json"
tries=0
while [ -n "$(live_maind)" ] || ! grep -q ' stopped$' "$STATE/run/quasar.child"; do
    [ "$tries" -lt 40 ] || exit 8
    sleep .1; tries=$((tries+1))
done
echo '{"event":"guardian-stopped","actors_absent":true}'
tries=0
while ! NATIVE_SERVICE --lab-reconcile-quasar "$CANON" > "$STATE/reconcile.json"; do
    [ "$tries" -lt 20 ] || exit 8
    sleep .05; tries=$((tries+1))
done
cat "$STATE/reconcile.json"
[ ! -e "$STATE/run/vendor.permit" ] && [ ! -e "$STATE/run/quasar.child" ]
denied=0
NATIVE_SERVICE --lab-start-quasar "$CANON" > "$STATE/denied.json" || denied=$?
[ "$denied" != 0 ] && grep -q '"result":"denied"' "$STATE/denied.json"
cat "$STATE/denied.json"
"""
    if closed_policy:
        cleanup_policy = r"""
if [ -f "$STATE/chain" ]; then
    chain=$(cat "$STATE/chain"); suffix=${chain#LISACQ_}
    [ "$suffix" != "$chain" ] || exit 9
    case "$suffix" in ''|*[!0-9]*) exit 9;; esac
    for version in 4 6; do
        tool=iptables; [ "$version" = 4 ] || tool=ip6tables
        if [ -f "$STATE/hook-$version" ] && "$tool" -C OUTPUT -j "$chain" >/dev/null 2>&1; then
            "$tool" -D OUTPUT -j "$chain" || exit 9
        fi
        if [ -f "$STATE/chain-$version" ] && "$tool" -S "$chain" >/dev/null 2>&1; then
            "$tool" -F "$chain" || exit 9
            "$tool" -X "$chain" || exit 9
        fi
        if "$tool" -S "$chain" >/dev/null 2>&1; then exit 9; fi
    done
fi
"""
        script = script.replace(
            'if ! sha256sum -c "$STATE/launch.sha256"',
            cleanup_policy + '\nif ! sha256sum -c "$STATE/launch.sha256"',
        )
        install = r"""
CHAIN=LISACQ_$$
for tool in iptables ip6tables; do
    if "$tool" -S "$CHAIN" >/dev/null 2>&1; then exit 8; fi
done
printf '%s\n' "$CHAIN" > "$STATE/chain"
printf '%s\n' "$CHAIN" > "$STATE/run/policy.chain"
touch "$STATE/chain-4"; iptables -N "$CHAIN"
iptables -A "$CHAIN" -m owner --gid-owner 57342 -j DROP
touch "$STATE/hook-4"; iptables -I OUTPUT 1 -j "$CHAIN"
rejected=0
NATIVE_SERVICE --lab-check-quasar-policy "$CANON" > "$STATE/missing-v6.json" || rejected=$?
[ "$rejected" != 0 ] && grep -q '"result":"failed"' "$STATE/missing-v6.json"
[ ! -e "$STATE/state/closed.request" ]
cat "$STATE/missing-v6.json"
touch "$STATE/chain-6"; ip6tables -N "$CHAIN"
ip6tables -A "$CHAIN" -m owner --gid-owner 57342 -j DROP
touch "$STATE/hook-6"; ip6tables -I OUTPUT 1 -j "$CHAIN"
NATIVE_SERVICE --lab-check-quasar-policy "$CANON"
"""
        closing = install + closing.replace("--lab-request-paused", "--lab-close-quasar")
        # Simulate a legacy writer publishing fresh Alice intent/permit after
        # closed reconciliation. The durable close fence must still deny start.
        closing = closing.replace(
            "denied=0\n",
            r"""
[ -f "$STATE/state/closed.request" ]
printf 'LISA_MODE_V1 3 alice\n' > "$STATE/state/mode.state"
printf 'LISA_VENDOR_PERMIT_V1 3 %s\n' "$(cat /proc/sys/kernel/random/boot_id)" > "$STATE/run/vendor.permit"
denied=0
""",
        )
    script = script.replace("done\nrestore\ntries=0", "done\n" + closing + "\nrestore\ntries=0")
    return (
        script.replace("NATIVE_SERVICE", target)
        .replace("PROBE", target)
        .replace("WATCHDOG_SECONDS", "65")
        .replace("OBSERVE_INTERVAL", "3")
        .replace("VOICE_READY", "0")
    )


def evaluate_events(events, closed_policy=False):
    if len(events) != (14 if closed_policy else 11):
        return False
    samples = [row for row in events if row.get("event") == "startup-sample"]
    if not evaluate_samples(samples):
        return False
    services = [row for row in events if row.get("event") == "station-service"]
    expected = [("start-quasar", "ok"), ("start-quasar", "busy")]
    if closed_policy:
        expected += [("check-quasar-policy", "failed"), ("check-quasar-policy", "ok")]
    expected += [
        ("close-quasar" if closed_policy else "request-paused", "ok"),
        ("reconcile-quasar", "ok"),
        ("start-quasar", "denied"),
    ]
    if [(row.get("operation"), row.get("result")) for row in services] != expected:
        return False
    if not all(row.get("isolation_verified") is False for row in services):
        return False
    if services[0].get("guardian_pid", 0) < 2 or services[0].get("child_pid", 0) < 2:
        return False
    closing = services[4 if closed_policy else 2]
    if services[0].get("revision") != 1 or closing.get("revision") != 2:
        return False
    if closed_policy:
        controls = [row for row in events if row.get("event") == "policy-controls"]
        if (
            closing.get("transition_phase") != "complete"
            or len(controls) != 1
            or not (controls[0].get("ipv4") is True and controls[0].get("ipv6") is True)
        ):
            return False
    stopped = [row for row in events if row.get("event") == "guardian-stopped"]
    restored = [row for row in events if row.get("event") == "restored"]
    return (
        len(stopped) == 1
        and stopped[0].get("actors_absent") is True
        and len(restored) == 1
        and (
            restored[0].get("workers") == 4
            and restored[0].get("boot_changed") is False
            and restored[0].get("capture_tool_used") is False
        )
    )


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("host")
    parser.add_argument("--ssh-config", type=Path)
    parser.add_argument("--allow-temporary-stock-restart", action="store_true", required=True)
    parser.add_argument(
        "--exercise-closed-policy",
        action="store_true",
        help="Temporarily filter only the trial vendor group and exercise the closed transaction",
    )
    args = parser.parse_args()
    if args.host.startswith("-"):
        parser.error("host must be an SSH alias")
    root = Path(__file__).resolve().parents[1]
    binary = (root / "build/station-service.armhf").read_bytes()
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
        return subprocess.run(ssh + [command], capture_output=True, timeout=700, **kwargs)

    identity = "pidof quasar_launcher2; cat /proc/sys/kernel/random/boot_id; sha256sum /system/vendor/quasar/launch.json"
    remote("test ! -d /bkupgrade/data/opt/lisa-station/state && test ! -d /run/lisa-station", check=True)
    before = remote(identity, check=True).stdout
    firewall = remote("iptables-save; ip6tables-save", check=True).stdout
    (root / "build/guardian-firewall-before.txt").write_bytes(firewall)
    (root / "build/guardian-startup-launch-backup.json").write_bytes(
        remote("cat /system/vendor/quasar/launch.json", check=True).stdout
    )
    target = "/data/opt/lisa-controller-lab/station-service-" + digest[:16]
    remote("umask 077; cat > " + target + ".new && chmod 700 " + target + ".new", input=binary, check=True)
    if remote("sha256sum " + target + ".new", check=True).stdout.decode().split()[0] != digest:
        raise RuntimeError("uploaded binary digest mismatch")
    remote("mv " + target + ".new " + target, check=True)
    # Uninstalled production paths must deny even before a lab permit exists.
    default = remote(target + " --start-quasar")
    default_event = json.loads(default.stdout)
    default_denied = default.returncode != 0 and default_event.get("result") == "denied"
    if not default_denied:
        raise SystemExit("uninstalled production path did not deny")
    result = remote("sh -s", input=trial_script(target, args.exercise_closed_policy).encode())
    after = remote(identity, check=True).stdout
    recovery = (
        remote(
            "for worker in $(pidof maind || :); do awk '/^Gid:/{print $2}' /proc/$worker/status; done; "
            "test ! -d /data/opt/lisa-lab/trial.lock",
            check=True,
        )
        .stdout.decode()
        .splitlines()
    )
    events = [json.loads(line) for line in result.stdout.decode().splitlines()]
    firewall_after = remote("iptables-save; ip6tables-save", check=True).stdout
    report = dict(
        binary_sha256=digest,
        returncode=result.returncode,
        events=events,
        qualified=result.returncode == 0 and evaluate_events(events, args.exercise_closed_policy),
        closed_policy_exercised=args.exercise_closed_policy,
        firewall_rules_restored=rules_only(firewall) == rules_only(firewall_after),
        default_production_start_denied=default_denied,
        original_launcher_boot_and_config_restored=before == after,
        ordinary_worker_identity_restored=len(recovery) == 4 and all(gid == "0" for gid in recovery),
        production_mode_changed=False,
        isolation_verified=False,
        audio_captured=False,
        error=result.stderr.decode(errors="replace")[-2000:],
    )
    filename = (
        "guardian-closed-policy-qualification.json"
        if args.exercise_closed_policy
        else "guardian-startup-qualification.json"
    )
    (root / "build" / filename).write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps({key: value for key, value in report.items() if key != "events"}, indent=2))
    if not (
        report["qualified"]
        and report["original_launcher_boot_and_config_restored"]
        and report["ordinary_worker_identity_restored"]
        and report["firewall_rules_restored"]
    ):
        raise SystemExit("guardian trial did not qualify; inspect private report")


if __name__ == "__main__":
    main()
