"""Exercise only unused guarded-group policy; ordinary stock services keep running.

No real vendor traffic is relabelled or stopped. This is not a cold-boot or
whole-device privacy test. The independent watchdog removes only owned rules.
"""

import argparse
import hashlib
import json
import subprocess
from pathlib import Path

from controller.qualify_socket_close import rules_only

SCRIPT = r"""
set -eu
umask 077
BASE=/data/opt/lisa-controller-lab
test ! -d /bkupgrade/data/opt/lisa-station/state
test ! -d /run/lisa-station
[ "$(id -u)" = 0 ]
CHAIN=LISACQ_BC_$$; MARK=LISACM_BC_$$; LABEL=LISACL_BC_$$; FOREIGN=LISACW_BC_$$
for tool in iptables ip6tables; do
    if "$tool" -S "$CHAIN" >/dev/null 2>&1 || "$tool" -S "$LABEL" >/dev/null 2>&1 ||
       "$tool" -t mangle -S "$MARK" >/dev/null 2>&1 || "$tool" -t mangle -S "$FOREIGN" >/dev/null 2>&1; then exit 3; fi
done
mkdir /data/opt/lisa-lab/trial.lock
STATE=$(mktemp -d "$BASE/boot-policy.XXXXXX")
CANON=$(readlink -f "$STATE")
mkdir "$STATE/state" "$STATE/run"
printf '%s\n' "$CHAIN" > "$STATE/chain"
printf '%s\n' "$CHAIN" > "$STATE/run/policy.chain"
printf 'LISA_MODE_V1 1 paused\n' > "$STATE/state/mode.state"
: > "$STATE/state/mode.lock"; : > "$STATE/run/boot.lock"
cat > "$STATE/cleanup.sh" <<'CLEANUP'
#!/bin/sh
set -u
STATE=$1
exec 9>"$STATE/cleanup.lock"; flock -x 9
[ ! -f "$STATE/cleaned" ] || exit 0
chain=$(cat "$STATE/chain"); suffix=${chain#LISACQ_BC_}
[ "$suffix" != "$chain" ] || exit 9
case "$suffix" in ''|*[!0-9]*) exit 9;; esac
mark=LISACM_BC_$suffix; label=LISACL_BC_$suffix; foreign=LISACW_BC_$suffix
# Never open a barrier over an unexpected guarded actor.
for status in /proc/[0-9]*/status; do
    if awk '/^Gid:|^Groups:/ {for(i=2;i<=NF;i++) if($i>=57342&&$i<=57345) found=1} END{exit !found}' "$status" 2>/dev/null; then exit 9; fi
done
for tool in iptables ip6tables; do
    for rule in "$chain" "$label"; do
        if "$tool" -C OUTPUT -j "$rule" >/dev/null 2>&1; then "$tool" -D OUTPUT -j "$rule" || exit 9; fi
    done
    if "$tool" -C OUTPUT -p tcp -j "$chain" >/dev/null 2>&1; then "$tool" -D OUTPUT -p tcp -j "$chain" || exit 9; fi
    if "$tool" -C INPUT -j "$label" >/dev/null 2>&1; then "$tool" -D INPUT -j "$label" || exit 9; fi
    if "$tool" -t mangle -C OUTPUT -j "$mark" >/dev/null 2>&1; then "$tool" -t mangle -D OUTPUT -j "$mark" || exit 9; fi
    for rule in "$chain" "$label"; do
        if "$tool" -S "$rule" >/dev/null 2>&1; then "$tool" -F "$rule" && "$tool" -X "$rule" || exit 9; fi
    done
    for rule in "$mark" "$foreign"; do
        if "$tool" -t mangle -S "$rule" >/dev/null 2>&1; then "$tool" -t mangle -F "$rule" && "$tool" -t mangle -X "$rule" || exit 9; fi
    done
done
touch "$STATE/cleaned"
rmdir /data/opt/lisa-lab/trial.lock
CLEANUP
cleanup() { sh "$STATE/cleanup.sh" "$STATE"; }
trap cleanup EXIT
trap 'exit 125' HUP INT TERM
nohup sh -c 'sleep 70; sh "$1/cleanup.sh" "$1"' watchdog "$STATE" </dev/null >"$STATE/watchdog.log" 2>&1 &
sequence=0
expect() {
    operation=$1; expected=$2; sequence=$((sequence+1)); result=0
    if [ "$operation" = bootstrap ]; then
        PROBE --bootstrap > "$STATE/event-$sequence.json" || result=$?
    else
        PROBE --$operation "$CANON" > "$STATE/event-$sequence.json" || result=$?
    fi
    cat "$STATE/event-$sequence.json"
    grep -q '"result":"'"$expected"'"' "$STATE/event-$sequence.json"
    if [ "$expected" = ok ]; then [ "$result" = 0 ]; else [ "$result" != 0 ]; fi
}
expect bootstrap denied
expect lab-policy-status denied
expect lab-policy ok
expect lab-policy ok
expect lab-policy-status ok
# Restore missing middle rules in their original order, without flushing.
ip6tables -D "$CHAIN" -m owner --gid-owner 57344 -j DROP
iptables -t mangle -D "$MARK" -m owner --gid-owner 57344 -j CONNMARK --set-xmark 0x40000000/0x40000000
expect lab-policy ok
iptables -A "$CHAIN" -j RETURN
expect lab-policy incomplete
iptables -C "$CHAIN" -j RETURN
iptables -D "$CHAIN" -j RETURN
expect lab-policy ok
# An unexpected conditional owned hook must not be moved or deleted to pass.
iptables -I OUTPUT 1 -p tcp -j "$CHAIN"
expect lab-policy incomplete
iptables -C OUTPUT -p tcp -j "$CHAIN"
iptables -D OUTPUT -p tcp -j "$CHAIN"
expect lab-policy ok
# A separate, unhooked writer is still a namespace conflict; do not adopt it.
iptables -t mangle -N "$FOREIGN"
iptables -t mangle -A "$FOREIGN" -m owner --gid-owner 57342 -j CONNMARK --set-xmark 0x1/0x1
expect lab-policy incomplete
iptables -t mangle -C "$FOREIGN" -m owner --gid-owner 57342 -j CONNMARK --set-xmark 0x1/0x1
iptables -t mangle -F "$FOREIGN"; iptables -t mangle -X "$FOREIGN"
expect lab-policy ok
# A ready record alone is never ownership of an existing kernel namespace.
mv "$STATE/run/boot.policy" "$STATE/owner.saved"
expect lab-policy denied
[ ! -e "$STATE/run/boot.policy" ]
mv "$STATE/owner.saved" "$STATE/run/boot.policy"
printf 'LISA_MODE_V1 2 alice\n' > "$STATE/state/mode.state"
expect lab-policy denied
printf 'LISA_MODE_V1 3 paused\n' > "$STATE/state/mode.state"
expect lab-policy ok
expect lab-policy-status ok
[ ! -e "$STATE/run/vendor.permit" ]
cleanup
echo '{"event":"boot-policy-cleanup","ok":true,"vendor_started":false}'
"""


def evaluate_events(events):
    if len(events) != 17 or any(not isinstance(row, dict) for row in events):
        return False
    expected = [
        ("bootstrap", "denied"),
        ("lab-policy-status", "denied"),
        ("lab-policy", "ok"),
        ("lab-policy", "ok"),
        ("lab-policy-status", "ok"),
        ("lab-policy", "ok"),
        ("lab-policy", "incomplete"),
        ("lab-policy", "ok"),
        ("lab-policy", "incomplete"),
        ("lab-policy", "ok"),
        ("lab-policy", "incomplete"),
        ("lab-policy", "ok"),
        ("lab-policy", "denied"),
        ("lab-policy", "denied"),
        ("lab-policy", "ok"),
        ("lab-policy-status", "ok"),
    ]
    if [(row.get("operation"), row.get("result")) for row in events[:-1]] != expected:
        return False
    for i, row in enumerate(events[:-1]):
        if row.get("event") != "station-boot" or any(
            row.get(key) is not False for key in ("vendor_started", "stock_fallback", "isolation_verified")
        ):
            return False
        if row.get("lab_policy_only") is not (i != 0) or row.get("policy_ready") is not (
            row["result"] == "ok"
        ):
            return False
        if type(row.get("elapsed_ms")) is not int or not 0 <= row["elapsed_ms"] < 3500:
            return False
        mode = "unknown" if i == 0 else "alice" if i == 13 else "paused"
        if row.get("requested_mode") != mode:
            return False
        if i in {0, 13}:
            if row.get("known_legacy_actors") is not None or row.get("tagged_actors") is not None:
                return False
        elif (
            type(row.get("known_legacy_actors")) is not int
            or not 1 <= row["known_legacy_actors"] <= 1024
            or type(row.get("tagged_actors")) is not int
            or row["tagged_actors"] != 0
        ):
            return False
        owned = i not in {0, 1, 12, 13}
        if row.get("namespace_owned") is not owned:
            return False
        controls = True if row["operation"] == "lab-policy" and row["result"] == "ok" else None
        if row.get("unrelated_controls_verified") is not controls:
            return False
    return events[-1] == dict(event="boot-policy-cleanup", ok=True, vendor_started=False)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("host")
    parser.add_argument("--ssh-config", type=Path)
    parser.add_argument("--apply-temporary-guarded-policy", required=True, action="store_true")
    args = parser.parse_args()
    if args.host.startswith("-"):
        parser.error("host must be an SSH alias")
    root = Path(__file__).resolve().parents[1]
    binary = (root / "build/station-boot.armhf").read_bytes()
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

    identity = "for p in $(pidof quasar_launcher2 maind alsa-audio-monitord hardvold); do echo $p; awk '{print $22}' /proc/$p/stat; done; cat /proc/sys/kernel/random/boot_id; sha256sum /etc/init.d/rcS /etc/init.d/S99zdropbear /system/vendor/quasar/launch.json"
    before = remote(identity, check=True).stdout
    rules = remote("iptables-save; ip6tables-save", check=True).stdout
    target = "/data/opt/lisa-controller-lab/station-boot-" + digest[:16]
    remote("umask 077; cat > " + target + ".new && chmod 700 " + target + ".new", input=binary, check=True)
    if remote("sha256sum " + target + ".new", check=True).stdout.decode().split()[0] != digest:
        raise RuntimeError("bootstrap helper digest mismatch")
    remote("mv " + target + ".new " + target, check=True)
    result = remote("sh -s", input=SCRIPT.replace("PROBE", target).encode())
    after = remote(identity, check=True).stdout
    after_rules = remote("iptables-save; ip6tables-save", check=True).stdout
    events = [json.loads(line) for line in result.stdout.decode().splitlines()]
    report = dict(
        binary_sha256=digest,
        returncode=result.returncode,
        events=events,
        error=result.stderr.decode()[-2000:],
        protocol_qualified=result.returncode == 0 and evaluate_events(events),
        stock_identity_preserved=before == after,
        firewall_rules_restored=rules_only(rules) == rules_only(after_rules),
        production_mode_changed=False,
        audio_captured=False,
        isolation_verified=False,
    )
    (root / "build/boot-policy-qualification.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps({key: value for key, value in report.items() if key != "events"}, indent=2))
    if not all(
        report[key] for key in ("protocol_qualified", "stock_identity_preserved", "firewall_rules_restored")
    ):
        raise SystemExit("bootstrap policy trial incomplete; inspect private report")


if __name__ == "__main__":
    main()
