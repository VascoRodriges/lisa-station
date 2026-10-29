"""Temporarily hand off only the mixer daemon; no PCM/capture or Alice restart."""

import argparse
import hashlib
import json
import subprocess
from pathlib import Path

from controller.qualify_bootstrap import SCRIPT as POLICY_SCRIPT
from controller.qualify_bootstrap import evaluate_events as evaluate_policy
from controller.qualify_socket_close import rules_only


def trial_script():
    anchors = (
        "for tool in iptables ip6tables; do\n    for rule",
        "expect bootstrap denied\n",
        'cleanup\necho \'{"event":"boot-policy-cleanup"',
    )
    if any(POLICY_SCRIPT.count(anchor) != 1 for anchor in anchors):
        raise RuntimeError("bootstrap fixture changed; review hardware handoff first")
    script = POLICY_SCRIPT.replace(
        anchors[0],
        r"""# Stop only our supervised actor before restoring the original mixer.
if [ -f "$STATE/hardware-restore" ] && [ ! -f "$STATE/hardware-restored" ]; then
    canon=$(readlink -f "$STATE")
    PROBE --lab-hardware-stop "$canon" > "$STATE/hardware-stop-cleanup.json" || exit 9
    PROBE --lab-hardware-clear-stale "$canon" > "$STATE/hardware-clear-cleanup.json" || exit 9
    /etc/init.d/S46hardvold start </dev/null > "$STATE/hardware-restore.log" 2>&1 9>&- || :
    tries=0
    while :; do
        set -- $(pidof hardvold)
        if [ "$#" = 1 ] && grep -q '^Seccomp:[[:space:]]*0$' "/proc/$1/status"; then break; fi
        [ "$tries" -lt 30 ] || exit 9
        sleep .1; tries=$((tries+1))
    done
    amixer -c 0 cset name='Master Playback Volume' "$(cat "$STATE/original-volume")" > "$STATE/mixer-restore.log" || exit 9
    sleep .5
    set -- $(pidof hardvold)
    [ "$#" = 1 ] && grep -q '^Seccomp:[[:space:]]*0$' "/proc/$1/status" || exit 9
    touch "$STATE/hardware-restored"
fi
for tool in iptables ip6tables; do
    for rule""",
    )
    script = script.replace(
        anchors[1],
        anchors[1]
        + r"""volume=$(amixer -c 0 cget name='Master Playback Volume' | sed -n 's/.*: values=\([0-9][0-9]*\)$/\1/p')
case "$volume" in ''|*[!0-9]*) exit 7;; esac
[ "$volume" -le 255 ]
printf '%s\n' "$volume" > "$STATE/original-volume"
hardware_volume=$(amixer -c 0 cget name='SY6045S Master Playback Volume' | sed -n 's/.*: values=\([0-9][0-9]*\)$/\1/p')
case "$hardware_volume" in ''|*[!0-9]*) exit 7;; esac
""",
    )
    script = script.replace(
        anchors[2],
        r'''expect lab-hardware-start denied
# Briefly mute the mixer during the handoff; no test sound is played.
touch "$STATE/hardware-restore"
amixer -c 0 cset name='Master Playback Volume' 0 > "$STATE/mixer-mute.log"
/etc/init.d/S46hardvold stop > "$STATE/hardware-stop-stock.log" 2>&1
tries=0
while pidof hardvold >/dev/null; do
    [ "$tries" -lt 30 ] || exit 7
    sleep .1; tries=$((tries+1))
done
expect lab-hardware-start ok
amixer -c 0 cset name='Master Playback Volume' "$volume" > "$STATE/mixer-active.log"
expect lab-hardware-status ok
expect lab-hardware-start ok
sleep .3
if [ "$volume" -ge 10 ]; then testlevel=$((volume-10)); else testlevel=$((volume+10)); fi
amixer -c 0 cset name='Master Playback Volume' "$testlevel" > "$STATE/mixer-test.log"
sleep .2
mapped=$(amixer -c 0 cget name='SY6045S Master Playback Volume' | sed -n 's/.*: values=\([0-9][0-9]*\)$/\1/p')
if [ "$testlevel" -lt "$volume" ]; then [ "$mapped" -lt "$hardware_volume" ]; else [ "$mapped" -gt "$hardware_volume" ]; fi
amixer -c 0 cset name='Master Playback Volume' "$volume" > "$STATE/mixer-test-restore.log"
sleep .2
mapped=$(amixer -c 0 cget name='SY6045S Master Playback Volume' | sed -n 's/.*: values=\([0-9][0-9]*\)$/\1/p')
[ "$mapped" = "$hardware_volume" ]
echo '{"event":"hardware-mixer","mapped_change_verified":true,"level_restored":true,"pcm_opened":false}'
printf 'LISA_MODE_V1 4 alice\n' > "$STATE/state/mode.state"
expect lab-hardware-status ok
printf 'LISA_MODE_V1 5 lisa\n' > "$STATE/state/mode.state"
expect lab-hardware-status ok
[ ! -e "$STATE/run/vendor.permit" ]
current=$(amixer -c 0 cget name='Master Playback Volume' | sed -n 's/.*: values=\([0-9][0-9]*\)$/\1/p')
[ "$current" = "$volume" ]
expect lab-hardware-stop ok
cleanup
[ -f "$STATE/hardware-restored" ]
current=$(amixer -c 0 cget name='Master Playback Volume' | sed -n 's/.*: values=\([0-9][0-9]*\)$/\1/p')
[ "$current" = "$volume" ]
echo '{"event":"hardware-restored","stock_mixer_running":true,"volume_preserved":true,"pcm_opened":false}'
echo '{"event":"boot-policy-cleanup"''',
    )
    return script


def evaluate_events(events):
    if not isinstance(events, list) or any(not isinstance(row, dict) for row in events):
        return False
    hardware = [row for row in events if str(row.get("operation", "")).startswith("lab-hardware-")]
    other = [
        row
        for row in events
        if row not in hardware and row.get("event") not in {"hardware-restored", "hardware-mixer"}
    ]
    if not evaluate_policy(other) or len(events) != 26 or len(hardware) != 7:
        return False
    if [row.get("event") for row in events] != ["station-boot"] * 20 + ["hardware-mixer"] + [
        "station-boot"
    ] * 3 + ["hardware-restored", "boot-policy-cleanup"]:
        return False
    operations = ["start", "start", "status", "start", "status", "status", "stop"]
    modes = ["paused"] * 4 + ["alice", "lisa", "lisa"]
    for index, row in enumerate(hardware):
        success = index != 0
        if (
            row.get("event") != "station-boot"
            or row.get("operation") != "lab-hardware-" + operations[index]
            or row.get("requested_mode") != modes[index]
            or row.get("result") != ("ok" if success else "denied")
            or row.get("hardware_operation_ok") is not success
            or row.get("lab_policy_only") is not True
            or row.get("namespace_owned") is not True
            or row.get("policy_ready") is not True
            or row.get("vendor_started") is not False
            or row.get("stock_fallback") is not False
            or row.get("isolation_verified") is not False
            or type(row.get("known_legacy_actors")) is not int
            or row["known_legacy_actors"] != other[15]["known_legacy_actors"] - (index != 0)
            or type(row.get("tagged_actors")) is not int
            or row["tagged_actors"] != 0
            or type(row.get("elapsed_ms")) is not int
            or not 0 <= row["elapsed_ms"] < 3500
        ):
            return False
    restored = [row for row in events if row.get("event") == "hardware-restored"]
    mixer = [row for row in events if row.get("event") == "hardware-mixer"]
    return mixer == [
        dict(event="hardware-mixer", mapped_change_verified=True, level_restored=True, pcm_opened=False)
    ] and restored == [
        dict(event="hardware-restored", stock_mixer_running=True, volume_preserved=True, pcm_opened=False)
    ]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("host")
    parser.add_argument("--ssh-config", type=Path)
    parser.add_argument("--temporary-mixer-handoff", action="store_true", required=True)
    args = parser.parse_args()
    if args.host.startswith("-"):
        parser.error("SSH alias required")
    root = Path(__file__).resolve().parents[1]
    binary = (root / "build/station-boot.armhf").read_bytes()
    digest = hashlib.sha256(binary).hexdigest()
    ssh = ["ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=20"]
    if args.ssh_config:
        ssh += ["-F", str(args.ssh_config)]
    ssh += [args.host]

    def remote(command, **kwargs):
        return subprocess.run(ssh + [command], capture_output=True, timeout=110, **kwargs)

    identity = "for p in $(pidof quasar_launcher2 maind alsa-audio-monitord); do echo $p; awk '{print $22}' /proc/$p/stat; done; cat /proc/sys/kernel/random/boot_id; sha256sum /etc/init.d/rcS /etc/init.d/S99zdropbear /system/vendor/quasar/launch.json"
    before = remote(identity, check=True).stdout
    rules = remote("iptables-save; ip6tables-save", check=True).stdout
    target = "/data/opt/lisa-controller-lab/station-boot-" + digest[:16]
    remote("umask 077; cat > " + target + ".new && chmod 700 " + target + ".new", input=binary, check=True)
    if remote("sha256sum " + target + ".new", check=True).stdout.decode().split()[0] != digest:
        raise RuntimeError("hardware coordinator digest mismatch")
    remote("mv " + target + ".new " + target, check=True)
    result = remote("sh -s", input=trial_script().replace("PROBE", target).encode())
    after = remote(identity, check=True).stdout
    after_rules = remote("iptables-save; ip6tables-save", check=True).stdout
    events = [json.loads(line) for line in result.stdout.decode().splitlines()]
    report = dict(
        binary_sha256=digest,
        returncode=result.returncode,
        events=events,
        error=result.stderr.decode()[-2000:],
        protocol_qualified=result.returncode == 0 and evaluate_events(events),
        stock_voice_identity_preserved=before == after,
        firewall_rules_restored=rules_only(rules) == rules_only(after_rules),
        production_mode_changed=False,
        audio_captured=False,
        isolation_verified=False,
    )
    (root / "build/hardware-qualification.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps({key: value for key, value in report.items() if key != "events"}, indent=2))
    if not all(
        report[key]
        for key in ("protocol_qualified", "stock_voice_identity_preserved", "firewall_rules_restored")
    ):
        raise SystemExit("mixer qualification incomplete; inspect private report")


if __name__ == "__main__":
    main()
