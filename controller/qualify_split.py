"""Bounded four-role stock-code trial; explicit restoration to ordinary Alice.

No voice command or audio payload is captured. This is guarded startup/close
qualification, not installed boot enforcement or whole-device isolation.
"""

import argparse
import re
from collections import Counter
from pathlib import Path

from controller.collector_profile import prepare_collector_profile
from controller.launch_profile import prepare_platform_launch
from controller.qualify_diagnostics import RESTORATION_CHECK
from controller.qualify_guardian_startup import run_trial
from controller.qualify_guardian_startup import trial_script as guardian_script
from controller.telemetry_profile import prepare_telemetry_profile


def trial_script(target, closed_policy=True):
    if not closed_policy:
        raise ValueError("split startup requires the complete guarded-role barrier")
    script = guardian_script("PROBE", True)

    def replace(old, new, count=1):
        nonlocal script
        if script.count(old) != count:
            raise RuntimeError("guardian template changed; review split restoration")
        script = script.replace(old, new)

    replace("if($i==57342)", "if($i>=57342 && $i<=57345)")
    start = script.index("live_maind() {")
    end = script.index("\n}", start) + 2
    replace(script[start:end], "live_maind() { PROBE --maind-pids; }")
    replace(
        "$2==57342 && $3==57342 && $4==57342 && $5==57342",
        "$2>=57342 && $2<=57345 && $3==$2 && $4==$2 && $5==$2",
    )
    marker = 'mkdir "$STATE/state" "$STATE/run"'
    replace(
        marker,
        marker
        + '''
mkdir "$STATE/collector-root" "$STATE/telemetry-root" "$STATE/diagnostics-root"
cp @COLLECTOR@ "$STATE/collector-profile.json"
cp @TELEMETRY@ "$STATE/telemetry-profile.json"
cp @LAUNCH@ "$STATE/quasar-launch.json"
chmod 600 "$STATE/collector-profile.json" "$STATE/telemetry-profile.json" "$STATE/quasar-launch.json"''',
    )
    marker = 'sha256sum /system/vendor/quasar/launch.json > "$STATE/launch.sha256"'
    replace(
        marker,
        marker
        + '''
sha256sum /system/vendor/quasar/quasar.cfg >> "$STATE/launch.sha256"
original_diag=$(pidof alsa-audio-monitord)
[ "$(echo "$original_diag" | wc -w)" = 1 ]
[ "$(readlink /proc/$original_diag/exe)" = /usr/bin/alsa-audio-monitord ]
[ "$(awk '/^Gid:/{print $2}' /proc/$original_diag/status)" = 0 ]
printf '%s %s\\n' "$original_diag" "$(awk '{print $22}' /proc/$original_diag/stat)" > "$STATE/diagnostics-original"''',
    )
    marker = '    "$service" --lab-stop-quasar "$canonical" >/dev/null 2>&1 || :'
    replace(
        marker,
        marker
        + """
    for role in collector telemetry diagnostics; do "$service" --lab-stop-$role "$canonical" >/dev/null 2>&1 || :; done""",
    )
    marker = 'for child in $(owned); do kill -KILL "$child" 2>/dev/null || :; done'
    replace(
        marker,
        marker
        + """
tries=0
while [ -n "$(owned)" ]; do [ "$tries" -lt 50 ] || exit 9; sleep .1; tries=$((tries+1)); done""",
    )
    marker = 'touch "$STATE/restored"'
    replace(
        marker,
        """if [ -f "$STATE/diagnostics-stopped" ] && ! pidof alsa-audio-monitord >/dev/null; then
    sh /etc/init.d/S47alsa-audio-monitor start 9>&- >"$STATE/stock-diagnostics.out" 2>&1 || exit 9
fi
"""
        + marker,
    )
    replace(
        "sh /system/vendor/quasar/run.sh >/dev/null 2>&1",
        "sh /system/vendor/quasar/run.sh 9>&- >/dev/null 2>&1",
    )
    replace('sleep 65; sh "$1/restore.sh" "$1"', 'sleep 95; sh "$1/restore.sh" "$1"')
    replace("--lab-start-quasar", "--lab-start-platform", 3)
    marker = 'PROBE --lab-start-platform "$CANON"\nduplicate=0'
    replace(
        marker,
        """PROBE --lab-start-telemetry "$CANON"
PROBE --lab-start-collector "$CANON"
"""
        + marker,
    )
    marker = 'cat "$STATE/duplicate.json"'
    replace(
        marker,
        marker
        + """
tries=0
while ! PROBE --lab-inspect-platform "$CANON" > "$STATE/platform-ready.json"; do
    [ "$tries" -lt 35 ] || exit 8; sleep 1; tries=$((tries+1))
done
set -- $(cat "$STATE/diagnostics-original"); original_diag=$1; original_ticks=$2
[ "$(awk '{print $22}' /proc/$original_diag/stat)" = "$original_ticks" ]
[ "$(readlink /proc/$original_diag/exe)" = /usr/bin/alsa-audio-monitord ]
touch "$STATE/diagnostics-stopped"; kill -TERM "$original_diag"
tries=0
while kill -0 "$original_diag" 2>/dev/null; do
    [ "$tries" -lt 50 ] || exit 8; sleep .1; tries=$((tries+1))
done
PROBE --lab-start-diagnostics "$CANON"
tries=0
while :; do
    if PROBE --lab-inspect-diagnostics "$CANON" > "$STATE/diagnostics-ready.json"; then
        child=$(sed -n 's/.*"child_pid":\\([0-9]*\\).*/\\1/p' "$STATE/diagnostics-ready.json")
        owner=$(dbus-send --system --print-reply --reply-timeout=1000 --dest=org.freedesktop.DBus \\
            /org/freedesktop/DBus org.freedesktop.DBus.GetConnectionUnixProcessID \\
            string:org.yandex.AudioMonitor 2>/dev/null | awk '/uint32/{print $2}')
        [ "$owner" != "$child" ] || break
    fi
    [ "$tries" -lt 30 ] || exit 8; sleep .1; tries=$((tries+1))
done
echo '{"event":"split-diagnostics-bus","matched":true}' """,
    )
    marker = "    echo ']}'"
    replace(
        marker,
        marker
        + """
    for role in telemetry collector platform diagnostics; do PROBE --lab-inspect-$role "$CANON"; done""",
    )
    for version in ("iptables", "ip6tables"):
        marker = f'{version} -A "$CHAIN" -m owner --gid-owner 57342 -j DROP'
        replace(
            marker,
            f'for group in 57342 57343 57344 57345; do {version} -A "$CHAIN" -m owner --gid-owner "$group" -j DROP; done',
        )
    replace("--lab-check-quasar-policy", "--lab-check-roles-policy", 2)
    replace("--lab-close-quasar", "--lab-close-roles")
    marker = 'cat "$STATE/reconcile.json"'
    replace(
        marker,
        marker
        + """
for role in collector telemetry diagnostics; do
    tries=0
    while ! PROBE --lab-reconcile-$role "$CANON" > "$STATE/reconcile-$role.json"; do
        [ "$tries" -lt 20 ] || exit 8; sleep .05; tries=$((tries+1))
    done
    cat "$STATE/reconcile-$role.json"
done
for name in collector telemetry diagnostics; do [ -z "$(ls -A "$STATE/$name-root")" ]; done""",
    )
    marker = 'echo \'{"event":"restored","workers":4,"boot_changed":false,"capture_tool_used":false}\''
    replace(marker, RESTORATION_CHECK + "\n" + marker)
    return script.replace("PROBE", target)


def evaluate_events(events, closed_policy=True):
    if not closed_policy or len(events) != 37 or any(not isinstance(row, dict) for row in events):
        return False
    services = [row for row in events if row.get("event") == "station-service"]
    expected = [
        ("start-telemetry", "ok"),
        ("start-collector", "ok"),
        ("start-platform", "ok"),
        ("start-platform", "busy"),
        ("start-diagnostics", "ok"),
    ]
    expected += [
        ("inspect-" + role, "ok")
        for _ in range(4)
        for role in ("telemetry", "collector", "platform", "diagnostics")
    ]
    expected += [("check-roles-policy", "failed"), ("check-roles-policy", "ok"), ("close-roles", "ok")]
    expected += [("reconcile-" + role, "ok") for role in ("quasar", "collector", "telemetry", "diagnostics")]
    expected += [("start-platform", "denied")]
    if [(row.get("operation"), row.get("result")) for row in services] != expected:
        return False
    starts = {
        row["operation"][6:]: row
        for row in services
        if row["operation"].startswith("start-") and row["result"] == "ok"
    }
    ids = [row.get(field) for row in starts.values() for field in ("child_pid", "guardian_pid")]
    if len(starts) != 4 or any(type(value) is not int or value < 2 for value in ids) or len(set(ids)) != 8:
        return False
    for row in services:
        if row.get("isolation_verified") is not False:
            return False
        if row["operation"].startswith("inspect-"):
            role = row["operation"][8:]
            if row.get("revision") != 1 or any(
                row.get(key) != starts[role][key] for key in ("child_pid", "guardian_pid")
            ):
                return False
            if any(row.get("inspection_" + field) is not True for field in ("live", "identity", "resources")):
                return False
            if role == "platform":
                if (
                    row.get("inspection_view") is not False
                    or row.get("platform_workers_verified") is not True
                ):
                    return False
            elif row.get("inspection_view") is not True:
                return False
        if (
            row["operation"] in {"check-roles-policy", "close-roles"}
            and row.get("closed_scope") != "guarded_roles"
        ):
            return False
    samples = [row for row in events if row.get("event") == "startup-sample"]
    if len(samples) != 4:
        return False
    stable = None
    try:
        for sample in samples:
            workers = sample["workers"]
            if len(workers) != 4 or Counter(w["gid"] for w in workers) != {57342: 2, 57344: 1, 57345: 1}:
                return False
            current = {w["pid"] for w in workers}
            if len(current) != 4 or (stable is not None and current != stable):
                return False
            stable = current
            for worker in workers:
                if type(worker["pid"]) is not int or not 2 <= worker["pid"] <= 2**31 - 1:
                    return False
                if not isinstance(worker["cap_eff"], str) or not re.fullmatch(
                    "[0-9a-f]{1,16}", worker["cap_eff"]
                ):
                    return False
                caps = int(worker["cap_eff"], 16)
                nnp = worker["no_new_privs"]
                if (
                    worker["seccomp"] != 2
                    or (nnp is not None and (type(nnp) is not int or nnp != 1))
                    or caps & ((1 << 12) | (1 << 13) | (1 << 19))
                ):
                    return False
                if worker["gid"] != 57342 and caps:
                    return False
                if worker["gid"] == 57342 and worker["pid"] in ids:
                    return False
                role = (
                    "collector" if worker["gid"] == 57344 else "telemetry" if worker["gid"] == 57345 else None
                )
                if role and worker["pid"] != starts[role]["child_pid"]:
                    return False
    except (KeyError, TypeError, ValueError):
        return False
    closing = next(row for row in services if row["operation"] == "close-roles")
    controls = [row for row in events if row.get("event") == "policy-controls"]
    stopped = [row for row in events if row.get("event") == "guardian-stopped"]
    restored = [row for row in events if row.get("event") == "restored"]
    bus = [row for row in events if row.get("event") == "split-diagnostics-bus"]
    return (
        closing.get("revision") == 2
        and closing.get("transition_phase") == "complete"
        and len(controls) == 1
        and controls[0].get("ipv4") is True
        and controls[0].get("ipv6") is True
        and len(stopped) == 1
        and stopped[0].get("actors_absent") is True
        and len(restored) == 1
        and restored[0].get("workers") == 4
        and restored[0].get("boot_changed") is False
        and restored[0].get("capture_tool_used") is False
        and len(bus) == 1
        and bus[0].get("matched") is True
    )


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("host")
    parser.add_argument("--ssh-config", type=Path)
    parser.add_argument("--allow-temporary-stock-restart", action="store_true", required=True)
    args = parser.parse_args()
    args.exercise_closed_policy = True
    run_trial(
        args,
        trial_script,
        evaluate_events,
        profile_factories={
            "COLLECTOR": prepare_collector_profile,
            "TELEMETRY": prepare_telemetry_profile,
            "LAUNCH": prepare_platform_launch,
        },
    )


if __name__ == "__main__":
    main()
