"""Kill only the own inner labelled trial shell; observe independent restoration.

Uninstalled lab only. This explicitly resumes ordinary Alice; it must never be
used as recovery for an installed Lisa/Paused mode. No new audio is captured.
"""

import argparse
from copy import deepcopy
from pathlib import Path

from controller.collector_profile import prepare_collector_profile
from controller.launch_profile import prepare_platform_launch
from controller.qualify_diagnostics import RESTORATION_CHECK
from controller.qualify_guardian_startup import run_trial
from controller.qualify_labelled_split import trial_script as labelled_script
from controller.qualify_split import evaluate_running
from controller.telemetry_profile import prepare_telemetry_profile


def trial_script(target, closed_policy=True):
    if not closed_policy:
        raise ValueError("labelled watchdog requires the closed-policy fixture")
    inner = labelled_script("PROBE", True)
    marker = 'tries=0\nwhile ! PROBE --lab-labelled-close-roles "$CANON" > "$STATE/pause.json"; do'
    if inner.count(marker) != 1 or "LISA_LABELLED_INNER_END" in inner:
        raise RuntimeError("labelled fault point changed; review before running")
    position = inner.index(marker)
    inner = (
        inner[:position]
        + """echo '{"event":"labelled-fault-injected","point":"after_all_barriers_before_close","signal":9}'
kill -KILL $$
exit 8
"""
        + inner[position:]
    )
    # A distinct sh process has its own $$; the outer shell only observes its
    # exit and waits. It does not invoke the inner restore.sh as a fallback.
    outer = (
        r"""
set -eu
umask 077
test ! -d /bkupgrade/data/opt/lisa-station/state
test ! -d /run/lisa-station
[ "$(id -u)" = 0 ]
STAGE=$(mktemp -d /data/opt/lisa-controller-lab/labelled-watchdog.XXXXXX)
cat > "$STAGE/trial.sh" <<'LISA_LABELLED_INNER_END'
"""
        + inner
        + r"""
LISA_LABELLED_INNER_END
began=$(cut -d ' ' -f 1 /proc/uptime)
sh "$STAGE/trial.sh" >"$STAGE/events" 2>"$STAGE/error" &
child=$!
result=0; wait "$child" 2>/dev/null || result=$?
cat "$STAGE/events"
cat "$STAGE/error" >&2
[ "$result" = 137 ] || exit 8
grep -q '"event":"labelled-fault-injected"' "$STAGE/events"
[ -d /data/opt/lisa-lab/trial.lock ]
tries=0
while [ -d /data/opt/lisa-lab/trial.lock ]; do
    [ "$tries" -lt 220 ] || exit 9
    sleep .5; tries=$((tries+1))
done
tries=0
while :; do
    workers=$(PROBE --maind-pids)
    [ "$(echo "$workers" | wc -w)" != 4 ] || break
    [ "$tries" -lt 625 ] || exit 9
    sleep 1; tries=$((tries+1))
done
for worker in $workers; do
    [ "$(awk '/^Gid:/{print $2,$3,$4,$5}' /proc/$worker/status)" = '0 0 0 0' ]
    [ "$(awk '/^Seccomp:/{print $2}' /proc/$worker/status)" = 0 ]
done
"""
        + RESTORATION_CHECK
        + r"""
elapsed=$(awk -v began="$began" '{printf "%d",$1-began}' /proc/uptime)
printf '{"event":"labelled-watchdog-recovered","inner_exit":137,"elapsed_seconds":%s,"lock_released":true,"ordinary_workers":4,"ordinary_diagnostics":true,"capture_tool_used":false}\n' "$elapsed"
"""
    )
    return outer.replace("PROBE", target)


def evaluate_events(events, closed_policy=True):
    if not closed_policy or len(events) != 38 or any(not isinstance(row, dict) for row in events):
        return False
    fault, recovered = events[-2:]
    if fault != dict(event="labelled-fault-injected", point="after_all_barriers_before_close", signal=9):
        return False
    if recovered.get("event") != "labelled-watchdog-recovered" or any(
        recovered.get(key) is not value
        for key, value in (
            ("lock_released", True),
            ("ordinary_diagnostics", True),
            ("capture_tool_used", False),
        )
    ):
        return False
    if any(
        type(recovered.get(key)) is not int or recovered[key] != value
        for key, value in (("inner_exit", 137), ("ordinary_workers", 4))
    ):
        return False
    if type(recovered.get("elapsed_seconds")) is not int or not 90 <= recovered["elapsed_seconds"] <= 750:
        return False
    barriers = events[31:-2]
    flow, incomplete_group, incomplete_label, full, controls = barriers
    if (
        flow.get("event") != "label-flows-observed"
        or type(flow.get("entries")) is not int
        or not 1 <= flow["entries"] <= 16384
        or flow.get("label") != 1073741824
        or flow.get("arm_before_start") is not True
    ):
        return False
    for row, operation, result, verified in (
        (incomplete_group, "labelled-check-roles-policy", "failed", False),
        (incomplete_label, "check-roles-policy", "failed", False),
        (full, "labelled-check-roles-policy", "ok", True),
    ):
        if (
            row.get("event") != "station-service"
            or row.get("operation") != operation
            or row.get("result") != result
            or row.get("label_policy_verified") is not verified
            or row.get("closed_scope") != "guarded_roles"
            or row.get("isolation_verified") is not False
        ):
            return False
    if (
        controls.get("event") != "policy-controls"
        or controls.get("ipv4") is not True
        or controls.get("ipv6") is not True
    ):
        return False
    prefix = events[:31]
    services = [row for row in prefix if row.get("event") == "station-service"]
    expected = [
        ("labelled-start-telemetry", "denied"),
        ("arm-labels", "denied"),
        ("arm-labels", "ok"),
        ("start-telemetry", "denied"),
        ("labelled-start-telemetry", "ok"),
        ("labelled-start-collector", "ok"),
        ("labelled-start-platform", "ok"),
        ("labelled-start-platform", "busy"),
        ("labelled-start-diagnostics", "ok"),
        ("arm-labels", "busy"),
    ]
    expected += [
        ("labelled-inspect-" + role, "ok")
        for _ in range(4)
        for role in ("telemetry", "collector", "platform", "diagnostics")
    ]
    if [(row.get("operation"), row.get("result")) for row in services] != expected:
        return False
    for row in services:
        if row.get("isolation_verified") is not False:
            return False
        admitted = row["result"] == "ok"
        if (
            row.get("label_admission_verified") is not admitted
            or row.get("label_policy_verified") is not False
        ):
            return False
    bus = [row for row in prefix if row.get("event") == "split-diagnostics-bus"]
    samples = [row for row in prefix if row.get("event") == "startup-sample"]
    if (
        len(bus) != 1
        or bus[0].get("matched") is not True
        or any(
            row.get("event") not in {"station-service", "split-diagnostics-bus", "startup-sample"}
            for row in prefix
        )
    ):
        return False
    running = deepcopy(services[4:9] + services[10:])
    for row in running:
        row["operation"] = row["operation"][9:]
    return evaluate_running(running, samples)


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
        report_name="labelled-watchdog-qualification.json",
    )


if __name__ == "__main__":
    main()
