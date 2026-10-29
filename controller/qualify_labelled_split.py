"""Four real guarded roles with marking armed before their socket creation.

Bounded uninstalled-only trial, explicit stock restoration, no audio capture.
This does not cover prior unmanaged flows or constitute boot enforcement.
"""

import argparse
from copy import deepcopy
from pathlib import Path

from controller.collector_profile import prepare_collector_profile
from controller.launch_profile import prepare_platform_launch
from controller.qualify_guardian_startup import run_trial
from controller.qualify_split import evaluate_events as split_evaluate
from controller.qualify_split import trial_script as split_script
from controller.telemetry_profile import prepare_telemetry_profile


def trial_script(target, closed_policy=True):
    if not closed_policy:
        raise ValueError("labelled startup requires the complete closed policy")
    script = split_script("PROBE", True)

    def replace(old, new, count=1):
        nonlocal script
        if script.count(old) != count:
            raise RuntimeError("split template changed; review labelled restoration")
        script = script.replace(old, new)

    # The lab begins without any installed label user. Leave old unmanaged
    # connections alone; an occupied label is a reason to refuse this fixture.
    replace(
        "mkdir /data/opt/lisa-lab/trial.lock || exit 4",
        """if iptables-save | grep -E 'CONNMARK|connmark' >/dev/null; then exit 3; fi
if ip6tables-save | grep -E 'CONNMARK|connmark' >/dev/null; then exit 3; fi
if ! awk '{for(i=1;i<=NF;i++) if($i~/^mark=/) {split($i,a,"="); if(int(a[2]/1073741824)%2) bad=1}} END{exit bad}' /proc/net/nf_conntrack; then
    echo 'The fixture label remains in conntrack; wait for its normal expiry.' >&2; exit 3
fi
mkdir /data/opt/lisa-lab/trial.lock || exit 4""",
    )
    marker = '        if "$tool" -S "$chain" >/dev/null 2>&1; then exit 9; fi'
    replace(
        marker,
        marker
        + """
        label=LISACL_$suffix; mark=LISACM_$suffix
        for hook in INPUT OUTPUT; do
            if [ -f "$STATE/label-$version-$hook" ] && "$tool" -C "$hook" -j "$label" >/dev/null 2>&1; then
                "$tool" -D "$hook" -j "$label" || exit 9
            fi
        done
        if [ -f "$STATE/mark-hook-$version" ] && "$tool" -t mangle -C OUTPUT -j "$mark" >/dev/null 2>&1; then
            "$tool" -t mangle -D OUTPUT -j "$mark" || exit 9
        fi
        if [ -f "$STATE/label-chain-$version" ] && "$tool" -S "$label" >/dev/null 2>&1; then
            "$tool" -F "$label" && "$tool" -X "$label" || exit 9
        fi
        if [ -f "$STATE/mark-chain-$version" ] && "$tool" -t mangle -S "$mark" >/dev/null 2>&1; then
            "$tool" -t mangle -F "$mark" && "$tool" -t mangle -X "$mark" || exit 9
        fi""",
    )
    # Move the name before first startup; the existing close script reuses it.
    replace("CHAIN=LISACQ_$$\n", "")
    marker = 'PROBE --lab-start-telemetry "$CANON"'
    replace(
        marker,
        '''CHAIN=LISACQ_$$
MARK=LISACM_$$; LABEL=LISACL_$$
printf '%s\\n' "$CHAIN" > "$STATE/chain"
printf '%s\\n' "$CHAIN" > "$STATE/run/policy.chain"
rejected=0
PROBE --lab-labelled-start-telemetry "$CANON" > "$STATE/unarmed.json" || rejected=$?
[ "$rejected" != 0 ] && grep -q '"result":"denied"' "$STATE/unarmed.json"
cat "$STATE/unarmed.json"
for version in 4 6; do
    tool=iptables; [ "$version" = 4 ] || tool=ip6tables
    if "$tool" -t mangle -S "$MARK" >/dev/null 2>&1 || "$tool" -S "$LABEL" >/dev/null 2>&1; then exit 8; fi
    touch "$STATE/mark-chain-$version"; "$tool" -t mangle -N "$MARK"
    for group in 57342 57343 57344 57345; do
        "$tool" -t mangle -A "$MARK" -m owner --gid-owner "$group" -j CONNMARK --set-xmark 0x40000000/0x40000000
    done
    touch "$STATE/mark-hook-$version"; "$tool" -t mangle -I OUTPUT 1 -j "$MARK"
    if [ "$version" = 4 ]; then
        rejected=0
        PROBE --lab-arm-labels "$CANON" > "$STATE/missing-mark-v6.json" || rejected=$?
        [ "$rejected" != 0 ] && grep -q '"result":"denied"' "$STATE/missing-mark-v6.json"
        cat "$STATE/missing-mark-v6.json"
        [ ! -e "$STATE/run/label.arm" ]
    fi
done
PROBE --lab-arm-labels "$CANON"
rejected=0
PROBE --lab-start-telemetry "$CANON" > "$STATE/downgrade-start.json" || rejected=$?
[ "$rejected" != 0 ] && grep -q '"result":"denied"' "$STATE/downgrade-start.json"
cat "$STATE/downgrade-start.json"
PROBE --lab-labelled-start-telemetry "$CANON"''',
    )
    for role in ("collector", "platform", "diagnostics"):
        replace("--lab-start-" + role, "--lab-labelled-start-" + role, 3 if role == "platform" else 1)
    replace('PROBE --lab-inspect-platform "$CANON"', 'PROBE --lab-labelled-inspect-platform "$CANON"')
    replace('PROBE --lab-inspect-diagnostics "$CANON"', 'PROBE --lab-labelled-inspect-diagnostics "$CANON"')
    replace('PROBE --lab-inspect-$role "$CANON"', 'PROBE --lab-labelled-inspect-$role "$CANON"')
    replace(
        'echo \'{"event":"split-diagnostics-bus","matched":true}\'',
        '''echo '{"event":"split-diagnostics-bus","matched":true}'
busy=0
PROBE --lab-arm-labels "$CANON" > "$STATE/late-arm.json" || busy=$?
[ "$busy" != 0 ] && grep -q '"result":"busy"' "$STATE/late-arm.json"
cat "$STATE/late-arm.json"''',
    )
    replace("CHAIN=LISACQ_$$", "CHAIN=LISACQ_$$")  # Assert the single moved definition.
    marker = 'touch "$STATE/chain-4"; iptables -N "$CHAIN"'
    replace(
        marker,
        """entries=$(awk '{for(i=1;i<=NF;i++) if($i=="mark=1073741824") count++} END{print count+0}' /proc/net/nf_conntrack)
[ "$entries" -gt 0 ]
printf '{"event":"label-flows-observed","entries":%s,"label":1073741824,"arm_before_start":true}\\n' "$entries"
"""
        + marker,
    )
    replace("--lab-check-roles-policy", "--lab-labelled-check-roles-policy", 2)
    marker = 'PROBE --lab-labelled-check-roles-policy "$CANON"\n'
    replace(
        marker,
        """for version in 4 6; do
    tool=iptables; [ "$version" = 4 ] || tool=ip6tables
    touch "$STATE/label-chain-$version"; "$tool" -N "$LABEL"
    "$tool" -A "$LABEL" -m connmark --mark 0x40000000/0x40000000 -j DROP
    touch "$STATE/label-$version-INPUT"; "$tool" -I INPUT 1 -j "$LABEL"
    touch "$STATE/label-$version-OUTPUT"; "$tool" -I OUTPUT 2 -j "$LABEL"
    if [ "$version" = 4 ]; then
        rejected=0
        PROBE --lab-check-roles-policy "$CANON" > "$STATE/missing-label-v6.json" || rejected=$?
        [ "$rejected" != 0 ] && grep -q '"result":"failed"' "$STATE/missing-label-v6.json"
        cat "$STATE/missing-label-v6.json"
        [ ! -e "$STATE/state/closed.request" ]
    fi
done
"""
        + marker,
    )
    replace("--lab-close-roles", "--lab-labelled-close-roles")
    return script.replace("PROBE", target)


def evaluate_events(events, closed_policy=True):
    if not closed_policy or len(events) != 44 or any(not isinstance(row, dict) for row in events):
        return False
    rows = deepcopy(events)
    service = [row for row in rows if row.get("event") == "station-service"]
    if any(row.get("isolation_verified") is not False for row in service):
        return False
    arm = [row for row in service if row.get("operation") == "arm-labels"]
    if [row.get("result") for row in arm] != ["denied", "ok", "busy"] or any(
        row.get("label_admission_verified") is not (row["result"] == "ok") for row in arm
    ):
        return False
    initial = [
        row
        for row in service
        if row.get("operation") in {"labelled-start-telemetry", "start-telemetry"}
        and row.get("result") == "denied"
    ]
    if [row["operation"] for row in initial] != ["labelled-start-telemetry", "start-telemetry"]:
        return False
    if any(row.get("label_admission_verified") is not False for row in initial):
        return False
    legacy_check = [row for row in service if row.get("operation") == "check-roles-policy"]
    if (
        len(legacy_check) != 1
        or legacy_check[0].get("result") != "failed"
        or legacy_check[0].get("label_policy_verified") is not False
    ):
        return False
    observed = [row for row in rows if row.get("event") == "label-flows-observed"]
    if (
        len(observed) != 1
        or type(observed[0].get("entries")) is not int
        or not 1 <= observed[0]["entries"] <= 16384
        or observed[0].get("label") != 1073741824
        or observed[0].get("arm_before_start") is not True
    ):
        return False
    # The root backend, not an echo alone, establishes the admission order.
    armed = rows.index(arm[1])
    if any(
        rows.index(row) < armed
        for row in service
        if row.get("operation", "").startswith("labelled-start-") and row.get("result") == "ok"
    ):
        return False
    remove = arm + initial + legacy_check + observed
    base = [row for row in rows if row not in remove]
    for row in base:
        operation = row.get("operation", "")
        if operation.startswith(("start-", "inspect-")) or operation in {"close-roles", "check-roles-policy"}:
            return False
        if operation.startswith(("labelled-start-", "labelled-inspect-")) and row.get("result") == "ok":
            if row.get("label_admission_verified") is not True:
                return False
        if operation in {"labelled-close-roles", "labelled-check-roles-policy"} and row.get("result") == "ok":
            if row.get("label_policy_verified") is not True:
                return False
        if operation.startswith("labelled-"):
            row["operation"] = operation[9:]
    return split_evaluate(base, True)


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
        report_name="labelled-split-qualification.json",
    )


if __name__ == "__main__":
    main()
