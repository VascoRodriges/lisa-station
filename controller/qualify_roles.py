"""Two real private epochs under the four guarded-role close barrier.

Original launcher/collector/telemetry are frozen then resumed with the same
identities. Other stock services stay ordinary Alice services; no whole-device
isolation is claimed. No microphone or application payload is opened.
"""

import argparse
from pathlib import Path

from controller.collector_profile import prepare_collector_profile
from controller.qualify_collector import SCRIPT, run_trial
from controller.qualify_collector import evaluate_events as evaluate_collector
from controller.telemetry_profile import prepare_telemetry_profile


def paired_collector_profile(stock, *, lab_clone=False):
    profile = prepare_collector_profile(stock, lab_clone=lab_clone)
    if lab_clone:
        try:
            for name, original, private in (("metricad", 9887, 57345), ("metrica2d", 9904, 57346)):
                if profile[name]["port"] != original:
                    raise ValueError("unreviewed telemetry peer port")
                profile[name]["port"] = private
        except (KeyError, TypeError) as error:
            raise ValueError("missing telemetry peer configuration") from error
    return profile


def trial_script():
    script = SCRIPT

    def replace(old, new, count=1):
        nonlocal script
        if script.count(old) != count:
            raise RuntimeError("epoch template changed; review composite recovery")
        script = script.replace(old, new)

    body = SCRIPT.split("role_processes() {", 1)[1].split("\ntagged() {", 1)[0]
    replace(
        "tagged() {",
        "telemetry_processes() {" + body.replace("--fluent-bitd", "--telemetry") + "\ntagged() {",
    )
    replace("if($i==57344)", "if($i>=57342 && $i<=57345)", 2)
    replace("/:E000$/", "/:(E000|E001|E002)$/")
    replace(
        "original=$(role_processes); parent=$(pidof quasar_launcher2)",
        """original=$(role_processes); parent=$(pidof quasar_launcher2)
second=$(telemetry_processes)
[ "$(echo "$second" | wc -w)" = 1 ]
[ "$(awk '{print $4}' /proc/$second/stat)" = "$parent" ]
case "$(awk '{print $3}' /proc/$second/stat)" in R|S) :;; *) exit 3;; esac""",
    )
    replace(
        'mkdir "$STATE/state" "$STATE/run" "$STATE/collector-root"',
        '''mkdir "$STATE/state" "$STATE/run" "$STATE/collector-root" "$STATE/telemetry-root"
cp @TELEMETRY@ "$STATE/telemetry-profile.json"; chmod 600 "$STATE/telemetry-profile.json"''',
    )
    marker = (
        r'''printf '%s %s\n' "$original" "$(awk '{print $22}' "/proc/$original/stat")" > "$STATE/original"'''
    )
    replace(
        marker,
        marker
        + r'''
printf '%s %s\n' "$second" "$(awk '{print $22}' /proc/$second/stat)" > "$STATE/second"''',
    )
    marker = '"$helper" --lab-stop-collector "$canonical" >/dev/null 2>&1 || :'
    replace(marker, marker + '\n"$helper" --lab-stop-telemetry "$canonical" >/dev/null 2>&1 || :')
    replace(
        '    set -- $(cat "$STATE/parent"); process=$1; ticks=$2',
        """    set -- $(cat "$STATE/second"); process=$1; ticks=$2
    [ "$(awk '{print $22}' /proc/$process/stat)" = "$ticks" ] || exit 9
    [ "$(readlink /proc/$process/exe)" = /system/vendor/quasar/maind ] || exit 9
    kill -CONT "$process" || exit 9
    set -- $(cat "$STATE/parent"); process=$1; ticks=$2""",
    )
    marker = 'kill -STOP "$parent"; kill -STOP "$original"'
    replace(marker, marker + '; kill -STOP "$second"')
    marker = 'cat "$STATE/unmanaged.json"'
    replace(
        marker,
        marker
        + '''
code=0
PROBE --lab-start-telemetry "$CANON" > "$STATE/unmanaged-telemetry.json" || code=$?
[ "$code" != 0 ] && grep -q '"result":"busy"' "$STATE/unmanaged-telemetry.json"
cat "$STATE/unmanaged-telemetry.json"''',
    )
    replace(
        """    "$tool" -A "$CHAIN" -m owner --gid-owner 57344 -d "$network" -j RETURN
    "$tool" -A "$CHAIN" -m owner --gid-owner 57344 -j DROP""",
        """    for group in 57342 57343 57344 57345; do
        "$tool" -A "$CHAIN" -m owner --gid-owner "$group" -d "$network" -j RETURN
        "$tool" -A "$CHAIN" -m owner --gid-owner "$group" -j DROP
    done""",
    )
    marker = 'cat "$STATE/duplicate.json"'
    replace(
        marker,
        marker
        + '''
PROBE --lab-start-telemetry "$CANON"
code=0
PROBE --lab-start-telemetry "$CANON" > "$STATE/duplicate-telemetry.json" || code=$?
[ "$code" != 0 ] && grep -q '"result":"busy"' "$STATE/duplicate-telemetry.json"
cat "$STATE/duplicate-telemetry.json"''',
    )
    collector_start = '''PROBE --lab-start-collector "$CANON"
code=0
PROBE --lab-start-collector "$CANON" > "$STATE/duplicate.json" || code=$?
[ "$code" != 0 ] && grep -q '"result":"busy"' "$STATE/duplicate.json"
cat "$STATE/duplicate.json"'''
    telemetry_start = '''PROBE --lab-start-telemetry "$CANON"
code=0
PROBE --lab-start-telemetry "$CANON" > "$STATE/duplicate-telemetry.json" || code=$?
[ "$code" != 0 ] && grep -q '"result":"busy"' "$STATE/duplicate-telemetry.json"
cat "$STATE/duplicate-telemetry.json"'''
    ready_telemetry = """tries=0
while ! PROBE --lab-inspect-telemetry "$CANON" > "$STATE/telemetry-readiness.json"; do
    [ "$tries" -lt 15 ] || exit 8; sleep 1; tries=$((tries+1))
done"""
    # The collector's SDK must reach this private receiver, not the deliberately
    # frozen stock port. Start/observe the receiver before starting its client.
    replace(
        collector_start + "\n" + telemetry_start,
        telemetry_start + "\n" + ready_telemetry + "\n" + collector_start,
    )
    collector_ready = """while ! PROBE --lab-inspect-collector "$CANON" > "$STATE/readiness.json"; do
    [ "$tries" -lt 15 ] || exit 8; sleep 1; tries=$((tries+1))"""
    # File/FD metadata showed the private SQLite queue was not created yet at
    # the old deadline. Permit cold SDK/input initialization; do not weaken any
    # readiness condition or reuse a successful observation from another actor.
    replace(collector_ready, collector_ready.replace('"$tries" -lt 15', '"$tries" -lt 25'))
    replace(
        'for sample in 1 2 3; do sleep 2; PROBE --lab-inspect-collector "$CANON"; done',
        """tries=0
while ! PROBE --lab-inspect-telemetry "$CANON" > "$STATE/telemetry-readiness.json"; do
    [ "$tries" -lt 15 ] || exit 8; sleep 1; tries=$((tries+1))
done
for sample in 1 2 3; do
    sleep 1
    PROBE --lab-inspect-collector "$CANON"
    PROBE --lab-inspect-telemetry "$CANON"
done""",
    )
    first = '''printf '%s\\n' "$CHAIN" > "$STATE/run/policy.chain"'''
    closing = SCRIPT.split(first, 1)[1].split('PROBE --lab-close-collector "$CANON"', 1)[0]
    replace(
        first + closing + 'PROBE --lab-close-collector "$CANON"',
        first
        + '''
for version in 4 6; do
    tool=iptables; network=127.0.0.0/8
    if [ "$version" = 6 ]; then tool=ip6tables; network=::1/128; fi
    for group in 57342 57343 57344 57345; do
        "$tool" -D "$CHAIN" -m owner --gid-owner "$group" -d "$network" -j RETURN
    done
done
ip6tables -D "$CHAIN" -m owner --gid-owner 57345 -j DROP
code=0
PROBE --lab-check-roles-policy "$CANON" > "$STATE/partial.json" || code=$?
[ "$code" != 0 ] && grep -q '"result":"failed"' "$STATE/partial.json"
[ ! -e "$STATE/state/closed.request" ]; cat "$STATE/partial.json"
ip6tables -A "$CHAIN" -m owner --gid-owner 57345 -j DROP
PROBE --lab-check-roles-policy "$CANON"
PROBE --lab-close-roles "$CANON"''',
    )
    marker = 'cat "$STATE/reconcile.json"'
    replace(
        marker,
        marker
        + '''
tries=0
while ! PROBE --lab-reconcile-telemetry "$CANON" > "$STATE/reconcile-telemetry.json"; do
    [ "$tries" -lt 20 ] || exit 8; sleep .05; tries=$((tries+1))
done
cat "$STATE/reconcile-telemetry.json"''',
    )
    marker = 'cat "$STATE/denied.json"'
    replace(
        marker,
        marker
        + '''
code=0
PROBE --lab-start-telemetry "$CANON" > "$STATE/denied-telemetry.json" || code=$?
[ "$code" != 0 ] && grep -q '"result":"denied"' "$STATE/denied-telemetry.json"
cat "$STATE/denied-telemetry.json"''',
    )
    marker = '[ -z "$(ls -A "$STATE/collector-root")" ]'
    replace(
        marker,
        marker
        + """
[ "$(telemetry_processes)" = "$second" ]
case "$(awk '{print $3}' /proc/$second/stat)" in R|S) :;; *) exit 9;; esac
[ -z "$(ls -A "$STATE/telemetry-root")" ]""",
    )
    return script.replace('"collector-stopped"', '"roles-stopped"').replace(
        '"collector-restored"', '"roles-restored"'
    )


def evaluate_events(events):
    if len(events) != 22 or any(not isinstance(row, dict) for row in events):
        return False
    starts = [
        row
        for row in events
        if row.get("operation") in {"start-collector", "start-telemetry"} and row.get("result") == "ok"
    ]
    identities = [row.get(field) for row in starts for field in ("child_pid", "guardian_pid")]
    if (
        len(starts) != 2
        or any(type(value) is not int or value < 2 for value in identities)
        or len(set(identities)) != 4
    ):
        return False
    for role in ("collector", "telemetry"):
        projected = []
        for row in events:
            item = dict(row)
            if row.get("event") == "station-service":
                operation = row.get("operation", "")
                if not isinstance(operation, str):
                    return False
                if operation in {"check-roles-policy", "close-roles"}:
                    if row.get("closed_scope") != "guarded_roles":
                        return False
                    item["operation"] = operation.replace("roles", "collector")
                elif operation.endswith("-" + role):
                    item["operation"] = operation.replace(role, "collector")
                else:
                    continue
                item["collector_jail_verified"] = row.get(role + "_jail_verified", False)
            elif row.get("event") in {"roles-stopped", "roles-restored"}:
                item["event"] = row["event"].replace("roles", "collector")
            projected.append(item)
        if not evaluate_collector(projected):
            return False
    return True


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("host")
    parser.add_argument("--ssh-config", type=Path)
    parser.add_argument("--allow-temporary-epoch-freeze", action="store_true", required=True)
    run_trial(
        parser.parse_args(),
        "collector",
        trial_script(),
        paired_collector_profile,
        evaluate_events,
        additional_profiles={"TELEMETRY": prepare_telemetry_profile},
        report_name="roles",
    )


if __name__ == "__main__":
    main()
