"""Own-flow recovery across nine emergency checkpoints and fresh coordinators."""

import argparse
from pathlib import Path

from controller.qualify_emergency import STAGES, evaluate_native, run_trial
from controller.qualify_emergency import trial_script as emergency_trial

RECOVERY = r"""
step=2
while [ "$step" -le 9 ]; do
    result=0; run_coord --lab-emergency-resume "$CANON" "$step" || result=$?
    [ "$result" = 137 ]; printf '{"event":"restart-worker-exit","step":%s,"code":%s}\n' "$step" "$result"
    if [ "$step" = 8 ]; then
        printf c >&3; wait_event emergency
        attributed retained 2 old
    fi
    step=$((step+1))
done
run_coord --lab-emergency-resume "$CANON"
protected_rules() { iptables -S; iptables -t mangle -S; ip6tables -S; ip6tables -t mangle -S; }
protected_rules > "$STATE/rules.before-refusal"
chmod 644 "$STATE/run/emergency.owner"
result=0; run_coord --lab-emergency-resume "$CANON" || result=$?
chmod 600 "$STATE/run/emergency.owner"
protected_rules > "$STATE/rules.after-refusal"
cmp -s "$STATE/rules.before-refusal" "$STATE/rules.after-refusal"
[ "$result" = 4 ]; printf '{"event":"restart-owner-refused","case":"public_mode","code":%s,"rules_unchanged":true}\n' "$result"
ln "$STATE/run/emergency.owner" "$STATE/run/emergency.alias"
result=0; run_coord --lab-emergency-resume "$CANON" || result=$?
rm "$STATE/run/emergency.alias"
protected_rules > "$STATE/rules.after-refusal"
cmp -s "$STATE/rules.before-refusal" "$STATE/rules.after-refusal"
[ "$result" = 4 ]; printf '{"event":"restart-owner-refused","case":"hardlink","code":%s,"rules_unchanged":true}\n' "$result"
run_coord --lab-emergency-resume "$CANON"
"""


def trial_script():
    script = emergency_trial()
    if script.count(STAGES) != 1:
        raise RuntimeError("Emergency body changed; review restart boundaries")
    body = STAGES.replace('--lab-watch-emergency "$CANON" 120', '--lab-watch-emergency-crash "$CANON" 120 1')
    body = body.replace(
        '[ "$result" = 4 ]; printf \'{"event":"emergency-watch-exit"',
        '[ "$result" = 137 ]; printf \'{"event":"emergency-watch-exit"',
    )
    point = "grep -qx 'damaged owner'"
    if body.count(point) != 1:
        raise RuntimeError("Primary-preservation check changed")
    at = body.index(point)
    body = body[:at] + RECOVERY + body[at:]
    body = body.replace("printf c >&3; wait_event emergency\nprintf r >&3;", "printf r >&3;")
    return script.replace(STAGES, body)


def evaluate_events(events):
    if not isinstance(events, list) or any(type(row) is not dict for row in events):
        return False
    # A valid opening may contend with the watcher before the first fault.
    if len(events) == 53:
        if events[4] != dict(event="recovery-watch", state="busy"):
            return False
        events = events[:4] + events[5:]
    if len(events) != 52:
        return False

    def exact(index, row):
        return events[index] == row and all(type(events[index].get(k)) is type(v) for k, v in row.items())

    def stage(index, op, result, rev, epoch, choice, closed, opened, permit, steps):
        return exact(
            index,
            dict(
                event="epoch-mutation",
                operation=op,
                result=result,
                phase="closed" if rev == 1 else "open",
                revision=rev,
                epoch=epoch,
                mode_revision=rev,
                requested_mode="paused" if rev == 1 else "alice",
                boot_choice=choice,
                opening_pending=False,
                permit_valid=permit,
                policy_closed=closed,
                policy_open=opened,
                mutation_steps=steps,
                control_ipv4=True,
                control_ipv6=True,
                vendor_started=False,
                stock_fallback=False,
                audio_opened=False,
                isolation_verified=False,
            ),
        )

    if not stage(0, "reserve", "ok", 1, 1, "paused", True, False, False, 36) or not stage(
        1, "open", "ok", 2, 2, "alice", False, True, True, 32
    ):
        return False

    def attribute(phase):
        return dict(
            event="epoch-attributed",
            family="ipv4",
            protocol="udp",
            phase=phase,
            epoch=2,
            mark=2 << 24,
            ok=True,
        )

    if not exact(2, attribute("old")) or not exact(
        3, dict(event="recovery-watch", state="ready", deadline_seconds=120)
    ):
        return False
    at = 4
    for step in range(1, 10):
        if not exact(
            at,
            dict(
                event="emergency-checkpoint",
                step=step,
                fault_present=True,
                permit_absent=step == 9,
                policy_closed=step >= 7,
                control_ipv4=True,
                control_ipv6=True,
            ),
        ):
            return False
        at += 1
        exited = (
            dict(event="emergency-watch-exit", code=137)
            if step == 1
            else dict(event="restart-worker-exit", step=step, code=137)
        )
        if not exact(at, exited):
            return False
        at += 1
        if step == 8:
            if not exact(at, attribute("retained")):
                return False
            at += 1

    def resumed(index, ok):
        return exact(
            index,
            dict(
                event="emergency-resume",
                result="ok" if ok else "denied",
                cache_reconstructed=ok,
                fault_valid=ok,
                policy_closed=True if ok else None,
                permit_absent=True,
                control_ipv4=True,
                control_ipv6=True,
                automatic_open=False,
                audio_opened=False,
                isolation_verified=False,
            ),
        )

    if not resumed(at, True):
        return False
    at += 1
    for case in ["public_mode", "hardlink"]:
        if not resumed(at, False) or not exact(
            at + 1, dict(event="restart-owner-refused", case=case, code=4, rules_unchanged=True)
        ):
            return False
        at += 2
    if not resumed(at, True):
        return False
    at += 1
    if not exact(
        at,
        dict(
            event="emergency-preserved",
            damaged_primary=True,
            intent_unchanged=True,
            fault_persisted=True,
            permit_absent=True,
        ),
    ):
        return False
    at += 1
    if not stage(at, "open", "denied", 2, 2, "paused", False, False, False, 0) or not exact(
        at + 1, dict(event="emergency-open-exit", code=4)
    ):
        return False
    at += 2
    return (
        at == 32
        and evaluate_native(events[at : at + 19])
        and exact(51, dict(event="emergency-cleanup", ok=True))
    )


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("host")
    parser.add_argument("--ssh-config", type=Path)
    parser.add_argument("--run-private-restart-trial", action="store_true", required=True)
    args = parser.parse_args()
    run_trial(args.host, args.ssh_config, trial_script(), evaluate_events, "emergency-restart")


if __name__ == "__main__":
    main()
