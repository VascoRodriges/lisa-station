"""Bounded common supervisor must close a corrupt intent without parsing it."""

import argparse
from pathlib import Path

from controller.qualify_emergency import STAGES, evaluate_native, run_trial
from controller.qualify_emergency import trial_script as emergency_trial

READER_AND_FAULT = r"""
exec 8<>"$STATE/run/epoch.lock"; flock -x 8
tries=0
while ! grep -q '"event":"supervisor-scope-busy"' "$STATE/watch.events"; do
    kill -0 "$watch_pid"; [ "$tries" -lt 100 ] || exit 8
    sleep .05; tries=$((tries+1))
done
grep -qx 'LISA_MODE_V1 2 alice' "$STATE/state/mode.state"
test -f "$STATE/run/vendor.permit"; test ! -e "$STATE/state/fault.request"
echo '{"event":"supervisor-reader-proof","mode_unchanged":true,"permit_retained":true,"fault_absent":true}'
exec 8>&-
# Serialize the three injected corruptions with the supervisor's inspection.
exec 7<>"$STATE/state/transition.lock"; flock -x 7
printf 'damaged mode\n' > "$STATE/state/mode.state.new"
mv "$STATE/state/mode.state.new" "$STATE/state/mode.state"
printf 'damaged owner\n' > "$STATE/run/epoch.owner.new"
mv "$STATE/run/epoch.owner.new" "$STATE/run/epoch.owner"
printf 'damaged epoch\n' > "$STATE/run/epoch.state.new"
mv "$STATE/run/epoch.state.new" "$STATE/run/epoch.state"
exec 7>&-
"""


def trial_script():
    script = emergency_trial()
    if script.count(STAGES) != 1:
        raise RuntimeError("Emergency body changed; review supervisor trial")
    body = STAGES.replace('--lab-watch-emergency "$CANON" 120', '--lab-supervise "$CANON" 120')
    body = body.replace(
        'cp "$STATE/run/epoch.state" "$STATE/epoch.before"',
        'cp "$STATE/run/epoch.state" "$STATE/epoch.before"\ncp "$STATE/state/mode.state" "$STATE/mode.before"',
    )
    start = body.index("printf 'damaged owner")
    end = body.index('result=0; wait "$watch_pid"', start)
    body = body[:start] + READER_AND_FAULT + body[end:]
    body = body.replace(
        "grep -qx 'damaged owner'", "run_coord --lab-emergency-resume \"$CANON\"\ngrep -qx 'damaged owner'"
    )
    # Replace only the post-fault preservation assertion, not the live reader proof.
    at = body.index('[ "$result" = 4 ]; printf \'{"event":"emergency-watch-exit"')
    body = body[:at] + body[at:].replace("grep -qx 'LISA_MODE_V1 2 alice'", "grep -qx 'damaged mode'", 1)
    body = body.replace(
        '{"event":"emergency-preserved","damaged_primary":true,"intent_unchanged":true,"fault_persisted":true,"permit_absent":true}',
        '{"event":"supervisor-preserved","damaged_mode":true,"damaged_primary":true,"fault_persisted":true,"permit_absent":true}',
    )
    restore = 'cp "$STATE/mode.before" "$STATE/state/mode.state.new"; mv "$STATE/state/mode.state.new" "$STATE/state/mode.state"\n'
    body = body.replace(
        'cp "$STATE/owner.initial" "$STATE/run/epoch.owner.new";',
        restore + 'cp "$STATE/owner.initial" "$STATE/run/epoch.owner.new";',
    )
    restart = r"""result=0; run_coord --lab-supervise-recover "$CANON" 120 || result=$?
[ "$result" = 4 ]; printf '{"event":"supervisor-restart-exit","code":%s}\n' "$result"
"""
    body = body.replace('run_coord --lab-emergency-resume "$CANON"\n', restart)
    return script.replace(STAGES, body)


def evaluate_events(events):
    if not isinstance(events, list) or len(events) != 39 or any(type(row) is not dict for row in events):
        return False

    def exact(index, row):
        return events[index] == row and all(type(events[index].get(k)) is type(v) for k, v in row.items())

    def stage(
        index, op, result, revision, epoch, mode, requested, phase, choice, closed, opened, permit, steps
    ):
        return exact(
            index,
            dict(
                event="epoch-mutation",
                operation=op,
                result=result,
                phase=phase,
                revision=revision,
                epoch=epoch,
                mode_revision=mode,
                requested_mode=requested,
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

    if not all(
        [
            stage(0, "reserve", "ok", 1, 1, 1, "paused", "closed", "paused", True, False, False, 36),
            stage(1, "open", "ok", 2, 2, 2, "alice", "open", "alice", False, True, True, 32),
            exact(
                2,
                dict(
                    event="epoch-attributed",
                    family="ipv4",
                    protocol="udp",
                    phase="old",
                    epoch=2,
                    mark=2 << 24,
                    ok=True,
                ),
            ),
            exact(
                3,
                dict(
                    event="supervisor-reader-proof",
                    mode_unchanged=True,
                    permit_retained=True,
                    fault_absent=True,
                ),
            ),
            exact(4, dict(event="recovery-watch", state="ready", deadline_seconds=120)),
            exact(
                7,
                dict(
                    event="supervisor-fault",
                    result="closed",
                    reason="journals",
                    barrier_verified=True,
                    permit_revoked=True,
                    fault_synced=True,
                    actors_absent=True,
                    automatic_open=False,
                    audio_opened=False,
                    isolation_verified=False,
                ),
            ),
            stage(9, "supervise", "denied", 0, 0, 0, "unknown", "unknown", "paused", None, None, False, 0),
            exact(10, dict(event="emergency-watch-exit", code=4)),
            exact(11, dict(event="recovery-watch", state="ready", deadline_seconds=120)),
            exact(
                12,
                dict(
                    event="supervisor-fault",
                    result="closed",
                    reason="journals",
                    barrier_verified=True,
                    permit_revoked=True,
                    fault_synced=True,
                    actors_absent=True,
                    automatic_open=False,
                    audio_opened=False,
                    isolation_verified=False,
                ),
            ),
            exact(
                13,
                dict(
                    event="recovery-watch-summary",
                    busy_polls=0,
                    idle_polls=0,
                    recovered=0,
                    faults=1,
                    stopped=False,
                    automatic_open=False,
                    audio_opened=False,
                ),
            ),
            stage(
                14,
                "supervise-recover",
                "denied",
                0,
                0,
                0,
                "unknown",
                "unknown",
                "paused",
                None,
                None,
                False,
                0,
            ),
            exact(15, dict(event="supervisor-restart-exit", code=4)),
            exact(
                16,
                dict(
                    event="supervisor-preserved",
                    damaged_mode=True,
                    damaged_primary=True,
                    fault_persisted=True,
                    permit_absent=True,
                ),
            ),
            stage(17, "open", "denied", 2, 2, 2, "alice", "open", "paused", False, False, False, 0),
            exact(18, dict(event="emergency-open-exit", code=4)),
            exact(38, dict(event="emergency-cleanup", ok=True)),
        ]
    ):
        return False
    busy_rows = [dict(event="recovery-watch", state="busy"), dict(event="supervisor-scope-busy")]
    if events[5:7] not in [busy_rows, busy_rows[::-1]]:
        return False
    summary = events[8]
    if set(summary) != {
        "event",
        "busy_polls",
        "idle_polls",
        "recovered",
        "faults",
        "stopped",
        "automatic_open",
        "audio_opened",
    }:
        return False
    if not (
        summary["event"] == "recovery-watch-summary"
        and all(type(summary[k]) is int for k in ["busy_polls", "idle_polls", "recovered", "faults"])
        and summary["busy_polls"] > 0
        and summary["idle_polls"] > 0
        and summary["recovered"] == 0
        and summary["faults"] == 1
        and all(summary[k] is False for k in ["stopped", "automatic_open", "audio_opened"])
    ):
        return False
    return evaluate_native(events[19:38])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("host")
    parser.add_argument("--ssh-config", type=Path)
    parser.add_argument("--run-private-supervisor-trial", action="store_true", required=True)
    args = parser.parse_args()
    run_trial(args.host, args.ssh_config, trial_script(), evaluate_events, "supervisor")


if __name__ == "__main__":
    main()
