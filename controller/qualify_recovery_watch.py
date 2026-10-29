"""Bounded local watcher must recover a dead worker without reopening Alice."""

import argparse
import hashlib
import json
import subprocess
from pathlib import Path

from controller.qualify_epoch_mutation import BODY
from controller.qualify_epoch_mutation import trial_script as composed_trial
from controller.qualify_socket_close import rules_only

STOP = r"""
stop_auxiliaries() {
    for record in watch-child held-child worker-child; do
        [ -f "$STATE/$record" ] || continue
        set -- $(cat "$STATE/$record"); managed_pid=$1; managed_ticks=$2
        if [ "$(awk '{print $22}' /proc/"$managed_pid"/stat 2>/dev/null || true)" = "$managed_ticks" ] && [ "$(readlink /proc/"$managed_pid"/exe)" = COORD ]; then
            kill -TERM "$managed_pid" || true
            tries=0
            while [ "$(awk '{print $22}' /proc/"$managed_pid"/stat 2>/dev/null || true)" = "$managed_ticks" ]; do
                [ "$(awk '{print $3}' /proc/"$managed_pid"/stat 2>/dev/null || true)" != Z ] || break
                [ "$tries" -lt 100 ] || return 9
                sleep .05; tries=$((tries+1))
            done
            wait "$managed_pid" 2>/dev/null || true
        fi
    done
}
run_coord() {
    COORD "$@" & managed_pid=$!
    printf '%s %s\n' "$managed_pid" "$(awk '{print $22}' /proc/"$managed_pid"/stat 2>/dev/null || true)" > "$STATE/worker-child"
    managed_result=0; wait "$managed_pid" || managed_result=$?
    rm "$STATE/worker-child"
    return "$managed_result"
}
wait_file() {
    tries=0
    while [ ! -f "$1" ]; do
        kill -0 "$watch_pid"
        [ "$tries" -lt 200 ] || return 8
        sleep .05; tries=$((tries+1))
    done
}
wait_watch() {
    tries=0
    while ! grep -q '"state":"'"$1"'"' "$STATE/watch.events"; do
        kill -0 "$watch_pid"
        [ "$tries" -lt 400 ] || return 8
        sleep .05; tries=$((tries+1))
    done
}
wait_recoveries() {
    tries=0
    while [ "$(grep -c '"state":"recovered"' "$STATE/watch.events" || true)" -lt "$1" ]; do
        kill -0 "$watch_pid"
        [ "$tries" -lt 400 ] || return 8
        sleep .05; tries=$((tries+1))
    done
}
"""

STAGES = r"""
run_coord --lab-reserve "$CANON"
cp "$STATE/run/epoch.owner" "$STATE/owner.initial"
COORD --lab-watch "$CANON" 120 >"$STATE/watch.events" 2>"$STATE/watch.error" & watch_pid=$!
printf '%s %s\n' "$watch_pid" "$(awk '{print $22}' /proc/"$watch_pid"/stat)" > "$STATE/watch-child"
wait_file "$STATE/run/watch.ready"
COORD --lab-open-hold "$CANON" 1 3 >"$STATE/held.events" 2>"$STATE/held.error" & held_pid=$!
printf '%s %s\n' "$held_pid" "$(awk '{print $22}' /proc/"$held_pid"/stat)" > "$STATE/held-child"
wait_file "$STATE/run/hold.ready"; wait_watch busy
kill -0 "$held_pid"
grep -qx 'LISA_MODE_V1 1 paused' "$STATE/state/mode.state"
test -f "$STATE/state/opening.request"
echo '{"event":"watch-busy-proof","worker_alive":true,"intent_unchanged":true,"opening_pending":true}'
printf 'LISA_HOLD_RELEASE_V1\n' > "$STATE/run/hold.release.tmp"
mv "$STATE/run/hold.release.tmp" "$STATE/run/hold.release"
wait "$held_pid"; rm "$STATE/held-child"; cat "$STATE/held.events"; cat "$STATE/held.error" >&2
run_coord --lab-status "$CANON"
family_name=ipv4; transport=udp; ct_family=ipv4; address=127.0.0.1
stem="$STATE/automatic"; mkfifo "$stem.control"; exec 3<>"$stem.control"
PROBE --own-recovery-epochs 4 udp 2 4 <"$stem.control" >"$stem.events" 2>"$stem.error" & child=$!
printf '%s %s\n' "$child" "$(awk '{print $22}' /proc/"$child"/stat)" > "$STATE/child"
wait_event old; attributed old 2 old
run_coord --lab-close "$CANON" 2
printf c >&3; wait_event closed
result=0; run_coord --lab-open "$CANON" 3 20 || result=$?
[ "$result" = 137 ]; printf '{"event":"watch-worker-exit","code":%s}\n' "$result"
wait_watch recovered
run_coord --lab-status "$CANON"
sleep 1
run_coord --lab-status "$CANON"
printf p >&3; wait_event recovery; attributed recovered 2 old
result=0; run_coord --lab-open "$CANON" 3 || result=$?
[ "$result" = 4 ]; printf '{"event":"watch-stale-exit","code":%s}\n' "$result"
run_coord --lab-open "$CANON" 5
printf n >&3; wait_event new; attributed new 4 new
result=0; run_coord --lab-close-lisa "$CANON" 6 1 || result=$?
[ "$result" = 137 ]; printf '{"event":"watch-close-worker-exit","code":%s}\n' "$result"
wait_recoveries 2
run_coord --lab-status "$CANON"
printf r >&3; wait "$child"; rm "$STATE/child"; exec 3>&-
cat "$stem.events"; cat "$stem.error" >&2
printf 'LISA_RECOVERY_STOP_V1\n' > "$STATE/run/watch.stop.tmp"
mv "$STATE/run/watch.stop.tmp" "$STATE/run/watch.stop"
wait "$watch_pid"; rm "$STATE/watch-child"
cat "$STATE/watch.events"; cat "$STATE/watch.error" >&2
cleanup
echo '{"event":"watch-cleanup","ok":true}'
"""


def trial_script():
    script = composed_trial()
    if script.count(BODY) != 1:
        raise RuntimeError("Composed body changed; review watcher fixture")
    prefix = BODY[: BODY.index('COORD --lab-reserve "$CANON"')]
    old = 'cleanup() { sh "$STATE/cleanup.sh" "$STATE"; }'
    if prefix.count(old) != 1:
        raise RuntimeError("Cleanup boundary changed")
    prefix = prefix.replace(old, 'cleanup() { stop_auxiliaries; sh "$STATE/cleanup.sh" "$STATE"; }')
    return script.replace(BODY, STOP + prefix + STAGES)


def evaluate_events(events):
    if not isinstance(events, list) or len(events) != 43 or any(not isinstance(row, dict) for row in events):
        return False
    stages = {
        0: ("reserve", "ok", 1, 1, 1, "paused", "closed", True, False, False, False, "paused", 36),
        2: ("open-hold", "ok", 2, 2, 2, "alice", "open", False, True, False, True, "alice", 32),
        3: ("status", "ok", 2, 2, 2, "alice", "open", False, True, False, True, "alice", 0),
        5: ("close", "ok", 2, 2, 3, "paused", "closed", True, False, False, False, "paused", 18),
        8: ("status", "ok", 4, 3, 5, "paused", "closed", True, False, True, False, "paused", 0),
        9: ("status", "ok", 4, 3, 5, "paused", "closed", True, False, True, False, "paused", 0),
        11: ("open", "denied", 4, 3, 5, "paused", "closed", True, False, True, False, "paused", 0),
        13: ("open", "ok", 6, 4, 6, "alice", "open", False, True, False, True, "alice", 32),
        17: ("status", "ok", 6, 4, 7, "lisa", "closed", True, False, False, False, "paused", 0),
        41: ("watch", "ok", 6, 4, 7, "lisa", "closed", True, False, False, False, "paused", 0),
    }
    for index, values in stages.items():
        (
            op,
            result,
            revision,
            epoch,
            mode,
            requested,
            phase,
            closed,
            opened,
            pending,
            permit,
            choice,
            steps,
        ) = values
        row = dict(
            event="epoch-mutation",
            operation=op,
            result=result,
            phase=phase,
            revision=revision,
            epoch=epoch,
            mode_revision=mode,
            requested_mode=requested,
            boot_choice=choice,
            opening_pending=pending,
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
        )
        if events[index] != row or any(
            type(events[index].get(key)) is not type(value) for key, value in row.items()
        ):
            return False
    constants = {
        1: dict(event="watch-busy-proof", worker_alive=True, intent_unchanged=True, opening_pending=True),
        6: dict(event="mutation-fault", step=20),
        7: dict(event="watch-worker-exit", code=137),
        12: dict(event="watch-stale-exit", code=4),
        15: dict(event="mutation-fault", step=1),
        16: dict(event="watch-close-worker-exit", code=137),
        36: dict(event="recovery-watch", state="ready", deadline_seconds=120),
        37: dict(event="recovery-watch", state="busy"),
        38: dict(
            event="recovery-watch",
            state="recovered",
            reason="cancel_open",
            base_revision=4,
            mode_revision=5,
            target="paused",
            policy_closed=True,
            permit_revoked=True,
        ),
        39: dict(
            event="recovery-watch",
            state="recovered",
            reason="finish_close",
            base_revision=6,
            mode_revision=7,
            target="lisa",
            policy_closed=True,
            permit_revoked=True,
        ),
        42: dict(event="watch-cleanup", ok=True),
    }
    for index, row in constants.items():
        if events[index] != row or any(
            type(events[index].get(key)) is not type(value) for key, value in row.items()
        ):
            return False
    for index, phase, epoch in [(4, "old", 2), (10, "recovered", 2), (14, "new", 4)]:
        row = dict(
            event="epoch-attributed",
            family="ipv4",
            protocol="udp",
            phase=phase,
            epoch=epoch,
            mark=epoch << 24,
            ok=True,
        )
        if (
            events[index] != row
            or events[index].get("ok") is not True
            or type(events[index].get("mark")) is not int
        ):
            return False
    checks = [
        "baseline",
        "old_open_exchange",
        "old_closed",
        "unrelated_closed",
        "old_during_recovery",
        "unrelated_recovery",
        "new_socket",
        "new_open_exchange",
        "old_still_denied",
        "unrelated_reopened",
        "new_closed",
        "old_remains_closed",
        "unrelated_final",
    ]
    native = events[18:36]
    common = dict(family="ipv4", protocol="udp", old_epoch=2, new_epoch=4)
    at = 0
    ready = []
    for index, check in enumerate(checks):
        row = dict(event="epoch-check", **common, check=check, ok=True)
        if native[at] != row or native[at].get("ok") is not True:
            return False
        at += 1
        if index in {1, 3, 5, 9}:
            phase = {1: "old", 3: "closed", 5: "recovery", 9: "new"}[index]
            row = native[at]
            expected_keys = {"event", *common, "phase", "source_port", "destination_port"}
            if (
                set(row) != expected_keys
                or row.get("event") != "epoch-ready"
                or row.get("phase") != phase
                or any(row.get(key) != value for key, value in common.items())
            ):
                return False
            ports = [row.get("source_port"), row.get("destination_port")]
            if any(type(port) is not int for port in ports) or (
                ports != [0, 0]
                if phase == "closed"
                else not all(0 < port < 65536 for port in ports) or ports[0] == ports[1]
            ):
                return False
            ready.append(ports)
            at += 1
    if ready[0] != ready[2] or ready[0] == ready[3]:
        return False
    row = dict(
        event="epoch-summary",
        **common,
        checks=13,
        failures=0,
        audio_opened=False,
        vendor_processes_changed=False,
    )
    if (
        native[at] != row
        or native[at].get("audio_opened") is not False
        or native[at].get("vendor_processes_changed") is not False
        or type(native[at].get("failures")) is not int
    ):
        return False
    summary = events[40]
    expected_keys = {
        "event",
        "busy_polls",
        "recovered",
        "idle_polls",
        "faults",
        "stopped",
        "automatic_open",
        "audio_opened",
    }
    return (
        set(summary) == expected_keys
        and summary.get("event") == "recovery-watch-summary"
        and all(type(summary.get(key)) is int for key in ("busy_polls", "recovered", "idle_polls", "faults"))
        and summary["busy_polls"] > 0
        and summary["idle_polls"] > 0
        and summary["recovered"] == 2
        and summary["faults"] == 0
        and summary.get("stopped") is True
        and summary.get("automatic_open") is False
        and summary.get("audio_opened") is False
    )


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("host")
    parser.add_argument("--ssh-config", type=Path)
    parser.add_argument("--run-bounded-watch-trial", action="store_true", required=True)
    args = parser.parse_args()
    if args.host.startswith("-"):
        parser.error("SSH alias required")
    root = Path(__file__).resolve().parents[1]
    ssh = ["ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=20"]
    if args.ssh_config:
        ssh += ["-F", str(args.ssh_config)]
    ssh += [args.host]

    def remote(command, **kwargs):
        return subprocess.run(ssh + [command], capture_output=True, timeout=180, **kwargs)

    targets, digests = {}, {}
    for key, name in [("COORD", "epoch-mutation-probe"), ("PROBE", "epoch-policy-probe")]:
        data = (root / f"build/{name}.armhf").read_bytes()
        digest = hashlib.sha256(data).hexdigest()
        target = "/data/opt/lisa-controller-lab/" + name + "-" + digest[:16]
        remote("umask 077; cat > " + target + ".new && chmod 700 " + target + ".new", input=data, check=True)
        if remote("sha256sum " + target + ".new", check=True).stdout.decode().split()[0] != digest:
            raise RuntimeError("watch helper digest mismatch")
        remote("mv " + target + ".new " + target, check=True)
        targets[key], digests[name] = target, digest
    identity = "pidof quasar_launcher2 maind alsa-audio-monitord hardvold chronyd unbound; cat /proc/sys/kernel/random/boot_id; sha256sum /etc/init.d/rcS /etc/init.d/S99zdropbear /etc/chrony.conf /etc/unbound/unbound.conf /etc/resolv.conf"
    before = remote(identity, check=True).stdout
    rules = remote("iptables-save; ip6tables-save", check=True).stdout
    script = trial_script()
    for key, target in targets.items():
        script = script.replace(key, target)
    result = remote("sh -s", input=script.encode())
    after = remote(identity, check=True).stdout
    after_rules = remote("iptables-save; ip6tables-save", check=True).stdout
    (root / "build/recovery-watch.stdout.private.txt").write_bytes(result.stdout)
    events = [json.loads(line) for line in result.stdout.decode().splitlines()]
    report = dict(
        binary_sha256=digests,
        returncode=result.returncode,
        events=events,
        error=result.stderr.decode()[-3000:],
        protocol_qualified=result.returncode == 0 and evaluate_events(events),
        stock_identity_and_configs_preserved=before == after,
        firewall_restored=rules_only(rules) == rules_only(after_rules),
        production_mode_changed=False,
        audio_captured=False,
        isolation_verified=False,
    )
    (root / "build/recovery-watch-qualification.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps({key: value for key, value in report.items() if key != "events"}, indent=2))
    if not all(
        report[key]
        for key in ("protocol_qualified", "stock_identity_and_configs_preserved", "firewall_restored")
    ):
        raise SystemExit("watch trial incomplete; inspect private report")


if __name__ == "__main__":
    main()
