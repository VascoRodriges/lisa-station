"""Bounded own-flow trial of cached denial after primary journal corruption."""

import argparse
import hashlib
import json
import subprocess
from pathlib import Path

from controller.qualify_epoch_mutation import BODY
from controller.qualify_epoch_mutation import trial_script as composed_trial
from controller.qualify_recovery_watch import STOP
from controller.qualify_socket_close import rules_only

EMERGENCY_CLEANUP = r"""
EGROUP=$(printf '%s' "$CHAIN" | sed 's/^LISACQ_/LISACE_/')
ELABEL=$(printf '%s' "$CHAIN" | sed 's/^LISACQ_/LISACF_/')
emergency_owned=0
if [ -f "$STATE/run/emergency.owner" ] && [ "$(cat "$STATE/run/emergency.owner")" = "LISA_EMERGENCY_V1 $(cat /proc/sys/kernel/random/boot_id) $CHAIN 1 0xff000000" ]; then emergency_owned=1; fi
for version in 4 6; do
    tool=iptables; [ "$version" = 4 ] || tool=ip6tables
    for name in "$EGROUP" "$ELABEL"; do
        if "$tool" -S "$name" > "$STATE/emergency-$version-$name.rules" 2>/dev/null; then
            [ "$emergency_owned" = 1 ] || exit 9
            pattern="^-N $name$|^-A $name -m owner --gid-owner (57342|57343|57344|57345) -j DROP$"
            [ "$name" != "$ELABEL" ] || pattern="^-N $name$|^-A $name -m connmark ! --mark 0x0/0xff000000 -j DROP$"
            result=0; grep -Ev "$pattern" "$STATE/emergency-$version-$name.rules" >/dev/null || result=$?
            [ "$result" = 1 ] || exit 9
            touch "$STATE/emergency-chain-$version-$name"
        else
            "$tool" -S > "$STATE/emergency-whole.rules"
            if grep -Fx -- "-N $name" "$STATE/emergency-whole.rules" >/dev/null; then exit 9; fi
            rm -f "$STATE/emergency-chain-$version-$name"
        fi
    done
done
for version in 4 6; do
    tool=iptables; [ "$version" = 4 ] || tool=ip6tables
    for hook in INPUT OUTPUT; do
        for name in "$EGROUP" "$ELABEL"; do
            if "$tool" -C "$hook" -j "$name" >/dev/null 2>&1; then "$tool" -D "$hook" -j "$name"; fi
        done
    done
    for name in "$EGROUP" "$ELABEL"; do
        [ ! -f "$STATE/emergency-chain-$version-$name" ] || { "$tool" -F "$name"; "$tool" -X "$name"; }
    done
done
"""

STAGES = r"""
run_coord --lab-reserve "$CANON"
cp "$STATE/run/epoch.owner" "$STATE/owner.initial"
COORD --lab-watch-emergency "$CANON" 120 >"$STATE/watch.events" 2>"$STATE/watch.error" & watch_pid=$!
printf '%s %s\n' "$watch_pid" "$(awk '{print $22}' /proc/"$watch_pid"/stat)" > "$STATE/watch-child"
wait_file "$STATE/run/watch.ready"
run_coord --lab-open "$CANON" 1
cp "$STATE/run/epoch.state" "$STATE/epoch.before"
family_name=ipv4; transport=udp; ct_family=ipv4; address=127.0.0.1
stem="$STATE/emergency"; mkfifo "$stem.control"; exec 3<>"$stem.control"
PROBE --own-emergency 4 udp 2 3 <"$stem.control" >"$stem.events" 2>"$stem.error" & child=$!
printf '%s %s\n' "$child" "$(awk '{print $22}' /proc/"$child"/stat)" > "$STATE/child"
wait_event old; attributed old 2 old
printf 'damaged owner\n' > "$STATE/run/epoch.owner.new"
mv "$STATE/run/epoch.owner.new" "$STATE/run/epoch.owner"
printf 'damaged epoch\n' > "$STATE/run/epoch.state.new"
mv "$STATE/run/epoch.state.new" "$STATE/run/epoch.state"
result=0; wait "$watch_pid" || result=$?; rm "$STATE/watch-child"
cat "$STATE/watch.events"; cat "$STATE/watch.error" >&2
[ "$result" = 4 ]; printf '{"event":"emergency-watch-exit","code":%s}\n' "$result"
grep -qx 'damaged owner' "$STATE/run/epoch.owner"
grep -qx 'damaged epoch' "$STATE/run/epoch.state"
grep -qx 'LISA_MODE_V1 2 alice' "$STATE/state/mode.state"
grep -qx "LISA_FAULT_V1 $(cat /proc/sys/kernel/random/boot_id) $CHAIN 1 0xff000000" "$STATE/state/fault.request"
test ! -e "$STATE/run/vendor.permit"
echo '{"event":"emergency-preserved","damaged_primary":true,"intent_unchanged":true,"fault_persisted":true,"permit_absent":true}'
# Restore ONLY this throwaway fixture's primary bytes to prove the independent
# fault latch still blocks an explicit opening. Never remove the fault fence.
cp "$STATE/owner.initial" "$STATE/run/epoch.owner.new"; mv "$STATE/run/epoch.owner.new" "$STATE/run/epoch.owner"
cp "$STATE/epoch.before" "$STATE/run/epoch.state.new"; mv "$STATE/run/epoch.state.new" "$STATE/run/epoch.state"
result=0; run_coord --lab-open "$CANON" 2 || result=$?
[ "$result" = 4 ]; printf '{"event":"emergency-open-exit","code":%s}\n' "$result"
printf c >&3; wait_event emergency
printf r >&3; wait "$child"; rm "$STATE/child"; exec 3>&-
cat "$stem.events"; cat "$stem.error" >&2
cleanup
echo '{"event":"emergency-cleanup","ok":true}'
"""


def trial_script():
    script = composed_trial()
    prefix = BODY[: BODY.index('COORD --lab-reserve "$CANON"')]
    old = 'cleanup() { sh "$STATE/cleanup.sh" "$STATE"; }'
    if script.count(BODY) != 1 or prefix.count(old) != 1:
        raise RuntimeError("Composed fixture changed; review emergency cleanup")
    prefix = prefix.replace(old, 'cleanup() { stop_auxiliaries; sh "$STATE/cleanup.sh" "$STATE"; }')
    script = script.replace(BODY, STOP + prefix + STAGES)
    at = script.index("for version in 4 6; do", script.index("owner_ok=0"))
    script = script[:at] + EMERGENCY_CLEANUP + script[at:]
    start = script.index('cat > "$STATE/cleanup.sh"')
    end = script.index("\nCLEANUP\n", start)
    # Stopping a parent does not synchronously reap its killed xtables child.
    # Every cleanup query/mutation waits for that child's lock to be released.
    return script[:start] + script[start:end].replace('"$tool" ', '"$tool" -w 5 ') + script[end:]


def evaluate_events(events):
    if (
        not isinstance(events, list)
        or len(events) not in {31, 32}
        or any(type(row) is not dict for row in events)
    ):
        return False

    busy_logged = len(events) == 32
    if busy_logged:
        if events[4] != dict(event="recovery-watch", state="busy"):
            return False
        events = events[:4] + events[5:]

    def exact(index, row):
        return events[index] == row and all(type(events[index].get(k)) is type(v) for k, v in row.items())

    def stage(index, op, result, revision, epoch, choice, closed, opened, permit, steps):
        return exact(
            index,
            dict(
                event="epoch-mutation",
                operation=op,
                result=result,
                phase="unknown" if revision == 0 else "closed" if index == 0 else "open",
                revision=revision,
                epoch=epoch,
                mode_revision=1 if index == 0 else 2,
                requested_mode="paused" if index == 0 else "alice",
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
            stage(0, "reserve", "ok", 1, 1, "paused", True, False, False, 36),
            stage(1, "open", "ok", 2, 2, "alice", False, True, True, 32),
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
            exact(3, dict(event="recovery-watch", state="ready", deadline_seconds=120)),
            exact(
                4,
                dict(
                    event="emergency-fault",
                    latched=True,
                    policy_closed=True,
                    primary_preserved=True,
                    automatic_open=False,
                ),
            ),
            stage(6, "watch-emergency", "denied", 0, 0, "paused", None, None, False, 0),
            exact(7, dict(event="emergency-watch-exit", code=4)),
            exact(
                8,
                dict(
                    event="emergency-preserved",
                    damaged_primary=True,
                    intent_unchanged=True,
                    fault_persisted=True,
                    permit_absent=True,
                ),
            ),
            stage(9, "open", "denied", 2, 2, "paused", False, False, False, 0),
            exact(10, dict(event="emergency-open-exit", code=4)),
            exact(30, dict(event="emergency-cleanup", ok=True)),
        ]
    ):
        return False
    summary = events[5]
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
        and summary["busy_polls"] >= 0
        and (summary["busy_polls"] > 0) == busy_logged
        and summary["idle_polls"] > 0
        and summary["recovered"] == 0
        and summary["faults"] == 1
        and all(summary[k] is False for k in ["stopped", "automatic_open", "audio_opened"])
    ):
        return False
    return evaluate_native(events[11:30])


def evaluate_native(events):
    if not isinstance(events, list) or len(events) != 19 or any(type(row) is not dict for row in events):
        return False

    def exact(index, row):
        return events[index] == row and all(type(events[index].get(k)) is type(v) for k, v in row.items())

    common = dict(family="ipv4", protocol="udp", old_epoch=2, new_epoch=3)
    names = ["baseline", "old_open_exchange", "old_closed", "unrelated_closed"]
    names += [f"group_{group}_{kind}" for group in range(57342, 57346) for kind in ["socket", "denied"]]
    names += ["old_root_reply_denied", "old_remains_closed", "unrelated_final"]
    at = 0
    for index, name in enumerate(names):
        if not exact(at, dict(event="epoch-check", **common, check=name, ok=True)):
            return False
        at += 1
        if index in {1, 3, 12}:
            row = events[at]
            phase = {1: "old", 3: "closed", 12: "emergency"}[index]
            if (
                set(row) != {"event", *common, "phase", "source_port", "destination_port"}
                or row.get("event") != "epoch-ready"
                or row.get("phase") != phase
                or any(type(row.get(k)) is not type(v) or row[k] != v for k, v in common.items())
            ):
                return False
            ports = [row["source_port"], row["destination_port"]]
            if any(type(port) is not int for port in ports) or (
                not all(0 < p < 65536 for p in ports) or ports[0] == ports[1]
                if phase == "old"
                else ports != [0, 0]
            ):
                return False
            at += 1
    return at == 18 and exact(
        18,
        dict(
            event="epoch-summary",
            **common,
            checks=15,
            failures=0,
            audio_opened=False,
            vendor_processes_changed=False,
        ),
    )


def run_trial(host, ssh_config, script, evaluate, stem):
    if not stem.replace("-", "").isalnum() or host.startswith("-"):
        raise ValueError("Fixed report name and SSH alias required")
    root = Path(__file__).resolve().parents[1]
    ssh = ["ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=20"]
    if ssh_config:
        ssh += ["-F", str(ssh_config)]
    ssh += [host]

    def remote(command, **kwargs):
        return subprocess.run(ssh + [command], capture_output=True, timeout=180, **kwargs)

    remote(
        "test ! -e /data/opt/lisa-lab/trial.lock && test ! -e /bkupgrade/data/opt/lisa-station/state && test ! -e /run/lisa-station",
        check=True,
    )
    targets, digests = {}, {}
    for key, name in [("COORD", "epoch-mutation-probe"), ("PROBE", "epoch-policy-probe")]:
        data = (root / f"build/{name}.armhf").read_bytes()
        digest = hashlib.sha256(data).hexdigest()
        target = "/data/opt/lisa-controller-lab/" + name + "-" + digest[:16]
        remote("umask 077; cat > " + target + ".new && chmod 700 " + target + ".new", input=data, check=True)
        if remote("sha256sum " + target + ".new", check=True).stdout.decode().split()[0] != digest:
            raise RuntimeError("emergency helper digest mismatch")
        remote("mv " + target + ".new " + target, check=True)
        targets[key], digests[name] = target, digest
    native = remote(targets["COORD"] + " --station-selftest", check=True)
    native_rows = [json.loads(line) for line in native.stdout.decode().splitlines()]
    if len(native_rows) != 4 or any(row.get("ok") is not True for row in native_rows):
        raise RuntimeError("Native emergency selftests incomplete")
    identity = "pidof quasar_launcher2 maind alsa-audio-monitord hardvold chronyd unbound; cat /proc/sys/kernel/random/boot_id; sha256sum /etc/init.d/rcS /etc/init.d/S99zdropbear /etc/chrony.conf /etc/unbound/unbound.conf /etc/resolv.conf"
    before = remote(identity, check=True).stdout
    rules = remote("iptables-save; ip6tables-save", check=True).stdout
    for key, target in targets.items():
        script = script.replace(key, target)
    result = remote("sh -s", input=script.encode())
    after = remote(identity, check=True).stdout
    after_rules = remote("iptables-save; ip6tables-save", check=True).stdout
    (root / f"build/{stem}.stdout.private.txt").write_bytes(result.stdout)
    events = [json.loads(line) for line in result.stdout.decode().splitlines()]
    report = dict(
        binary_sha256=digests,
        native_selftests=native_rows,
        returncode=result.returncode,
        events=events,
        error=result.stderr.decode()[-3000:],
        protocol_qualified=result.returncode == 0 and evaluate(events),
        stock_identity_and_configs_preserved=before == after,
        firewall_restored=rules_only(rules) == rules_only(after_rules),
        production_mode_changed=False,
        audio_captured=False,
        isolation_verified=False,
    )
    (root / f"build/{stem}-qualification.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps({k: v for k, v in report.items() if k != "events"}, indent=2))
    if not all(
        report[k] for k in ["protocol_qualified", "stock_identity_and_configs_preserved", "firewall_restored"]
    ):
        raise SystemExit("emergency trial incomplete; inspect private report")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("host")
    parser.add_argument("--ssh-config", type=Path)
    parser.add_argument("--run-private-corruption-trial", action="store_true", required=True)
    args = parser.parse_args()
    if args.host.startswith("-"):
        parser.error("SSH alias required")
    run_trial(args.host, args.ssh_config, trial_script(), evaluate_events, "emergency")


if __name__ == "__main__":
    main()
