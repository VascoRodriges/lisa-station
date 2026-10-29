"""Closed intent changes and cancellation must invalidate an earlier opener."""

import argparse
import hashlib
import json
import subprocess
from pathlib import Path

from controller.qualify_epoch_mutation import BODY as OPENING_BODY
from controller.qualify_epoch_mutation import trial_script as opening_trial
from controller.qualify_socket_close import rules_only

STAGES = r"""
COORD --lab-reserve "$CANON"
cp "$STATE/run/epoch.owner" "$STATE/owner.initial"
COORD --lab-close-lisa "$CANON" 1
COORD --lab-close-lisa "$CANON" 2
COORD --lab-close "$CANON" 3
COORD --lab-open "$CANON" 4
COORD --lab-close "$CANON" 5
COORD --lab-close-lisa "$CANON" 6
result=0; COORD --lab-open "$CANON" 7 3 || result=$?
[ "$result" = 137 ]; printf '{"event":"rollover-fault-exit","exit_code":%s}\n' "$result"
COORD --lab-status "$CANON"
COORD --lab-close "$CANON" 7
result=0; COORD --lab-open "$CANON" 7 || result=$?
[ "$result" = 4 ]; printf '{"event":"rollover-stale-exit","exit_code":%s}\n' "$result"
COORD --lab-open "$CANON" 8
COORD --lab-close "$CANON" 9
cleanup
echo '{"event":"rollover-cleanup","ok":true}'
"""


def trial_script():
    script = opening_trial()
    if script.count(OPENING_BODY) != 1 or OPENING_BODY.count('COORD --lab-reserve "$CANON"') != 1:
        raise RuntimeError("Opening fixture changed; review the rollover boundary")
    prefix = OPENING_BODY[: OPENING_BODY.index('COORD --lab-reserve "$CANON"')]
    return script.replace(OPENING_BODY, prefix + STAGES)


def evaluate_events(events):
    if not isinstance(events, list) or len(events) != 16 or any(not isinstance(row, dict) for row in events):
        return False
    # operation, label revision/generation, intent revision/name, phase, closed,
    # open, pending, permit, boot choice, mutation count, result.
    expected = {
        0: ("reserve", 1, 1, 1, "paused", "closed", True, False, False, False, "paused", 36, "ok"),
        1: ("close-lisa", 1, 1, 2, "lisa", "closed", True, False, False, False, "paused", 2, "ok"),
        2: ("close-lisa", 1, 1, 3, "lisa", "closed", True, False, False, False, "paused", 2, "ok"),
        3: ("close", 1, 1, 4, "paused", "closed", True, False, False, False, "paused", 2, "ok"),
        4: ("open", 5, 2, 5, "alice", "open", False, True, False, True, "alice", 32, "ok"),
        5: ("close", 5, 2, 6, "paused", "closed", True, False, False, False, "paused", 18, "ok"),
        6: ("close-lisa", 5, 2, 7, "lisa", "closed", True, False, False, False, "paused", 2, "ok"),
        9: ("status", 8, 3, 7, "lisa", "arming", False, False, True, False, "paused", 0, "ok"),
        10: ("close", 8, 3, 8, "paused", "closed", True, False, True, False, "paused", 10, "ok"),
        11: ("open", 8, 3, 8, "paused", "closed", True, False, True, False, "paused", 0, "denied"),
        13: ("open", 9, 4, 9, "alice", "open", False, True, False, True, "alice", 32, "ok"),
        14: ("close", 9, 4, 10, "paused", "closed", True, False, False, False, "paused", 18, "ok"),
    }
    for index, values in expected.items():
        (
            op,
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
            result,
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
    return (
        events[7] == dict(event="mutation-fault", step=3)
        and type(events[7].get("step")) is int
        and events[8] == dict(event="rollover-fault-exit", exit_code=137)
        and type(events[8].get("exit_code")) is int
        and events[12] == dict(event="rollover-stale-exit", exit_code=4)
        and type(events[12].get("exit_code")) is int
        and events[15] == dict(event="rollover-cleanup", ok=True)
        and events[15].get("ok") is True
    )


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("host")
    parser.add_argument("--ssh-config", type=Path)
    parser.add_argument("--run-private-intent-trial", action="store_true", required=True)
    args = parser.parse_args()
    if args.host.startswith("-"):
        parser.error("SSH alias required")
    root = Path(__file__).resolve().parents[1]
    ssh = ["ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=20"]
    if args.ssh_config:
        ssh += ["-F", str(args.ssh_config)]
    ssh += [args.host]

    def remote(command, **kwargs):
        return subprocess.run(ssh + [command], capture_output=True, timeout=150, **kwargs)

    binary = (root / "build/epoch-mutation-probe.armhf").read_bytes()
    digest = hashlib.sha256(binary).hexdigest()
    target = "/data/opt/lisa-controller-lab/epoch-mutation-probe-" + digest[:16]
    remote("umask 077; cat > " + target + ".new && chmod 700 " + target + ".new", input=binary, check=True)
    if remote("sha256sum " + target + ".new", check=True).stdout.decode().split()[0] != digest:
        raise RuntimeError("rollover helper digest mismatch")
    remote("mv " + target + ".new " + target, check=True)
    identity = "pidof quasar_launcher2 maind alsa-audio-monitord hardvold chronyd unbound; cat /proc/sys/kernel/random/boot_id; sha256sum /etc/init.d/rcS /etc/init.d/S99zdropbear /etc/chrony.conf /etc/unbound/unbound.conf /etc/resolv.conf"
    before = remote(identity, check=True).stdout
    rules = remote("iptables-save; ip6tables-save", check=True).stdout
    result = remote("sh -s", input=trial_script().replace("COORD", target).replace("PROBE", target).encode())
    after = remote(identity, check=True).stdout
    after_rules = remote("iptables-save; ip6tables-save", check=True).stdout
    events = [json.loads(line) for line in result.stdout.decode().splitlines()]
    report = dict(
        binary_sha256=digest,
        returncode=result.returncode,
        events=events,
        error=result.stderr.decode()[-2000:],
        protocol_qualified=result.returncode == 0 and evaluate_events(events),
        stock_identity_and_configs_preserved=before == after,
        firewall_restored=rules_only(rules) == rules_only(after_rules),
        production_mode_changed=False,
        audio_captured=False,
        isolation_verified=False,
    )
    (root / "build/closed-rollover-qualification.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps({key: value for key, value in report.items() if key != "events"}, indent=2))
    if not all(
        report[key]
        for key in ("protocol_qualified", "stock_identity_and_configs_preserved", "firewall_restored")
    ):
        raise SystemExit("closed rollover trial incomplete; inspect private report")


if __name__ == "__main__":
    main()
