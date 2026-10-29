"""Composed intent/policy transitions and explicit recovery of interrupted openings."""

import argparse
import hashlib
import json
import subprocess
from pathlib import Path

from controller.qualify_epochs import SCRIPT as OLD
from controller.qualify_socket_close import rules_only

BODY = r"""
cleanup() { sh "$STATE/cleanup.sh" "$STATE"; }
trap cleanup EXIT
trap 'exit 125' HUP INT TERM
printf '%s %s %s\n' "$$" "$(awk '{print $22}' /proc/$$/stat)" "$(readlink /proc/$$/exe)" > "$STATE/driver"
nohup sh -c '
    state=$1; sleep 900
    [ ! -f "$state/cleaned" ] || exit 0
    set -- $(cat "$state/driver"); driver=$1; ticks=$2; executable=$3
    if [ "$(awk "{print \$22}" /proc/"$driver"/stat 2>/dev/null || true)" = "$ticks" ] && [ "$(readlink /proc/"$driver"/exe)" = "$executable" ]; then kill -KILL "$driver"; sleep 1; fi
    sh "$state/cleanup.sh" "$state"
' watchdog "$STATE" </dev/null >"$STATE/watchdog.log" 2>&1 &
COORD --lab-reserve "$CANON"
cp "$STATE/run/epoch.owner" "$STATE/owner.initial"
index=0
while [ "$index" -lt 38 ]; do
    case $((index%6)) in
        0) family=4; transport=tcp;; 1) family=4; transport=udp;;
        2) family=6; transport=tcp;; 3) family=6; transport=udp;;
        4) family=mapped; transport=tcp;; 5) family=mapped; transport=udp;;
    esac
    family_name=ipv4; ct_family=ipv4; address=127.0.0.1
    if [ "$family" = 6 ]; then family_name=ipv6; ct_family=ipv6; address=0000:0000:0000:0000:0000:0000:0000:0001; fi
    if [ "$family" = mapped ]; then family_name=ipv4-mapped-ipv6; fi
    point=0; if [ "$index" -ge 6 ]; then point=$((index-5)); fi
    base=$((index*4+1)); old=$((index*2+2)); new=$((old+1))
    printf '{"event":"mutation-case-begin","index":%s,"point":%s,"family":"%s","protocol":"%s"}\n' "$index" "$point" "$family_name" "$transport"
    COORD --lab-open "$CANON" "$base"
    stem="$STATE/case-$index"; mkfifo "$stem.control"; exec 3<>"$stem.control"
    PROBE --own-recovery-epochs "$family" "$transport" "$old" "$new" <"$stem.control" >"$stem.events" 2>"$stem.error" &
    child=$!; ticks=$(awk '{print $22}' /proc/"$child"/stat); printf '%s %s\n' "$child" "$ticks" > "$STATE/child"
    wait_event old; attributed old "$old" old
    COORD --lab-close "$CANON" "$((base+1))"
    printf c >&3; wait_event closed
    if [ "$point" -gt 0 ]; then
        result=0; COORD --lab-open "$CANON" "$((base+2))" "$point" || result=$?
        [ "$result" = 137 ]
        printf '{"event":"mutation-fault-exit","point":%s,"code":%s}\n' "$point" "$result"
        COORD --lab-status "$CANON"
        printf p >&3; wait_event recovery
        attributed fault-retained "$old" old
        COORD --lab-deny "$CANON"
    fi
    COORD --lab-open "$CANON" "$((base+2))"
    printf n >&3; wait_event new
    attributed retained "$old" old; attributed new "$new" new
    COORD --lab-close "$CANON" "$((base+3))"
    printf r >&3
    result=0; wait "$child" || result=$?; rm "$STATE/child"; exec 3>&-
    cat "$stem.events"; cat "$stem.error" >&2
    [ "$result" = 0 ]
    printf '{"event":"mutation-case-end","index":%s,"point":%s,"ok":true}\n' "$index" "$point"
    index=$((index+1))
done
cleanup
echo '{"event":"mutation-cleanup","ok":true}'
"""


def trial_script():
    if (
        hashlib.sha256(OLD.encode()).hexdigest()
        != "bb3bd14e73c34af8da390d8a1b701dc9fdb51b8a4697ef8ca71c9fd605ebd3ff"
    ):
        raise RuntimeError("Epoch fixture changed; review cleanup/admission boundaries")
    preamble = OLD[: OLD.index("mkdir /data/opt/lisa-lab/trial.lock")]
    cleanup = OLD[OLD.index('cat > "$STATE/cleanup.sh"') : OLD.index("\ncleanup()")]
    cleanup = cleanup.replace(
        "LISACQ_EPOCHS[A-Z0-9]*:LISACM_EPOCHS[A-Z0-9]*:LISACL_EPOCHS[A-Z0-9]*",
        "LISACQ_MUTATION[A-Z0-9]*:LISACM_MUTATION[A-Z0-9]*:LISACL_MUTATION[A-Z0-9]*",
    )
    cleanup = cleanup.replace("0x[1-9a-c]000000", "0x[1-9a-f][0-9a-f]?000000").replace(
        "0x(0|[1-9a-c]000000)", "0x(0|[1-9a-f][0-9a-f]?000000)"
    )
    cleanup = cleanup.replace(
        '[ -f "$STATE/chain-$version-$kind" ] || continue\n        "$tool" -t "$table" -S "$name" > "$STATE/cleanup-$version-$kind.rules"',
        r'''if ! "$tool" -t "$table" -S "$name" > "$STATE/cleanup-$version-$kind.rules" 2>/dev/null; then
                "$tool" -t "$table" -S > "$STATE/whole.rules"
                if grep -Fx -- "-N $name" "$STATE/whole.rules" >/dev/null; then exit 9; fi
                continue
            fi
            [ "$owner_ok" = 1 ] || exit 9
            touch "$STATE/chain-$version-$kind"''',
    )
    ownership = r"""owner_ok=0
    owner_file="$STATE/run/epoch.owner"
    [ ! -f "$STATE/owner.initial" ] || owner_file="$STATE/owner.initial"
    if [ -f "$owner_file" ] && [ "$(cat "$owner_file")" = "LISA_EPOCH_OWNER_V1 $(cat /proc/sys/kernel/random/boot_id) $CHAIN 1 0xff000000" ]; then owner_ok=1; fi
    """
    cleanup = cleanup.replace("for version in 4 6; do", ownership + "for version in 4 6; do", 1)
    setup = r"""
    mkdir /data/opt/lisa-lab/trial.lock
    STATE=$(mktemp -d /data/opt/lisa-controller-lab/epoch-mutation.XXXXXX)
    CANON=$(readlink -f "$STATE")
    SUFFIX=$(basename "$STATE" | sed 's/epoch-mutation\.//' | tr 'a-z' 'A-Z')
    CHAIN=LISACQ_MUTATION$SUFFIX; MARK=LISACM_MUTATION$SUFFIX; DENY=LISACL_MUTATION$SUFFIX
    printf '%s %s %s\n' "$CHAIN" "$MARK" "$DENY" > "$STATE/chains"
    mkdir "$STATE/run" "$STATE/state"
    printf '%s\n' "$CHAIN" > "$STATE/run/policy.chain"
    printf 'LISA_MODE_V1 1 paused\n' > "$STATE/state/mode.state"
    """
    helpers = OLD[OLD.index("wait_event()") : OLD.index("sequence=0")]
    return preamble + setup + cleanup + "\n" + helpers + BODY


def evaluate_events(events):
    if (
        not isinstance(events, list)
        or len(events) != 1170
        or any(not isinstance(row, dict) for row in events)
    ):
        return False

    def transition(
        row,
        operation,
        revision,
        epoch,
        mode_revision,
        requested,
        phase,
        closed,
        opened,
        pending,
        permit,
        choice,
        steps,
    ):
        expected = dict(
            event="epoch-mutation",
            operation=operation,
            result="ok",
            phase=phase,
            revision=revision,
            epoch=epoch,
            mode_revision=mode_revision,
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
        return row == expected and all(type(row.get(key)) is type(value) for key, value in expected.items())

    if not transition(
        events[0], "reserve", 1, 1, 1, "paused", "closed", True, False, False, False, "paused", 36
    ):
        return False
    position = 1
    pairs = [
        (family, protocol) for family in ("ipv4", "ipv6", "ipv4-mapped-ipv6") for protocol in ("tcp", "udp")
    ]
    native_checks = [
        "baseline",
        "old_open_exchange",
        "old_closed",
        "unrelated_closed",
        "new_socket",
        "new_open_exchange",
        "old_still_denied",
        "unrelated_reopened",
        "new_closed",
        "old_remains_closed",
        "unrelated_final",
    ]
    for index in range(38):
        point = 0 if index < 6 else index - 5
        family, protocol = pairs[index % 6]
        base, old, new = index * 4 + 1, index * 2 + 2, index * 2 + 3
        size = 32 if point else 24
        rows = events[position : position + size]
        position += size
        begin = dict(event="mutation-case-begin", index=index, point=point, family=family, protocol=protocol)
        if rows[0] != begin or type(rows[0].get("index")) is not int or type(rows[0].get("point")) is not int:
            return False
        end = dict(event="mutation-case-end", index=index, point=point, ok=True)
        if (
            rows[-1] != end
            or rows[-1].get("ok") is not True
            or type(rows[-1].get("index")) is not int
            or type(rows[-1].get("point")) is not int
        ):
            return False
        if not transition(
            rows[1], "open", base + 1, old, base + 1, "alice", "open", False, True, False, True, "alice", 32
        ):
            return False
        if not transition(
            rows[3],
            "close",
            base + 1,
            old,
            base + 2,
            "paused",
            "closed",
            True,
            False,
            False,
            False,
            "paused",
            18,
        ):
            return False
        offset = 4
        if point:
            if rows[4] != dict(event="mutation-fault", step=point) or type(rows[4].get("step")) is not int:
                return False
            if (
                rows[5] != dict(event="mutation-fault-exit", point=point, code=137)
                or type(rows[5].get("code")) is not int
                or type(rows[5].get("point")) is not int
            ):
                return False
            label_revision, epoch = (base + 1, old) if point < 3 else (base + 3, new)
            mode_revision, requested, permit = (
                (base + 2, "paused", False) if point < 15 else (base + 3, "alice", True)
            )
            phase = (
                ("denying" if point == 1 else "closed")
                if point < 3
                else (
                    "arming"
                    if point == 3
                    else "denying"
                    if point < 13
                    else "closed"
                    if point == 13
                    else "armed"
                    if point == 14
                    else "opening"
                    if point < 32
                    else "open"
                )
            )
            closed, opened = point in {1, 2, 12, 13, 14, 15}, point >= 31
            if not transition(
                rows[6],
                "status",
                label_revision,
                epoch,
                mode_revision,
                requested,
                phase,
                closed,
                opened,
                True,
                permit,
                "paused",
                0,
            ):
                return False
            recovery_steps = (
                2
                if point < 3 or 12 <= point <= 15
                else 10
                if point == 3
                else 14 - point
                if point < 12
                else min(point - 13, 18)
            )
            if not transition(
                rows[8],
                "deny",
                label_revision,
                epoch,
                mode_revision,
                requested,
                "closed",
                True,
                False,
                True,
                False,
                "paused",
                recovery_steps,
            ):
                return False
            offset = 9
        if not transition(
            rows[offset],
            "open",
            base + 3,
            new,
            base + 3,
            "alice",
            "open",
            False,
            True,
            False,
            True,
            "alice",
            21 if point >= 3 else 32,
        ):
            return False
        if not transition(
            rows[offset + 3],
            "close",
            base + 3,
            new,
            base + 4,
            "paused",
            "closed",
            True,
            False,
            False,
            False,
            "paused",
            18,
        ):
            return False
        attributes = [(2, "old", old), (offset + 1, "retained", old), (offset + 2, "new", new)]
        if point:
            attributes.append((7, "fault-retained", old))
        for at, name, epoch in attributes:
            expected = dict(
                event="epoch-attributed",
                family=family,
                protocol=protocol,
                phase=name,
                epoch=epoch,
                mark=epoch << 24,
                ok=True,
            )
            if (
                rows[at] != expected
                or rows[at].get("ok") is not True
                or type(rows[at].get("epoch")) is not int
                or type(rows[at].get("mark")) is not int
            ):
                return False
        native = rows[offset + 4 : -1]
        common_keys = {"event", "family", "protocol", "old_epoch", "new_epoch"}
        fields = {
            "epoch-check": common_keys | {"check", "ok"},
            "epoch-ready": common_keys | {"phase", "source_port", "destination_port"},
            "epoch-summary": common_keys | {"checks", "failures", "audio_opened", "vendor_processes_changed"},
        }
        if any(set(row) != fields.get(row.get("event")) for row in native):
            return False
        if len(native) != (18 if point else 15) or any(
            row.get("family") != family
            or row.get("protocol") != protocol
            or type(row.get("old_epoch")) is not int
            or row.get("old_epoch") != old
            or type(row.get("new_epoch")) is not int
            or row.get("new_epoch") != new
            for row in native
        ):
            return False
        expected_checks = (
            native_checks[:4]
            + (["old_during_recovery", "unrelated_recovery"] if point else [])
            + native_checks[4:]
        )
        checked = [row for row in native if row.get("event") == "epoch-check"]
        if [row.get("check") for row in checked] != expected_checks or any(
            row.get("ok") is not True for row in checked
        ):
            return False
        ready = [row for row in native if row.get("event") == "epoch-ready"]
        expected_phases = ["old", "closed"] + (["recovery"] if point else []) + ["new"]
        if [row.get("phase") for row in ready] != expected_phases:
            return False
        for row in ready:
            ports = [row.get("source_port"), row.get("destination_port")]
            if any(type(port) is not int for port in ports) or (
                ports != [0, 0]
                if row["phase"] == "closed"
                else not all(0 < port < 65536 for port in ports) or ports[0] == ports[1]
            ):
                return False
        if point and any(ready[0][key] != ready[2][key] for key in ("source_port", "destination_port")):
            return False
        summary = dict(
            event="epoch-summary",
            family=family,
            protocol=protocol,
            old_epoch=old,
            new_epoch=new,
            checks=13 if point else 11,
            failures=0,
            audio_opened=False,
            vendor_processes_changed=False,
        )
        if (
            native[-1] != summary
            or type(native[-1].get("failures")) is not int
            or native[-1].get("audio_opened") is not False
            or native[-1].get("vendor_processes_changed") is not False
        ):
            return False
        expected_native = ["epoch-check"] * 2 + ["epoch-ready"] + ["epoch-check"] * 2 + ["epoch-ready"]
        if point:
            expected_native += ["epoch-check"] * 2 + ["epoch-ready"]
        expected_native += ["epoch-check"] * 4 + ["epoch-ready"] + ["epoch-check"] * 3 + ["epoch-summary"]
        if [row.get("event") for row in native] != expected_native:
            return False
    return (
        position == len(events) - 1
        and events[-1] == dict(event="mutation-cleanup", ok=True)
        and events[-1].get("ok") is True
    )


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("host")
    parser.add_argument("--ssh-config", type=Path)
    parser.add_argument("--run-composed-policy-trial", action="store_true", required=True)
    args = parser.parse_args()
    if args.host.startswith("-"):
        parser.error("SSH alias required")
    root = Path(__file__).resolve().parents[1]
    ssh = ["ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=20"]
    if args.ssh_config:
        ssh += ["-F", str(args.ssh_config)]
    ssh += [args.host]

    def remote(command, **kwargs):
        return subprocess.run(ssh + [command], capture_output=True, timeout=1100, **kwargs)

    targets = {}
    digests = {}
    for key, name in [("COORD", "epoch-mutation-probe"), ("PROBE", "epoch-policy-probe")]:
        binary = (root / f"build/{name}.armhf").read_bytes()
        digest = hashlib.sha256(binary).hexdigest()
        target = "/data/opt/lisa-controller-lab/" + name + "-" + digest[:16]
        remote(
            "umask 077; cat > " + target + ".new && chmod 700 " + target + ".new", input=binary, check=True
        )
        if remote("sha256sum " + target + ".new", check=True).stdout.decode().split()[0] != digest:
            raise RuntimeError("composed helper digest mismatch")
        remote("mv " + target + ".new " + target, check=True)
        targets[key] = target
        digests[name] = digest
    identity = "for p in $(pidof quasar_launcher2 maind alsa-audio-monitord hardvold chronyd unbound); do echo $p; awk '{print $22}' /proc/$p/stat; done; cat /proc/sys/kernel/random/boot_id; sha256sum /etc/init.d/rcS /etc/init.d/S99zdropbear /etc/chrony.conf /etc/unbound/unbound.conf /etc/resolv.conf"
    before = remote(identity, check=True).stdout
    rules = remote("iptables-save; ip6tables-save", check=True).stdout
    script = trial_script()
    for key, target in targets.items():
        script = script.replace(key, target)
    result = remote("sh -s", input=script.encode())
    after = remote(identity, check=True).stdout
    after_rules = remote("iptables-save; ip6tables-save", check=True).stdout
    (root / "build/epoch-mutation.stdout.private.txt").write_bytes(result.stdout)
    events = [json.loads(line) for line in result.stdout.decode().splitlines()]
    report = dict(
        binary_sha256=digests,
        returncode=result.returncode,
        events=events,
        error=result.stderr.decode()[-4000:],
        protocol_qualified=result.returncode == 0 and evaluate_events(events),
        stock_identity_and_configs_preserved=before == after,
        firewall_restored=rules_only(rules) == rules_only(after_rules),
        production_mode_changed=False,
        audio_captured=False,
        isolation_verified=False,
    )
    (root / "build/epoch-mutation-qualification.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps({key: value for key, value in report.items() if key != "events"}, indent=2))
    if not all(
        report[key]
        for key in ("protocol_qualified", "stock_identity_and_configs_preserved", "firewall_restored")
    ):
        raise SystemExit("composed trial incomplete; inspect private report")


if __name__ == "__main__":
    main()
