"""Audio-free SDK compatibility diagnostic through a private byte-only bus.

This is a bounded lab test with synthetic identities, not an Alice mode or a
production isolation claim. Private SDK logs stay under build/ and on device.
"""

import argparse
import hashlib
import json
import subprocess
from pathlib import Path

from controller.lab_artifact import canonical_lab_artifact
from controller.qualify_private_bus import SCRIPT as BUS_SCRIPT
from controller.qualify_socket_close import rules_only


def diagnostic_script(*, empty_bluez=False, synthetic_adapter=False):
    if empty_bluez and synthetic_adapter:
        raise ValueError("choose one explicit service fixture")
    mode = "--run-sdk-adapter" if synthetic_adapter else "--run-sdk-bluez" if empty_bluez else "--run-sdk"
    script = BUS_SCRIPT.replace("PROBE --run ", f"PROBE {mode} ")
    # The same owned-PID watchdog also watches the SDK family leader. Its
    # descendants inherit PDEATH/ptrace EXITKILL; no stock process is targeted.
    script = script.replace(
        '"$STATE"/root[012]-client.child;',
        '"$STATE"/root[012]-client.child "$STATE"/root[012]-sdk.child;',
    ).replace(
        '"$state"/root[012]-client.child;',
        '"$state"/root[012]-client.child "$state"/root[012]-sdk.child;',
    )
    for prefix in ["STATE", "state"]:
        before = f'        [ ! -e "${prefix}/listener$epoch" ]'
        extra = "\n".join(
            [
                f'        [ ! -d "${prefix}/root$epoch-sdk" ] || rmdir "${prefix}/root$epoch-sdk"',
                f'        [ ! -d "${prefix}/root$epoch-sdk-stage" ] || rmdir "${prefix}/root$epoch-sdk-stage"',
                f'        [ ! -f "${prefix}/root$epoch-sdk.child" ] || rm "${prefix}/root$epoch-sdk.child"',
            ]
        )
        script = script.replace(before, extra + "\n" + before)
    return script.replace(
        "remaining\nprintf '%s %s %s",
        "remaining\nprintf '{\"event\":\"sdk-bus-state\",\"path\":\"%s\"}\\n' \"$STATE\"\nprintf '%s %s %s",
    )


def evaluate_events(events, *, empty_bluez=False, synthetic_adapter=False):
    """Require SDK boundary, real EXTERNAL authentication and complete teardown."""
    if empty_bluez and synthetic_adapter:
        return False
    if empty_bluez or synthetic_adapter:
        if type(events) is not list or len(events) != 13 or any(type(e) is not dict for e in events):
            return False
        for index, role in [(2, "own-elf"), (6, "platform")]:
            event = events[index]
            required = dict(event="sdk-adapter-provider" if synthetic_adapter else "sdk-empty-provider",
                            role=role, primary_owner=True, closed=True, hardware_opened=False)
            required["synthetic_adapter" if synthetic_adapter else "empty_tree_only"] = True
            if (set(event) != set(required) | {"calls"}
                or any(type(event.get(k)) is not type(v) or event[k] != v for k, v in required.items())
                or type(event.get("calls")) is not int or not 1 <= event["calls"] <= 4
                or (role == "own-elf" and event["calls"] != 1)):
                return False
        if type(events[8].get("checks")) is not int or events[8]["checks"] != 29:
            return False
        normalized = [events[0], events[1], events[3], events[4], events[5], events[7],
                      dict(events[8], checks=26), *events[9:]]
        return evaluate_events(normalized)
    if type(events) is not list or len(events) != 11 or any(type(e) is not dict for e in events):
        return False
    for i, role in [(0, "own-elf"), (3, "platform")]:
        event = events[i]
        required = dict(
            event="sdk-bus-diagnostic", role=role, boundary_ok=True,
            exec_verified=True, binding_mapped=True, drained=True,
            synthetic_identity=True, audio_opened=False, functionality_verified=False,
        )
        if any(type(event.get(k)) is not type(v) or event[k] != v for k, v in required.items()):
            return False
        bounds = {
            "threads": (0, 79), "syscalls": (1, 20000), "denied": (0, 20000),
            "socket_attempts": (0, 20000), "lost_registers": (0, 20000),
            "exit_code": (-1, 255), "exit_signal": (0, 64), "private_objects_mask": (0, 63),
            "private_stderr_bytes": (0, 65536),
        }
        if any(type(event.get(k)) is not int or not low <= event[k] <= high for k, (low, high) in bounds.items()):
            return False
        if any(type(event.get(k)) is not bool for k in ["bounded_stop", "path_control", "private_stderr_truncated"]):
            return False
        if set(event) != set(required) | set(bounds) | {"bounded_stop", "path_control", "private_stderr_truncated"}:
            return False
        if (event["exit_code"] == -1) != (event["exit_signal"] > 0):
            return False
        if role == "own-elf" and (
            event["threads"] != 9 or event["exit_code"] != -1 or event["exit_signal"] != 6
            or not event["path_control"] or not event["private_objects_mask"] & 1
            or event["bounded_stop"]
        ):
            return False
        relay = events[i + 1]
        required = dict(event="sdk-bus-relay", role=role, boundary_ok=True, actor_checks=11, auth_verified=True, protocol_traffic=True)
        if any(type(relay.get(k)) is not type(v) or relay[k] != v for k, v in required.items()):
            return False
        if (
            type(relay.get("result")) is not int or relay["result"] not in range(5)
            or relay["result"] == 1 or type(relay.get("origin")) is not int
            or relay["origin"] not in [-1, 0, 1] or type(relay.get("protocol_traffic")) is not bool
        ):
            return False
        if set(relay) != set(required) | {"result", "origin"}:
            return False
        if role == "own-elf" and (relay["result"] != 0 or relay["origin"] != 0 or not relay["protocol_traffic"]):
            return False
        observer = events[i + 2]
        required = dict(event="sdk-match-observer", role=role, snapshot_captured=True,
                        own_fixture_match=role == "own-elf", sdk_subscription_removed=True,
                        observer_closed=True, private_metadata_only=True)
        if (set(observer) != set(required) | {"queries", "peak_rules"}
            or any(type(observer.get(k)) is not type(v) or observer[k] != v for k, v in required.items())
            or type(observer.get("queries")) is not int or not 1 <= observer["queries"] <= 40
            or type(observer.get("peak_rules")) is not int or not 1 <= observer["peak_rules"] <= 4
            or (role == "own-elf" and observer["peak_rules"] != 2)):
            return False
    wanted = [
        dict(event="sdk-subscription-policy", checks=26, failures=0, driver_signal_received=True,
             peer_signal_blocked=True, rule_limit=4, connections_closed=True, own_controls_only=True),
        dict(selftest="sdk-private-bus", ok=True, sdk_executed=True, audio_opened=False, functionality_verified=False),
        dict(event="private-bus-parent", checks=5, failures=0, unrelated_internet_controls=True),
        dict(event="private-bus-exit", code=0), dict(event="private-bus-cleanup", ok=True),
    ]
    return all(
        row == target and all(type(row.get(k)) is type(v) for k, v in target.items())
        for row, target in zip(events[6:], wanted, strict=True)
    )


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("host")
    parser.add_argument("--ssh-config", type=Path)
    parser.add_argument("--run-sdk-bus-diagnostic", action="store_true", required=True)
    service = parser.add_mutually_exclusive_group()
    service.add_argument("--empty-bluez", action="store_true", help="Explicit empty ObjectManager lab; no Bluetooth hardware")
    service.add_argument("--synthetic-adapter", action="store_true", help="One synthetic offline Adapter1; no real Bluetooth hardware")
    args = parser.parse_args()
    if args.host.startswith("-"):
        parser.error("SSH alias required")
    root = Path(__file__).resolve().parents[1]
    ssh = ["ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=20"]
    if args.ssh_config:
        ssh += ["-F", str(args.ssh_config)]
    ssh += [args.host]

    def remote(command, **kwargs):
        return subprocess.run(ssh + [command], capture_output=True, timeout=120, **kwargs)

    remote("test ! -e /data/opt/lisa-lab/trial.lock && test ! -e /bkupgrade/data/opt/lisa-station/state && test ! -e /run/lisa-station", check=True)
    resolved, digests = [], []
    for name, filename in [
        ("private-bus-probe", "private-bus-probe.armhf"),
        ("private-bus-factory", "private-bus-factory.so"),
        ("unix-bus-factory", "unix-bus-factory.so"),
    ]:
        data = (root / "build" / filename).read_bytes()
        digest = hashlib.sha256(data).hexdigest()
        target = "/data/opt/lisa-controller-lab/" + name + "-" + digest[:16]
        remote("umask 077; cat > " + target + ".new && chmod 700 " + target + ".new", input=data, check=True)
        if remote("sha256sum " + target + ".new", check=True).stdout.decode().split()[0] != digest:
            raise RuntimeError("artifact digest mismatch")
        remote("mv " + target + ".new " + target, check=True)
        resolved.append(canonical_lab_artifact(remote, target))
        digests.append(digest)
    identity = "pidof dbus-daemon quasar_launcher2 maind alsa-audio-monitord hardvold chronyd unbound; cat /proc/sys/kernel/random/boot_id; sha256sum /etc/init.d/rcS /etc/init.d/S99zdropbear /etc/chrony.conf /etc/unbound/unbound.conf /etc/resolv.conf"
    before = remote(identity, check=True).stdout
    firewall = remote("iptables-save; ip6tables-save", check=True).stdout
    script = diagnostic_script(empty_bluez=args.empty_bluez, synthetic_adapter=args.synthetic_adapter).replace("PROBE", resolved[0]).replace("FACTORY", resolved[1]).replace("CLIENT_LIBRARY", resolved[2])
    result = remote("sh -s", input=script.encode())
    after = remote(identity, check=True).stdout
    after_firewall = remote("iptables-save; ip6tables-save", check=True).stdout
    report_name = "sdk-adapter-bus" if args.synthetic_adapter else "sdk-bluez-bus" if args.empty_bluez else "sdk-bus"
    (root / f"build/{report_name}.stdout.private.txt").write_bytes(result.stdout)
    (root / f"build/{report_name}.stderr.private.txt").write_bytes(result.stderr)
    events = [json.loads(line) for line in result.stdout.decode().splitlines()]
    state = None
    if events and events[0].get("event") == "sdk-bus-state":
        state = events.pop(0).get("path")
    prefix = "/bkupgrade/data/opt/lisa-controller-lab/private-bus."
    if isinstance(state, str) and state.startswith(prefix) and 6 <= len(state[len(prefix):]) <= 16 and state[len(prefix):].isascii() and state[len(prefix):].isalnum():
        (root / f"build/{report_name}-state.private.txt").write_text(state + "\n", encoding="utf-8")
        for role in range(2):
            for suffix in ["stderr", "paths", "bus-stderr", "match"]:
                name = f"sdk{role}-{suffix}.private.txt"
                local_name = "adapter-" + name if args.synthetic_adapter else "bluez-" + name if args.empty_bluez else name
                saved = remote("test ! -L " + state + "/" + name + " && head -c 65536 " + state + "/" + name)
                if saved.returncode == 0:
                    (root / "build" / local_name).write_bytes(saved.stdout)
                else:
                    # An early control failure must not leave a prior SDK
                    # run's private log looking like current evidence.
                    (root / "build" / local_name).unlink(missing_ok=True)
    else:
        raise RuntimeError("missing canonical private SDK evidence location")
    report = dict(
        binary_sha256=digests[0], binding_sha256=digests[1], client_binding_sha256=digests[2],
        returncode=result.returncode, events=events,
        qualified=result.returncode == 0 and evaluate_events(events, empty_bluez=args.empty_bluez, synthetic_adapter=args.synthetic_adapter),
        stock_identity_and_configs_preserved=before == after,
        firewall_unchanged=rules_only(firewall) == rules_only(after_firewall),
        audio_captured=False, sdk_executed=any(e.get("event") == "sdk-bus-diagnostic" and e.get("role") == "platform" and e.get("exec_verified") is True for e in events),
        host_bus_forwarded=False, production_mode_changed=False,
        isolation_verified=False, functionality_verified=False,
    )
    (root / f"build/{report_name}-qualification.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(report, indent=2))
    if not report["qualified"] or not report["stock_identity_and_configs_preserved"] or not report["firewall_unchanged"]:
        raise SystemExit("SDK bus diagnostic incomplete; inspect private evidence")


if __name__ == "__main__":
    main()
