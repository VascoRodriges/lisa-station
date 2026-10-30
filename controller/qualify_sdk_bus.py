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


def diagnostic_script():
    script = BUS_SCRIPT.replace("PROBE --run ", "PROBE --run-sdk ")
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


def evaluate_events(events):
    """Require complete control, SDK boundary, drain and unchanged-root proofs."""
    if type(events) is not list or len(events) != 8 or any(type(e) is not dict for e in events):
        return False
    for i, role in [(0, "own-elf"), (2, "platform")]:
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
        required = dict(event="sdk-bus-relay", role=role, boundary_ok=True, actor_checks=11)
        if any(type(relay.get(k)) is not type(v) or relay[k] != v for k, v in required.items()):
            return False
        if (
            type(relay.get("result")) is not int or relay["result"] not in range(5)
            or relay["result"] == 1 or type(relay.get("origin")) is not int
            or relay["origin"] not in [-1, 0, 1] or type(relay.get("protocol_traffic")) is not bool
        ):
            return False
        if set(relay) != set(required) | {"result", "origin", "protocol_traffic"}:
            return False
        if role == "own-elf" and (relay["result"] != 0 or relay["origin"] != 0 or not relay["protocol_traffic"]):
            return False
    wanted = [
        dict(selftest="sdk-private-bus", ok=True, sdk_executed=True, audio_opened=False, functionality_verified=False),
        dict(event="private-bus-parent", checks=5, failures=0, unrelated_internet_controls=True),
        dict(event="private-bus-exit", code=0), dict(event="private-bus-cleanup", ok=True),
    ]
    return all(
        row == target and all(type(row.get(k)) is type(v) for k, v in target.items())
        for row, target in zip(events[4:], wanted, strict=True)
    )


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("host")
    parser.add_argument("--ssh-config", type=Path)
    parser.add_argument("--run-sdk-bus-diagnostic", action="store_true", required=True)
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
    script = diagnostic_script().replace("PROBE", resolved[0]).replace("FACTORY", resolved[1]).replace("CLIENT_LIBRARY", resolved[2])
    result = remote("sh -s", input=script.encode())
    after = remote(identity, check=True).stdout
    after_firewall = remote("iptables-save; ip6tables-save", check=True).stdout
    (root / "build/sdk-bus.stdout.private.txt").write_bytes(result.stdout)
    (root / "build/sdk-bus.stderr.private.txt").write_bytes(result.stderr)
    events = [json.loads(line) for line in result.stdout.decode().splitlines()]
    state = None
    if events and events[0].get("event") == "sdk-bus-state":
        state = events.pop(0).get("path")
    prefix = "/bkupgrade/data/opt/lisa-controller-lab/private-bus."
    if isinstance(state, str) and state.startswith(prefix) and 6 <= len(state[len(prefix):]) <= 16 and state[len(prefix):].isascii() and state[len(prefix):].isalnum():
        (root / "build/sdk-bus-state.private.txt").write_text(state + "\n", encoding="utf-8")
        for role in range(2):
            for suffix in ["stderr", "paths", "bus-stderr"]:
                name = f"sdk{role}-{suffix}.private.txt"
                saved = remote("test ! -L " + state + "/" + name + " && head -c 65536 " + state + "/" + name)
                if saved.returncode == 0:
                    (root / "build" / name).write_bytes(saved.stdout)
    else:
        raise RuntimeError("missing canonical private SDK evidence location")
    report = dict(
        binary_sha256=digests[0], binding_sha256=digests[1], client_binding_sha256=digests[2],
        returncode=result.returncode, events=events,
        qualified=result.returncode == 0 and evaluate_events(events),
        stock_identity_and_configs_preserved=before == after,
        firewall_unchanged=rules_only(firewall) == rules_only(after_firewall),
        audio_captured=False, sdk_executed=any(e.get("role") == "platform" for e in events),
        host_bus_forwarded=False, production_mode_changed=False,
        isolation_verified=False, functionality_verified=False,
    )
    (root / "build/sdk-bus-qualification.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(report, indent=2))
    if not report["qualified"] or not report["stock_identity_and_configs_preserved"] or not report["firewall_unchanged"]:
        raise SystemExit("SDK bus diagnostic incomplete; inspect private evidence")


if __name__ == "__main__":
    main()
