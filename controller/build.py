"""Reproducible native helper build; requires Zig 0.14.1, no firmware inputs."""

import argparse
import hashlib
import subprocess
from pathlib import Path

parser = argparse.ArgumentParser()
parser.add_argument("--zig", default="zig")
parser.add_argument(
    "--target",
    choices=(
        "station-ctl",
        "net-owner-probe",
        "vendor-launch-probe",
        "mode-store-probe",
        "socket-close-probe",
        "flow-quarantine-probe",
        "service-profile-probe",
        "service-gate-probe",
        "startup-guardian-probe",
        "station-service",
        "closed-transition-probe",
        "open-transition-probe",
        "flow-store-probe",
        "closed-flow-probe",
        "tcp-evidence-probe",
        "diagnostics-guard-probe",
        "relay-evidence-probe",
        "collector-guard-probe",
        "telemetry-guard-probe",
        "unix-peer-probe",
        "composite-roles-probe",
        "ipc-guard-probe",
        "udp-evidence-probe",
        "connmark-probe",
        "label-policy-probe",
        "epoch-policy-probe",
        "epoch-mutation-probe",
        "platform-storage-probe",
        "platform-worker-probe",
        "platform-sdk-probe",
        "unix-channel-probe",
        "unix-bus-factory",
        "unix-mixer-factory",
        "private-bus-probe",
        "master-read-probe",
        "master-ctl-plugin",
        "bus-auth-probe",
        "bus-relay-probe",
        "private-bus-factory",
        "private-bus-error-factory",
        "station-init",
        "boot-runner-probe",
        "boot-dispatch-probe",
        "station-boot",
        "boot-state-probe",
        "auxiliary-probe",
        "dns-profile-probe",
        "time-guard-probe",
        "time-clock-proof",
    ),
    default="station-ctl",
)
args = parser.parse_args()
root = Path(__file__).resolve().parents[1]
sources = {
    "station-ctl": "station_ctl.c",
    "net-owner-probe": "net_owner_probe.c",
    "vendor-launch-probe": "vendor_launch_probe.c",
    "mode-store-probe": "mode_store_probe.c",
    "socket-close-probe": "socket_close_probe.c",
    "flow-quarantine-probe": "flow_quarantine_probe.c",
    "service-profile-probe": "service_profile_probe.c",
    "service-gate-probe": "service_gate_probe.c",
    "startup-guardian-probe": "startup_guardian_probe.c",
    "station-service": "station_service.c",
    "closed-transition-probe": "closed_transition_probe.c",
    "open-transition-probe": "open_transition_probe.c",
    "flow-store-probe": "flow_store_probe.c",
    "closed-flow-probe": "closed_flow_probe.c",
    "tcp-evidence-probe": "tcp_evidence_probe.c",
    "diagnostics-guard-probe": "diagnostics_guard_probe.c",
    "relay-evidence-probe": "relay_evidence_probe.c",
    "collector-guard-probe": "collector_guard_probe.c",
    "telemetry-guard-probe": "telemetry_guard_probe.c",
    "unix-peer-probe": "unix_peer_probe.c",
    "composite-roles-probe": "composite_roles_probe.c",
    "ipc-guard-probe": "ipc_guard_probe.c",
    "udp-evidence-probe": "udp_evidence_probe.c",
    "connmark-probe": "connmark_probe.c",
    "label-policy-probe": "label_policy_probe.c",
    "epoch-policy-probe": "epoch_policy_probe.c",
    "epoch-mutation-probe": "epoch_mutation_probe.c",
    "platform-storage-probe": "platform_storage_probe.c",
    "platform-worker-probe": "platform_worker_probe.c",
    "platform-sdk-probe": "platform_sdk_probe.c",
    "unix-channel-probe": "unix_channel_probe.c",
    "unix-bus-factory": "unix_bus_factory.c",
    "unix-mixer-factory": "unix_bus_factory.c",
    "private-bus-probe": "private_bus_probe.c",
    "master-read-probe": "master_broker_probe.c",
    "master-ctl-plugin": "master_ctl_plugin.c",
    "bus-auth-probe": "bus_auth_probe.c",
    "bus-relay-probe": "bus_relay_probe.c",
    "private-bus-factory": "private_bus_factory.c",
    "private-bus-error-factory": "private_bus_factory.c",
    "station-init": "station_init.c",
    "boot-runner-probe": "boot_runner_probe.c",
    "boot-dispatch-probe": "boot_dispatch_probe.c",
    "station-boot": "station_boot.c",
    "boot-state-probe": "boot_state_probe.c",
    "auxiliary-probe": "auxiliary_probe.c",
    "dns-profile-probe": "dns_profile_probe.c",
    "time-guard-probe": "time_guard_probe.c",
    "time-clock-proof": "time_clock_proof.c",
}
output = (
    root
    / "build"
    / (
        args.target
        + (
            ".so"
            if args.target in {"time-clock-proof", "unix-bus-factory", "unix-mixer-factory", "private-bus-factory", "private-bus-error-factory", "master-ctl-plugin"}
            else ".armhf"
        )
    )
)
output.parent.mkdir(exist_ok=True)
assert subprocess.check_output([args.zig, "version"], text=True).strip() == "0.14.1"
plugin_flags = []
if args.target == "master-ctl-plugin":
    from alsa_headers import prepare_headers

    plugin_flags = ["-DPIC", "-I" + str(prepare_headers(root))]
subprocess.run(
    [
        args.zig,
        "cc",
        "-target",
        "arm-linux-gnueabihf.2.30",
        "-mcpu=cortex_a53",
        "-O2",
        "-Wall",
        "-Wextra",
        "-Werror",
        str(root / "controller" / sources[args.target]),
        *(
            ["-pthread"]
            if args.target
            in {"platform-worker-probe", "platform-sdk-probe", "unix-bus-factory", "unix-mixer-factory", "unix-channel-probe", "private-bus-probe", "master-ctl-plugin"}
            else []
        ),
        *(["-ldl"] if args.target in {"diagnostics-guard-probe", "time-clock-proof", "private-bus-error-factory", "unix-mixer-factory", "private-bus-probe"} else []),
        *(["-DLISA_PRIVATE_ERROR_AUDIT=1"] if args.target == "private-bus-error-factory" else []),
        *(["-DLISA_MIXER_DIAGNOSTIC=1"] if args.target == "unix-mixer-factory" else []),
        *plugin_flags,
        *(
            ["-shared", "-fPIC"]
            if args.target in {"time-clock-proof", "unix-bus-factory", "unix-mixer-factory", "private-bus-factory", "private-bus-error-factory", "master-ctl-plugin"}
            else []
        ),
        "-o",
        str(output),
    ],
    check=True,
)
print("BUILD_OK", output.name, output.stat().st_size, hashlib.sha256(output.read_bytes()).hexdigest())
