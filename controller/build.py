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
        "station-init",
        "boot-runner-probe",
        "boot-dispatch-probe",
        "station-boot",
        "boot-state-probe",
        "auxiliary-probe",
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
    "station-init": "station_init.c",
    "boot-runner-probe": "boot_runner_probe.c",
    "boot-dispatch-probe": "boot_dispatch_probe.c",
    "station-boot": "station_boot.c",
    "boot-state-probe": "boot_state_probe.c",
    "auxiliary-probe": "auxiliary_probe.c",
}
output = root / "build" / (args.target + ".armhf")
output.parent.mkdir(exist_ok=True)
assert subprocess.check_output([args.zig, "version"], text=True).strip() == "0.14.1"
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
        *(["-ldl"] if args.target == "diagnostics-guard-probe" else []),
        "-o",
        str(output),
    ],
    check=True,
)
print("BUILD_OK", output.name, output.stat().st_size, hashlib.sha256(output.read_bytes()).hexdigest())
