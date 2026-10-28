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
        "-o",
        str(output),
    ],
    check=True,
)
print("BUILD_OK", output.name, output.stat().st_size, hashlib.sha256(output.read_bytes()).hexdigest())
