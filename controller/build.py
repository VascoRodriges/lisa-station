"""Reproducible native helper build; requires Zig 0.14.1, no firmware inputs."""

import argparse
import hashlib
import subprocess
from pathlib import Path

parser = argparse.ArgumentParser()
parser.add_argument("--zig", default="zig")
args = parser.parse_args()
root = Path(__file__).resolve().parents[1]
output = root / "build/station-ctl.armhf"
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
        str(root / "controller/station_ctl.c"),
        "-o",
        str(output),
    ],
    check=True,
)
print("BUILD_OK", output.name, output.stat().st_size, hashlib.sha256(output.read_bytes()).hexdigest())
