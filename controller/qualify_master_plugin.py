"""Host-only ALSA plugin ABI tests with an explicitly synthetic packet peer."""

import argparse
import os
import subprocess
import sys
import tarfile
import tempfile
from pathlib import Path

from controller.alsa_headers import VERSION, prepare_headers


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--sanitize", action="store_true")
    args = parser.parse_args()
    if not sys.platform.startswith("linux"):
        parser.error("The host ABI fixture requires Linux, a C compiler and make")
    root = Path(__file__).resolve().parents[1]
    headers = prepare_headers(root)
    # prepare_headers verifies the entire release hash, including source/license.
    # A fresh directory avoids adopting a previous mutable library as evidence.
    work = Path(tempfile.mkdtemp(prefix="master-plugin-host.", dir=root / "build"))
    archive_path = root / "build" / f"alsa-lib-{VERSION}.tar.bz2"
    with tarfile.open(archive_path, "r:bz2") as archive:
        if any(not member.name.startswith(f"alsa-lib-{VERSION}/") and member.name != f"alsa-lib-{VERSION}"
               for member in archive.getmembers()):
            raise ValueError("Unexpected ALSA public archive root")
        archive.extractall(work, filter="data")
    source = work / f"alsa-lib-{VERSION}"
    with (work / "library-build.log").open("wb") as log:
        subprocess.run([str(source / "configure"), "--disable-static", "--disable-python", "--disable-alisp",
                        "--disable-ucm", "--disable-topology", "--disable-hwdep", "--disable-rawmidi", "--disable-seq"],
                       cwd=source, stdout=log, stderr=subprocess.STDOUT, check=True, timeout=120)
        subprocess.run(["make", "-j2"], cwd=source, stdout=log, stderr=subprocess.STDOUT, check=True, timeout=240)
    library = source / "src" / ".libs"
    flags = ["-O1", "-g", "-fsanitize=address,undefined", "-fno-omit-frame-pointer"] if args.sanitize else ["-O2", "-D_FORTIFY_SOURCE=3"]
    common = ["cc", *flags, "-Wall", "-Wextra", "-Werror", "-fstack-protector-strong", "-pthread", "-I" + str(headers)]
    plugin, probe = work / "libasound_module_ctl_lisa_master.so", work / "master-plugin-probe"
    subprocess.run(common + ["-DPIC", "-shared", "-fPIC", str(root / "controller/master_ctl_plugin.c"), "-o", str(plugin)], check=True)
    subprocess.run(common + [str(root / "controller/master_plugin_probe.c"), "-ldl", "-L" + str(library), "-l:libasound.so.2", "-o", str(probe)], check=True)
    environment = os.environ.copy()
    # Exclude unrelated host ALSA library/plugin/search settings from this fixture.
    for key in list(environment):
        if key.startswith(("ALSA_", "LISA_MASTER_", "LD_")):
            del environment[key]
    environment["LD_LIBRARY_PATH"] = str(library)
    subprocess.run([str(probe), str(plugin)], env=environment, check=True, timeout=40)


if __name__ == "__main__":
    main()
