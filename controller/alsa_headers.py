"""Fetch hash-pinned public ALSA headers; never use firmware build inputs."""

import argparse
import hashlib
import io
import tarfile
import urllib.request
from pathlib import Path

VERSION = "1.2.1.2"
URL = f"https://www.alsa-project.org/files/pub/lib/alsa-lib-{VERSION}.tar.bz2"
SHA256 = "958e260e3673f1f6ff6b2d2c0df3fc2e469bea5b2957163ce96ce17f23e87943"
LIMIT = 4 * 1024 * 1024
HEADERS = ("global.h", "input.h", "output.h", "conf.h", "control.h", "control_external.h", "mixer.h")


def unpack_headers(data: bytes, output: Path):
    if len(data) > LIMIT or hashlib.sha256(data).hexdigest() != SHA256:
        raise ValueError("ALSA public release digest mismatch")
    # Only fixed regular members, no extractall, paths or symlinks from the tar.
    contents = {}
    with tarfile.open(fileobj=io.BytesIO(data), mode="r:bz2") as archive:
        for name in (*("include/" + header for header in HEADERS), "COPYING"):
            member = archive.getmember(f"alsa-lib-{VERSION}/{name}")
            if not member.isfile() or not 0 < member.size <= 128 * 1024:
                raise ValueError("Invalid public header member")
            with archive.extractfile(member) as stream:
                contents[name] = stream.read()
    for name, body in contents.items():
        target = output / ("alsa/" + Path(name).name if name.startswith("include/") else "COPYING.alsa-lib")
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(body)
    (output / "PROVENANCE.txt").write_text(f"{URL}\nsha256 {SHA256}\nLGPL-2.1-or-later; see COPYING.alsa-lib\n", encoding="utf-8")
    return output


def prepare_headers(root: Path):
    cache = root / "build" / f"alsa-lib-{VERSION}.tar.bz2"
    if cache.exists():
        data = cache.read_bytes()
    else:
        with urllib.request.urlopen(URL, timeout=40) as response:
            data = response.read(LIMIT + 1)
        if len(data) > LIMIT or hashlib.sha256(data).hexdigest() != SHA256:
            raise ValueError("ALSA public release digest mismatch")
        cache.parent.mkdir(parents=True, exist_ok=True)
        cache.write_bytes(data)
    return unpack_headers(data, root / "build" / "alsa-public-headers")


if __name__ == "__main__":
    argparse.ArgumentParser(description=__doc__).parse_args()
    print(prepare_headers(Path(__file__).resolve().parents[1]))
