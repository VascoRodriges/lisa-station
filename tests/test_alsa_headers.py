import hashlib
import io
import tarfile

import pytest

from controller import alsa_headers


def release():
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode="w:bz2") as archive:
        for name in (*("include/" + h for h in alsa_headers.HEADERS), "COPYING"):
            member = tarfile.TarInfo(f"alsa-lib-{alsa_headers.VERSION}/{name}")
            body = name.encode()
            member.size = len(body)
            archive.addfile(member, io.BytesIO(body))
        # Unselected unsafe entries must never be extracted.
        member = tarfile.TarInfo("../../escape")
        member.type = tarfile.SYMTYPE
        member.linkname = "/etc/passwd"
        archive.addfile(member)
    return output.getvalue()


def test_only_fixed_regular_headers_and_license_are_materialized(tmp_path, monkeypatch):
    data = release()
    monkeypatch.setattr(alsa_headers, "SHA256", hashlib.sha256(data).hexdigest())
    alsa_headers.unpack_headers(data, tmp_path)
    assert (tmp_path / "alsa/control_external.h").read_text() == "include/control_external.h"
    assert (tmp_path / "COPYING.alsa-lib").read_text() == "COPYING"
    assert "LGPL-2.1-or-later" in (tmp_path / "PROVENANCE.txt").read_text()
    assert sorted(p.name for p in tmp_path.iterdir()) == ["COPYING.alsa-lib", "PROVENANCE.txt", "alsa"]


@pytest.mark.parametrize("data", [b"", b"not a release", b"x" * (alsa_headers.LIMIT + 1)])
def test_rejects_bad_digest_or_oversize_without_output(tmp_path, data):
    with pytest.raises(ValueError, match="digest"):
        alsa_headers.unpack_headers(data, tmp_path)
    assert not list(tmp_path.iterdir())


@pytest.mark.parametrize("selected", ["include/control_external.h", "COPYING"])
def test_rejects_selected_symlink_before_any_header_is_written(tmp_path, monkeypatch, selected):
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode="w:bz2") as archive:
        for name in (*("include/" + h for h in alsa_headers.HEADERS), "COPYING"):
            member = tarfile.TarInfo(f"alsa-lib-{alsa_headers.VERSION}/{name}")
            if name == selected:
                member.type = tarfile.SYMTYPE
                member.linkname = "/etc/passwd"
                archive.addfile(member)
            else:
                member.size = 1
                archive.addfile(member, io.BytesIO(b"x"))
    data = output.getvalue()
    monkeypatch.setattr(alsa_headers, "SHA256", hashlib.sha256(data).hexdigest())
    with pytest.raises(ValueError, match="member"):
        alsa_headers.unpack_headers(data, tmp_path)
    assert not list(tmp_path.iterdir())
