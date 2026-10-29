"""Resolve a fixed lab artifact before comparing it with proc executable paths."""

import re


def canonical_lab_artifact(remote, alias):
    if type(alias) is not str or not re.fullmatch(
        r"/data/opt/lisa-controller-lab/[a-z][a-z0-9-]*-[0-9a-f]{16}", alias
    ):
        raise ValueError("unexpected lab artifact alias")
    expected = "/bkupgrade" + alias
    result = remote("readlink -f " + alias, check=True)
    if result.stdout != (expected + "\n").encode():
        raise ValueError("unexpected canonical lab artifact path")
    return expected
