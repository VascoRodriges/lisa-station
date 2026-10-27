"""Reject compatibility snapshots which hide respawns or lost restrictions."""

from copy import deepcopy

import pytest

from controller.qualify_vendor_startup import evaluate_samples


def samples():
    workers = [
        dict(pid=100 + index, gid=57342, no_new_privs=None, seccomp=2, cap_eff="0000003ffff7cfff")
        for index in range(4)
    ]
    return [dict(workers=deepcopy(workers[:3]))] + [dict(workers=deepcopy(workers)) for _ in range(3)]


def test_warmup_does_not_mask_stable_protected_startup():
    assert evaluate_samples(samples())


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("pid", 999),
        ("gid", 0),
        ("seccomp", 0),
        ("no_new_privs", 0),
        ("cap_eff", "0000003fffffffff"),
    ],
)
def test_respawn_or_lost_restriction_rejected(field, value):
    data = samples()
    data[-1]["workers"][0][field] = value
    assert not evaluate_samples(data)


def test_missing_or_incomplete_snapshots_rejected():
    assert not evaluate_samples([])
    data = samples()
    data[-1]["workers"].pop()
    assert not evaluate_samples(data)
