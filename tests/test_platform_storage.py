"""Synthetic storage evidence cannot be upgraded to SDK/privacy acceptance."""

import pytest

from controller.qualify_platform_storage import SCRIPT, evaluate_events


def evidence():
    return [
        dict(selftest="platform-seeds", checks=50, ok=True, synthetic_only=True),
        dict(
            event="platform-storage-epoch",
            epoch=1,
            checks=100,
            failures=0,
            synthetic_only=True,
            audio_opened=False,
        ),
        dict(
            event="platform-storage-epoch",
            epoch=2,
            checks=205,
            failures=0,
            synthetic_only=True,
            audio_opened=False,
        ),
        dict(
            selftest="platform-storage",
            checks=206,
            ok=True,
            synthetic_only=True,
            audio_opened=False,
            vendor_processes_changed=False,
            isolation_verified=False,
        ),
        dict(event="platform-storage-exit", code=0),
        dict(event="platform-storage-cleanup", ok=True),
    ]


def test_two_private_synthetic_epochs():
    assert evaluate_events(evidence())


@pytest.mark.parametrize(
    "index,key,value",
    [
        (0, "checks", True),
        (0, "checks", 0),
        (0, "checks", 49),
        (0, "ok", 1),
        (0, "synthetic_only", False),
        (1, "epoch", True),
        (1, "epoch", 2),
        (1, "checks", 0),
        (1, "failures", True),
        (1, "failures", 1),
        (1, "synthetic_only", False),
        (1, "audio_opened", True),
        (2, "epoch", 1),
        (2, "checks", 100),
        (2, "failures", 1),
        (2, "audio_opened", True),
        (3, "checks", 205),
        (3, "checks", True),
        (3, "ok", False),
        (3, "synthetic_only", False),
        (3, "audio_opened", True),
        (3, "vendor_processes_changed", True),
        (3, "isolation_verified", True),
        (4, "code", False),
        (4, "code", 4),
        (5, "ok", False),
        (5, "ok", 1),
    ],
)
def test_false_or_incomplete_storage_evidence_rejected(index, key, value):
    rows = evidence()
    rows[index][key] = value
    assert not evaluate_events(rows)


@pytest.mark.parametrize("rows", [None, {}, [], [None] * 6])
def test_bad_shape(rows):
    assert not evaluate_events(rows)


def test_cleanup_is_scoped_and_waits_for_owned_workers():
    assert 'PROBE --cleanup "$STATE"' in SCRIPT
    assert 'PROBE --cleanup "$state"' in SCRIPT
    assert "$(cat /data/opt/lisa-lab/trial.lock/platform-storage.owner)" in SCRIPT
    assert '"$(readlink /proc/"$pid"/exe' in SCRIPT
    assert 'kill -KILL "$pid"' in SCRIPT
    assert "rm -r" not in SCRIPT and "iptables -F" not in SCRIPT


def test_no_missing_epoch_or_cleanup():
    assert not evaluate_events(evidence()[:-1])
    rows = evidence()
    rows[1], rows[2] = rows[2], rows[1]
    assert not evaluate_events(rows)
