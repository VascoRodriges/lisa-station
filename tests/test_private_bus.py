from copy import deepcopy

import pytest

from controller.qualify_private_bus import evaluate_events


def evidence():
    return [
        dict(event="private-bus-control", checks=15, failures=0),
        *[
            dict(
                event="private-bus-epoch",
                epoch=i,
                checks=count,
                failures=0,
                actual_daemon=i > 0,
                fd_negotiation_disabled=False,
            )
            for i, count in enumerate([7, 28, 49])
        ],
        dict(
            selftest="private-bus",
            checks=50,
            failures=0,
            ok=True,
            sdk_executed=False,
            audio_opened=False,
            isolation_verified=False,
        ),
        dict(event="private-bus-parent", checks=5, failures=0, unrelated_internet_controls=True),
        dict(event="private-bus-exit", code=0),
        dict(event="private-bus-cleanup", ok=True),
    ]


def test_accepts_complete_private_daemon_trial():
    assert evaluate_events(evidence())


@pytest.mark.parametrize("index", range(8))
def test_requires_complete_ordered_unique_evidence(index):
    rows = evidence()
    del rows[index]
    assert not evaluate_events(rows)
    rows = evidence()
    rows.insert(index, deepcopy(rows[index]))
    assert not evaluate_events(rows)
    rows = evidence()
    rows[index]["unexpected"] = True
    assert not evaluate_events(rows)
    rows = evidence()
    rows[index] = None
    assert not evaluate_events(rows)


@pytest.mark.parametrize(
    "index,key,value",
    [
        (0, "checks", 14),
        (0, "failures", 1),
        (1, "epoch", False),
        (2, "checks", 27),
        (3, "failures", 1),
        (2, "actual_daemon", False),
        (3, "actual_daemon", 1),
        (2, "fd_negotiation_disabled", True),
        (4, "checks", 49),
        (4, "ok", False),
        (4, "sdk_executed", True),
        (4, "audio_opened", True),
        (4, "isolation_verified", True),
        (5, "failures", 1),
        (5, "unrelated_internet_controls", False),
        (6, "code", False),
        (6, "code", 1),
        (7, "ok", 1),
        (7, "ok", False),
    ],
)
def test_rejects_failed_or_overstated_scope(index, key, value):
    rows = evidence()
    rows[index][key] = value
    assert not evaluate_events(rows)


@pytest.mark.parametrize("value", [None, {}, True, [None] * 8])
def test_rejects_invalid_container(value):
    assert not evaluate_events(value)
