from copy import deepcopy

import pytest

from controller.qualify_private_bus import evaluate_events


def evidence():
    rows = [dict(event="private-bus-control", checks=15, failures=0)]
    for i, count in enumerate([7, 29, 51]):
        if i:
            relay = dict(
                event="private-bus-relay",
                epoch=i,
                actor_checks=11,
                failures=0,
                result=0,
                origin=1 if i == 1 else 0,
                bounded=True,
            )
            client = dict(
                event="private-bus-client", epoch=i, actor_checks=27, failures=0, client_binding=True
            )
            rows.extend([relay, client] if i == 1 else [client, relay])
        rows.append(
            dict(
                event="private-bus-epoch",
                epoch=i,
                checks=count,
                failures=0,
                actual_daemon=i > 0,
                fd_negotiation_disabled=False,
                auth_gate_verified=i > 0,
            )
        )
    return rows + [
        dict(
            selftest="private-bus",
            checks=52,
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


@pytest.mark.parametrize("index", range(12))
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
        (2, "actor_checks", 10),
        (2, "result", 1),
        (2, "origin", 0),
        (2, "bounded", False),
        (6, "actor_checks", 11.0),
        (6, "failures", 1),
        (6, "origin", 1),
        (6, "bounded", 1),
        (3, "actor_checks", 25),
        (5, "actor_checks", 26.0),
        (3, "client_binding", False),
        (5, "client_binding", 1),
        (3, "failures", 1),
        (4, "checks", 28),
        (7, "failures", 1),
        (4, "actual_daemon", False),
        (7, "actual_daemon", 1),
        (4, "fd_negotiation_disabled", True),
        (4, "auth_gate_verified", False),
        (1, "auth_gate_verified", True),
        (7, "auth_gate_verified", 1),
        (8, "checks", 51),
        (8, "ok", False),
        (8, "sdk_executed", True),
        (8, "audio_opened", True),
        (8, "isolation_verified", True),
        (9, "failures", 1),
        (9, "unrelated_internet_controls", False),
        (10, "code", False),
        (10, "code", 1),
        (11, "ok", 1),
        (11, "ok", False),
    ],
)
def test_rejects_failed_or_overstated_scope(index, key, value):
    rows = evidence()
    rows[index][key] = value
    assert not evaluate_events(rows)


@pytest.mark.parametrize("value", [None, {}, True, [None] * 12])
def test_rejects_invalid_container(value):
    assert not evaluate_events(value)
