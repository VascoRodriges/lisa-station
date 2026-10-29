"""Retired-flow denial must coexist with successful new/unrelated traffic."""

import pytest

from controller.qualify_epochs import evaluate_events


def events():
    rows = []
    for index, (family, protocol) in enumerate(
        (family, protocol) for family in ("ipv4", "ipv6", "ipv4-mapped-ipv6") for protocol in ("tcp", "udp")
    ):
        old = index * 2 + 1
        new = old + 1

        def policy(epoch, closed):
            return dict(event="epoch-policy", epoch=epoch, closed=closed, ok=True)

        def attributed(phase, epoch):
            return dict(
                event="epoch-attributed",
                family=family,
                protocol=protocol,
                phase=phase,
                epoch=epoch,
                mark=epoch << 24,
                ok=True,
            )

        def native(event, **kwargs):
            return dict(event=event, family=family, protocol=protocol, old_epoch=old, new_epoch=new, **kwargs)

        def check(name):
            return native("epoch-check", check=name, ok=True)

        rows += [
            policy(old, True),
            policy(old, False),
            attributed("old", old),
            policy(old, True),
            policy(new, True),
            policy(new, False),
            attributed("retained", old),
            attributed("new", new),
            policy(new, True),
        ]
        rows += [
            check("baseline"),
            check("old_open_exchange"),
            native(
                "epoch-ready", phase="old", source_port=20000 + index * 4, destination_port=20001 + index * 4
            ),
            check("old_closed"),
            check("unrelated_closed"),
            native("epoch-ready", phase="closed", source_port=0, destination_port=0),
        ]
        rows += [
            check("new_socket"),
            check("new_open_exchange"),
            check("old_still_denied"),
            check("unrelated_reopened"),
            native(
                "epoch-ready", phase="new", source_port=20002 + index * 4, destination_port=20003 + index * 4
            ),
            check("new_closed"),
            check("old_remains_closed"),
            check("unrelated_final"),
            native(
                "epoch-summary", checks=11, failures=0, audio_opened=False, vendor_processes_changed=False
            ),
        ]
    return rows + [dict(event="epoch-cleanup", ok=True)]


def test_complete_two_epoch_kernel_evidence():
    assert evaluate_events(events())


@pytest.mark.parametrize(
    "index,key,value",
    [
        (0, "ok", 1),
        (0, "epoch", True),
        (1, "closed", True),
        (2, "mark", 0),
        (3, "closed", False),
        (4, "epoch", 1),
        (5, "ok", False),
        (6, "epoch", 2),
        (6, "mark", 2 << 24),
        (6, "epoch", True),
        (7, "phase", "retained"),
        (8, "closed", 1),
        (9, "old_epoch", True),
        (10, "ok", False),
        (11, "source_port", True),
        (11, "destination_port", 20000),
        (12, "ok", False),
        (13, "check", "old_closed"),
        (14, "source_port", 20000),
        (16, "ok", False),
        (17, "ok", False),
        (18, "ok", False),
        (19, "source_port", 65536),
        (20, "ok", 1),
        (22, "ok", False),
        (23, "failures", False),
        (23, "audio_opened", True),
        (23, "vendor_processes_changed", True),
        (48, "epoch", 3),
        (81, "family", "ipv4"),
        (120, "epoch", 9),
        (144, "ok", 1),
    ],
)
def test_incomplete_or_fabricated_evidence_rejected(index, key, value):
    rows = events()
    rows[index][key] = value
    assert not evaluate_events(rows)


def test_missing_reordered_and_unknown_events_rejected():
    assert not evaluate_events(events()[:-1])
    rows = events()
    rows[11], rows[12] = rows[12], rows[11]
    assert not evaluate_events(rows)
    rows = events()
    rows[13]["event"] = "invented"
    assert not evaluate_events(rows)


@pytest.mark.parametrize("value", [None, {}, [], [None] * 145])
def test_invalid_shape(value):
    assert not evaluate_events(value)
