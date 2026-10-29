"""Reject composed evidence that loses a fence, retired flow or unrelated traffic."""

import pytest

from controller.qualify_epoch_mutation import evaluate_events, trial_script


def events():
    def stage(
        op, revision, epoch, mode_revision, requested, phase, closed, opened, pending, permit, choice, steps
    ):
        return dict(
            event="epoch-mutation",
            operation=op,
            result="ok",
            phase=phase,
            revision=revision,
            epoch=epoch,
            mode_revision=mode_revision,
            requested_mode=requested,
            boot_choice=choice,
            opening_pending=pending,
            permit_valid=permit,
            policy_closed=closed,
            policy_open=opened,
            mutation_steps=steps,
            control_ipv4=True,
            control_ipv6=True,
            vendor_started=False,
            stock_fallback=False,
            audio_opened=False,
            isolation_verified=False,
        )

    rows = [stage("reserve", 1, 1, 1, "paused", "closed", True, False, False, False, "paused", 36)]
    recovery_steps = [
        2,
        2,
        10,
        10,
        9,
        8,
        7,
        6,
        5,
        4,
        3,
        2,
        2,
        2,
        2,
        3,
        4,
        5,
        6,
        7,
        8,
        9,
        10,
        11,
        12,
        13,
        14,
        15,
        16,
        17,
        18,
        18,
    ]
    phases = (
        ["denying", "closed", "arming"] + ["denying"] * 9 + ["closed", "armed"] + ["opening"] * 17 + ["open"]
    )
    for index in range(38):
        point = 0 if index < 6 else index - 5
        family = ("ipv4", "ipv6", "ipv4-mapped-ipv6")[(index % 6) // 2]
        protocol = "tcp" if index % 2 == 0 else "udp"
        base, old, new = index * 4 + 1, index * 2 + 2, index * 2 + 3

        def attribute(name, epoch):
            return dict(
                event="epoch-attributed",
                family=family,
                protocol=protocol,
                phase=name,
                epoch=epoch,
                mark=epoch << 24,
                ok=True,
            )

        def native(event, **kwargs):
            return dict(event=event, family=family, protocol=protocol, old_epoch=old, new_epoch=new, **kwargs)

        def check(name):
            return native("epoch-check", check=name, ok=True)

        def ready(name):
            a, b = (0, 0) if name == "closed" else (20000 + index * 4, 20001 + index * 4)
            if name == "new":
                a += 2
                b += 2
            return native("epoch-ready", phase=name, source_port=a, destination_port=b)

        rows += [
            dict(event="mutation-case-begin", index=index, point=point, family=family, protocol=protocol),
            stage("open", base + 1, old, base + 1, "alice", "open", False, True, False, True, "alice", 32),
            attribute("old", old),
            stage(
                "close", base + 1, old, base + 2, "paused", "closed", True, False, False, False, "paused", 18
            ),
        ]
        if point:
            revision, epoch = (base + 1, old) if point < 3 else (base + 3, new)
            mode, requested = (base + 2, "paused") if point < 15 else (base + 3, "alice")
            rows += [
                dict(event="mutation-fault", step=point),
                dict(event="mutation-fault-exit", point=point, code=137),
                stage(
                    "status",
                    revision,
                    epoch,
                    mode,
                    requested,
                    phases[point - 1],
                    point in {1, 2, 12, 13, 14, 15},
                    point >= 31,
                    True,
                    point >= 15,
                    "paused",
                    0,
                ),
                attribute("fault-retained", old),
                stage(
                    "deny",
                    revision,
                    epoch,
                    mode,
                    requested,
                    "closed",
                    True,
                    False,
                    True,
                    False,
                    "paused",
                    recovery_steps[point - 1],
                ),
            ]
        rows += [
            stage(
                "open",
                base + 3,
                new,
                base + 3,
                "alice",
                "open",
                False,
                True,
                False,
                True,
                "alice",
                21 if point >= 3 else 32,
            ),
            attribute("retained", old),
            attribute("new", new),
            stage(
                "close", base + 3, new, base + 4, "paused", "closed", True, False, False, False, "paused", 18
            ),
            check("baseline"),
            check("old_open_exchange"),
            ready("old"),
            check("old_closed"),
            check("unrelated_closed"),
            ready("closed"),
        ]
        if point:
            rows += [check("old_during_recovery"), check("unrelated_recovery"), ready("recovery")]
        rows += [
            check("new_socket"),
            check("new_open_exchange"),
            check("old_still_denied"),
            check("unrelated_reopened"),
            ready("new"),
            check("new_closed"),
            check("old_remains_closed"),
            check("unrelated_final"),
            native(
                "epoch-summary",
                checks=13 if point else 11,
                failures=0,
                audio_opened=False,
                vendor_processes_changed=False,
            ),
            dict(event="mutation-case-end", index=index, point=point, ok=True),
        ]
    return rows + [dict(event="mutation-cleanup", ok=True)]


def case_start(rows, index):
    return next(
        i for i, row in enumerate(rows) if row.get("event") == "mutation-case-begin" and row["index"] == index
    )


def test_complete_composed_recovery_evidence():
    assert evaluate_events(events())


@pytest.mark.parametrize("point", range(1, 33))
def test_every_interruption_requires_preserved_boot_fence_and_explicit_recovery(point):
    rows = events()
    rows[case_start(rows, point + 5) + 6]["boot_choice"] = "alice"
    assert not evaluate_events(rows)


@pytest.mark.parametrize(
    "offset,key,value",
    [
        (1, "permit_valid", False),
        (1, "mode_revision", 25),
        (1, "isolation_verified", True),
        (2, "epoch", True),
        (2, "mark", 0),
        (3, "policy_closed", False),
        (4, "step", 2),
        (5, "code", 0),
        (5, "point", True),
        (6, "opening_pending", False),
        (6, "control_ipv4", False),
        (6, "control_ipv6", False),
        (6, "mode_revision", 28),
        (7, "mark", 15 << 24),
        (8, "permit_valid", True),
        (8, "opening_pending", False),
        (8, "policy_closed", 1),
        (9, "revision", 29),
        (9, "boot_choice", "paused"),
        (12, "requested_mode", "alice"),
        (14, "ok", False),
        (19, "ok", False),
        (20, "ok", False),
        (21, "source_port", False),
        (23, "ok", False),
        (24, "ok", 1),
        (28, "ok", False),
        (29, "failures", False),
        (29, "vendor_processes_changed", True),
        (29, "audio_opened", True),
        (30, "failures", False),
        (30, "vendor_processes_changed", True),
        (30, "audio_opened", True),
        (31, "point", False),
    ],
)
def test_false_claims_and_missing_scope_rejected(offset, key, value):
    rows = events()
    # Case six is the first real SIGKILL, with one extra recovery packet probe.
    rows[case_start(rows, 6) + offset][key] = value
    assert not evaluate_events(rows)


def test_missing_or_reordered_case_rejected():
    assert not evaluate_events(events()[:-1])
    rows = events()
    at = case_start(rows, 7)
    rows[at + 6], rows[at + 8] = rows[at + 8], rows[at + 6]
    assert not evaluate_events(rows)


def test_heredoc_closes_before_helpers_and_trial_body():
    script = trial_script()
    assert "\nCLEANUP\nwait_event()" in script
    assert "CLEANUPwait_event" not in script


def test_changed_cleanup_source_requires_review(monkeypatch):
    monkeypatch.setattr("controller.qualify_epoch_mutation.OLD", "exit 0")
    with pytest.raises(RuntimeError):
        trial_script()


@pytest.mark.parametrize("value", [None, {}, [], [None] * 1170])
def test_invalid_shape_rejected(value):
    assert not evaluate_events(value)
