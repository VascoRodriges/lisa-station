from copy import deepcopy

import pytest

from controller.qualify_platform_worker import evaluate_events


def evidence():
    return [
        dict(
            selftest="platform-worker",
            checks=18,
            worker_checks=92,
            exec_workers=2,
            parent_death_workers=1,
            failures=0,
            ok=True,
            own_elf_only=True,
            audio_opened=False,
            isolation_verified=False,
        ),
        dict(event="platform-worker-exit", code=0),
        dict(event="platform-worker-cleanup", ok=True),
    ]


def test_accepts_complete_worker_proof():
    assert evaluate_events(evidence())


@pytest.mark.parametrize(
    "key,value",
    [
        ("checks", 17),
        ("checks", True),
        ("worker_checks", 91),
        ("worker_checks", 92.0),
        ("exec_workers", 1),
        ("parent_death_workers", False),
        ("failures", 1),
        ("failures", False),
        ("ok", False),
        ("ok", 1),
        ("own_elf_only", False),
        ("audio_opened", True),
        ("isolation_verified", True),
        ("selftest", "other"),
        ("unexpected", False),
    ],
)
def test_rejects_incomplete_or_reinterpreted_worker_proof(key, value):
    rows = evidence()
    rows[0][key] = value
    assert not evaluate_events(rows)


@pytest.mark.parametrize("index", range(3))
def test_requires_every_ordered_event(index):
    rows = evidence()
    del rows[index]
    assert not evaluate_events(rows)
    assert not evaluate_events(evidence() + [deepcopy(evidence()[index])])


@pytest.mark.parametrize("value", [None, {}, True, [None, None, None]])
def test_rejects_wrong_event_container(value):
    assert not evaluate_events(value)


def test_requires_successful_exit_and_cleanup():
    rows = evidence()
    rows[1]["code"] = False
    assert not evaluate_events(rows)
    rows = evidence()
    rows[2]["ok"] = 1
    assert not evaluate_events(rows)
    rows = evidence()
    rows.reverse()
    assert not evaluate_events(rows)
