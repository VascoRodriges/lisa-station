from copy import deepcopy

import pytest

from controller.qualify_unix_factory import evaluate_events


def evidence():
    rows = [
        dict(
            event="unix-factory-case",
            case=i,
            actor_checks=47 if i == 0 else 10 if i == 6 else 0,
            failures=0,
            expected_rejection=1 <= i <= 5,
            exit_code=125 if 1 <= i <= 5 else 0,
            exit_signal=0,
            own_mock_only=True,
        )
        for i in range(7)
    ]
    return rows + [
        dict(
            selftest="unix-factory",
            checks=44,
            actor_checks=57,
            cases=7,
            failures=0,
            ok=True,
            own_mock_only=True,
            audio_opened=False,
            isolation_verified=False,
        ),
        dict(event="unix-factory-exit", code=0),
        dict(event="unix-factory-cleanup", ok=True),
    ]


def test_accepts_binding_and_constructor_rejection_cases():
    assert evaluate_events(evidence())
    rows = evidence()
    assert rows[7]["actor_checks"] == sum(row["actor_checks"] for row in rows[:7])
    rows[7]["actor_checks"] = 47
    assert not evaluate_events(rows)


@pytest.mark.parametrize("index", range(7))
@pytest.mark.parametrize(
    "key,value",
    [
        ("case", True),
        ("actor_checks", 37.0),
        ("failures", 1),
        ("expected_rejection", 1),
        ("exit_signal", 9),
        ("own_mock_only", False),
        ("unexpected", 0),
    ],
)
def test_rejects_incomplete_or_reinterpreted_case(index, key, value):
    rows = evidence()
    rows[index][key] = value
    assert not evaluate_events(rows)


@pytest.mark.parametrize("index", range(1, 6))
def test_requires_constructor_exit_125_without_client_execution(index):
    rows = evidence()
    rows[index]["exit_code"] = 0
    assert not evaluate_events(rows)
    rows = evidence()
    rows[index]["actor_checks"] = 37
    assert not evaluate_events(rows)


@pytest.mark.parametrize(
    "key,value",
    [
        ("checks", 43),
        ("actor_checks", 46),
        ("cases", 6),
        ("failures", False),
        ("ok", False),
        ("own_mock_only", False),
        ("audio_opened", True),
        ("isolation_verified", True),
    ],
)
def test_rejects_incomplete_summary(key, value):
    rows = evidence()
    rows[7][key] = value
    assert not evaluate_events(rows)


def test_requires_ordered_unique_cases_and_cleanup():
    for index in range(10):
        rows = evidence()
        del rows[index]
        assert not evaluate_events(rows)
        assert not evaluate_events(evidence() + [deepcopy(evidence()[index])])
    rows = evidence()
    rows[0], rows[1] = rows[1], rows[0]
    assert not evaluate_events(rows)
    rows = evidence()
    rows[8]["code"] = False
    assert not evaluate_events(rows)
    rows = evidence()
    rows[9]["ok"] = 1
    assert not evaluate_events(rows)


@pytest.mark.parametrize("value", [None, {}, True, [None] * 10])
def test_rejects_bad_container(value):
    assert not evaluate_events(value)
