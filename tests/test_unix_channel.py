from copy import deepcopy
from types import SimpleNamespace

import pytest

from controller.lab_artifact import canonical_lab_artifact
from controller.qualify_unix_channel import evaluate_events


def evidence():
    first = dict(event="unix-channel-epoch", epoch=1, actor_checks=39, failures=0, own_mock_only=True)
    summary = dict(
        selftest="unix-channel",
        checks=36,
        actor_checks=78,
        epochs=2,
        failures=0,
        ok=True,
        own_mock_only=True,
        audio_opened=False,
        isolation_verified=False,
    )
    return [
        first,
        dict(first, epoch=2),
        summary,
        dict(event="unix-channel-exit", code=0),
        dict(event="unix-channel-cleanup", ok=True),
    ]


def test_accepts_two_complete_channel_epochs():
    assert evaluate_events(evidence())


@pytest.mark.parametrize("index", [0, 1])
@pytest.mark.parametrize(
    "key,value",
    [
        ("epoch", True),
        ("actor_checks", 38),
        ("actor_checks", 39.0),
        ("failures", False),
        ("failures", 1),
        ("own_mock_only", False),
        ("own_mock_only", 1),
        ("unexpected", False),
    ],
)
def test_rejects_incomplete_or_reinterpreted_epoch(index, key, value):
    rows = evidence()
    rows[index][key] = value
    assert not evaluate_events(rows)


@pytest.mark.parametrize(
    "key,value",
    [
        ("checks", 35),
        ("actor_checks", 77),
        ("epochs", True),
        ("failures", False),
        ("ok", False),
        ("own_mock_only", False),
        ("audio_opened", True),
        ("isolation_verified", True),
        ("unexpected", False),
    ],
)
def test_rejects_incomplete_summary(key, value):
    rows = evidence()
    rows[2][key] = value
    assert not evaluate_events(rows)


def test_requires_ordered_unique_events_and_successful_cleanup():
    for index in range(5):
        rows = evidence()
        del rows[index]
        assert not evaluate_events(rows)
        assert not evaluate_events(evidence() + [deepcopy(evidence()[index])])
    rows = evidence()
    rows[0], rows[1] = rows[1], rows[0]
    assert not evaluate_events(rows)
    rows = evidence()
    rows[3]["code"] = False
    assert not evaluate_events(rows)
    rows = evidence()
    rows[4]["ok"] = 1
    assert not evaluate_events(rows)


@pytest.mark.parametrize("value", [None, {}, True, [None] * 5])
def test_rejects_bad_container(value):
    assert not evaluate_events(value)


ALIAS = "/data/opt/lisa-controller-lab/unix-channel-probe-" + "a" * 16


def test_resolves_artifact_symlink_before_watchdog_comparison():
    def remote(command, *, check):
        assert command == "readlink -f " + ALIAS
        assert check is True
        return SimpleNamespace(stdout=("/bkupgrade" + ALIAS + "\n").encode())

    assert canonical_lab_artifact(remote, ALIAS) == "/bkupgrade" + ALIAS


@pytest.mark.parametrize(
    "value", [None, ALIAS + ";id", ALIAS + "\n", "/tmp/" + "a" * 16, ALIAS + "/../other"]
)
def test_rejects_nonfixed_alias_before_remote_command(value):
    def remote(*args, **kwargs):
        pytest.fail("unvalidated alias reached remote shell")

    with pytest.raises(ValueError):
        canonical_lab_artifact(remote, value)


@pytest.mark.parametrize(
    "value",
    [b"", (ALIAS + "\n").encode(), ("/bkupgrade" + ALIAS + "\nextra\n").encode(), b"/elsewhere/file\n"],
)
def test_rejects_unexpected_canonical_location(value):
    with pytest.raises(ValueError):
        canonical_lab_artifact(lambda *args, **kwargs: SimpleNamespace(stdout=value), ALIAS)
