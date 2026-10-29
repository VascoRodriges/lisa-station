from copy import deepcopy

import pytest

from controller.qualify_platform_sdk import evaluate_events


def evidence():
    own = dict(
        event="platform-sdk-diagnostic",
        role="own-elf",
        boundary_ok=True,
        exec_verified=True,
        drained=True,
        syscalls=100,
        errors=20,
        denied=5,
        socket_attempts=4,
        open_attempts=40,
        clone_attempts=9,
        threads=9,
        bounded_stop=False,
        exit_code=-1,
        exit_signal=6,
        private_objects_mask=32,
        lost_registers=0,
        path_control=True,
        private_stderr_bytes=0,
        private_stderr_truncated=False,
        synthetic_identity=True,
        audio_opened=False,
        functionality_verified=False,
    )
    platform = dict(
        own,
        role="platform",
        exit_code=127,
        exit_signal=0,
        threads=0,
        private_objects_mask=0,
        path_control=False,
    )
    media = dict(platform, role="media", exit_code=-1, exit_signal=9, bounded_stop=True)
    return [
        own,
        platform,
        media,
        dict(event="platform-sdk-exit", code=0),
        dict(event="platform-sdk-cleanup", ok=True),
    ]


def test_diagnostic_does_not_require_functional_sdk_success():
    assert evaluate_events(evidence())


@pytest.mark.parametrize("index", range(3))
@pytest.mark.parametrize(
    "key,value",
    [
        ("boundary_ok", False),
        ("exec_verified", False),
        ("drained", False),
        ("synthetic_identity", False),
        ("audio_opened", True),
        ("functionality_verified", True),
        ("syscalls", 0),
        ("syscalls", 20001),
        ("syscalls", True),
        ("denied", -1),
        ("denied", 21),
        ("threads", 80),
        ("open_attempts", 101),
        ("exit_code", 256),
        ("exit_signal", 65),
        ("bounded_stop", 0),
        ("private_objects_mask", 64),
        ("private_stderr_bytes", 65537),
        ("lost_registers", 81),
        ("private_stderr_truncated", 1),
        ("unexpected", None),
    ],
)
def test_rejects_incomplete_or_reinterpreted_boundary(index, key, value):
    rows = evidence()
    rows[index][key] = value
    assert not evaluate_events(rows)


@pytest.mark.parametrize(
    "key,value",
    [
        ("threads", 8),
        ("socket_attempts", 3),
        ("denied", 4),
        ("bounded_stop", True),
        ("private_objects_mask", 0),
    ],
)
def test_requires_composition_control_before_vendor_execution(key, value):
    rows = evidence()
    rows[0][key] = value
    assert not evaluate_events(rows)


@pytest.mark.parametrize("index", [1, 2])
def test_rejects_cross_epoch_own_marker(index):
    rows = evidence()
    rows[index]["private_objects_mask"] = 32
    assert not evaluate_events(rows)


def test_requires_every_role_in_order_and_successful_cleanup():
    rows = evidence()
    rows[0], rows[1] = rows[1], rows[0]
    assert not evaluate_events(rows)
    for index in range(5):
        rows = evidence()
        del rows[index]
        assert not evaluate_events(rows)
        assert not evaluate_events(evidence() + [deepcopy(evidence()[index])])
    rows = evidence()
    rows[3]["code"] = False
    assert not evaluate_events(rows)
    rows = evidence()
    rows[4]["ok"] = 1
    assert not evaluate_events(rows)


@pytest.mark.parametrize("value", [None, {}, True, [None] * 5])
def test_rejects_bad_event_container(value):
    assert not evaluate_events(value)


@pytest.mark.parametrize("index", range(3))
def test_requires_independent_path_trace_control(index):
    rows = evidence()
    rows[index]["path_control"] = not rows[index]["path_control"]
    assert not evaluate_events(rows)


@pytest.mark.parametrize("index", range(3))
def test_rejects_thread_creation_without_clone_observation(index):
    rows = evidence()
    rows[index]["threads"] = 1
    rows[index]["clone_attempts"] = 0
    assert not evaluate_events(rows)
