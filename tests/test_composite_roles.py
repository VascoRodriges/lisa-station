"""Two synthetic role histories must prove one shared durable close scope."""

from copy import deepcopy

import pytest

from controller.qualify_roles import evaluate_events, paired_collector_profile, trial_script
from tests.test_collector_guard import events as collector_events
from tests.test_collector_guard import stock as collector_stock


def events():
    a = collector_events()
    b = deepcopy(a)
    for row in b:
        if "operation" in row:
            row["operation"] = row["operation"].replace("collector", "telemetry")
            row["telemetry_jail_verified"] = row.pop("collector_jail_verified")
            if row["child_pid"]:
                row["child_pid"] += 2
                row["guardian_pid"] += 2
    failed, full, close = (dict(a[i]) for i in (6, 7, 9))
    for row in (failed, full, close):
        row["operation"] = row["operation"].replace("collector", "roles")
        row["closed_scope"] = "guarded_roles"
    stopped, restored = dict(a[10]), dict(a[-1])
    stopped["event"], restored["event"] = "roles-stopped", "roles-restored"
    return [
        a[0],
        b[0],
        a[1],
        a[2],
        b[1],
        b[2],
        a[3],
        b[3],
        a[4],
        b[4],
        a[5],
        b[5],
        failed,
        full,
        a[8],
        close,
        stopped,
        a[11],
        b[11],
        a[12],
        b[12],
        restored,
    ]


def test_two_guarded_epochs_closed_under_shared_barrier():
    assert evaluate_events(events())


@pytest.mark.parametrize(
    ("index", "key", "value"),
    [
        (1, "result", "ok"),
        (2, "child_pid", 0),
        (2, "guardian_pid", True),
        (4, "child_pid", 30002),
        (4, "guardian_pid", 30001),
        (7, "telemetry_jail_verified", False),
        (8, "child_pid", 30003),
        (9, "guardian_pid", 30005),
        (10, "revision", 2),
        (11, "operation", None),
        (12, "result", "ok"),
        (12, "closed_scope", "single_role"),
        (13, "closed_scope", "single_role"),
        (14, "ipv6", False),
        (15, "closed_scope", "single_role"),
        (15, "transition_phase", "actors_stopped"),
        (15, "revision", 3),
        (16, "actors_absent", False),
        (18, "result", "failed"),
        (20, "result", "ok"),
        (21, "private_epoch_discarded", False),
        (21, "audio_opened", True),
        (15, "isolation_verified", True),
    ],
)
def test_partial_role_or_barrier_evidence_rejected(index, key, value):
    rows = events()
    rows[index][key] = value
    assert not evaluate_events(rows)


def test_missing_role_or_event_rejected():
    rows = events()
    del rows[9]
    assert not evaluate_events(rows)
    rows = events()
    rows[9] = []
    assert not evaluate_events(rows)


def test_restore_retains_both_original_epochs_and_all_four_groups():
    script = trial_script()
    assert 'kill -STOP "$second"' in script
    assert 'set -- $(cat "$STATE/second")' in script
    assert '--lab-stop-telemetry "$canonical"' in script
    assert "for group in 57342 57343 57344 57345;" in script
    assert 'ip6tables -D "$CHAIN" -m owner --gid-owner 57345 -j DROP' in script
    assert '--lab-check-roles-policy "$CANON"' in script
    assert '--lab-close-roles "$CANON"' in script
    assert script.index('--lab-close-roles "$CANON"') < script.index('--lab-reconcile-telemetry "$CANON"')
    assert '[ "$(telemetry_processes)" = "$second" ]' in script
    assert "sleep 60;" in script


def test_collector_uses_observed_private_telemetry_peer():
    source = collector_stock()
    source.update(metricad={"port": 9887}, metrica2d={"port": 9904})
    before = deepcopy(source)
    profile = paired_collector_profile(source, lab_clone=True)
    assert source == before
    assert (profile["metricad"]["port"], profile["metrica2d"]["port"]) == (57345, 57346)
    assert paired_collector_profile(source)["metricad"]["port"] == 9887
    script = trial_script()
    receiver = script.index('PROBE --lab-start-telemetry "$CANON"\ncode=0')
    client = script.index('PROBE --lab-start-collector "$CANON"\ncode=0')
    assert receiver < script.index("while ! PROBE --lab-inspect-telemetry", receiver) < client


@pytest.mark.parametrize("fault", ("missing", "changed"))
def test_unreviewed_peer_port_refused(fault):
    source = collector_stock()
    source.update(metricad={"port": 1 if fault == "changed" else 9887}, metrica2d={"port": 9904})
    if fault == "missing":
        del source["metricad"]
    with pytest.raises(ValueError):
        paired_collector_profile(source, lab_clone=True)
