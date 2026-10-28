"""Reject profile injection and incomplete evidence of independent DNS/time."""

from copy import deepcopy

import pytest

from controller.qualify_service_profiles import evaluate_events
from controller.service_profiles import compile_profiles, numeric_servers


@pytest.mark.parametrize(
    "value",
    (
        "resolver.example",
        "8.8.8.8\ninclude /etc/chrony.conf",
        "8.8.8.8@5353",
        "8.8.8.8#name",
        "127.0.0.1",
        "::1",
        "0.0.0.0",
        "::",
        "224.0.0.1",
        "ff02::1",
        "fe80::1",
        "fe80::1%wlan0",
        "::ffff:8.8.8.8",
        "255.255.255.255",
        None,
    ),
)
def test_implicit_or_unsafe_upstream_rejected(value):
    with pytest.raises(ValueError):
        numeric_servers([value])


def test_empty_or_duplicate_upstream_rejected():
    for values in ([], ["2001:db8::1", "2001:0db8::1"], ["203.0.113.1"] * 5):
        with pytest.raises(ValueError):
            numeric_servers(values)


def test_explicit_profiles_do_not_import_vendor_or_dhcp_defaults():
    result = compile_profiles(["203.0.113.1", "2001:db8::1"], ["198.51.100.1"])
    assert 'forward-addr: "203.0.113.1"' in result.dns
    assert 'forward-addr: "2001:db8::1"' in result.dns
    assert "forward-first: no" in result.dns and "include" not in result.dns
    assert "forward-host" not in result.dns
    assert "server 198.51.100.1 iburst\n" in result.time
    assert "pool " not in result.time and "include" not in result.time
    assert "bindcmdaddress /\n" in result.time and "port 0\n" in result.time


def test_parallel_probe_has_separate_files_ports_and_no_clock_control_directives():
    result = compile_profiles(
        ["203.0.113.1"], ["198.51.100.1"], probe_directory="/tmp/lisa-service-probe.ABC123", dns_port=25053
    )
    assert "port: 25053" in result.dns
    assert "/tmp/lisa-service-probe.ABC123/chronyd.pid" in result.time
    assert all(word not in result.time for word in ("makestep", "rtcsync", "driftfile"))


@pytest.mark.parametrize(
    "directory,port",
    (
        ("/tmp/other", 25053),
        ("/tmp/lisa-service-probe.ABC123\nextra", 25053),
        ("/tmp/lisa-service-probe.ABC123", 53),
        ("/tmp/lisa-service-probe.ABC123", 65536),
        (None, 53.0),
        (None, 25053),
    ),
)
def test_invalid_runtime_profile_parameters_rejected(directory, port):
    with pytest.raises(ValueError):
        compile_profiles(["203.0.113.1"], ["198.51.100.1"], probe_directory=directory, dns_port=port)


def events():
    child = dict(
        event="profile-child",
        uid=65534,
        gid=65534,
        capabilities_zero=True,
        no_new_privs=True,
        clock_writes_denied=True,
    )
    return [
        dict(event="profile-syntax", dns=True),
        dict(event="dns-runtime", uid=65534, capabilities_zero=True, seccomp=2),
        deepcopy(child),
        *[
            dict(event="dns-query", family=family, transport=transport, ok=True)
            for family in (4, 6)
            for transport in ("udp", "tcp")
        ],
        deepcopy(child),
        dict(event="time-query", ok=True, clock_control=False),
        dict(event="profile-cleanup", ok=True),
    ]


def test_complete_profile_evidence():
    assert evaluate_events(events())


@pytest.mark.parametrize("fault", ("dns", "duplicate", "uid", "clock", "bool", "cleanup", "partial"))
def test_incomplete_or_unsafe_profile_evidence_rejected(fault):
    rows = events()
    if fault == "dns":
        rows[3]["ok"] = False
    elif fault == "duplicate":
        rows[3] = deepcopy(rows[4])
    elif fault == "uid":
        rows[2]["uid"] = 0
    elif fault == "clock":
        rows[8]["clock_control"] = True
    elif fault == "bool":
        rows[8]["clock_control"] = 0
    elif fault == "cleanup":
        rows[-1]["ok"] = False
    elif fault == "partial":
        rows.pop()
    assert not evaluate_events(rows)
