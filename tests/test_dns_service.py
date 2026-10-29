"""Require a full resolver handoff rather than merely a prepared process."""

import shutil
import subprocess
import sys
from copy import deepcopy
from pathlib import Path

import pytest

from controller.qualify_dns import evaluate_events, trial_script
from controller.service_profiles import compile_profiles
from tests.test_bootstrap import events as policy_events


def events():
    base = policy_events()
    dns = []
    for i, operation in enumerate(
        ["start", "start", "start", "status", "start", "status", "status", "start", "status", "stop"]
    ):
        row = deepcopy(base[15])
        row.update(
            operation="lab-dns-" + operation,
            dns_operation_ok=i not in {0, 1, 7},
            result="denied" if i in {0, 1, 7} else "ok",
            requested_mode=(["paused"] * 5 + ["alice"] + ["lisa"] * 4)[i],
        )
        dns.append(row)
    query = [
        dict(
            event="profile-child",
            uid=65534,
            gid=65534,
            capabilities_zero=True,
            no_new_privs=True,
            clock_writes_denied=True,
        )
    ]
    query += [
        dict(event="dns-query", family=family, transport=transport, ok=True)
        for family in (4, 6)
        for transport in ("udp", "tcp")
    ]
    return (
        base[:-1]
        + dns[:5]
        + query
        + dns[5:]
        + [dict(event="dns-restored", stock_resolver_running=True, local_queries_work=True), base[-1]]
    )


def test_complete_handoff_evidence():
    assert evaluate_events(events())


@pytest.mark.parametrize(
    "index,key,value",
    [
        (16, "result", "ok"),
        (17, "dns_operation_ok", True),
        (18, "dns_operation_ok", False),
        (18, "dns_operation_ok", 1),
        (18, "namespace_owned", False),
        (18, "policy_ready", False),
        (18, "known_legacy_actors", 0),
        (18, "tagged_actors", 1),
        (18, "stock_fallback", True),
        (18, "vendor_started", True),
        (18, "isolation_verified", True),
        (18, "elapsed_ms", 8000),
        (21, "capabilities_zero", 1),
        (21, "clock_writes_denied", False),
        (22, "ok", False),
        (24, "family", 4),
        (26, "requested_mode", "paused"),
        (28, "result", "ok"),
        (30, "result", "denied"),
        (31, "stock_resolver_running", False),
        (31, "local_queries_work", 1),
    ],
)
def test_incomplete_or_invented_evidence_rejected(index, key, value):
    rows = events()
    rows[index][key] = value
    assert not evaluate_events(rows)


def test_changed_bootstrap_fixture_requires_review(monkeypatch):
    monkeypatch.setattr("controller.qualify_dns.POLICY_SCRIPT", "exit 0")
    with pytest.raises(RuntimeError):
        trial_script("encoded")


@pytest.fixture(scope="module")
def native_validator(tmp_path_factory):
    if sys.platform != "linux" or not shutil.which("cc"):
        pytest.skip("Linux C compiler required for cross-language profile validation")
    output = tmp_path_factory.mktemp("dns-validator") / "validator"
    root = Path(__file__).resolve().parents[1]
    subprocess.run(
        [
            "cc",
            "-O2",
            "-D_FORTIFY_SOURCE=3",
            "-Wall",
            "-Wextra",
            "-Werror",
            str(root / "controller/dns_profile_probe.c"),
            "-o",
            str(output),
        ],
        capture_output=True,
        check=True,
    )
    return output


def test_python_profile_accepted_by_device_parser(native_validator):
    profile = compile_profiles(["203.0.113.1", "2001:db8::1"], ["198.51.100.1"]).dns
    result = subprocess.run(
        [str(native_validator), "--validate-production"], input=profile.encode(), capture_output=True
    )
    assert result.returncode == 0


@pytest.mark.parametrize(
    "before,after",
    [
        ('username: ""', 'username: "root"'),
        ("log-queries: no", "log-queries: yes"),
        ("forward-first: no", "forward-first: yes"),
        ("port: 53", "port: 5353"),
        ('module-config: "iterator"', 'module-config: "python iterator"'),
        ("control-enable: no", "control-enable: yes"),
        ("203.0.113.1", "resolver.example"),
        ("203.0.113.1", "127.0.0.1"),
        ("203.0.113.1", "203.0.113.1@5353"),
        ('pidfile: "/run/lisa-station-net/dns/unbound.pid"', 'pidfile: "/run/lisa-station/vendor.permit"'),
    ],
)
def test_native_parser_rejects_dangerous_profile_changes(native_validator, before, after):
    profile = compile_profiles(["203.0.113.1"], ["198.51.100.1"]).dns.replace(before, after)
    result = subprocess.run(
        [str(native_validator), "--validate-production"], input=profile.encode(), capture_output=True
    )
    assert result.returncode != 0
