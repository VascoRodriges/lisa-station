"""Network services cannot share the coordinator's root-only journal directory."""

import pytest

from controller.service_profiles import compile_profiles


def test_production_runtime_is_split_by_service_and_dns_arrives_pre_dropped():
    result = compile_profiles(["203.0.113.1"], ["198.51.100.1"])
    assert "/run/lisa-station-net/dns/unbound.pid" in result.dns
    assert "/run/lisa-station-net/time/chronyd.pid" in result.time
    assert 'username: ""' in result.dns
    assert "/run/lisa-station/unbound.pid" not in result.dns
    assert "/run/lisa-station/chronyd.pid" not in result.time


def test_explicit_network_fixture_uses_its_own_paths_and_no_clock_writes():
    result = compile_profiles(
        ["203.0.113.1"],
        ["198.51.100.1"],
        network_directory="/bkupgrade/data/opt/lisa-controller-lab/boot-policy.ABC123/network",
        dns_port=25053,
    )
    assert "/network/dns/unbound.pid" in result.dns and "/network/time/chronyd.pid" in result.time
    assert all(word not in result.time for word in ("driftfile", "makestep", "rtcsync"))


@pytest.mark.parametrize(
    "directory,port",
    [
        ("/tmp/other", 25053),
        ("/bkupgrade/data/opt/lisa-controller-lab/boot-policy.ABC123/network\ninclude", 25053),
        ("/bkupgrade/data/opt/lisa-controller-lab/boot-policy.ABC123/../network", 25053),
        ("/bkupgrade/data/opt/lisa-controller-lab/boot-policy.ABC123/network", 0),
        ("/bkupgrade/data/opt/lisa-controller-lab/boot-policy.ABC123/network", 65536),
    ],
)
def test_network_profile_injection_is_rejected(directory, port):
    with pytest.raises(ValueError):
        compile_profiles(["203.0.113.1"], ["198.51.100.1"], network_directory=directory, dns_port=port)


def test_mixed_laboratory_paths_are_rejected():
    with pytest.raises(ValueError):
        compile_profiles(
            ["203.0.113.1"],
            ["198.51.100.1"],
            network_directory="/bkupgrade/data/opt/lisa-controller-lab/boot-policy.ABC123/network",
            probe_directory="/tmp/lisa-service-probe.ABC123",
            dns_port=25053,
        )
