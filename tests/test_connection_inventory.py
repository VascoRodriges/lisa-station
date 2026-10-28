"""Audit metadata must preserve ambiguous ownership and reject partial snapshots."""

import ipaddress

import pytest

from controller.inventory_connections import endpoint, parse_inventory, summary

HEADER = "  sl local_address rem_address st tx_queue rx_queue tr tm->when retrnsmt uid timeout inode"


def snapshot():
    return "\n".join(
        [
            "B\ttest-boot",
            "P\t101\t1234\tS\tvendor-worker",
            "P\t102\t1235\tS\tother",
            "S\t101\t300",
            "S\t102\t301",
            "N\ttcp",
            HEADER,
            "0: 0100007F:26C1 0100007F:26C2 01 00000000:00000000 00:00000000 00000000 0 0 999",
            "N\ttcp6",
            HEADER,
            "N\tudp",
            HEADER,
            "0: 00000000:C3B4 00000000:0000 07 00000000:00000000 00:00000000 00000000 0 0 300",
            "1: 00000000:C3B4 00000000:0000 07 00000000:00000000 00:00000000 00000000 0 0 301",
            "N\tudp6",
            HEADER,
            "N\tconntrack",
            "ipv4 2 udp 17 30 src=203.0.113.10 dst=198.51.100.20 sport=50100 dport=53 "
            "src=198.51.100.20 dst=203.0.113.10 sport=53 dport=50100 [ASSURED] mark=0 use=2",
            "E\ttest-boot",
            "",
        ]
    )


def test_native_word_address_endianness():
    assert endpoint("0100007F:26C1", False) == {"address": "127.0.0.1", "port": 9921}
    assert endpoint("00000000000000000000000001000000:0035", True) == {
        "address": "::1",
        "port": 53,
    }
    mapped = endpoint("0000000000000000FFFF00000100007F:0035", True)["address"]
    assert ipaddress.ip_address(mapped) == ipaddress.IPv6Address("::ffff:127.0.0.1")


def test_unconnected_udp_keeps_multiple_candidates_and_original_direction():
    result = parse_inventory(snapshot())
    flow = result["conntrack"][0]
    assert flow["src"] == "203.0.113.10" and flow["sport"] == 50100
    assert flow["reply"] == dict(src="198.51.100.20", sport=53, dst="203.0.113.10", dport=50100)
    assert flow["candidate_inodes"] == [300, 301]
    assert result["sockets"][0]["owners"] == []
    assert summary(result)["sockets_without_observed_owner"] == 1
    assert result["atomic_snapshot"] is False and result["isolation_proven"] is False


def test_resource_audit_exports_classes_and_flags_without_file_contents():
    text = snapshot().replace("N\ttcp\n", "F\t101\t3\tvendor-log\t0100001\nN\ttcp\n")
    assert parse_inventory(text)["resource_links"] == [
        dict(pid=101, descriptor=3, kind="vendor-log", flags=0o100001)
    ]


@pytest.mark.parametrize("fault", ("partial_reply", "family", "resource_flags", "resource_owner"))
def test_invalid_conntrack_or_resource_metadata_rejected(fault):
    text = snapshot()
    if fault == "partial_reply":
        text = text.replace("src=198.51.100.20 dst=203.0.113.10 sport=53 dport=50100", "src=198.51.100.20")
    elif fault == "family":
        text = text.replace("src=198.51.100.20", "src=::1")
    elif fault == "resource_flags":
        text = text.replace("N\ttcp\n", "F\t101\t3\tvendor-log\tinvalid\nN\ttcp\n")
    elif fault == "resource_owner":
        text = text.replace("N\ttcp\n", "F\t999\t3\tvendor-log\t01\nN\ttcp\n")
    with pytest.raises(ValueError):
        parse_inventory(text)


def test_changed_owner_is_explicitly_unreliable():
    result = parse_inventory(snapshot().replace("N\ttcp\n", "R\t101\nN\ttcp\n"))
    assert result["owner_races"] == [101]
    assert next(row for row in result["sockets"] if row["inode"] == 300)["owner_race"]


@pytest.mark.parametrize("change", ("boot", "missing", "truncated", "bad_address", "missing_owner"))
def test_incomplete_or_inconsistent_snapshot_rejected(change):
    data = snapshot()
    if change == "boot":
        data = data.replace("E\ttest-boot", "E\tnew-boot")
    elif change == "missing":
        data = data.replace("N\ttcp6\n" + HEADER + "\n", "")
    elif change == "truncated":
        data = data.replace("N\tconntrack\n", "N\tconntrack\n" + "unknown\n" * 4097)
    elif change == "bad_address":
        data = data.replace("0100007F:26C1", "GGGGGGGG:26C1")
    elif change == "missing_owner":
        data = data.replace("S\t101\t300", "S\t999\t300")
    with pytest.raises(ValueError):
        parse_inventory(data)
