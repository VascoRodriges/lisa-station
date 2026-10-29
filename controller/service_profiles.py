"""Explicit DNS/time profiles, independent of stock defaults and DHCP providers.

The caller must choose non-Yandex endpoints. Numeric addresses remove DNS
bootstrap dependencies; this compiler alone does not establish vendor isolation.
"""

import ipaddress
import re
from dataclasses import dataclass


def numeric_servers(values):
    if not isinstance(values, (list, tuple)) or not 1 <= len(values) <= 4:
        raise ValueError("one to four explicit numeric servers required")
    result = []
    for value in values:
        if not isinstance(value, str) or "%" in value:
            raise ValueError("scoped addresses and non-string servers are unsupported")
        address = ipaddress.ip_address(value)
        if (
            address.is_unspecified
            or address.is_multicast
            or address.is_loopback
            or address.is_link_local
            or getattr(address, "ipv4_mapped", None)
            or str(address) == "255.255.255.255"
        ):
            raise ValueError("unicast upstream outside loopback/link-local required")
        canonical = str(address)
        if canonical in result:
            raise ValueError("duplicate server")
        result.append(canonical)
    return tuple(result)


@dataclass(frozen=True)
class ServiceProfiles:
    dns: str
    time: str


def compile_profiles(dns_servers, ntp_servers, *, probe_directory=None, dns_port=53, network_directory=None):
    if type(dns_port) is not int:
        raise ValueError("numeric integer DNS port required")
    dns = numeric_servers(dns_servers)
    ntp = numeric_servers(ntp_servers)
    if probe_directory is not None and network_directory is not None:
        raise ValueError("choose one explicit laboratory runtime")
    if network_directory is not None:
        if not isinstance(network_directory, str) or not re.fullmatch(
            r"/bkupgrade/data/opt/lisa-controller-lab/boot-policy\.[A-Za-z0-9]{6,16}/network",
            network_directory,
        ):
            raise ValueError("invalid independent network service runtime")
        if dns_port != 53 and not 1024 <= dns_port <= 65535:
            raise ValueError("invalid laboratory DNS port")
        dns_runtime, time_runtime = network_directory + "/dns", network_directory + "/time"
    elif probe_directory is None:
        dns_runtime, time_runtime = "/run/lisa-station-net/dns", "/run/lisa-station-net/time"
        if dns_port != 53:
            raise ValueError("production DNS uses port 53")
    else:
        if not isinstance(probe_directory, str) or not re.fullmatch(
            r"/tmp/lisa-service-probe\.[A-Za-z0-9]{6,16}", probe_directory
        ):
            raise ValueError("invalid private probe directory")
        dns_runtime = time_runtime = probe_directory
        if type(dns_port) is not int or not 1024 <= dns_port <= 65535:
            raise ValueError("probe requires an unprivileged DNS port")
    resolver = [
        "server:",
        '    interface: "127.0.0.1"',
        '    interface: "::1"',
        f"    port: {dns_port}",
        '    username: "nobody"' if probe_directory is not None else '    username: ""',
        '    chroot: ""',
        f'    directory: "{dns_runtime}"',
        f'    pidfile: "{dns_runtime}/unbound.pid"',
        "    do-ip4: yes",
        "    do-ip6: yes",
        "    do-udp: yes",
        "    do-tcp: yes",
        "    so-reuseport: no",
        '    module-config: "iterator"',
        "    use-syslog: no",
        "    verbosity: 0",
        "    log-queries: no",
        "    log-replies: no",
        "    hide-identity: yes",
        "    hide-version: yes",
        "    msg-cache-size: 2m",
        "    rrset-cache-size: 2m",
        "remote-control:",
        "    control-enable: no",
        "forward-zone:",
        '    name: "."',
        "    forward-first: no",
    ]
    resolver += [f'    forward-addr: "{address}"' for address in dns]
    clock = [f"server {address} iburst" for address in ntp]
    clock += [f"pidfile {time_runtime}/chronyd.pid", "port 0", "cmdport 0", "bindcmdaddress /"]
    if probe_directory is None and network_directory is None:
        clock += ["driftfile /data/opt/lisa-station/time/drift", "makestep 1.0 3", "rtcsync"]
    return ServiceProfiles("\n".join(resolver) + "\n", "\n".join(clock) + "\n")
