# Guarded independent resolver

The staged coordinator now has fixed DNS start/status/stop operations. It is
**not installed in the boot path**. Time, explicit Alice return, boot installation
and full mode/voice composition remain unfinished. HA still ships diagnostic
behavior and does not claim verified vendor isolation.

## Service boundary

The resolver runs under the independent supervisor, without a vendor permit or
HA/NAS dependency. Before exec it enters a private mount namespace/chroot,
switches all UID/GID fields to 65534 and clears supplementary groups. Its only
capability in all five sets is `CAP_NET_BIND_SERVICE`, needed for port 53. NNP is
set and checked directly, including on Linux 4.9 where proc omits that field.

The private view exposes read-only libraries, the fixed Unbound executable,
null/random devices, a snapshot of its configuration and one writable private
PID directory. Host proc, sysfs, accounts, resolver defaults, vendor data,
shared memory, D-Bus and audio nodes are absent. The root is read-only and the
writable state mount is nodev/nosuid/noexec. Root-only coordinator journals stay
separate from the UID-65534 service directory.

Seccomp denies process creation, identity changes, mounts, clock writes,
cross-process memory/FD access and IPC queues. Threads and signals within the
same process remain possible. Internet DNS sockets and the kernel's route
inventory interface needed by `getifaddrs` are allowed. Other netlink protocols
and UNIX connection sockets are denied; NET_ADMIN and NET_RAW are absent.

The parent verifies executable identity, credentials, all capability sets,
seccomp, private filesystem and the PID file. All four UDP/TCP IPv4/IPv6 loopback
listeners must belong to current socket FDs of that child. A reply from a
different resolver cannot certify startup. Readiness queries only `localhost`,
so starting the service does not require WAN connectivity. Authoritative DNS
answers are accepted; truncated, wrong-opcode, wrong-ID and error replies fail.

## Profiles and ownership

The Python compiler emits numeric forwarders, loopback listeners, no query/reply
logs, no remote control and `forward-first: no`. The native parser independently
accepts only that exact template and canonical numeric unicast endpoints. Extra
directives, includes, hostname providers, duplicates, unsafe addresses and path,
privilege or logging changes are rejected before startup.

Production profiles require this **pre-dropped guarded launcher**. Their empty
Unbound username prevents a second credential change. Do not launch such a
profile directly as root. Production service state uses
`/run/lisa-station-net/dns`; the root-only journal remains in `/run/lisa-station`.
The operator must choose non-Yandex upstreams: numeric address validation does
not identify the organization operating a server.

Start is serialized and idempotent. Stop uses the root-authenticated guardian
channel instead of signalling a PID from a file. Missing or invalid profiles do
not select stock defaults. A changed invalid profile also does not kill an
already running independent service. The current coordinator entry still
requires its owned closed bootstrap policy; independent boot dispatch during a
vendor-bootstrap failure and opened Alice mode remain deployment work.

## Evidence

The actual **33-event port-53 handoff** passed missing-profile refusal, collision
refusal while stock DNS was running, guarded startup, repeat-start identity,
four external DNS transports, private Paused/Alice/Lisa intent without a vendor
permit, unsafe-include refusal while the current service remained available,
authenticated stop and verified stock resolver restoration. The slowest DNS
operation was **601 ms**, below the eight-second init deadline. Other service
identities, boot/configuration digests and complete firewall rules were preserved
or restored. No audio was opened and no production mode was installed.

The query client's `profile-child` event has zero capabilities; the actual
resolver has the single bind capability described above. The upstream trial
used IPv4 providers, so IPv6 loopback success does not certify WAN IPv6.

The native profile/kernel probe passed **55 checks on the speaker and a fortified
Linux host**. The Python/HA suite passed **662 tests**, including cross-language
acceptance and rejection of profile changes; the native matrix has **31** targets.

Qualified ARM SHA256:

- coordinator: `b2e3156a504a2511e4e30999ae9c0d6003f86de6662c605f671c20c1068cfa62`
- profile/kernel probe: `7bac035ebb912b350bfed81075902d819d1ad4a42d8fbb1dc4e81a3729480563`
- external-query helper: `bb70f76d7e65495a5843273958985b21805586aae12a7cede3850a281e6035a7`

```sh
python controller/build.py --target station-boot
python controller/build.py --target dns-profile-probe
python controller/build.py --target service-profile-probe
python -m controller.qualify_dns YOUR_SPEAKER_SSH_ALIAS \
  --ssh-config YOUR_SSH_CONFIG --dns-server YOUR_NON_YANDEX_DNS_IP \
  --temporary-dns-handoff
```

That administrative lab command refuses an installed controller, briefly replaces
only the resolver and restores stock DNS. It must never be used as a production
mode transition. Reports and real profiles remain private. Ordinary Alice stays
outside the guard in this experiment; complete speaker isolation is still pending.
