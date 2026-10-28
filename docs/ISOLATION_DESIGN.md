# Isolation design and kernel qualification

This document records evidence and remaining work. It does not enable Lisa mode
or certify whole-device isolation. Current HA privacy state remains unknown.

## More than four vendor workers

The audited firmware runs an audio diagnostics daemon outside the main launcher.
The system DNS resolver includes Yandex forwarders and the time service is configured for
`ntp.yantp.net`. Stopping only the four `maind` processes is insufficient.

Mode control must cover:

- Main launcher/workers, audio diagnostics and any other identified sender.
- The DNS and time configurations used in each mode, including startup order.
- Connections opened before the transition, kernel-retained TCP state and relays.
- Vendor audio/telemetry queues and their later accessibility on return to Alice.
- Boot, restart and failure paths before any vendor process can run.

The speaker has neither a usable network namespace nor a network cgroup. Vendor
services share root with administration, so blocking UID 0 would affect unrelated
software. DNS blocklists alone are not an isolation mechanism.

The scope is **Yandex services and their traffic**, not an internet cutoff for
the device. HA, NAS, administration and unrelated applications retain their
network access. There is no blanket device/UID-0 DROP policy, vendor-IP blocklist
as the primary defense, or shared router/DHCP change.

## Candidate: socket group ownership plus a locked process identity

The kernel supports `xt_owner --gid-owner` for IPv4 and IPv6. A process launched
with a dedicated filesystem group gives that identity to newly opened sockets.
A rule at the start of OUTPUT can filter that group independently of unrelated
root processes. The eventual production group must be reserved and verified
unused. Qualification uses a separate, temporary test group.

`vendor_identity.h` is an experimental primitive:

- Set a dedicated group before opening network sockets.
- Lock changes to UID/GID and filesystem identities with seccomp.
- Include **both** old and 32-bit ARM syscall families; glibc uses the latter.
- Remove network-administration, raw-networking and ptrace capabilities from the
  current and bounding sets. `no_new_privs` and the filter survive exec.
- Test the identity/capabilities again after exec, rather than assuming inheritance.

This is not a complete sandbox. A production launcher must close inherited
sockets, restrict its entry points, and handle IPC/file relays. Old sockets
created as group 0 are not retroactively retagged. The current native agent and
stock processes have not been converted to this identity.

## Qualification tool

`net_owner_probe.c` uses synthetic data and ephemeral **loopback-only** sockets.
It neither captures audio nor contacts an external server. The opt-in Python
driver installs rules only for an otherwise unused test group, in unique private
chains, and verifies restoration of the original rules and stock process IDs.
An independent watchdog performs cleanup if the driver disconnects.

Build with Zig 0.14.1:

```sh
python controller/build.py --target net-owner-probe
```

On a trusted administrative connection to an owned compatible speaker, explicitly
opt in to temporary test rules:

```sh
python controller/qualify_group_policy.py YOUR_SPEAKER_SSH_ALIAS \
  --ssh-config YOUR_SSH_CONFIG \
  --apply-temporary-loopback-test-rules
```

The program is a development qualification tool, not part of the HA key's
allowed commands. Reports and before-test firewall snapshots stay under the
ignored `build/` directory. Do not publish a real firewall snapshot.

## Work required before production mode switching

1. Keep the qualified new/already-open socket checks as regression tests;
   separately qualify exact-flow quarantine, orphaned TCP packets and local relays.
2. Inventory existing group-0 vendor connections during first migration. Close
   or quarantine their exact flows; do not claim that new-socket tagging covers them.
3. Validate stock startup under the restricted identity, with a bounded rollback.
4. Persist mode intent and enforce boot gates before the relevant system services.
5. Select non-Yandex DNS/time configurations in Lisa mode. Preserve unrelated
   applications' internet access; no router/DHCP changes are needed.
6. Stop vendor diagnostics before Lisa audio starts, and prevent delayed export
   of Lisa-mode audio/telemetry. The standalone DSP keeps its existing network
   and filesystem sandbox.
7. Exercise reboot, interrupted transitions, policy tampering/failure, HA/NAS
   outage and explicit return to Alice before enabling the mode selector.

## Qualification results on the verified firmware

The loopback suite passed **32 cases**: 24 baseline/filtered/restored new-socket
checks, plus 8 already-open TCP/UDP socket checks across IPv4/IPv6 and grouped/
unaffected-root controls. Checks run after fork/exec with the identity lock and
reduced capabilities. Temporary rules were removed and the original firewall
rules and vendor process identities were verified unchanged. This does not cover
old group-0 vendor sockets, orphaned kernel packets or external relays.

A separate bounded stock-startup trial used `vendor_launch_probe.c` with the
experimental production identity. Four vendor workers remained stable through a
60-second observation. The owner reported ordinary replies to two spoken Alice
queries. The original launcher, configuration and four ordinary workers were
restored afterwards. No microphone stream was captured by the qualification tool;
stock Alice handled those queries in its usual way. This is a small compatibility
check, not a full firmware feature/regression test or a privacy-mode test.

The firmware does not expose `NoNewPrivs` in `/proc/PID/status`; reports preserve
that as null. The native wrapper checks the flag before exec and the separate
loopback test checks its inheritance. `Seccomp` and capability bits are observed
on the actual vendor workers.

Do not use `pidof` alone to decide whether a stopped launcher still has live
workers: exited children can remain zombies until the frozen launcher reaps them.
The startup tool excludes zombie/dead entries and checks stable PID sets after
warm-up. Its independent watchdog terminates only its own reserved-group trial
processes before resuming the original launcher.

For an explicit administrative compatibility test:

```sh
python controller/build.py --target vendor-launch-probe
python controller/qualify_vendor_startup.py YOUR_SPEAKER_SSH_ALIAS \
  --ssh-config YOUR_SSH_CONFIG --allow-temporary-stock-restart
```

The optional `--observe-seconds 60 --live-observation` prints a technical readiness
event for a coordinated voice check. It does not record audio. Real reports and
configuration backups remain in ignored `build/`, not in the public source tree.

## Closing connections from before the identity migration

The kernel supports `INET_DIAG_DESTROY`. `socket_diag.h` implements bounded,
exact-tuple TCP lookup and cookie-qualified `SOCK_DESTROY` requests. A kernel
cookie distinguishes a particular socket from a later connection reusing its
tuple. Destruction without a cookie is rejected locally. Netlink replies must
come from the kernel, match the request sequence and fit one bounded message.
Unexpected, truncated or multipart responses fail closed.

The administrative `socket-close-probe` passed **27 checks on the speaker** across
IPv4, IPv6 and IPv4-mapped IPv6. It first matches a socket it created against its
own file descriptor's inode. It checks missing/wrong cookies, rejection after
dropping network administration capabilities, actual closure at both endpoints,
rejection of a repeated stale request and survival of an unrelated connection.
Only its own ephemeral loopback sockets are destroyed. Vendor processes,
firewall rules and the microphone are not changed.

```sh
python controller/build.py --target socket-close-probe
python controller/qualify_socket_close.py YOUR_SPEAKER_SSH_ALIAS \
  --ssh-config YOUR_SSH_CONFIG --run-own-loopback-selftest
```

This primitive is not wired into a mode transition. Closing a TCP socket can
generate a reset packet. A production transition must install exact-flow
quarantine **before** destruction, including kernel-generated packets without an
owning process, and verify that queued traffic cannot escape. UDP requires a
separate policy; TCP destruction does not close UDP or erase conntrack state.

The UAPI and error behavior were checked against the
[sock_diag documentation](https://man7.org/linux/man-pages/man7/sock_diag.7.html),
Linux 4.9 [TCP diagnostic handler](https://github.com/torvalds/linux/blob/v4.9/net/ipv4/tcp_diag.c),
[socket permissions](https://github.com/torvalds/linux/blob/v4.9/net/core/sock_diag.c)
and [exact lookup](https://github.com/torvalds/linux/blob/v4.9/net/ipv4/inet_diag.c).
That kernel maps a cookie mismatch to `ENOENT`; the test also accepts `ESTALE`.

## Passive ownership inventory

`inventory_connections.py` reads process executable identities/start times,
socket descriptor inodes, IPv4/IPv6 TCP/UDP tables and conntrack tuples. It does
not read payloads, command lines or process environments. Known roles include
the main vendor workers/launcher, other vendor executables, audio diagnostics,
DNS and time services. Other processes are retained as an explicit separate role.

```sh
python controller/inventory_connections.py YOUR_SPEAKER_SSH_ALIAS \
  --ssh-config YOUR_SSH_CONFIG
```

Real endpoints and process metadata are saved only under ignored `build/`;
stdout contains aggregate counts. This is a sequential live audit, **not an
atomic migration snapshot**. Process disappearance/reuse is flagged where observed;
connections can still change between reads. Socket tables can contain entries
with no observed descriptor owner. Conntrack also contains incoming and expired-
socket flows, so absence of a candidate does not establish an uncontained sender.
Truncated/incomplete tables or a changed boot are rejected.

Unconnected UDP sockets have no peer in `/proc/net/udp`. The audit retains all
candidate source-port/address matches to conntrack's original direction, including
wildcard binds. Original/reply legs are now retained separately. The
[known-role audit](VENDOR_SCOPE.md) orients both legs against assigned local
addresses, including inbound/NAT cases, and keeps unknown dual-stack behavior
explicit. It does not guess one owner when several sockets match. A frozen
transition must resolve these ambiguities, IPv4-mapped cross-family attribution,
descriptor sharing, local relays and already-queued packets before claiming that
old group-0 traffic is contained. No live vendor connection has been closed by
these tools, and neither tool changes the diagnostic HA entity's unknown privacy
state.

## Exact-flow quarantine and post-close kernel replies

`flow-quarantine-probe` and `qualify_flow_quarantine.py` passed **54 native checks**
on the verified speaker. All fixtures are ephemeral loopback connections created
as root/group 0 by the test; no real vendor connection is closed or filtered.
The private chains match the fixture's protocol, local/remote addresses and both
ports. They do not depend on the current process/socket owner to decide denial.

For TCP, the driver installs the exact outgoing-flow rule before cookie-qualified
destruction. The peer does not receive the reset, while a separate control
connection continues to deliver data. After the original descriptor is closed,
the probe confirms the old cookie is absent and sends a late packet from the
peer to that closed endpoint. The kernel's reply is counted and blocked. When
the test rule is removed, a further peer packet receives the expected reset;
the unrelated connection still works.

There is a relevant IPv4/IPv6 distinction. The actual IPv4 and mapped-IPv4 tests
count post-close replies with `--socket-exists`; pure IPv6 counts them without
an associated socket. `--socket-exists` is **not proof of application ownership**.
Linux 4.9's [IPv4 TCP reset path](https://github.com/torvalds/linux/blob/v4.9/net/ipv4/tcp_ipv4.c)
uses the kernel's per-CPU control socket. The
[owner matcher](https://github.com/torvalds/linux/blob/v4.9/net/netfilter/xt_owner.c)
checks socket association separately from UID/GID credentials. The report keeps
the two counter categories separate and requires the observed family-specific
increase after the late packet. This is why owner-only filtering is insufficient
for post-close kernel traffic.

For UDP, sockets are deliberately unconnected and created before quarantine.
The test separately verifies exact-flow INPUT and OUTPUT denial, the matching
packet counters, uninterrupted UDP control delivery and recovery after removing
the rules. IPv4, IPv6 and IPv4-mapped IPv6 are covered for both transports.

```sh
python controller/build.py --target flow-quarantine-probe
python -m controller.qualify_flow_quarantine YOUR_SPEAKER_SSH_ALIAS \
  --ssh-config YOUR_SSH_CONFIG --apply-temporary-exact-loopback-rules \
  --exercise-watchdog
```

The opt-in watchdog exercise kills the remote test shell with SIGKILL immediately
after installing the first hook. Shell exit traps cannot perform cleanup in
this case. The independent watchdog was verified to remove the private hooks,
chains and test lock. Both normal and fault trials compare pre/post firewall
rules and stock process/boot identities. Reports and firewall backups remain in
ignored `build/`. The HA restricted key cannot invoke this administrative tool.

These results qualify the mechanism, not production switching. They do not
establish a complete vendor-flow inventory, handle ambiguous UDP ownership,
audit local relays, quarantine application queues, or recall packets which have
already passed the output hook. The production transition still needs an
explicit completion barrier for previously queued traffic and safe persistence
of quarantined tuples. Test cleanup deliberately restores the initial state;
a production Lisa-mode failure must instead retain the closed vendor policy.
