# Known service scope and live socket evidence

`vendor_inventory.py` combines process/socket snapshots before and after a
native metadata-only TCP observation. It prepares the scope for a future
transition. It **does not stop a service, change firewall rules, publish
`flows.state` or enable Lisa mode**. The restricted HA SSH key remains status-only.

## Different responsibilities

| Observed role | Required transition action |
|---|---|
| Main launcher and workers | Deny new startup, establish selective denial, inventory/stop tracked actors |
| Other helpers from the vendor executable directory | Inventory and explicitly cover their lifecycle |
| ALSA audio diagnostics | Stop and gate startup; inspect its file/kernel-log relay paths |
| DNS resolver | Keep resolution working under the selected independent profile |
| Time service | Keep time working under the selected independent profile |
| Processes outside the known roles | Leave unaffected; they are not certified harmless or unrelated by a path label |

Executable paths identify known roles on the verified firmware, not every
possible sender or relay. A missing direct internet socket does not exempt a
service from control: audio diagnostics currently has writable descriptors to
a vendor log and the kernel log. Only descriptor target **classes** and open
flags are collected; log contents, audio, environment and command lines are not.

## Per-FD TCP evidence

`tcp_owner.h` checks PID kernel start ticks and the executable's device/inode,
then verifies the descriptor's socket inode. A read-only inet_diag query must
match the exact tuple, inode, UID and TCP state and return a kernel cookie. The
descriptor, process and executable identities are checked again after the query.
No socket-destruction operation is exposed by the evidence program.

The administrative census is root-only and checks the supported device model.
It reads numeric interface addresses to orient flows and emits bounded metadata
records. Its self-test creates only its own loopback connections and works
without root on the Linux CI host. **34 checks** passed both there and on the
speaker, covering IPv4/IPv6/mapped sockets, stale ticks, executable/FD reuse,
inode/UID/tuple mismatches, missing ports and malformed table data. A separate
live census confirmed 78 descriptor observations in one run; counts can change.

The Python assessor requires agreement among the before snapshot, native FD
evidence and after snapshot for every observed holder. A changed actor, shared
socket, missing cookie/FD evidence, unsupported endpoint scope or state is
reported explicitly. Same-vendor local TCP peers are listed separately from
external and cross-role local connections. The latter require relay auditing.
An observed candidate is never automatically converted into an executable plan.

## UDP, conntrack and data paths

Both original and reply conntrack tuples are retained, including differing NAT
addresses/ports. Assigned interface addresses orient inbound and outbound legs;
the reply direction is not mistaken for another independent connection.

Unconnected UDP has no peer proof in its socket table. Matching a single source
port is still insufficient to certify it. Multiple holders/candidates and IPv6
wildcard sockets with unknown `IPV6_V6ONLY` remain ambiguous. Unmatched vendor
UDP sockets and conntrack records without observed owners remain visible;
none are silently discarded or turned into destination-wide deny rules.

In a live observation the audit found one launcher, four workers, the independent
audio diagnostics daemon, resolver and time service. It separated **74 internal
TCP socket inodes and 3 external TCP candidates**, with **9 vendor UDP sockets**.
It also observed writable vendor-log/data and system/kernel-log descriptor
classes. These counts describe that observation, not a complete fixed policy or
evidence that particular data was exported. Real endpoints, FD numbers, cookies
and reports stay in ignored `build/`; the CLI prints aggregate counts only.

```sh
python controller/build.py --target tcp-evidence-probe
python -m controller.vendor_inventory YOUR_SPEAKER_SSH_ALIAS \
  --ssh-config YOUR_SSH_CONFIG
```

## Completion still blocked

The separate [file/mapping audit](RELAY_QUEUES.md) now identifies collector
SQLite/telemetry LMDB state, shared-system-log ingress, unlinked objects and
mapping-only holders. It distinguishes device state and hardware mappings from
queues and never reads their contents or quarantines them automatically.

The independent [diagnostics guard](DIAGNOSTICS_GUARD.md) now qualifies this
role's gated lifecycle and private ephemeral log paths. Its exact shared-memory
object and D-Bus connection are explicit local relay dependencies, not evidence
of complete isolation. The census and other vendor file/UDP paths remain unchanged.

These collections are sequential. They do not freeze all senders or prevent a
socket from appearing between observations. Consequently `atomic_snapshot`,
`production_plan_ready`, `apply_supported` and `isolation_verified` remain false.
The report also enumerates actual gaps, rather than inferring privacy from an
empty direct-connection list.

Next work must combine guarded actor inventory and the selective group barrier
with the [durable exact-flow layer](FLOW_RECOVERY.md), establish UDP attribution,
cover diagnostics/relays/telemetry queues, and enforce independent profiles and
boot gates. Already queued packets and safe tuple retention/expiry also need
their completion barriers. Device internet access for unrelated applications,
root recovery and OTA protection remain intact. No shared router/DHCP changes
are part of this work.
