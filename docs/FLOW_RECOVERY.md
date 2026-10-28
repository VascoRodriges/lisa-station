# Durable exact-flow quarantine during a closed transition

`flow_store.h` and `flow_policy.h` connect attributed old-flow evidence to the
[closed-transition engine](CLOSED_TRANSITION.md). Qualification uses only its
own pre-existing loopback sockets. No real vendor connection is closed and the
stock Alice launcher/workers remain running throughout these tests.

## What is persisted

An immutable `flows.state` binds a bounded list of exact flows to a mode revision,
the current boot ID and an exclusively owned chain name. Each flow contains its
socket family, TCP/UDP protocol, local/remote addresses and ports, socket inode
and TCP kernel cookie. IPv4-mapped IPv6 retains its socket family for inet_diag
but generates IPv4 packet rules. Duplicate wire tuples and ambiguous mapped
addresses are rejected.

The canonical versioned text is stored in a private single-link regular file.
The writer fsyncs a temporary file, atomically publishes it without replacement
using `linkat`, unlinks the temporary name and fsyncs the directory **before any
socket destruction**. A crash between link and unlink leaves multiple links;
readers reject that evidence until explicit recovery. Missing, corrupt, public,
linked, wrong-owner, wrong-revision or previous-boot evidence never means an empty
flow list. Conflicting evidence cannot silently replace the original.
Retrying an identical publication fsyncs the existing record and directory too;
its visibility alone cannot substitute for a previously failed durability step.

There are at most 32 entries. Unsupported protocols, missing ports/inodes,
missing TCP cookies, noncanonical text, scoped/link-local and multicast addresses
are rejected. Such cases need explicit future handling rather than being skipped.
This is evidence storage, not an automatic proof of attribution or completeness.
For UDP the trusted caller must establish the exact peer; an unconnected socket
alone is insufficient and ambiguous conntrack candidates remain unresolved.

## Policy and ordering

The trusted caller exclusively creates private chains. The installer only adds
the immutable plan's exact DROP rules and first unconditional INPUT/OUTPUT jumps;
it never flushes a chain or removes a rule during a closed request. OUTPUT covers
the stored local-to-remote tuple; INPUT covers its reverse. No destination-wide
blacklist, global root-UID deny or device internet cutoff is used.

Before mutation, every owned chain must contain only a subset of the expected
DROP rules. Unknown rules, duplicates or unexpected jump ordering prevent
completion. A retry fills missing DROP rules and verifies the actual rules and
hooks in both IP families. Rules remain after sockets are destroyed so old
tuples also cover matching kernel traffic, without relying on process ownership.

The qualification callbacks load durable evidence, install/verify denial, revoke
the permit, commit private Paused intent, then destroy only TCP sockets whose
cookie and inode match the owned snapshot and close their own UDP endpoints.
Completion checks TCP disappearance, UDP inode absence and packet policy again.
The production attribution, actor inventory and socket-destruction callbacks
still need to be composed with the real quasar/diagnostics policy.

## Measured qualification

`flow-store-probe` passed **49 checks** on actual writable speaker storage and a
separate Linux host. These include canonical IPv4/IPv6/mapped roundtrips,
revision/boot binding, invalid/duplicate tuples, short/oversized data, permissions,
links, corruption and immutable/idempotent publication.

`closed-flow-probe` passed **56 checks** on the speaker, covering TCP and
unconnected UDP across IPv4, IPv6 and mapped IPv6:

- Sockets predate the transition and have no dedicated vendor group.
- Owned FD inode/TCP cookie evidence is captured and persisted before closure.
- UDP delivery is denied in both directions and TCP destruction resets are
  quarantined; separate TCP/UDP control exchanges continue working.
- A repeated request retains the revision. Deleting one owned DROP is detected
  and repaired on retry. An injected unknown rule refuses completion and keeps
  the close fence.

A separate restart trial kills the coordinator after the stored `actors_stopped`
phase and removes one DROP rule. A **new process with no inherited target FDs**
loads the retained plan, repairs policy and completes the same revision; its
**8 recovery checks** passed. UDP inode absence is checked in both kernel tables;
this remains a sequential fixture observation, not a frozen global inventory.

An additional fault trial kills the administrative shell after `network_denied`.
Parent-death signaling terminates its native child. The independent watchdog
removes only the lab's chains/jumps; persisted evidence and the fence remain.
Normal, restart and watchdog trials compare complete firewall rules and stock
process/boot identities before/after. They all passed. Reports remain in ignored
`build/`; no microphone stream is opened or recorded.

```sh
python controller/build.py --target flow-store-probe
python controller/build.py --target closed-flow-probe
python -m controller.qualify_closed_flows YOUR_SPEAKER_SSH_ALIAS \
  --ssh-config YOUR_SSH_CONFIG --apply-temporary-exact-loopback-rules \
  --exercise-restart --exercise-watchdog
```

The watchdog's rule deletion is an administrative lab rollback. Production
recovery must retain/reestablish denial and must not restore Alice automatically.

## Limits before deployment

The existing [kernel mechanism tests](ISOLATION_DESIGN.md) separately exercise
post-close kernel replies and UDP filtering counters. This combined transaction
test does not claim to recall packets already past OUTPUT or queued for a device.
Queue-drain barriers and safe tuple retention/expiry remain to be implemented;
port reuse can otherwise make a retained exact rule affect a later connection.

No complete live vendor snapshot, ambiguous UDP attribution, root IPC/file relay
audit, telemetry-queue treatment, diagnostics/DNS/time migration or boot policy
is installed by these components. Real mode switching still requires those
pieces and an explicit Alice return. Results retain `isolation_verified: false`;
the released integration remains diagnostic and has no mode selector yet.
