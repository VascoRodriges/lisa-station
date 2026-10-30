# Bounded byte-stream relay

The relay now runs the [authentication gate](BUS_AUTH_GATE.md) over two actual
nonblocking streams. A separate sealed own-ELF actor on the speaker relays an own
client to the private standard daemon. The client receives the real OK and local
FD-negotiation ERROR on its socket; restricted method replies traverse the relay.
No SDK, host bus, account or microphone is connected by this diagnostic.

## Admission and I/O ownership

Both objects must be distinct connected parent-created UNIX streams, with the
expected cached peer PID/UID, nonblocking mode and prepared SIGPIPE policy. The
caller must already have installed the reviewed no-new-privileges, seccomp and
parent-death layers; observing these flags alone does not attest their policy.
Rejected inputs remain caller-owned. After admission, the function owns both
FDs and closes them on every result. Trusted code serializes FD ownership; this
is not a defense against hostile concurrent descriptor close/reuse.

A poll loop uses byte readv/writev through the checked adapter. Pending reads are
at most 512 bytes per direction and gate outputs at most 8 KiB per direction.
When a destination is full, its source stops reading. Short writes consume only
the written prefix; EINTR/EAGAIN retain data, with blocked feeds retried before
new reads. The fixed authentication deadline is checked while waiting for events.

EOF, hangup, error or deadline closes both streams and clears pending storage.
Queued tail bytes can be discarded on hangup; this contract does not half-close,
flush an interrupted session or replay it into a new epoch. The current API
requires a finite lab lifetime, capped at 60 seconds. Permanent supervision and
production lifetime handling remain separate work.

## Actual actor boundary

The coordinator creates the listener/backend connection/client pair, then gives
only the two relay endpoints and a report pipe to the actor. Before its first
instruction, the parent checks the private mount/filesystem, zero capabilities,
identity and exact six FDs. Standard input/output/error are null; there are no
listener/reload/host-directory descriptors in the relay. A ready marker from the
exec'd own actor precedes a second executable/private-view check. The parent's
surplus endpoint copies are closed before protocol processing.

The actor inherits full identity/capability/lifecycle restrictions and the strict
channel filter, including raw accept/retarget/socket/ancillary denial. It checks
those denials on its valid channel before reading any protocol bytes. Its root is
read-only, writable run/tmp are bounded NOEXEC filesystems, and host DATA, accounts,
proc, logs, audio and the host bus remain absent. It has no mode journal or packet
administration rights. The existing byte-channel parent validator is unchanged.

Cached SO_PEERCRED reports the creator, not the current reader after inheritance.
The coordinator's independent executable, view and FD-object admission therefore
matters. This trial proves daemon/relay sibling ownership with an own client in
the coordinator. A separate SDK sibling/client-binding composition remains to be
qualified; cached credentials alone do not prove all current holders.

## Evidence and remaining work

The fortified host fixture passed **85 checks across nine cases**. It verifies
pipelined authentication/binary tail, 256 KiB of independently checked data in
each direction, and paused receivers that cause real short writes, EAGAIN and
backpressure without exceeding storage bounds. Other cases cover authentication
timeout, malformed authentication, blocking descriptors, object aliases, pipe/
datagram rejection, missing SIGPIPE preparation and wrong expected parent. Rejected
objects remain open for caller cleanup. ASan/UBSan also passed the fixture. These
host workers have syscall guards; they are not filesystem-isolation evidence.

The composed device trial passed **99 checks**: 15 controls, 57 coordinator checks,
five outer controls and 11 checks in each of two sealed relay actors. Actual
Hello/GetId and forbidden method controls pass through the relay. The raw second
connection still gets AGREE_UNIX_FD, confirming the gate's effect on the relay path.

In the first epoch, daemon termination causes backend EOF and relay teardown;
a retained client alias then reaches EOF. In the second, closing all client aliases
causes client EOF and relay teardown before daemon termination. Both actors report
the correct EOF origin and closed descriptors, are reaped, and their private roots
are released before the next epoch. Fresh daemon IDs differ. This is actual local
bus/relay evidence, not SDK batch materialization or a new parent-death crash test.

Stock identities, configuration, firewall and rootfs are preserved; unrelated root
network controls pass. Ruff/public-source validation and **1391 Python/HA tests**
pass. CI builds 45 native targets and repeats the host relay fixture. Qualified
private-bus ARM probe SHA256:

`4401f5c5d54f8e57f3d2ee43f18becbc2b8f1e53276fdb50820293eaef3a6e1f`

The server binding is unchanged. Actual SDK immutable client binding, peer/holder
lifetime completion, required service schemas, identity/hardware/time compatibility
and production mode/boot/voice integration remain unfinished. This diagnostic
installs no permanent service and never restores or restarts ordinary Alice.
