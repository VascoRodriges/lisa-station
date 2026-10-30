# Byte-only message adapter

The explicit C adapter lets a prepared local helper exchange vectored payloads
through its approved preconnected channel while the kernel still denies raw
sendmsg/recvmsg, endpoint creation/retargeting and descriptor passing. It is an
explicit API, not an installed libc interposer or a D-Bus protocol implementation.
The real SDK and host bus are not connected by this change.

Initialization binds a channel to its parent peer and descriptor object. Each call
rechecks the object and peer. An unrelated descriptor, a changed object or a closed
original FD is rejected; a deliberately initialized duplicate still works. The
independent [kernel channel guard](UNIX_CHANNEL.md) provides enforcement even if an
application bypasses the adapter.

## Deliberately limited contract

Calls accept at most 16 vectors and 64 KiB of buffer space. The vector layout is
copied before I/O; malformed/null vectors, length overflow, destinations and outgoing
ancillary data are rejected before transmission. This is a per-call bound, not a
complete wire-message framing limit. Callers provide valid C structures and handle
kernel short I/O, errors and retries; the adapter has no pending-data queue.

Payload sends use writev and receives use readv. Receive metadata is cleared: no
address, credentials or descriptors are fabricated. Incoming ancillary objects are
discarded by the kernel; the adapter neither detects nor reconstructs truncated
control data. Thus its peer protocol must forbid FD negotiation. MSG_CMSG_CLOEXEC is
accepted because no descriptor is received. This is not general recvmsg emulation.

MSG_DONTWAIT requires an already nonblocking descriptor; the adapter does not change
shared open-file-description flags. MSG_NOSIGNAL requires the caller to maintain an
ignored SIGPIPE policy, configured during trusted preparation. The adapter checks
that policy and never changes signal handlers or consumes pending signals. Other
flags, including peek/FASTOPEN, are rejected. The ignored-handler requirement must
remain true across the call; this API does not lock application signal policy.

## Evidence

The extended own-mock channel trial passed **163 checks on the speaker**: 36 parent
checks and 63/64 child checks. The fortified x86 host passed **151 checks**; the
speaker has six additional ABI-denial checks per child. Existing retarget, raw
message syscall, rights-passing and old-queue controls still run under the kernel
guards.

The new calls reject wrong descriptors, mismatched inode identity, null arguments,
malformed/oversized vectors, destinations, control sends and unsupported flags.
An offered receive control buffer receives no descriptors from the parent’s real
SCM_RIGHTS fixture; vectored payload and descriptor-count checks pass. Zero-vector
I/O, blocking-mode rejection of DONTWAIT, actual nonblocking EAGAIN, SIGPIPE-policy
rejection, byte replies and closed-original/approved-duplicate behavior pass.

The first old endpoint intentionally retains synthetic STALE bytes through a parent
alias while a fresh second epoch runs. The second drains its payload and verifies
actual EOF with a nonempty receive buffer. After peer closure, the adapter returns
EPIPE under the prepared SIGPIPE policy without killing its process.

Both groups are reaped and final references closed. Stock process identities,
boot/configuration, firewall rules and unrelated root IPv4/IPv6 controls are
preserved. No SDK, actual bus, account or microphone is accessed. Ruff, the
public-source check and **1278 Python/HA tests** pass; the build remains at 40 native
targets. Qualified ARM SHA256:

`fc004739b043428fd3a9765cc4f3ead406af711175176c97ad54ddd66269b81c`

## Next integration boundary

A [per-child factory binding](UNIX_BUS_FACTORY.md) is now qualified with own
clients. Actual SDK binding, private protocol framing and broker schemas remain
required. The adapter does not
negotiate FD transport, implement D-Bus authentication or authorize real host
services. Kernel guards, private filesystems, worker ownership and complete queue/
receiver revocation are separate requirements. The strict no-IP local-helper policy
is not the final cloud Alice policy. Permanent mode switching remains uninstalled.

The underlying API contracts are described in Linux
[send(2)](https://man7.org/linux/man-pages/man2/sendmsg.2.html),
[recv(2)](https://man7.org/linux/man-pages/man2/recvmsg.2.html) and
[readv(2)](https://man7.org/linux/man-pages/man2/readv.2.html).
