# Per-child byte-channel factory binding

This diagnostic shared library binds a helper's observed libc socket/connect and
sendmsg/recvmsg calls to a small pool of preapproved byte streams. It is loaded
only into a prepared child, never through a global preload configuration. The
independent [kernel guard](UNIX_CHANNEL.md) continues to reject raw socket,
connect and ancillary-message syscalls when application code bypasses the hooks.
No real SDK, host bus, device account or audio is connected by this stage.

## Admission and one-shot lifetime

Trusted preparation supplies one to four distinct connected AF_UNIX SOCK_STREAM
objects. Constructor admission requires the live parent peer, matching UID,
no-new-privileges, seccomp filtering and parent-death SIGKILL. Missing or malformed
configuration, pipes and duplicate objects terminate the child before its client
code. The constructor observes these flags; it cannot attest the contents of an
arbitrary caller's seccomp program. The coordinator must install the exact guard.

Only UNIX stream/protocol-zero requests claim a slot. Claims are atomic across
threads and never refunded, including after close or allocation failure. Each
successful call duplicates its source, honors CLOEXEC/NONBLOCK and closes the
source descriptor. Object identity, rather than the original descriptor number,
allows approved duplicates while rejecting unrelated objects. Trusted clients
must preserve descriptor ownership and synchronize descriptor close/reuse with
calls; this compatibility layer does not make hostile application races safe.

connect acknowledges only the two reviewed symbolic system-bus pathname aliases;
it never passes either address to the kernel. Abstract, unknown and malformed
addresses fail. A second logical connect fails even through a duplicate. Message
calls require that first logical connect and use the existing bounded
[byte adapter](BYTE_MESSAGE_ADAPTER.md), including its signal/nonblocking contract
and rejection of outgoing destinations or ancillary data. There is no fallback
to the actual system bus or an arbitrary network destination.

## Qualification

Seven own-client cases passed on the speaker and fortified Linux host: **44
parent checks and 47 actor checks, 91 total**. The normal client makes 37 checks;
the two-thread client makes ten. Five malformed admission cases exit with the
expected code 125 before running their client. The threaded client claims two
different streams, returns each stream's own marker and exhausts the pool. Each
fixture pthread has an explicit 1 MiB stack. An inherited large stack default
otherwise exhausted the child's 32 MiB DATA budget in CI; the host regression now
runs with a 32 MiB default stack limit while keeping that DATA budget unchanged.

The real dynamic loader resolves the child's libc calls through the shared
library. Checks cover socket flags, logical connect ordering, aliases, duplicate
FDs, per-object identity, pool exhaustion after close, rejection of wrong pipes,
and raw-syscall denial despite the hooks. Synthetic SCM_RIGHTS input leaves no
new child descriptor. The parent owns and reaps every child and closes all stream
references; unrelated root IPv4/IPv6 controls work. Stock identities/configuration
and firewall rules are preserved. The read-only root filesystem is unchanged.

Qualified ARM SHA256 values:

- Binding: `61765af42ad63d79dbaa72f8551a2021fea0e40aae44154c61e2468dfc2e59d6`
- Probe: `48b42ca44726a9ad0a88c128d8513801dd9d907efe05b07a382b8e1ec8ebaf4a`

Ruff and **1346 Python/HA tests** pass. There are 41 native build targets. CI
builds the binding and repeats the own-client host trial alongside the original
byte-channel test. Speaker qualification uses the global single-trial lock and
refuses installed production state; it never stops or restores ordinary Alice.

## Remaining integration

This is neither a D-Bus implementation nor functional SDK acceptance. A private
peer must implement authentication/framing and forbid FD negotiation; no host bus
forwarder is provided. Binding placement in a private immutable filesystem,
actual SDK compatibility, reviewed service schemas, receiver ownership and full
queue revocation remain required. The library and strict helper guard deny IP;
normal explicit cloud Alice needs its separate reviewed network admission.
Permanent mode switching and boot enforcement remain uninstalled.
