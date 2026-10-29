# Preconnected byte-channel foundation

A prepared child can communicate through one approved, already connected UNIX
stream without permission to create sockets, connect to other endpoints or exchange
file descriptors. This is a building block for narrow local helpers and diagnostic
IPC adapters. It is not a D-Bus implementation or the final cloud Alice policy.

The trusted preparation checks the descriptor’s socket type/domain, connected state
and cached peer credentials against its live parent. Datagram/seqpacket, listener,
pipe and unrelated-peer candidates are rejected. The child closes other inherited
FDs and installs the worker lifecycle guard before exec. Speaker children also use
the vendor identity and complete capability drop. The supplied channel survives
exec; read/readv and write/writev transport ordinary bytes.

Seccomp denies all socket creation, address-bearing operations, accept, message
send/receive APIs, time64 recvmmsg, pidfd descriptor import and io_uring setup.
Legacy ARM multiplexor slots are explicitly denied even when modern EABI headers
omit their names. The host filter rejects x32. Duplicating the admitted channel does
not evade the restrictions because they do not depend on its original FD number.

This strict policy also denies IP socket creation. A normal cloud Alice worker
needs separate reviewed internet admission; this policy cannot be installed on that
worker unchanged. Complete composition also requires private filesystem/FD views,
capability drops, approved broker protocols and receiver lifecycle checks.

## Kernel evidence

Two epochs passed **114 checks on the speaker**: 36 parent checks and 39 child checks
per epoch. A fortified x86 Linux host passed **102 checks**; six additional ARM
checks cover direct send/recv, time64 and legacy syscall exclusions.

The parent creates only an own abstract canary listener and preconnected pairs.
Children cannot reconnect the channel to that canary, disconnect it with AF_UNSPEC,
use FASTOPEN/sendto, create other sockets or import/export SCM_RIGHTS. A real parent
SCM_RIGHTS message carries an empty, unlinked fixture file. The child’s denied
recvmsg leaves it queued; readv receives its byte without adding a descriptor.
Descriptor counts agree before and after. Vectored byte replies work.

The test deliberately retains an alias of each old receiving endpoint. After the
peer closes, queued synthetic bytes remain readable through that alias. Thus peer
closure alone is not a queue-purge guarantee. The next child receives a fresh socket
object and no old descriptor; retained old bytes are read separately by the trusted
parent and all final references released. This verifies real kernel socket queues
using synthetic data, not SDK telemetry/batch queues.

The own canary listener accepts the parent’s positive control afterward. Unrelated
root IPv4/IPv6 loopback exchanges work. Stock process identities, boot/configuration
and firewall rules match before and after. No actual bus, SDK, account or audio was
accessed, and no production state was installed.

Ruff, the public-source check and **1278 Python/HA tests** passed. CI now includes
**40 native targets**, with the channel probe built for ARM and exercised on its
host. The qualified ARM SHA256 is:

`3af497acba5fde891421631a666a8360b6b4a8ab94acbe6eb6a004864b07c5db`

```sh
python controller/build.py --target unix-channel-probe
python -m controller.qualify_unix_channel YOUR_SPEAKER_SSH_ALIAS \
  --ssh-config YOUR_SSH_CONFIG --run-own-channel-trial
```

The shared trial mutex, bounded native lifetime, parent-death SIGKILL and independent
watchdog cover the own fixture. Lab harnesses now resolve the executable to its
fixed canonical location before comparing proc executable paths: the speaker’s
`/data` is a symlink. This also corrects the storage, worker and SDK diagnostic
harnesses; it does not constitute new crash-injection evidence for those trials.

## Remaining work

SDK/libc compatibility, broker message schemas, endpoint ownership and complete
sender/receiver reference revocation remain required before admitting a real bus.
Ordinary SDK sendmsg/recvmsg use needs a reviewed byte adapter; a preload hook must
never be the security boundary. No full host-bus bind or broad UNIX socket allowance
has been added. Permanent switching and boot installation remain unfinished.

Linux [unix(7)](https://man7.org/linux/man-pages/man7/unix.7.html) describes peer
credentials, descriptor passing and discarded ancillary descriptors. The historical
ARM compat syscall slots are listed in the Linux
[AArch32 syscall table](https://github.com/torvalds/linux/blob/v4.9/arch/arm64/include/asm/unistd32.h).
