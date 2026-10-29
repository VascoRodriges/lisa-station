# UDP ownership and kernel capability

The fixed read-only UDP helper brackets its process/FD census with two socket
tables. With UDP_DIAG available, it retains kernel cookies, state, UID,
interface, queue lengths and supplied IPv6-only metadata. Process start ticks,
executable object identity and socket FD inode are checked again. Shared holder
observations remain separate; endpoint ownership is never inferred solely from
a source port or a conntrack candidate.

The actual speaker reports `CONFIG_INET_UDP_DIAG` **not set**. Its kernel dump
returns `ENOENT`. The helper handles only explicitly unavailable capabilities
with a `/proc/net/udp{,6}` fallback; malformed/interrupted dump evidence is an
error, not permission to use weaker evidence. Fallback rows keep missing cookies
as the kernel sentinel and interface/queue/IPv6-only metadata as `null`. Stable
table/FD metadata must not be described as a kernel-cookie-qualified old flow.
The native implementation follows the Linux
[UDP diagnostic implementation](https://github.com/torvalds/linux/blob/v4.9/net/ipv4/udp_diag.c)
and [inet diagnostic attributes](https://github.com/torvalds/linux/blob/v4.9/net/ipv4/inet_diag.c).

## Qualification

The own-loopback probe passed **108 checks on the speaker** using the explicit
fallback and **98 checks on the fortified Linux host** with UDP_DIAG available.
It covers connected/unconnected IPv4/IPv6 endpoints, optional IPv6-only
metadata compared with effective socket settings, process/executable/FD reuse,
shared descriptors, changed cookies/peers and malformed metadata. It receives
no application payloads and changes no vendor process or firewall rule.

One real read-only census found 15 UDP sockets and 17 confirmed FD-holder
observations, with no unreadable process FD directories. Nine sockets belonged
to known vendor actors; all nine were unconnected. Their `sendto()` destinations
remain unattributed, and three IPv6 endpoints retain unknown IPv6-only flags.
Counts describe this observation, not a permanent inventory. The native digest
is `34ec9a14d502c3ca7687a98af8764cbd06ccb2b518a110ccdd5919bb3d0a17e5`.
The Python/HA suite passed **509 tests**.

```sh
python controller/build.py --target udp-evidence-probe
python -m controller.udp_inventory YOUR_SPEAKER_SSH_ALIAS \
  --ssh-config YOUR_SSH_CONFIG
```

The CLI prints only counts, capability and unresolved reasons. Real addresses,
PIDs and descriptors stay in ignored `build/udp-inventory.json`. The root-only
census accepts no caller-supplied target PID/address, requests no SOCK_DESTROY,
reads no audio or socket payload and changes no network infrastructure.

No UDP evidence from this tool becomes an executable policy plan. A connected
peer is only that socket's current peer, and an unconnected endpoint does not
name all past or future destinations. Sequential observations cannot prove a
complete frozen census. Old-flow/queued-packet handling and composition with
the guarded roles remain pending; `production_plan_ready`, `apply_supported`
and `isolation_verified` remain false.
