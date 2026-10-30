# Private standard-bus diagnostic

A separate copy of the device's standard D-Bus daemon now authenticates an own
client and handles Hello/GetId in a fresh private filesystem. The host system bus,
SDK, real account state and audio are not exposed. This is a bounded diagnostic;
no production bus, mode selector or boot service is installed.

## Endpoint and filesystem admission

The device kernel rejected a private network namespace with EINVAL. Its libdbus
also appears compiled without inherited systemd-listener support. The working
path therefore admits one already-listening UNIX stream object and one prepared
stream pair for the daemon's internal reload notification. It never enables
systemd service activation or loads the host system/session configuration.

The coordinator creates these objects in its private 0700 lab directory. A
per-child read-only preload binding maps socket/bind/listen/socketpair calls onto
the one-shot capabilities. accept/accept4 admits at most four lifetime connections
from the actual parent peer. Address arguments to accept are kernel output, not
a new destination. Accepted streams and the internal pair use the bounded
[byte adapter](BYTE_MESSAGE_ADAPTER.md) for libc send/recv/sendmsg/recvmsg calls.
No fallback opens another endpoint. The caller maintains FD ownership and the
nonblocking/SIGPIPE contracts; this is not arbitrary POSIX emulation.

Independent inherited kernel filters deny all new socket/socketpair, bind/listen,
connect, address-bearing sends, raw ancillary receive/send calls and alternate
reviewed ARM entry points. Only acceptance on inherited stream listeners remains
available. UID/GID changes, filesystem escape, foreign signalling and process
forks are denied; all current/bounding capabilities are zero. The binding is a
compatibility layer, not the security boundary. No rule blocks other device
applications from the internet.

Before the daemon's first instruction, the parent verifies a distinct mount
namespace, read-only root, bounded 1 MiB writable NOEXEC run/tmp filesystems,
zero capabilities, dedicated identity and the exact six inherited descriptors:
null stdin/stdout, private stderr pipe, listener and reload pair. Host DATA,
accounts, logs, proc/PIDs, audio, shared memory and the host bus are absent.
Libraries, daemon and our binding are read-only; machine identity/NSS/configuration
are synthetic. The actual executable/private view are checked again after exec.

A pre-listening socket's cached SO_PEERCRED identifies its creator, the
coordinator. It does not prove which process later accepts it. Admission therefore
also checks descriptor identity and the daemon executable/private view. The
daemon's accepted peer is independently verified as its live parent.

## Fixed protocol surface and evidence

The explicit private configuration uses EXTERNAL authentication, with no includes,
service directories/helpers, syslog, pidfile, daemonization or service activation.
It limits message sizes, bytes, connections, names, matches and replies. Only
Hello/GetId method calls are allowed in this fixture; ListNames and ReloadConfig
return AccessDenied. This is an own-client test policy, not an SDK service schema.

The speaker passed **146 checks**: 15 own-ELF syscall controls, 52 coordinator checks,
five outer-parent checks, 11 per relay and 26 per separate own client in two epochs.
Two fresh daemon epochs authenticate and answer methods. Their generated bus identifiers differ. A retained client duplicate is
drained to real EOF after daemon termination; the parent closes all listener,
reload and client references before starting the next epoch. Every child is
reaped. These are actual private-bus queues, not SDK telemetry/batch evidence.

Stock process identities, boot/configuration and packet rules are preserved.
Unrelated root UNIX/IPv4/IPv6 controls work, and rootfs remains read-only. Private
stderr records expected inability to chmod the symbolic listener path or raise
the hard 64-FD limit; neither admission restriction is relaxed. The wrapper uses
the single global trial lock, PID/tick stamps and bounded parent-death/watchdog
cleanup. This stage does not add a separate crash-injection acceptance result.

Qualified ARM SHA256 values:

- Probe: `8ef15300b2e0ed93bd50c4ad046f3fde472035cb4af5bf49f65bcf83defe7193`
- Binding: `7d330f59f0e62c18230408150b582163603a157810e1bbfb0d7bc126d6f1881b`

Ruff, public-source validation and **1398 Python/HA tests** pass. CI builds 45 native
targets and compiles the new binding with fortified host GCC. The actual daemon
trial is device-only; CI neither obtains nor distributes firmware libraries.

## Explicit remaining protocol gap

The unmodified daemon still replies AGREE_UNIX_FD to negotiation. The byte adapter
cannot provide that advertised transport: kernel ancillary calls remain denied
and readv drops incoming control objects. The diagnostic deliberately reports
`fd_negotiation_disabled=false` for that raw daemon, never full isolation or SDK
readiness. The [bounded authentication gate](BUS_AUTH_GATE.md) now supplies a
verified no-FD path through the [sealed byte relay](BUS_BYTE_RELAY.md) for an own
client on an actual socket: it forwards the real daemon OK,
answers negotiation locally with ERROR and sends only BEGIN to the daemon. This
path reports `auth_gate_verified=true`. The separate raw connection still obtains
AGREE_UNIX_FD as a control. The relay actor composes the gate with socket I/O in
this bounded trial; the [own-client sibling/binding](PRIVATE_CLIENT_BINDING.md) is now qualified.
Actual SDK compatibility and full holder lifecycle still require qualification. Small FD-count limits alone are not
evidence of a byte-only authentication contract.

Immutable client binding placement, actual SDK service authorization, protocol
framing/receiver lifecycle, real identity/queue handling, permanent supervision
and boot/mode integration remain required. The bounded wire helpers here are own
test clients, not a production D-Bus parser or a general host-bus forwarder.

The configuration and compatibility decisions use the upstream
[daemon manual](https://dbus.freedesktop.org/doc/dbus-daemon.1.html),
[1.12.16 UNIX transport](https://github.com/d-bus/dbus/blob/dbus-1.12.16/dbus/dbus-sysdeps-unix.c)
and [authentication implementation](https://github.com/d-bus/dbus/blob/dbus-1.12.16/dbus/dbus-auth.c).
