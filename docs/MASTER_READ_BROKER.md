# Master-volume read broker

A standalone lab now reads the **actual Master Playback Volume** through a
separate guarded helper. Its own client receives the real value over a fixed
GET-only protocol. The client receives no sound-control descriptor, arbitrary
ioctl interface, control selector or write operation. This is not yet connected
to the SDK, ALSA plugin or Home Assistant, and installs no production service.

Each epoch uses a new anonymous UNIX **SEQPACKET** pair and a nonzero 16-byte
epoch tag. Packet boundaries let the receiver reject both short and oversized
requests rather than treating an extra byte as another stream fragment. A
40-byte request contains only the fixed version, epoch, expected sequence,
GET opcode and zero reserved bytes. A 48-byte reply binds the same epoch and
sequence and carries either a current integer level in 0..255 or a bounded
error with no value payload. Epoch tags correlate requests; they do not
authenticate roles or authorize hardware access.

The session permits at most 32 sequential exchanges. A second request cannot
be accepted while one is pending. Replay, a different epoch, unknown operation,
reserved data and invalid framing stop the epoch. A rejected packet never
causes a hardware query. Codec failures preserve prior session state for
inspection only; the live backend immediately faults and closes it.

The parent opens card zero's control descriptor **read-only**, proves its
character-device identity, validates the compatible unlocked user Master
control and binds its current kernel element ID to this epoch. The backend
rechecks the fixed name, type, count, range, lock/owner state and element ID on
every GET. INFO/READ/INFO must all succeed and preserve the ID. Only the actual
current value is returned. Missing, recreated or incompatible controls and
read errors produce an error and close the epoch; no old level or substitute
value is returned as success. No volume is set or restored by this lab.

Both own actors have separate read-only mount namespaces, no host data, proc,
sysfs, writable state, bus or sound-device paths, and zero supplementary groups
and all five capability sets. NNP and parent-death signal are checked directly;
the latter is rearmed after credential changes and cannot then be cleared.
Inherited descriptors close before setup. The backend retains only null stdin/
stdout, a private report pipe, its packet peer and the read-only control FD;
the client has the same layout without that control FD.

The parent inspects descriptor objects, credentials, capabilities, root view
and executable during preparation and at the kernel exec stop, where the
final seccomp policy must be active. It releases the own client only after
closing its copies of both packet endpoints and the control descriptor.
Cached SO_PEERCRED identifies the common creator, **not the actual sibling
holder**; exclusive descriptor admission and parent inspection are separate
obligations. Direct kernel checks test endpoint/ancillary creation, process
creation, death-signal reset and mutating ioctl denial.

The additive ioctl filter permits only INFO and READ on the exact admitted
descriptor. Other ioctl classes and use on another FD are denied, alongside
the existing hardware helper restrictions on network, IPC, tracing, identity
and namespace operations. Classic seccomp cannot inspect the nested ALSA
element selector: **Master-only selection is enforced by trusted backend
code**. The kernel enforces the read-only ioctl class/FD boundary; the backend
retains read access to its card's control interface. The client has no such
descriptor and its protocol cannot select another element. This distinction
is part of the design, not a claim of kernel filtering by control name.

The actual speaker qualification passes **eight fresh epochs**: normal reads,
replay, wrong epoch, SET opcode, oversized packet, truncated packet, nonzero
selector/reserved bytes, and backend SIGKILL after one verified reply. It
checks matching backend/client values, no extra hardware read after invalid
input, client closure and released views. Direct checks total 17 per completed
actor, or 16 for the deliberately killed backend. Another **28 inspection
controls** verify source identity through bind-mounted exec, foreign-image
rejection and final absence. All eleven ordered typed report events are
required, including successful cleanup.

Cleanup uses the artifact's read-only inode inspection commands, not a shell
`stat` utility absent from this firmware. A committed PID/start-tick journal
plus matching executable identity limits signals to owned actors. Native and
actor journals commit atomically; known temporary journal files are handled
explicitly. Cleanup is serialized, waits for absence and removes only known
empty view directories and journal files. An independent watchdog and inherited
ptrace/death fencing cover the bounded trial. No stock daemon is restarted.

The pure wire/state fixture passes **665 checks** on Windows/Zig, fortified GCC
and ASan/UBSan. Host kernel fixtures use `/dev/null`, not ALSA hardware, and pass
19 checks in each of two guarded modes plus four parent checks, also under
ASan/UBSan. Ruff and **1825 Python/HA tests** pass. CI includes both host fixtures
and the new 48th ARM build target. The actual lab preserves stock identities,
configuration, boot and firewall snapshots, and opens no recording/playback
PCM. The SDK and second station are not involved.

Next is a limited ALSA control plugin backed by this real read interface, with
separate SDK descriptor admission and runtime ABI qualification. Unsupported
writes must remain errors until a real bounded write path is implemented.
Plugin integration, event delivery, persistent supervision, full switching
and the remaining voice/HA roadmap are still unfinished.
