# Roadmap

The target is a standalone integration for device control, with the existing
Home Assistant Assist pipeline supplying command recognition and responses.
This roadmap distinguishes shipped code from acceptance targets.

| Phase | Deliverable | Acceptance | Status |
|---|---|---|---|
| 1 | Status controller, pinned transport, UI setup and diagnostic entities | Real device status; incompatible data rejected; offline state safe; no false privacy claim | v0.1.0 |
| 2 | Speaker-local vendor isolation | Cover senders outside the main launcher, descendants, old sockets, local relays, DNS, IPv4/IPv6 and telemetry queues; other applications retain internet | Actual four-role startup/close composed with pre-start conntrack label admission; collector/telemetry boundaries implemented; platform shared state, receiver/IPC, old unmanaged flows, packet queues and boot composition pending; real SDK batch remains unmaterialized |
| 3 | Persistent mode controller | Alice / Lisa / Paused, serialized transitions, verified actual state, boot enforcement before vendor startup, fail closed, explicit return to Alice | Composed explicit open/close and closed-mode rollover qualified; bounded local watcher recovers killed opening/closing workers without automatic Alice return; permanent supervisor, runtime health admission, production actor/boot composition and installation pending |
| 4 | Permanent speech service | No workstation dependency; local KWS, standalone VQE, target-speaker extraction on a server, Assist through response playback, physical mute honored | Bounded research prototype exists outside this release |
| 5 | Assist satellite and voice settings | Pipeline choice, listening/processing/responding states, LED feedback, measured latency and recovery | Planned |
| 6 | Independent media player | Playback/volume/metadata, files/URLs/radio, Music Assistant without the old Yandex Station backend, announcements and volume restoration | Planned |
| 7 | Household functions | Persistent timers/alarms/reminders, buttons and lights, explicit behavior during HA/NAS failure | Planned |
| 8 | Per-speaker migration | Inventory and replace dashboards/scripts/automations/music routes; disable old control only for the migrated device | Planned |
| 9 | Acceptance and additional speakers | Reboot/failure/audio tests, independent wake-word evaluation, verified rollback, then migrate another speaker | Planned |

## Invariants

- Requested mode and verified actual mode are different facts.
- Switching to Lisa/Paused persists the closed policy before subsequent steps.
- Failure of HA, NAS or the voice process never automatically enables Alice.
- A damaged installed mode record fails closed; return to Alice is explicit.
- Privacy cannot be inferred merely from zero vendor processes or a successful
  isolated-process seccomp test.
- Hardware microphone mute is respected, not bypassed.
- Deny Yandex services and their flows; keep internet access for unrelated device applications.
- Existing OTA protection and recovery access survive every migration.
- No continuous audio or transcript history is saved by default.
- Diagnostics omit secrets, speech and private network configuration.
- One speaker's migration must not disable another speaker's old integration.

## Known platform constraints

The verified Station 2 firmware has a Linux 4.9 kernel without a network
namespace or a usable network cgroup. Vendor processes and administration share
root, so a blanket UID-0 firewall rule cannot provide selective isolation.
Seccomp works in our own process and survives exec, but this does not retrofit
existing vendor processes or prevent external file/IPC relays by itself.

The separate ALSA audio diagnostics service and local DNS resolver start before
the main vendor launcher. They belong in the isolation audit as well. No complete
whole-device protection is claimed in the diagnostic release.

Cloud Alice's exact voice, skills and personal recommendations are not promised
as autonomous copies. A selected external conversation agent remains external
even when the speaker does not interact with Yandex.

See [DNS/time profiles and startup admission](SERVICE_PROFILES.md) for the new
components, measured results and remaining deployment requirements.
The [startup guardian](STARTUP_GUARDIAN.md) now links admission to a tracked
process and closed reconciliation; production boot/mode switching remains pending.
The [durable close engine](CLOSED_TRANSITION.md) adds interruption recovery and
a persistent startup fence. Its scoped group-policy trial is not whole-device
isolation and does not enable the HA mode selector.
The [flow recovery layer](FLOW_RECOVERY.md) persists exact tuples/cookies before
socket closure and rebuilds their policy in a new coordinator. Full vendor
attribution, relays and queued traffic still require integration before deployment.
The [known-service census](VENDOR_SCOPE.md) distinguishes stable external TCP
observations from vendor-internal peers and preserves unresolved UDP/data paths;
sequential audit output is never a production flow manifest.
The [diagnostics guard](DIAGNOSTICS_GUARD.md) adds a separate gated role,
private ephemeral logs and direct internet-socket denial. Its D-Bus/shared-memory
dependencies remain explicit relays; boot installation and full isolation are pending.
The [queue/holder audit](RELAY_QUEUES.md) now retains unlinked and mapping-only
objects and identifies system-log ingress. It supplies metadata and transition
requirements; it does not purge device state or authorize a closed mode.
The [collector epoch](COLLECTOR_EPOCH.md) now enforces a separate filesystem
view and queue lifecycle for the standalone log collector, with fixed admission
and close behavior. Production boot/mode composition is still pending.
The [telemetry storage boundary](TELEMETRY_EPOCH.md) adds private LMDB/session/
batch paths and a post-exit directory observer. Its real-code lifecycle passes,
but SDK batch materialization is explicitly unobserved and full acceptance fails.
The [UNIX peer/holder audit](IPC_PEERS.md) adds kernel peer/cookie evidence and
explicit cross-role, shared-holder and datagram gaps. It is read-only; composite
IPC enforcement and receiver-data lifecycle remain pending.
The [shared guarded-role close](COMPOSITE_ROLES.md) now verifies all four group
barriers before common permit revocation and stops/verifies every role. A
two-epoch real-code trial passes; full sender migration and relay/flow/boot
composition remain pending.
The [kernel IPC queue guard](IPC_QUEUES.md) denies System V and POSIX message
queue interfaces in new guarded actors. Existing unguarded services and UNIX/
file/mapping relay paths still require migration and composition.
The [four-role startup trial](SPLIT_STARTUP.md) now runs the actual platform/media,
collector, telemetry and diagnostics under separate guards and closes them
together. It verifies executable object identity across jail aliases; platform
filesystem isolation and permanent deployment remain pending.
The [UDP holder audit](UDP_EVIDENCE.md) now verifies endpoint/FD metadata and
records the speaker's missing UDP_DIAG capability explicitly. Unconnected UDP
destinations remain unattributed; this audit never authorizes a flow policy.
The [conntrack-label experiment](CONNTRACK_LABELS.md) passed TCP/UDP own-flow
tests including replies after socket closure and working unrelated controls.
The [labelled startup trial](LABELLED_STARTUP.md) now composes marking admission
before the four actual guarded roles with their shared durable close. Full
coordinator ownership and production boot remain pending; its separate SIGKILL
watchdog trial restored stock services and all owned rules successfully.
The [bounded boot dispatcher](BOOT_DISPATCH.md) now has fixed helper entry points
and real-shell failure fixtures preserving recovery. It is not installed;
the coordinator's service handlers, hardware adapter, installer and cold-boot acceptance remain.
The [closed bootstrap coordinator](BOOTSTRAP.md) now durably reserves its
per-boot namespace before selective policy installation, repairs known ordered
subsets and refuses unknown rules. Its actual-kernel trial preserves ordinary
stock services and does not claim installed isolation.
The [independent mixer adapter](HARDWARE_VOLUME.md) now runs the real calibrated
volume daemon with no networking, PCM nodes or host state. Its bounded handoff
verifies hardware mapping and restores stock volume; permanent boot deployment,
independent DNS/time and the remaining mode handlers are still pending.
The [independent DNS handler](INDEPENDENT_DNS.md) now has a pre-dropped identity,
private filesystem, native profile validation and actual four-listener evidence.
Its port-53 handoff passes and restores stock DNS; persistent time/boot/mode
composition and full isolation remain pending.
The [independent clock handler](INDEPENDENT_TIME.md) now limits chronyd to
SYS_TIME and a private filesystem. A single-controller handoff selected an NTP
source, recorded successful kernel adjustments and restored stock time.
Independent boot failure handling, Alice return and installation remain pending.

The [independent boot path](AUXILIARY_BOOT.md) now keeps mixer, DNS and time
admission separate from vendor mode/policy failures. A real resolver trial passed
with absent/corrupt state and a busy mode lock; the dispatcher still denies vendor
fallbacks. Explicit Alice return, installation and composed acceptance remain pending.

The [explicit Alice-return engine](ALICE_RETURN.md) now preserves a durable
opening fence across every interrupted preparation/commit and fsync failure.
It does not open vendor traffic yet: policy epoch rotation, coordinator callbacks,
private platform state and production installation remain required.

The [generation policy](EPOCH_POLICY.md) now permits new TCP/UDP flows while
retired labelled sockets stay denied on IPv4/IPv6/mapped paths. Its real-kernel
trial preserves unrelated connections. Durable ownership, mutation recovery and
the real mode/role callback composition remain the next implementation work.

The [journalled policy adapter](EPOCH_RECOVERY.md) now composes real packet rules
with the opening/closing intent engines. Its 32 interrupted-opening cases keep
retired flows denied and require an explicit retry. Autonomous local recovery,
closed-mode journal rollover and production role/boot composition remain pending.

The [closed-mode rollover](CLOSED_MODES.md) now changes Lisa/Paused intent without
an unfenced interval and invalidates an early cancelled opener. Native crash
fixtures and a composed kernel trial pass. Autonomous recovery and production
actor/voice/boot installation remain required.

The [bounded recovery watcher](RECOVERY_WATCH.md) now respects live transition
leases, cancels an abandoned opening and finishes an abandoned close with its
original target. A worker-independent kernel trial passes with retired-flow
denial and working unrelated controls. This is a bounded laboratory process;
permanent supervision, fault latching, runtime admission and installation remain.

The [emergency policy adapter](EMERGENCY_POLICY.md) now pre-reserves separate
selective barriers and latches a durable fault after primary-policy journal
corruption. Its own-flow trial closes old/new service sockets while preserving
unrelated controls; restored primary bytes cannot bypass the retained fault.
Permanent supervision, restart reconstruction, all fault paths and explicit
repair remain required before production installation.

The [emergency restart path](EMERGENCY_RESTART.md) now reconstructs the reserved
scope independently of damaged primary files and continues a known partial
barrier. A nine-death transaction preserves the fault and denies old/new service
flows. Permanent supervision, all intent-journal fault paths and production boot
integration remain required.

The [transaction safety paths](BARRIER_ORDERING.md) now require a successful
barrier before permit revocation or actor teardown, including a failed re-denial
after partial release. Native opening/closing/four-role fixtures pass; a pending
fence without a verified barrier remains an incomplete transition. Permanent
supervisor fault routing and production installation remain required.

The [common supervisor recovery engine](SUPERVISOR_RECOVERY.md) now distinguishes
valid contention from corrupt intent/policy, verifies separate closure facts and
restarts through the independent emergency owner. Its composed fault trial and
native decision fixtures pass. Permanent supervision, production actor/FD and
filesystem/IPC boundaries, explicit repair and installation remain required.

The [platform storage foundation](PLATFORM_STORAGE.md) now creates fresh bounded
DATA/TMP/shared-memory epochs without exposing the host vendor DATA tree. Two
own-ELF epochs and pinned seed/race checks pass. Actual SDK, IPC/hardware and
identity lifecycle integration remain required; production switching is still
uninstalled.

The [platform worker guard](PLATFORM_WORKERS.md) now qualifies per-worker thread-only
creation and self-signalling across exec, including parent loss after the leader
exits. This own-ELF boundary is not yet the permanent manager or actual SDK
composition; private IPC compatibility and production installation remain pending.

The [audio-free SDK diagnostic](PLATFORM_SDK_DIAGNOSTIC.md) now composes the private
storage and worker guards with complete per-child socket denial. Actual SDK modes
load configuration and create threads after admission of one pinned read-only boot
metadata file. Platform stops at the denied D-Bus dependency; media cannot create
its time provider. Both are drained, with no real identity/audio or production
changes. Narrow IPC/time adapters, actual SDK queues and permanent installation
remain required; these diagnostic failures are not functional acceptance.

The [preconnected byte-channel foundation](UNIX_CHANNEL.md) now verifies kernel
retarget/descriptor-passing denial and fresh channels despite retained old queue
references. It uses only own mock endpoints and has not opened the real bus or
changed the SDK’s network policy. Protocol adapters and receiver revocation remain
required before production composition.

The [byte-only message adapter](BYTE_MESSAGE_ADAPTER.md) now transports bounded
vectored payloads under the unchanged kernel syscall restrictions. Own mock tests
cover FD identity, ancillary rejection/discard, nonblocking and signal contracts,
EOF and EPIPE. SDK factory/binding, real bus authorization and production switching
remain unfinished; no real services were opened by this adapter.

The [per-child factory binding](UNIX_BUS_FACTORY.md) now adapts observed libc
socket/message calls to a one-shot pool under the unchanged syscall guard. Seven
own-client cases cover constructor rejection, object identity and concurrent
claims. Actual SDK/private-bus protocols, receiver revocation and permanent
switching remain unfinished; the real bus and audio were not opened.

The [private standard-bus diagnostic](PRIVATE_BUS_DIAGNOSTIC.md) now runs the
actual daemon in a fresh filesystem through preadmitted listener/reload streams.
Two epochs authenticate and answer restricted methods without opening the host
bus. Its FD-negotiation contract is still incompatible with byte-only transport;
actual SDK service schemas and permanent mode/boot composition remain pending.

The [bounded authentication gate](BUS_AUTH_GATE.md) now rejects FD negotiation for
an own pipelined client while preserving the real private daemon's OK and
restricted method replies. Split/limit/deadline/backpressure tests pass. Actual
relay I/O/ownership and SDK integration remain required; this is a qualified
state machine, not an installed broker or permanent mode switch.

The [bounded byte-stream relay](BUS_BYTE_RELAY.md) now runs as a separate sealed
actor with actual private-bus method traffic. Host fixtures force short writes,
backpressure and timeout/rejection paths; two speaker epochs verify client/backend
EOF and descriptor cleanup. Actual SDK binding, full holder lifecycle and
permanent mode/boot/voice composition remain pending.

The [immutable client binding](PRIVATE_CLIENT_BINDING.md) now runs an own third
sibling in the private platform filesystem through the actual relay/bus. Both
EOF directions, immutable object/FD admission and default-storage absence checks
pass. Actual SDK compatibility and normal cloud-network policy composition,
permanent mode/boot/voice and HA migration remain unfinished.

The [audio-free SDK admission diagnostic](SDK_PRIVATE_BUS_DIAGNOSTIC.md) now
verifies the actual platform SDK, mapped immutable binding and private FD/storage
view under the common parent. Its tracer drains only enrolled SDK threads while
preserving independent sibling exit reports; a nine-thread own control passes
first. Numeric call-origin metadata distinguished denied libc name-cache sockets
from the SDK's missing logical bind. The reviewed client-label bind is now
adapted without a kernel bind. [Per-thread MSG_NOSIGNAL
compatibility](BYTE_SIGNAL_COMPATIBILITY.md) now preserves the SDK handler and
pending signals. The SDK now completes real EXTERNAL challenge authentication
through the private gate. A [separate subscription lab profile](PRIVATE_BUS_SUBSCRIPTIONS.md)
now permits bounded AddMatch registrations with driver-only reception and a
four-rule lab quota; the default profile retains one and denies AddMatch.
Own controls verify broad/eavesdropping matches do not bypass receive policy,
forbidden methods remain denied and connections close. Further subscriptions,
service compatibility, service schemas and the full permanent switching/voice/HA
roadmap remain open.

A [bounded match-rule metadata decoder](PRIVATE_MATCH_SNAPSHOT.md) now qualifies
the private daemon's Stats reply format with synthetic fixtures. A
[live parent observer](PRIVATE_MATCH_OBSERVER.md) now composes that decoder with
private API queries after scalar SDK readv events. Its
[bounded set audit](PRIVATE_MATCH_SET.md) verifies two known own rules, captures
two actual BlueZ ObjectManager watchers privately and proves SDK state removal
and observer closure. The next dependency is the absent org.bluez service;
host-bus forwarding and service access remain denied. All permanent production
scope remains unfinished.

The next service audit now has a qualified
[fixed-schema empty ObjectManager codec](PRIVATE_EMPTY_OBJECTS.md): bounded
zero-argument request validation and an independently parsed empty-tree reply.
It has no bus/service/device I/O and grants no runtime rights. A private owner,
bounded parent pump and live own-client/SDK composition remain required.
