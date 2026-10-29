# Roadmap

The target is a standalone integration for device control, with the existing
Home Assistant Assist pipeline supplying command recognition and responses.
This roadmap distinguishes shipped code from acceptance targets.

| Phase | Deliverable | Acceptance | Status |
|---|---|---|---|
| 1 | Status controller, pinned transport, UI setup and diagnostic entities | Real device status; incompatible data rejected; offline state safe; no false privacy claim | v0.1.0 |
| 2 | Speaker-local vendor isolation | Cover senders outside the main launcher, descendants, old sockets, local relays, DNS, IPv4/IPv6 and telemetry queues; other applications retain internet | Actual four-role startup/close trial passed; collector and telemetry filesystem boundaries implemented; platform shared state, receiver/IPC, UDP, old flows and boot composition pending; real SDK batch remains unmaterialized |
| 3 | Persistent mode controller | Alice / Lisa / Paused, serialized transitions, verified actual state, boot enforcement before vendor startup, fail closed, explicit return to Alice | Durable close engine: 65 transaction, 34 admission and 54 guardian checks passed; scoped quasar policy/stop trial implemented; production callbacks, boot gates and Alice return pending |
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
