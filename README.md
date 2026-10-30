# Lisa Station

Custom Home Assistant integration and local controller for a rooted Yandex
Station 2. The long-term goal is an explicit **Lisa / Alice / Paused** selector,
local enforcement of Yandex isolation, an Assist satellite and an independent
media player.

**v0.1.0 is a diagnostic preview. It does not switch modes, isolate the whole
station, capture speech or execute voice commands.** Stock Alice keeps working.
The Yandex-isolation entity intentionally stays `unknown` in this release.

## Available now

- UI configuration with SSH server public-key pinning and a dedicated client key.
- Physical microphone mute, root filesystem read-only state, vendor process
  counts, and controller state in Home Assistant.
- Bounded status responses, timeouts, offline availability and connection
  reconfiguration. The client executes one fixed read-only command.
- Diagnostics omit connection settings, keys, identifiers and speech.
- Optional on-device sandbox self-test, confined to its own disposable process.
  This is a mechanism test, **not** evidence of whole-device isolation.
- English and Russian UI strings.

## Requirements and installation

- Home Assistant **2026.10.4 or newer**; tested against 2026.10.4.
- A rooted Station 2 with the verified `yandex,station-midi` firmware ABI:
  Linux 4.9, armhf userspace, glibc 2.30. Other devices/firmwares are untested.
- SSH access and a separately verified SSH server public key.
- The status helper and a dedicated **forced-command** key, described in
  [controller setup](docs/CONTROLLER_SETUP.md).

Copy `custom_components/lisa_station` into your HA `custom_components` directory,
then restart Home Assistant. Alternatively, add this repository as a HACS
**custom repository**, category Integration. This project is not in the default
HACS catalog.

In HA: **Settings → Devices & services → Add integration → Lisa Station**.
Enter the host, SSH port, user, the absolute private-key file path **inside HA**,
and the verified SSH server **public** key (`ssh-ed25519 ...`). No key contents
are pasted into the integration. The private key is read from its file.

Do not remove Yandex Station while you still depend on it for media,
announcements, automations or another speaker. v0.1.0 can coexist with it.

## Planned behavior

The controller on the speaker will own transitions and persist the requested
mode before vendor startup. HA/NAS failure must not turn Alice back on.
Speech processing uses the existing HA Assist pipeline; it does not introduce a
second conversation engine. OpenRouter or other cloud agents remain optional
pipeline choices; excluding Yandex is not the same as operating fully offline.

See the [roadmap](docs/ROADMAP.md) for scope and acceptance criteria. Mode
switching, an Assist satellite, continuous audio, an independent media player,
Music Assistant output, timers and alarms are **not implemented in v0.1.0**.

Development notes: [feature migration matrix](docs/FEATURE_PARITY.md) and
[speaker-local isolation design](docs/ISOLATION_DESIGN.md). Experimental kernel
qualification tools are separate from the diagnostic integration's commands.
The development tree includes scoped packet filtering, exact TCP closure,
post-close kernel reply/UDP quarantine and passive connection ownership tools.
These do not enable mode switching or change the released v0.1.0 feature set.
The planned policy targets Yandex services; unrelated applications retain internet access.
Independent [DNS/time profiles and startup admission](docs/SERVICE_PROFILES.md)
have been qualified separately; boot enforcement is not installed yet.
The [fixed startup backend](docs/STARTUP_GUARDIAN.md) also passed a bounded real
launcher/start-stop-recovery trial. It is not yet connected to the HA mode selector.
The [durable close engine](docs/CLOSED_TRANSITION.md) adds a persistent startup
fence, interruption recovery and a scoped vendor policy/stop trial. Complete
production isolation, boot enforcement and explicit Alice return remain pending.
[Exact-flow recovery](docs/FLOW_RECOVERY.md) also passed a closed-transition trial
with persisted evidence, selective rules and a fresh coordinator after a crash;
only owned test sockets were touched and stock Alice stayed running.
The [known-service audit](docs/VENDOR_SCOPE.md) now joins live per-FD TCP evidence
with process snapshots and reports UDP, local-relay and log/data-path gaps. It
is read-only and does not create an executable isolation plan.
The [ALSA diagnostics guard](docs/DIAGNOSTICS_GUARD.md) passed a bounded real
service trial with private ephemeral logs, direct internet-socket denial and
verified stock restoration. Local D-Bus/shared-memory relays remain explicit;
this backend is not installed into boot or exposed to HA mode controls yet.
The [file/mapping queue audit](docs/RELAY_QUEUES.md) identifies shared-system-log
ingress, retained descriptors and mapping-only holders. It keeps unresolved
relay/queue requirements explicit and never deletes mixed device state.
The [guarded collector epoch](docs/COLLECTOR_EPOCH.md) now excludes the shared
system journal and provides private SQLite/log storage for a standalone gated
collector. It passed a bounded real-code trial and remains separate from boot
installation and HA mode controls.
The [telemetry storage boundary](docs/TELEMETRY_EPOCH.md) also separates LMDB,
working sessions and batch paths. Its real-code lifecycle is observed, while
real SDK batch materialization remains an explicit failed acceptance criterion.
The [UNIX peer/holder audit](docs/IPC_PEERS.md) identifies local relay candidates
without reading socket names or payloads. Unresolved datagram/shared-holder and
receiver-data gaps remain explicit; it does not apply a policy.
The [shared guarded-role close](docs/COMPOSITE_ROLES.md) verifies all four
group barriers before shared permit revocation and attempts every role's stop.
Its two-epoch trial passes; it is separate from full migration and boot control.
The [kernel IPC queue guard](docs/IPC_QUEUES.md) adds inherited per-process
denial of System V IPC and POSIX message queues, without changing host queues
or unrelated applications. UNIX/file/mapping relays remain separate requirements.

The [private standard-bus diagnostic](docs/PRIVATE_BUS_DIAGNOSTIC.md) now handles
restricted own-client methods in two disposable filesystem epochs through
preadmitted streams. The [no-FD authentication component](docs/BUS_AUTH_GATE.md)
is qualified with an own client. SDK sibling ownership, hookup and permanent
mode switching remain unfinished.

The [bounded byte relay](docs/BUS_BYTE_RELAY.md) now carries own-client method
traffic through a separate sealed actor. Both EOF directions and descriptor
cleanup pass in disposable speaker trials; actual SDK binding and permanent
mode/boot/voice composition remain unfinished.

The [immutable client binding](docs/PRIVATE_CLIENT_BINDING.md) now qualifies a
separate own client beside the bus and relay in private platform storage. The
actual SDK, permanent modes/boot/voice and HA migration remain unfinished.

The [audio-free SDK admission diagnostic](docs/SDK_PRIVATE_BUS_DIAGNOSTIC.md)
now verifies the actual platform executable and loaded client binding, private
storage/FD boundaries and complete thread teardown beside the bus and relay.
A reviewed logical client-label bind now works without a kernel bind, and [per-thread MSG_NOSIGNAL
compatibility](docs/BYTE_SIGNAL_COMPATIBILITY.md) preserves the SDK's handler.
The SDK now authenticates through the private gate. A [bounded subscription lab
profile](docs/PRIVATE_BUS_SUBSCRIPTIONS.md) permits bounded AddMatch registrations
while retaining driver-only reception. The actual SDK registers two BlueZ
watchers and stops because that service is absent. Usable Alice mode, service compatibility and permanent switching
remain unfinished.

The [live private metadata observer](docs/PRIVATE_MATCH_OBSERVER.md) now captures
the SDK's [bounded subscription set](docs/PRIVATE_MATCH_SET.md) through the private
daemon API, after an independent two-rule own positive control. It verifies
subscription removal and observer closure; actual rule evidence stays private.

A [fixed-schema empty ObjectManager codec](docs/PRIVATE_EMPTY_OBJECTS.md) now
passes synthetic and independent libdbus validation for the next service audit.
It does not enable Bluetooth or change the current SDK/service permissions.

## Development

Use Python 3.14 on Linux in an isolated virtual environment:

```sh
python -m pip install -r requirements-dev.txt
ruff check .
pytest -q
```

Tests include real HA setup/entity lifecycle and a loopback SSH server for key
pinning, command restriction and response limits. All fixtures are synthetic.
Build the native helper separately with Zig 0.14.1:

```sh
python controller/build.py --zig zig
```

No firmware libraries, device account data, model weights, household recordings,
SSH credentials or private infrastructure configuration are distributed.

MIT license. This is an independent community project, not affiliated with
Yandex, Home Assistant or Nabu Casa.
