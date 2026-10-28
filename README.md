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
