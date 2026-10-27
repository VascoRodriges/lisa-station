# Mapping Yandex Station features to a rooted local implementation

Reference reviewed: [AlexxIT/YandexStation](https://github.com/AlexxIT/YandexStation),
commit [`4e8567b8dd06679d233233ebb17f9d56a9b2003a`](https://github.com/AlexxIT/YandexStation/tree/4e8567b8dd06679d233233ebb17f9d56a9b2003a).
Relevant source: `core/yandex_station.py`, `core/yandex_glagol.py`, media/stream
helpers, calendar, shopping/todo and notification platforms. The upstream project
is MIT-licensed. This document compares behavior; no upstream implementation is
copied into our controller.

The upstream integration's local Glagol connection is a transport to the stock
application. A local `sendText` or `play` request does not prove that subsequent
speech processing, TTS or media retrieval avoids Yandex. Lisa mode therefore
cannot keep that stock connection as the backend for its core operations.

| User-facing feature | Upstream path | Our intended local path | Acceptance before advertising support |
|---|---|---|---|
| Volume, mute, volume step | Stock `setVolume`/external commands or cloud text | Own PCM renderer's gain/mute, separate announcement gain | Readback reflects applied gain; hardware limits preserved; no automatic jump in loudness |
| Play, pause, stop | Stock Glagol commands or cloud text | Own decoder/renderer lifecycle | Confirm actual playback state, bounded buffers and immediate stop; no unrelated process signals |
| Previous/next, repeat/shuffle | Stock player queue commands | Music Assistant/owned queue | Only advertise operations supported by the active source |
| Seek and duration | Stock `rewind`, stock metadata | Decoder position for seekable media | Disable seek on live/MA streams; position reflects playback, not bytes enqueued |
| URLs, radio, local media | Stock/proxy audio playback commands | HA media-source or MA → decoder → local PCM sink | Preserve authorization, resolve media-source in HA, reconnect/EOF handling |
| Music Assistant output | URL sent to the old station media player | Independent output entity | Verify no hidden call to old Yandex Station entity or vendor decoder |
| TTS and notifications | Alice repeat phrase/dialog functions | Existing HA TTS/Piper → own PCM sink | Queue priority, interruption/ducking and volume restoration |
| Text commands and questions | `sendText` / cloud requests | Existing HA Assist/conversation pipeline | No routing of Lisa requests into Alice; response rendered locally |
| Timers and alarms | Stock device/cloud state | Persistent HA timers/schedules with explicit offline behavior | Restart, timezone, cancellation, missed events, HA/NAS outage |
| Shopping/todo | Vendor list synchronization | HA todo entities | Preserve actual lists and chosen provider; no implicit vendor synchronization |
| Dialogs and follow-up questions | Yandex Dialogs/stock conversation | Assist conversation session | Correct session ownership and playback completion before a follow-up |
| Speaker buttons | Stock application handling | Native input events and local policy | Preserve physical mic mute; avoid double handling with stock Alice |
| Lighting/animations | Stock animation commands | Own framebuffer renderer | Geometry, bounded brightness and exclusive ownership on mode changes |
| Settings/equalizer | Vendor configuration commands | Own gain/DSP profiles where supported | Measure audio/AEC effects; do not expose arbitrary mixer writes |
| Alice on demand | Stock application | Explicit controller mode transition | Whole-device policy and service state confirmed before reporting success |

## Important audio findings

On the verified Station 2, ALSA's simple `Master` is the user-created
`Master Playback Volume` control of a `softvol` path. It is not a reliable measure
of gain for every output path. The normal playback plug also includes an
`audio_metrics` tap. The previously tested direct `dmix_spk` output bypasses that
tap and softvol; its gain must be handled by our renderer rather than by assuming
that changing the old Master control affects it.

The hardware amplifier has separate SY6045S controls. Changing their gain may
affect echo cancellation and calibration. They are not a shortcut to HA volume
support. Keep them unchanged while implementing independent playback gain.

## Delivery rule

The matrix is a migration target, not the current supported-feature bitmask.
v0.1.0 still provides diagnostics only. Enable each HA feature only after its
local backend and failure behavior work. The old integration remains active for
unmigrated speakers. Original cloud voices, skills and personal recommendations
are not promised as autonomous copies.
