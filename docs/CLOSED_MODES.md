# Closed-mode changes and opening cancellation

The close engine now supports a new explicit closed request after a completed
one: Lisa → Paused, Paused → Lisa and a repeated target used to cancel an opening.
It atomically replaces only a completed fence matching the current closed intent.
The fence is never absent during this rollover, and denial/stop/verification run
again before completion. Incomplete, corrupt or mismatched requests are refused.

A new explicit request advances the revision even when its target is unchanged.
This matters when cancelling an opening before its Alice intent was committed:
the old opener's expected revision becomes stale. It cannot retry that cancelled
request. A later explicit opening must use the new revision and pass preparation
again. Cancellation leaves the old opening journal present until an authorized
new request can supersede it; no production state is deleted to bypass guards.

## Evidence

Native close/open probes passed **109/155 checks on persistent speaker storage
and a fortified Linux host**. They cover interruptions at every closed-rollover
checkpoint, closed-mode changes, refusal to supersede an incomplete fence,
early cancellation and rejection of the cancelled opener. Existing opening fsync
failure tests and close/startup ordering checks remain included.

The **16-event composed kernel trial** then exercised the real intent engines
and packet-policy callbacks with private mode records. Lisa/Paused changes kept
the verified closed policy. After a SIGKILL during opening preparation, explicit
Paused cancellation advanced the intent revision; the old opening was refused
without any policy mutation. A fresh explicit request succeeded and final close
restored denial. IPv4/IPv6 controls worked throughout. Stock processes, boot and
configuration were unchanged and all firewall rules restored.

Lisa here is a durable test intent. Its voice process, actual Alice services and
HA mode selector remain uninstalled. The conservative boot choice continues to
block Alice while a closed fence is present; future Lisa activation additionally
requires verified closed policy and the voice actor's own prerequisites.

Ruff, the public-source check and **870 Python/HA tests** passed. The native matrix
remains 36 targets. This short rollover/cancellation trial supplements the earlier
[32 interrupted-opening cases](EPOCH_RECOVERY.md); it does not add automatic local
supervision or installer/power-loss acceptance.

Qualified ARM SHA256:

- closed engine probe: `f4fb6d2a0cc7766b2e5f78c8354d7c4c707a41a73cb47062f271045dc50f0279`
- open engine probe: `877525fb3ae6de927368b67325e6eb831a211e9191672777f0e0f7c41c3ad3b6`
- composed rollover probe: `c5081df57c32d20ceecfef2b4a2145137db02edcda6c2f860d48c04fb7eda653`

```sh
python -m controller.qualify_closed_rollover YOUR_SPEAKER_SSH_ALIAS \
  --ssh-config YOUR_SSH_CONFIG --run-private-intent-trial
```

Autonomous recovery after controller death, production actor/FD inventory and
filesystem/IPC boundaries, real boot admission and installation remain required.
