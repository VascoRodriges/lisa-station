# Bounded local transition recovery

The staged watcher recovers abandoned intent transactions without depending on
the transition worker, Home Assistant or the speech server. It never opens Alice.
It first takes the validated exclusive transition lease: a busy lease means a
worker may still be operating, so the watcher waits without revoking its permit
or stopping its actors.

After acquiring the lease it inspects the durable journals. An unfinished close
retains its original base revision and Lisa/Paused target. An abandoned opening
is cancelled by closing the current revision to Paused. The existing close engine
performs denial, permit revocation, stopping and verification. Inspection releases
its lease before that engine acquires its own; revision checks and another busy
lease cause reinspection if an explicit request wins the intervening race.

A completed newer close makes its cancelled opening stale. Keeping that opening
fence does not cause another revision on every poll. A retry of the old opening
is refused; a fresh explicit request must prepare a new generation. Corrupt or
mismatched journals are preserved and reported as faults.

The composed wrapper now acquires the epoch lease inside the first denial
callback, after the transition/mode locks, rather than before starting the intent
engine. This removes the previous epoch/transition lock-order inversion.

## Qualification

The native recovery decision fixture passed **33 checks on persistent speaker
storage and a fortified Linux host**. The same native target retains its 76
epoch-store checks and strict mark/deny parser fixtures. The build matrix remains
36 targets.

The **43-event kernel trial** used private synthetic mode records and its own
loopback sockets. It verified this sequence:

1. A held live opener retained its lease and original intent. The watcher reported
   busy and allowed that explicit opening to finish after release.
2. SIGKILL interrupted another opener after a partial IPv4 release. Without a
   driver-issued denial or close, the watcher closed the current intent to Paused,
   revoked its permit and preserved the opening fence. Repeated status checks
   showed no revision loop.
3. The stale opener was refused. A new explicit request succeeded with a fresh
   generation, while the retired socket remained denied and retained its mark.
4. SIGKILL interrupted a Lisa close at its first journal checkpoint. The watcher
   finished that original close to Lisa, rather than changing its target.
5. The watcher stopped only after observing the verified closed policy.

All **13 UDP socket checks** passed. Unrelated IPv4/IPv6 controls remained usable,
both recoveries reported closed policy and revoked permits, and the final watcher
summary reported two recoveries, no faults and no automatic opening. Stock
process identities, boot and configurations were preserved; firewall rules were
restored. No audio was captured and no actual vendor process was started or
stopped by the mode callbacks.

The strict report checker rejects missing/reordered records, incorrect revisions
or targets, missing permit revocation, wrong flow attribution, boolean values
substituted for counters, and claims of full isolation. Private raw reports and
device configuration are excluded from the repository.

Ruff, the public-source check and **930 Python/HA tests** passed before publication.

Qualified ARM SHA256:

- composed watcher: `604c5e9c94e2f67a6b6f985d5333886b1df17aaa9f44614ec4819fa1b3aaa514`
- socket fixture: `8a9aa4ea21fca2113211d63527c5934966a53e6734fa1c8bc7c5e4ae3e705322`

```sh
python -m controller.qualify_recovery_watch YOUR_SPEAKER_SSH_ALIAS \
  --ssh-config YOUR_SSH_CONFIG --run-bounded-watch-trial
```

The fixture refuses installed production state, writable rootfs and concurrent
speaker trials. Cleanup stops only its recorded helper identities before removing
its owned rules. The older 32-case opening matrix used explicit driver recovery;
it is separate evidence and was not a 32-case autonomous watcher trial.

## Deployment boundary

This watcher is a bounded laboratory process with an SSH parent and a 120-second
deadline. It is not the permanent PID-1-supervised coordinator. Its CLEAR result
means only that no journal action is pending; it does not attest to live permits,
actual packet policy or production actor/FD inventory. A damaged policy owner
now has a separately [qualified emergency path and durable fault latch](EMERGENCY_POLICY.md).
Its bounded runtime check respects epoch-reader contention. Permanent supervision,
all journal-fault paths and production runtime admission still need composition.

Actual service migration, platform filesystem/IPC boundaries, boot gates,
installer and cold-boot acceptance remain unfinished. Lisa in this fixture is
an intent record, not the permanent speech service. The diagnostic HA integration
still does not offer a production mode selector or claim complete isolation.
