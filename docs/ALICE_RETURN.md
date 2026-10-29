# Explicit Alice return transaction

The native opening executor now implements durable **administrative intent** to
return to Alice. It is not yet wired to the coordinator or HA mode selector and
has not opened real vendor traffic. The closed policy and ordinary diagnostic
HA release retain their existing deployment status.

Only an explicit authorized operation may invoke this executor. HA/NAS failure,
service restart or an interrupted boot must never call it. Boot code does not
resume an unfinished opening request automatically.

## Transaction

The executor shares `transition.lock` with the close engine and retains an
exclusive `mode.lock` through preparation, new intent, permit and policy changes.
It checks the expected revision and any completed close journal, then durably
publishes a private `opening.request` before making changes. Presence of this
file, including corrupt or unsafe contents, blocks new vendor starts and makes
boot choose Paused independently of a readable Alice intent or permit.

Compiled callbacks must reestablish denial, revoke the old permit, stop the
declared actors (including Lisa voice), and prepare the next marking revision.
Only then can the matching completed close fence be retired. The executor commits
the next Alice revision and a permit bound to that revision/current boot. A
policy-release callback and a separate verification must pass before the opening
fence is removed and its parent directory synchronized. Actual guarded service
starts happen separately after this completed admission transaction.

Failures retain or recreate the opening fence, attempt denial before permit
revocation/stop, and never restore stock services. Explicit retry must repeat all
preparation and verification, rather than trust a saved phase; an already
committed revision is not incremented again. Another boot cannot retry the old
opening transaction. A completed explicit close can authorize a later explicit
request with a new revision/boot to replace the earlier, valid opening journal.
Malformed journals are preserved for recovery rather than treated as absent.

This engine deliberately does not supply a permissive network callback. The
[epoch policy primitive](EPOCH_POLICY.md) now has own-loopback kernel evidence;
the real adapter must release **new** guarded traffic while retaining denial for
previously closed labelled flows. Simply deleting the existing connmark DROP
rules would reopen those old flows and is not a valid implementation. Policy
epoch handling, platform private filesystem, fixed service composition and
boot/recovery installation remain required before real mode switching.

## Evidence

The native probe passed **150 checks on the speaker's persistent storage and a
fortified Linux host**. It exits at all seven transaction checkpoints, verifies
that every incomplete request keeps boot/admission closed, and explicitly retries
without duplicate revision commits. It covers five callback failures, contention
with mode/start and transition leases, cancellation through the close engine,
new-boot rejection and malformed/symlink journals.

It additionally injects an I/O error at each of **19 actual fsync boundaries**,
including the final directory sync after fence unlink. Every failed attempt
stays closed and a later explicit retry succeeds. All fixtures use their own
throwaway state; no real firewall, vendor service or microphone is touched.

Storage, startup-gate, close-engine and guardian regression probes passed
27/37/65/57 checks on both systems. All fixture directories were removed. The
Python/HA suite remains **728 passing tests**; the native build matrix now has
34 targets. The previous service handoffs are separate evidence, not a composed
real-Alice return trial.

Qualified ARM SHA256:

- open transaction: `37603a04e9bf28280678d3650bb8d8e5057bd3231f7aa1e60e8dc5c44f42b6c9`
- startup gate: `c824b6bd8c621c93a2a9d12c5fb7861a483e4f9d6ac1481a94dca3ee6a3ed684`

```sh
python controller/build.py --target open-transition-probe
```

Running the native probe tests only its private synthetic transaction. It does
not switch the speaker to Alice or authorize recording audio.
