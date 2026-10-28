# Durable requests to stop vendor services

`closed_transition.h` connects durable mode intent, startup admission and a
tracked service stop. It is a development engine with compiled-in policy/stop
callbacks. The bounded quasar trial exercises one managed service group. It is
not an installed Lisa-mode policy and does not assert whole-device isolation.

## Ordering and interruption recovery

1. Serialize requests with private `transition.lock` and check the expected
   intent revision. A stale new request has no side effects.
2. Atomically write and fsync `closed.request` and its containing directory.
   Its presence blocks new Alice admission, including already admitted starts
   that have not received permission to exec. Boot choice becomes Paused even
   while the old mode record still says Alice.
3. Establish and verify selective network denial for the declared service scope.
4. Revoke and fsync the runtime Alice permit.
5. Commit Lisa/Paused intent with revision comparison and atomic storage.
6. Stop the managed actors, verify their absence and recheck network denial.
7. Persist completion. The close fence remains in place.

The canonical record is `LISA_CLOSE_V1 BASE_REVISION lisa|paused PHASE` followed
by one newline. Phases are `requested`, `network_denied`, `permit_revoked`,
`intent_committed`, `actors_stopped` and `complete`. Files must be private,
single-link regular files in owner-controlled directories. Unknown/corrupt
records remain available for recovery and never authorize Alice.

A resumed request reestablishes policy and verifies actors even after a stored
`complete` phase. It does not assume that a firewall survived reboot. The same
request commits the intent revision once; an unexpected revision is a conflict.
Failure retains the fence and attempts denial, permit revocation and stop
without reopening anything. Busy startup leases cannot prevent the durable
fence from being written. The caller retries a busy transaction within a bound.

For an existing service the pending fence alone does not trigger shutdown:
the executor must first establish the network barrier and revoke its permit.
This avoids relying on process shutdown before traffic is denied. New starts
are denied immediately. This ordering is separate from TCP teardown/queued-packet
containment, which still needs the old-flow mechanisms described below.

Neither a raw Alice mode write nor a fresh permit removes the fence. Returning
to Alice needs a future explicit controller operation that validates all
profiles and prerequisites under the same transition serialization. There is
no automatic Alice rollback or open operation in this engine.

## Scoped device trial

`qualify_guardian_startup --exercise-closed-policy` temporarily installs a unique
OUTPUT chain in IPv4 and IPv6, targeting only the trial vendor GID. The native
backend checks the exact owner/DROP rule and unconditional first OUTPUT jump in
both families. It rejects a deliberately incomplete IPv4-only setup. It uses
the firmware-compatible `iptables -S` form and the correct IPv6 multicall name.

Unrelated administrative-identity TCP controls exchange a token over their own
ephemeral IPv4/IPv6 loopback sockets while the filter is installed. The backend
then completes the private Paused request, stops the tracked workers, reconciles
the journal and refuses another start even after a synthetic legacy Alice write.
No external control endpoint or firmware `ping6` utility is required.

The lab `deny` callback **verifies a preinstalled test policy**; it does not yet
install production rules. Its completion means only that this declared group
policy and actor stop were verified. All result events retain
`isolation_verified: false`.

The administrative trial restores the original stock state and deletes only
its own chains/jumps, with an independent bounded watchdog. It compares firewall
rules, launcher/configuration/boot identity and ordinary worker identities
before/after. Its private fixture is never a production mode record. Reports
and real configuration backups stay in ignored `build/`.
The original stock launcher's restart limiter can delay ordinary workers for
600 seconds after repeated trials. The final recovery observer waits up to
625 seconds without changing that configuration or restarting the launcher.

```sh
python controller/build.py --target station-service
python controller/build.py --target closed-transition-probe
python -m controller.qualify_guardian_startup YOUR_SPEAKER_SSH_ALIAS \
  --ssh-config YOUR_SSH_CONFIG --allow-temporary-stock-restart \
  --exercise-closed-policy
```

The transaction suite passed **65 checks on actual writable speaker storage**
and on a separate Linux host. It interrupts the coordinator after each durable
phase, retries without double commits, tests policy/stop/verification failures,
busy admission, stale requests, conflicting revisions and corrupt fences.
Admission and guardian suites add **34** and **54** checks respectively, including
a close request during child preparation and unrelated-process survival.

## Work before deployment

The quasar group filter does not cover old untagged sockets, kernel orphan
replies, independent diagnostics, local root relays or telemetry queues.
[Durable exact-flow quarantine](FLOW_RECOVERY.md) now has a separate integrated
transaction trial on owned sockets, including a fresh coordinator after a crash.
Those callbacks are not yet composed with the real quasar/vendor inventory.
Group-only completion must never be promoted to whole-vendor privacy proof.

Production work still includes policy installation/ownership, all vendor roles,
independent DNS/time profiles, relay/queue handling, boot enforcement before any
vendor startup, explicit Alice return and verified actual-mode reporting.
The device keeps internet access for unrelated applications. No router, shared
DHCP or shared DNS changes are involved. The HA selector remains unavailable
until those requirements are met.
