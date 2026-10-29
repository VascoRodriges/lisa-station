# Shared close for guarded roles

The laboratory backend now has fixed `check-roles-policy` and `close-roles`
operations for quasar, diagnostics, collector and telemetry. This replaces
single-role reasoning for a shared permit: **all four group barriers must be
verified before normal permit revocation and actor shutdown**. These commands
are not exposed by the released HA diagnostic key or installed into boot.

The verifier requires exactly the four ordered group DROP rules in both IPv4
and IPv6, with the owned chain first in OUTPUT. A missing role, missing family,
extra exception or unexpected rule prevents success. There is no UID-0-wide or
device-wide internet ban. Single-role verification retains its original exact
one-group contract; it cannot certify a four-group chain.

The durable executor creates the startup fence, verifies the complete declared
barrier, revokes the common permit, commits closed intent and stops each fixed
role through its authenticated guardian. Every role is attempted even if one
fails. Final verification rechecks the full barrier and absence of actors in
all four groups. Failures retain the fence and perform best-effort denial and
stop; they never publish an Alice permit as rollback. Recovery reestablishes
the scope rather than trusting an earlier completed checkpoint.

## Qualification

The synthetic storage suite passed **85 checks on the speaker and a fortified
Linux host**: omission of each group's barrier, failure of each role's stop or
verification, interruption at all six durable checkpoints, complete retry,
permit/fence ordering, all-role callback coverage and invalid rule specifications.
These fixtures do not change real services or firewall rules.

A real-code trial passed **22 protocol events** with **two live guarded epochs**:
collector and telemetry. Their originals and launcher were frozen, not replaced.
Three observations saw both private queues and identities; a missing telemetry
IPv6 rule was rejected; the four-group barrier passed with unrelated root
loopback controls working; shared close/reconciliation stopped both epochs;
rewritten Alice intent/permit could not restart either role. Both original
processes and launcher resumed with unchanged boot/configuration identities,
private epochs disappeared and original firewall rules were restored.

The other two guarded groups were empty in this trial. Original platform,
media and diagnostics remained ordinary stock services outside the fixture.
This is deliberately **not a full migration or whole-device no-Yandex test**.
The report declares `closed_scope: guarded_roles` and retains
`isolation_verified: false`. SDK startup can delay readiness; the trial waits
with a bound and fails/restores if readiness is not established.
The paired lab profile directs the collector's SDK to the private telemetry
ports and observes that receiver before starting its client. Its cold SQLite
initialization has a bounded 25-second wait; private queue/holder conditions
are unchanged. The original stock receiver remains frozen throughout.

```sh
python controller/build.py --target composite-roles-probe
python controller/build.py --target station-service
python -m controller.qualify_roles YOUR_SPEAKER_SSH_ALIAS \
  --ssh-config YOUR_SSH_CONFIG --allow-temporary-epoch-freeze
```

An independent watchdog and identity-checked restoration script cover both
epochs and all owned rules. This lab rollback resumes Alice explicitly;
installed Lisa failures must retain closed vendor policy instead. Real reports
and generated profiles stay in ignored `build/` or the root-only laboratory.
The fault test killed its own trial shell after both guarded starts, during
initialization. Without an exit trap, the watchdog restored the same original
processes, boot/configuration and firewall in about 70 seconds from test start.

Remaining work includes migration of every sender into guarded startup,
receiver/activation policy, retained IPC objects, queued packets, UDP and old
flows, independent DNS/time installation and boot enforcement. The
[IPC graph](IPC_PEERS.md) supplies peer evidence, not a receiver-data purge;
[SDK batch materialization](TELEMETRY_EPOCH.md) remains unobserved. This shared
actor transaction cannot certify those missing scopes.
