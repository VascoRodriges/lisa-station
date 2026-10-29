# A failed denial must not trigger early teardown

The open/close engines' safety paths now require a successful denial callback
before revoking the running vendor permit or calling actor teardown. This ordering
also applies after a partial opening release. Permit revocation itself can make
guardians terminate their actors; guarding only the explicit stop callback would
still allow premature socket resets or queued traffic.

When both denial attempts fail, the durable transaction fence remains and denies
new starts and boot admission. The previous running permit is retained until a
primary retry or the independently reserved emergency barrier can establish
denial. The request remains failed/incomplete. A fence alone is not closed packet
policy and must not be presented as a successful Lisa/Paused transition.

If the first denial fails but the safety retry succeeds, that verified barrier
precedes revocation and teardown. A later explicit transaction retry keeps the
original revision checks and does not duplicate the intent commit.

## Evidence

The native probes passed on persistent speaker storage and a fortified Linux
host:

- **112 close checks**, including permanent and transient denial failure;
- **164 open checks**, including partial release followed by failed re-denial;
- **85 four-role checks**, including each missing service-group barrier.

The partial-release fixture verifies that a matching running permit remains valid
while new admission and boot are fenced. Teardown does not run until a later
denial succeeds. Four-role fixtures retain every live synthetic actor if any group
barrier is missing; once the barrier is restored, the close finishes normally.
Stop callbacks now assert successful denial rather than merely counting a denial
attempt. These assertions would reject the earlier safety behavior.

Ruff, the public-source check and **1040 Python/HA tests** passed. This is native
transaction/callback evidence; these fixtures do not change real firewall rules,
stop vendor processes or capture audio. It is separate from the earlier kernel
emergency-restart trial.

Qualified ARM SHA256:

- close: `aaf552f98332537502a73d4335a4a1e6b96cb418fd633c5d9a21c3ebc6dde5bc`
- open: `03c8de42ece12bfe12614522f7c92d0b5e21e59441d91c34d17d5b810888d9b8`
- four-role: `9bdcc6664ec45857ba56ecf755ded5a50627a8603ea32eb176a4bbcd2e4514ca`

The permanent supervisor still needs to route every journal fault through its
cached emergency barrier and report incomplete scope closure honestly. Production
service/boot installation and full privacy acceptance remain unfinished.
