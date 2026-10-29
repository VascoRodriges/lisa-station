# Common scoped supervisor recovery

The staged supervisor now routes damaged intent journals and broken live policy
through the same independently reserved emergency barrier. Its compiled adapters
do not need a readable mode, opening or closing record to deny the declared scope.
Corrupt journals are preserved; recovery never invents an intent revision, clears
the fault or opens Alice.

The engine takes the validated transition lease before inspecting policy. Valid
transition or epoch-reader contention causes waiting without revocation, actor
teardown or a fabricated fault. The policy adapter releases its epoch lease before
the intent executor releases/reacquires the transition lease, avoiding reversed
lock ordering. Valid interrupted transactions still use the existing close engine
and revision checks; errors are reinspected on the next tick.

The emergency adapter reports three separately verified facts: a real barrier,
revoked permit and synced fault fence. Actor teardown is not called without a
verified barrier. Scoped fault closure additionally requires all three facts,
successful teardown and an absent declared actor inventory. A missing permit,
fence alone, negative error flag or failed inventory cannot report successful
scope closure.

A fresh bounded supervisor can also start through the independent emergency
owner before attempting ordinary primary-state admission. It verifies the current
boot/namespace and actual reserved chains, then enters the same recovery loop.
Its lab restart token has a separate fixed filename; it does not delete an older
token or any persistent fence to start.

## Evidence

The **39-event speaker trial** first held the real epoch-reader lock while the
private Alice intent and old UDP flow were active. The supervisor observed that
specific contention; intent and permit were retained and no fault was created.

Under the transition lease, the fixture then corrupted the mode record and both
primary epoch records. Without a driver-issued denial, the common loop established
its independent barrier, revoked the permit and synced the fault. A fresh supervisor
started with all three primary records still corrupt and reached the same verified
scoped closure through the independent owner. No intent revision was fabricated.

The original damaged bytes and fault were preserved. Restoring only this throwaway
fixture's primary bytes still did not permit explicit opening. All **15 IPv4 UDP
checks** passed: old service flow, new sockets from all four declared groups and
a root-owned reply remained denied; unrelated controls worked. IPv4/IPv6
administrative probes also passed. Stock process identities, boot/configuration
and the full firewall snapshot were preserved/restored. No audio was captured.

The native supervisor fixture passed **45 checks** on persistent speaker storage
and a fortified Linux host. It covers each damaged mode/opening/closing record,
unsafe transition-lock metadata, an existing fault, valid contention, missing or
negative closure flags, failed stop/inventory checks, and one-time completion of
an interrupted close. Pure argument fixtures also reject oversized values before
conversion to bounded lifetime/checkpoint fields.

The existing 76 store, 33 recovery-decision, 36 emergency and 256/16 parser cases
passed. Ruff, the public-source check and **1097 Python/HA tests** passed. The
native matrix remains 36 targets; the existing coordinator target now runs five
selftest groups.

Qualified ARM SHA256:

- composed supervisor: `75c48a26a2a780a72a59053182aa5c3f2b7205549c36cd3b141263acd585dfc7`
- socket fixture: `38c84371b0e5f745db457c8e097464705e494a0072abbf13e15fec618644f284`

```sh
python -m controller.qualify_supervisor YOUR_SPEAKER_SSH_ALIAS \
  --ssh-config YOUR_SSH_CONFIG --run-private-supervisor-trial
```

The earlier 35-event capture qualified the running loop before adding the fresh
supervisor startup path. The final 39-event trial includes that additional path;
it is not a new TCP/IPv6/mapped fault-flow matrix. Separate opening/closing journal
corruption paths have native fixture coverage, not separate kernel fault trials.

## Deployment boundary

These are bounded SSH-parented laboratory supervisors with private synthetic
intent records. Their actor callbacks inspect the declared tagged scope; they do
not stop or count ordinary unwrapped stock actors as isolated. Working controls
and scoped fault closure are not complete device isolation.

Permanent supervision, production actor/FD inventory, platform filesystem/IPC
boundaries, queued-data lifecycle, explicit repair, installation and physical
cold-boot acceptance remain unfinished. The diagnostic HA integration still has
no production mode selector. A supervisor restart or a failure of HA/NAS never
authorizes returning to Alice.
