# Live private subscription metadata observer

The explicit SDK diagnostic now captures its registered match rules through
the private daemon's GetAllMatchRules API. It first proves the observer against
an own executable registering two known rules, then samples the proprietary SDK.
The actual set targets BlueZ ObjectManager InterfacesAdded/InterfacesRemoved watchers. This
observes a subscription request; it does not expose Bluetooth services or grant
permission to forward the host bus. The [bounded set audit](PRIVATE_MATCH_SET.md)
allows at most four lab rules; the default profile retains its one-rule limit.

## Ownership and bounded observation

The common parent owns a separate observer connection. The own policy fixture
hands off its third connection, keeping the daemon's four-accept lifetime budget;
the actual SDK epoch uses only an observer and SDK connection. The observer is
closed in the SDK child before sealing. The independent pre-exec/exec census
still requires exactly four SDK descriptors and no observer capability.

A tracer callback sees only the FD number and positive readv result. Parent-side
FD-object metadata must match the admitted SDK byte stream before a query is
made. No SDK read/write, authentication, audio or stack buffer is inspected. The
observer uses its own framed metadata API, checks the driver sender/signature,
and uses the [bounded decoder](PRIVATE_MATCH_SNAPSHOT.md). Its own unique name is
excluded from the SDK snapshot.

Queries use nonblocking I/O with one fixed 50 ms deadline per whole exchange,
at most 32 candidate read events, at most 40 total queries and a one-second query
budget. Reaching the four-rule cap stops further sampling; earlier snapshots
must be retained in each later set. Existing authentication and
SDK tracing deadlines are not extended or reset by this work.

Both explicit lab profiles allow only GetAllMatchRules on the Stats interface;
the default profile denies it. The SDK shares the lab's root credential and can
also query this private metadata. This is not an observer-only ACL or complete
role isolation. The private bus contains only own synthetic fixtures, an observer
and the SDK with synthetic identity storage; host bus and real accounts remain
absent. No production profile gains Stats access.

## Capture and teardown evidence

The own executable registers two fixed synthetic rules. Their exact unordered set
must match before the actual SDK epoch is allowed. Captured SDK metadata is saved
only in a mode-0600 file under the private nonce and copied into ignored build
evidence. Public reports contain counters and verification flags, not rule bodies.

After the SDK and relay have been drained, a fresh Stats query must show that the
SDK's unique name and subscriptions are gone while the observer's known state is
unchanged. The observer then closes, with EBADF confirmation, before the daemon
is reaped and the private filesystem released. This qualifies private-bus cleanup;
it does not establish vendor telemetry queue purging or permanent mode switching.

Policy evidence now has 26 checks: quota controls, admission/handoff and actual observer closure.
Both observer events, own-rule verification, SDK-state removal and descriptor
closure are mandatory in the strict eleven-event evaluator. The default-profile
regression passes 148 checks, including a real GetAllMatchRules denial through
the proper Stats interface. The metadata decoder passes 1530 synthetic host
checks and sanitizer qualification. Ruff/public-source validation and 1520
Python/HA tests pass; the ARM build matrix remains at 45 targets.

Qualified private-bus probe SHA256:
`5aae2d77de2c0cfbf0dabe5aba4e1a8c3d7bd19048f232e9d99020501e053d5b`.
Client/server bindings are unchanged. Full subscription/service compatibility,
normal cloud-Alice policy and permanent boot/mode/voice/HA work remain unfinished.
