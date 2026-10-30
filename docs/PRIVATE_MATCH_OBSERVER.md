# Live private subscription metadata observer

The explicit SDK diagnostic now captures its first registered match rule through
the private daemon's GetAllMatchRules API. It first proves the observer against
an own executable registering a known rule, then samples the proprietary SDK.
The actual rule targets a BlueZ ObjectManager InterfacesAdded watcher. This
observes a subscription request; it does not expose Bluetooth services or grant
permission to forward the host bus. The one-rule quota remains unchanged.

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
budget. Successful capture stops further sampling. Existing authentication and
SDK tracing deadlines are not extended or reset by this work.

Both explicit lab profiles allow only GetAllMatchRules on the Stats interface;
the default profile denies it. The SDK shares the lab's root credential and can
also query this private metadata. This is not an observer-only ACL or complete
role isolation. The private bus contains only own synthetic fixtures, an observer
and the SDK with synthetic identity storage; host bus and real accounts remain
absent. No production profile gains Stats access.

## Capture and teardown evidence

The own executable registers the fixed `type='signal'` rule. Its exact snapshot
must match before the actual SDK epoch is allowed. Captured SDK metadata is saved
only in a mode-0600 file under the private nonce and copied into ignored build
evidence. Public reports contain counters and verification flags, not rule bodies.

After the SDK and relay have been drained, a fresh Stats query must show that the
SDK's unique name and subscriptions are gone while the observer's known state is
unchanged. The observer then closes, with EBADF confirmation, before the daemon
is reaped and the private filesystem released. This qualifies private-bus cleanup;
it does not establish vendor telemetry queue purging or permanent mode switching.

Policy evidence now has 23 checks: admission/handoff plus actual observer closure.
Both observer events, own-rule verification, SDK-state removal and descriptor
closure are mandatory in the strict eleven-event evaluator. The default-profile
regression passes 148 checks, including a real GetAllMatchRules denial through
the proper Stats interface. The metadata decoder retains its 507 synthetic host
checks and sanitizer qualification. Ruff/public-source validation and 1505
Python/HA tests pass; the ARM build matrix remains at 45 targets.

Qualified private-bus probe SHA256:
`caf2ea1cfb12a4317c7090cab83d11e94c43f9e1911d38cebafb76d9e3b3cded`.
Client/server bindings are unchanged. Full subscription/service compatibility,
normal cloud-Alice policy and permanent boot/mode/voice/HA work remain unfinished.
