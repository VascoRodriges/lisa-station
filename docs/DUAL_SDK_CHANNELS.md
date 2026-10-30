# Two independently admitted SDK bus channels

The explicit `--run-sdk-two` diagnostic now supplies two independent one-shot
channels. Both the own control and proprietary SDK authenticate two connections
through separate sealed relays. Both relays reach client EOF, both SDK names
retire, and the private bus/view are destroyed. The one-channel EMFILE refusal
disappears. The SDK next receives AccessDenied while requesting a service name;
the requested name has not yet been audited or approved.

This qualifies a private IPC composition, not a usable Alice mode, permanent
switch or complete vendor isolation. It retains the synthetic offline adapter,
fake identity storage and existing method/name permissions. No real Bluetooth,
microphone, host bus, raw socket or new internet access is exposed.
The private UID0 policy is still shared; this is not per-role authorization.

```sh
python -m controller.qualify_sdk_bus SPEAKER_ALIAS --ssh-config PRIVATE_SSH_CONFIG --run-sdk-bus-diagnostic --dual-channels
```

The option is exclusive with other service fixtures. Earlier modes keep their
one-source admission and evidence protocol.

## Fixed capacity and independent ownership

The coordinator first runs the 29 policy controls in a separate private epoch.
Its provider and observer close, a fresh query contains only the observer, then
the observer closes and the daemon/view are reaped before SDK admission begins.
Fresh own-control and actual-SDK epochs each use exactly four accepts: provider,
observer and two SDK streams. The existing daemon/factory four-accept bounds are
not raised. The client factory receives exactly two distinct source objects.

Each stream has a separate backend connection, relay process, immutable view,
report and PID/start-tick stamp. The watchdog and fixed empty-underlay cleanup
cover both relay paths independently. No retired endpoint or duplicated queue
stands in for a fresh stream, and no SDK-family wait consumes relay exit status.

SDK admission requires null stdin/stdout, private stderr and both exact approved
socket objects: five descriptors before and at exec. Both sources are checked
for distinct identity and the approved parent peer; the factory revalidates them
after exec. The one-source modes still require four descriptors. Independent
kernel endpoint and ancillary denial remains unchanged.

Before the own executable runs, four negative attestation controls use the
actual stopped guarded child's descriptor table: wrong source count, duplicated
declared FD, wrong second object and missing declared second FD are rejected.
A fifth check restores and accepts the correct inventory. These are mismatched
attestation tests, not injected extra descriptors. Actual SDK exec occurs only
after the own exchange, marker and complete nine-thread drain succeed.

## Observation and retirement

Both admitted source inodes can trigger bounded metadata queries. The observer
uses the qualified [two-name ledger](SDK_NAME_LEDGER.md), recording names of the
exclusive SDK group, including a connection with no rules yet. It does not infer
a socket-to-name mapping from the cached creator PID. Rule peaks are independent,
missing names retire permanently, and a third name cannot reuse a retired slot.
Private evidence uses a versioned two-name format; public reports carry counts
and lifecycle flags, never the rule bodies.

Each source has at most 32 candidate read events. The shared limits remain 40
queries, a one-second query budget and 50 ms per whole exchange. Provider limits,
the six-second trace and three-second drain bounds are unchanged. After SDK and
both relays drain, the provider closes; a fresh snapshot must contain only the
unchanged observer. Both ledger names become inactive, the group finishes and
the observer closes before daemon teardown.

The first own attempt correctly failed its EOF requirement: opening the second
connection queued a driver notification on the first subscribed stream. Closing
that stream unread caused a reset. The own fixture now validates the second
connection's creation and disappearance notifications, then uses a driver reply
barrier before closing the first. Neither EOF nor cleanup requirements were
weakened to accept the failed attempt.

## Qualified evidence

The strict sixteen-event evaluator requires the separate policy-epoch closure,
both source admissions, five own attestation controls, independent authentication
and terminal reports for all four relays, and both finished group ledgers. Each
relay passes the complete existing typed boundary/traffic checks. Single-source
or incomplete evidence cannot qualify this mode.

The device trial passes all sixteen events and both clean EOFs for each client.
The same final binary retains the one-channel synthetic-adapter regression.
Stock PID/configuration/boot identities, firewall and unrelated network controls
are preserved; all owned processes and private underlays close. Ruff/public-source
checks and **1661 Python/HA tests** pass. The ledger retains its 89 fortified and
sanitizer-qualified synthetic checks; the factory retains its 125 host/device
checks. The ARM matrix stays at 45 targets.

Qualified private-bus probe SHA256:
`63a2726224d82e516f0ea7450026e68eac8d11ac30ec0edbf5f122ea763f4c82`.
Client/server libraries remain the previously qualified diagnostic versions.

Next is read-only attribution of the denied service-name request before any
ownership permission changes. Normal cloud-Alice admission, real service/hardware
and retained-data lifecycles, permanent supervision/boot/mode control, speech
deployment and HA migration remain unfinished. Ordinary Alice and the second
station are unchanged.
