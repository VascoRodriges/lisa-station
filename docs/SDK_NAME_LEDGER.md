# Two-name SDK group ledger

`sdk_name_ledger.h` qualifies the pure metadata bookkeeping needed for two
independent SDK streams. The subsequent [two-channel diagnostic](DUAL_SDK_CHANNELS.md)
now calls it within explicit source/relay admission. The ledger itself admits
no channel and grants no runtime permission.

A bus unique name identifies a connection, while the current cached kernel peer
identifies the common creator. The ledger therefore tracks names belonging to
the preadmitted SDK **group**. It deliberately provides no socket-slot-to-name
mapping, peer authentication or production role authorization. Before using it,
the caller must prove exclusive ownership of both source objects, their sealed
relays and the private bus, validate fresh driver replies, and retain immutable
observer/provider baselines from admission.

The input is the bounded decoder's structured Stats snapshot, not arbitrary wire
data. Names, rule bounds, UTF-8, duplicate keys and aggregate counts are checked
again. Observer and provider entries must remain unchanged and separate from SDK
names. Up to two distinct SDK names may appear over the whole epoch, including
connections with no match rules yet. A disappearing name retires permanently:
its later reappearance is refused, and a third name cannot reuse a retired slot.

Each name retains its own peak rules. Later observations must contain its prior
rule multiset, irrespective of order; duplicate serialized rules retain their
multiplicity. Existing four-client and four-rule limits are unchanged. Final
retirement requires a fresh snapshot containing only the unchanged observer
after SDK and provider closure. Both names remain recorded, active membership
becomes empty, and further observation is refused. Repeating that verified final
snapshot is idempotent.

Failure leaves the ledger unchanged for inspection. The caller must stop the
epoch on failure and must never treat the retained previous snapshot as fresh
evidence or permission to continue. Active-name lookup is bookkeeping only.
The API requires valid, distinct C objects and one serial trusted parent; it
performs no I/O, allocation, channel closure or persistent mode-state mutation.

The synthetic fixture passes **89 checks** on Windows/Zig and fortified GCC,
also under ASan/UBSan. It covers all 24 connection-entry orders and all 24
four-rule orders, zero-rule discovery, multiset preservation, retirement and
reappearance, third-name rejection, final closure, malformed/corrupt inputs and
unchanged state on failure. Each malformed snapshot starts from an independently
accepted valid baseline. CI runs the host fixture; it also compiles for ARM.
The existing 45-target device matrix and 1614 Python/HA tests are unchanged.

The explicit two-channel lab now composes descriptor admission, independent relay
roots/stamps, separate policy/SDK epochs and callback/retirement verification.
Other modes retain one source. Production switching, real Bluetooth operation,
host-bus access and microphone access remain outside this component.
