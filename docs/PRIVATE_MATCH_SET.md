# Bounded SDK subscription-set audit

The audio-free SDK lab now captures a set of up to four match rules from the
private daemon. The actual SDK registers two standard BlueZ ObjectManager
watchers, InterfacesAdded and InterfacesRemoved, then stops because org.bluez
is absent. This identifies the next service dependency; it does not provide
Bluetooth, approve host-bus forwarding or establish SDK functionality.

Only the two explicit lab profiles have a four-rule quota. The default private
bus retains its one-rule quota and denies AddMatch and Stats. Reception remains
driver-only, ownership/activation/monitoring/removal remain denied, and no new
service or hardware capability is granted. Private lab Stats still shares UID0
with the SDK, so this is not an observer-only ACL or production role policy.

The parent now retains the peak registered set instead of stopping at its first
rule. Subsequent snapshots must retain the same unique connection name and all
previously captured rules; rule ordering is immaterial. Sampling still stops at
four rules or the existing bounded tracer exit. The 32-candidate, 40-query,
50 ms whole-exchange and one-second total query bounds are unchanged. A peak
is an observed set, not a claim that all SDK requirements have been enumerated.

Before the proprietary SDK is admitted, an own executable registers two known
distinct rules. Both must appear in the independent observer snapshot. Separate
daemon controls verify four successful registrations and rejection of a fifth,
driver signals, blocked peer reception and the same eight forbidden method
calls. Together with admission/handoff and actual observer closure, this is a
26-check policy/lifecycle proof.

The pure decoder has an explicit limit of one through four rules per connection;
its default entry point still accepts only one. The 4 KiB body, four-client,
63-byte unique-name and 1024-byte per-rule bounds remain. Over-limit arrays,
invalid limits, malformed later elements and truncation clear the output. Empty
strings remain distinct from absent rules. **1530 synthetic checks** pass on
Windows/Zig and fortified GCC, also under ASan/UBSan. The fixture includes an
independent two-rule wire image and validates every rule-limit combination.

Private evidence uses a versioned, length-delimited set file, created mode 0600
under the owned nonce and copied only into ignored build storage. Public event
records add a typed `peak_rules` count: exactly two for the own positive, one
through four for the SDK. After SDK/relay drain, Stats must again contain only
the unchanged observer, then its descriptor must close before daemon teardown.
SDK read/write, authentication and audio buffers are never inspected.

The composed device trial captures two rules for each client and passes all
eleven strict SDK events, cleanup, unchanged stock/configuration/boot/firewall
and unrelated network controls. The default-profile regression retains 148
checks. Ruff/public-source and 1520 Python/HA tests pass; the existing 45-target
ARM matrix is unchanged. Client/server bindings are unchanged.

Qualified ARM probe SHA256:
`5aae2d77de2c0cfbf0dabe5aba4e1a8c3d7bd19048f232e9d99020501e053d5b`.

Normal cloud-Alice network admission, reviewed private service schemas, real
identity/hardware/queue lifecycles, permanent supervision/boot/mode control and
voice/HA migration remain unfinished. Ordinary Alice and the second station
are unchanged. This work does not install a permanent isolated Alice.
