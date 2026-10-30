# Bounded subscription policy for the SDK diagnostic

The explicit SDK lab profile now allows AddMatch to the private D-Bus driver.
The default own-client profile still allows only Hello/GetId. Neither profile
uses the host bus, host configuration, service activation or production state.

AddMatch accepts a standard match-rule string, validated by the real daemon.
The explicit lab profiles permit **four rules per connection** for the
[bounded subscription-set audit](PRIVATE_MATCH_SET.md); the default remains at
one and denies AddMatch. Receive policy remains limited
to the private bus driver, independently of the requested match. A later
[observer profile update](PRIVATE_MATCH_OBSERVER.md) also allows only the Stats
GetAllMatchRules metadata method in the explicit lab profiles. Ownership of
service names remains denied. In particular, RemoveMatch,
BecomeMonitor, StartServiceByName, RequestName and GetNameOwner are not enabled.
This is a lab capability for reviewing SDK requirements, not an approved
production subscription/service schema.

The coordinator checks policy before the SDK step and descriptor closure after
it, with 26 own policy/lifecycle checks against the actual private daemon. Its
fixture profile has the same receive policy and quota, plus
permission to emit exactly one synthetic canary signal. That extra send permission
is absent from the actual SDK profile, so a blocked canary tests reception rather
than the default send denial:

- A broad signal rule explicitly requesting eavesdropping and three more
  distinct rules are accepted; a fifth exceeds the four-rule quota.
- A new own publisher produces the expected driver NameOwnerChanged signal.
  Its peer broadcast is blocked, and the subscriber receives no unicast signal
  intended for the publisher. A reply on the publisher acts as an ordering barrier
  before a bounded quiet check.
- Eight forbidden calls, including monitoring, activation, ownership, rule
  removal and a mismatched interface, receive AccessDenied.
- The first two control connections close; a fresh third connection installs its
  own rule and is handed off to the metadata observer. It closes after SDK
  teardown. The bus and private filesystem are destroyed at each epoch boundary.

The fixture uses fixed synthetic strings and a bounded builder/reader for its
own messages. It does not inspect SDK read/write/authentication buffers or act
as a production D-Bus parser or forwarder. The real daemon retains binary framing,
match syntax, queue and subscription validation. The existing syscall filters,
descriptor ownership and private filesystem admission remain unchanged.

The actual SDK now registers two BlueZ ObjectManager watchers. It then stops
because org.bluez is absent. Its match bodies
are now captured privately by the observer after a known own positive control;
capture and static string candidates are not treated as runtime authorization.
Further service-schema review is needed before exposing services.

The own and SDK clients still complete real EXTERNAL authentication through the
byte-only relay. All owned actors are reaped, and stock identities/configuration,
boot identity, firewall and unrelated network controls are preserved. No audio,
real account state or host-bus traffic is exposed. This does not install a
permanent controller, mode selector or boot behavior.

The separate default-profile regression passes 148 device checks, including Stats
denial through its proper interface. The SDK evidence evaluator requires the
additional 26-control policy/lifecycle proof and both metadata-observer events,
as well as each client's private boundary, real authentication and teardown.
Missing, malformed, failed or overstated evidence is rejected.
Ruff and 1520 Python/HA tests pass; the 45-target native build matrix is unchanged.

Qualified ARM probe SHA256:
`5aae2d77de2c0cfbf0dabe5aba4e1a8c3d7bd19048f232e9d99020501e053d5b`.
The previously qualified client/server libraries are unchanged.
