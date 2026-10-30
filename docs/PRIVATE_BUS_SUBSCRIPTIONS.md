# Bounded subscription policy for the SDK diagnostic

The explicit SDK lab profile now allows AddMatch to the private D-Bus driver.
The default own-client profile still allows only Hello/GetId. Neither profile
uses the host bus, host configuration, service activation or production state.

AddMatch accepts a standard match-rule string, validated by the real daemon.
This profile permits **one rule per connection**. Receive policy remains limited
to the private bus driver, independently of the requested match. Other method
calls and ownership of service names remain denied. In particular, RemoveMatch,
BecomeMonitor, StartServiceByName, RequestName and GetNameOwner are not enabled.
This is a lab capability for reviewing SDK requirements, not an approved
production subscription/service schema.

Before any SDK step, the coordinator runs 22 own controls against the actual
private daemon. Its fixture profile has the same receive policy and quota, plus
permission to emit exactly one synthetic canary signal. That extra send permission
is absent from the actual SDK profile, so a blocked canary tests reception rather
than the default send denial:

- A broad signal rule explicitly requesting eavesdropping is accepted; a second
  distinct rule exceeds the one-rule quota.
- A new own publisher produces the expected driver NameOwnerChanged signal.
  Its peer broadcast is blocked, and the subscriber receives no unicast signal
  intended for the publisher. A reply on the publisher acts as an ordering barrier
  before a bounded quiet check.
- Eight forbidden calls, including monitoring, activation, ownership, rule
  removal and a mismatched interface, receive AccessDenied.
- All control connections close; a fresh connection can install its own rule.
  The bus and its private filesystem are destroyed at each epoch boundary.

The fixture uses fixed synthetic strings and a bounded builder/reader for its
own messages. It does not inspect SDK read/write/authentication buffers or act
as a production D-Bus parser or forwarder. The real daemon retains binary framing,
match syntax, queue and subscription validation. The existing syscall filters,
descriptor ownership and private filesystem admission remain unchanged.

The actual SDK now passes its first subscription registration. It then stops on
the one-rule quota while registering another signal handler. Its match bodies
have not been captured or approved; static string candidates are not treated as
runtime authorization. Further subscription auditing is needed before changing
the quota or exposing services.

The own and SDK clients still complete real EXTERNAL authentication through the
byte-only relay. All owned actors are reaped, and stock identities/configuration,
boot identity, firewall and unrelated network controls are preserved. No audio,
real account state or host-bus traffic is exposed. This does not install a
permanent controller, mode selector or boot behavior.

The separate default-profile regression retains its 146 device checks. The SDK
evidence evaluator now requires the complete additional 22-control policy proof,
as well as each client's private boundary, real authentication and teardown.
Missing, malformed, failed or overstated evidence is rejected.
Ruff and 1488 Python/HA tests pass; the 45-target native build matrix is unchanged.

Qualified ARM probe SHA256:
`cdd6d0f33bce82030d2967d8ba5439f0d0306de1f9f75b58b2367cb5ff77fcfd`.
The previously qualified client/server libraries are unchanged.
