# Bounded byte-only authentication gate

The explicit C state machine accepts a narrow EXTERNAL/UID0 authentication
sequence, obtains OK from the admitted private daemon, answers UNIX_FD negotiation
with ERROR locally and forwards BEGIN once. It then passes opaque binary bytes.
It creates no sockets, fabricates no OS credentials and changes no kernel policy.
Endpoint/peer admission and ancillary syscall denial remain independent.

The gate is qualified with a real private daemon through the
[bounded relay actor](BUS_BYTE_RELAY.md). It is not a permanent service or an SDK
connection.

## Contract

Input can be split across calls. One AUTH discovery and one EXTERNAL attempt are
allowed, with the expected UID0 encoding and optional DATA challenge. Other
mechanisms, identities, unexpected replies and repeated negotiation fail closed.
A backend OK must contain a valid generated identifier and must precede BEGIN.
The gate never creates OK itself or forwards NEGOTIATE_UNIX_FD to the backend.
Pipelined AUTH/negotiation/BEGIN waits for that real reply; binary bytes following
BEGIN preserve their order, including embedded NULs.

ASCII authentication lines are limited to 128 bytes, pending input to 2 KiB per
direction and total parsed handshake bytes to 2 KiB. A fixed three-second deadline
starts at initialization and is not extended by received bytes. The owner calls
the monotonic tick while waiting, including when no data arrives; the pure state
machine does not interrupt a caller's blocking I/O.

Output buffers hold at most 8 KiB per direction. A blocked feed consumes no input
or state; the caller retains that input, drains output and retries. Output consume
acknowledges only the prefix actually written, supporting short writes and
backpressure. A failure/close clears the gate's pending storage. The owner must
close both endpoints and destroy all other references on EOF/error; this API does
not own descriptors or implement a poll loop.

Callers provide valid C buffers, initialized private state and serialized access.
After BEGIN, bytes are opaque: the gate does not authorize D-Bus binary methods,
detect an ASCII command embedded in binary traffic or implement FD transport.
The backend policy and kernel guards continue to enforce their own restrictions.

## Evidence

The synthetic native self-test passed **26657 checks** on Windows/Zig and fortified
Linux/GCC. It tests every two-piece split of the fixture's pipelined client
handshake and real-shaped server reply, split output consumption, embedded binary
tails, discovery/challenge, malformed replies/identities/commands, deadline and
clock reversal, overlong input, invalid API arguments and transactional output
backpressure. It verifies pending storage clearing after failure/close.

The updated [private-bus diagnostic](PRIVATE_BUS_DIAGNOSTIC.md) passed **146 speaker
checks** with two separate sealed relay actors. An own client pipelines a request
on an actual socket and receives the daemon OK plus local negotiation ERROR.
Hello/GetId and forbidden-method replies traverse the relay. A raw control
connection still obtains AGREE_UNIX_FD from the unchanged daemon. Both EOF
origins are checked, all owned actors reaped and references closed between epochs.
No SDK, microphone, account or host bus is connected.

Ruff, public-source validation and **1398 Python/HA tests** pass. CI builds 45
native targets and repeats the fortified gate and relay self-tests. The exhaustive
split-test count above is host evidence; the actual ARM relay uses the same gate.

## Next composition

The separate relay actor now supplies bounded poll I/O and descriptor ownership
for the diagnostic. The [own-client sibling and binding](PRIVATE_CLIENT_BINDING.md) are now qualified;
actual SDK compatibility, full receiver/holder lifecycle and production
supervision remain required before product use.
Actual SDK authentication variants, service schemas, private client binding,
identity/hardware/time compatibility and production boot/mode/voice integration
remain unfinished. This component does not install permanent mode switching.
