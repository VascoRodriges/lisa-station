# Per-thread MSG_NOSIGNAL compatibility

The client factory now uses `unix_byte_signal.h` for admitted sendmsg calls that
request MSG_NOSIGNAL. The original byte adapter remains unchanged. Raw socket,
bind, connect and ancillary syscalls remain blocked independently.

The SDK installs its own SIGPIPE handler. The original adapter refused this
combination because writev cannot directly implement MSG_NOSIGNAL. The new wrapper
blocks SIGPIPE only in the sending thread, snapshots pending SIGPIPE, performs
the existing validated byte write, consumes a newly generated SIGPIPE only after
EPIPE when none was pending before, then restores the original thread mask and
write errno. A previously pending signal is preserved. The process handler is
neither replaced nor suppressed globally. Unexpected drain/mask-restore failures
terminate the prepared worker instead of continuing with an unknown signal state.

This contract assumes a trusted caller synchronizing descriptor lifetimes and
not concurrently injecting unrelated SIGPIPE into the sending thread. It does
not claim signal provenance under hostile asynchronous signal injection. Calls
without MSG_NOSIGNAL retain the original adapter behavior. No transport fallback,
new destination or FD/credential passing is introduced.

The dynamic-loader fixture checks successful sends with a custom handler, EPIPE
with custom/default handlers, preservation of a prior pending signal, restoration
of the complete thread mask and retention of the process handler. A deliberate
SIGPIPE after the call still invokes that handler. Two simultaneous sender threads
also preserve their own masks under a default process handler. Existing endpoint,
ancillary, logical-bind and one-shot lifetime controls continue to pass.

Seven cases pass **122 native checks** on the fortified host and speaker: 44 in
the parent, 66 in the ordinary actor and 12 in the threaded actor. Five malformed
admission cases still terminate before client code. Ruff and 1475 Python/HA tests
pass; there are 45 native targets.

The actual audio-free SDK diagnostic passes its former message-send refusal.
The subsequent [EXTERNAL challenge update](BUS_AUTH_GATE.md)
now authenticates the SDK. A later [subscription lab profile](PRIVATE_BUS_SUBSCRIPTIONS.md)
allows its first AddMatch while retaining driver-only reception and a one-rule quota.
Usable Alice functionality remains unverified. All
SDK threads and sibling actors are drained; stock processes/configuration,
firewall and unrelated network controls remain intact. No audio or host bus is
opened and permanent mode switching is not installed by this component.
