# Bounded private error text

The audio-free dual-channel SDK diagnostic reaches a denied service-name
request. Its generic exception omits the driver's explanation. Before adding
an explicit private error-copy audit, `private_error_text.h` qualifies the
small body decoder that such an audit needs. It is not yet connected to the
bus diagnostic and grants no ownership or receive permission.

The input is an already delimited **little-endian body** and bounded signature
from a separately validated message. Only signature `s` is accepted. The body
must contain exactly one 32-bit length, at most 1024 bytes of strict UTF-8,
and one final NUL, with no trailing bytes or embedded NUL. Empty strings are
valid wire data; the caller must separately decide whether they are useful.
The decoder checks the exact body size before reading the declared length's
payload. Failure clears the whole output, including its length and padding.

The API requires valid, distinct C objects. It does not parse headers, determine
the sender or destination, authenticate a driver, correlate replies, inspect
SDK buffers, open a channel or allocate memory. Text must remain private because
it may contain device-derived identifiers. It must never become an ownership
allowlist or other authorization decision.

The synthetic native fixture passes **2106 checks** on Windows/Zig and fortified
GCC, also under ASan/UBSan. Cases cover every truncated prefix and embedded-NUL
position at the maximum size; wrong sizes, signatures and terminators; integer
limits and opposite-endian length; valid UTF-8 boundaries and malformed,
overlong, surrogate or out-of-range sequences; and complete output clearing.
CI runs the fortified fixture. ARM compilation is verified separately; no new
device build target, microphone recording or speaker trial is needed.

Next is an explicitly enabled, bounded audit of driver AccessDenied copies on
the disposable private bus, with a known denied-name control before the SDK.
The existing name denial, two-source admission and relay retirement remain.
Permanent switching and production isolation remain unfinished.
