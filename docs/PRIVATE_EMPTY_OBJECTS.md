# Fixed-schema empty ObjectManager codec

The next audio-free service diagnostic needs to distinguish a valid empty object
tree from an absent service. `private_empty_objects.h` now qualifies the pure
request/reply codec for that experiment. **No service is installed or enabled by
this component.** The baseline SDK diagnostic still stops because org.bluez is
absent. A separate [explicit service trial](PRIVATE_EMPTY_SERVICE.md) now uses the
codec, confirms an actual GetManagedObjects call, and reaches the missing
Adapter1 dependency.

The [ObjectManager specification](https://dbus.freedesktop.org/doc/dbus-specification.html#standard-interfaces-objectmanager)
defines GetManagedObjects without input arguments and with result signature
`a{oa{sa{sv}}}`. The synthetic reply represents an empty object tree, containing
no adapters, devices or properties. It does not implement Bluetooth or forward
the host bus.

The decoder accepts only a complete little-endian method call to org.bluez,
path `/`, interface org.freedesktop.DBus.ObjectManager, member GetManagedObjects,
with no body and an exact caller-supplied unique sender. Serial must be nonzero.
NO_AUTO_START is the only optional flag; no-reply and unknown flags are rejected.
An absent or empty signature and absent or zero UNIX_FDS field are accepted.
Wrong or duplicate header fields, wrong variant types, padding, lengths,
destination, sender, method, interface, path or trailing bytes fail closed.
The limits are 8 KiB per complete frame and 4 KiB of header fields. Failure
clears the decoded request.

Channel ownership and the sender's identity must be established separately by
the future coordinator; this codec authenticates neither. A matching request is
not production service authorization. The implementation reads only the supplied
message and never attaches to SDK memory, authentication or audio buffers.

The reply builder pins the actual request serial and unique destination, requires
a nonzero own serial and emits only the fixed empty-array body and signature.
It does not add a sender header; the private daemon must supply the real origin.
On failure the written count is zero and output bytes remain unchanged. Callers
must supply valid, distinct C objects and use only the returned byte count.

The synthetic fixture passes **2060 native checks** on Windows/Zig and fortified
Linux/GCC, also under ASan/UBSan. It checks an independently marshalled libdbus
request, every truncation, optional-field/flag combinations, all unsupported
flags, missing/duplicate/incorrect fields, mutations, maximum and unterminated
unique names and every undersized reply buffer.

A separate stdlib Python check loads the host libdbus parser and validates both
synthetic wire images, including the reply's serial, destination, signature and
empty nested array: **23 independent checks**. It opens no connection. This is a
host development check, not a firmware or integration runtime dependency. CI
runs both host checks; the fixture also compiles for ARM. Ruff/public-source
validation and the existing 1520 Python/HA tests pass. The 45-target device build
matrix is unchanged, and no unchanged speaker trial was repeated.

The separate service diagnostic now composes ownership, narrow lab policy, a
bounded parent pump and own-client/SDK exchange. This pure codec itself remains
independent of runtime I/O and grants no permissions. Permanent
mode switching, cloud-Alice policy and the remaining voice/HA roadmap remain
unfinished.
