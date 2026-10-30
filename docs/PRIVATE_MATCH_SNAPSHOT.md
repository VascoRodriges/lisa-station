# Bounded private match-rule metadata decoder

`private_match_snapshot.h` decodes only the little-endian `a{sas}` body returned
by the private daemon's GetAllMatchRules API. The firmware daemon's immutable
interface strings and the [matching 1.12.16 dispatcher](https://github.com/d-bus/dbus/blob/dbus-1.12.16/bus/driver.c)
confirm that signature. This component does not call the API, grant permission
to call it, attach to SDK memory or change the current one-rule quota.

The caller supplies distinct valid input/output buffers and separately validates
the message sender, signature and frame boundaries. The decoder accepts at most
4 KiB of body, four distinct unique connection names and one rule per connection.
Names fit in 63 bytes and rules in 1024 bytes, with strict UTF-8 and NUL validation.
An empty rule string is distinguishable from an empty array of rules.

Array byte lengths, dictionary/string alignment, zero padding, duplicate keys,
trailing bytes and all configured bounds are checked before copying. There is no
recursion, general variant handling or production D-Bus forwarding. Failure
clears the output, preventing a prior snapshot from being mistaken for current
evidence. Successful metadata is not interpreted as authorization for a service
or subscription.

The synthetic fixture passes **507 checks** on Windows/Zig and fortified
Linux/GCC, also under ASan/UBSan. It uses an independent fixed wire image, every
prefix truncation of valid multi-client replies, empty arrays/rules, valid UTF-8,
malformed Unicode, duplicate/invalid keys, oversize/extra rules, mutated lengths,
padding and trailing data. The same fixture compiles for the ARM ABI; no device
test or unchanged SDK diagnostic was repeated for this pure component.

Ruff/public-source checks and 1505 Python/HA tests pass. CI runs the host fixture;
the existing 45-target ARM build matrix is unchanged. The subsequent
[parent observer](PRIVATE_MATCH_OBSERVER.md) now captures the actual first SDK
rule through the private daemon API, after a known own positive control, and
verifies descriptor and subscription-state teardown. SDK read/write,
authentication and audio buffers remain uninspected.
