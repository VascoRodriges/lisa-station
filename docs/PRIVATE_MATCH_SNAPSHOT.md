# Bounded private match-rule metadata decoder

`private_match_snapshot.h` decodes only the little-endian `a{sas}` body returned
by the private daemon's GetAllMatchRules API. The firmware daemon's immutable
interface strings and the [matching 1.12.16 dispatcher](https://github.com/d-bus/dbus/blob/dbus-1.12.16/bus/driver.c)
confirm that signature. This component does not call the API, grant permission
to call it or attach to SDK memory. Its default entry point retains a one-rule
limit; the explicit bounded audit accepts a caller-selected limit of one to four.

The caller supplies distinct valid input/output buffers and separately validates
the message sender, signature and frame boundaries. The decoder accepts at most
4 KiB of body and four distinct unique connection names. The explicit limit is
checked independently for each connection; invalid or exceeded limits fail.
Names fit in 63 bytes and rules in 1024 bytes, with strict UTF-8 and NUL validation.
An empty rule string is distinguishable from an empty array of rules.

Array byte lengths, dictionary/string alignment, zero padding, duplicate keys,
trailing bytes and all configured bounds are checked before copying. There is no
recursion, general variant handling or production D-Bus forwarding. Failure
clears the output, preventing a prior snapshot from being mistaken for current
evidence. Successful metadata is not interpreted as authorization for a service
or subscription.

The synthetic fixture passes **1530 checks** on Windows/Zig and fortified
Linux/GCC, also under ASan/UBSan. It uses an independent fixed wire image, every
prefix truncation of valid multi-client replies, empty arrays/rules, valid UTF-8,
malformed Unicode, duplicate/invalid keys, oversize/extra rules, mutated lengths,
padding and trailing data. It also checks an independent two-rule wire image,
all one-to-four limit combinations, later malformed elements and a fifth-rule
rejection. The fixture also compiles for the ARM ABI.

Ruff/public-source checks and 1520 Python/HA tests pass. CI runs the host fixture;
the existing 45-target ARM build matrix is unchanged. The subsequent
[parent observer](PRIVATE_MATCH_OBSERVER.md) now captures a
[bounded SDK set](PRIVATE_MATCH_SET.md) through the private daemon API, after a
known own positive control, and
verifies descriptor and subscription-state teardown. SDK read/write,
authentication and audio buffers remain uninspected.
