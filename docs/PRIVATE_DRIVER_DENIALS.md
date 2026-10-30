# Private driver denial audit

The explicit audio-free `--error-audit` SDK diagnostic attributes the previously
generic RequestName failure to **`ru.yandex.quasar`**. The private driver's reply
identifies the ownership policy as the reason. A separate read-only literal check
in the SDK confirms the same service name. Ownership remains denied; this stage
changes no bus policy, endpoint permission or production mode.

In [D-Bus 1.12.16's driver reply path](https://raw.githubusercontent.com/d-bus/dbus/dbus-1.12.16/bus/connection.c),
driver error replies go directly to their recipient and to monitors. An ordinary
AddMatch error subscriber did not receive the known denied-name control, so that
attempt stopped before the SDK. No monitoring permission was added. Instead,
the new `private-bus-error-factory` build optionally records the error where the
already admitted **private daemon** constructs it. The normal factory build
does not contain this hook.

The hook resolves the real libdbus function and required metadata getters before
use. It calls the original function unchanged and records only a successful
AccessDenied error construction for a method call addressed to the driver,
on the driver interface, with member RequestName. Other errors and methods are
ignored. The returned reply and errno are preserved. The policy-only epoch
disables recording; the two subsequent SDK epochs explicitly enable it.

Each fixed 1109-byte record contains a version marker, nonzero request serial,
bounded unique sender name, and the [bounded one-string body](PRIVATE_ERROR_TEXT.md),
with zero padding. Up to four records may be emitted. Invalid metadata, overflow
or a failed/partial write terminates this lab daemon. This is diagnostic data,
never a permission or authorization token.

Records use a separate parent-owned pipe on the daemon's otherwise unused stdout.
The daemon still has the same six admitted descriptors. Before and after exec,
the parent checks stdout's device/inode against that pipe and its separation
from stderr. Capacity must hold the entire bounded batch. Parent write references
close before use; SDK and relay descriptor whitelists retain no audit pipe.
After daemon retirement the parent requires exact complete records and EOF,
closes its read reference, and binds each sender to the **finished SDK group
history**. Historical membership permits diagnosis, not new traffic or ownership.
Records are saved only in an exclusive root-private nonce directory, never in
public JSON or repository contents. Private diagnostic bodies may contain
device-derived data; the service name above was reviewed separately.

The known own client first requests `org.example.LisaDenied` and consumes the
real denial. Its private record must contain that name before any proprietary
SDK is admitted. The new typed **18-event** qualification requires this control,
the separate 29-check policy epoch, both source admissions and relays, completed
group retirement, private record saving and pipe closure. Older 16-event results
cannot qualify the new profile. The actual SDK yields one denial record; both
of its relays authenticate and reach EOF. Stock identity/configuration and
firewall snapshots are preserved. The existing dual-channel profile also passes
with the normal factory on the same native probe build.

The synthetic real-libdbus fixture passes **1164 checks** under fortified GCC
and ASan/UBSan: unchanged original error replies, exact filtering, disabled audit,
four-record capacity and overflow termination, every truncated record prefix,
corrupt framing/padding, invalid names/sizes and maximum UTF-8 body bounds.
Ruff and **1703 Python/HA tests** pass. CI includes the host fixture and the
additional ARM factory build, bringing the native build matrix to 46 targets.

Next is an explicitly reviewed exact-name ownership profile with positive and
negative controls and evidence of actual registration and retirement. There is
no `own="*"` grant, host-bus forwarding, new hardware or microphone access, or
production installation here. Full SDK compatibility, normal cloud policy,
permanent switching and the voice/HA roadmap remain unfinished.
