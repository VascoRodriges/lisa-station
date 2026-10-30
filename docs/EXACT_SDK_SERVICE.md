# Exact private SDK service ownership

The explicit audio-free `--owned-service` profile now permits registration of
the previously attributed **`ru.yandex.quasar`** name on the disposable private
bus. A separate observer verifies the actual SDK acquires it and that the name
has no owner after teardown. The SDK passes the prior RequestName failure and
next stops at `snd_mixer_attach` because hardware is absent from its view.
This qualifies local registration, not a working mixer, voice pipeline or
production mode switch.

This profile alone adds an exact `own` rule for that name and allows the driver's
GetNameOwner method. There is no ownership prefix or wildcard grant. The normal
dual-channel and denial-audit profiles retain their earlier policies. Existing
two-name, four-client, four-rule, one-shot source and reply limits remain.
All lab actors share UID 0: this is not per-role authentication. XML method
policy cannot constrain the string argument, so this lookup permission covers
other **private** bus names too; the parent always queries the one fixed name.
There is no host-bus access or new network, hardware or microphone permission.

The separate policy epoch now passes **34 controls**. It rejects both
`ru.yandex.quasar.Other` and `ru.yandex.quasarOther`, obtains PRIMARY_OWNER for
the exact name using an existing own connection, verifies its unique owner,
then verifies absence after closure. Existing peer-signal, quota, monitoring,
activation and other method denials remain. The previous forbidden-name lookup
now returns NameHasNoOwner, reflecting the explicit metadata permission.
No extra connection or ReleaseName permission is needed.

For the SDK epochs, the same preadmitted observer performs fresh
[GetNameOwner requests](https://dbus.freedesktop.org/doc/dbus-specification.html#bus-messages-get-name-owner).
It requires the driver sender, its own destination and reply serial, exact
one-string body and a valid unique owner in the active SDK group. A successful
RequestName log or absence of an exception is insufficient. Ownership is kept
as observed metadata; it grants no traffic rights. The pure state helper rejects
owner changes, foreign or retired names, invalid state and observation after
retirement, leaving prior state unchanged on failure.

Lookup runs after two SDK names are known and stops once ownership is observed.
It shares the existing **40-query, one-second total, 50-ms per query** budget
with Stats. There are at most 14 acquisition attempts and one final lookup.
After both SDK streams and the provider close, a fresh observer-only Stats
snapshot must finish the group ledger. Only then does an explicit NameHasNoOwner
reply qualify service retirement, before the observer closes. The previous
observed owner is never accepted as current authorization or a fresh snapshot.

The own SDK control first acquires the exact name and consumes the real
PRIMARY_OWNER reply. An unrelated dotted name remains denied. Its first stream
checks creation and loss signals for both the second unique name and service
name; the two loss signals may arrive in either order. Duplicate, missing and
unexpected transitions fail, and a GetId barrier precedes closure so both
relays retain their clean EOF requirement. This control completes before the
proprietary SDK is admitted.

The explicit typed 16-event owner protocol requires both acquisition and
retirement flags, bounded owner query counts, all 34 policy checks, both source
and relay admissions, group retirement and complete cleanup. Earlier 16-event
dual proofs cannot qualify it. The actual SDK reaches a later mixer dependency;
no mixer or PCM device was opened. Stock identities/configuration and firewall
snapshots are preserved. A same-build normal dual-profile regression passes.

The pure owner fixture passes **45 checks** on Windows/Zig, fortified GCC and
ASan/UBSan. Ruff and **1741 Python/HA tests** pass; CI includes the owner host
fixture and retains the 46-target native matrix. The next step is read-only
analysis of the mixer's required control interface, without granting arbitrary
ALSA access or pretending a missing hardware operation succeeded. The subsequent
[API metadata audit](SDK_MIXER_AUDIT.md) now identifies `default` and the real
negative attach result while retaining the hardware denial. Permanent
switching, full service compatibility and the rest of the roadmap remain open.
