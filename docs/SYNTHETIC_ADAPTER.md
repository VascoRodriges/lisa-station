# Synthetic offline adapter dependency audit

The explicit `--run-sdk-adapter` lab now returns one synthetic Adapter1 object
from the private ObjectManager. The SDK gets past the missing-default-adapter
failure and next reports EMFILE while opening a bus connection. The one-shot
client factory currently receives only one channel; attribution of the new
allocation failure must be confirmed before admitting another channel. Raising
the file limit or enabling raw sockets is not a justified fix.

This experiment adds no method permissions beyond the existing
[empty-service diagnostic](PRIVATE_EMPTY_SERVICE.md). The provider still accepts
only the exact zero-argument GetManagedObjects call at `/`. Property changes,
pairing, discovery, connection, media and hardware operations remain unavailable.
It implements no Bluetooth device or audio transport.

The body contains exactly `/org/bluez/hci0`, with only org.bluez.Adapter1 and
fourteen fixed typed properties. Address, name, alias and modalias are synthetic
constants. Class and timeouts are zero; all power/discovery/pairing booleans are
false; UUID and role arrays are empty. No real address, alias, paired device,
account, firmware profile or host-bus snapshot supplies the body. The prior
read-only device audit informed property types only.

The bounded encoder takes no caller-provided object or property values. Body
storage is capped at 1024 bytes, with checked array lengths and alignment; the
current body is 476 bytes. Reply construction retains the qualified empty
codec's serial and unique-destination handling. Invalid inputs or insufficient
capacity return a zero written count and leave output bytes unchanged.

The native fixture passes **1029 checks** on Windows/Zig and fortified GCC,
also under ASan/UBSan, including every undersized body/reply buffer and maximum
or malformed destination names. A separate host-libdbus parser passes **141
checks**, independently traversing every dictionary, variant, exact property
type/value, empty array and end-of-container. CI runs both host checks; the
fixture also compiles for ARM without adding a device-build target.

The own SDK control first verifies the provider sender, reply serial, signature
and complete canonical body, then completes its marker and thread-drain proof.
Only afterward is the actual SDK admitted. The provider, observer, relay and SDK
retain their existing separate ownership and complete teardown requirements.
The actual SDK completes one ObjectManager exchange before its next failure;
the relay can terminate with an I/O error during abort, which remains explicit
in evidence. No functional-SDK or full-isolation claim follows from this test.

The wrapper option is deliberately distinct from the empty-tree mode:

```sh
python -m controller.qualify_sdk_bus SPEAKER_ALIAS --ssh-config PRIVATE_SSH_CONFIG --run-sdk-bus-diagnostic --synthetic-adapter
```

The two service options are mutually exclusive. The strict thirteen-event
protocol requires `sdk-adapter-provider` and a typed synthetic-adapter marker;
empty-tree evidence cannot qualify this mode. Reports and private logs have
separate filenames. Both service variants retain the same 29 policy controls.
Ruff/public-source checks and **1596 Python/HA tests** pass; the device build
matrix remains at 45 targets.

Qualified private-bus probe SHA256:
`c82e04634393621ce89105d7980c405e49e97f5fc6f29f1a9a5c6fdd2d1ef702`.
The client and server libraries are unchanged. Stock identities, configuration,
boot, firewall and unrelated network controls are preserved. This does not
install a mode switch, change ordinary Alice or migrate the second station.

Next work is to verify the new logical-channel allocation failure and design
bounded independent channel ownership, admission and teardown. It must preserve
one-shot semantics and discard retired socket queues. This is not permission to
grow a general mock Bluetooth stack, reuse old stream aliases, forward the host
bus, expose hardware audio or weaken kernel network denial. Normal cloud-Alice
policy and the permanent mode/boot/voice/HA roadmap remain unfinished.
