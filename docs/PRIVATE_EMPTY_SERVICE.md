# Live empty ObjectManager lab service

An explicit `--run-sdk-bluez` diagnostic now supplies an own private org.bluez
service returning an empty object tree. The actual platform SDK completes its
GetManagedObjects call and then stops because it cannot find a default
org.bluez.Adapter1 object. This confirms that the adapter is a required startup
dependency. No Bluetooth adapter, devices, pairing, discovery or host bus is
exposed, and usable SDK functionality remains unverified.

The default `--run` and earlier `--run-sdk` profiles retain their previous rights.
The new wrapper option is explicit:

```sh
python -m controller.qualify_sdk_bus SPEAKER_ALIAS --ssh-config PRIVATE_SSH_CONFIG --run-sdk-bus-diagnostic --empty-bluez
```

It refuses production state and concurrent device trials. This is a bounded,
audio-free lab experiment, not a permanent Alice mode or a production service
gateway. Ordinary speaker processes and the second station are unchanged.

## Separate ownership and narrow policy

The common parent owns distinct provider and Stats-observer sockets. The own
policy fixture retains its first connection as provider, closes the publisher,
then creates its observer and SDK connection. This stays within the existing
four-accept lifetime budget; the actual SDK epoch uses three connections.
Both parent descriptors are discarded in the SDK child before the unchanged
four-FD pre-exec/exec admission checks.

Before SDK execution, the provider requests only org.bluez with DO_NOT_QUEUE and
requires PRIMARY_OWNER. It does not queue, replace or adopt another service.
The lab name limit allows a unique name plus this service. Other service names,
activation, monitoring and RemoveMatch remain denied. Only the exact
ObjectManager GetManagedObjects method at `/` and requested method returns are
added. Wrong path, interface and member receive actual AccessDenied replies.
The earlier eight method denials and reception/canary controls still pass, for
29 policy/lifecycle checks in the service mode and 26 in the earlier SDK mode.

These actors share the lab's UID0 policy. This is not per-role authorization:
the SDK also sees the lab's narrowly added permissions and private Stats.
Sender pinning, a private fake-identity environment and the absence of any real
hardware or host service remain essential. No production policy gains access.

## Bounded parent event pump

A synchronous SDK request cannot receive a reply from a callback that runs only
after a successful SDK read. The metadata tracer now has an optional parent idle
pump, independent of SDK I/O-buffer contents. It neither consumes sibling wait
statuses nor extends the existing six-second trace and three-second drain limits.
Other diagnostic callers retain a null callback.

The provider pins its socket inode, uses nonblocking I/O, and handles at most
four calls and sixteen validated driver signals. Each whole exchange has a
50 ms deadline within a one-second total I/O budget. The request sender must
equal the SDK unique name already observed through private Stats. The
[qualified fixed codec](PRIVATE_EMPTY_OBJECTS.md) validates the exact method and
zero-body schema and builds only its empty-tree reply. Unexpected traffic fails
the diagnostic; it is not forwarded or automatically granted access.

The Stats observer separately tracks an unchanged known provider entry and
excludes it from SDK match snapshots. After SDK and relay drain, the provider
closes with EBADF confirmation. A fresh Stats query must contain only the
unchanged observer, with both SDK and provider absent. The observer then closes,
the daemon is reaped and the private filesystem released.

## Evidence and limits

An own executable first registers two known rules, requests the empty tree and
validates the reply's actual provider sender, serial, signature and complete
empty body. Its normal control marker and nine-thread exit must then pass before
the proprietary SDK is admitted. Both clients complete one verified service call.
The actual SDK reaches the missing Adapter1 dependency; its cleanup attempts to
RemoveMatch remain denied. The byte relay may terminate with an I/O error during
SDK abort; the report retains that outcome and requires complete actor teardown.

The strict service evaluator requires thirteen ordered events, including both
provider ownership/call/closure proofs and both observer teardown proofs. The
earlier eleven-event SDK protocol is rejected as service evidence. Native codec
fixtures retain 2060 checks, plus 23 independent host-libdbus checks. Ruff and
1566 Python/HA tests pass; the ARM build matrix remains at 45 targets.

Qualified private-bus probe SHA256:
`dae9952080b272ee49dbaadb4f24ebcc2a398ad10139b06e7d80b35c5a311586`.
Client and server libraries are unchanged. The same binary also retains the
earlier eleven-event SDK diagnostic and the default 148-check bus regression.

The completed device tests preserve stock process/configuration/boot identities,
firewall rules, read-only rootfs, OTA/recovery access and unrelated network
controls. No microphone, account or host-bus access is added. The local SDK lab
still denies IP; this is not the final cloud-Alice network policy or a device-wide
internet ban. Permanent supervision, mode/boot installation, real service/queue
lifecycles and the voice/HA roadmap remain unfinished.
