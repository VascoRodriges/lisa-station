# Immutable client binding and sibling admission

An own client now runs as a third child beside the private bus and sealed relay.
It loads the client compatibility library from a read-only file inside the
platform filesystem, creates its logical bus connection through that factory and
exchanges real private-bus method traffic. The real SDK has not been connected
by this change; its executable path is occupied by our own qualified ELF.

## Explicit filesystem variant

`platform_storage_enter_with_binding` adds only the fixed `/opt/lisa/client.so`
path and a version marker before sealing/chroot. The file is descriptor-pinned,
root-owned, single-link, regular and executable, with no group/world writes or
set-ID bits, then bound read-only/NOSUID/NODEV. The trusted preparer protects the
source artifact; a read-only bind does not protect against a hostile host root.
There is no writable bind of host vendor/lib directories or global preload file.

Existing storage calls pass no binding. Their `/opt` and binding-marker paths
remain absent, checked in both default regression epochs. The variant does not
itself admit IPC or change kernel policy; the caller must prepare its exact stream
capabilities and independent guards.

For the own-client trial, fake identity seeds and a minimal profile are created
on a disposable staging tmpfs in the child mount namespace. They are copied into
fresh bounded platform storage. Staging, DATA, tmp and shared memory disappear
with the actor; their host underlay directories remain empty. No real account,
firmware profile or audio is read for this fixture.

## Three siblings and descriptor ownership

The common coordinator creates the client pair/backend connection and forks the
bus, relay and own client. Existing parent-only cached-peer validation remains
unchanged. Because cached SO_PEERCRED identifies the creator, the coordinator also
checks each actual child executable, private view and descriptor objects.

Before the client's first instruction, admission verifies a private read-only
root, distinct bounded DATA/tmp/shm filesystems, zero capabilities, UID0/GID57342,
seccomp and exactly six FDs: null stdin/out/err, approved stream and two own control/
report pipes. Host accounts, proc/PIDs, audio, administrative paths and bus are
absent. The client binding's file object/read-only mount are verified independently.

After exec and the library constructor, the client factory duplicates its one-shot
source to a new FD. A ready message supplies that FD number; the coordinator
rechecks its object against the retained source, the actual ELF/binding/view and
all six FDs. Only then does it close surplus source/pipe copies and permit protocol
traffic. No existing validator is weakened to accept an unrelated sibling.

The client has the full identity/capability/worker guard plus the strict channel
filter. Raw socket/connect/message/accept/fork calls fail even with a valid channel;
the compatibility factory's logical socket/connect succeeds without opening a
host endpoint. Binding write attempts fail, private fake identity is checked and
the actual host-bus pathname stays absent.

## Evidence and remaining work

The composed speaker trial passed **146 checks**: 15 controls, 52 coordinator
checks, five outer controls, 11 per relay and 26 per own client across two epochs.
The separate own clients receive the real daemon OK, local no-FD ERROR and actual
method replies through the relay. Forbidden methods still fail. Backend EOF in
one epoch and explicit client closure in the other close all owned endpoints;
clients/relays/daemons are reaped and private roots released before the next epoch.

Default storage also passed **192 checks plus 50 seed checks**, including absence
of the optional binding paths. Stock identities, configuration, firewall and
read-only rootfs are preserved, with unrelated root network controls working.
Ruff, public-source validation and **1398 Python/HA tests** pass; the matrix remains
at 45 native targets. No actual SDK, account, microphone or host-bus forwarding is
involved in these fixtures.

Qualified ARM probe SHA256 values:

- Sibling composition: `8ef15300b2e0ed93bd50c4ad046f3fde472035cb4af5bf49f65bcf83defe7193`
- Default storage: `e8ef5f9b3c1a47f4b6d07166a1e0a22e62dde500b2b24a8378d78b250939d0e8`

The existing client/server library artifacts are unchanged. This qualifies own
ELF loading and IPC composition, not SDK functionality. Next work is an audio-free
SDK diagnostic through the same admitted path and narrowly reviewed service
schemas. Normal cloud Alice also needs a separate network-capable policy; the
strict local factory rejects IP and must not become a whole-device internet ban
or a substitute TCP stack. Actual SDK identity/hardware/time/queue lifecycle,
permanent supervision, mode/boot/voice and HA migration remain unfinished.

The subsequent [SDK admission diagnostic](SDK_PRIVATE_BUS_DIAGNOSTIC.md) verifies
this immutable library mapping in the actual platform SDK. A reviewed logical
client-label bind is now adapted; SIGPIPE compatibility still blocks bus
authentication. The own-client qualification above
must not be interpreted as SDK compatibility.
