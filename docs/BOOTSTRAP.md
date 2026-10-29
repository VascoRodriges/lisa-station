# Closed bootstrap coordinator

`station-boot` now implements a real, bounded closed-policy bootstrap and
read-only status. It is **not installed**. The [hardware mixer handler](HARDWARE_VOLUME.md)
is now implemented; independent DNS/time handlers,
explicit Alice return and transactional boot installer remain unfinished;
the HA release is still diagnostic and reports no verified isolation.

## Ownership before mutation

Production bootstrap requires the supported model, read-only rootfs, trusted
private installation marker and durable Lisa/Paused intent. It refuses live
unmanaged vendor actors, tagged actors, Alice intent and existing actor journals
or permits. It never stops stock services or publishes an Alice permit.

The coordinator serializes mode and boot operations. It reserves its per-boot
chain namespace in a private immutable `boot.policy` record before changing
rules. `boot.ready` is published only after both families' canonical policy and
unrelated loopback controls succeed. Records use no-replace publication and
file/directory fsync; malformed, linked, stale or public records are refused.
Temporary filename generation cannot block on cold-boot entropy seeding.
A ready record without namespace ownership is invalid. Status inspects actual
kernel rules instead of trusting a marker and does not create missing locks.

The policy uses four vendor groups, conntrack creation marking and retained
label denial in IPv4 and IPv6. It changes no default policy, global chain or
unrelated mark bit. Initial namespace reservation refuses preexisting names,
occupied label bits and foreign CONNMARK writers. Recovery permits only the
exact owned marking rules, including when examining unhooked chains.

Interrupted installation can fill missing rules in an owned **ordered subset**
and missing jumps in an owned prefix. Extra, duplicate, reordered or conditional
owned references are refused and left intact. There is no global flush,
conntrack purge or destination blacklist. Completion certifies these selective
barriers, not whole-device privacy or retrospective attribution of stock flows.

## Actual-kernel qualification

The explicit `--lab-policy` fixture uses its own private state and unique chain
names while ordinary Alice remains running. It refuses an installed controller
and serializes with other speaker trials. Its independent cleanup watchdog
removes only its own hooks/chains and refuses unexpected tagged actors.

The 17-event speaker trial passed fresh installation, repetition, inspection,
repair of missing rules in both families, rejection of unknown rules,
conditional hooks and a foreign marking writer, missing ownership refusal,
Alice-intent refusal and recovery to Paused. The slowest coordinator operation
was **587 ms**, within the dispatcher's four-second bootstrap bound. Stock
identities, boot/config digests and complete firewall rules were preserved or
restored. No microphone data was captured and no production mode was changed.
This policy-only experiment deliberately does not isolate the running Alice.

The native state probe passed **238 checks on the speaker and a fortified Linux
host**, covering ordered subsets, hook references, record privacy/corruption
and forced nonblocking random-source EAGAIN/ENOSYS/EIO outcomes. Python/HA tests
passed **597**; the native build matrix contains **29** targets.

Qualified ARM digests:

- coordinator: `380f8359eb3a6103e4545fa5007e70747aff736561e85949afcfad91f952373d`
- state probe: `19bd1a2593de8efd389f090f5dfd0b930101ff1d095c3b04096213a7c5d24649`

```sh
python controller/build.py --target station-boot
python controller/build.py --target boot-state-probe
```

Actual cold boot, power loss, constrained hardware, independent DNS/time,
guarded production actor admission and explicit Alice return still require
composition and acceptance. Do not copy the staged dispatcher into rcS alone.
