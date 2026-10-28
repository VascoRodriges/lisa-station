# File relays and retained queues

Stopping a network sender does not identify every queue that could feed a later
sender. The development tree now includes a separate, read-only file/mapping
ownership census. It does **not** move, delete, clear, replay or authorize access
to any queue, and is not exposed through the released HA diagnostic key.

## What the live audit found

The verified speaker has a vendor collector reading the shared system log
`/tmp/messages`. An ordinary system logger holds a writable descriptor for the
same device/inode. Therefore simply separating vendor daemon log files misses
an observed system-log-to-vendor ingress path. This is metadata evidence of a
possible relay; it does not establish what content was uploaded.

The audit also identified a collector SQLite database with WAL/shared-memory
companions, a telemetry LMDB directory, launcher logs including unlinked files,
vendor daemon logs, the shared RMS object and named anonymous buffers. Persistent
vendor device databases, runtime capability state and sound/framebuffer mappings
are distinguished from telemetry queues. Their contents were not inspected.
Mixed device/pairing state must not be blindly erased to implement privacy.

One paired live observation found **88 stable holder observations across 37
device/inode resources**, with **6 known vendor processes**. It included 10
unlinked descriptor holders and 10 deleted-path mapping hints. The 37 resources
comprised 10 vendor logs, 2 launcher logs, 1 shared system log, 2 telemetry LMDB
objects, 3 collector SQLite objects, 1 RMS object, 5 named anonymous buffers,
11 persistent device-state objects, 1 runtime-state object and 1 device mapping.
Counts describe that observation and can change.

## Evidence and limitations

`relay_resources.h` collects only process/executable identity, descriptor access
flags, file metadata and mapping metadata. It never opens an observed file or
audio device for data reads and never reads a mapping's contents. Descriptor
paths are classified in memory; real path strings are not printed in evidence.

Descriptor identity is rechecked around metadata collection. PID start ticks
and executable device/inode are checked again, and mappings are re-observed by
range, backing device/inode, offset, permissions and sharing mode. Resources
join by device/inode, so an alias does not hide another holder. Classification
from a stale, unconfirmed observation cannot certify an unrelated alias holder.
An unidentified writable vendor resource remains explicit.

The assessor compares two native frames and requires the same process identity
and holder metadata in both before including a stable graph edge. A writable
`MAP_PRIVATE` mapping is not described as a writer to the backing file; `O_PATH`
retains an object without being described as readable or writable. Mapping-only
holders survive a closed descriptor and must still be included.

For descriptors, an unlinked object is identified by its zero link count. The
` (deleted)` text in a mapping is only a **hint**: the proc format is ambiguous
with a literal pathname suffix. See the Linux manual descriptions of
[`/proc/PID/maps`](https://man7.org/linux/man-pages/man5/proc_pid_maps.5.html) and
[`/proc/PID/fdinfo`](https://man7.org/linux/man-pages/man5/proc_pid_fdinfo.5.html).

These are sequential observations, not pinned file descriptions or a frozen
global census. A new descriptor, mapping, writer, renamed object or inode reuse
can occur between reads. The tool counts unreadable/changed metadata and
unidentified processes; the latter can include kernel threads and exiting tasks,
and are not silently certified as safe. AF_UNIX/D-Bus peer policy, anonymous
memory without a backing inode, unknown paths and already buffered data still
require separate handling. Even an empty graph never authorizes Lisa mode.

## Qualification and use

The native self-test uses only its own temporary files and mappings. **51
checks** passed on the speaker and an unprivileged Linux host, covering fixed
resource classification, malformed mapping metadata, process/descriptor reuse,
hard-link aliases, stale classification sources, unlinked open descriptors,
mapping-only retention and cleanup. Python tests reject overstated evidence,
changed actors, unconfirmed holders and inconsistent access/format claims.

```sh
python controller/build.py --target relay-evidence-probe
python -m controller.relay_inventory YOUR_SPEAKER_SSH_ALIAS \
  --ssh-config YOUR_SSH_CONFIG
```

The root-only census checks the supported model, has bounded tables and a
25-second alarm. The own-file self-test needs no root or firmware inputs.
The Python CLI prints aggregate counts and blockers; numeric identities and
real holder graphs remain in ignored `build/relay-inventory.json`.
No services are stopped and no firewall, shared logger or queue is changed.

## Required transition policy

- Stop and gate all vendor collectors and diagnostics before Lisa capture.
- Prevent future vendor collectors from consuming the shared system journal;
  keep the ordinary logger available to unrelated applications.
- Place vendor logs in an explicit private epoch and close inherited handles.
- Quarantine vendor-only telemetry queues only after all descriptor and mapping
  holders are gone. SQLite database/WAL/SHM state needs a coherent lifecycle.
- Review mixed device state separately; release hardware/anonymous mappings
  through tracked process termination. Do not treat them as deletable queues.
- Compose those checks with admission, old-flow/queued-packet barriers and boot
  enforcement before claiming a closed mode or enabling explicit Alice return.

The audit lists these actions but does not execute them. `production_plan_ready`,
`apply_supported`, `isolation_verified` and `mutation_performed` remain false.
It preserves internet access for unrelated applications and changes no shared
router or DHCP infrastructure.
