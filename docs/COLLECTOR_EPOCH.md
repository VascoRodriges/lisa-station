# Collector filesystem epoch

The fixed `collector` development role now runs stock `maind --fluent-bitd`
under admission and a guardian with a separate group identity. It excludes the
shared system journal through both a reviewed configuration transform and a
separate filesystem view. It is **Alice-only**, not a privacy mode, and is not
installed into init or exposed to the released HA diagnostic key.

## What is enforced

The collector gets a private mount namespace and chroot. Firmware libraries,
vendor configuration and the vendor data directory are read-only. Its `/tmp`
is a fresh, bounded 16 MiB tmpfs. The shared system journal and old temporary
collector/telemetry queues are outside that view. `/var/log` resolves to the
private `/tmp`, so both system-log aliases remain private even after rotation.
The global system logger, its journal and unrelated applications are untouched.

The private profile removes `/var/log/messages` and `/tmp/messages` from the
reviewed input list. Vendor daemon logs remain read-only inputs in Alice mode.
The collector's SQLite database, WAL/SHM companions and own log use fixed paths
under `/tmp/lisa-collector/`. Queue creation, rename and unlink operate in a
directory rather than on individually overmounted SQLite files. Its crash dump
feature is disabled and the core-size limit is zero.

`collector_profile.py` rejects unknown input paths/layouts and copies the source
without changing account data, other service settings or the original file. The
generated profile contains private firmware configuration and must not be
published. Filtering JSON alone is not the enforcement mechanism: a changed
input path still cannot see the host journal through the collector's filesystem.

Live process trees, `/sys`, audio devices, `/dev/log`, alternate host-data roots
and kernel log devices are absent. The collector sees only read-only boot ID
and kernel command-line files in its otherwise synthetic `/proc`. Stock device
identity initialization requires the latter; without it the program exits with
`bad_optional_access` before the collection engine starts. The guard never
exports the command-line contents.

All capabilities are removed, including the bounding set. The existing locked
group/credentials and `no_new_privs` survive exec. Seccomp also prevents chroot,
device creation, kernel syslog, process-memory reads and file-handle escape.
New sockets are limited to ordinary IPv4/IPv6 and AF_UNIX. **Alice IP access and
local IPC remain allowed dependencies**; this role must be stopped and denied
startup in Lisa/Paused. D-Bus, abstract sockets and descriptor transfer still
require composite IPC policy and retained-holder checks. No whole-device
isolation claim is made.

## Qualification

The own-executable probe passed **44 checks on the speaker**: read-only host
data, private temporary storage and system-log aliases, private rotation,
SQLite-style rename/unlink, removed capabilities, identity/socket restrictions,
hidden paths, runtime queue/log handle observation and namespace teardown.
It uses only synthetic epoch files; no stock log or audio payload is read.

The bounded real-stock-code trial passed **14 protocol events**:

- An ordinary live collector prevents startup; duplicate guarded startup is
  also rejected.
- Three timed observations see the same guarded child/guardian/revision, zero
  capabilities and the expected filesystem view. The child holds its SQLite
  database and own log in private tmpfs. Observed descriptors/mappings do not
  refer to the current host system journal or old SQLite queue objects.
- An incomplete IPv4/IPv6 barrier fails verification. A complete barrier passes,
  with unrelated root-owned loopback controls still working.
- Durable close stops the clone, revokes admission and completes the fixture
  Paused revision. Reconciliation clears its runtime state. Rewriting Alice
  intent/permit cannot bypass the retained close fence.
- The same original collector and launcher resume; their PIDs, boot and stock
  configuration remain unchanged. The private filesystem view disappears and
  the original firewall rules are restored.

For this trial only, the stock launcher/collector are frozen while the clone
uses a separate local IPC port. The clone's IP egress permits loopback only
during warm-up, then is completely denied before close. This avoids replacing
the original collector or resetting its restart limiter. Local IPC/DNS relay
behavior is not a whole-device isolation test. The freeze/port override is a
laboratory accommodation; production startup refuses an unmanaged collector,
including a frozen one.

An independent watchdog and exit trap stop the clone, remove only the test's
group rules and resume the identity-checked original processes after interruption.
That administrative rollback is specific to the fixture; an installed Lisa-mode
failure must instead retain closed vendor policy.

A separate fault trial killed only its own remote test shell with SIGKILL after
the three successful observations, while both temporary family-specific group
chains were installed. Without an exit trap, the independent watchdog stopped
the clone, restored the rules and resumed the same stock processes in about a
minute. Boot/configuration identities still matched. Namespace teardown is a
filesystem-lifecycle observation, not proof that every possible IPC transfer or
queued network packet has been eliminated.

```sh
python controller/build.py --target collector-guard-probe
python controller/build.py --target station-service
python -m controller.qualify_collector YOUR_SPEAKER_SSH_ALIAS \
  --ssh-config YOUR_SSH_CONFIG --allow-temporary-collector-freeze
```

Reports, generated profiles, actual identities and source firmware files stay in
ignored `build/` or the root-only device laboratory. No firmware or account data
is distributed. The released integration remains v0.1.0 diagnostics.

## Remaining deployment requirements

This is one collector's filesystem boundary. The separate telemetry daemon,
main-worker/launcher logs, mixed device databases, retained IPC handles, old
network flows/queued packets and boot ordering still require composition. No
existing queue or system journal is deleted. Production profiles, explicit Alice
return and the HA mode selector remain pending; `isolation_verified` stays false.
