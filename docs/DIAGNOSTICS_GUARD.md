# Guarded ALSA diagnostics lifecycle

This is a development backend for the independent `alsa-audio-monitord` service,
not a released HA command or an installed privacy mode. The ordinary Alice
launcher does not own this daemon, so stopping the launcher alone misses it.

The fixed `diagnostics` role now uses the same admission lease, PID/start-tick
journal, guardian and durable closed-request fence as the main launcher. It has
its own reserved group and control files. A live unmanaged monitor, including a
stopped one, prevents duplicate startup. There is no automatic respawn or return
to Alice. Uninstalled production state denies startup.

## Resource boundary

The verified Station 2 kernel supports a **private mount namespace** even though
it lacks a usable network namespace. Before executing the fixed stock ELF, the
backend creates a private filesystem view and chroot:

- Fixed libraries, two hardware/configuration files and minimal locked account
  metadata are read-only. The host's account database is not exposed.
- Live `/proc`, `/sys`, audio devices, vendor account/configuration/data paths,
  `/dev/log` and the host's system/kernel log interfaces are hidden. Only the
  kernel boot ID is bound into the otherwise synthetic `/proc` directory.
- Daemon logs and the substitute regular file at `/dev/kmsg` live in a private
  4 MiB tmpfs. They disappear with the child namespace; host log files are not
  truncated, read or replaced by this guard.
- The system D-Bus socket and **one fixed shared-memory object**,
  `/dev/shm/alsa-audio-monitor-v2`, remain explicit local IPC dependencies. The
  latter must be an existing root-owned regular file with the verified fixed
  layout size, link count and permissions. Its inode is checked after binding;
  no other host shared-memory objects are exposed.

The stock monitor opens this shared object for reading and writing and calls
`ftruncate` before it initializes D-Bus. Omitting it makes the program exit with
code 3 before its D-Bus setup; granting general filesystem or network access is
unnecessary. The guard preserves that exact object with read/write access and
nosuid/nodev/noexec mount flags. The qualification tools inspect only its
metadata, never its contents, and do not initialize or resize it themselves.

The group identity is locked before execution. Seccomp denies every new socket
family except AF_UNIX, including IPv4, IPv6, netlink and packet sockets. It also
denies chroot, device-node creation, kernel syslog and file-handle access, in
addition to the existing identity/mount/namespace restrictions. Relevant DAC,
namespace, kernel-log, raw-network and tracing capabilities are removed from
effective, permitted, inheritable and bounding sets. `no_new_privs` survives exec.

**This is not complete IPC isolation.** AF_UNIX includes abstract sockets, the
system bus is not filtered by method, and the shared object is writable. These
are still potential relay paths requiring the composite vendor policy. While
Lisa/Paused is active the intended state is to stop and deny startup of this
role, not keep it running and infer privacy from its socket restrictions.

## Qualification

The own-executable guard probe passed **52 checks on the speaker**: identity and
capability locks, socket-family refusals, forbidden filesystem operations,
read-only mounts, hidden paths, synthetic private log writes, D-Bus connection,
shared-object metadata rejection cases, exact binding and namespace teardown.
It does not execute the vendor daemon or read its shared-memory contents.

The separate real-service trial passed all **15 protocol events**:

1. An existing unmanaged monitor prevents startup; a second managed start is
   rejected after the guarded process starts.
2. Three timed inspections observe the same guarded PID/guardian/revision and
   filesystem boundary. D-Bus reports that exact child as the owner of
   `org.yandex.AudioMonitor` on all three samples.
3. An IPv4-only group barrier fails verification. Adding IPv6 passes; unrelated
   root-owned IPv4/IPv6 loopback controls still work.
4. The durable Paused transition verifies the group barrier, revokes admission,
   stops the role and completes at the next revision. Reconciliation clears its
   runtime journal. Manually rewriting an Alice request/permit cannot bypass
   the retained closed-request fence.
5. The stock init script restores a single ordinary monitor, with its D-Bus
   ownership, original identity and mount namespace. The private log namespace
   is gone. Core Alice PIDs, boot/configuration, shared-object metadata and
   firewall rules match their pre-trial state.

A trap and independent watchdog recover the original service if the trial
aborts. Recovery closes the watchdog's lock descriptor before starting the stock
daemon so that it cannot inherit the recovery lock. This administrative rollback
is confined to the test fixture; installed Lisa-mode failure must retain closed
vendor policy instead.

A separate fault trial killed only its own remote test shell with SIGKILL after
the three guarded observations. Without an exit trap, the independent watchdog
restored the stock monitor and its D-Bus ownership in about a minute. Core Alice
processes, boot/configuration and firewall rules still matched the initial state.

```sh
python controller/build.py --target diagnostics-guard-probe
python controller/build.py --target station-service
python -m controller.qualify_diagnostics YOUR_SPEAKER_SSH_ALIAS \
  --ssh-config YOUR_SSH_CONFIG --allow-temporary-diagnostics-restart
```

The last command briefly stops/restarts only the diagnostics service. It refuses
installed production mode/runtime directories and uses an existing trusted
administrative SSH configuration. Reports and real metadata remain in ignored
`build/`. No microphone stream is captured and no speech test is needed.

## Remaining work

The guard is not installed into init, and the released HA diagnostic key cannot
invoke it. Global vendor UDP attribution, other file/IPC relays, telemetry
queues, packets already beyond OUTPUT, complete boot ordering and explicit
Alice return remain separate requirements. `isolation_verified` stays false.
The device retains internet access for unrelated applications; no shared router,
DHCP or network-wide policy is changed.
