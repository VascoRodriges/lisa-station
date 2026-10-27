# Isolation design and kernel qualification

This document records evidence and remaining work. It does not enable Lisa mode
or certify whole-device isolation. Current HA privacy state remains unknown.

## More than four vendor workers

The audited firmware runs an audio diagnostics daemon outside the main launcher.
The system DNS resolver includes Yandex forwarders and the time service is configured for
`ntp.yantp.net`. Stopping only the four `maind` processes is insufficient.

Mode control must cover:

- Main launcher/workers, audio diagnostics and any other identified sender.
- The DNS and time configurations used in each mode, including startup order.
- Connections opened before the transition, kernel-retained TCP state and relays.
- Vendor audio/telemetry queues and their later accessibility on return to Alice.
- Boot, restart and failure paths before any vendor process can run.

The speaker has neither a usable network namespace nor a network cgroup. Vendor
services share root with administration, so blocking UID 0 would affect unrelated
software. DNS blocklists alone are not an isolation mechanism.

## Candidate: socket group ownership plus a locked process identity

The kernel supports `xt_owner --gid-owner` for IPv4 and IPv6. A process launched
with a dedicated filesystem group gives that identity to newly opened sockets.
A rule at the start of OUTPUT can filter that group independently of unrelated
root processes. The eventual production group must be reserved and verified
unused. Qualification uses a separate, temporary test group.

`vendor_identity.h` is an experimental primitive:

- Set a dedicated group before opening network sockets.
- Lock changes to UID/GID and filesystem identities with seccomp.
- Include **both** old and 32-bit ARM syscall families; glibc uses the latter.
- Remove network-administration, raw-networking and ptrace capabilities from the
  current and bounding sets. `no_new_privs` and the filter survive exec.
- Test the identity/capabilities again after exec, rather than assuming inheritance.

This is not a complete sandbox. A production launcher must close inherited
sockets, restrict its entry points, and handle IPC/file relays. Old sockets
created as group 0 are not retroactively retagged. The current native agent and
stock processes have not been converted to this identity.

## Qualification tool

`net_owner_probe.c` uses synthetic data and ephemeral **loopback-only** sockets.
It neither captures audio nor contacts an external server. The opt-in Python
driver installs rules only for an otherwise unused test group, in unique private
chains, and verifies restoration of the original rules and stock process IDs.
An independent watchdog performs cleanup if the driver disconnects.

Build with Zig 0.14.1:

```sh
python controller/build.py --target net-owner-probe
```

On a trusted administrative connection to an owned compatible speaker, explicitly
opt in to temporary test rules:

```sh
python controller/qualify_group_policy.py YOUR_SPEAKER_SSH_ALIAS \
  --ssh-config YOUR_SSH_CONFIG \
  --apply-temporary-loopback-test-rules
```

The program is a development qualification tool, not part of the HA key's
allowed commands. Reports and before-test firewall snapshots stay under the
ignored `build/` directory. Do not publish a real firewall snapshot.

## Work required before production mode switching

1. Qualify filtering of both new and already-open sockets, including IPv6 and
   unaffected root controls; separately audit orphaned TCP packets and local relays.
2. Inventory existing group-0 vendor connections during first migration. Close
   or quarantine their exact flows; do not claim that new-socket tagging covers them.
3. Validate stock startup under the restricted identity, with a bounded rollback.
4. Persist mode intent and enforce boot gates before the relevant system services.
5. Select non-Yandex DNS/time configurations in Lisa mode. Preserve unrelated
   applications' internet access; no router/DHCP changes are needed.
6. Stop vendor diagnostics before Lisa audio starts, and prevent delayed export
   of Lisa-mode audio/telemetry. The standalone DSP keeps its existing network
   and filesystem sandbox.
7. Exercise reboot, interrupted transitions, policy tampering/failure, HA/NAS
   outage and explicit return to Alice before enabling the mode selector.

## Qualification results on the verified firmware

The loopback suite passed **32 cases**: 24 baseline/filtered/restored new-socket
checks, plus 8 already-open TCP/UDP socket checks across IPv4/IPv6 and grouped/
unaffected-root controls. Checks run after fork/exec with the identity lock and
reduced capabilities. Temporary rules were removed and the original firewall
rules and vendor process identities were verified unchanged. This does not cover
old group-0 vendor sockets, orphaned kernel packets or external relays.

A separate bounded stock-startup trial used `vendor_launch_probe.c` with the
experimental production identity. Four vendor workers remained stable through a
60-second observation. The owner reported ordinary replies to two spoken Alice
queries. The original launcher, configuration and four ordinary workers were
restored afterwards. No microphone stream was captured by the qualification tool;
stock Alice handled those queries in its usual way. This is a small compatibility
check, not a full firmware feature/regression test or a privacy-mode test.

The firmware does not expose `NoNewPrivs` in `/proc/PID/status`; reports preserve
that as null. The native wrapper checks the flag before exec and the separate
loopback test checks its inheritance. `Seccomp` and capability bits are observed
on the actual vendor workers.

Do not use `pidof` alone to decide whether a stopped launcher still has live
workers: exited children can remain zombies until the frozen launcher reaps them.
The startup tool excludes zombie/dead entries and checks stable PID sets after
warm-up. Its independent watchdog terminates only its own reserved-group trial
processes before resuming the original launcher.

For an explicit administrative compatibility test:

```sh
python controller/build.py --target vendor-launch-probe
python controller/qualify_vendor_startup.py YOUR_SPEAKER_SSH_ALIAS \
  --ssh-config YOUR_SSH_CONFIG --allow-temporary-stock-restart
```

The optional `--observe-seconds 60 --live-observation` prints a technical readiness
event for a coordinated voice check. It does not record audio. Real reports and
configuration backups remain in ignored `build/`, not in the public source tree.
