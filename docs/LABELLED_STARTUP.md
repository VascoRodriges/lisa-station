# Label admission composed with four real roles

The uninstalled-only labelled startup trial now combines the four actual
guarded roles with the tested conntrack mechanism. It passed **44 events** on
the speaker, including **16 successful role inspections** and **62 observed
labelled conntrack entries** in that run. This is a bounded laboratory result;
`isolation_verified` remains false and no HA mode selector or boot hook is enabled.

## Admission and close ordering

The root backend first verifies exact four-group marking chains and first mangle
OUTPUT hooks in both families. With mode.lock held exclusively, it requires
current Alice intent/permit and an empty guarded actor/journal scope before
publishing `label.arm`. The immutable private record binds marking admission to
the mode revision, boot and owned chain. Publication fsyncs its file and directory
before any labelled start. Missing, stale, linked, malformed or public records
deny admission; conflicting evidence is never overwritten. A retry also syncs
existing evidence rather than assuming visibility means durability.

Each labelled start rechecks that record, the current admission lease and the
actual marking policy before child preparation can create vendor sockets.
The existing guardian holds startup admission through exec observation. An
existing arm record also prevents accidental use of ordinary unlabelled start
operations. It is not an authorization to relabel old unmanaged connections.

The shared close requires the arm record at its base revision, all four owner
DROP rules and the exact label policy in **both families**. Filter OUTPUT starts
with group denial followed by label denial; filter INPUT starts with label
denial. Marking remains installed. Only then may the durable executor revoke
the permit, commit closed intent and stop/reconcile every guarded role. Once
armed, the generic shared-policy operation also requires labels; omitting the
`labelled-` prefix cannot weaken this check. The retained fence still blocks a
raw Alice intent/permit rewrite afterward.

The trial rejected startup before arming, incomplete IPv6 marking, an ordinary
start after arming, late arming over live roles, an incomplete group barrier and
a missing IPv6 label barrier. Unrelated root loopback controls continued to
work. All four roles closed and reconciled, private epochs disappeared and
ordinary Alice/diagnostics, the original launcher/boot/configuration identity
and complete firewall rule specifications were restored. No audio was captured.

## Qualification

The native admission/rule fixtures passed **60 checks on the speaker and a
fortified Linux host**. They cover canonical rules/hooks plus missing, stale,
conflicting, linked, public, symlinked and oversized arm records, immutable
publication and cleanup. The guardian regression suite passed **57 checks** on
both systems, including transient exclusive mode-lock contention; this prevents
an admission review from prematurely stopping live roles before network denial.
The Python/HA suite passed **572 tests** after adding independent fault recovery.

The qualified backend digest is
`46aa0416f1fa98bc811cfede95b6676744b9f435a488decc71e5d82bc72f3f5e`.
The actual report remains private in `build/labelled-split-qualification.json`.

```sh
python controller/build.py --target station-service
python controller/build.py --target label-policy-probe
python -m controller.qualify_labelled_split YOUR_SPEAKER_SSH_ALIAS \
  --ssh-config YOUR_SSH_CONFIG --allow-temporary-stock-restart
```

This command temporarily replaces stock workers and explicitly restores Alice.
It refuses installed production state and any occupied fixture label or existing
connmark policy. It does not flush conntrack to make a retry possible. A trap,
bounded guardians and independent watchdog cover its lifecycle; a separate
SIGKILL qualification of the combined restoration also passed, as described below.

## Independent watchdog recovery

The separate `qualify_labelled_watchdog` trial passed **38 events**. After all
four running-role observations, incomplete-policy refusals and full IPv4/IPv6
group/label verification, it killed **only its own inner trial shell with
SIGKILL**, before the durable close command. An outer shell observed exit 137
and waited; it did not invoke the restoration script itself. The inner EXIT
trap could not run.

The independent watchdog restored ordinary Alice/diagnostics and removed every
owned filter/mangle hook and chain in **102 seconds from trial start**. The
original launcher/boot/configuration identity and complete rule specifications
matched their pre-trial state. The global trial lock was released; ordinary
worker groups, diagnostics seccomp/mount namespace and D-Bus ownership were
verified. No audio was captured. Evidence remains private in
`build/labelled-watchdog-qualification.json`.

```sh
python -m controller.qualify_labelled_watchdog YOUR_SPEAKER_SSH_ALIAS \
  --ssh-config YOUR_SSH_CONFIG --allow-temporary-stock-restart
```

This is **administrative lab restoration to Alice**, not production recovery
for Lisa/Paused. Installed recovery must preserve or rebuild denial instead of
resuming Alice. Both tools refuse production state/runtime directories.

## Limits

The arm record establishes the reviewed startup sequence, not a continuously
atomic global snapshot or protection against a separate root administrator
rewriting the firewall. Permanent coordinator ownership and boot enforcement
remain to be installed. The platform still shares its filesystem state; local
IPC/file receivers, independent DNS/time, earlier unmanaged flows, packet queues,
label retention/tuple reuse and explicit Alice return require further work.
Real SDK batch materialization remains unobserved. This stage captures no new
microphone audio and does not install the permanent speech/Assist service.
