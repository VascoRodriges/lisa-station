# Guarded service startup and closed reconciliation

`startup_guardian.h` and the fixed `station-service` backend connect startup
admission to actual process creation. They are development components, not an
installed boot policy or a complete Lisa-mode transition executor. The shipped
HA diagnostic command and its restricted SSH key remain unchanged.

## Startup ordering

1. Validate private mode/runtime directories and acquire the revision/boot-bound
   Alice admission lease. Missing state or permits deny startup.
2. Take an exclusive role lock and refuse any existing process journal. A second
   start cannot replace or duplicate a running guardian.
3. Create a separate guardian session, private local control socket and initial
   journal. The guardian closes unrelated inherited descriptors and uses
   `/dev/null` for standard streams.
4. Fork a child into its own process group. Journal its PID and kernel start
   ticks before giving permission to exec. The fixed child preparation completes
   before that permission is sent.
5. Wait for the close-on-exec pipe, then verify the live PID/start ticks, actual
   executable inode and role-specific identity/capabilities. EOF alone is not
   enough to report success.
6. Atomically publish/fsync the running journal, release the startup lease and
   only then reply to the caller. The guardian keeps the exclusive role lock and
   supervises the child; it does not respawn it automatically.

The mode writer's exclusive lock cannot commit while startup holds its shared
lease. A busy result is explicit and callers must retry within a bound. After
startup, the guardian checks mode/revision/permit validity and stops its role if
admission is revoked. This polling is **not a network privacy barrier**: the
future transition executor must install selective vendor denial before relying
on process shutdown or acknowledging isolation.

The quasar child receives the previously qualified dedicated group, identity
lock, capability reductions and `no_new_privs` before exec. It inherits no
administrative sockets or mode lock. Its environment and startup limits are
explicit. The backend refuses an unmanaged live launcher/worker set; it does
not replay stock `onboot.sh`, whose privileged setup belongs in the trusted
controller. Production executables must be root-owned, non-writable by other
users and have no set-ID bits or file capabilities.

## Parent death, orderly stop and process identity

The child arms `PDEATHSIG` and checks its parent both before and after preparation.
It must arm it again after effective/filesystem credential changes, which clear
that setting. The initial target cannot be a privileged executable that clears
the setting during exec. See [Linux parent-death semantics](https://man7.org/linux/man-pages/man2/PR_SET_PDEATHSIG.2const.html).

For orderly teardown the guardian retains its direct child unreaped until
terminating the owned process group. `waitid(...WNOWAIT)` confirms that it still
owns that child; this pins the PID against reuse. It never signals an arbitrary
PID supplied by a journal or HA. Relevant semantics:
[wait/waitid](https://man7.org/linux/man-pages/man2/waitpid.2.html) and
[subreaping](https://man7.org/linux/man-pages/man2/PR_SET_CHILD_SUBREAPER.2const.html).

Stop requests use a private Unix sequenced-packet socket. The peer UID, guardian
PID, boot ID and start ticks must match the journal. A stale record cannot cause
a client to signal a new unrelated process with the same PID.

After teardown a role-specific inventory must confirm that no actors remain.
For quasar this scans the reserved group, including partial/supplementary tags;
an unreadable live process is not treated as absent. Unknown inventory or failed
tracking persists an error and cannot produce a successful stop acknowledgement.

Parent-death signaling protects the direct child; it is cleared in newly forked
descendants. Descendants can also use other sessions/groups. Therefore a guardian
crash still requires role/group inventory and selective network protection.
These components are not a complete sandbox or an assertion that every vendor
relay and queued packet has been handled.

## Journal and recovery

The canonical, versioned journal records revision, boot ID, guardian/child PIDs,
kernel start ticks and startup phase. It uses private regular single-link files,
exclusive temporary creation, fsync and atomic rename. The runtime journal is
distinct from durable mode intent; neither proves application health or privacy.

An interrupted or terminal journal prevents a new start until reconciliation.
Closed reconciliation:

- Requires valid Lisa/Paused intent and exclusive mode/role locks.
- Revokes any old Alice permit.
- Requires matching boot, no live tracked processes and a verified empty actor
  inventory; malformed, stale or uncertain evidence is retained for recovery.
- Removes only the private role journal/control socket. It never starts Alice,
  creates an Alice permit, changes firewall rules or claims network isolation.

The engine is for single-threaded native helpers with normal SIGCHLD handling.
It rejects callers that auto-reap children, since safe PID ownership is required.

## Fixed backend and qualification

`station-service` exposes fixed quasar start/stop/closed-reconcile operations.
Production paths are fixed and traversed without following symlinks through
writable/untrusted directories. There is no arbitrary executable, PID, shell
command or child argument input. Every result currently includes
`isolation_verified: false`.

On an uninstalled device, the production start command was verified to deny.
Lab commands require an owned compatible speaker, a private canonical fixture
path and the existing administrative trial lock. The qualification tool refuses
installed production state/runtime directories.

```sh
python controller/build.py --target startup-guardian-probe
python controller/build.py --target station-service
python -m controller.qualify_guardian_startup YOUR_SPEAKER_SSH_ALIAS \
  --ssh-config YOUR_SSH_CONFIG --allow-temporary-stock-restart
```

The guardian suite passed **54 checks on the speaker's writable storage** and
on a separate Linux host. Tests use their own fixture executable without set-ID bits or file capabilities,
not the firmware's set-ID BusyBox. They cover concurrent mode/start, duplicate
starts, actual exec observation, descriptor leakage (including above a lowered soft limit), permit revocation, closed
mode, failed observation, guardian crashes before/after exec, stale/corrupt
journals, unrelated-process survival and unknown actor inventory. Root device
tests also change child credentials during the interrupted preparation window.
Pending close fences deny new startup and cancel a prepared child before exec;
the running guardian waits for network denial and permit revocation before
stopping an existing actor. See [durable closed requests](CLOSED_TRANSITION.md).

A separate bounded real-launcher trial passed: four protected workers were
stable after warm-up, duplicate startup was rejected, a fixture Paused request
stopped them, closed reconciliation revoked the permit/cleared the journal, and
another start was denied. The original launcher/configuration/boot identity and
four ordinary workers were restored. This checked process compatibility and
lifecycle, not a new spoken-response test. No microphone stream was captured.
Real reports and configuration backups remain in ignored `build/`.

The administrative trial restores the pre-test Alice state. That rollback is
not the recovery policy for an installed Lisa-mode failure; the Paused request
in this trial belongs only to its private fixture.

## Deployment still required

The backend is not hooked into init or the HA mode selector. A development
[closed-transition engine](CLOSED_TRANSITION.md) now connects a durable fence to
policy verification and tracked stop. Production integration must still
coordinate selective firewall/old-flow quarantine, all vendor roles
including diagnostics, DNS/time profile choice, telemetry/relay handling and
boot ordering before publishing permits or reporting Lisa isolation. Independent
root SSH recovery and unrelated applications' internet access must remain intact.
