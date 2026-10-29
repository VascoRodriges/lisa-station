# Journalled policy and explicit opening recovery

The native adapter now composes the [opening transaction](ALICE_RETURN.md),
close engine and [generation policy](EPOCH_POLICY.md) on the real speaker kernel.
It uses private test intents and own loopback sockets. **It is not installed in
the production coordinator and has not switched the actual Alice services.**

## Ownership and mutation

Before its first rule the adapter checks the unused label namespace, absence
of its chain names/foreign CONNMARK writers and a caller-supplied actor scope.
It publishes an immutable owner bound to the boot, chain names, initial revision
and mask. A separate journal records the current/previous generation and mutation
phase. Private single-link files and an exclusive lease protect these records;
corrupt, unsafe or stale ownership is refused. The owner uses atomic no-replace
rename, avoiding a temporary hardlink on the live journal. This operation was
verified on the speaker's persistent filesystem; unsupported rename fails.

Recovery accepts only known ordered subsets: group rules, marking rows for the
journalled current/previous generation, and protected partial open tails. It
installs both-family denial before repairing marking rows. Unknown, duplicate
or reordered rules are not removed to make verification succeed. No global
table flush, connection purge, default-policy change or UID-0 ban is used.

Opening prepares a fresh unused generation under denial. Release requires the
matching Alice revision/current-boot permit and a pending opening journal at
the permitted phase. The opening executor retains the exclusive intent lease
until final verification/fence removal. No standalone startup or saved phase
can substitute for these checks. Closing retains denial for retired generations.

The native lab entry points refuse installed production state and require the
supported model, read-only root, administrative credentials, a private fixture
and the shared trial mutex. Their actor census deliberately excludes the stock
unlabelled processes and permits an untagged test holder to retain its old socket.
That exception is not a production vendor/FD absence check.

## Composed evidence

The **1,170-event trial** passed six normal cases and **32 SIGKILL cases**, one
after each durable/kernel-mutation checkpoint in opening. TCP/unconnected UDP
and IPv4/IPv6/mapped paths are exercised across the cases.

Every interrupted opening retained its startup fence and boot choice Paused,
including after Alice intent/permit publication. The old socket attempted a
send while the interrupted policy was still present: it remained denied, its
conntrack mark was unchanged and the unrelated control still worked. The driver
then explicitly requested denial and explicitly retried the same opening.
Preparation was reverified, the revision committed only once, the new socket
worked and the old one stayed denied. Final close blocked both generations.

This supplied 482 socket checks, 146 tuple/mark observations and 217 observed
controller operations with working IPv4/IPv6 root controls. The completed capture
was evaluated offline by the strict protocol checker after that checker was
implemented; no additional device trial was needed for the evaluator changes.
Stock process identities/configuration/boot were unchanged and all firewall
rules restored. There was no audio capture or firmware write.

An initial fixture-construction error joined a heredoc delimiter to the next
function, producing no events and never executing the coordinator. The failed
capture was retained privately. After proving that the owner/driver and all own
chains were absent, only its empty trial mutex was removed. The delimiter was
fixed and the complete trial above ran without intervention.

The native store passed 76 tests; pure rule parsers exercised 256 marking
subsets and 16 denial subsets on the speaker and a fortified Linux host. The
legacy label regression passed 60 checks on both. Ruff, source privacy checks
and **840 Python/HA tests** passed; the native matrix now contains 36 targets.

Qualified ARM SHA256:

- composed controller probe: `dfc663442dde2dd2413e0f3a5acecb2d261158c95d20790894dbbc0f4463a2c7`
- recovery socket probe: `8a9aa4ea21fca2113211d63527c5934966a53e6734fa1c8bc7c5e4ae3e705322`

```sh
python controller/build.py --target epoch-mutation-probe
python controller/build.py --target epoch-policy-probe
python -m controller.qualify_epoch_mutation YOUR_SPEAKER_SSH_ALIAS \
  --ssh-config YOUR_SSH_CONFIG --run-composed-policy-trial
```

## Deployment remains unfinished

Recovery in this trial was **explicitly driven by the fixture**. A permanent local
supervisor that finishes pending denial after controller death, independent of
HA/NAS, is still required. The bounded cleanup watchdog was prepared but not
fault-injected here. The new adapter's close/reservation mutation checkpoints
have not received the same complete SIGKILL matrix as opening.

[Closed-mode changes and early cancellation](CLOSED_MODES.md) now have completed
close journal rollover and a separate composed trial. Production actor/FD census, platform private
filesystem/IPC boundaries, actual vendor admission, boot/direct-init gates,
installer and power-loss acceptance also remain. Neither this lab component nor
its mode names certify whole-device isolation or enable the HA mode selector.
