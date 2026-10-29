# Independent emergency denial and a latched fault

The staged emergency adapter pre-reserves a second selective denial path while
the primary epoch policy is verified closed. Its separate immutable owner binds
the boot, primary namespace, initial revision and mark mask. It publishes that
owner before creating any rules and refuses to adopt existing unknown chains,
references or contents. Known ordered partial chains can be completed while
admission remains closed.

The armed chains are complete but unhooked. They contain the four declared
service-group drops and a drop for any nonzero generation in the already owned
upper-byte conntrack namespace. They do not mark traffic or drop unrelated UID-0
applications. There is no blanket device internet block.

After a primary-journal fault, the cached trusted scope can activate those
pre-reserved chains without parsing or repairing the damaged primary files:

1. Publish and sync an independent `fault.request` with no-overwrite rename.
2. Verify the reserved chain contents and known hook subsets, then install the
   selective OUTPUT/INPUT barriers for both IP families.
3. Verify those barriers before revoking the vendor permit. Production actor
   shutdown must follow this barrier, using the actual guarded-role callbacks.

This fault remains latched. Its presence, an unsafe object at its path or inability
to inspect it makes the boot-choice helper select Paused. It also blocks new
service admission, raw Alice-intent commits and explicit opening transactions.
The packet-release callback independently checks it. A close does not clear it.
There is deliberately no automatic unlatching or file-deletion recovery API.

The optional bounded emergency watcher checks journal-clear runtime state under
transition-before-epoch locks. It compares the mode, primary journal, real rules
and permit. Valid lock contention causes waiting. The lab opener retries only
`OPEN_BUSY`, with the same expected revision and a bounded deadline; policy or
journal failures are not retried as if they were contention.

## Evidence

A **32-event own-flow trial on the speaker** started with armed unhooked chains,
then explicitly opened its private Alice intent. It damaged both the primary
owner and epoch records while the old labelled UDP flow existed. The watcher
latched the fault, installed the independent barrier and revoked its permit.
The damaged files and original Alice intent were preserved.

All **15 UDP checks** passed: the old socket stayed denied, new sockets from
each of the four declared groups were denied, a root-owned reply on the old
labelled connection was denied, and unrelated control traffic worked. Native
IPv4/IPv6 administrative controls also succeeded. This is an IPv4 UDP fault
trial, not a new TCP/IPv6/mapped emergency-flow matrix.

The fixture restored only its throwaway primary record bytes and tried an
explicit opening. The retained fault still denied it without policy mutations;
the boot-choice helper remained Paused. It did not delete the fault fence or
change installed production state. All owned rules were then removed and the
full firewall snapshot restored. Stock processes, boot and configuration were
unchanged; no audio was captured.

The first attempt stopped before corruption testing because a valid transition
lease was busy; cleanup then encountered a dying child's xtables lock. That
attempt is not qualification evidence. The lab opener gained bounded busy-only
retry, and cleanup now waits for xtables and tolerates a confirmed absent chain
from an earlier partial cleanup. Only the failed fixture's owned rules were
recovered before the successful run; neither global flush nor stock-service
restart was used. Regression tests cover these cleanup boundaries.

The native fault/ownership fixture passed **22 checks** on persistent speaker
storage and a fortified host. The updated service-admission/opening probes passed
**41/157 checks** on both systems; the store/recovery/parser fixtures also passed.
Ruff, the public-source check and **978 Python/HA tests** passed. The build matrix
remains 36 targets.

Qualified ARM SHA256:

- composed emergency watcher: `47787e88c3557837b527c3972bbc5ef5f7c13ba6c448042020dcdbda18397774`
- socket fixture: `38c84371b0e5f745db457c8e097464705e494a0072abbf13e15fec618644f284`
- service admission: `4137389f3d1206b376ac164f433020e6e69f701521b308f18a137bb3235ce9f3`
- explicit opening: `5af8f60ae25efd996ce2d07ec067ee9cd3d2ee353e597bdd731f613a007cd4bd`

```sh
python -m controller.qualify_emergency YOUR_SPEAKER_SSH_ALIAS \
  --ssh-config YOUR_SSH_CONFIG --run-private-corruption-trial
```

## Remaining composition

This is a bounded SSH-parented laboratory watcher. Its cached emergency path was
qualified for primary-policy record corruption after healthy intent-journal
inspection. Permanent supervision, restart reconstruction of that cache,
integration of every journal-fault path, explicit repair/unlatching and supervisor
death acceptance remain required. A damaged emergency chain is refused rather
than overwritten or silently declared closed. Failed fault publication still
attempts selective denial but cannot report a durably successful close.

The trial callbacks do not stop actual vendor services. Production sender/FD
inventory, filesystem/IPC boundaries, boot admission, installation and cold-boot
tests remain unfinished. The new fault helper does not imply that a production
boot hook or HA mode selector is installed, or that full isolation is verified.
