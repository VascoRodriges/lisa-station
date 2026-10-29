# Reconstructing emergency denial after coordinator death

A fresh bounded coordinator can now reconstruct the emergency scope without
reading either damaged primary epoch record. It accepts only the separately
published private immutable owner, its canonical bytes, current boot and configured
namespace. It then checks the actual complete reserved chains and known ordered
hook prefixes. Missing, foreign or unsafe ownership is refused; kernel rules alone
never establish ownership.

The reconstructed cache authorizes completing selective denial only. It does not
authorize Alice, repair primary files, remove the persistent fault or reset intent.
The same transition lease serializes this operation with explicit requests. An
interrupted activation can finish its known partial prefix idempotently.

## Evidence

The speaker passed a **53-event transaction with nine consecutive SIGKILLs**.
The first coordinator was killed just after syncing the fault fence. A fresh
coordinator was then killed at each later checkpoint while advancing that same
emergency transaction:

| Checkpoint | Completed operation |
|---|---|
| 1 | Durable fault publication |
| 2–4 | IPv4 OUTPUT group, OUTPUT label and INPUT label hooks |
| 5–7 | IPv6 OUTPUT group, OUTPUT label and INPUT label hooks |
| 8 | Verification of both-family barriers |
| 9 | Durable vendor-permit revocation |

Both primary epoch records remained damaged throughout the restart sequence.
After checkpoint 8, the permit was still present, but the actual old flow, all
four groups' new sockets and a root-owned reply were already denied. Its retained
tuple still had its original generation. After checkpoint 9, another fresh
coordinator verified the existing denial and absent permit without reopening.

Making the independent owner publicly readable, then adding another hard link,
caused separate restart requests to be refused. Before/after rule snapshots were
identical. Restoring only this private fixture's original permissions/link count
allowed denial verification again. Later restoration of the throwaway primary
bytes still did not bypass the retained fault: explicit opening was denied and
boot choice stayed Paused.

All **15 IPv4 UDP checks**, unrelated IPv4/IPv6 administrative controls and cleanup
checks passed. Stock process identities, boot/configuration and the full firewall
snapshot were preserved/restored. The fixture did not capture audio or start/stop
actual vendor actors. This is one progressively interrupted transaction, not nine
independent fresh-policy trials or a physical reboot test.

The native emergency fixture passed **36 checks** on persistent speaker storage
and a fortified Linux host, including independent scope reconstruction with damaged
primary files and refusal of stale/malformed scope records. Existing 76 store,
33 recovery-decision and 256/16 parser cases passed. Ruff, the public-source check
and **1040 Python/HA tests** passed; the native matrix remains 36 targets.

Qualified ARM SHA256:

- composed coordinator: `1d417f45bb8e6a56bf3d15c37502cee7164bfd8cf420f7e27963962dffe33bfa`
- socket fixture: `38c84371b0e5f745db457c8e097464705e494a0072abbf13e15fec618644f284`

```sh
python -m controller.qualify_emergency_restart YOUR_SPEAKER_SSH_ALIAS \
  --ssh-config YOUR_SSH_CONFIG --run-private-restart-trial
```

The harness refuses installed production state and concurrent speaker trials.
Its bounded cleanup validates the independent owner before removing its own rules
and waits for dying xtables children. It never deletes a fault fence for retry.

## Remaining work

Restart reconstruction is still a fixed laboratory command under an SSH parent,
not the permanent supervisor or an installed boot recovery path. All intent-journal
fault paths still need the same barrier-before-stop handling, followed by permanent
supervision, production actor/FD and filesystem/IPC boundaries, explicit repair,
installation and physical power-loss/cold-boot acceptance. The diagnostic HA
integration still has no production mode selector or complete isolation claim.
