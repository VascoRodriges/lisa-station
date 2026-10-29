# Independent hardware volume

The staged coordinator now implements fixed hardware start/status/stop handlers
for the verified Station Midi mixer. **No real boot hook is installed.** Explicit
Alice return and the installer remain incomplete; the HA release
still provides diagnostics rather than a production mode switch.

## Local adapter

The fixed firmware `hardvold` maps the synthetic Master control to the calibrated
amplifier control. The adapter keeps its existing calibration file and exposes
only `/dev/snd/controlC0`, null, its executable and read-only libraries. A minimal
ALSA control configuration avoids the normal PCM/capture plugins and state.
Its private mount namespace/chroot has a read-only root and no host data, proc,
sysfs, D-Bus, logs, shared memory or capture/playback PCM nodes.

Before exec it clears supplementary groups and every effective, permitted,
inheritable, bounding and ambient capability, sets and directly checks NNP,
and installs seccomp. Networking, socket pairs, process creation, identity
changes, mounts, tracing, cross-process memory/FD access, outgoing signals,
clock control and IPC queue interfaces are denied. Inherited descriptors are
closed. Linux 4.9 does not expose NoNewPrivs in proc status: NNP evidence comes
from the preparation's direct kernel query and its exec inheritance, not an
invented proc field. Parent inspection verifies identity, credentials, all five
capability sets, seccomp, private filesystem, hidden nodes and control-only FDs.

The independent supervisor has a private boot-bound process journal, serialized
start and a root-authenticated UNIX control channel. Repeating start returns
the verified existing actor. Stop contacts its authenticated guardian, never
signals an arbitrary journal PID. Guardian death kills its child; child process
creation is forbidden. It does not read a vendor permit or depend on HA/NAS.
The coordinator now permits [independent startup](AUXILIARY_BOOT.md) without
valid vendor state or policy; opening real Alice mode remains a separate unfinished transition.

ALSA software controls can survive their daemon. After proving no mixer daemon
exists, startup snapshots and removes only the compatible unlocked **user**
Master control so the fixed daemon can recreate it, then restores its value.
Wrong names, hardware controls, locked/owned controls, different types, counts,
indices or ranges are refused. Normal stop retains the software value. A
separate lab-only stale-control operation supports the bounded stock handoff;
it is unavailable with an installed production state.

ALSA's [control interface documentation](https://www.alsa-project.org/alsa-doc/alsa-lib/group___control.html)
defines user-element, lock, owner, type and range inspection; the kernel's
[control implementation](https://kernel.googlesource.com/pub/scm/linux/kernel/git/torvalds/linux/+/7846b12fe0b5feab5446d892f41b5140c1419109/sound/core/control.c)
reports an unlocked owner as `-1`.

## Evidence and limits

The actual 26-event speaker trial composes the prior bootstrap policy fixture
with a temporary mixer-only handoff. It refuses duplication of stock hardvold,
starts and inspects the real guarded daemon, verifies that a small Master change
moves the calibrated hardware level, restores the original level and exercises
private Paused/Alice/Lisa intent without granting a vendor permit. It then stops
only the guarded mixer, restores the stock mixer and verifies stable recovery.
The slowest hardware handler took **351 ms**, below its four-second init bound.
Stock voice-service identities and boot/configuration were preserved and all
owned firewall rules were removed. No PCM or microphone capture was performed.
The existing amixer warning about the software control's missing TLV is retained
in private stderr; success requires independent value/mapping and runtime checks.

The auxiliary probe passed **50 checks on the speaker and a fortified Linux
host** using only its own actors: kernel denials, incompatible-control rejection,
authenticated status/stop, repeat start, stale-boot refusal, restart, guardian
SIGKILL/child death, corrupt journal and ignored SIGCHLD refusal. It never opens
hardware. Python/HA tests passed **620**; the native matrix now has **30** targets.

- coordinator ARM SHA256: `61dedb42e5450a2b82bd9080c2a974d668696bc85e460e6a84e87c4b9aa2a29d`
- auxiliary probe ARM SHA256: `3506ef6bdf0192e85b3fc855f098981d1cc5b1954fc37b074c7020a82d5e198f`

Ordinary Alice runs outside this guard after the lab cleanup. This component is
not a whole-speaker isolation claim. Boot installation, cold/power-loss tests,
guarded vendor/voice/mode composition and permanent installation are still pending.
