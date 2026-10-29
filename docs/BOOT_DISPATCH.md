# Bounded boot dispatch

The development tree now includes `station-init`, a fixed entry-point runner,
and an exported rcS dispatcher. **Neither is installed into the real boot path.**
The [closed bootstrap coordinator](BOOTSTRAP.md) now exists, but its service
handlers and transactional installer are still required; copying this dispatcher
alone would leave its gated services unavailable.
The HA release remains diagnostic and `isolation_verified` stays false.

## Fixed boundary

`station-init` accepts only bootstrap, hardware, diagnostics-stage, independent
time/DNS and vendor-start operations. It checks the actual supported model and
executes one fixed coordinator path. It cannot accept a command, program path,
PID or free-form arguments. Missing, linked, set-ID, capability-bearing or
insecure executables are rejected. A missing coordinator does not execute a
stock fallback.

The runner closes inherited descriptors, replaces standard streams with
`/dev/null`, clears the environment, fixes PATH/locale/working directory,
disables core dumps and arms parent-death signalling. It requires a reapable
child rather than running with ignored SIGCHLD. Operation deadlines range from
4 seconds for bootstrap to 45 seconds for vendor startup. On timeout it signals
only its own unreaped child and process group, then reaps that child.

The exported dispatcher retains ordinary init ordering and isolated sourcing
of reviewed `.sh` scripts. It routes the ALSA hardvolume daemon, audio monitor,
clock, resolver and main vendor startup through the fixed runner. Failed
bootstrap suppresses vendor and diagnostics calls; mixer, clock and DNS are
still attempted through their guarded handlers. Bootstrap runs only after successful
normal loopback initialization, before Wi-Fi and the first gated service; a
missing or failed loopback stage keeps vendor gates closed while local services
remain independent. A failed gated call never invokes
the original script. Existing network initialization still runs, and the
unchanged independent SSH init is called before the first gated service as well
as at its usual position. The coordinator's actual ready/mode state must be
observed separately; rcS exit status alone is not a privacy claim.

The hardvolume init entry is a hardware dependency, distinct from the four
previously guarded vendor roles. Its [local adapter](HARDWARE_VOLUME.md) now
preserves mixer behavior while denying networking and exposing no PCM nodes.
The boot dispatcher remains uninstalled.

## Evidence

The bounded-runner probe passed **18 checks on the speaker and a fortified
Linux host**: fixed target validation, invalid deadlines, ignored SIGCHLD,
environment/FD/core-dump boundaries, successful and failing helpers, timeout,
subsequent recovery and child reaping. Host fixture binaries must have trusted
permissions; a group-writable build is correctly rejected.

The dispatcher probe passed **24 checks across seven cases on the speaker**. It
uses the actual exported script, real BusyBox shell and bounded runner in a
private mount namespace/chroot with synthetic init scripts. Normal startup,
failed bootstrap, missing runner, failing stage handlers and a hanging bootstrap
all preserve synthetic recovery and prevent original vendor fallbacks. Failed
and missing loopback initialization also keep vendor gates closed while still
attempting mixer, clock and resolver. Sourced
script variables do not leak to later init entries. No real init script, audio
device, network service or hardware setup is executed. The firmware's set-ID
BusyBox is copied as a plain private executable for this fixture; production
target validation is not weakened.

The actual uninstalled runner separately refused bootstrap/vendor-start with
the fixed coordinator absent. ARM and host builds exported identical dispatcher
bytes. The real boot/recovery file digests, read-only rootfs, current services,
OTA protection and idle lab state were preserved. The existing Python/HA suite
passed **597 tests**; with the coordinator/state probe the native matrix is 29.

Qualified digests:

- station-init: `ef14d81afe9578e026ad197bde25e46bf3c7e8a5ccf85ed268a09b729fc2010c`
- runner probe: `c031c81bedb5eedd395070f6dbcb3a796e339c5fdb4b41f72931bffd997f830c`
- dispatcher probe: `d0e57bb10e77ec656787b174fb8f39c5b0930d0d981df6d8ebd2ca04113778a1`

```sh
python controller/build.py --target station-init
python controller/build.py --target boot-runner-probe
python controller/build.py --target boot-dispatch-probe
```

## Deployment still required

Independent [boot-failure handling](AUXILIARY_BOOT.md) is now qualified.
Complete mode composition; the closed
bootstrap, constrained mixer, [resolver](INDEPENDENT_DNS.md) and
[clock](INDEPENDENT_TIME.md) are qualified separately. Bind every vendor admission to
the verified current boot and explicit intent. Prepare an immutable private
firmware/init manifest, reject unsupported entry changes and make direct init
calls obey the same gates. The installer must verify all payloads/backups before
its atomic boot-hook commit, preserve independent SSH/OTA protection, restore
the normal read-only root mount and provide explicit rollback. Power-loss and
cold-boot acceptance remain pending. No real boot file is changed by these
qualification components.
