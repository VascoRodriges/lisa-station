# Audio-free SDK compatibility diagnostic

The diagnostic composes private platform storage, a complete capability drop,
fixed worker identity, thread-only creation and self-signalling with a policy
that denies every socket family and outbound address-bearing operation. The
policy applies only to these disposable children. It does not disconnect the
speaker, alter firewall rules or stop/restart the ordinary vendor services.

It first executes our own ELF in the prepared view, then the actual platform and
media SDK separately. Both receive synthetic identity seeds in fresh private DATA.
The immutable firmware configuration is copied to a private file; real account or
token files are never read. No ALSA device, RMS shared object, keymaster, host bus,
log stream, administrative root or inherited host channel is available.

The trusted parent checks the mount namespace, read-only root, bounded private
mounts, executable object, fixed UID/GID, zero current/bounding/ambient capabilities
and inherited descriptors before execution. Standard input/output use devnull;
standard error uses one new file in private DATA. All host directory and other
file descriptors are closed before entering the view.

Linux 4.9 omits NoNewPrivs from proc status. The trusted prepared child checks
PR_GET_NO_NEW_PRIVS and seccomp before its initial stop; the irreversible setting
survives exec. Any exported proc value must still agree.

## Reviewed boot metadata dependency

Without kernel boot parameters, both SDK modes aborted during early initialization
with bad_optional_access. The SDK preparation mode now admits only the fixed
`/proc/cmdline` object. It must be a root-owned read-only regular file on procfs;
its descriptor is pinned, bound read-only/noexec and closed before exec. Parent
inspection checks the same object and read-only mount. No PID or general proc
view is provided, and its contents are not added to diagnostic reports.

The ordinary storage API still omits this dependency. Its two-epoch kernel control
now passes **188 storage checks**, explicitly including absent cmdline in both
default views, plus the existing **50 synthetic seed checks**.

## Bounds and observations

Each worker has a 6-second trace deadline, 4/5-second CPU limit, 96 MiB data limit,
256 MiB address-space limit, the firmware’s 1 MiB stack limit, 128 descriptors and
2 MiB file-size limit. Core dumps are disabled; a piped host core handler causes
preflight rejection because such handlers ignore RLIMIT_CORE. No sysctl is changed.
The tracer also bounds stops and recorded thread identities. Parent-death SIGKILL,
ptrace EXITKILL and a separate driver watchdog cover loss of supervision.

The own-ELF control checks socket/signal denial, pthread operation and a known
missing pathname. It then intentionally aborts with eight further pthreads alive.
The parent drains the entire group. A vanished thread may lose a final register
snapshot during group exit; this is counted explicitly. Only kernel-reported
children/clone events are enrolled, with the worker’s clone filter preventing
process forks. An unavailable final snapshot does not relax any kernel policy.

The qualified five-event trial observed **16 platform threads and 19 media threads**
created before SDK termination. Platform made three socket attempts; media made
nine. All socket creation was denied by the per-process kernel policy. The SDK
reported a denied D-Bus open in platform mode and inability to create its time
provider in media mode. Both terminated with SIGABRT and were fully reaped.
These are compatibility failures, not functional success.

The tracer records syscall numbers/results and bounded pathname arguments for
fixed filesystem syscall ABIs. It never dereferences read/write buffers, audio or
credential objects. Up to 64 KiB of each private stderr and bounded failed pathname
metadata remain in the generated root-private lab directory for diagnosis. These
journals, firmware configuration and real boot parameters are never public assets.

Stock process identities, boot/configuration and firewall rules matched before and
after. Unrelated root IPv4/IPv6 loopback controls worked. No microphone was opened,
real identity seed read or production state installed. Ruff, the public-source
check and **1237 Python/HA tests** passed. The build has **39 native targets**.

Qualified SDK diagnostic ARM SHA256:

`00e9e17524961d6c2d40b336f1ebb11915cd3897f8757a0be398ede58cdfc1c6`

Default storage control ARM SHA256:

`a35c771ca26d68cc217502a1015ce2d4f97dc9c63d662579890ba06b02f42c9a`

```sh
python controller/build.py --target platform-sdk-probe
python -m controller.qualify_platform_sdk YOUR_SPEAKER_SSH_ALIAS \
  --ssh-config YOUR_SSH_CONFIG --run-audio-free-sdk-diagnostic
```

## Remaining work

The SDK�s static imports/configuration also identify a GStreamer network time
provider. Its [documented constructor](https://gstreamer.freedesktop.org/documentation/net/gstnettimeprovider.html)
exports a clock on a network address/port and can fail. The observed media error
is consistent with deliberate socket denial; it does not establish a missing
hardware clock or justify access to live RMS/audio. The dynamic dependency still
needs verification before designing a clock adapter.

The next step is reviewed D-Bus/time-provider compatibility through explicit
capabilities or narrow adapters, with bounded queues and receiver lifecycle checks.
The host bus, broad UNIX socket creation and host DATA must not be reopened merely
to make the SDK start. Actual SDK batch/queue materialization, approved identity
lifecycle, hardware/audio compatibility and permanent worker supervision remain
unfinished. This trial installs neither production mode switching nor boot control.

See Linux [ptrace(2)](https://man7.org/linux/man-pages/man2/ptrace.2.html) for trace
and EXITKILL contracts, and the [worker boundary](PLATFORM_WORKERS.md) for clone and
signal restrictions. This diagnostic is not a complete vendor sandbox or a ready
replacement for the ordinary assistant.
