# Platform worker thread and signal boundary

The native worker guard is installed in each freshly forked, single-threaded
child after credential setup and before exec. It binds its signal policy to that
child’s actual thread-group ID. Installing one filter in a launcher and then
forking platform/media workers would bind the policy to the wrong process.

Workers can create threads only with shared memory, signal handlers, filesystem
context and descriptor tables. Only the reviewed pthread clone flags are allowed;
process forks, vfork, namespace changes and separate thread descriptor tables
are denied. Pointer-based clone3 returns ENOSYS so libc can use the inspected
legacy clone interface. The x86 host path also rejects the alternate x32 ABI.

kill and queued process signals require the fixed worker PID. Thread signals
require that same thread-group ID; the kernel checks that the requested thread
belongs to it. PID zero, process groups, unrelated processes, tkill and pidfd
signalling are denied. The guard fixes parent-death SIGKILL and prevents the
worker from changing it. Restrictions persist across exec and into new threads.

This is a process-lifecycle layer. It does not drop capabilities, prepare private
storage, close inherited descriptors or block network/IPC by itself. Those layers
must be applied separately. The storage-only fixture still uses its stricter
all-signals-denied policy; stacking that policy would not enable SDK self-signals.
The permanent trusted worker manager and actual SDK composition remain unfinished.

## Kernel evidence

A bounded own-ELF trial passed on the speaker: **18 parent/lifecycle checks and
92 worker checks**. Two children installed separate guards before exec. Both
performed real pthread creation, self-signals, thread signals, cancellation and
join; prohibited process/signal operations failed. The trusted parent could still
create and reap its own control child.

A third own worker exited its leader while leaving a pthread alive. After its
manager exited, parent-death SIGKILL terminated the remaining thread group, which
the fixture subreaper collected. All processes were newly created by the fixture;
no stock process was signalled or restarted.

The fortified x86 Linux host passed the same lifecycle checks plus four additional
ABI checks (96 worker checks). The public build now includes **38 native targets**.
Ruff, the public-source check and **1155 Python/HA tests** passed.

The three-event speaker trial retained stock process identities, boot/configuration
and firewall rules. No proprietary executable, real identity seed, microphone or
production mode was accessed. Driver loss is bounded by parent-death signals,
native time limits and an independent watchdog. Cleanup retains the trial lock if
any instance of that exact own-ELF artifact remains.

Qualified ARM SHA256:

`f31fd9d39021728a446f63b1b5c92682e603a34d10a2cf82ee4ef81064d61a81`

```sh
python controller/build.py --target platform-worker-probe
python -m controller.qualify_platform_worker YOUR_SPEAKER_SSH_ALIAS \
  --ssh-config YOUR_SSH_CONFIG --run-own-worker-trial
```

The next step is composing this guard with private storage for an audio-free,
network-denied SDK diagnostic. A failed SDK initialization is diagnostic evidence,
not functional acceptance or proof of complete vendor isolation. Permanent mode
switching and boot installation have not been installed by this trial.

The syscall contracts are documented in Linux [clone(2)](https://man7.org/linux/man-pages/man2/clone.2.html),
[tgkill(2)](https://man7.org/linux/man-pages/man2/tgkill.2.html) and
[seccomp(2)](https://man7.org/linux/man-pages/man2/seccomp.2.html).
