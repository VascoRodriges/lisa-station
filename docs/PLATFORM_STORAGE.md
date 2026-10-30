# Platform storage epoch foundation

The new native boundary gives a prepared platform child a read-only root and
separate bounded writable DATA, TMP and shared-memory filesystems. It never binds
or recursively copies the shared vendor DATA tree. Retained sound logs, events,
session data, capability state and telemetry queues therefore do not appear in a
new storage epoch.

Only five fixed staging names are accepted: `account_storage.dat`, `gsdkTokens.json`
and three empty registration markers. Staging must be private; each input is a
root-owned, single-link regular file opened without following symlinks. Identity
files are bounded to 64 KiB and markers must be empty. Copies use exclusive creation,
explicit private permissions and before/after inode, size, mode and timestamp
checks. Existing outputs are not overwritten. Source replacement during copying
is rejected and the incomplete output removed.

This validates file objects and bounds, not the semantic contents of an identity
database. Production seed approval, credential refresh and persistence policy
remain separate work. The fixture uses only synthetic seeds and never reads real
account/token files.

The storage child sees read-only libraries/vendor code and a pinned private
configuration. Its writable mounts are non-executable and bounded to 32 MiB DATA,
16 MiB TMP and 4 MiB shared memory. Host proc, administrative roots, system logs,
D-Bus, keymaster and audio devices are absent. Host directory/file descriptors
are closed before entering the view.

After preparation, the child has group 57342, no capabilities, no-new-privileges
and seccomp restrictions retained across exec. The storage-only policy blocks
named/abstract UNIX socket creation, UNIX socketpairs, host signalling and
keyring calls. Bounded anonymous pipes provide the probe control/report channel;
ordinary IP socket creation remains possible. These restrictions
are local to this child. The separate [SDK diagnostic](PLATFORM_SDK_DIAGNOSTIC.md) can additionally
admit only pinned read-only boot cmdline metadata; this default storage view still
hides it in both qualified epochs. Reviewed SDK IPC/hardware compatibility is still needed
before replacing actual platform workers.

## Evidence

The **six-event speaker trial** executed our own ELF through the prepared vendor
executable alias in two fresh storage epochs. It did not execute proprietary SDK
code. Both epochs started with synthetic identity copies and absent old queue
paths, then wrote synthetic state and queue files entirely inside their private
DATA mounts. Private identity refresh did not change the staging source.

The coordinator retained the first epoch's directory while starting the second.
The second still received fresh storage and original seed bytes. Parent inspection
verified distinct mount namespaces/filesystems, the executable inode, private seed
copies and absence of leaked host file/directory descriptors. Root IPv4/IPv6
loopback controls worked throughout. Releasing the final directory references
completed the synthetic lifecycle.

The trial passed **192 storage checks**. **50 seed checks** passed on the speaker
and a fortified Linux host, including unsafe permissions, hard links, symlinks,
FIFOs/directories, oversized/empty identity inputs, nonempty markers, restrictive
caller umask and deterministic replacement of a pinned input during copying.

All fixture cleanup was confined to the generated private prefix, fixed synthetic
filenames and recorded dead process identities. A bounded watchdog covers driver
loss; the shared trial lock is released only for its matching ownership token.
Stock process identities, boot/configuration and firewall rules were unchanged.
No audio, real identity data or proprietary process was involved.

Ruff, the public-source check and **1398 Python/HA tests** passed. The build matrix
now has **45 native targets**, including the storage probe and its host seed checks.

Qualified ARM SHA256:

`e8ef5f9b3c1a47f4b6d07166a1e0a22e62dde500b2b24a8378d78b250939d0e8`

```sh
python controller/build.py --target platform-storage-probe
python -m controller.qualify_platform_storage YOUR_SPEAKER_SSH_ALIAS \
  --ssh-config YOUR_SSH_CONFIG --run-synthetic-storage-trial
```

## Remaining boundary

The [audio-free SDK diagnostic](PLATFORM_SDK_DIAGNOSTIC.md) uses this foundation,
with explicit compatibility failures. The [own-client binding variant](PRIVATE_CLIENT_BINDING.md)
now adds a pinned read-only preload inside the private filesystem; default calls
still expose neither `/opt` nor the binding marker. Functional SDK and permanent
speech-service composition remain unfinished. It does not demonstrate SDK batch materialization,
hardware/audio compatibility, complete receiver/IPC isolation or production mode
switching. Existing collector/telemetry DATA exposure also requires review rather
than being treated as safe merely because it is read-only.

The next composition must admit only approved identity state, keep queues ephemeral,
control explicit IPC/hardware dependencies and verify actual worker lifecycles.
Production control/boot installation and full privacy acceptance remain unfinished.
