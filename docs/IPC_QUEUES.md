# Guard against kernel IPC queues

The reviewed speaker kernel exposes System V IPC tables but lacks IPC namespaces.
The observed shared-memory/message/semaphore tables were empty. Empty tables
are a snapshot, not an enforcement mechanism or permission to remove host data.

New guarded vendor processes now inherit a separate seccomp filter that denies
System V message queues, shared-memory attach/control, semaphore operations and
POSIX message-queue operations. It covers ARM's legacy `ipc` multiplexer, direct
syscalls and available time64 variants. Noncanonical x32 syscalls are denied in
the Linux x86-64 qualification build. Unrecognized audit architectures terminate
the process rather than bypassing the filter.

The filter is installed by the shared vendor identity primitive before exec.
It composes with the existing credential/capability/startup guards; exec and
fork cannot remove a filter. Host queues, permissions and unrelated processes
are unchanged. No blanket device internet policy is introduced. AF_UNIX and
ordinary IPv4/IPv6 socket calls remain outside this filter's deny list.

## Verification

The own-queue probe creates one private synthetic System V message, installs
the filter in a child and execs its own executable. The child verifies inherited
restrictions and reinforces the filter before using even the supplied own queue
ID. It cannot consume that message. The unfiltered parent must still read its
original byte and remove its queue. Remaining forbidden calls use invalid IDs
without allocation, so a failed test cannot modify an unrelated IPC object.
Own UNIX communication and ordinary IP socket creation remain functional.

The host suite passes **28 checks**, and the ARM suite passes **30 checks**,
including ABI variants available in that target's headers. Reports and binaries remain in
ignored `build/`; the probe does not open stock IPC payloads or a microphone.

The four-worker stock launcher passed its bounded startup/shared-identity and
single-group close trial with the added filter. The independent ALSA diagnostics
trial also passed and restored its ordinary service and bus registration. These
checks establish process/lifecycle compatibility, not live voice or every audio
feature. Original launcher, boot and firmware configuration were preserved;
ordinary workers and diagnostics were restored. No production filter is installed.
Two consecutive unmodified paired-epoch trials also passed with the added
filter and corrected private peer/startup ordering. Readiness diagnostics now
separate live actor, identity, filesystem view and resource readiness; no queue
or log payload is included in those status fields.

```sh
python controller/build.py --target ipc-guard-probe
# Linux host self-test:
cc -O2 -Wall -Wextra -Werror controller/ipc_guard_probe.c -o build/ipc-guard-host
./build/ipc-guard-host --selftest
```

This prevents these kernel-queue interfaces only for newly guarded actors.
Existing unguarded services are not retroactively filtered. It does not deny
D-Bus/abstract UNIX sockets, named shared files, inherited mappings or copied
receiver data. Those remain part of [peer/holder](IPC_PEERS.md) and
[composite-role](COMPOSITE_ROLES.md) work. Production boot installation, complete
sender migration, UDP/old-flow composition and voice acceptance remain pending.
The released diagnostic integration and `isolation_verified: false` are unchanged.
