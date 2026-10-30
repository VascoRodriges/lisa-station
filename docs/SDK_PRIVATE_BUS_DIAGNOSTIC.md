# Audio-free SDK admission beside the private bus

The explicit `--run-sdk` lab mode in `private_bus_probe.c` now admits the actual
platform SDK beside the private daemon and sealed byte relay. It qualifies the
storage, descriptor, binding and process boundaries. **The SDK does not yet
communicate successfully with this bus or implement a usable Alice mode.**

This is separate from the default own-client test and from production switching.
The wrapper refuses installed production state and any concurrent device trial.
It does not stop ordinary station processes, change the device firewall,
capture audio or forward the host bus. Other device applications retain internet.

## Before the first SDK instruction

The common coordinator creates all three children and preadmitted stream objects.
Cached peer credentials still identify that creator; current holder ownership is
checked separately. No cached-parent validator is relaxed.

The SDK child receives a disposable platform filesystem, a private copy of the
immutable firmware profile, five synthetic identity seeds and the pinned,
read-only client library. Host accounts, writable host DATA, audio devices, RMS
objects, host bus and general proc access are absent. The explicit SDK profile
includes only pinned read-only boot command-line metadata. Private DATA, temporary
storage and shared memory remain distinct bounded NOEXEC/NOSUID/NODEV filesystems.

The parent checks the private mount view, zero capabilities, UID/GID, seccomp and
an exact four-descriptor census before exec and at the exec stop: null stdin/stdout,
one private regular stderr file and one approved stream. The kernel byte-channel
guard still denies raw sockets, retargeting and ancillary transport. Loader
mapping metadata proves that the pinned client library was loaded; this does
**not** prove that every SDK call passes through its hooks.

Resources are bounded: one MiB stack, 96 MiB DATA, 256 MiB address space, 128 FDs,
four/five-second CPU limits, two MiB file size and no core files. A piped core
handler causes refusal before the diagnostic; the global core setting is never
modified. The metadata tracer has a six-second/20,000-stop/80-task limit plus
bounded teardown. No production lifetime or automatic Alice restoration is used.

## Common-parent tracing and control

`sdk_metadata_trace.h` shares the reviewed ARM tracing engine with the standalone
SDK diagnostic. The new mode waits only for enrolled SDK TIDs. It cannot consume
the exit status of the sibling daemon or relay. The standalone mode retains its
original wait behavior.

Before any proprietary SDK execution, an own ELF uses the same filesystem,
binding and admission path, authenticates through the real relay, completes
Hello/GetId, closes the stream, creates a private marker, starts nine threads and
aborts. The tracer must verify the missing-path control and marker, observe all
nine threads and drain the entire family. The already-closed sibling relay must
remain available for its own independent report and reap. Failure prevents the
SDK step.

Tracing reads syscall numbers/results and bounded pathname arguments only.
Socket failures add numeric domain/type or FD metadata; addresses, authentication
buffers, read/write buffers and audio are never inspected. SDK stderr is retained
only in private lab evidence, capped at 64 KiB. The wrapper keeps this evidence in
ignored `build/` files and never prints SDK logs in its report.

## Call-origin refinement and logical bind

The next diagnostic records numeric PC/LR values and mapped file offsets for
denied calls. It never reads stack contents or code bytes from the running SDK.
An own raw-socket rejection exercises this path before the proprietary step.
Private immutable-file analysis located the two raw socket attempts in libc's
name-cache client, not in the bus transport. Their denial remains unchanged.
The original bus-open failure instead followed a raw bind from the SDK.

The reviewed SDK labels its client with `@<hex>/bus/<part>/<part>` before connect.
The client library now acknowledges only that bounded abstract-label grammar,
once per admitted object and before logical connect. It never performs a kernel
bind or creates a new endpoint: the stream remains connected to the preapproved
peer. Named, malformed and unrelated abstract addresses are rejected. Repeated
binds and binds after connect fail; raw bind is still denied by the kernel.

Optional `LISA_BYTE_DIAGNOSTIC=1` records only rejected message-call metadata in
the caller's private stderr: flags, vector/control/name lengths, errno and whether
SIGPIPE is ignored. It records no addresses, buffer contents or pointers.

## Observed result

The actual device trial passed the own control and both independent process
boundaries. The platform SDK loaded the pinned binding, created 16 threads and
then aborted before completing authentication; all threads were drained. The
logical bind removed the previous bind rejection. Scalar diagnostics then showed
that a sendmsg with no destination or ancillary data was refused because the SDK
installs its own SIGPIPE handler. The [per-thread signal wrapper](BYTE_SIGNAL_COMPATIBILITY.md)
now resolves that contract without changing the process handler or enabling raw
send syscalls. The SDK reaches the relay, which rejects its authentication
sequence. SDK authentication and method authorization remain unverified.

The completed trials preserved stock process/configuration identities, boot identity and
firewall rules. All owned actors were reaped and private mount underlays released.
The control also exercised disappearing register sets during group exit without
losing the SDK-family drain or reaping its siblings.

Qualified probe SHA256:
`773723bb30d4cbc5555e26a06281287114283fd951765829eca8d094adeba7b4`.
Client binding:
`29e08ce7dde7430d21ffe33e2e7b223bb47ceab300b6956577c723177e6d2b07`.
The server library is unchanged. Seven factory cases pass 122 native checks on
the speaker and fortified host, including signal masks, pending signals, handler
preservation, logical-bind rejection and ordering.
Ruff and 1475 Python/HA tests pass; the matrix remains at 45 native targets.

Next work is to review the SDK's EXTERNAL authentication variant, retaining real
backend authentication and independent kernel denial. Narrow service
schemas, normal cloud-Alice network policy, real identity/hardware/time/queue
lifecycle, permanent supervision/boot/voice and HA migration remain unfinished.
The strict local diagnostic is not the final cloud-Alice network policy and must
not become a whole-device internet ban.
