# Experimental read-only ALSA control plugin

The external control plugin exposes one logical **Master Playback Volume**
element: integer, count one, range 0..255, step zero, readable and volatile.
It cannot expose capture/AGC controls, open a sound-control descriptor or write
volume. Unsupported writes return an error. There is no invented dB scale,
TLV data or event stream. The external ALSA core can retain subscription state,
but this plugin has no event source or poll descriptor and cannot provide
change notifications.

Each read uses the separately admitted anonymous UNIX SEQPACKET descriptor
and the [Master GET protocol](MASTER_READ_BROKER.md). There is no cached level,
new socket, pathname connection or fallback. The entire exchange has a
200 ms deadline; malformed/error replies, EOF, transport failure and timeout
close the owned descriptor and retire the epoch. The 32nd successful read
also retires it; subsequent reads return an error. This bounded limit is for
the lab and is not a permanent volume service.

The module accepts only its fixed `type` configuration field. Its parent
supplies `LISA_MASTER_FD` and `LISA_MASTER_EPOCH`; malformed settings and
unrelated configuration fields are refused. The module checks packet socket
shape and cached creator credentials, then permits only one handle attempt
per loaded module instance. Environment variables and cached SO_PEERCRED are
**not authorization**. Parent admission must separately prove the actual
descriptor objects, exclusive holders, executable/view and epoch before
releasing a client. Opening the logical control validates transport shape;
only a successful GET proves that a value was received.

Reads are serialized with a per-handle mutex, including request sequencing.
The caller must end all operations before closing or unloading the handle;
concurrent destruction is not supported. Packet writes preserve the process
SIGPIPE handler and temporarily block the signal only in the calling thread,
preserving an already pending SIGPIPE. This works with the existing byte-only
guard rather than requiring sendto/sendmsg permissions.

The build fetches the official public **alsa-lib 1.2.1.2** release, pinned to
SHA-256 `958e260e3673f1f6ff6b2d2c0df3fc2e469bea5b2957163ce96ce17f23e87943`.
Only named regular public headers and their license are staged for the ARM
build. No firmware library/header is a build input. The external ABI is
version 1.0.1; the declarations and dynamic symbol marker come from those
headers, not reconstructed structure layouts.

The original Lisa plugin code uses the repository's MIT license. ALSA public
headers/library are **LGPL-2.1-or-later**, under their own notices. Build output
includes `COPYING.alsa-lib` and `PROVENANCE.txt`; the CI plugin artifact includes
them too. The host fixture builds the unmodified hash-verified public ALSA
library in a fresh directory. It does not substitute a fake ALSA callee.

The host ABI fixture loads the real external entry, creates the control and
uses real ALSA metadata/read/write APIs. Its packet provider is explicitly
**synthetic**, separate from the real speaker broker qualification. Thirteen
fresh-process cases cover 32 reads from four threads, range/metadata,
unknown-control/configuration rejection, write/TLV refusal, single-handle
ownership, truthful backend error, short/oversized/epoch/sequence/reserved/
range errors, EOF, timeout and three SIGPIPE states. It checks handle/descriptor
closure and refusal to reconnect. These are host compatibility tests, not
proof of a functioning speaker or SDK integration.

```sh
python controller/build.py --target master-ctl-plugin --zig zig
python -m controller.qualify_master_plugin
python -m controller.qualify_master_plugin --sanitize
```

The subsequent [real speaker composition](MASTER_PLUGIN_READ.md) now loads the
ARM module with the firmware ALSA library and verifies actual Master values
using own clients. The normal ALSA configuration loader, SDK-only configuration
and separately qualified third-capability admission remain next. Existing SDK
descriptors, bus source budgets, production modes, microphone and second
station are unchanged.

Primary ABI sources: [external control declarations](https://github.com/alsa-project/alsa-lib/blob/v1.2.1.2/include/control_external.h),
[external control implementation](https://github.com/alsa-project/alsa-lib/blob/v1.2.1.2/src/control/control_ext.c),
[official source release](https://www.alsa-project.org/files/pub/lib/alsa-lib-1.2.1.2.tar.bz2).
