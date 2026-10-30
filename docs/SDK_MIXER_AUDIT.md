# Private SDK mixer attachment audit

The explicit audio-free `--mixer-audit` profile now identifies the SDK's failing
ALSA control attachment: its label is **`default`**, and the real operation
returns **`-2`** in the private view without sound devices. No hardware permission
was added and attachment success was not fabricated. The independent own client
first exercises the real firmware ALSA library with a deliberately missing
control name; its negative result and private diagnostic record are required
before the proprietary SDK runs.

ALSA's [mixer interface](https://www.alsa-project.org/alsa-doc/alsa-lib/group___mixer.html)
defines attachment in terms of a control/HCTL name. This audit records that API
parameter and signed return value only. It does not inspect PCM, authentication
or audio buffers, trace a stack, or read arbitrary SDK process memory. The label
is supplied to the instrumented API inside that process. The caller's actual
ALSA function executes unchanged, and its return value and errno are preserved.

The separate `unix-mixer-factory` build includes the hook; the default byte
factory does not. The variant requires its explicit audit environment flag and
retains the same one-shot source pool and independent kernel endpoint guards.
Its real attach symbol resolves lazily with pthread_once/RTLD_NEXT, which also
supports the own executable loading the firmware library after exec. The own
client opens an empty mixer, attaches the deliberately missing control, checks
failure, and closes the handle. It never substitutes a synthetic ALSA backend.

At most four fixed 145-byte records are written, each in a single write, to the
already pinned private stderr file. A record contains a version marker, bounded
strict UTF-8 label of at most 128 bytes, signed 32-bit result and zero padding.
The atomic record budget, invalid metadata, resolution failure and incomplete
writes terminate this disposable actor rather than return invented success.
These are private diagnostic records, not authorization or admission tokens.

The parent decodes records while retaining the bounded original stderr file.
Its scanner handles records split across read chunks and discards ordinary log
noise. Recognized malformed or unknown-version records, partial candidates,
overflow and truncation fail qualification. Failure is sticky; earlier records
cannot qualify an invalid stream. Public JSON contains only bounded counts,
validity and the known own-fixture match. Actual parameter text remains private
until separately reviewed; `default` above was reviewed as a generic control
label. No credentials, device addresses or firmware binaries are published.

The typed 16-event protocol retains all exact-service ownership/retirement,
34 policy controls, two-source descriptor admission, both relays and complete
cleanup checks. It additionally requires the known own record, bounded actual
records, valid parsing and untruncated stderr. The actual SDK emits one record;
both SDK streams authenticate and reach EOF. Stock identities/configuration
and firewall snapshots are preserved. The normal exact-owner profile passes
on the same native build with the uninstrumented byte factory.

The pure record/scanner fixture passes **678 checks** on Windows/Zig and fortified
GCC, also under ASan/UBSan. It covers every two-chunk split, byte-sized and other
chunk feeds, every truncated record prefix, signed limits, maximum labels,
invalid UTF-8/framing/padding, overflow and sticky failure. The host forwarding
fixture passes **13 checks** under fortified GCC and ASan/UBSan using a synthetic
callee to verify the real function call, return, errno and overflow termination.
That synthetic callee is used only by host tests and is never loaded into the
SDK. The speaker's own positive control uses the actual firmware ALSA library.
Ruff and **1778 Python/HA tests** pass. CI adds the diagnostic factory as the
47th native build target and runs both host fixtures.

Read-only inspection found that the firmware's default control configuration
selects card zero. That card also exposes capture/AGC controls, so giving the
SDK its raw control descriptor would exceed a Master-volume interface. The next
step is a reviewed, limited connection to the independent hardware-volume role,
with truthful metadata and operations; arbitrary ioctl access and a fake mixer
remain outside this design. No real sound device, recording or playback was
opened in this stage. Production switching and the remaining roadmap are open.
