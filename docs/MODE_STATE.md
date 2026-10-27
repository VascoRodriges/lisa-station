# Requested-mode persistence primitive

`controller/mode_store.h` implements a small durable **intent** record. It does
not change services or firewall rules and is not yet connected to an init script
or the diagnostic integration. Requested mode must never substitute for observed
actual state or confirmed isolation.

The record contains a format version, a positive 64-bit revision and one of
`alice`, `lisa`, `paused`. Parsing requires canonical bytes. Unknown versions,
extra content, invalid modes/revisions, public-writable files and symbolic links
are rejected. Production callers must use a root-owned private directory and
require root ownership.

Writes take an exclusive nonblocking file lock and compare the caller's expected
revision. Concurrent or stale requests are rejected. A new file is written under
a fresh exclusive name, synchronized, atomically renamed, then the directory is
synchronized. Readers see a published record, not a partially written temporary
file. Revision overflow and an invalid existing record do not enable a write.

The library's boot-choice function returns **Paused** for every missing, corrupt,
incompatible or unreadable record. This is a contract for the future boot gate;
the speaker's actual boot process is unchanged today. An I/O failure must stop
the future transition and must not be treated as a successful mode confirmation.

## Checks

`mode_store_probe.c` passed **27 checks** on the real speaker's writable storage,
including stale revisions, simultaneous child requests, busy locks, corruption,
symbolic links, permissions, a partial unpublished file and revision overflow.
All fixtures live in a freshly created test directory, which is removed at the
end. The real requested-mode record is never accessed or changed. This is not a
physical power-loss test.

Build for the speaker:

```sh
python controller/build.py --target mode-store-probe
```

Running the resulting binary with `--station-storage` uses a fresh test directory
under the existing controller lab directory. The default uses `/tmp`, enabling an
unprivileged host build/test in CI as well.
