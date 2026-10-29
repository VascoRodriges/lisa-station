# Guarded independent clock

The staged coordinator now implements fixed time start/status/stop operations.
**It is not installed in the boot path.** Alice return, independent boot failure
handling, the installer and full mode/voice composition remain unfinished.
The HA release stays diagnostic and does not claim complete vendor isolation.

## Privilege and filesystem

The installed chrony 3.5 binary lacks its optional privilege-drop support. Our
launcher instead limits it before exec: UID/GID 0, no supplementary groups,
only `CAP_SYS_TIME` in effective/permitted/bounding sets, empty inheritable and
ambient sets, and directly checked NNP. Linux 4.9's missing proc NNP field is
not treated as an observation. Seccomp locks identity, denies process creation,
host namespace changes, cross-process memory/FD access, IPC queues and external
process signals. Clock-ID APIs are restricted to CLOCK_REALTIME. DNS retains
its separate clock-denied filter; clock permission cannot be selected through
a caller-supplied program or configuration directive.

A private mount namespace/chroot exposes read-only libraries, chronyd, the
compiler-produced profile, null/random and synthetic locked root account
metadata. Even this chrony build performs an account lookup before startup.
The host account database, proc, sysfs, vendor data, audio nodes, logs, shared
memory and stock chrony state are absent. Only the private PID directory and
dedicated drift directory are writable, with nodev/nosuid/noexec mounts.

The independent supervisor authenticates status/stop, tracks executable and
process generation, and preserves the existing actor on repeat start. Startup
refuses any other live chronyd rather than running two clock controllers.
Missing or malformed profiles never select the old configuration. A bad new
profile does not kill a healthy existing clock process. Production has no lab
lifetime limit and no HA/NAS or vendor-permit dependency within its supervisor.
The coordinator and dispatcher now allow [independent operation](AUXILIARY_BOOT.md)
without valid vendor mode or policy state; production deployment remains pending.

## Fixed profile

Python and native validation agree on one client-only template: one to four
canonical numeric unicast servers, private PID/drift paths, `port 0`, `cmdport 0`,
`bindcmdaddress /`, `makestep 1.0 3` and `rtcsync`. Includes, hostname pools, keys,
logging, remote command listeners and other options are refused. Operators must
select non-Yandex providers; an arbitrary numeric address is not an ownership
attestation. No stock/DHCP profile is imported.

The [chrony 3.5 configuration manual](https://chrony-project.org/doc/3.5/chrony.conf.html)
documents disabling the UNIX command socket with `/` and kernel RTC copying with
`rtcsync`. Its [startup source](https://github.com/mlichvar/chrony/blob/3.5/main.c)
performs the root account lookup even when no privilege drop follows.

RUNNING means the guarded process, identity, private view and PID file are
verified. It does **not** by itself mean a source is synchronized. Failure to
reach a time source does not authorize Alice or a stock fallback.

## Actual-clock evidence

The **41-event speaker trial** first measured the chosen source with `chronyd -Q`
and clock writes denied, accepting an offset within 100 ms. It then stopped only
the stock chronyd, verified absence, and started the real guarded clock daemon.
The trial selected its configured NTP source and recorded **nine accepted
adjtimex writes**. Initial TIME_ERROR states alone are insufficient: the final
accepted adjustment returned TIME_OK. No manual clock value or backward-time
rollback was supplied. The slowest time operation took **355 ms**, below the
eight-second init deadline.

This evidence uses an **explicit lab-only** read-only preload library that calls
the real libc functions and preserves their return values and errno. It records
only API, mode flags, result and error in the role's private runtime directory.
It does not record clock values, servers or speech. Lab stderr separately retains
chrony's source-selection evidence privately. Normal production preparation
does not load this library or enable those logs.

The trial also passed duplicate-controller refusal, repeat-start identity,
private Paused/Alice/Lisa intent with no vendor permit, malformed-profile refusal,
authenticated stop and stable restoration of the stock clock. Other service
identities, boot/configuration and complete firewall rules were preserved or
restored. There was no microphone capture, firmware write or production mode
installation.

The time-filter probe passed both query/control modes on the speaker and a
fortified Linux host. Its clock-pointer tests clear all capabilities and never
supply a valid time value. Cross-language profile and mocked interposer tests
are included in the **700 passing Python/HA tests**. The build matrix now contains
**33 native targets**, including the lab-only shared library.

Qualified ARM SHA256:

- coordinator: `2f7e154164463a3b54ce428ba8a91ae414ec7bf757237b77d3cbd4cddd9ee8a4`
- time/filter probe: `2013267ea22bd870acbc46d83aff16409e7d413b348f5296a41f0deca166bba2`
- lab return observer: `35707d05ceead9b2a76fe4a0cf052da02d958d04930a91f16bd610d1fb3106cd`

```sh
python controller/build.py --target station-boot
python controller/build.py --target time-guard-probe
python controller/build.py --target time-clock-proof
python controller/build.py --target service-profile-probe
python -m controller.qualify_time YOUR_SPEAKER_SSH_ALIAS \
  --ssh-config YOUR_SSH_CONFIG --ntp-server YOUR_NON_YANDEX_NTP_IP \
  --temporary-clock-handoff
```

The administrative fixture refuses an installed controller and restores only
the stock clock. It is not a production mode transition. Real providers, logs,
profiles and reports remain private; ordinary Alice stays outside these guards
in the lab. Permanent boot and complete isolation acceptance remain pending.
