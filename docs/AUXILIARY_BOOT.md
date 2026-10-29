# Local services during vendor startup failure

The uninstalled boot dispatcher attempts the guarded mixer, resolver and clock
even when vendor bootstrap fails, hangs or lacks loopback initialization. The
diagnostics and main Yandex roles remain gated. A missing runner never invokes
the original service scripts; independent SSH retains its early recovery path.

The coordinator authenticates administration with real/effective UID and GID 0,
then validates the supported model, read-only root and trusted installation (or
the restricted lab directory). Local-service operations take their own boot
lock and keep their fixed profile, executable, child-view and journal checks.
They do not require a valid mode record, the mode lock, a vendor permit or a
working vendor policy namespace. Optional mode/policy observations cannot grant
vendor admission or certify isolation. The original vendor bootstrap still
refuses missing/corrupt state and policy ownership.

Auxiliary and vendor supervisor sockets now require the administrator's GID as
well as UID and expected process generation. This matters because vendor roles
retain UID 0 with immutable nonadministrative GIDs. This socket check alone does
not isolate root-owned files; the platform filesystem boundary remains pending.

## Evidence

The actual **13-event speaker trial** started a separate resolver on an
unprivileged port with no mode directory or policy namespace. The same child
survived corrupt mode data, a held exclusive mode lock and a corrupt policy
name. Vendor policy status correctly refused the corrupt namespace. Repeat
start preserved the child journal; IPv4/IPv6 UDP/TCP queries and authenticated
stop passed. The slowest service call was **192 ms**. Stock service identities,
configuration, boot and complete firewall rules were unchanged. No audio was
captured and no production mode was installed.

The auxiliary native probe passed **53 checks on the root speaker**, including
a UID-0/GID-tagged client denied both status and raw stop access, with the child
remaining healthy; its unprivileged Linux version passed 50 checks. The existing
vendor guardian passed 57 checks on both systems. The real-shell dispatcher
passed 24 checks across seven synthetic cases with the new independent-call
behavior; the bounded runner passed 18. Fortified host builds, **728 Python/HA
tests**, Ruff and the public-tree check passed. The native matrix has 33 targets.

Qualified ARM SHA256:

- coordinator: `7a4cc4c12438f920e2e9873d1b34c4441af09caff3618983c592d444846f7b39`
- auxiliary probe: `dc9bdaf72ee44a5f197b7c3a4661da470ac6cca2086fc9aff25b8cffb7c222c1`
- vendor guardian probe: `f534670559f125b81071cc16d1a423e1a34e22711dec32db91a3c62dc41e28b5`
- init runner: `ef14d81afe9578e026ad197bde25e46bf3c7e8a5ccf85ed268a09b729fc2010c`
- dispatcher probe: `d0e57bb10e77ec656787b174fb8f39c5b0930d0d981df6d8ebd2ca04113778a1`

```sh
python -m controller.qualify_auxiliary YOUR_SPEAKER_SSH_ALIAS \
  --ssh-config YOUR_SSH_CONFIG --dns-server YOUR_NON_YANDEX_DNS_IP \
  --run-independent-service-trial
```

The qualifier refuses installed production state and never stops stock services
or edits firewall rules. Its watchdog can only stop its own lab resolver. This
proves independent dispatch and the common admission path, not another live
hardware/time handoff. Permanent mode composition, explicit Alice return,
installer/direct-init gates and cold-boot acceptance remain unfinished.
