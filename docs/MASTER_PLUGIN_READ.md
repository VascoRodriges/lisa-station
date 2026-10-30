# Real Master reads through firmware ALSA and the plugin

The own-client lab now composes **firmware ALSA → pinned Lisa control plugin →
packet GET capability → guarded real Master reader** on the speaker. It reads
the actual volume; neither synthetic values nor a substitute ALSA library are
used in this device test. It opens no playback/capture PCM, changes no volume
and does not involve the proprietary SDK or install a service.

This is a separate native build and explicit qualification command. The
[broker's existing guards](MASTER_READ_BROKER.md) retain the read-only hardware
FD in the backend. The own client keeps only its byte peer, null stdio and
private report pipe. Its separate read-only view adds one pinned plugin file;
the backend's view must not contain that file. At preparation and the kernel
exec stop, the parent checks the module's inode against the uploaded artifact,
alongside the exact descriptor/view/executable and credential inspection.

For each stopped own client, the parent also substitutes an unrelated expected
module inode: inspection must refuse it. Restoring the admitted module must
restore success, giving **16 negative/restored-positive controls** across eight
epochs. These are admission-verifier tests; they do not inject another module
into the actor or authorize a replacement.

The client loads its firmware `libasound.so.2`, verifies the expected 1.2.1.2
version and resolves the reviewed public API and plugin symbol marker. It builds
a private typed configuration tree: `ctl_type.lisa_master.lib` identifies the
absolute pinned module and `ctl.default.type` selects it. A real
`snd_ctl_open_lconf(..., "default", ...)` call searches the definition and loads
the plugin through ALSA. The client does not call the plugin entry directly.
Configuration nodes are constructed through ALSA's API, with no interpolation
of file paths into configuration syntax; the root owns and frees its children.
Real ALSA metadata calls must show one
readable, volatile integer Master with the agreed range and no write access.
Every real read then passes through `snd_ctl_elem_read` and the plugin callback
to the backend. Public libasound declarations and kernel ioctl declarations
are kept in separate translation units rather than overriding conflicting ABI
types. No firmware files are used by the compiler.

The same eight fresh epochs now pass with the plugin in the data path: normal
reads, replay, wrong epoch, SET opcode, oversized/truncated/reserved requests
and backend SIGKILL. The parent compares actual backend/client values and the
exact successful ioctl counts. Invalid packets are deliberately sent by the
own lab client after its valid ALSA reads; the SDK receives no such test code.
After backend death, the client first observes EOF, then an actual ALSA read
must return EPIPE with zero output; it cannot return the earlier value. Plugin
close retires its owned FD, and both views must be released.

The **12-event** typed proof requires the distinct plugin-composition record,
including `configuration_loader: true`,
all eight broker epochs, 28 native source-inspection controls, successful exit
and cleanup. Neither the older direct-byte-client report nor the initial
direct-entry plugin report can qualify this configuration-loader mode.
Stock process/configuration/boot and firewall snapshots remain unchanged.
The ARM module qualified here is the same artifact used by the preceding
plugin build; the native composition is a separate 50th build target.

The host dynamic-loader fixture additionally uses the same separate client
translation unit against a hash-pinned **real public ALSA library**, with an
explicitly synthetic packet provider for normal value, backend error and EOF.
It complements the plugin's 13 host ABI cases; it is not hardware evidence.

```sh
python controller/build.py --target master-ctl-plugin --zig zig
python controller/build.py --target master-plugin-read-probe --zig zig
python -m controller.qualify_master_plugin_read SPEAKER_SSH_ALIAS \
  --ssh-config PRIVATE_SSH_CONFIG --run-read-only-plugin-lab
```

The initial device composition used a direct external-entry call. The current
composition additionally verifies ALSA's normal definition/plugin loader with
a private configuration root. It does not call the global configuration updater
or change a firmware configuration file. A private `ALSA_CONFIG_PATH` file and
the SDK's actual `snd_mixer_attach("default")` path remain next, alongside exact
admission of a third SDK capability.
SDK source/descriptor budgets and bus profiles remain unchanged. This lab is
not a complete isolated Alice, permanent hardware service, production mode
controller or finished voice/HA integration.

The distinction between local-root loading and global configuration update
follows the [official ALSA control implementation](https://github.com/alsa-project/alsa-lib/blob/v1.2.1.2/src/control/control.c).
