# Telemetry storage boundary

The development `telemetry` role runs fixed `maind --telemetry` under the
admission/guardian protocol with its own locked group. It is an Alice-only
service, separate from the collector. Its filesystem boundary is implemented;
**real SDK batch persistence is not yet qualified**. Production boot and the
released HA mode selector are unchanged.

## Enforced boundary

The collector's mount/chroot primitive is reused with a distinct synthetic
group. Libraries, firmware and vendor data are read-only; live process trees,
audio devices, kernel logs and alternate host roots are absent. A bounded
16 MiB private tmpfs holds LMDB, both working session parts, own log and the
configured persistent-batch path. Dumps are disabled. Original session/account
data and old queues are never deleted.

The entire `/data/quasar/appmetrica` directory is overmounted by a private
directory in that tmpfs. The old literal batch path cannot reach the host queue,
including after rename/replacement. All capabilities and the bounding set are
removed; locked credentials, `no_new_privs` and seccomp survive exec. Ordinary
IPv4/IPv6 and AF_UNIX remain Alice dependencies. Lisa/Paused must stop and deny
this role; this is not an IPC or whole-device isolation certificate.

The transformer validates the reviewed layout and limits and deep-copies the
private source. Normal profiles preserve ports, event filters and timing.
Only the bounded clone changes ports/timers, bypasses clock/network gating and
admits its own periodic diagnostic metrics for the offline storage experiment.
These are laboratory accommodations, not production settings.

## Evidence and open acceptance

The own-executable probe passed **30 checks on the speaker**, using synthetic
files only: private aliases, mapping-only database holder, materialized batch,
mapping removal, capability/path restrictions and observation after actor exit.
It does not open stock queue payloads or a microphone.

Parent readiness requires private LMDB and log holders. Current host queue and
system-journal inodes are rejected in both descriptors and mappings. Batch
evidence requires a regular file on the private filesystem with nonzero size
and allocated blocks. The close observer pins directories through process exit,
checks known batch names and closes all its references. It never reads payloads.

A real stock-code clone completed the **16-event lifecycle**: unmanaged and
duplicate starts denied; three private-ready observations; incomplete IPv4/IPv6
barrier rejected; complete barrier/control checks passed; durable close and
reconciliation completed; rewritten Alice intent/permit rejected by the fence;
the same original launcher/telemetry resumed. Boot, configuration and firewall
matched afterwards. Uninstalled production startup remains denied.

**No nonempty persistent batch was observed from the real SDK**, including at
exit. Its private LMDB, working session files and log were observed. The report
therefore distinguishes `storage_boundary_qualified: true` from
`batch_materialized: false` and `qualified: false`. The qualification command
deliberately exits unsuccessfully in this case. Synthetic batch materialization
does not substitute for this missing real-SDK evidence.

Warm-up permits loopback and rejects ordinary external connections for the
clone's group only; close requires DROP in both families. Other applications
retain their policy. An independent watchdog restores only the lab fixture
after interruption. An installed Lisa failure must retain closed policy instead.
Local IPC/DNS and queued packets remain separate composition requirements.
The fault test killed only its own trial shell after three successful guarded
observations and observer startup. The independent watchdog resumed the same
stock processes and restored firewall/boot/configuration identities in about
69 seconds from test start. No exit trap was available to perform that recovery.

```sh
python controller/build.py --target telemetry-guard-probe
python controller/build.py --target station-service
python -m controller.qualify_telemetry YOUR_SPEAKER_SSH_ALIAS \
  --ssh-config YOUR_SSH_CONFIG --allow-temporary-telemetry-freeze
```

Reports, generated configuration, firmware and debugging logs stay in ignored
`build/` or the root-only device laboratory. They must not be published. The
integration remains the v0.1.0 diagnostic preview; `isolation_verified` stays
false. Independent IPC/holder work can proceed while SDK-batch acceptance
remains open, followed by composite roles, UDP/old-flow barriers and boot gates.
