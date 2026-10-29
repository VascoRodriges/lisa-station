# Local IPC peer evidence

`unix-peer-probe` and `ipc_inventory.py` add a read-only UNIX socket/holder graph.
They do not apply a bus policy, stop a service or enable a privacy mode.

The native helper uses Linux `UNIX_DIAG` peer and queue metadata. It never
requests socket names, duplicates another process's descriptor, destroys
sockets or receives application data. See the
[Linux UAPI](https://github.com/torvalds/linux/blob/v4.9/include/uapi/linux/unix_diag.h).
Two bounded kernel dumps bracket descriptor enumeration. Confirmation rechecks
socket inode/cookie/type/state/peer, descriptor inode, PID start time, executable
device/inode and role. Truncated/interrupted dumps, invalid attributes, duplicate
inodes and capacity/time exhaustion fail collection.

The assessor retains missing/changing peers, shared holders, nonreciprocal
endpoints, missing queue metadata and observed nonempty receive queues. A
connected datagram peer does not cover arbitrary `sendto` destinations. A
reciprocal stream holder candidate still requires relay-policy review for a
cross-role peer; internal vendor links require composite close. Queue counts
are two observations, not a continuous quiet-period guarantee.

## Verification and limits

The own-socket suite passed **46 checks on the speaker and Linux host**, without
requiring host root: stream/datagram/seqpacket pairs, reciprocal peers, cookies,
queued synthetic data, queue removal, closed descriptors and malformed/duplicate
attributes. Only its own synthetic byte is sent/received in the self-test.

A live observation found **67 UNIX sockets, 84 confirmed holder observations
and 17 vendor endpoints**. Five vendor endpoints had peers outside vendor roles;
two datagram endpoints remained nonreciprocal and unresolved. These counts are
observations, not a fixed policy. Stock process/boot/configuration identities
matched before and after; no audio was opened.

`atomic_snapshot`, `production_plan_ready`, `apply_supported` and
`isolation_verified` remain false. This cannot detect every copied payload,
queued SCM_RIGHTS transfer, previously delivered message or future activation.
Unidentified processes and unreadable metadata remain explicit. Stopping a
sender alone is not a receiver-data lifecycle policy.

```sh
python controller/build.py --target unix-peer-probe
python -m controller.ipc_inventory YOUR_SPEAKER_SSH_ALIAS \
  --ssh-config YOUR_SSH_CONFIG
```

The CLI prints aggregates; actual identities and graphs remain in ignored
`build/ipc-inventory.json`. No network, firewall, service configuration or
microphone state changes. Unrelated Wi-Fi, logging and D-Bus services keep
working. Next work combines guarded roles with receiver/activation policy,
retained objects and UDP/old-flow barriers. Real telemetry batch materialization
remains separately open in [the storage report](TELEMETRY_EPOCH.md).
