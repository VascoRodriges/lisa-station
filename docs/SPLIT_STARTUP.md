# Four-role startup and close

The bounded `qualify_split` trial now runs the actual platform/media launcher,
log collector, telemetry SDK and audio diagnostics under four separately tracked
roles. This is a laboratory milestone, not an installed mode selector or boot
policy. `isolation_verified` remains false.

The private launch transformer accepts only the reviewed four-task firmware
schema and retains the two platform/media tasks with their original timing and
environment. Collector and telemetry receive their own guarded filesystem
epochs and ordinary local ports. The platform requires those tracked SDK
children before startup; its inspector additionally requires their private
queues and exactly two tagged launcher children. A duplicate launcher is refused.
Audio diagnostics has its own guard and private view; the trial verifies that
the D-Bus AudioMonitor name belongs to that tracked child.

Executable identity uses device/inode comparison with the fixed firmware file.
The kernel can render a bind-mounted SDK executable under a different pathname;
a pathname-only census would omit both jailed workers. The fixed root-only
`--maind-pids` inventory uses the same object identity and live process ticks.
It accepts no caller-supplied path or PID and is not exposed by the HA key.

## Evidence

The real speaker passed **37 events**, including four samples of all four maind
workers and **16 successful role inspections**. Collector and telemetry had
separate private queues; platform/media inherited the intended group and
seccomp restrictions; diagnostics owned the expected bus name. The trial then
rejected an incomplete IPv6 barrier, verified the complete four-group barrier
with unrelated root loopback controls working, closed every role, reconciled
their epochs and rejected a raw Alice-record rewrite behind the durable fence.
Original launcher/boot/configuration identity, ordinary four-worker startup,
diagnostics and firewall rules were restored. No audio was captured.

The final backend digest was
`51b88aaab3647502c2ed8bbbc18710f36e3e014b6f32bbb7d5d4dd896af4debb`.
The development suite passed **467 tests**. Native collector identity checks
also cover the bind-mounted alias; the classifier is shared by relay and TCP
metadata probes. Reports and generated profiles remain private in `build/`.

```sh
python controller/build.py --target station-service
python -m controller.qualify_split YOUR_SPEAKER_SSH_ALIAS \
  --ssh-config YOUR_SSH_CONFIG --allow-temporary-stock-restart
```

This command temporarily replaces stock workers and explicitly restores Alice.
It refuses an installed production state. An independent watchdog and bounded
guardians cover loss of the trial shell. The stock launcher's restart limiter
can delay restoration; the qualifier preserves that launcher rather than
resetting its limiter. Never use this lab restoration procedure after installing
permanent Lisa/Paused mode enforcement.

## Remaining boundaries

The platform has **no private filesystem view yet**. Its successful inspection
reports `platform_workers_verified: true` and `inspection_view: false`; these
fields must not be collapsed into a privacy claim. Shared platform state/logs,
receiver lifecycle, activation policy, retained UNIX/file/mapping objects,
UDP/queued traffic, old flows, independent DNS/time and boot enforcement still
need composition. Real SDK batch materialization is still unobserved. This
trial does not exercise voice behavior or the permanent Assist service.
