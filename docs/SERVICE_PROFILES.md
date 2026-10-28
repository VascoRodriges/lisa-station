# Independent DNS/time profiles and startup admission

These are development components. They do not replace the speaker's current
services, install boot wrappers, or enable the HA mode selector. The diagnostic
release still reports vendor isolation as unknown.

## Explicit service profiles

`controller/service_profiles.py` compiles new configurations from explicitly
selected numeric DNS and NTP server addresses. It does not import stock files,
DHCP-supplied providers, hostname pools or include directives. Empty lists,
duplicate servers, hostnames, scoped/mapped addresses and invalid endpoints are
rejected. The operator/controller must select non-Yandex endpoints; numeric input
validation does not identify the organization operating an arbitrary server.

The resolver listens on IPv4/IPv6 loopback, accepts UDP/TCP and forwards the root
zone only to the chosen servers. `forward-first: no` prevents fallback to ordinary
recursion when a forwarder fails. Its iterator forwards without a local DNSSEC
validator; validation is delegated to the selected upstream. Query/reply logging
and remote control are disabled. The profile and selected startup command are
independent of `/etc/unbound/unbound.conf` and its writable DHCP-era location.

The time profile uses numeric `server` entries, with no hostname bootstrap or
pool fallback. It is client-only and disables UDP and Unix command sockets.
The production template retains a dedicated drift file and the stock initial
clock-correction behavior. A diagnostic template has separate paths/ports and
omits drift, stepping and RTC directives.

The format was checked against the installed Unbound 1.19.0 and chrony 3.5.
References: [Unbound forwarding](https://unbound.docs.nlnetlabs.nl/en/latest/manpages/unbound.conf.html#forward-zone-options),
[chrony configuration](https://chrony-project.org/doc/3.5/chrony.conf.html) and
[chronyd query mode](https://chrony-project.org/doc/3.5/chronyd.html).

## Parallel qualification on the speaker

`service-profile-probe` executes only fixed Unbound/chronyd paths and private
temporary profiles. Before exec it closes extra descriptors, clears the
environment, switches to UID/GID 65534, removes supplementary groups, verifies
zero capabilities and sets `no_new_privs`. Seccomp denies clock-setting and
adjustment syscalls, including available ARM time64 variants. The time trial
additionally uses **`chronyd -Q`**, which measures an offset without correcting
the clock. It never uses `-q`, which would request correction.

The DNS trial uses a separate unprivileged port and does not replace port 53 or
the system resolver configuration. Its fixed `example.com` query checks UDP/TCP
over IPv4/IPv6 loopback. The tested upstream DNS addresses were IPv4; this does
not establish WAN IPv6 reachability. Executions have bounded lifetimes. A separate
cleanup watchdog tracks the DNS PID and start time before terminating it, and
removes only its temporary configuration directory.

```sh
python controller/build.py --target service-profile-probe
python -m controller.qualify_service_profiles YOUR_SPEAKER_SSH_ALIAS \
  --ssh-config YOUR_SSH_CONFIG --dns-server YOUR_NON_YANDEX_DNS_IP \
  --ntp-server YOUR_NTP_IP --run-parallel-service-probes
```

On the verified speaker, configuration validation, all four DNS transports and
the numeric LAN NTP query passed. The live DNS process had UID 65534, zero
effective capabilities and `Seccomp: 2`. Temporary processes/files were removed;
stock DNS/time/vendor process identities, boot ID and stock configuration hashes
matched before and after. No audio was opened or recorded. Reports remain under
ignored `build/`; real LAN addresses are not distributed with the source.

## Admission leases for future vendor startup

`controller/service_gate.h` adds an admission primitive to the existing mode
record. A valid `alice` request alone does **not** allow startup. Admission also
requires a private runtime `vendor.permit` with the same revision and the current
kernel boot ID. Missing, corrupt, public, linked, wrong-owner or stale records
deny admission. Lisa/Paused always deny it. A previous boot's permit is invalid.

Successful admission returns a shared lease on `mode.lock`. The caller must
initialize its lease descriptor to `-1` and retain it throughout the fixed start
operation. The existing mode writer requires an exclusive lock, so it cannot
commit a transition while an admitted start is active. Busy admission denies
startup. Overwriting an occupied lease is rejected; close-on-exec descriptors
help avoid leaving the lock in a daemon accidentally.

The future trusted guardian must hold the lease in its parent until its tagged,
fixed child startup has completed and is tracked. **Checking, releasing the
lease, then starting an unguarded process is unsafe.** The controller must publish
permits under the same transition serialization only after verifying chosen
profiles and policy. A permit is admission evidence, not network privacy proof.

`service-gate-probe` passed **31 checks on the speaker's writable storage**:
concurrent transition/start admission, revocation, revision/boot changes,
malformed files, permissions, links and occupied-lease handling. Fixtures were
removed; no real mode record, permit or service was changed. The same test runs
without root on the Linux CI host.

```sh
python controller/build.py --target service-gate-probe
```

## Remaining integration work

- Implement the trusted guardian and transition executor, with observed
  policy/profile validation before publishing runtime permits.
- Enforce boot policy before diagnostics and all vendor launch paths, including
  init wrappers and launcher restarts; retain independent root SSH recovery.
- Make DNS/time restarts choose the correct explicit profiles. Missing or bad
  Lisa profiles must not fall back to stock Yandex providers.
- Complete old-flow attribution, relays, queued packets and telemetry handling
  before acknowledging Lisa isolation or exposing the mode selector.

The policy targets Yandex services and their traffic. It does not disable
internet access for unrelated applications or change shared router/DHCP/DNS
infrastructure. The speaker's actual boot process is unchanged at this stage.
