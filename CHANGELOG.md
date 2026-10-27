# Changelog

## Unreleased

Development qualification for scoped IPv4/IPv6 filtering and locked ARM process
identity, with loopback probes and watchdog cleanup. This does not enable a
production privacy mode. Added an upstream feature migration matrix and isolation
design notes. Diagnostic integration behavior remains unchanged.
Added a fixed-target bounded vendor-startup compatibility tool and a durable
requested-mode storage primitive, with concurrency/corruption checks. Neither
installs a permanent privacy mode or changes the HA supported-feature set.

## 0.1.0

Initial diagnostic preview: UI setup, pinned SSH transport, read-only controller,
diagnostic sensors, English/Russian translations and test coverage.

No mode switching, whole-device isolation, voice capture or media player yet.
