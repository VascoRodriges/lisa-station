# Controller setup: diagnostic preview

This release assumes you already own and administer a rooted, compatible
Station 2. It does not root or flash a speaker. Keep your existing recovery
access. Installation changes only the dedicated helper directory and the new
key's authorization; it needs no boot or firewall changes.

## 1. Build and install the helper

Build `controller/station_ctl.c` with `python controller/build.py --zig zig`,
using Zig **0.14.1**. It targets `arm-linux-gnueabihf.2.30`, Cortex-A53.
Use your existing trusted administrative connection to copy the resulting
`build/station-ctl.armhf` and `controller/status-only.sh` to:

```text
/data/opt/lisa-station/station-ctl
/data/opt/lisa-station/status-only.sh
```

Use a root-owned directory with mode 0700 and root-owned executable files.
Verify the SHA256 after transfer. Run the helper's `status` command through
your administrative connection. It must return JSON schema version 1,
`agent_kind=controller_foundation`, `managed=false`, `isolation=unverified`.
The command reads mute state but does not open an ALSA capture device.

The optional `--sandbox-selftest` command runs a disposable unprivileged child.
It checks networking denial across fork/exec while leaving the parent and stock
processes alone. For this test the binary needs execute permission for the child
(0755); keep the parent directory 0700. The HA key cannot invoke this test.

## 2. Create a dedicated HA key

Generate an unencrypted Ed25519 key **on your HA system**, for example in the
SSH add-on, with the private file in `/config/.ssh/lisa_station_ed25519`.
The directory should be 0700 and the private file 0600. The key has a narrowly
restricted purpose; do not reuse an interactive administrator key.

Add only its **public** key to the speaker's root `authorized_keys`, with:

```text
command="/data/opt/lisa-station/status-only.sh",no-port-forwarding,no-agent-forwarding,no-X11-forwarding,no-pty ssh-ed25519 PUBLIC_KEY_DATA lisa-station-status
```

Replace `PUBLIC_KEY_DATA` with the generated public key material. Back up the
current `authorized_keys` and append the restricted line without replacing
existing recovery keys. Check that the SSH server supports and enforces every
restriction. The wrapper accepts exactly:

```text
/data/opt/lisa-station/station-ctl status
```

With the new key, verify status succeeds and an unrelated command such as `id`
is rejected. Verify forwarding and PTY are disabled. Do not put private keys in
this repository or issue attachments.

## 3. Pin the server key and connect HA

Obtain the speaker's SSH server public key through an already authenticated
administrative channel or another trusted method. Do not blindly trust a fresh
network scan. The integration requires the OpenSSH public-key line, not a
fingerprint. A mismatch blocks connection before any remote command runs.

The setup form takes the private key **file path inside HA**, not its contents.
The SSH agent, user SSH config, password fallback and keyboard-interactive
authentication are not used. The SSH host key also supplies the stable HA device
identity; address changes can be handled by reconfiguration. Key rotation needs
explicit device verification and is not silently accepted as the same device.

Polling is every 30 seconds. A disconnected device becomes unavailable; it does
not retain a success-looking privacy indicator. The diagnostic preview always
reports whole-device isolation as unknown.

## Removal

Remove the HA config entry and only the dedicated restricted-key line from
`authorized_keys`. Then remove the dedicated helper directory and private key
if they are no longer needed. Keep other keys and the separate Yandex Station
integration for speakers which still use it.
