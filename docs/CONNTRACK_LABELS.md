# Process-created flow labels

UDP_DIAG is unavailable on the speaker, and a source-port match cannot establish
every destination of an unconnected UDP sender. A separate loopback experiment
now tests an alternative for **new guarded traffic**: set a conntrack label from
the creating socket's group before sending the first packet. Later filtering
uses that label, including when the original application socket is gone.
It does not label old unmanaged traffic retrospectively.

This is an experimental kernel-mechanism test, not installed policy. The driver
requires an unused test group and label bit, checks that no connmark policy is
already present, and creates exclusively owned temporary chains in both IP
families. It preserves other mark bits. Neither a global root-UID ban nor a
destination-wide blacklist is used.

## Measured behavior

The speaker passed **103 protocol events / 60 native checks** across TCP and
unconnected UDP over IPv4, IPv6 and IPv4-mapped IPv6. For each case:

1. Only the target client socket is created with the fixture group. Its server
   and separate working control pair belong to ordinary root.
2. An ordinary exchange succeeds. The driver observes the exact own loopback
   tuple with the expected conntrack label before installing denial.
3. Label filtering stops target traffic; TCP destruction resets are denied and
   UDP `sendto()` delivery is denied. Separate root controls still exchange data.
4. A **lab-only exact peer-direction exception** lets the own peer send toward
   the now-closed endpoint. The TCP reset or UDP ICMP error generated afterward
   is denied: the DROP counter increases and the peer sees neither data nor an
   error. Controls still work. A production closed policy must have no such
   exception.
5. Removing only the fixture's denial lets the kernel error arrive again.
   Ordinary vendor processes, boot/configuration identity and complete firewall
   rule specifications match their pre-trial state afterward.

The native digest is
`af52688a22bc34cda31a89d4ec28c035e0785e79d2e2522c6646ac2d91bb5b78`.
The probe also compiles on the fortified Linux host. The Python/HA suite passed
**536 tests**, including refusal of missing attribution, false controls,
unchanged orphan counters, duplicate/incomplete evidence and overstated results.
Real reports remain in ignored `build/connmark-qualification.json`.

```sh
python controller/build.py --target connmark-probe
python -m controller.qualify_connmark YOUR_SPEAKER_SSH_ALIAS \
  --ssh-config YOUR_SSH_CONFIG --apply-temporary-loopback-labels
```

The trial refuses installed production state and serializes with the speaker
lab lock. A trap and independent 60-second watchdog remove only owned chains.
No conntrack table is flushed. Own connection labels can remain until their
normal kernel expiry; another run refuses the occupied label rather than
reusing it or clearing unrelated connections. The watchdog interruption path
has not yet been separately fault-injected for this new fixture.

## Required composition

Install and verify marking **before** releasing any guarded sender. Compose
label rules and their ordering with the four-role barrier, durable close fence
and restart recovery; verify missing-family and conflicting-rule refusal.
Reserve a collision-free label namespace and define explicit Alice return,
port/tuple reuse and label retention. Existing unmanaged flows still need their
own migration or a verified early boot boundary. Local IPC/file receivers,
independent DNS/time and boot ordering remain separate work.

This experiment does not retract packets already beyond the tested netfilter
hooks, drain device queues, certify all external protocols or prove whole-device
isolation. It changes no real vendor flow and captures no audio. Public status
continues to report `isolation_verified: false`.
