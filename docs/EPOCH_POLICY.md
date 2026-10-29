# Reopening without reviving retired flows

The staged epoch policy now has real-kernel evidence: a newly authorized
generation can exchange data while sockets from the previously closed
generation remain denied. This supplies the packet-policy primitive needed by
the [explicit Alice-return engine](ALICE_RETURN.md). It is **not installed or
wired into vendor admission**, and does not enable the HA mode selector.

The earlier single-bit label policy cannot achieve this by removing its DROP
rule: that would allow the old labelled connections again. The new policy uses
the upper eight connmark bits for a generation value, with zero reserved for
unrelated traffic. New declared-role flows receive the active value only when
those bits are still zero. Changing the active generation therefore cannot
relabel an old socket's retransmission or an existing connection. The lower
24 bits are outside the assignment mask.

Closed mode denies the four declared role groups and every nonzero generation.
Open mode permits unmarked traffic and the active generation, then drops other
generation values. The group/label filter hooks and first mangle hook stay in
place in both modes. IPv4 and IPv6 are verified separately against canonical
complete rules. Generation selection skips retained conntrack values and the
current generation; exhaustion must stay closed without flushing connections.

This namespace must be durably reserved before the first admitted vendor
socket. An empty snapshot or these generated strings do not establish
ownership. Boot ownership, revision-bound admission, crash recovery and mutation
callbacks remain to be composed; the old single-bit admission verifier does
not silently accept this new format.

## Kernel trial

The **145-event speaker trial** passed six cases: TCP and unconnected UDP on
IPv4, IPv6 and IPv4-mapped IPv6. Each case used two distinct values; the entire
run used twelve generations without reusing one while it remained in conntrack.
There were **66 native socket checks**, 36 complete dual-family policy
verifications and 18 exact tuple/mark observations.

Each case exchanged data with an initial marked socket, closed it, changed the
marking rules under the closed policy and released a new generation. A new
socket exchanged data successfully. The earlier socket stayed denied even when
it attempted another send, and its kernel conntrack mark remained unchanged.
Closing the new generation blocked both. Unmarked root control connections
continued to exchange data in every phase.

Keeping the old test socket alive is deliberate: it tests that an already
labelled flow cannot acquire the new authorization. Production opening must
additionally verify its old actor/FD scope has stopped. These fixtures use only
own loopback sockets, never vendor processes or external endpoints.

During release the complete open rules are appended underneath the existing
closed DROP before that first DROP is removed. During close, the closed DROP
is inserted before the open rules are removed. An independent watchdog can
remove only the trial's recorded, whitelisted chains. The fixture refuses an
installed controller, occupied generation namespace and existing tagged roles.
It never flushes conntrack, changes default policy or bans the device's internet.

Stock process identities, boot/configuration and all firewall rules were
preserved/restored. No microphone, production mode or rootfs write was used.
The watchdog itself was not fault-injected in this new trial; this is not
installer or power-loss acceptance.

The native generator/slot/parser selftest passed on the speaker and a fortified
Linux host, exercising all 255 nonzero values. Ruff, the public-tree check and
**766 Python/HA tests** passed. The native matrix now has 35 targets.

Qualified ARM SHA256:

- epoch probe: `b29849c2cb78f146ade7f5a14b354ae78eca813b9ae0af0113db99f7168d5e8a`

```sh
python controller/build.py --target epoch-policy-probe
python -m controller.qualify_epochs YOUR_SPEAKER_SSH_ALIAS \
  --ssh-config YOUR_SSH_CONFIG --run-own-loopback-trial
```

Retained labels expire normally after the trial. Immediate repeat runs refuse
an occupied namespace; deleting live conntrack entries is not a workaround.
Permanent isolation and real mode-switch acceptance remain unfinished.
