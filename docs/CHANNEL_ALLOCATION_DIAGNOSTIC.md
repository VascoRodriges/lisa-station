# Channel-budget failure attribution

The SDK's EMFILE failure is now attributed to the one-shot channel budget.
The pinned client library reports `channel-budget exhausted slots=1` at the
exact branch that refuses a further logical socket. Its kernel-duplication
failure branch emits a different notice, which is absent from the SDK trial.
This supports admitting another independently owned channel; raising RLIMIT_NOFILE
or enabling raw sockets would not address the observed refusal.

The change adds diagnostics only. With the existing explicit diagnostic flag,
each failure class emits at most one scalar notice per process, guarded by an
atomic flag. Notices contain only slot count or errno, without descriptors,
addresses, authentication, speech or message buffers. The original errno is
restored after logging. No allocation, endpoint or one-shot reuse policy changes.

The own factory fixture redirects stderr to an immediately unlinked own file
only for its final allocation controls. It verifies EMFILE both before and after
closing the consumed channels, and exactly one canonical two-slot notice across
both attempts. All existing signal, ancillary, endpoint, constructor-rejection
and two-thread controls remain. Seven cases now pass **125 native checks** on
the fortified host and speaker: 44 parent checks, 69 normal-client checks and
12 concurrent-client checks. Five unsafe constructors still exit before actor
execution. This stage does not claim new sanitizer qualification.

The actual guarded SDK trial then confirms the corresponding one-slot notice,
with no duplication-failure notice, beside its EMFILE exception. Its synthetic
adapter exchange, private storage/FD admission, full family drain and all thirteen
service evidence events still pass. Stock process/configuration/boot identities,
firewall and unrelated network controls remain unchanged. No audio, real
Bluetooth, real identity or host bus is exposed.

The report helper classifies these bounded notices separately from the strict
boundary protocol. Missing notices remain unobserved; malformed, repeated,
truncated or out-of-range notices are invalid. Both failure classes together
remain multiple, rather than guessing a primary cause. Generic EMFILE exception
text alone cannot establish attribution. **Log classification is diagnostic data,
never authentication or permission to admit a channel.** Ruff/public-source and
1614 Python/HA tests pass; the 45-target ARM matrix is unchanged.

Qualified client library SHA256:
`da61e62e79e45976cc69fb8743411417adce996b2a4152f86ec173c2e9f0cf70`.
Own factory probe:
`df9ec9e9dd93bbfe50853ac3c757e989707ca54c000154ccdc258d38a90455ac`.
The SDK probe remains
`c82e04634393621ce89105d7980c405e49e97f5fc6f29f1a9a5c6fdd2d1ef702`;
the server library is unchanged.

Next is two-channel composition: independent source objects, sealed relays and
backend connections; exact pre-exec/exec admission of both descriptors; separate
policy and SDK epochs within the existing accept budget; observation of both
SDK connection names; and complete retirement of all stream queues. Retired
aliases must never become a fresh connection. No second SDK channel, permanent
mode controller or final cloud-Alice network policy is installed by this change.
