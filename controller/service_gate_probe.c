/* Admission/serialization tests in fresh private fixtures; no actual services. */
#define _GNU_SOURCE
#include <stdlib.h>
#include <sys/wait.h>
#include "mode_store.h"
#include "service_gate.h"

static const char BOOT[] = "11111111-2222-4333-8444-555555555555";
static const char NEXT_BOOT[] = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee";

static int replace(int directory, const char *name, const char *text, size_t size, mode_t mode) {
    if (unlinkat(directory, name, 0) && errno != ENOENT) return -1;
    int fd = openat(directory, name, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW, 0600);
    if (fd < 0) return -1;
    int result = store_write_all(fd, text, size) || fchmod(fd, mode);
    if (close(fd)) result = -1;
    return result;
}

static int permit(int runtime, uint64_t revision) {
    char text[160];
    int size = snprintf(text, sizeof(text), "LISA_VENDOR_PERMIT_V1 %" PRIu64 " %s\n", revision, BOOT);
    return replace(runtime, "vendor.permit", text, (size_t)size, 0600);
}

#define CHECK(condition, name) do { ++checks; if (!(condition)) { \
    fprintf(stderr, "failed:%s\n", name); failed = 1; goto cleanup; } } while (0)

int main(int argc, char **argv) {
    umask(077);
    const char *base = "/tmp";
    if (argc == 2 && !strcmp(argv[1], "--station-storage") && !geteuid()) base = "/data/opt/lisa-controller-lab";
    else if (argc != 1) return 2;
    char path[256]; snprintf(path, sizeof(path), "%s/service-gate-test.XXXXXX", base);
    if (!mkdtemp(path)) return 3;
    int root = open(path, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    if (root < 0) return 3;
    int state = -1, runtime = -1, held = -1, failed = 0;
    unsigned checks = 0;
    struct gate_lease lease = {-1, 0}, second = {-1, 0};
    struct mode_record record;
    uid_t owner = geteuid();
    CHECK(!mkdirat(root, "state", 0700) && !mkdirat(root, "run", 0700), "private_fixture");
    state = openat(root, "state", O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    runtime = openat(root, "run", O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    CHECK(state >= 0 && runtime >= 0 && mode_store_boot_choice(state, owner) == LISA_MODE_PAUSED &&
        gate_acquire(state, runtime, owner, BOOT, &lease) == GATE_DENIED, "missing_intent_denied");
    CHECK(!permit(runtime, 1) && gate_acquire(state, runtime, owner, BOOT, &lease) == GATE_DENIED,
        "permit_alone_never_allows_start");
    CHECK(!unlinkat(runtime, "vendor.permit", 0) &&
        mode_store_request(state, owner, 0, LISA_MODE_ALICE, &record) == STORE_OK &&
        gate_acquire(state, runtime, owner, BOOT, &lease) == GATE_DENIED, "intent_alone_denied");
    CHECK(!permit(runtime, 1) && gate_acquire(state, runtime, owner, BOOT, &lease) == GATE_GRANTED &&
        lease.revision == 1 && (fcntl(lease.descriptor, F_GETFD) & FD_CLOEXEC), "matching_admission_lease");
    CHECK(gate_acquire(state, runtime, owner, BOOT, &lease) == GATE_DENIED &&
        lease.descriptor >= 0 && lease.revision == 1, "occupied_lease_not_overwritten");
    CHECK(gate_acquire(state, runtime, owner, BOOT, &second) == GATE_GRANTED,
        "parallel_starts_share_lease");
    gate_release(&second);
    pid_t child = fork();
    CHECK(child >= 0, "transition_contender_fork");
    if (!child) {
        gate_release(&lease);
        _exit(mode_store_request(state, owner, 1, LISA_MODE_LISA, &record) == STORE_BUSY ? 0 : 9);
    }
    int status;
    CHECK(waitpid(child, &status, 0) == child && WIFEXITED(status) && !WEXITSTATUS(status),
        "transition_cannot_commit_during_start");
    gate_release(&lease);
    CHECK(mode_store_request(state, owner, 1, LISA_MODE_LISA, &record) == STORE_OK &&
        gate_acquire(state, runtime, owner, BOOT, &lease) == GATE_DENIED, "lisa_denies_old_permit");
    CHECK(mode_store_request(state, owner, 2, LISA_MODE_ALICE, &record) == STORE_OK &&
        gate_acquire(state, runtime, owner, BOOT, &lease) == GATE_DENIED, "alice_needs_fresh_revision_permit");
    CHECK(!permit(runtime, 3) && gate_acquire(state, runtime, owner, BOOT, &lease) == GATE_GRANTED,
        "fresh_alice_permit_allows");
    gate_release(&lease);
    CHECK(gate_acquire(state, runtime, owner, NEXT_BOOT, &lease) == GATE_DENIED, "previous_boot_denied");
    CHECK(gate_acquire(state, runtime, owner, "invalid", &lease) == GATE_DENIED, "malformed_boot_denied");
    CHECK(!replace(state,"closed.request","corrupt\n",8,0600) &&
        mode_store_boot_choice(state,owner)==LISA_MODE_PAUSED &&
        gate_acquire(state,runtime,owner,BOOT,&lease)==GATE_DENIED,"close_fence_blocks_stale_alice");
    CHECK(gate_acquire_running(state,runtime,owner,BOOT,&lease)==GATE_GRANTED,
        "pending_fence_does_not_stop_before_network_denial");
    gate_release(&lease);
    CHECK(!unlinkat(state,"closed.request",0) && !symlinkat("missing",state,"closed.request") &&
        gate_acquire(state,runtime,owner,BOOT,&lease)==GATE_DENIED &&
        mode_store_boot_choice(state,owner)==LISA_MODE_PAUSED && !unlinkat(state,"closed.request",0),
        "unsafe_close_fence_also_denies_start");
    CHECK(!unlinkat(runtime, "vendor.permit", 0) &&
        gate_acquire(state, runtime, owner, BOOT, &lease) == GATE_DENIED, "revocation_denies_restart");
    const char *bad[] = {
        "LISA_VENDOR_PERMIT_V1 03 11111111-2222-4333-8444-555555555555\n",
        "LISA_VENDOR_PERMIT_V2 3 11111111-2222-4333-8444-555555555555\n",
        "LISA_VENDOR_PERMIT_V1 3 11111111-2222-4333-8444-555555555555\nextra",
        "LISA_VENDOR_PERMIT_V1 3 11111111-2222-4333-8444-555555555555",
        "LISA_VENDOR_PERMIT_V1 -1 11111111-2222-4333-8444-555555555555\n",
    };
    for (unsigned i = 0; i < sizeof(bad)/sizeof(bad[0]); ++i)
        CHECK(!replace(runtime, "vendor.permit", bad[i], strlen(bad[i]), 0600) &&
            gate_acquire(state, runtime, owner, BOOT, &lease) == GATE_DENIED, "noncanonical_permit_denied");
    char embedded[] = "LISA_VENDOR_PERMIT_V1 3 11111111-2222-4333-8444-555555555555\n\0tail";
    CHECK(!replace(runtime, "vendor.permit", embedded, sizeof(embedded)-1, 0600) &&
        gate_acquire(state, runtime, owner, BOOT, &lease) == GATE_DENIED, "embedded_nul_denied");
    CHECK(!permit(runtime, 3) && !fchmodat(runtime, "vendor.permit", 0666, 0) &&
        gate_acquire(state, runtime, owner, BOOT, &lease) == GATE_DENIED, "public_permit_denied");
    CHECK(!permit(runtime, 3) && !linkat(runtime, "vendor.permit", runtime, "linked", 0) &&
        gate_acquire(state, runtime, owner, BOOT, &lease) == GATE_DENIED, "hardlinked_permit_denied");
    CHECK(!unlinkat(runtime, "linked", 0) && !unlinkat(runtime, "vendor.permit", 0) &&
        !symlinkat("missing", runtime, "vendor.permit") &&
        gate_acquire(state, runtime, owner, BOOT, &lease) == GATE_DENIED, "symlink_permit_denied");
    CHECK(!permit(runtime, 3) && !fchmod(runtime, 0755) &&
        gate_acquire(state, runtime, owner, BOOT, &lease) == GATE_DENIED, "public_runtime_denied");
    CHECK(!fchmod(runtime, 0700) && !fchmod(state, 0755) &&
        gate_acquire(state, runtime, owner, BOOT, &lease) == GATE_DENIED, "public_state_denied");
    CHECK(!fchmod(state, 0700) && gate_acquire(state, runtime, owner+1, BOOT, &lease) == GATE_DENIED,
        "wrong_owner_denied");
    held = openat(state, "mode.lock", O_RDWR | O_CLOEXEC | O_NOFOLLOW);
    CHECK(held >= 0 && !flock(held, LOCK_EX | LOCK_NB) &&
        gate_acquire(state, runtime, owner, BOOT, &lease) == GATE_BUSY, "active_transition_denies_start");
    close(held); held = -1;
    CHECK(!fchmodat(state, "mode.lock", 0666, 0) &&
        gate_acquire(state, runtime, owner, BOOT, &lease) == GATE_DENIED, "public_lock_denied");
    CHECK(!fchmodat(state, "mode.lock", 0600, 0) &&
        !replace(state, "mode.state", "damaged\n", 8, 0600) &&
        gate_acquire(state, runtime, owner, BOOT, &lease) == GATE_DENIED, "corrupt_intent_denied");
    const char paused[] = "LISA_MODE_V1 4 paused\n";
    CHECK(!replace(state, "mode.state", paused, sizeof(paused)-1, 0600) && !permit(runtime, 4) &&
        gate_acquire(state, runtime, owner, BOOT, &lease) == GATE_DENIED, "paused_with_valid_permit_denied");
cleanup:
    gate_release(&lease); gate_release(&second);
    if (held >= 0) close(held);
    if (runtime >= 0) { unlinkat(runtime, "vendor.permit", 0); unlinkat(runtime, "linked", 0); close(runtime); }
    if (state >= 0) { unlinkat(state, "mode.state", 0); unlinkat(state, "mode.lock", 0);
        unlinkat(state,"closed.request",0); close(state); }
    unlinkat(root, "run", AT_REMOVEDIR); unlinkat(root, "state", AT_REMOVEDIR); close(root);
    int removed = !rmdir(path);
    printf("{\"selftest\":\"service-gate\",\"checks\":%u,\"ok\":%s,\"temporary_directory_removed\":%s,"
        "\"production_mode_changed\":false}\n", checks, failed ? "false" : "true", removed ? "true" : "false");
    return failed || !removed ? 4 : 0;
}
