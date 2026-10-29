/* Startup admission primitive, NOT an installed boot gate or isolation proof.
 * Guardian must retain the shared lease until its fixed start operation ends.
 * Never use acquire/close followed by an unguarded exec. Mode requests use the
 * same exclusive mode.lock and cannot commit while an admitted start is active.
 */
#ifndef LISA_SERVICE_GATE_H
#define LISA_SERVICE_GATE_H
#include "mode_store.h"

enum gate_result { GATE_DENIED, GATE_GRANTED, GATE_BUSY };
struct gate_lease { int descriptor; uint64_t revision; };

static inline int gate_boot_valid(const char *boot) {
    if (!boot || strlen(boot) != 36) return 0;
    for (unsigned i = 0; i < 36; ++i) {
        if (i == 8 || i == 13 || i == 18 || i == 23) {
            if (boot[i] != '-') return 0;
        } else if (!((boot[i] >= '0' && boot[i] <= '9') || (boot[i] >= 'a' && boot[i] <= 'f'))) return 0;
    }
    return 1;
}

static inline int gate_permit_valid(int runtime, uid_t owner, uint64_t revision, const char *boot) {
    if (!store_directory_valid(runtime, owner) || !gate_boot_valid(boot)) return 0;
    int file = openat(runtime, "vendor.permit", O_RDONLY | O_NONBLOCK | O_NOFOLLOW | O_CLOEXEC);
    if (file < 0) return 0;
    if (!store_file_valid(file, owner)) { close(file); return 0; }
    char actual[160], expected[160];
    size_t used = 0;
    while (used < sizeof(actual)) {
        ssize_t count = read(file, actual + used, sizeof(actual) - used);
        if (count < 0 && errno == EINTR) continue;
        if (count < 0) { close(file); return 0; }
        if (!count) break;
        used += (size_t)count;
    }
    close(file);
    int length = snprintf(expected, sizeof(expected), "LISA_VENDOR_PERMIT_V1 %" PRIu64 " %s\n", revision, boot);
    return length > 0 && (size_t)length == used && !memcmp(actual, expected, used);
}

static inline enum gate_result gate_acquire_internal(int state, int runtime, uid_t owner,
                                     const char *boot, struct gate_lease *lease,int starting) {
    if (lease->descriptor >= 0) return GATE_DENIED;
    lease->revision = 0;
    if (!store_directory_valid(state, owner) || !store_directory_valid(runtime, owner) ||
        !gate_boot_valid(boot)) return GATE_DENIED;
    if(starting && (mode_store_fault_pending(state,owner)||mode_store_close_pending(state,owner)||mode_store_open_pending(state,owner))) return GATE_DENIED;
    int lock = openat(state, "mode.lock", O_RDWR | O_CREAT | O_NONBLOCK | O_NOFOLLOW | O_CLOEXEC, 0600);
    if (lock < 0) return GATE_DENIED;
    if (!store_file_valid(lock, owner)) { close(lock); return GATE_DENIED; }
    if (flock(lock, LOCK_SH | LOCK_NB)) {
        int busy = errno == EWOULDBLOCK;
        close(lock); return busy ? GATE_BUSY : GATE_DENIED;
    }
    struct mode_record record;
    if ((starting && (mode_store_fault_pending(state,owner)||mode_store_close_pending(state,owner)||mode_store_open_pending(state,owner))) ||
        mode_store_read(state, owner, &record) != STORE_OK || record.requested != LISA_MODE_ALICE ||
        !gate_permit_valid(runtime, owner, record.revision, boot)) {
        close(lock); return GATE_DENIED;
    }
    lease->descriptor = lock; lease->revision = record.revision;
    return GATE_GRANTED;
}

static inline enum gate_result gate_acquire(int state,int runtime,uid_t owner,const char *boot,struct gate_lease *lease) {
    return gate_acquire_internal(state,runtime,owner,boot,lease,1);
}

/* A pending fence blocks new starts immediately. Existing actors keep their
 * old admission until the executor has denied traffic and revoked the permit.
 * This prevents an early shutdown/reset before the network barrier is in place. */
static inline enum gate_result gate_acquire_running(int state,int runtime,uid_t owner,const char *boot,struct gate_lease *lease) {
    return gate_acquire_internal(state,runtime,owner,boot,lease,0);
}

static inline void gate_release(struct gate_lease *lease) {
    if (lease->descriptor >= 0) close(lease->descriptor);
    lease->descriptor = -1; lease->revision = 0;
}
#endif
