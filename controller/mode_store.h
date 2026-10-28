/* Durable intent only; actual service/privacy state must be observed separately.
 * Production: a root-owned 0700 directory, expected_owner=0. A missing or invalid
 * record never grants permission to start Alice.
 */
#ifndef LISA_MODE_STORE_H
#define LISA_MODE_STORE_H
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/file.h>
#include <sys/random.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

enum lisa_mode { LISA_MODE_PAUSED, LISA_MODE_ALICE, LISA_MODE_LISA };
enum store_result { STORE_OK, STORE_MISSING, STORE_INVALID, STORE_CONFLICT, STORE_BUSY, STORE_IO };
struct mode_record { uint64_t revision; enum lisa_mode requested; };

static inline const char *mode_name(enum lisa_mode mode) {
    switch (mode) {
        case LISA_MODE_PAUSED: return "paused";
        case LISA_MODE_ALICE: return "alice";
        case LISA_MODE_LISA: return "lisa";
    }
    return NULL;
}

static inline int store_directory_valid(int directory, uid_t owner) {
    struct stat info;
    return !fstat(directory, &info) && S_ISDIR(info.st_mode) &&
           info.st_uid == owner && !(info.st_mode & 0077);
}

static inline int store_file_valid(int descriptor, uid_t owner) {
    struct stat info;
    return !fstat(descriptor, &info) && S_ISREG(info.st_mode) &&
           info.st_uid == owner && info.st_nlink == 1 && !(info.st_mode & 0077);
}

static inline enum store_result mode_store_read(int directory, uid_t owner, struct mode_record *record) {
    if (!store_directory_valid(directory, owner)) return STORE_INVALID;
    int descriptor = openat(directory, "mode.state", O_RDONLY | O_NONBLOCK | O_CLOEXEC | O_NOFOLLOW);
    if (descriptor < 0) return errno == ENOENT ? STORE_MISSING : errno == ELOOP ? STORE_INVALID : STORE_IO;
    if (!store_file_valid(descriptor, owner)) { close(descriptor); return STORE_INVALID; }
    char data[128]; size_t used = 0;
    while (used < sizeof(data) - 1) {
        ssize_t count = read(descriptor, data + used, sizeof(data) - 1 - used);
        if (count < 0 && errno == EINTR) continue;
        if (count < 0) { close(descriptor); return STORE_IO; }
        if (!count) break;
        used += (size_t)count;
    }
    close(descriptor); data[used] = 0;
    if (!used || used == sizeof(data) - 1 || memchr(data, 0, used)) return STORE_INVALID;
    unsigned long long revision; char name[16]; int parsed = 0;
    if (sscanf(data, "LISA_MODE_V1 %llu %15s\n%n", &revision, name, &parsed) != 2 ||
        !revision || parsed != (int)used) return STORE_INVALID;
    enum lisa_mode mode;
    if (!strcmp(name, "alice")) mode = LISA_MODE_ALICE;
    else if (!strcmp(name, "lisa")) mode = LISA_MODE_LISA;
    else if (!strcmp(name, "paused")) mode = LISA_MODE_PAUSED;
    else return STORE_INVALID;
    char canonical[128];
    int size = snprintf(canonical, sizeof(canonical), "LISA_MODE_V1 %llu %s\n", revision, mode_name(mode));
    if (size != (int)used || memcmp(data, canonical, used)) return STORE_INVALID;
    record->revision = (uint64_t)revision; record->requested = mode;
    return STORE_OK;
}

/* Presence, corruption or inability to inspect a close fence all deny Alice.
 * The transaction reader interprets its contents separately; boot never guesses. */
static inline int mode_store_close_pending(int directory, uid_t owner) {
    if (!store_directory_valid(directory, owner)) return 1;
    struct stat info;
    if (!fstatat(directory,"closed.request",&info,AT_SYMLINK_NOFOLLOW)) return 1;
    return errno!=ENOENT;
}

static inline enum lisa_mode mode_store_boot_choice(int directory, uid_t owner) {
    if (mode_store_close_pending(directory,owner)) return LISA_MODE_PAUSED;
    struct mode_record record;
    return mode_store_read(directory, owner, &record) == STORE_OK ? record.requested : LISA_MODE_PAUSED;
}

static inline int store_write_all(int descriptor, const char *data, size_t size) {
    while (size) {
        ssize_t written = write(descriptor, data, size);
        if (written < 0 && errno == EINTR) continue;
        if (written <= 0) return -1;
        data += written; size -= (size_t)written;
    }
    return 0;
}

static inline enum store_result mode_store_request(int directory, uid_t owner, uint64_t expected_revision,
                                           enum lisa_mode requested, struct mode_record *committed) {
    if (!mode_name(requested) || !store_directory_valid(directory, owner)) return STORE_INVALID;
    int lock = openat(directory, "mode.lock", O_RDWR | O_CREAT | O_NONBLOCK | O_NOFOLLOW | O_CLOEXEC, 0600);
    if (lock < 0) return errno == ELOOP ? STORE_INVALID : STORE_IO;
    enum store_result result = STORE_IO;
    if (!store_file_valid(lock, owner)) { close(lock); return STORE_INVALID; }
    if (flock(lock, LOCK_EX | LOCK_NB)) {
        result = errno == EWOULDBLOCK ? STORE_BUSY : STORE_IO;
        close(lock); return result;
    }
    struct mode_record current = {0, LISA_MODE_PAUSED};
    result = mode_store_read(directory, owner, &current);
    if (result != STORE_OK && result != STORE_MISSING) { close(lock); return result; }
    if (current.revision != expected_revision) { close(lock); return STORE_CONFLICT; }
    if (current.revision == UINT64_MAX) { close(lock); return STORE_INVALID; }
    struct mode_record next = {current.revision + 1, requested};
    char payload[128], temporary[64];
    int size = snprintf(payload, sizeof(payload), "LISA_MODE_V1 %" PRIu64 " %s\n", next.revision, mode_name(requested));
    uint64_t nonce;
    if (getrandom(&nonce, sizeof(nonce), 0) != (ssize_t)sizeof(nonce)) { close(lock); return STORE_IO; }
    snprintf(temporary, sizeof(temporary), ".mode-%" PRIx64 ".tmp", nonce);
    int output = openat(directory, temporary, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
    if (output < 0) { close(lock); return STORE_IO; }
    int failed = store_write_all(output, payload, (size_t)size) || fsync(output);
    if (close(output)) failed = 1;
    if (!failed && renameat(directory, temporary, directory, "mode.state")) failed = 1;
    if (!failed && fsync(directory)) failed = 1;
    if (failed) {
        (void)unlinkat(directory, temporary, 0);
        result = STORE_IO;
    } else {
        *committed = next; result = STORE_OK;
    }
    close(lock);
    return result;
}
#endif
