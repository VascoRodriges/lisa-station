/* Native persistence tests in a fresh throwaway directory; no real mode changes. */
#define _GNU_SOURCE
#include <stdlib.h>
#include <sys/wait.h>
#include "mode_store.h"

#define CHECK(condition, name) do { ++checks; if (!(condition)) { \
    fprintf(stderr, "failed:%s\n", name); failed = 1; goto cleanup; } } while (0)

static int replace_record(int directory, const char *text, mode_t permissions) {
    if (unlinkat(directory, "mode.state", 0) && errno != ENOENT) return -1;
    int file = openat(directory, "mode.state", O_CREAT | O_EXCL | O_WRONLY | O_CLOEXEC, permissions);
    if (file < 0) return -1;
    int result = store_write_all(file, text, strlen(text));
    if (fchmod(file, permissions)) result = -1;
    if (close(file)) result = -1;
    return result;
}

int main(int argc, char **argv) {
    umask(077);
    const char *base = "/tmp";
    if (argc == 2 && !strcmp(argv[1], "--station-storage") && !geteuid()) base = "/data/opt/lisa-controller-lab";
    else if (argc != 1) return 2;
    char path[256]; snprintf(path, sizeof(path), "%s/mode-store-test.XXXXXX", base);
    if (!mkdtemp(path)) return 3;
    int directory = open(path, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    if (directory < 0) return 3;
    unsigned checks = 0; int failed = 0, held = -1;
    uid_t owner = geteuid(); struct mode_record record;
    CHECK(mode_store_read(directory, owner, &record) == STORE_MISSING &&
          mode_store_boot_choice(directory, owner) == LISA_MODE_PAUSED, "missing_fails_closed");
    CHECK(mode_store_request(directory, owner, 0, LISA_MODE_ALICE, &record) == STORE_OK &&
          record.revision == 1 && mode_store_boot_choice(directory, owner) == LISA_MODE_ALICE, "first_commit");
    CHECK(mode_store_request(directory, owner, 0, LISA_MODE_LISA, &record) == STORE_CONFLICT &&
          mode_store_boot_choice(directory, owner) == LISA_MODE_ALICE, "stale_revision_cannot_overwrite");
    CHECK(mode_store_request(directory, owner, 1, LISA_MODE_LISA, &record) == STORE_OK &&
          record.revision == 2 && mode_store_boot_choice(directory, owner) == LISA_MODE_LISA, "durable_next_commit");
    held = openat(directory, "mode.lock", O_RDWR | O_CLOEXEC | O_NOFOLLOW);
    CHECK(held >= 0 && !flock(held, LOCK_EX | LOCK_NB) &&
          mode_store_request(directory, owner, 2, LISA_MODE_ALICE, &record) == STORE_BUSY, "parallel_request_rejected");
    close(held); held = -1;
    CHECK(!replace_record(directory, "corrupted\n", 0600) &&
          mode_store_boot_choice(directory, owner) == LISA_MODE_PAUSED &&
          mode_store_request(directory, owner, 0, LISA_MODE_ALICE, &record) == STORE_INVALID,
          "corruption_never_enables_alice");
    const char *bad[] = {"LISA_MODE_V1 -1 alice\n", "LISA_MODE_V1 0 alice\n", "LISA_MODE_V1 01 alice\n",
                        "LISA_MODE_V1 1 alice\nextra", "LISA_MODE_V2 1 alice\n", "LISA_MODE_V1 1 unknown\n",
                        "LISA_MODE_V1 1 alice", "LISA_MODE_V1 1 alice\n\n"};
    for (unsigned i = 0; i < sizeof(bad) / sizeof(bad[0]); ++i)
        CHECK(!replace_record(directory, bad[i], 0600) &&
              mode_store_boot_choice(directory, owner) == LISA_MODE_PAUSED, "noncanonical_record_rejected");
    CHECK(!replace_record(directory, "LISA_MODE_V1 1 alice\n", 0666) &&
          mode_store_boot_choice(directory, owner) == LISA_MODE_PAUSED, "writable_record_rejected");
    CHECK(!unlinkat(directory, "mode.state", 0) &&
          !symlinkat("mode.lock", directory, "mode.state") &&
          mode_store_read(directory, owner, &record) == STORE_INVALID &&
          mode_store_request(directory, owner, 0, LISA_MODE_ALICE, &record) == STORE_INVALID,
          "symlink_not_followed");
    CHECK(!unlinkat(directory, "mode.state", 0) &&
          mode_store_request(directory, owner, 0, LISA_MODE_LISA, &record) == STORE_OK, "reset_test_fixture");
    int partial = openat(directory, ".interrupted.tmp", O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
    CHECK(partial >= 0 && write(partial, "LISA_MODE_V1 2 ali", 18) == 18, "interrupted_temporary_write");
    close(partial);
    CHECK(mode_store_boot_choice(directory, owner) == LISA_MODE_LISA &&
          mode_store_read(directory, owner, &record) == STORE_OK && record.revision == 1,
          "unpublished_partial_write_does_not_change_mode");
    int barrier[2]; pid_t contenders[2];
    CHECK(!pipe(barrier), "concurrency_barrier");
    for (int i = 0; i < 2; ++i) {
        contenders[i] = fork();
        CHECK(contenders[i] >= 0, "concurrent_request_fork");
        if (!contenders[i]) {
            close(barrier[1]); char start;
            if (read(barrier[0], &start, 1) != 1) _exit(99);
            struct mode_record next;
            enum store_result result = mode_store_request(directory, owner, 1,
                i ? LISA_MODE_ALICE : LISA_MODE_PAUSED, &next);
            _exit(result == STORE_OK ? 0 : result == STORE_BUSY || result == STORE_CONFLICT ? 10 : 99);
        }
    }
    close(barrier[0]);
    CHECK(write(barrier[1], "gg", 2) == 2, "concurrent_request_release");
    close(barrier[1]);
    int successes = 0, rejected = 0;
    for (int i = 0; i < 2; ++i) {
        int result;
        CHECK(waitpid(contenders[i], &result, 0) == contenders[i] && WIFEXITED(result), "concurrent_request_exit");
        successes += WEXITSTATUS(result) == 0; rejected += WEXITSTATUS(result) == 10;
    }
    CHECK(successes == 1 && rejected == 1 && mode_store_read(directory, owner, &record) == STORE_OK &&
          record.revision == 2, "only_one_concurrent_request_commits");
    CHECK(!replace_record(directory, "LISA_MODE_V1 18446744073709551615 lisa\n", 0600) &&
          mode_store_request(directory, owner, UINT64_MAX, LISA_MODE_ALICE, &record) == STORE_INVALID,
          "revision_overflow_rejected");
cleanup:
    if (held >= 0) close(held);
    (void)unlinkat(directory, "mode.state", 0); (void)unlinkat(directory, "mode.lock", 0);
    (void)unlinkat(directory, ".interrupted.tmp", 0); close(directory);
    int removed = rmdir(path) == 0;
    printf("{\"selftest\":\"mode-store\",\"checks\":%u,\"ok\":%s,\"temporary_directory_removed\":%s,"
           "\"production_mode_changed\":false}\n", checks, failed ? "false" : "true", removed ? "true" : "false");
    return failed || !removed ? 4 : 0;
}
