/* Administrative self-test. Only sockets created here on loopback are queried
 * or destroyed. No arbitrary target arguments, network policy or vendor changes.
 */
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <grp.h>
#include <linux/audit.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <signal.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/prctl.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include "socket_diag.h"
#include "vendor_identity.h"

#define TEST_GID 57341
#include "loopback_socket.h"
static unsigned checks, failures;
static int check(const char *family, const char *name, int ok) {
    ++checks; failures += !ok;
    printf("{\"event\":\"socket-close-check\",\"family\":\"%s\",\"check\":\"%s\",\"ok\":%s}\n",
        family, name, ok ? "true" : "false");
    fflush(stdout);
    return ok;
}

static int restricted_attempt(int family, const struct inet_diag_sockid *id) {
    pid_t child = fork();
    if (child < 0) return 0;
    if (!child) {
        alarm(4);
        long maximum = sysconf(_SC_OPEN_MAX);
        if (maximum < 0 || maximum > 1048576) _exit(3);
        for (long fd = 3; fd < maximum; ++fd) close((int)fd);
        if (vendor_identity_prepare(TEST_GID)) _exit(4);
        _exit(diag_exchange(family, id, 1, NULL) == -EPERM ? 0 : 5);
    }
    int status;
    return waitpid(child, &status, 0) == child && WIFEXITED(status) && !WEXITSTATUS(status);
}

static int run(int family, int mapped, const char *name) {
    struct pair target = {-1, -1}, control = {-1, -1};
    struct inet_diag_sockid id;
    struct inet_diag_msg found;
    struct stat info;
    int result = 1;
    if (!check(name, "own_loopback_pairs", !make_pair(family, mapped, &target) &&
        !make_pair(family, mapped, &control) && exchange(&target) && exchange(&control))) goto done;
    if (!check(name, "lookup_matches_own_inode", !socket_id(target.client, family, &id) &&
        !diag_exchange(family, &id, 0, &found) && !fstat(target.client, &info) &&
        found.idiag_inode == info.st_ino)) goto done;
    if (!check(name, "destroy_requires_cookie", diag_exchange(family, &id, 1, NULL) == -EINVAL &&
        exchange(&target))) goto done;
    struct inet_diag_sockid wrong = found.id;
    wrong.idiag_cookie[0] ^= 1;
    int wrong_result = diag_exchange(family, &wrong, 1, NULL);
    /* Linux 4.9 inet_diag_find_one_icsk maps a cookie mismatch to ENOENT. */
    if (!check(name, "wrong_cookie_rejected", (wrong_result == -ENOENT || wrong_result == -ESTALE) &&
        exchange(&target))) goto done;
    if (!check(name, "restricted_root_denied", restricted_attempt(family, &found.id) &&
        exchange(&target))) goto done;
    if (!check(name, "exact_cookie_destroyed", !diag_exchange(family, &found.id, 1, NULL))) goto done;
    char byte;
    errno = 0;
    ssize_t received = recv(target.client, &byte, 1, MSG_DONTWAIT);
    int closed = received < 0 && errno == ECONNABORTED;
    struct pollfd ready = {target.peer, POLLIN, 0};
    int peer_closed = 0;
    if (poll(&ready, 1, 1000) == 1) {
        received = recv(target.peer, &byte, 1, MSG_DONTWAIT);
        peer_closed = !received || (received < 0 && errno == ECONNRESET);
    }
    if (!check(name, "target_endpoints_closed", closed && peer_closed)) goto done;
    int stale = diag_exchange(family, &found.id, 1, NULL);
    if (!check(name, "stale_destroy_rejected", stale == -ENOENT || stale == -ESTALE)) goto done;
    if (!check(name, "unrelated_connection_survives", exchange(&control))) goto done;
    result = 0;
done:
    if (target.client >= 0) close(target.client);
    if (target.peer >= 0) close(target.peer);
    if (control.client >= 0) close(control.client);
    if (control.peer >= 0) close(control.peer);
    return result;
}

int main(int argc, char **argv) {
    if (argc != 2 || strcmp(argv[1], "--selftest") || geteuid()) return 2;
    alarm(20);
    int result = run(AF_INET, 0, "ipv4");
    result |= run(AF_INET6, 0, "ipv6");
    result |= run(AF_INET6, 1, "ipv4-mapped-ipv6");
    printf("{\"event\":\"socket-close-summary\",\"checks\":%u,\"failures\":%u,"
        "\"microphone_opened\":false,\"vendor_processes_changed\":false}\n", checks, failures);
    return result || failures;
}
