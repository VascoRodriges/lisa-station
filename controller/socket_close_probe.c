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
struct pair { int client, peer; };
static unsigned checks, failures;
static int check(const char *family, const char *name, int ok) {
    ++checks; failures += !ok;
    printf("{\"event\":\"socket-close-check\",\"family\":\"%s\",\"check\":\"%s\",\"ok\":%s}\n",
        family, name, ok ? "true" : "false");
    fflush(stdout);
    return ok;
}

static int make_pair(int family, int mapped, struct pair *pair) {
    int server = socket(family, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (server < 0) return -1;
    struct sockaddr_storage address = {0};
    socklen_t length;
    if (family == AF_INET) {
        struct sockaddr_in *a = (struct sockaddr_in *)&address;
        a->sin_family = AF_INET; a->sin_addr.s_addr = htonl(INADDR_LOOPBACK); length = sizeof(*a);
    } else {
        struct sockaddr_in6 *a = (struct sockaddr_in6 *)&address;
        a->sin6_family = AF_INET6; length = sizeof(*a);
        int only = !mapped;
        if (setsockopt(server, IPPROTO_IPV6, IPV6_V6ONLY, &only, sizeof(only))) goto fail;
        if (inet_pton(AF_INET6, mapped ? "::ffff:127.0.0.1" : "::1", &a->sin6_addr) != 1) goto fail;
    }
    if (bind(server, (struct sockaddr *)&address, length) ||
        getsockname(server, (struct sockaddr *)&address, &length) || listen(server, 1)) goto fail;
    pair->client = socket(family, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (pair->client < 0) goto fail;
    struct timeval limit = {1, 0};
    if (setsockopt(pair->client, SOL_SOCKET, SO_SNDTIMEO, &limit, sizeof(limit)) ||
        connect(pair->client, (struct sockaddr *)&address, length)) goto fail;
    pair->peer = accept4(server, NULL, NULL, SOCK_CLOEXEC);
    if (pair->peer < 0) goto fail;
    close(server);
    return 0;
fail:
    close(server);
    return -1;
}

static int exchange(struct pair *pair) {
    const char token[] = "lisa-socket-probe";
    char data[sizeof(token)];
    if (send(pair->client, token, sizeof(token), MSG_NOSIGNAL) != sizeof(token)) return 0;
    struct pollfd ready = {pair->peer, POLLIN, 0};
    return poll(&ready, 1, 1000) == 1 && recv(pair->peer, data, sizeof(data), MSG_DONTWAIT) ==
        sizeof(token) && !memcmp(data, token, sizeof(token));
}

static int socket_id(int fd, int family, struct inet_diag_sockid *id) {
    struct sockaddr_storage local = {0}, peer = {0};
    socklen_t length = sizeof(local);
    if (getsockname(fd, (struct sockaddr *)&local, &length)) return -1;
    length = sizeof(peer);
    if (getpeername(fd, (struct sockaddr *)&peer, &length)) return -1;
    memset(id, 0, sizeof(*id));
    if (family == AF_INET) {
        struct sockaddr_in *a = (struct sockaddr_in *)&local, *b = (struct sockaddr_in *)&peer;
        id->idiag_sport = a->sin_port; id->idiag_dport = b->sin_port;
        memcpy(id->idiag_src, &a->sin_addr, 4); memcpy(id->idiag_dst, &b->sin_addr, 4);
    } else {
        struct sockaddr_in6 *a = (struct sockaddr_in6 *)&local, *b = (struct sockaddr_in6 *)&peer;
        id->idiag_sport = a->sin6_port; id->idiag_dport = b->sin6_port;
        memcpy(id->idiag_src, &a->sin6_addr, 16); memcpy(id->idiag_dst, &b->sin6_addr, 16);
    }
    id->idiag_cookie[0] = id->idiag_cookie[1] = INET_DIAG_NOCOOKIE;
    return 0;
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
