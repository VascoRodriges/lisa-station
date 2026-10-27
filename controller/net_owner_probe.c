/* Qualify process-group packet ownership on the real kernel.
 * Own ephemeral loopback sockets only, no microphone, external addresses,
 * firewall writes or vendor process changes. The administrator installs a
 * temporary rule for the otherwise unused test group around the blocked run.
 */
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <linux/audit.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <poll.h>
#include <signal.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>
#include "vendor_identity.h"

#define TEST_GID 57341
#define LIMIT_MS 600
#define TOKEN "lisa-owner-probe"

static int wait_readable(int fd) {
    struct pollfd item = {fd, POLLIN, 0};
    return poll(&item, 1, LIMIT_MS) == 1 && (item.revents & POLLIN);
}

static int client_attempt(int family, int type, const struct sockaddr *address,
                          socklen_t length, int use_group, int go_fd) {
    if (use_group && vendor_identity_check(TEST_GID)) return 5;
    int fd = socket(family, type | SOCK_CLOEXEC | SOCK_NONBLOCK, 0);
    if (fd < 0) return 6;
    if (type == SOCK_STREAM) {
        struct linger linger = {1, 0};
        if (setsockopt(fd, SOL_SOCKET, SO_LINGER, &linger, sizeof(linger))) return 6;
        int result = connect(fd, address, length);
        if (result && errno != EINPROGRESS) { close(fd); return 10; }
        struct pollfd ready = {fd, POLLOUT, 0};
        int error = 0; socklen_t error_length = sizeof(error);
        if (poll(&ready, 1, LIMIT_MS) != 1 ||
            getsockopt(fd, SOL_SOCKET, SO_ERROR, &error, &error_length) || error) {
            close(fd); return 10;
        }
    } else if (connect(fd, address, length)) { close(fd); return 10; }
    if (send(fd, TOKEN, sizeof(TOKEN), MSG_NOSIGNAL) != (ssize_t)sizeof(TOKEN)) {
        close(fd); return 10;
    }
    char response[sizeof(TOKEN)] = {0};
    int delivered = wait_readable(fd) && recv(fd, response, sizeof(response), 0) ==
                    (ssize_t)sizeof(TOKEN) && !memcmp(response, TOKEN, sizeof(TOKEN));
    if (delivered && go_fd >= 0) {
        char go;
        if (read(go_fd, &go, 1) != 1 || go != 'g') { close(fd); return 6; }
        if (send(fd, TOKEN, sizeof(TOKEN), MSG_NOSIGNAL) != (ssize_t)sizeof(TOKEN)) {
            int denied = errno == EPERM || errno == EACCES;
            close(fd); return denied ? 10 : 6;
        }
        delivered = wait_readable(fd) && recv(fd, response, sizeof(response), 0) ==
                    (ssize_t)sizeof(TOKEN) && !memcmp(response, TOKEN, sizeof(TOKEN));
    }
    close(fd);
    return delivered ? 0 : 10;
}

static int attempt(int family, int type, int grouped, int blocked) {
    int server = socket(family, type | SOCK_CLOEXEC, 0);
    if (server < 0) return 3;
    struct sockaddr_storage storage; memset(&storage, 0, sizeof(storage));
    socklen_t length;
    if (family == AF_INET) {
        struct sockaddr_in *address = (struct sockaddr_in *)&storage;
        address->sin_family = AF_INET; address->sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        length = sizeof(*address);
    } else {
        struct sockaddr_in6 *address = (struct sockaddr_in6 *)&storage;
        address->sin6_family = AF_INET6; address->sin6_addr = in6addr_loopback;
        length = sizeof(*address);
        int one = 1;
        if (setsockopt(server, IPPROTO_IPV6, IPV6_V6ONLY, &one, sizeof(one))) return 3;
    }
    if (bind(server, (struct sockaddr *)&storage, length) ||
        getsockname(server, (struct sockaddr *)&storage, &length) ||
        (type == SOCK_STREAM && listen(server, 1))) { close(server); return 3; }
    pid_t child = fork();
    if (child < 0) { close(server); return 3; }
    if (!child) {
        close(server); /* No inherited network descriptor created as group 0. */
        if (grouped && vendor_identity_prepare(TEST_GID)) _exit(5);
        char port[8];
        snprintf(port, sizeof(port), "%u", family == AF_INET ?
            (unsigned)ntohs(((struct sockaddr_in *)&storage)->sin_port) :
            (unsigned)ntohs(((struct sockaddr_in6 *)&storage)->sin6_port));
        execl("/proc/self/exe", "net-owner-probe", "--client", family == AF_INET ? "4" : "6",
              type == SOCK_STREAM ? "tcp" : "udp", grouped ? "grouped" : "root", port, (char *)NULL);
        _exit(7);
    }
    int received = 0;
    if (wait_readable(server)) {
        int connection = type == SOCK_STREAM ? accept4(server, NULL, NULL, SOCK_CLOEXEC) : server;
        char request[sizeof(TOKEN)];
        struct sockaddr_storage peer; socklen_t peer_length = sizeof(peer);
        if (connection >= 0 && wait_readable(connection)) {
            ssize_t count = recvfrom(connection, request, sizeof(request), 0,
                                     (struct sockaddr *)&peer, &peer_length);
            if (count == (ssize_t)sizeof(TOKEN) && !memcmp(request, TOKEN, sizeof(TOKEN))) {
                received = 1;
                if (type == SOCK_STREAM) (void)send(connection, request, sizeof(request), MSG_NOSIGNAL);
                else (void)sendto(connection, request, sizeof(request), 0, (struct sockaddr *)&peer, peer_length);
            }
        }
        if (connection >= 0 && connection != server) close(connection);
    }
    int result = 0;
    if (waitpid(child, &result, 0) != child) { close(server); return 3; }
    close(server);
    int allowed = WIFEXITED(result) && WEXITSTATUS(result) == 0 && received;
    int denied = WIFEXITED(result) && WEXITSTATUS(result) == 10 && !received;
    int expected_block = grouped && blocked;
    int ok = expected_block ? denied : allowed;
    printf("{\"event\":\"owner-probe\",\"family\":%d,\"transport\":\"%s\","
           "\"grouped\":%s,\"expected_blocked\":%s,\"delivered\":%s,\"ok\":%s,\"client_exit\":%d}\n",
           family == AF_INET ? 4 : 6, type == SOCK_STREAM ? "tcp" : "udp",
           grouped ? "true" : "false", expected_block ? "true" : "false",
           allowed ? "true" : "false", ok ? "true" : "false",
           WIFEXITED(result) ? WEXITSTATUS(result) : -1);
    return ok ? 0 : 4;
}

/* The first exchange completes before announcing readiness. An administrator
 * then attaches the temporary owner rule and sends 'g' over stdin. The second
 * exchange uses exactly the same socket, including TCP's existing connection.
 */
static int existing(int family, int type, int grouped) {
    int server = socket(family, type | SOCK_CLOEXEC, 0), go[2];
    if (server < 0 || pipe(go)) return 3;
    struct sockaddr_storage storage; memset(&storage, 0, sizeof(storage));
    socklen_t length;
    if (family == AF_INET) {
        struct sockaddr_in *address = (struct sockaddr_in *)&storage;
        address->sin_family = AF_INET; address->sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        length = sizeof(*address);
    } else {
        struct sockaddr_in6 *address = (struct sockaddr_in6 *)&storage;
        address->sin6_family = AF_INET6; address->sin6_addr = in6addr_loopback;
        length = sizeof(*address);
        int one = 1;
        if (setsockopt(server, IPPROTO_IPV6, IPV6_V6ONLY, &one, sizeof(one))) return 3;
    }
    if (bind(server, (struct sockaddr *)&storage, length) ||
        getsockname(server, (struct sockaddr *)&storage, &length) ||
        (type == SOCK_STREAM && listen(server, 1))) return 3;
    pid_t child = fork();
    if (child < 0) return 3;
    if (!child) {
        close(server); close(go[1]);
        if (grouped && vendor_identity_prepare(TEST_GID)) _exit(5);
        char port[8], fd[16];
        snprintf(port, sizeof(port), "%u", family == AF_INET ?
            (unsigned)ntohs(((struct sockaddr_in *)&storage)->sin_port) :
            (unsigned)ntohs(((struct sockaddr_in6 *)&storage)->sin6_port));
        snprintf(fd, sizeof(fd), "%d", go[0]);
        execl("/proc/self/exe", "net-owner-probe", "--held-client", family == AF_INET ? "4" : "6",
              type == SOCK_STREAM ? "tcp" : "udp", grouped ? "grouped" : "root", port, fd, (char *)NULL);
        _exit(7);
    }
    close(go[0]);
    if (!wait_readable(server)) return 4;
    int connection = type == SOCK_STREAM ? accept4(server, NULL, NULL, SOCK_CLOEXEC) : server;
    if (connection < 0 || !wait_readable(connection)) return 4;
    char request[sizeof(TOKEN)]; struct sockaddr_storage peer; socklen_t peer_length = sizeof(peer);
    if (recvfrom(connection, request, sizeof(request), 0, (struct sockaddr *)&peer, &peer_length) !=
        (ssize_t)sizeof(TOKEN) || memcmp(request, TOKEN, sizeof(TOKEN))) return 4;
    if (type == SOCK_STREAM) (void)send(connection, request, sizeof(request), MSG_NOSIGNAL);
    else (void)sendto(connection, request, sizeof(request), 0, (struct sockaddr *)&peer, peer_length);
    puts("{\"event\":\"existing-ready\"}");
    char command;
    if (read(STDIN_FILENO, &command, 1) != 1 || command != 'g' || write(go[1], "g", 1) != 1) return 4;
    close(go[1]);
    int received = 0;
    if (wait_readable(connection)) {
        ssize_t count = recvfrom(connection, request, sizeof(request), 0,
                                 (struct sockaddr *)&peer, &peer_length);
        received = count == (ssize_t)sizeof(TOKEN) && !memcmp(request, TOKEN, sizeof(TOKEN));
        if (received) {
            if (type == SOCK_STREAM) (void)send(connection, request, sizeof(request), MSG_NOSIGNAL);
            else (void)sendto(connection, request, sizeof(request), 0, (struct sockaddr *)&peer, peer_length);
        }
    }
    int result;
    if (waitpid(child, &result, 0) != child) return 4;
    if (connection != server) close(connection);
    close(server);
    int ok = WIFEXITED(result) && (grouped ? WEXITSTATUS(result) == 10 && !received :
                                                  WEXITSTATUS(result) == 0 && received);
    printf("{\"event\":\"existing-result\",\"family\":%d,\"transport\":\"%s\","
           "\"grouped\":%s,\"second_payload_received\":%s,\"ok\":%s}\n",
           family == AF_INET ? 4 : 6, type == SOCK_STREAM ? "tcp" : "udp",
           grouped ? "true" : "false", received ? "true" : "false", ok ? "true" : "false");
    return ok ? 0 : 4;
}

int main(int argc, char **argv) {
    setvbuf(stdout, NULL, _IOLBF, 0); alarm(15); signal(SIGPIPE, SIG_IGN);
    if ((argc == 6 && !strcmp(argv[1], "--client")) || (argc == 7 && !strcmp(argv[1], "--held-client"))) {
        int family = !strcmp(argv[2], "4") ? AF_INET : !strcmp(argv[2], "6") ? AF_INET6 : 0;
        int type = !strcmp(argv[3], "tcp") ? SOCK_STREAM : !strcmp(argv[3], "udp") ? SOCK_DGRAM : 0;
        int grouped = !strcmp(argv[4], "grouped");
        if (geteuid() || !family || !type || (!grouped && (strcmp(argv[4], "root") || getgid()))) return 2;
        char *end; long port = strtol(argv[5], &end, 10);
        if (*end || port < 1 || port > 65535) return 2;
        struct sockaddr_storage storage; memset(&storage, 0, sizeof(storage));
        socklen_t length;
        if (family == AF_INET) {
            struct sockaddr_in *address = (struct sockaddr_in *)&storage;
            address->sin_family = AF_INET; address->sin_addr.s_addr = htonl(INADDR_LOOPBACK);
            address->sin_port = htons((unsigned short)port); length = sizeof(*address);
        } else {
            struct sockaddr_in6 *address = (struct sockaddr_in6 *)&storage;
            address->sin6_family = AF_INET6; address->sin6_addr = in6addr_loopback;
            address->sin6_port = htons((unsigned short)port); length = sizeof(*address);
        }
        int go_fd = -1;
        if (argc == 7) {
            long value = strtol(argv[6], &end, 10);
            if (*end || value < 3 || value > 65535) return 2;
            go_fd = (int)value;
        }
        return client_attempt(family, type, (struct sockaddr *)&storage, length, grouped, go_fd);
    }
    if (argc == 5 && !strcmp(argv[1], "existing")) {
        int family = !strcmp(argv[2], "4") ? AF_INET : !strcmp(argv[2], "6") ? AF_INET6 : 0;
        int type = !strcmp(argv[3], "tcp") ? SOCK_STREAM : !strcmp(argv[3], "udp") ? SOCK_DGRAM : 0;
        int grouped = !strcmp(argv[4], "grouped");
        if (geteuid() || !family || !type || (!grouped && strcmp(argv[4], "root"))) return 2;
        return existing(family, type, grouped);
    }
    if (geteuid() || argc != 2 || (strcmp(argv[1], "baseline") && strcmp(argv[1], "blocked"))) return 2;
    int blocked = !strcmp(argv[1], "blocked"), failed = 0;
    for (int family = 0; family < 2; ++family)
        for (int type = 0; type < 2; ++type)
            for (int grouped = 0; grouped < 2; ++grouped)
                failed |= attempt(family ? AF_INET6 : AF_INET, type ? SOCK_DGRAM : SOCK_STREAM, grouped, blocked);
    return failed ? 4 : 0;
}
