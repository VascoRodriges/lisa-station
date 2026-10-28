/* Own ephemeral loopback fixtures shared by kernel qualification programs. */
#ifndef LISA_LOOPBACK_SOCKET_H
#define LISA_LOOPBACK_SOCKET_H
#include <arpa/inet.h>
#include <poll.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
#include <linux/inet_diag.h>
struct pair { int client, peer; };
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

#endif
