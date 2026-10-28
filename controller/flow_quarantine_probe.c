/* Own loopback flows only. The administrative driver installs exact-tuple
 * quarantine between synchronized phases. No arbitrary address/port inputs.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include "socket_diag.h"
#include "loopback_socket.h"

static const char *label, *protocol;
static unsigned checks, failures;
static int check(const char *name, int ok) {
    ++checks; failures += !ok;
    printf("{\"event\":\"flow-check\",\"family\":\"%s\",\"protocol\":\"%s\","
        "\"check\":\"%s\",\"ok\":%s}\n", label, protocol, name, ok ? "true" : "false");
    fflush(stdout);
    return ok;
}

static void event(const char *name) {
    printf("{\"event\":\"%s\",\"family\":\"%s\",\"protocol\":\"%s\"}\n", name, label, protocol);
    fflush(stdout);
}

static int command(char expected) {
    struct pollfd ready = {STDIN_FILENO, POLLIN, 0};
    char actual;
    return poll(&ready, 1, 7000) == 1 && read(STDIN_FILENO, &actual, 1) == 1 && actual == expected;
}

static int readable(int fd, int timeout) {
    struct pollfd item = {fd, POLLIN, 0};
    int result = poll(&item, 1, timeout);
    return result < 0 ? -1 : result && item.revents;
}

static unsigned port(int fd) {
    struct sockaddr_storage address;
    socklen_t length = sizeof(address);
    if (getsockname(fd, (struct sockaddr *)&address, &length)) return 0;
    return ntohs(address.ss_family == AF_INET ? ((struct sockaddr_in *)&address)->sin_port :
                  ((struct sockaddr_in6 *)&address)->sin6_port);
}

static int ready(struct pair *target) {
    unsigned source = port(target->client), destination = port(target->peer);
    if (!source || !destination || source == destination) return 0;
    printf("{\"event\":\"flow-ready\",\"family\":\"%s\",\"protocol\":\"%s\","
        "\"source_port\":%u,\"destination_port\":%u}\n", label, protocol, source, destination);
    fflush(stdout);
    return 1;
}

static void close_pair(struct pair *pair) {
    struct linger abortive = {1, 0};
    if (pair->client >= 0) {
        setsockopt(pair->client, SOL_SOCKET, SO_LINGER, &abortive, sizeof(abortive));
        close(pair->client);
    }
    if (pair->peer >= 0) {
        setsockopt(pair->peer, SOL_SOCKET, SO_LINGER, &abortive, sizeof(abortive));
        close(pair->peer);
    }
}

static int tcp_case(int family, int mapped) {
    struct pair target = {-1, -1}, control = {-1, -1};
    int result = 1;
    struct inet_diag_sockid id;
    struct inet_diag_msg found;
    struct stat info;
    if (!check("baseline", !make_pair(family, mapped, &target) &&
        !make_pair(family, mapped, &control) && exchange(&target) && exchange(&control))) goto done;
    if (!check("own_inode_confirmed", !socket_id(target.client, family, &id) &&
        !diag_exchange(family, &id, 0, &found) && !fstat(target.client, &info) &&
        found.idiag_inode == info.st_ino)) goto done;
    if (!ready(&target) || !command('d')) goto done;
    int destroyed = !diag_exchange(family, &found.id, 1, NULL);
    char byte;
    errno = 0;
    ssize_t count = recv(target.client, &byte, 1, MSG_DONTWAIT);
    if (!check("client_destroyed", destroyed && count < 0 && errno == ECONNABORTED)) goto done;
    if (!check("reset_quarantined", readable(target.peer, 250) == 0)) goto done;
    if (!check("control_after_destroy", exchange(&control))) goto done;
    event("flow-destroyed");
    if (!command('o')) goto done;
    close(target.client); target.client = -1;
    int lookup = diag_exchange(family, &found.id, 0, &found);
    if (!check("closed_tuple_absent", lookup == -ENOENT || lookup == -ESTALE)) goto done;
    const char token[] = "lisa-orphan-reset-probe";
    if (!check("stray_sent_to_closed_endpoint", send(target.peer, token, sizeof(token), MSG_NOSIGNAL) ==
        sizeof(token))) goto done;
    if (!check("post_close_kernel_reply_quarantined", readable(target.peer, 250) == 0)) goto done;
    if (!check("control_after_stray", exchange(&control))) goto done;
    event("flow-orphan-triggered");
    if (!command('r')) goto done;
    errno = 0;
    ssize_t sent = send(target.peer, token, sizeof(token), MSG_NOSIGNAL);
    int reset = sent < 0 && errno == ECONNRESET;
    if (readable(target.peer, 1000) > 0) {
        count = recv(target.peer, &byte, 1, MSG_DONTWAIT);
        reset |= count < 0 && errno == ECONNRESET;
    }
    if (!check("reset_arrives_after_rule_removal", reset)) goto done;
    if (!check("control_after_restore", exchange(&control))) goto done;
    result = 0;
done:
    close_pair(&target); close_pair(&control);
    return result;
}

static int make_udp_pair(int family, int mapped, struct pair *pair) {
    struct sockaddr_storage address = {0};
    socklen_t length;
    if (family == AF_INET) {
        struct sockaddr_in *a = (struct sockaddr_in *)&address;
        a->sin_family = AF_INET; a->sin_addr.s_addr = htonl(INADDR_LOOPBACK); length = sizeof(*a);
    } else {
        struct sockaddr_in6 *a = (struct sockaddr_in6 *)&address;
        a->sin6_family = AF_INET6; length = sizeof(*a);
        if (inet_pton(AF_INET6, mapped ? "::ffff:127.0.0.1" : "::1", &a->sin6_addr) != 1) return -1;
    }
    pair->client = socket(family, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    pair->peer = socket(family, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    if (pair->client < 0 || pair->peer < 0 ||
        bind(pair->client, (struct sockaddr *)&address, length) ||
        bind(pair->peer, (struct sockaddr *)&address, length)) return -1;
    return 0;
}

static ssize_t udp_send(struct pair *pair) {
    struct sockaddr_storage destination;
    socklen_t length = sizeof(destination);
    if (getsockname(pair->peer, (struct sockaddr *)&destination, &length)) return -2;
    return sendto(pair->client, "lisa-flow-probe", 15, MSG_NOSIGNAL,
                  (struct sockaddr *)&destination, length);
}

static int udp_delivers(struct pair *pair) {
    char data[64];
    struct sockaddr_storage from;
    socklen_t length = sizeof(from);
    if (udp_send(pair) != 15 || readable(pair->peer, 500) <= 0) return 0;
    ssize_t size = recvfrom(pair->peer, data, sizeof(data), MSG_DONTWAIT, (struct sockaddr *)&from, &length);
    unsigned source = ntohs(from.ss_family == AF_INET ? ((struct sockaddr_in *)&from)->sin_port :
                               ((struct sockaddr_in6 *)&from)->sin6_port);
    return size == 15 && !memcmp(data, "lisa-flow-probe", 15) && source == port(pair->client);
}

static int udp_blocked(struct pair *pair) {
    errno = 0;
    ssize_t result = udp_send(pair);
    int acceptable = result == 15 || (result == -1 && (errno == EPERM || errno == EACCES));
    return acceptable && readable(pair->peer, 250) == 0;
}

static int udp_case(int family, int mapped) {
    struct pair target = {-1, -1}, control = {-1, -1};
    int result = 1;
    if (!check("baseline", !make_udp_pair(family, mapped, &target) &&
        !make_udp_pair(family, mapped, &control) && udp_delivers(&target) && udp_delivers(&control))) goto done;
    if (!ready(&target) || !command('i')) goto done;
    if (!check("input_quarantined", udp_blocked(&target))) goto done;
    if (!check("control_after_input", udp_delivers(&control))) goto done;
    event("flow-input-blocked");
    if (!command('b')) goto done;
    if (!check("output_quarantined", udp_blocked(&target))) goto done;
    if (!check("control_after_output", udp_delivers(&control))) goto done;
    event("flow-output-blocked");
    if (!command('r')) goto done;
    if (!check("target_after_restore", udp_delivers(&target))) goto done;
    if (!check("control_after_restore", udp_delivers(&control))) goto done;
    result = 0;
done:
    close_pair(&target); close_pair(&control);
    return result;
}

int main(int argc, char **argv) {
    if (argc != 4 || strcmp(argv[1], "--own-loopback-flow") || geteuid() || getgid() || getegid()) return 2;
    int mapped = !strcmp(argv[2], "mapped");
    int family = !strcmp(argv[2], "4") ? AF_INET : AF_INET6;
    if (family == AF_INET6 && !mapped && strcmp(argv[2], "6")) return 2;
    if (strcmp(argv[3], "tcp") && strcmp(argv[3], "udp")) return 2;
    label = mapped ? "ipv4-mapped-ipv6" : family == AF_INET ? "ipv4" : "ipv6";
    protocol = argv[3];
    alarm(25);
    int result = !strcmp(protocol, "tcp") ? tcp_case(family, mapped) : udp_case(family, mapped);
    printf("{\"event\":\"flow-summary\",\"family\":\"%s\",\"protocol\":\"%s\","
        "\"checks\":%u,\"failures\":%u,\"microphone_opened\":false,\"vendor_processes_changed\":false}\n",
        label, protocol, checks, failures);
    return result || failures;
}
