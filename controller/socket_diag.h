/* Exact TCP socket lookup/destruction, Linux inet_diag UAPI.
 * No dumps, wildcard destruction, tuple-only deletion or caller-supplied shell.
 * Callers must establish ownership and quarantine the flow before production use.
 */
#ifndef LISA_SOCKET_DIAG_H
#define LISA_SOCKET_DIAG_H
#include <errno.h>
#include <linux/inet_diag.h>
#include <linux/netlink.h>
#include <linux/sock_diag.h>
#include <netinet/in.h>
#include <poll.h>
#include <stdint.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

static int diag_same_tuple(const struct inet_diag_sockid *a, const struct inet_diag_sockid *b) {
    return a->idiag_sport == b->idiag_sport && a->idiag_dport == b->idiag_dport &&
        !memcmp(a->idiag_src, b->idiag_src, sizeof(a->idiag_src)) &&
        !memcmp(a->idiag_dst, b->idiag_dst, sizeof(a->idiag_dst)) &&
        (!a->idiag_if || a->idiag_if == b->idiag_if);
}

/* Returns zero or a negative errno. Each exchange uses its own bound socket. */
static int diag_exchange(int family, const struct inet_diag_sockid *id, int destroy,
                         struct inet_diag_msg *answer) {
    if ((family != AF_INET && family != AF_INET6) || !id->idiag_sport || !id->idiag_dport ||
        (destroy && id->idiag_cookie[0] == INET_DIAG_NOCOOKIE &&
                    id->idiag_cookie[1] == INET_DIAG_NOCOOKIE)) return -EINVAL;
    int fd = socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_SOCK_DIAG);
    if (fd < 0) return -errno;
    int result = -EPROTO;
    struct sockaddr_nl local = {.nl_family = AF_NETLINK}, kernel = {.nl_family = AF_NETLINK};
    if (bind(fd, (struct sockaddr *)&local, sizeof(local))) { result = -errno; goto done; }
    struct {
        struct nlmsghdr header;
        struct inet_diag_req_v2 request;
    } message = {
        .header = {.nlmsg_len = NLMSG_LENGTH(sizeof(struct inet_diag_req_v2)),
            .nlmsg_type = destroy ? SOCK_DESTROY : SOCK_DIAG_BY_FAMILY,
            .nlmsg_flags = NLM_F_REQUEST | (destroy ? NLM_F_ACK : 0), .nlmsg_seq = 1},
        .request = {.sdiag_family = family, .sdiag_protocol = IPPROTO_TCP,
            .idiag_states = UINT32_MAX}
    };
    message.request.id = *id;
    ssize_t sent = sendto(fd, &message, message.header.nlmsg_len, 0,
                         (struct sockaddr *)&kernel, sizeof(kernel));
    if (sent != (ssize_t)message.header.nlmsg_len) {
        result = sent < 0 ? -errno : -EIO; goto done;
    }
    struct pollfd ready = {fd, POLLIN, 0};
    if (poll(&ready, 1, 1000) != 1) { result = -ETIMEDOUT; goto done; }
    union { struct nlmsghdr align; unsigned char data[8192]; } buffer;
    struct sockaddr_nl sender = {0};
    struct iovec iov = {buffer.data, sizeof(buffer.data)};
    struct msghdr response = {.msg_name = &sender, .msg_namelen = sizeof(sender),
        .msg_iov = &iov, .msg_iovlen = 1};
    ssize_t count = recvmsg(fd, &response, MSG_DONTWAIT);
    if (count < 0) { result = -errno; goto done; }
    if ((response.msg_flags & (MSG_TRUNC | MSG_CTRUNC)) ||
        response.msg_namelen != sizeof(sender) || sender.nl_family != AF_NETLINK ||
        sender.nl_pid || sender.nl_groups) goto done;
    unsigned remaining = (unsigned)count;
    struct nlmsghdr *header = (struct nlmsghdr *)buffer.data;
    if (!NLMSG_OK(header, remaining) || header->nlmsg_seq != 1 ||
        NLMSG_ALIGN(header->nlmsg_len) != (unsigned)remaining ||
        (header->nlmsg_flags & NLM_F_MULTI)) goto done;
    if (header->nlmsg_type == NLMSG_ERROR) {
        if (header->nlmsg_len < NLMSG_LENGTH(sizeof(struct nlmsgerr))) goto done;
        int error = ((struct nlmsgerr *)NLMSG_DATA(header))->error;
        if (error < 0 && error >= -4095) result = error;
        else if (!error && destroy) result = 0;
        goto done;
    }
    if (destroy || !answer || header->nlmsg_type != SOCK_DIAG_BY_FAMILY ||
        header->nlmsg_len < NLMSG_LENGTH(sizeof(*answer))) goto done;
    struct inet_diag_msg *found = (struct inet_diag_msg *)NLMSG_DATA(header);
    if (found->idiag_family != family || !diag_same_tuple(id, &found->id) ||
        !found->idiag_inode || (found->id.idiag_cookie[0] == INET_DIAG_NOCOOKIE &&
        found->id.idiag_cookie[1] == INET_DIAG_NOCOOKIE)) goto done;
    *answer = *found;
    result = 0;
done:
    close(fd);
    return result;
}
#endif
