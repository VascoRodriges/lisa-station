/* Fixed service executables, private temporary profiles only, no clock writes.
 * Administrative qualification helper, never an HA forced-command entry point.
 */
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <linux/audit.h>
#include <linux/capability.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <poll.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <sys/random.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>

static int dns_query(int family, int stream, unsigned port) {
    unsigned char question[] = {0,0,1,0,0,1,0,0,0,0,0,0,7,'e','x','a','m','p','l','e',3,'c','o','m',0,0,1,0,1};
    if (getrandom(question, 2, 0) != 2) return 0;
    int fd = socket(family, (stream ? SOCK_STREAM : SOCK_DGRAM) | SOCK_CLOEXEC, 0);
    if (fd < 0) return 0;
    struct timeval limit = {3, 0};
    struct sockaddr_storage address = {0};
    socklen_t length;
    if (family == AF_INET) {
        struct sockaddr_in *a = (struct sockaddr_in *)&address;
        a->sin_family = AF_INET; a->sin_port = htons(port);
        a->sin_addr.s_addr = htonl(INADDR_LOOPBACK); length = sizeof(*a);
    } else {
        struct sockaddr_in6 *a = (struct sockaddr_in6 *)&address;
        a->sin6_family = AF_INET6; a->sin6_port = htons(port);
        a->sin6_addr = in6addr_loopback; length = sizeof(*a);
    }
    int ok = 0;
    if (setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &limit, sizeof(limit)) ||
        setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &limit, sizeof(limit)) ||
        connect(fd, (struct sockaddr *)&address, length)) goto done;
    unsigned char buffer[4096], prefix[2] = {0, sizeof(question)};
    if (stream && send(fd, prefix, 2, MSG_NOSIGNAL) != 2) goto done;
    if (send(fd, question, sizeof(question), MSG_NOSIGNAL) != sizeof(question)) goto done;
    ssize_t size;
    if (stream) {
        if (recv(fd, prefix, 2, MSG_WAITALL) != 2) goto done;
        unsigned needed = ((unsigned)prefix[0] << 8) | prefix[1];
        if (needed < sizeof(question) || needed > sizeof(buffer)) goto done;
        size = recv(fd, buffer, needed, MSG_WAITALL);
        if (size != (ssize_t)needed) goto done;
    } else size = recv(fd, buffer, sizeof(buffer), 0);
    ok = size >= (ssize_t)sizeof(question) && !memcmp(buffer, question, 2) &&
        (buffer[2] & 0xfe) == 0x80 && !(buffer[3] & 15) && buffer[4] == 0 && buffer[5] == 1 &&
        (buffer[6] || buffer[7]) && !memcmp(buffer + 12, question + 12, sizeof(question)-12);
done:
    close(fd);
    return ok;
}

static int private_profile(const char *path, const char *kind) {
    const char prefix[] = "/tmp/lisa-service-probe.";
    if (strncmp(path, prefix, sizeof(prefix)-1)) return 0;
    const char *suffix = path + sizeof(prefix)-1;
    unsigned length = 0;
    while ((*suffix >= 'a' && *suffix <= 'z') || (*suffix >= 'A' && *suffix <= 'Z') ||
           (*suffix >= '0' && *suffix <= '9')) { ++suffix; ++length; }
    if (length < 6 || length > 16 || *suffix != '/' || strcmp(suffix+1, kind)) return 0;
    char parent[128];
    size_t size = (size_t)(suffix-path);
    if (size >= sizeof(parent)) return 0;
    memcpy(parent, path, size); parent[size] = 0;
    int directory = open(parent, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    struct stat info;
    if (directory < 0) return 0;
    int valid = !fstat(directory, &info) && info.st_uid == 65534 && !(info.st_mode & 0077);
    int file = openat(directory, kind, O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC);
    valid = valid && file >= 0 && !fstat(file, &info) && S_ISREG(info.st_mode) &&
        info.st_uid == 65534 && info.st_nlink == 1 && !(info.st_mode & 0077);
    if (file >= 0) close(file);
    close(directory);
    return valid;
}

int main(int argc, char **argv) {
    if (argc != 3 || geteuid()) return 2;
    int query = !strcmp(argv[1], "--dns-query");
    int dns = !strcmp(argv[1], "--dns");
    unsigned port = 0;
    if (query) {
        char *end;
        unsigned long value = strtoul(argv[2], &end, 10);
        if (!*argv[2] || *end || value < 1024 || value > 65535) return 3;
        port = (unsigned)value;
    } else if ((!dns && strcmp(argv[1], "--time")) ||
        !private_profile(argv[2], dns ? "unbound.conf" : "chrony.conf")) return 3;
    const char *program = dns ? "/usr/sbin/unbound" : "/usr/sbin/chronyd";
    struct stat info;
    if (lstat(program, &info) || !S_ISREG(info.st_mode) || info.st_uid ||
        (info.st_mode & (0022 | S_ISUID | S_ISGID))) return 3;
    struct rlimit limit;
    if (getrlimit(RLIMIT_NOFILE, &limit) || limit.rlim_cur > 1048576) return 4;
    for (unsigned long fd = 3; fd < limit.rlim_cur; ++fd) close((int)fd);
    if (clearenv() || setenv("PATH", "/usr/sbin:/usr/bin:/sbin:/bin", 1) ||
        setgroups(0, NULL) || setgid(65534) || setuid(65534) ||
        prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)) return 4;
    struct __user_cap_header_struct header = {_LINUX_CAPABILITY_VERSION_3, 0};
    struct __user_cap_data_struct caps[2];
    if (syscall(SYS_capget, &header, caps) || caps[0].effective || caps[1].effective ||
        caps[0].permitted || caps[1].permitted || caps[0].inheritable || caps[1].inheritable ||
        getuid() != 65534 || getgid() != 65534) return 4;
#define DENY(n) BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, n, 0, 1), \
    BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | EPERM)
    struct sock_filter filter[] = {
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, arch)),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, AUDIT_ARCH_ARM, 1, 0),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL),
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, nr)),
        DENY(SYS_clock_settime), DENY(SYS_clock_adjtime), DENY(SYS_adjtimex),
        DENY(SYS_settimeofday),
#ifdef SYS_stime
        DENY(SYS_stime),
#endif
#ifdef SYS_clock_settime64
        DENY(SYS_clock_settime64), DENY(SYS_clock_adjtime64),
#endif
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW)
    };
#undef DENY
    struct sock_fprog rules = {sizeof(filter)/sizeof(filter[0]), filter};
    if (prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &rules) ||
        prctl(PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0) != 1) return 4;
    printf("{\"event\":\"profile-child\",\"uid\":65534,\"gid\":65534,\"capabilities_zero\":true,"
        "\"no_new_privs\":true,\"clock_writes_denied\":true}\n");
    fflush(stdout);
    /* alarm is inherited across exec; the DNS child cannot outlive its trial. */
    alarm(query ? 20 : dns ? 40 : 12);
    if (query) {
        int failures = 0;
        for (int family = 4; family <= 6; family += 2) {
            for (int stream = 0; stream <= 1; ++stream) {
                int ok = dns_query(family == 4 ? AF_INET : AF_INET6, stream, port);
                failures += !ok;
                printf("{\"event\":\"dns-query\",\"family\":%d,\"transport\":\"%s\",\"ok\":%s}\n",
                    family, stream ? "tcp" : "udp", ok ? "true" : "false");
            }
        }
        return failures ? 6 : 0;
    }
    if (dns) execl(program, "unbound", "-d", "-p", "-c", argv[2], (char *)NULL);
    else execl(program, "chronyd", "-Q", "-d", "-t", "8", "-f", argv[2], (char *)NULL);
    return 5;
}
