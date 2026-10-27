/* Controller foundation: read-only status and an opt-in disposable sandbox test.
 * No microphone, playback, mode changes, network traffic or boot modifications.
 * The sandbox is applied only to a new child, never to existing vendor daemons.
 */
#define _GNU_SOURCE
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <linux/audit.h>
#include <linux/filter.h>
#include <linux/input.h>
#include <linux/seccomp.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

#if defined(__arm__)
#define EXPECTED_ARCH AUDIT_ARCH_ARM
#else
#error This controller build targets the verified armhf Station firmware only.
#endif

static const char *boolean(int value) { return value ? "true" : "false"; }

static int read_file(const char *path, char *buffer, size_t capacity) {
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) return -1;
    ssize_t count = read(fd, buffer, capacity - 1);
    close(fd);
    if (count < 0) return -1;
    buffer[count] = 0;
    return (int)count;
}

static int supported_device(void) {
    char data[512];
    int size = read_file("/proc/device-tree/compatible", data, sizeof(data));
    if (size < 0) return 0;
    const char expected[] = "yandex,station-midi";
    for (int i = 0; i + (int)sizeof(expected) <= size; ++i)
        if ((i == 0 || data[i - 1] == 0) && !memcmp(data + i, expected, sizeof(expected))) return 1;
    return 0;
}

static int workers(int *launchers, int *stopped) {
    DIR *directory = opendir("/proc");
    if (!directory) return -1;
    int count = 0; *launchers = 0; *stopped = 0;
    struct dirent *entry;
    while ((entry = readdir(directory))) {
        if (!entry->d_name[0] || strspn(entry->d_name, "0123456789") != strlen(entry->d_name)) continue;
        char path[512], executable[512];
        snprintf(path, sizeof(path), "/proc/%s/exe", entry->d_name);
        ssize_t n = readlink(path, executable, sizeof(executable) - 1);
        if (n < 0) continue;
        executable[n] = 0;
        if (!strcmp(executable, "/system/vendor/quasar/maind")) ++count;
        if (!strcmp(executable, "/system/vendor/quasar/quasar_launcher2")) {
            ++*launchers;
            snprintf(path, sizeof(path), "/proc/%s/stat", entry->d_name);
            char stat[1024];
            if (read_file(path, stat, sizeof(stat)) >= 0) {
                char *tail = strrchr(stat, ')');
                if (tail && tail[1] == ' ' && tail[2] == 'T') ++*stopped;
            }
        }
    }
    closedir(directory);
    return count;
}

static int physical_mute(void) {
    int fd = open("/dev/input/event0", O_RDONLY | O_NONBLOCK | O_CLOEXEC);
    if (fd < 0) return -1;
    char name[80] = {0}; unsigned char bits[8] = {0};
    int result = -1;
    if (ioctl(fd, EVIOCGNAME(sizeof(name)), name) >= 0 && !strcmp(name, "gpio-keys") &&
        ioctl(fd, EVIOCGSW(sizeof(bits)), bits) >= 0)
        result = !!(bits[SW_MUTE_DEVICE / 8] & (1u << (SW_MUTE_DEVICE % 8)));
    close(fd);
    return result;
}

static int status(void) {
    if (!supported_device()) { fputs("unsupported_device\n", stderr); return 3; }
    int launchers, stopped, count = workers(&launchers, &stopped);
    if (count < 0) return 4;
    int mute = physical_mute();
    struct statvfs root;
    int readonly = statvfs("/", &root) == 0 ? !!(root.f_flag & ST_RDONLY) : -1;
    printf("{\"schema_version\":1,\"agent_kind\":\"controller_foundation\","
           "\"device_model\":\"yandex,station-midi\",\"managed\":false,"
           "\"actual_mode\":\"unmanaged\",\"requested_mode\":null,"
           "\"isolation\":\"unverified\",\"apply_supported\":false,"
           "\"stock_workers\":%d,\"stock_launchers\":%d,\"stopped_launchers\":%d,"
           "\"physical_mute\":%s,\"root_readonly\":%s,"
           "\"capabilities\":[\"status\",\"sandbox-selftest\"],"
           "\"audio_opened\":false}\n", count, launchers, stopped,
           mute < 0 ? "null" : boolean(mute), readonly < 0 ? "null" : boolean(readonly));
    return 0;
}

static int isolate_child(void) {
    for (int fd = 0; fd < 3; ++fd) {
        struct stat st;
        if (fstat(fd, &st) || S_ISSOCK(st.st_mode)) return -1;
    }
    struct rlimit limit;
    if (getrlimit(RLIMIT_NOFILE, &limit) || limit.rlim_cur > 65536) return -1;
    for (unsigned long fd = 3; fd < limit.rlim_cur; ++fd) close((int)fd);
    if (setgroups(0, NULL) || setgid(65534) || setuid(65534)) return -1;
#define DENY(n) BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, n, 0, 1), \
    BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | EPERM)
    struct sock_filter filter[] = {
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, arch)),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, EXPECTED_ARCH, 1, 0),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL),
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, nr)),
        DENY(SYS_socket), DENY(SYS_socketpair), DENY(SYS_connect),
        DENY(SYS_bind), DENY(SYS_listen), DENY(SYS_accept), DENY(SYS_accept4),
        DENY(SYS_sendto), DENY(SYS_sendmsg), DENY(SYS_sendmmsg),
        DENY(SYS_recvfrom), DENY(SYS_recvmsg), DENY(SYS_recvmmsg),
        DENY(SYS_ptrace), DENY(SYS_process_vm_writev),
        DENY(SYS_mount), DENY(SYS_umount2), DENY(SYS_setns), DENY(SYS_unshare),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW)
    };
#undef DENY
    struct sock_fprog program = {sizeof(filter) / sizeof(filter[0]), filter};
    return prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) ||
           prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &program) ? -1 : 0;
}

static int socket_denied(int family, int type, int protocol) {
    errno = 0;
    int fd = socket(family, type, protocol);
    int result = fd == -1 && errno == EPERM;
    if (fd >= 0) close(fd);
    return result;
}

static int sandbox_checks(int inherited) {
    int pair[2]; errno = 0;
    int pair_result = socketpair(AF_UNIX, SOCK_STREAM, 0, pair);
    int pair_denied = pair_result == -1 && errno == EPERM;
    if (pair_result == 0) { close(pair[0]); close(pair[1]); }
    int tcp4 = socket_denied(AF_INET, SOCK_STREAM, 0);
    int tcp6 = socket_denied(AF_INET6, SOCK_STREAM, 0);
    int udp4 = socket_denied(AF_INET, SOCK_DGRAM, 0);
    int udp6 = socket_denied(AF_INET6, SOCK_DGRAM, 0);
    int raw = socket_denied(AF_PACKET, SOCK_RAW, 0);
    int unix_socket = socket_denied(AF_UNIX, SOCK_STREAM, 0);
    errno = 0; int connect_result = connect(-1, NULL, 0);
    int connect_denied = connect_result == -1 && errno == EPERM;
    errno = 0; ssize_t send_result = sendto(-1, "", 0, 0, NULL, 0);
    int send_denied = send_result == -1 && errno == EPERM;
    int nnp = prctl(PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0) == 1;
    int active = prctl(PR_GET_SECCOMP, 0, 0, 0, 0) == 2;
    int unprivileged = getuid() == 65534 && geteuid() == 65534;
    int ok = tcp4 && tcp6 && udp4 && udp6 && raw && unix_socket && pair_denied &&
             connect_denied && send_denied && nnp && active && unprivileged;
    printf("{\"event\":\"sandbox-check\",\"after_exec\":%s,\"ok\":%s,"
           "\"tcp4_denied\":%s,\"tcp6_denied\":%s,\"udp4_denied\":%s,"
           "\"udp6_denied\":%s,\"raw_denied\":%s,\"unix_denied\":%s,"
           "\"socketpair_denied\":%s,\"connect_denied\":%s,\"sendto_denied\":%s,"
           "\"no_new_privs\":%s,\"seccomp\":%s,\"unprivileged\":%s}\n",
           boolean(inherited), boolean(ok), boolean(tcp4), boolean(tcp6), boolean(udp4),
           boolean(udp6), boolean(raw), boolean(unix_socket), boolean(pair_denied),
           boolean(connect_denied), boolean(send_denied), boolean(nnp), boolean(active), boolean(unprivileged));
    return ok ? 0 : 5;
}

static int wait_ok(pid_t pid) {
    int result;
    while (waitpid(pid, &result, 0) < 0) if (errno != EINTR) return 0;
    return WIFEXITED(result) && WEXITSTATUS(result) == 0;
}

static int parent_socket_available(void) {
    int fd = socket(AF_INET, SOCK_STREAM, 0); /* Creation only: no connect/send. */
    if (fd < 0) return 0;
    close(fd); return 1;
}

static int selftest(void) {
    if (!supported_device() || geteuid() != 0) return 3;
    int before = parent_socket_available();
    pid_t child = fork();
    if (child < 0) return 4;
    if (child == 0) {
        if (isolate_child() || sandbox_checks(0)) _exit(5);
        pid_t descendant = fork();
        if (descendant < 0) _exit(6);
        if (descendant == 0) {
            /* Exec preserves no_new_privs and the installed filter. */
            execl("/proc/self/exe", "station-ctl", "--sandbox-exec-child", (char *)NULL);
            _exit(7);
        }
        _exit(wait_ok(descendant) ? 0 : 8);
    }
    int child_ok = wait_ok(child), after = parent_socket_available();
    printf("{\"event\":\"sandbox-selftest-complete\",\"ok\":%s,"
           "\"parent_socket_before\":%s,\"parent_socket_after\":%s,"
           "\"network_traffic_generated\":false,\"audio_opened\":false,"
           "\"vendor_processes_modified\":false,\"whole_device_isolation_proven\":false}\n",
           boolean(before && child_ok && after), boolean(before), boolean(after));
    return before && child_ok && after ? 0 : 9;
}

int main(int argc, char **argv) {
    setvbuf(stdout, NULL, _IOLBF, 0);
    alarm(10);
    if (argc != 2) return 2;
    if (!strcmp(argv[1], "status")) return status();
    if (!strcmp(argv[1], "--sandbox-selftest")) return selftest();
    if (!strcmp(argv[1], "--sandbox-exec-child")) return sandbox_checks(1);
    /* Mode changes are deliberately absent until a complete isolation backend. */
    fputs("unsupported_command\n", stderr); return 2;
}
