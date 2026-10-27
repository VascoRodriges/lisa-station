/* Experimental identity primitive, not a complete vendor sandbox.
 * New sockets get a dedicated group for xt_owner; both ARM UID/GID syscall
 * families are locked. Drop network-administration/raw and ptrace capabilities
 * from current and bounding sets so exec cannot restore them.
 * Callers still must close inherited sockets and audit IPC/file relays.
 */
#include <linux/capability.h>

static int vendor_identity_check(gid_t group) {
    struct __user_cap_header_struct header = {_LINUX_CAPABILITY_VERSION_3, 0};
    struct __user_cap_data_struct caps[2];
    unsigned mask = (1u << CAP_NET_ADMIN) | (1u << CAP_NET_RAW) | (1u << CAP_SYS_PTRACE);
    if (syscall(SYS_capget, &header, caps) || getgid() != group || geteuid() != 0 ||
        prctl(PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0) != 1 ||
        ((caps[0].effective | caps[0].permitted | caps[0].inheritable) & mask)) return -1;
    const int changes[] = {SYS_setgid, SYS_setgid32, SYS_setfsgid, SYS_setfsgid32};
    for (unsigned i = 0; i < sizeof(changes) / sizeof(changes[0]); ++i) {
        errno = 0;
        if (syscall(changes[i], 0) != -1 || errno != EPERM) return -1;
    }
    return 0;
}

static int vendor_identity_prepare(gid_t group) {
    if (setgroups(0, NULL) || setgid(group)) return -1;
    struct __user_cap_header_struct header = {_LINUX_CAPABILITY_VERSION_3, 0};
    struct __user_cap_data_struct caps[2];
    const int remove[] = {CAP_NET_ADMIN, CAP_NET_RAW, CAP_SYS_PTRACE};
    if (syscall(SYS_capget, &header, caps)) return -1;
    for (unsigned i = 0; i < sizeof(remove) / sizeof(remove[0]); ++i) {
        int cap = remove[i]; unsigned word = (unsigned)cap / 32, mask = 1u << (cap % 32);
        if (prctl(PR_CAPBSET_DROP, cap, 0, 0, 0)) return -1;
        caps[word].effective &= ~mask; caps[word].permitted &= ~mask; caps[word].inheritable &= ~mask;
    }
    if (syscall(SYS_capset, &header, caps)) return -1;
#define DENY(n) BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, n, 0, 1), \
    BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | EPERM)
    struct sock_filter filter[] = {
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, arch)),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, AUDIT_ARCH_ARM, 1, 0),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL),
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, nr)),
        DENY(SYS_setgid), DENY(SYS_setregid), DENY(SYS_setresgid), DENY(SYS_setfsgid),
        DENY(SYS_setgroups), DENY(SYS_setuid), DENY(SYS_setreuid), DENY(SYS_setresuid), DENY(SYS_setfsuid),
        DENY(SYS_setgid32), DENY(SYS_setregid32), DENY(SYS_setresgid32), DENY(SYS_setfsgid32),
        DENY(SYS_setgroups32), DENY(SYS_setuid32), DENY(SYS_setreuid32), DENY(SYS_setresuid32), DENY(SYS_setfsuid32),
        DENY(SYS_ptrace), DENY(SYS_process_vm_writev), DENY(SYS_mount), DENY(SYS_umount2),
        DENY(SYS_unshare), DENY(SYS_setns), DENY(SYS_bpf),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW)
    };
#undef DENY
    struct sock_fprog program = {sizeof(filter) / sizeof(filter[0]), filter};
    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) ||
        prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &program)) return -1;
    return vendor_identity_check(group);
}
