/* Per-process denial of System V IPC and POSIX message queues. The vendor
 * kernel lacks IPC namespaces. AF_UNIX, shared files and copied data remain
 * separate relay requirements; this never changes host queue permissions. */
#ifndef LISA_VENDOR_IPC_GUARD_H
#define LISA_VENDOR_IPC_GUARD_H
#include <errno.h>
#include <linux/audit.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <stddef.h>
#include <sys/prctl.h>
#include <sys/syscall.h>

static inline int vendor_ipc_guard(void) {
#if defined(__arm__)
    const unsigned architecture=AUDIT_ARCH_ARM;
#elif defined(__x86_64__)
    const unsigned architecture=AUDIT_ARCH_X86_64;
#elif defined(__aarch64__)
    const unsigned architecture=AUDIT_ARCH_AARCH64;
#else
#error Unsupported IPC guard audit architecture
#endif
#define IPC_DENY(n) BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K,n,0,1),BPF_STMT(BPF_RET|BPF_K,SECCOMP_RET_ERRNO|EPERM)
    struct sock_filter filter[]={
        BPF_STMT(BPF_LD|BPF_W|BPF_ABS,offsetof(struct seccomp_data,arch)),
        BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K,architecture,1,0),BPF_STMT(BPF_RET|BPF_K,SECCOMP_RET_KILL),
        BPF_STMT(BPF_LD|BPF_W|BPF_ABS,offsetof(struct seccomp_data,nr)),
#if defined(__x86_64__)
        BPF_JUMP(BPF_JMP|BPF_JSET|BPF_K,0x40000000u,0,1),BPF_STMT(BPF_RET|BPF_K,SECCOMP_RET_ERRNO|EPERM),
#endif
#ifdef SYS_ipc
        IPC_DENY(SYS_ipc),
#endif
#ifdef SYS_msgget
        IPC_DENY(SYS_msgget),
#endif
#ifdef SYS_msgctl
        IPC_DENY(SYS_msgctl),
#endif
#ifdef SYS_msgsnd
        IPC_DENY(SYS_msgsnd),
#endif
#ifdef SYS_msgrcv
        IPC_DENY(SYS_msgrcv),
#endif
#ifdef SYS_shmget
        IPC_DENY(SYS_shmget),
#endif
#ifdef SYS_shmat
        IPC_DENY(SYS_shmat),
#endif
#ifdef SYS_shmdt
        IPC_DENY(SYS_shmdt),
#endif
#ifdef SYS_shmctl
        IPC_DENY(SYS_shmctl),
#endif
#ifdef SYS_semget
        IPC_DENY(SYS_semget),
#endif
#ifdef SYS_semctl
        IPC_DENY(SYS_semctl),
#endif
#ifdef SYS_semop
        IPC_DENY(SYS_semop),
#endif
#ifdef SYS_semtimedop
        IPC_DENY(SYS_semtimedop),
#endif
#ifdef SYS_semtimedop_time64
        IPC_DENY(SYS_semtimedop_time64),
#endif
#ifdef SYS_mq_open
        IPC_DENY(SYS_mq_open),
#endif
#ifdef SYS_mq_unlink
        IPC_DENY(SYS_mq_unlink),
#endif
#ifdef SYS_mq_timedsend
        IPC_DENY(SYS_mq_timedsend),
#endif
#ifdef SYS_mq_timedreceive
        IPC_DENY(SYS_mq_timedreceive),
#endif
#ifdef SYS_mq_timedsend_time64
        IPC_DENY(SYS_mq_timedsend_time64),
#endif
#ifdef SYS_mq_timedreceive_time64
        IPC_DENY(SYS_mq_timedreceive_time64),
#endif
#ifdef SYS_mq_notify
        IPC_DENY(SYS_mq_notify),
#endif
#ifdef SYS_mq_getsetattr
        IPC_DENY(SYS_mq_getsetattr),
#endif
        BPF_STMT(BPF_RET|BPF_K,SECCOMP_RET_ALLOW),
    };
#undef IPC_DENY
    struct sock_fprog program={sizeof(filter)/sizeof(filter[0]),filter};
    return prctl(PR_SET_NO_NEW_PRIVS,1,0,0,0)||prctl(PR_SET_SECCOMP,SECCOMP_MODE_FILTER,&program)?-1:0;
}
#endif
