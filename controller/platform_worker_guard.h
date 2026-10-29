/* A post-fork, pre-exec worker may create pthreads and signal only its own
 * fixed thread group. This is one layer, not a filesystem/network sandbox.
 * Install in a fresh single-threaded child AFTER credential/capability setup.
 * The trusted parent must independently bound lifetime and reap this worker.
 */
#ifndef LISA_PLATFORM_WORKER_GUARD_H
#define LISA_PLATFORM_WORKER_GUARD_H
#include <errno.h>
#include <linux/audit.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <sched.h>
#include <signal.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <unistd.h>
#if defined(__arm__) && __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
#define PLATFORM_WORKER_ARCH AUDIT_ARCH_ARM
#elif defined(__x86_64__) && !defined(__ILP32__)
#define PLATFORM_WORKER_ARCH AUDIT_ARCH_X86_64
#else
#error Unreviewed platform worker syscall ABI
#endif
static inline int platform_worker_guard(pid_t parent){
    pid_t own=getpid();
    if(parent<=1||own!=syscall(SYS_gettid)||getppid()!=parent){errno=EINVAL;return -1;}
    if(prctl(PR_SET_PDEATHSIG,SIGKILL,0,0,0)||getppid()!=parent||
        prctl(PR_SET_NO_NEW_PRIVS,1,0,0,0))return -1;
    /* Shared FS and FD table are mandatory too: the parent's leader census
     * must not overlook a thread's separate descriptor table or root view. */
    const unsigned required=CLONE_VM|CLONE_FS|CLONE_FILES|CLONE_SIGHAND|CLONE_THREAD;
    const unsigned allowed=required|CLONE_SYSVSEM|CLONE_SETTLS|CLONE_PARENT_SETTID|
        CLONE_CHILD_CLEARTID|CLONE_CHILD_SETTID;
#define WORKER_DENY(n) BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K,n,0,1),BPF_STMT(BPF_RET|BPF_K,SECCOMP_RET_ERRNO|EPERM)
#define WORKER_SELF(n) BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K,n,0,4), \
    BPF_STMT(BPF_LD|BPF_W|BPF_ABS,offsetof(struct seccomp_data,args[0])), \
    BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K,(uint32_t)own,0,1), \
    BPF_STMT(BPF_RET|BPF_K,SECCOMP_RET_ALLOW), \
    BPF_STMT(BPF_RET|BPF_K,SECCOMP_RET_ERRNO|EPERM)
    struct sock_filter filter[]={
        BPF_STMT(BPF_LD|BPF_W|BPF_ABS,offsetof(struct seccomp_data,arch)),
        BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K,PLATFORM_WORKER_ARCH,1,0),
        BPF_STMT(BPF_RET|BPF_K,SECCOMP_RET_KILL),
        BPF_STMT(BPF_LD|BPF_W|BPF_ABS,offsetof(struct seccomp_data,nr)),
#ifdef __x86_64__
        /* AUDIT_ARCH_X86_64 also covers x32; never allow its alternate table. */
        BPF_JUMP(BPF_JMP|BPF_JGE|BPF_K,0x40000000u,0,1),
        BPF_STMT(BPF_RET|BPF_K,SECCOMP_RET_ERRNO|EPERM),
#endif
        WORKER_DENY(SYS_fork),WORKER_DENY(SYS_vfork),WORKER_DENY(SYS_tkill),
        WORKER_DENY(SYS_unshare),WORKER_DENY(SYS_setns),
#ifdef SYS_pidfd_send_signal
        WORKER_DENY(SYS_pidfd_send_signal),
#endif
#ifdef SYS_close_range
        WORKER_DENY(SYS_close_range),
#endif
#ifdef SYS_clone3
        /* glibc can fall back to inspectable legacy clone. The pointer-based
         * clone3 argument structure cannot be validated by classic seccomp. */
        BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K,SYS_clone3,0,1),
        BPF_STMT(BPF_RET|BPF_K,SECCOMP_RET_ERRNO|ENOSYS),
#endif
        WORKER_SELF(SYS_kill),WORKER_SELF(SYS_tgkill),
        WORKER_SELF(SYS_rt_sigqueueinfo),WORKER_SELF(SYS_rt_tgsigqueueinfo),
        BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K,SYS_prctl,0,4),
        BPF_STMT(BPF_LD|BPF_W|BPF_ABS,offsetof(struct seccomp_data,args[0])),
        BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K,PR_SET_PDEATHSIG,0,1),
        BPF_STMT(BPF_RET|BPF_K,SECCOMP_RET_ERRNO|EPERM),
        BPF_STMT(BPF_RET|BPF_K,SECCOMP_RET_ALLOW),
        BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K,SYS_clone,0,10),
        BPF_STMT(BPF_LD|BPF_W|BPF_ABS,offsetof(struct seccomp_data,args[0])+4),
        BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K,0,1,0),
        BPF_STMT(BPF_RET|BPF_K,SECCOMP_RET_ERRNO|EPERM),
        BPF_STMT(BPF_LD|BPF_W|BPF_ABS,offsetof(struct seccomp_data,args[0])),
        BPF_JUMP(BPF_JMP|BPF_JSET|BPF_K,~allowed,0,1),
        BPF_STMT(BPF_RET|BPF_K,SECCOMP_RET_ERRNO|EPERM),
        BPF_STMT(BPF_ALU|BPF_AND|BPF_K,required),
        BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K,required,0,1),
        BPF_STMT(BPF_RET|BPF_K,SECCOMP_RET_ALLOW),
        BPF_STMT(BPF_RET|BPF_K,SECCOMP_RET_ERRNO|EPERM),
        BPF_STMT(BPF_RET|BPF_K,SECCOMP_RET_ALLOW),
    };
#undef WORKER_SELF
#undef WORKER_DENY
    struct sock_fprog program={sizeof(filter)/sizeof(filter[0]),filter};
    return prctl(PR_SET_SECCOMP,SECCOMP_MODE_FILTER,&program);
}
#undef PLATFORM_WORKER_ARCH
#endif
