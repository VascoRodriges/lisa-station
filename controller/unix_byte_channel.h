/* Preconnected byte channel only. The caller closes all other inherited
 * channels and composes identity/capability, lifecycle and filesystem guards.
 * This layer alone is not a sandbox or a D-Bus protocol implementation. */
#ifndef LISA_UNIX_BYTE_CHANNEL_H
#define LISA_UNIX_BYTE_CHANNEL_H
#include <errno.h>
#include <linux/audit.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <stddef.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/un.h>
#include <unistd.h>
static inline int unix_byte_channel_valid(int fd,pid_t broker){
    struct stat info;struct ucred peer;struct sockaddr_un local,remote;
    socklen_t size=sizeof(peer),a=sizeof(local),b=sizeof(remote);int type=0,domain=0,accepting=1;
    if(broker<=1||broker!=getppid()||fstat(fd,&info)||!S_ISSOCK(info.st_mode)||
        getsockopt(fd,SOL_SOCKET,SO_PEERCRED,&peer,&size)||size!=sizeof(peer)||peer.pid!=broker||peer.uid!=geteuid())return 0;
    size=sizeof(type);if(getsockopt(fd,SOL_SOCKET,SO_TYPE,&type,&size)||size!=sizeof(type)||type!=SOCK_STREAM)return 0;
    size=sizeof(domain);if(getsockopt(fd,SOL_SOCKET,SO_DOMAIN,&domain,&size)||size!=sizeof(domain)||domain!=AF_UNIX)return 0;
    size=sizeof(accepting);if(getsockopt(fd,SOL_SOCKET,SO_ACCEPTCONN,&accepting,&size)||size!=sizeof(accepting)||accepting)return 0;
    return !getsockname(fd,(struct sockaddr *)&local,&a)&&!getpeername(fd,(struct sockaddr *)&remote,&b)&&
        a>=sizeof(sa_family_t)&&a<=sizeof(local)&&b>=sizeof(sa_family_t)&&b<=sizeof(remote)&&
        local.sun_family==AF_UNIX&&remote.sun_family==AF_UNIX;
}
static inline int unix_byte_channel_guard(int fd,pid_t broker){
    if(getpid()!=syscall(SYS_gettid)||!unix_byte_channel_valid(fd,broker)){errno=EINVAL;return -1;}
#if defined(__arm__) && __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
    const unsigned architecture=AUDIT_ARCH_ARM;
#elif defined(__x86_64__) && !defined(__ILP32__)
    const unsigned architecture=AUDIT_ARCH_X86_64;
#else
#error Unreviewed byte-channel syscall ABI
#endif
#define CHANNEL_DENY(n) BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K,n,0,1),BPF_STMT(BPF_RET|BPF_K,SECCOMP_RET_ERRNO|EPERM)
    struct sock_filter filter[]={
        BPF_STMT(BPF_LD|BPF_W|BPF_ABS,offsetof(struct seccomp_data,arch)),
        BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K,architecture,1,0),BPF_STMT(BPF_RET|BPF_K,SECCOMP_RET_KILL),
        BPF_STMT(BPF_LD|BPF_W|BPF_ABS,offsetof(struct seccomp_data,nr)),
#ifdef __x86_64__
        BPF_JUMP(BPF_JMP|BPF_JGE|BPF_K,0x40000000u,0,1),BPF_STMT(BPF_RET|BPF_K,SECCOMP_RET_ERRNO|EPERM),
#endif
        CHANNEL_DENY(SYS_socket),CHANNEL_DENY(SYS_socketpair),CHANNEL_DENY(SYS_connect),
        CHANNEL_DENY(SYS_bind),CHANNEL_DENY(SYS_listen),CHANNEL_DENY(SYS_accept),CHANNEL_DENY(SYS_accept4),
        CHANNEL_DENY(SYS_sendto),CHANNEL_DENY(SYS_sendmsg),CHANNEL_DENY(SYS_sendmmsg),
        CHANNEL_DENY(SYS_recvfrom),CHANNEL_DENY(SYS_recvmsg),CHANNEL_DENY(SYS_recvmmsg),
#ifdef SYS_recvmmsg_time64
        CHANNEL_DENY(SYS_recvmmsg_time64),
#endif
#ifdef SYS_send
        CHANNEL_DENY(SYS_send),
#endif
#ifdef SYS_recv
        CHANNEL_DENY(SYS_recv),
#endif
#ifdef SYS_socketcall
        CHANNEL_DENY(SYS_socketcall),
#elif defined(__arm__)
        /* Modern EABI headers omit the legacy multiplexor constants. */
        CHANNEL_DENY(102),
#endif
#ifdef __arm__
        CHANNEL_DENY(113),CHANNEL_DENY(117),
#endif
#ifdef SYS_pidfd_getfd
        CHANNEL_DENY(SYS_pidfd_getfd),
#endif
#ifdef SYS_io_uring_setup
        CHANNEL_DENY(SYS_io_uring_setup),
#endif
        BPF_STMT(BPF_RET|BPF_K,SECCOMP_RET_ALLOW),
    };
#undef CHANNEL_DENY
    struct sock_fprog program={sizeof(filter)/sizeof(filter[0]),filter};
    return prctl(PR_SET_NO_NEW_PRIVS,1,0,0,0)||prctl(PR_SET_SECCOMP,SECCOMP_MODE_FILTER,&program)?-1:0;
}
#endif
