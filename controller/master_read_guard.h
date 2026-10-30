/* Additive GET-only helper guard. Kernel policy limits ioctl classes/FD;
 * fixed Master selection is enforced by trusted backend code, NOT seccomp
 * inspection of a nested ioctl pointer. No raw control FD reaches an SDK. */
#ifndef LISA_MASTER_READ_GUARD_H
#define LISA_MASTER_READ_GUARD_H
#include <sound/asound.h>
#include "hardvolume_guard.h"
static inline int master_peer_valid(int fd,pid_t parent){
    struct stat info;struct ucred peer;int type=0,domain=0,listening=1;socklen_t size=sizeof(peer);
    if(parent<=1||getppid()!=parent||fd<3||fstat(fd,&info)||!S_ISSOCK(info.st_mode)||
        getsockopt(fd,SOL_SOCKET,SO_PEERCRED,&peer,&size)||size!=sizeof(peer)||peer.pid!=parent||peer.uid!=geteuid())return 0;
    size=sizeof(type);if(getsockopt(fd,SOL_SOCKET,SO_TYPE,&type,&size)||size!=sizeof(type)||type!=SOCK_SEQPACKET)return 0;
    size=sizeof(domain);if(getsockopt(fd,SOL_SOCKET,SO_DOMAIN,&domain,&size)||size!=sizeof(domain)||domain!=AF_UNIX)return 0;
    size=sizeof(listening);if(getsockopt(fd,SOL_SOCKET,SO_ACCEPTCONN,&listening,&size)||size!=sizeof(listening)||listening)return 0;
    struct sockaddr_un local,remote;socklen_t a=sizeof(local),b=sizeof(remote);
    return !getsockname(fd,(struct sockaddr *)&local,&a)&&!getpeername(fd,(struct sockaddr *)&remote,&b)&&
        a==sizeof(sa_family_t)&&b==sizeof(sa_family_t)&&local.sun_family==AF_UNIX&&remote.sun_family==AF_UNIX;
}
static inline int master_read_guard(int peer,pid_t parent,int control){
    if(getpid()!=syscall(SYS_gettid)||!master_peer_valid(peer,parent)||control==peer||
        prctl(PR_SET_PDEATHSIG,SIGKILL,0,0,0)||getppid()!=parent||prctl(PR_SET_NO_NEW_PRIVS,1,0,0,0)||hardvolume_filter())return -1;
#if defined(__arm__) && __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
    const unsigned architecture=AUDIT_ARCH_ARM;
#elif defined(__x86_64__) && !defined(__ILP32__)
    const unsigned architecture=AUDIT_ARCH_X86_64;
#else
#error Unreviewed Master helper syscall ABI
#endif
#define MASTER_DENY(n) BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K,n,0,1),BPF_STMT(BPF_RET|BPF_K,SECCOMP_RET_ERRNO|EPERM)
    struct sock_filter filter[]={
        BPF_STMT(BPF_LD|BPF_W|BPF_ABS,offsetof(struct seccomp_data,arch)),
        BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K,architecture,1,0),BPF_STMT(BPF_RET|BPF_K,SECCOMP_RET_KILL),
        BPF_STMT(BPF_LD|BPF_W|BPF_ABS,offsetof(struct seccomp_data,nr)),
#ifdef __x86_64__
        BPF_JUMP(BPF_JMP|BPF_JGE|BPF_K,0x40000000u,0,1),BPF_STMT(BPF_RET|BPF_K,SECCOMP_RET_ERRNO|EPERM),
#endif
        MASTER_DENY(SYS_bind),MASTER_DENY(SYS_recvfrom),MASTER_DENY(SYS_syslog),
        MASTER_DENY(SYS_keyctl),MASTER_DENY(SYS_add_key),MASTER_DENY(SYS_request_key),MASTER_DENY(SYS_perf_event_open),
#ifdef SYS_io_uring_setup
        MASTER_DENY(SYS_io_uring_setup),
#endif
#ifdef SYS_userfaultfd
        MASTER_DENY(SYS_userfaultfd),
#endif
#ifdef __arm__
        MASTER_DENY(102),MASTER_DENY(113),MASTER_DENY(117),
#endif
        BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K,SYS_prctl,0,4),
        BPF_STMT(BPF_LD|BPF_W|BPF_ABS,offsetof(struct seccomp_data,args[0])),
        BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K,PR_SET_PDEATHSIG,0,1),
        BPF_STMT(BPF_RET|BPF_K,SECCOMP_RET_ERRNO|EPERM),BPF_STMT(BPF_RET|BPF_K,SECCOMP_RET_ALLOW),
        BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K,SYS_ioctl,0,16),
        BPF_STMT(BPF_LD|BPF_IMM,(unsigned)(control>=3)),
        BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K,1,1,0),BPF_STMT(BPF_RET|BPF_K,SECCOMP_RET_ERRNO|EPERM),
        BPF_STMT(BPF_LD|BPF_W|BPF_ABS,offsetof(struct seccomp_data,args[0])+4),
        BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K,0,1,0),BPF_STMT(BPF_RET|BPF_K,SECCOMP_RET_ERRNO|EPERM),
        BPF_STMT(BPF_LD|BPF_W|BPF_ABS,offsetof(struct seccomp_data,args[0])),
        BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K,(unsigned)control,1,0),BPF_STMT(BPF_RET|BPF_K,SECCOMP_RET_ERRNO|EPERM),
        BPF_STMT(BPF_LD|BPF_W|BPF_ABS,offsetof(struct seccomp_data,args[1])+4),
        BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K,0,1,0),BPF_STMT(BPF_RET|BPF_K,SECCOMP_RET_ERRNO|EPERM),
        BPF_STMT(BPF_LD|BPF_W|BPF_ABS,offsetof(struct seccomp_data,args[1])),
        BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K,SNDRV_CTL_IOCTL_ELEM_INFO,2,0),
        BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K,SNDRV_CTL_IOCTL_ELEM_READ,1,0),
        BPF_STMT(BPF_RET|BPF_K,SECCOMP_RET_ERRNO|EPERM),BPF_STMT(BPF_RET|BPF_K,SECCOMP_RET_ALLOW),
    };
#undef MASTER_DENY
    struct sock_fprog program={sizeof(filter)/sizeof(filter[0]),filter};return prctl(PR_SET_SECCOMP,SECCOMP_MODE_FILTER,&program);
}
#endif
