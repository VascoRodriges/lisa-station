/* Diagnostic-only SDK boundary: no sockets, host IPC, devices or inherited
 * channels. Not the final Alice network/IPC policy. Includes the full capability
 * drop and the separately qualified post-fork worker lifecycle guard. */
#ifndef LISA_PLATFORM_SDK_GUARD_H
#define LISA_PLATFORM_SDK_GUARD_H
#include "platform_storage.h"
#include "platform_worker_guard.h"
static inline int platform_sdk_guard(pid_t parent){
    if(collector_extra_guard()||platform_worker_guard(parent))return -1;
#define SDK_DENY(n) BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K,n,0,1),BPF_STMT(BPF_RET|BPF_K,SECCOMP_RET_ERRNO|EPERM)
    struct sock_filter filter[]={
        BPF_STMT(BPF_LD|BPF_W|BPF_ABS,offsetof(struct seccomp_data,nr)),
        SDK_DENY(SYS_socket),SDK_DENY(SYS_socketpair),SDK_DENY(SYS_connect),
        SDK_DENY(SYS_bind),SDK_DENY(SYS_listen),SDK_DENY(SYS_accept),SDK_DENY(SYS_accept4),
        SDK_DENY(SYS_sendto),SDK_DENY(SYS_sendmsg),SDK_DENY(SYS_sendmmsg),
        SDK_DENY(SYS_keyctl),SDK_DENY(SYS_add_key),SDK_DENY(SYS_request_key),
#ifdef SYS_io_uring_setup
        SDK_DENY(SYS_io_uring_setup),
#endif
        BPF_STMT(BPF_RET|BPF_K,SECCOMP_RET_ALLOW),
    };
#undef SDK_DENY
    struct sock_fprog program={sizeof(filter)/sizeof(filter[0]),filter};
    return prctl(PR_SET_SECCOMP,SECCOMP_MODE_FILTER,&program);
}
#endif
