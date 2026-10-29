/* Independent resolver preparation, not a vendor admission path. Caller reads
 * a trusted compiler-produced profile; writable service state is separate from
 * root-only coordinator journals. No production installation here. */
#ifndef LISA_NETWORK_GUARD_H
#define LISA_NETWORK_GUARD_H
#include "hardvolume_guard.h"

static char network_jail[PATH_MAX],network_dns_runtime[PATH_MAX],network_dns_profile[16384];
static inline int network_jail_directories(const char *root,const char *path) {
    if(path[0]!='/'||strlen(path)>=PATH_MAX)return -1;
    char copy[PATH_MAX],current[PATH_MAX]="";strcpy(copy,path);char *save=NULL;
    for(char *part=strtok_r(copy,"/",&save);part;part=strtok_r(NULL,"/",&save)){
        if(!strcmp(part,".")||!strcmp(part,".."))return -1;
        size_t used=strlen(current),count=strlen(part);
        if(used+count+2>sizeof(current))return -1;
        current[used]='/';memcpy(current+used+1,part,count+1);
        if(diagnostics_directory(root,current)&&errno!=EEXIST)return -1;
        char target[PATH_MAX];
        if(snprintf(target,sizeof(target),"%s%s",root,current)>=(int)sizeof(target)||chmod(target,0755))return -1;
    }
    return 0;
}
static inline int network_dns_isolate(void) {
    struct stat info;
    if(lstat(network_jail,&info)||!S_ISDIR(info.st_mode)||info.st_uid||(info.st_mode&0077)||
        unshare(CLONE_NEWNS)||mount(NULL,"/",NULL,MS_REC|MS_PRIVATE,NULL)||
        mount("tmpfs",network_jail,"tmpfs",MS_NOSUID|MS_NODEV,"size=2m,mode=755"))return -1;
    const char *directories[]={"/lib","/usr/lib","/usr/sbin","/etc","/dev",network_dns_runtime};
    for(unsigned i=0;i<sizeof(directories)/sizeof(directories[0]);++i)
        if(network_jail_directories(network_jail,directories[i]))return -1;
    if(diagnostics_text(network_jail,"/etc/lisa-dns.conf",network_dns_profile))return -1;
    char config[PATH_MAX];
    if(snprintf(config,sizeof(config),"%s/etc/lisa-dns.conf",network_jail)>=(int)sizeof(config)||chmod(config,0444)||
        diagnostics_bind(network_jail,"/lib","/lib",0,0)||diagnostics_bind(network_jail,"/usr/lib","/usr/lib",0,0)||
        diagnostics_bind(network_jail,"/usr/sbin/unbound","/usr/sbin/unbound",1,0)||
        diagnostics_bind(network_jail,"/dev/null","/dev/null",1,1)||
        diagnostics_bind(network_jail,"/dev/urandom","/dev/urandom",1,1)||
        diagnostics_bind(network_jail,network_dns_runtime,network_dns_runtime,0,1))return -1;
    char state[PATH_MAX];
    if(snprintf(state,sizeof(state),"%s%s",network_jail,network_dns_runtime)>=(int)sizeof(state)||
        mount(NULL,state,NULL,MS_BIND|MS_REMOUNT|MS_NOSUID|MS_NODEV|MS_NOEXEC,NULL)||
        mount(NULL,network_jail,NULL,MS_REMOUNT|MS_RDONLY|MS_NOSUID|MS_NODEV,NULL)||
        chroot(network_jail)||chdir("/"))return -1;
    return 0;
}
static inline int network_dns_filter(void) {
#if defined(__arm__)
    const unsigned architecture=AUDIT_ARCH_ARM;
#elif defined(__x86_64__)
    const unsigned architecture=AUDIT_ARCH_X86_64;
#else
#error Unsupported network guard architecture
#endif
#define NET_DENY(n) BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K,n,0,1),BPF_STMT(BPF_RET|BPF_K,SECCOMP_RET_ERRNO|EPERM)
    struct sock_filter filter[]={
        BPF_STMT(BPF_LD|BPF_W|BPF_ABS,offsetof(struct seccomp_data,arch)),
        BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K,architecture,1,0),BPF_STMT(BPF_RET|BPF_K,SECCOMP_RET_KILL),
        BPF_STMT(BPF_LD|BPF_W|BPF_ABS,offsetof(struct seccomp_data,nr)),
#if defined(__x86_64__)
        BPF_JUMP(BPF_JMP|BPF_JSET|BPF_K,0x40000000u,0,1),BPF_STMT(BPF_RET|BPF_K,SECCOMP_RET_ERRNO|EPERM),
#endif
        NET_DENY(SYS_fork),NET_DENY(SYS_vfork),NET_DENY(SYS_mount),NET_DENY(SYS_umount2),NET_DENY(SYS_chroot),
        NET_DENY(SYS_unshare),NET_DENY(SYS_setns),NET_DENY(SYS_ptrace),NET_DENY(SYS_process_vm_writev),NET_DENY(SYS_process_vm_readv),
        NET_DENY(SYS_open_by_handle_at),NET_DENY(SYS_name_to_handle_at),NET_DENY(SYS_bpf),
        NET_DENY(SYS_tkill),
#ifdef SYS_pidfd_open
        NET_DENY(SYS_pidfd_open),
#endif
#ifdef SYS_pidfd_getfd
        NET_DENY(SYS_pidfd_getfd),
#endif
#ifdef SYS_pidfd_send_signal
        NET_DENY(SYS_pidfd_send_signal),
#endif
        NET_DENY(SYS_setuid),NET_DENY(SYS_setgid),NET_DENY(SYS_setresuid),NET_DENY(SYS_setresgid),
        NET_DENY(SYS_setreuid),NET_DENY(SYS_setregid),NET_DENY(SYS_setfsuid),NET_DENY(SYS_setfsgid),NET_DENY(SYS_setgroups),
#ifdef SYS_setuid32
        NET_DENY(SYS_setuid32),NET_DENY(SYS_setgid32),NET_DENY(SYS_setresuid32),NET_DENY(SYS_setresgid32),
        NET_DENY(SYS_setreuid32),NET_DENY(SYS_setregid32),NET_DENY(SYS_setfsuid32),NET_DENY(SYS_setfsgid32),NET_DENY(SYS_setgroups32),
#endif
        NET_DENY(SYS_clock_settime),NET_DENY(SYS_clock_adjtime),NET_DENY(SYS_adjtimex),NET_DENY(SYS_settimeofday),
#ifdef SYS_clock_settime64
        NET_DENY(SYS_clock_settime64),NET_DENY(SYS_clock_adjtime64),
#endif
#ifdef SYS_socketcall
        NET_DENY(SYS_socketcall),
#endif
#ifdef SYS_clone3
        BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K,SYS_clone3,0,1),BPF_STMT(BPF_RET|BPF_K,SECCOMP_RET_ERRNO|ENOSYS),
#endif
        BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K,SYS_kill,0,4),
        BPF_STMT(BPF_LD|BPF_W|BPF_ABS,offsetof(struct seccomp_data,args[0])),
        BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K,(unsigned)getpid(),1,0),BPF_STMT(BPF_RET|BPF_K,SECCOMP_RET_ERRNO|EPERM),
        BPF_STMT(BPF_RET|BPF_K,SECCOMP_RET_ALLOW),
        BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K,SYS_tgkill,0,4),
        BPF_STMT(BPF_LD|BPF_W|BPF_ABS,offsetof(struct seccomp_data,args[0])),
        BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K,(unsigned)getpid(),1,0),BPF_STMT(BPF_RET|BPF_K,SECCOMP_RET_ERRNO|EPERM),
        BPF_STMT(BPF_RET|BPF_K,SECCOMP_RET_ALLOW),
        BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K,SYS_clone,0,4),
        BPF_STMT(BPF_LD|BPF_W|BPF_ABS,offsetof(struct seccomp_data,args[0])),
        BPF_JUMP(BPF_JMP|BPF_JSET|BPF_K,CLONE_THREAD,1,0),BPF_STMT(BPF_RET|BPF_K,SECCOMP_RET_ERRNO|EPERM),
        BPF_STMT(BPF_RET|BPF_K,SECCOMP_RET_ALLOW),
        BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K,SYS_socket,1,0),BPF_STMT(BPF_RET|BPF_K,SECCOMP_RET_ALLOW),
        BPF_STMT(BPF_LD|BPF_W|BPF_ABS,offsetof(struct seccomp_data,args[0])),
        BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K,AF_INET,5,0),BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K,AF_INET6,4,0),
        /* getifaddrs needs route inventory. NET_ADMIN/NET_RAW are absent;
         * other netlink protocols and UNIX connection sockets stay denied. */
        BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K,AF_NETLINK,0,2),
        BPF_STMT(BPF_LD|BPF_W|BPF_ABS,offsetof(struct seccomp_data,args[2])),
        BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K,NETLINK_ROUTE,1,0),
        BPF_STMT(BPF_RET|BPF_K,SECCOMP_RET_ERRNO|EPERM),BPF_STMT(BPF_RET|BPF_K,SECCOMP_RET_ALLOW),
    };
#undef NET_DENY
    struct sock_fprog program={sizeof(filter)/sizeof(filter[0]),filter};
    return prctl(PR_SET_SECCOMP,SECCOMP_MODE_FILTER,&program)||vendor_ipc_guard()?-1:0;
}
static inline int network_dns_prepare(void) {
    if(network_dns_isolate())return -1;
    for(unsigned cap=0;cap<=CAP_LAST_CAP;++cap)
        if(cap!=CAP_NET_BIND_SERVICE&&prctl(PR_CAPBSET_DROP,cap,0,0,0)&&errno!=EINVAL)return -1;
    if(prctl(PR_SET_KEEPCAPS,1,0,0,0)||setgroups(0,NULL)||setgid(65534)||setuid(65534))return -1;
    struct __user_cap_header_struct header={_LINUX_CAPABILITY_VERSION_3,0};
    struct __user_cap_data_struct caps[2]={{0},{0}};
    caps[0].effective=caps[0].permitted=caps[0].inheritable=1u<<CAP_NET_BIND_SERVICE;
    if(syscall(SYS_capset,&header,caps)||prctl(PR_CAP_AMBIENT,PR_CAP_AMBIENT_RAISE,CAP_NET_BIND_SERVICE,0,0)||
        prctl(PR_SET_KEEPCAPS,0,0,0,0)||prctl(PR_SET_NO_NEW_PRIVS,1,0,0,0)||prctl(PR_GET_NO_NEW_PRIVS,0,0,0,0)!=1)return -1;
    return network_dns_filter();
}
#endif
