/* Clock-service preparation. Only the fixed clock caller can request SYS_TIME;
 * query preparation denies clock changes and has no capabilities at all. */
#ifndef LISA_TIME_GUARD_H
#define LISA_TIME_GUARD_H
#include "network_guard.h"
static char time_jail[PATH_MAX],time_runtime[PATH_MAX],time_profile[8192];
static char time_drift_source[PATH_MAX],time_drift_target[PATH_MAX];
static char time_proof_source[PATH_MAX]; /* Empty in production; readonly lab DSO. */
static inline int time_isolate(void) {
    struct stat info;
    if(lstat(time_jail,&info)||!S_ISDIR(info.st_mode)||info.st_uid||(info.st_mode&0077)||
        unshare(CLONE_NEWNS)||mount(NULL,"/",NULL,MS_REC|MS_PRIVATE,NULL)||
        mount("tmpfs",time_jail,"tmpfs",MS_NOSUID|MS_NODEV,"size=2m,mode=755"))return -1;
    const char *directories[]={"/lib","/usr/lib","/usr/sbin","/etc","/dev",time_runtime};
    for(unsigned i=0;i<sizeof(directories)/sizeof(directories[0]);++i)
        if(network_jail_directories(time_jail,directories[i]))return -1;
    if(time_drift_target[0]&&network_jail_directories(time_jail,time_drift_target))return -1;
    if(time_proof_source[0]&&(network_jail_directories(time_jail,"/run/lisa-clock-proof")||
        network_jail_directories(time_jail,"/opt")))return -1;
    if(diagnostics_text(time_jail,"/etc/lisa-time.conf",time_profile)||
        diagnostics_text(time_jail,"/etc/passwd","root:*:0:0:Clock:/:/nonexistent\n")||
        diagnostics_text(time_jail,"/etc/group","root:*:0:\n")||
        diagnostics_text(time_jail,"/etc/nsswitch.conf","passwd: files\ngroup: files\nhosts: files\n"))return -1;
    char config[PATH_MAX];
    if(snprintf(config,sizeof(config),"%s/etc/lisa-time.conf",time_jail)>=(int)sizeof(config)||chmod(config,0444)||
        diagnostics_bind(time_jail,"/lib","/lib",0,0)||diagnostics_bind(time_jail,"/usr/lib","/usr/lib",0,0)||
        diagnostics_bind(time_jail,"/usr/sbin/chronyd","/usr/sbin/chronyd",1,0)||
        diagnostics_bind(time_jail,"/dev/null","/dev/null",1,1)||diagnostics_bind(time_jail,"/dev/urandom","/dev/urandom",1,1)||
        diagnostics_bind(time_jail,time_runtime,time_runtime,0,1))return -1;
    char state[PATH_MAX];
    if(snprintf(state,sizeof(state),"%s%s",time_jail,time_runtime)>=(int)sizeof(state)||
        mount(NULL,state,NULL,MS_BIND|MS_REMOUNT|MS_NOSUID|MS_NODEV|MS_NOEXEC,NULL))return -1;
    if(time_drift_target[0]){
        if(!time_drift_source[0]||diagnostics_bind(time_jail,time_drift_source,time_drift_target,0,1)||
            snprintf(state,sizeof(state),"%s%s",time_jail,time_drift_target)>=(int)sizeof(state)||
            mount(NULL,state,NULL,MS_BIND|MS_REMOUNT|MS_NOSUID|MS_NODEV|MS_NOEXEC,NULL))return -1;
    }
    if(time_proof_source[0]){
        struct guardian_spec library={.executable=time_proof_source};
        if(guardian_target(&library,&info)||info.st_nlink!=1||
            diagnostics_bind(time_jail,time_proof_source,"/opt/lisa-clock-proof.so",1,0)||
            diagnostics_bind(time_jail,time_runtime,"/run/lisa-clock-proof",0,1)||
            snprintf(state,sizeof(state),"%s/run/lisa-clock-proof",time_jail)>=(int)sizeof(state)||
            mount(NULL,state,NULL,MS_BIND|MS_REMOUNT|MS_NOSUID|MS_NODEV|MS_NOEXEC,NULL)||
            setenv("LD_PRELOAD","/opt/lisa-clock-proof.so",1))return -1;
    }
    if(mount(NULL,time_jail,NULL,MS_REMOUNT|MS_RDONLY|MS_NOSUID|MS_NODEV,NULL)||chroot(time_jail)||chdir("/"))return -1;
    if(time_proof_source[0]){
        if(snprintf(state,sizeof(state),"%s/chrony-proof.log",time_runtime)>=(int)sizeof(state))return -1;
        int fd=open(state,O_WRONLY|O_CREAT|O_APPEND|O_NOFOLLOW|O_CLOEXEC,0600);
        if(fd<0)return -1;
        int failed=!store_file_valid(fd,0)||dup2(fd,2)<0;
        close(fd);if(failed)return -1;
    }
    return 0;
}
static inline int time_realtime_filter(void) {
#if defined(__arm__)
    const unsigned architecture=AUDIT_ARCH_ARM;
#elif defined(__x86_64__)
    const unsigned architecture=AUDIT_ARCH_X86_64;
#else
#error Unsupported clock guard architecture
#endif
#define TIME_CLOCK(n) BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K,n,0,4), \
    BPF_STMT(BPF_LD|BPF_W|BPF_ABS,offsetof(struct seccomp_data,args[0])), \
    BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K,CLOCK_REALTIME,1,0),BPF_STMT(BPF_RET|BPF_K,SECCOMP_RET_ERRNO|EPERM), \
    BPF_STMT(BPF_RET|BPF_K,SECCOMP_RET_ALLOW)
    struct sock_filter filter[]={
        BPF_STMT(BPF_LD|BPF_W|BPF_ABS,offsetof(struct seccomp_data,arch)),
        BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K,architecture,1,0),BPF_STMT(BPF_RET|BPF_K,SECCOMP_RET_KILL),
        BPF_STMT(BPF_LD|BPF_W|BPF_ABS,offsetof(struct seccomp_data,nr)),
        TIME_CLOCK(SYS_clock_settime),TIME_CLOCK(SYS_clock_adjtime),
#ifdef SYS_clock_settime64
        TIME_CLOCK(SYS_clock_settime64),TIME_CLOCK(SYS_clock_adjtime64),
#endif
        BPF_STMT(BPF_RET|BPF_K,SECCOMP_RET_ALLOW),
    };
#undef TIME_CLOCK
    struct sock_fprog program={sizeof(filter)/sizeof(filter[0]),filter};
    return prctl(PR_SET_SECCOMP,SECCOMP_MODE_FILTER,&program);
}
static inline int time_prepare(int clock_control) {
    if(time_isolate()||setgroups(0,NULL))return -1;
    for(unsigned cap=0;cap<=CAP_LAST_CAP;++cap)
        if((clock_control!=1||cap!=CAP_SYS_TIME)&&prctl(PR_CAPBSET_DROP,cap,0,0,0)&&errno!=EINVAL)return -1;
    struct __user_cap_header_struct header={_LINUX_CAPABILITY_VERSION_3,0};
    struct __user_cap_data_struct caps[2]={{0},{0}};
    if(clock_control==1)caps[0].effective=caps[0].permitted=1u<<CAP_SYS_TIME;
    if(syscall(SYS_capset,&header,caps)||prctl(PR_SET_NO_NEW_PRIVS,1,0,0,0)||prctl(PR_GET_NO_NEW_PRIVS,0,0,0,0)!=1||
        network_service_filter(clock_control))return -1;
    return clock_control==1?time_realtime_filter():0;
}
static inline int time_service_prepare(void) {return time_prepare(1);}
static inline int time_query_prepare(void) {return time_prepare(0);}
#endif
