/* Preserve the calibrated hardware mixer with only its control node exposed.
 * No capture/playback PCM, host state/IPC, network or process creation. */
#ifndef LISA_HARDVOLUME_GUARD_H
#define LISA_HARDVOLUME_GUARD_H
#include <grp.h>
#include <linux/capability.h>
#include "auxiliary_supervisor.h"
#include "vendor_ipc_guard.h"
#include "diagnostics_guard.h"

static char hardvolume_root[PATH_MAX];
static inline int hardvolume_isolate(const char *root) {
    struct stat info;
    if(lstat(root,&info)||!S_ISDIR(info.st_mode)||info.st_uid||(info.st_mode&0077)||
        unshare(CLONE_NEWNS)||mount(NULL,"/",NULL,MS_REC|MS_PRIVATE,NULL)||
        mount("tmpfs",root,"tmpfs",MS_NOSUID|MS_NODEV,"size=1m,mode=755")) return -1;
    const char *directories[]={"/lib","/usr","/usr/lib","/usr/bin","/etc","/dev","/dev/snd"};
    for(unsigned i=0;i<sizeof(directories)/sizeof(directories[0]);++i)
        if(diagnostics_directory(root,directories[i])) return -1;
    const char alsa[]="ctl.hw {\n @args [ CARD ]\n @args.CARD { type string default \"0\" }\n type hw\n card $CARD\n}\n";
    if(diagnostics_text(root,"/etc/lisa-alsa.conf",alsa)||
        diagnostics_bind(root,"/lib","/lib",0,0)||diagnostics_bind(root,"/usr/lib","/usr/lib",0,0)||
        diagnostics_bind(root,"/usr/bin/hardvold","/usr/bin/hardvold",1,0)||
        diagnostics_bind(root,"/etc/hardvold.config","/etc/hardvold.config",1,0)||
        lstat("/dev/snd/controlC0",&info)||!S_ISCHR(info.st_mode)||
        diagnostics_bind(root,"/dev/snd/controlC0","/dev/snd/controlC0",1,1)||
        diagnostics_bind(root,"/dev/null","/dev/null",1,1)||
        mount(NULL,root,NULL,MS_REMOUNT|MS_RDONLY|MS_NOSUID|MS_NODEV,NULL)||
        chroot(root)||chdir("/")) return -1;
    return setenv("ALSA_CONFIG_PATH","/etc/lisa-alsa.conf",1);
}
static inline int hardvolume_filter(void) {
#if defined(__arm__)
    const unsigned architecture=AUDIT_ARCH_ARM;
#elif defined(__x86_64__)
    const unsigned architecture=AUDIT_ARCH_X86_64;
#else
#error Unsupported hardvolume guard architecture
#endif
#define HW_DENY(n) BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K,n,0,1),BPF_STMT(BPF_RET|BPF_K,SECCOMP_RET_ERRNO|EPERM)
    struct sock_filter filter[]={
        BPF_STMT(BPF_LD|BPF_W|BPF_ABS,offsetof(struct seccomp_data,arch)),
        BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K,architecture,1,0),BPF_STMT(BPF_RET|BPF_K,SECCOMP_RET_KILL),
        BPF_STMT(BPF_LD|BPF_W|BPF_ABS,offsetof(struct seccomp_data,nr)),
#if defined(__x86_64__)
        BPF_JUMP(BPF_JMP|BPF_JSET|BPF_K,0x40000000u,0,1),BPF_STMT(BPF_RET|BPF_K,SECCOMP_RET_ERRNO|EPERM),
#endif
        HW_DENY(SYS_socket),HW_DENY(SYS_socketpair),HW_DENY(SYS_connect),HW_DENY(SYS_sendto),HW_DENY(SYS_sendmsg),
        HW_DENY(SYS_sendmmsg),HW_DENY(SYS_recvmsg),HW_DENY(SYS_recvmmsg),HW_DENY(SYS_listen),HW_DENY(SYS_accept),HW_DENY(SYS_accept4),
#ifdef SYS_socketcall
        HW_DENY(SYS_socketcall),
#endif
        HW_DENY(SYS_fork),HW_DENY(SYS_vfork),HW_DENY(SYS_clone),
#ifdef SYS_clone3
        HW_DENY(SYS_clone3),
#endif
        HW_DENY(SYS_mount),HW_DENY(SYS_umount2),HW_DENY(SYS_chroot),HW_DENY(SYS_pivot_root),
        HW_DENY(SYS_unshare),HW_DENY(SYS_setns),HW_DENY(SYS_ptrace),HW_DENY(SYS_process_vm_writev),HW_DENY(SYS_process_vm_readv),
        HW_DENY(SYS_kill),HW_DENY(SYS_tkill),HW_DENY(SYS_tgkill),
#ifdef SYS_pidfd_open
        HW_DENY(SYS_pidfd_open),
#endif
#ifdef SYS_pidfd_getfd
        HW_DENY(SYS_pidfd_getfd),
#endif
#ifdef SYS_pidfd_send_signal
        HW_DENY(SYS_pidfd_send_signal),
#endif
        HW_DENY(SYS_open_by_handle_at),HW_DENY(SYS_name_to_handle_at),HW_DENY(SYS_bpf),
        HW_DENY(SYS_setuid),HW_DENY(SYS_setgid),HW_DENY(SYS_setreuid),HW_DENY(SYS_setregid),
        HW_DENY(SYS_setresuid),HW_DENY(SYS_setresgid),HW_DENY(SYS_setfsuid),HW_DENY(SYS_setfsgid),HW_DENY(SYS_setgroups),
#ifdef SYS_setuid32
        HW_DENY(SYS_setuid32),HW_DENY(SYS_setgid32),HW_DENY(SYS_setreuid32),HW_DENY(SYS_setregid32),
        HW_DENY(SYS_setresuid32),HW_DENY(SYS_setresgid32),HW_DENY(SYS_setfsuid32),HW_DENY(SYS_setfsgid32),HW_DENY(SYS_setgroups32),
#endif
        HW_DENY(SYS_clock_settime),HW_DENY(SYS_clock_adjtime),HW_DENY(SYS_adjtimex),HW_DENY(SYS_settimeofday),
#ifdef SYS_clock_settime64
        HW_DENY(SYS_clock_settime64),HW_DENY(SYS_clock_adjtime64),
#endif
        BPF_STMT(BPF_RET|BPF_K,SECCOMP_RET_ALLOW),
    };
#undef HW_DENY
    struct sock_fprog program={sizeof(filter)/sizeof(filter[0]),filter};
    return prctl(PR_SET_SECCOMP,SECCOMP_MODE_FILTER,&program)||vendor_ipc_guard()?-1:0;
}
static inline int hardvolume_prepare(void) {
    if(hardvolume_isolate(hardvolume_root)||setgroups(0,NULL)) return -1;
    for(unsigned cap=0;cap<=CAP_LAST_CAP;++cap)
        if(prctl(PR_CAPBSET_DROP,cap,0,0,0)&&errno!=EINVAL) return -1;
    struct __user_cap_header_struct header={_LINUX_CAPABILITY_VERSION_3,0};
    struct __user_cap_data_struct caps[2]={{0},{0}};
    if(syscall(SYS_capset,&header,caps)||prctl(PR_SET_NO_NEW_PRIVS,1,0,0,0)||
        prctl(PR_GET_NO_NEW_PRIVS,0,0,0,0)!=1) return -1;
    return hardvolume_filter();
}
static inline int hardvolume_observe(pid_t pid) {
    char path[PATH_MAX],line[512],own[128],child[128];struct stat info,host;struct statvfs filesystem;
    snprintf(path,sizeof(path),"/proc/%ld/status",(long)pid);FILE *file=fopen(path,"r");
    if(!file)return -1;
    /* Linux 4.9 does not export NoNewPrivs in proc status. Preparation checks
     * PR_GET_NO_NEW_PRIVS directly; NNP survives exec. Reject false if exported. */
    unsigned count=0;int uid=0,gid=0,nnp=1,seccomp=0,bad=0;unsigned a,b,c,d;unsigned long long caps;
    while(fgets(line,sizeof(line),file)) {
        if(sscanf(line,"Uid: %u %u %u %u",&a,&b,&c,&d)==4)uid=!a&&!b&&!c&&!d;
        if(sscanf(line,"Gid: %u %u %u %u",&a,&b,&c,&d)==4)gid=!a&&!b&&!c&&!d;
        if(sscanf(line,"NoNewPrivs: %u",&a)==1)nnp=a==1;
        if(sscanf(line,"Seccomp: %u",&a)==1)seccomp=a==2;
        if(sscanf(line,"CapEff: %llx",&caps)==1||sscanf(line,"CapPrm: %llx",&caps)==1||
            sscanf(line,"CapInh: %llx",&caps)==1||sscanf(line,"CapBnd: %llx",&caps)==1||sscanf(line,"CapAmb: %llx",&caps)==1){++count;bad|=caps!=0;}
    }
    if(ferror(file))bad=1;
    fclose(file);if(!uid||!gid||!nnp||!seccomp||bad||count!=5)return -1;
    snprintf(path,sizeof(path),"/proc/%ld/ns/mnt",(long)pid);
    ssize_t x=readlink("/proc/self/ns/mnt",own,sizeof(own)),y=readlink(path,child,sizeof(child));
    if(x<=0||y<=0||(x==y&&!memcmp(own,child,(size_t)x)))return -1;
    snprintf(path,sizeof(path),"/proc/%ld/root",(long)pid);
    if(statvfs(path,&filesystem)||!(filesystem.f_flag&ST_RDONLY))return -1;
    snprintf(path,sizeof(path),"/proc/%ld/root/dev/snd/controlC0",(long)pid);
    if(stat(path,&info)||!S_ISCHR(info.st_mode)||stat("/dev/snd/controlC0",&host)||info.st_rdev!=host.st_rdev)return -1;
    const char *hidden[]={"/proc","/sys","/data","/run","/bkupgrade","/dev/log","/dev/shm","/dev/snd/pcmC0D2c","/dev/snd/pcmC0D0p","/etc/asound.conf"};
    for(unsigned i=0;i<sizeof(hidden)/sizeof(hidden[0]);++i){
        snprintf(path,sizeof(path),"/proc/%ld/root%s",(long)pid,hidden[i]);if(!lstat(path,&info)||errno!=ENOENT)return -1;
    }
    snprintf(path,sizeof(path),"/proc/%ld/fd",(long)pid);DIR *directory=opendir(path);struct dirent *entry;
    if(!directory)return -1;
    int ok=1,control=0;
    while((entry=readdir(directory))){
        char *end;long fd=strtol(entry->d_name,&end,10);if(*end||fd<0||fd>INT_MAX)continue;
        snprintf(path,sizeof(path),"/proc/%ld/fd/%ld",(long)pid,fd);
        if(stat(path,&info)||S_ISSOCK(info.st_mode)){ok=0;break;}
        if(S_ISCHR(info.st_mode)&&info.st_rdev==host.st_rdev)++control;
    }
    closedir(directory);return ok&&control==1?0:-1;
}
static inline int hardvolume_absent(const struct guardian_record *record) {
    return record->child<2||!process_live(record->child,record->child_ticks);
}
#endif
