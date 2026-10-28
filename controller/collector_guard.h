/* Alice-only collector filesystem epoch. Host logs/data are read-only; shared
 * system journals, old /tmp queues, live proc and audio devices are absent.
 * AF_UNIX and ordinary IP remain explicit Alice dependencies, not isolation. */
#ifndef LISA_COLLECTOR_GUARD_H
#define LISA_COLLECTOR_GUARD_H
#include "diagnostics_guard.h"
#include "relay_resources.h"

static inline int collector_profile_valid(const char *path) {
    struct stat info;
    return !lstat(path,&info)&&S_ISREG(info.st_mode)&&info.st_uid==0&&info.st_nlink==1&&
        (info.st_mode&07777)==0600&&info.st_size>0&&info.st_size<=1024*1024;
}
static inline int collector_isolate(const char *root,const char *profile,const char *executable) {
    struct stat info; char target[PATH_MAX];
    if(lstat(root,&info)||!S_ISDIR(info.st_mode)||info.st_uid||(info.st_mode&0077)||
        !collector_profile_valid(profile)||unshare(CLONE_NEWNS)||mount(NULL,"/",NULL,MS_REC|MS_PRIVATE,NULL)||
        mount("tmpfs",root,"tmpfs",MS_NOSUID|MS_NODEV,"size=2m,mode=755")) return -1;
    const char *directories[]={"/lib","/usr","/usr/lib","/system","/system/vendor","/system/vendor/quasar",
        "/data","/data/quasar","/etc","/dev","/tmp","/var","/var/lib","/var/lib/dbus","/var/run","/var/run/dbus",
        "/proc","/proc/sys","/proc/sys/kernel","/proc/sys/kernel/random"};
    for(unsigned i=0;i<sizeof(directories)/sizeof(directories[0]);++i)
        if(diagnostics_directory(root,directories[i])) return -1;
    if(diagnostics_text(root,"/etc/passwd","root:*:0:57344:Collector:/:/nonexistent\n")||
        diagnostics_text(root,"/etc/group","root:*:0:\nlisa-collector:*:57344:\n")||
        diagnostics_text(root,"/etc/nsswitch.conf","passwd: files\ngroup: files\nhosts: files dns\n")) return -1;
    if(diagnostics_bind(root,"/lib","/lib",0,0)||diagnostics_bind(root,"/usr/lib","/usr/lib",0,0)||
        diagnostics_bind(root,"/system/vendor/quasar","/system/vendor/quasar",0,0)||
        diagnostics_bind(root,"/data/quasar","/data/quasar",0,0)) return -1;
    if(snprintf(target,sizeof(target),"%s/system/vendor/quasar/quasar.cfg",root)>=(int)sizeof(target)||
        mount(profile,target,NULL,MS_BIND,NULL)||
        mount(NULL,target,NULL,MS_BIND|MS_REMOUNT|MS_RDONLY|MS_NOSUID|MS_NODEV|MS_NOEXEC,NULL)) return -1;
    if(snprintf(target,sizeof(target),"%s/system/vendor/quasar/maind",root)>=(int)sizeof(target)||
        mount(executable,target,NULL,MS_BIND,NULL)||
        mount(NULL,target,NULL,MS_BIND|MS_REMOUNT|MS_RDONLY|MS_NOSUID|MS_NODEV,NULL)) return -1;
    const char *files[]={"/etc/resolv.conf","/etc/hosts","/etc/localtime","/etc/machine-id","/var/lib/dbus/machine-id"};
    for(unsigned i=0;i<sizeof(files)/sizeof(files[0]);++i) {
        if(!stat(files[i],&info)) {
            if(!S_ISREG(info.st_mode)||diagnostics_bind(root,files[i],files[i],1,0)) return -1;
        } else if(errno!=ENOENT) return -1;
    }
    if(diagnostics_bind(root,"/dev/null","/dev/null",1,1)||diagnostics_bind(root,"/dev/urandom","/dev/urandom",1,1)||
        diagnostics_bind(root,"/proc/sys/kernel/random/boot_id","/proc/sys/kernel/random/boot_id",1,0)||
        diagnostics_bind(root,"/proc/cmdline","/proc/cmdline",1,0)||
        diagnostics_bind(root,"/var/run/dbus/system_bus_socket","/var/run/dbus/system_bus_socket",1,0)) return -1;
    if(snprintf(target,sizeof(target),"%s/tmp",root)>=(int)sizeof(target)||
        mount("tmpfs",target,"tmpfs",MS_NOSUID|MS_NODEV|MS_NOEXEC,"size=16m,mode=700")||
        diagnostics_directory(root,"/tmp/lisa-collector")||
        diagnostics_text(root,"/tmp/messages","")||diagnostics_text(root,"/dev/kmsg","")||
        snprintf(target,sizeof(target),"%s/var/log",root)>=(int)sizeof(target)||symlink("../tmp",target)||
        mount(NULL,root,NULL,MS_REMOUNT|MS_RDONLY|MS_NOSUID|MS_NODEV,NULL)||chroot(root)||chdir("/")) return -1;
    return 0;
}
static inline int collector_extra_guard(void) {
    struct __user_cap_header_struct header={_LINUX_CAPABILITY_VERSION_3,0};
    struct __user_cap_data_struct caps[2]={{0}};
    int ended=0;
    for(unsigned bit=0;bit<64;++bit) {
        int present=prctl(PR_CAPBSET_READ,bit,0,0,0);
        if(present<0) { if(errno==EINVAL) { ended=1; break; } return -1; }
        if(present&&prctl(PR_CAPBSET_DROP,bit,0,0,0)) return -1;
    }
    if(!ended||syscall(SYS_capset,&header,caps)) return -1;
#define COLLECTOR_DENY(n) BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K,n,0,1),BPF_STMT(BPF_RET|BPF_K,SECCOMP_RET_ERRNO|EPERM)
    struct sock_filter filter[]={
        BPF_STMT(BPF_LD|BPF_W|BPF_ABS,offsetof(struct seccomp_data,arch)),
        BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K,AUDIT_ARCH_ARM,1,0),BPF_STMT(BPF_RET|BPF_K,SECCOMP_RET_KILL),
        BPF_STMT(BPF_LD|BPF_W|BPF_ABS,offsetof(struct seccomp_data,nr)),
        COLLECTOR_DENY(SYS_chroot),COLLECTOR_DENY(SYS_mknod),COLLECTOR_DENY(SYS_mknodat),
        COLLECTOR_DENY(SYS_syslog),COLLECTOR_DENY(SYS_process_vm_readv),
        COLLECTOR_DENY(SYS_open_by_handle_at),COLLECTOR_DENY(SYS_name_to_handle_at),
#ifdef SYS_socketcall
        COLLECTOR_DENY(SYS_socketcall),
#endif
        BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K,SYS_socket,2,0),
        BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K,SYS_socketpair,1,0),BPF_STMT(BPF_RET|BPF_K,SECCOMP_RET_ALLOW),
        BPF_STMT(BPF_LD|BPF_W|BPF_ABS,offsetof(struct seccomp_data,args[0])),
        BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K,AF_UNIX,3,0),
        BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K,AF_INET,2,0),
        BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K,AF_INET6,1,0),
        BPF_STMT(BPF_RET|BPF_K,SECCOMP_RET_ERRNO|EPERM),BPF_STMT(BPF_RET|BPF_K,SECCOMP_RET_ALLOW),
    };
#undef COLLECTOR_DENY
    struct sock_fprog program={sizeof(filter)/sizeof(filter[0]),filter};
    return prctl(PR_SET_SECCOMP,SECCOMP_MODE_FILTER,&program);
}
static inline int collector_private_view(pid_t pid) {
    char path[PATH_MAX],own[128],child[128]; struct stat info,host; struct statvfs fs;
    snprintf(path,sizeof(path),"/proc/%ld/ns/mnt",(long)pid);
    ssize_t a=readlink("/proc/self/ns/mnt",own,sizeof(own)),b=readlink(path,child,sizeof(child));
    if(a<=0||b<=0||(a==b&&!memcmp(own,child,(size_t)a))) return -1;
    snprintf(path,sizeof(path),"/proc/%ld/root",(long)pid);
    if(statvfs(path,&fs)||!(fs.f_flag&ST_RDONLY)) return -1;
    snprintf(path,sizeof(path),"/proc/%ld/root/data/quasar",(long)pid);
    if(statvfs(path,&fs)||!(fs.f_flag&ST_RDONLY)||stat(path,&info)||stat("/data/quasar",&host)||
        info.st_dev!=host.st_dev||info.st_ino!=host.st_ino) return -1;
    snprintf(path,sizeof(path),"/proc/%ld/root/tmp",(long)pid);
    if(stat(path,&info)||stat("/tmp",&host)||info.st_dev==host.st_dev||statvfs(path,&fs)||
        (fs.f_flag&ST_RDONLY)||(uint64_t)fs.f_blocks*fs.f_frsize>16u*1024u*1024u) return -1;
    const char *messages[]={"/tmp/messages","/var/log/messages"};
    for(unsigned i=0;i<2;++i) {
        snprintf(path,sizeof(path),"/proc/%ld/root%s",(long)pid,messages[i]);
        if(stat(path,&info)||!S_ISREG(info.st_mode)||stat("/tmp/messages",&host)||
            (info.st_dev==host.st_dev&&info.st_ino==host.st_ino)) return -1;
    }
    const char *hidden[]={"/proc/self","/proc/1","/sys","/dev/snd","/dev/log","/bkupgrade","/tmp/fluent-bit.db","/tmp/teleme3d"};
    for(unsigned i=0;i<sizeof(hidden)/sizeof(hidden[0]);++i) {
        snprintf(path,sizeof(path),"/proc/%ld/root%s",(long)pid,hidden[i]);
        if(!lstat(path,&info)||errno!=ENOENT) return -1;
    }
    return 0;
}
/* Observe initialization without reading any queue/log data. Both the SQLite
 * database and own log must be held in this process's private tmpfs epoch. */
static inline int collector_runtime_private(pid_t pid) {
    char path[PATH_MAX]; struct stat queue,log,tmp,host,forbidden[5]; unsigned deny_count=0;
    snprintf(path,sizeof(path),"/proc/%ld/root/tmp",(long)pid);
    if(stat(path,&tmp)||stat("/tmp",&host)||tmp.st_dev==host.st_dev) return 0;
    snprintf(path,sizeof(path),"/proc/%ld/root/tmp/lisa-collector/tail.db",(long)pid);
    if(stat(path,&queue)||!S_ISREG(queue.st_mode)||queue.st_dev!=tmp.st_dev) return 0;
    snprintf(path,sizeof(path),"/proc/%ld/root/tmp/lisa-collector/collector.log",(long)pid);
    if(stat(path,&log)||!S_ISREG(log.st_mode)||log.st_dev!=tmp.st_dev) return 0;
    const char *names[]={"/tmp/messages","/tmp/messages.0","/tmp/fluent-bit.db","/tmp/fluent-bit.db-wal","/tmp/fluent-bit.db-shm"};
    for(unsigned i=0;i<5;++i) {
        if(!stat(names[i],&forbidden[deny_count])) ++deny_count;
        else if(errno!=ENOENT) return 0;
    }
    snprintf(path,sizeof(path),"/proc/%ld/fd",(long)pid); DIR *fds=opendir(path);
    if(!fds) return 0;
    unsigned seen=0; int queue_held=0,log_held=0,ok=1; struct dirent *entry;
    for(;;) {
        errno=0; entry=readdir(fds);
        if(!entry) { if(errno) ok=0; break; }
        char *end; long fd=strtol(entry->d_name,&end,10);
        if(*end||fd<0||fd>INT_MAX) continue;
        if(++seen>1024) { ok=0; break; }
        struct stat actual; snprintf(path,sizeof(path),"/proc/%ld/fd/%ld",(long)pid,fd);
        if(stat(path,&actual)) { ok=0; break; }
        queue_held|=actual.st_dev==queue.st_dev&&actual.st_ino==queue.st_ino;
        log_held|=actual.st_dev==log.st_dev&&actual.st_ino==log.st_ino;
        for(unsigned i=0;i<deny_count;++i)
            if(actual.st_dev==forbidden[i].st_dev&&actual.st_ino==forbidden[i].st_ino) ok=0;
    }
    closedir(fds);
    snprintf(path,sizeof(path),"/proc/%ld/maps",(long)pid); FILE *maps=fopen(path,"r"); char line[PATH_MAX+256];
    if(!maps) return 0;
    unsigned count=0;
    while(fgets(line,sizeof(line),maps)) {
        struct relay_row row;
        if(++count>RELAY_MAP_LIMIT||!strchr(line,'\n')||relay_parse_map(line,&row)) { ok=0; break; }
        for(unsigned i=0;i<deny_count;++i)
            if(row.device==forbidden[i].st_dev&&row.inode==forbidden[i].st_ino) ok=0;
    }
    if(ferror(maps)) ok=0;
    fclose(maps); return ok&&queue_held&&log_held;
}
#endif
