/* Narrow ALSA monitor jail. A private mount namespace/chroot exposes fixed
 * libraries/profile/identity metadata, D-Bus, one shared RMS object, null/random
 * and ephemeral logs. D-Bus and shared memory remain explicit local relays. */
#ifndef LISA_DIAGNOSTICS_GUARD_H
#define LISA_DIAGNOSTICS_GUARD_H
#include <sched.h>
#include <sys/mount.h>
#include <sys/statvfs.h>
#include <linux/netlink.h>
#include "startup_guardian.h"

static inline int diagnostics_directory(const char *root,const char *path) {
    char target[PATH_MAX];
    int size=snprintf(target,sizeof(target),"%s%s",root,path);
    return size>0&&size<(int)sizeof(target)?mkdir(target,0755):-1;
}
static inline int diagnostics_bind(const char *root,const char *source,const char *destination,int file,int device) {
    char target[PATH_MAX];
    int size=snprintf(target,sizeof(target),"%s%s",root,destination);
    if(size<0||size>=(int)sizeof(target)) return -1;
    if(file) {
        int fd=open(target,O_WRONLY|O_CREAT|O_EXCL|O_NOFOLLOW|O_CLOEXEC,0600);
        if(fd<0) return -1;
        if(close(fd)) return -1;
    }
    if(mount(source,target,NULL,MS_BIND,NULL)) return -1;
    if(!device && mount(NULL,target,NULL,MS_BIND|MS_REMOUNT|MS_RDONLY|MS_NOSUID|MS_NODEV,NULL)) return -1;
    return 0;
}
static inline int diagnostics_text(const char *root,const char *name,const char *text) {
    char path[PATH_MAX];
    if(snprintf(path,sizeof(path),"%s%s",root,name)>=(int)sizeof(path)) return -1;
    int file=open(path,O_WRONLY|O_CREAT|O_EXCL|O_NOFOLLOW|O_CLOEXEC,0600);
    if(file<0) return -1;
    int failed=store_write_all(file,text,strlen(text));
    if(close(file)) failed=1;
    return failed?-1:0;
}
/* The stock monitor requires its exact shared RMS state object before D-Bus
 * setup. Keep this explicit writable IPC dependency, not the host shm tree.
 * The verified firmware opens it RDWR and ftruncates it to this fixed size. */
#define DIAGNOSTICS_SHARED "/dev/shm/alsa-audio-monitor-v2"
#define DIAGNOSTICS_SHARED_BYTES 270408
static inline int diagnostics_shared_valid(const struct stat *info) {
    return S_ISREG(info->st_mode)&&info->st_uid==0&&info->st_gid==0&&info->st_nlink==1&&
        (info->st_mode&07777)==0640&&info->st_size==DIAGNOSTICS_SHARED_BYTES;
}
static inline int diagnostics_shared_bind(const char *root) {
    struct stat original,bound;
    char target[PATH_MAX];
    if(lstat(DIAGNOSTICS_SHARED,&original)||!diagnostics_shared_valid(&original)||
        diagnostics_bind(root,DIAGNOSTICS_SHARED,DIAGNOSTICS_SHARED,1,1)||
        snprintf(target,sizeof(target),"%s%s",root,DIAGNOSTICS_SHARED)>=(int)sizeof(target)||
        mount(NULL,target,NULL,MS_BIND|MS_REMOUNT|MS_NOSUID|MS_NODEV|MS_NOEXEC,NULL)||
        lstat(target,&bound)||!diagnostics_shared_valid(&bound)||
        original.st_dev!=bound.st_dev||original.st_ino!=bound.st_ino) return -1;
    return 0;
}
static inline int diagnostics_isolate(const char *root,const char *executable) {
    struct stat info;
    if(lstat(root,&info)||!S_ISDIR(info.st_mode)||info.st_uid||(info.st_mode&0077)||
        unshare(CLONE_NEWNS)||mount(NULL,"/",NULL,MS_REC|MS_PRIVATE,NULL)||
        mount("tmpfs",root,"tmpfs",MS_NOSUID|MS_NODEV,"size=2m,mode=755")) return -1;
    const char *directories[]={"/lib","/usr","/usr/lib","/usr/bin","/etc","/etc/alsa-audio-diagnostics",
        "/etc/alsa-audio-diagnostics/devices","/dev","/dev/shm","/data","/data/quasar","/var","/var/run","/var/run/dbus",
        "/var/lib","/var/lib/dbus","/proc","/proc/sys","/proc/sys/kernel","/proc/sys/kernel/random"};
    for(unsigned i=0;i<sizeof(directories)/sizeof(directories[0]);++i)
        if(diagnostics_directory(root,directories[i])) return -1;
    /* libdbus resolves its own numeric UID through NSS. Expose synthetic locked
     * metadata, never the host account database or password files. */
    if(diagnostics_text(root,"/etc/passwd","root:*:0:57343:Diagnostics:/:/nonexistent\n")||
        diagnostics_text(root,"/etc/group","root:*:0:\nlisa-diagnostics:*:57343:\n")||
        diagnostics_text(root,"/etc/nsswitch.conf","passwd: files\ngroup: files\nhosts: files\n")) return -1;
    if(diagnostics_bind(root,"/lib","/lib",0,0)||diagnostics_bind(root,"/usr/lib","/usr/lib",0,0)||
        diagnostics_bind(root,executable,"/usr/bin/alsa-audio-monitord",1,0)||
        diagnostics_bind(root,"/etc/alsa-audio-diagnostics.conf","/etc/alsa-audio-diagnostics.conf",1,0)||
        diagnostics_bind(root,"/etc/alsa-audio-diagnostics/devices/yandexmidi.json",
            "/etc/alsa-audio-diagnostics/devices/yandexmidi.json",1,0)||
        diagnostics_bind(root,"/dev/null","/dev/null",1,1)||diagnostics_bind(root,"/dev/urandom","/dev/urandom",1,1)||
        diagnostics_bind(root,"/var/run/dbus/system_bus_socket","/var/run/dbus/system_bus_socket",1,0)||
        diagnostics_bind(root,"/proc/sys/kernel/random/boot_id","/proc/sys/kernel/random/boot_id",1,0)||
        diagnostics_shared_bind(root)) return -1;
    const char *identities[]={"/etc/machine-id","/var/lib/dbus/machine-id"};
    for(unsigned i=0;i<sizeof(identities)/sizeof(identities[0]);++i) {
        if(!stat(identities[i],&info)) {
            if(!S_ISREG(info.st_mode)||diagnostics_bind(root,identities[i],identities[i],1,0)) return -1;
        } else if(errno!=ENOENT) return -1;
    }
    char data[PATH_MAX],kernel[PATH_MAX],kmsg[PATH_MAX];
    if(snprintf(data,sizeof(data),"%s/data/quasar",root)>=(int)sizeof(data)||
        mount("tmpfs",data,"tmpfs",MS_NOSUID|MS_NODEV|MS_NOEXEC,"size=4m,mode=700")||
        diagnostics_directory(root,"/data/quasar/daemons_logs")) return -1;
    if(snprintf(kernel,sizeof(kernel),"%s/data/quasar/daemons_logs/kernel.log",root)>=(int)sizeof(kernel)||
        snprintf(kmsg,sizeof(kmsg),"%s/dev/kmsg",root)>=(int)sizeof(kmsg)) return -1;
    int fd=open(kernel,O_WRONLY|O_CREAT|O_EXCL|O_CLOEXEC,0600);
    if(fd<0) return -1;
    if(close(fd)) return -1;
    fd=open(kmsg,O_WRONLY|O_CREAT|O_EXCL|O_CLOEXEC,0600);
    if(fd<0) return -1;
    if(close(fd)||mount(kernel,kmsg,NULL,MS_BIND,NULL)||
        mount(NULL,root,NULL,MS_REMOUNT|MS_RDONLY|MS_NOSUID|MS_NODEV,NULL)||chroot(root)||chdir("/")) return -1;
    struct statvfs filesystem;
    if(statvfs("/",&filesystem)||!(filesystem.f_flag&ST_RDONLY)||stat("/dev/kmsg",&info)||!S_ISREG(info.st_mode)) return -1;
    const char *hidden[]={"/proc/self","/proc/1","/proc/kmsg","/proc/mounts","/sys","/tmp/messages",
        "/data/quasar/data","/system/vendor/quasar/quasar.cfg","/dev/log"};
    for(unsigned i=0;i<sizeof(hidden)/sizeof(hidden[0]);++i)
        if(!lstat(hidden[i],&info)||errno!=ENOENT) return -1;
    return 0;
}
static inline uint64_t diagnostics_forbidden_caps(void) {
    return (1ull<<CAP_NET_ADMIN)|(1ull<<CAP_NET_RAW)|(1ull<<CAP_SYS_PTRACE)|(1ull<<CAP_SYS_ADMIN)|
        (1ull<<CAP_SYS_CHROOT)|(1ull<<CAP_SYSLOG)|(1ull<<CAP_MKNOD)|(1ull<<CAP_DAC_READ_SEARCH)|(1ull<<CAP_DAC_OVERRIDE);
}
/* Parent-side metadata checks after exec; never read private log contents. */
static inline int diagnostics_private_view(pid_t pid) {
    char path[PATH_MAX],own[128],child[128]; struct stat info,host; struct statvfs filesystem;
    snprintf(path,sizeof(path),"/proc/%ld/ns/mnt",(long)pid);
    ssize_t a=readlink("/proc/self/ns/mnt",own,sizeof(own)),b=readlink(path,child,sizeof(child));
    if(a<=0||b<=0||(a==b&&!memcmp(own,child,(size_t)a))) return -1;
    snprintf(path,sizeof(path),"/proc/%ld/root/dev/kmsg",(long)pid);
    if(stat(path,&info)||!S_ISREG(info.st_mode)||stat("/dev/kmsg",&host)||!S_ISCHR(host.st_mode)) return -1;
    snprintf(path,sizeof(path),"/proc/%ld/root",(long)pid);
    if(statvfs(path,&filesystem)||!(filesystem.f_flag&ST_RDONLY)) return -1;
    snprintf(path,sizeof(path),"/proc/%ld/root/data/quasar",(long)pid);
    if(stat(path,&info)||stat("/data/quasar",&host)||info.st_dev==host.st_dev||
        statvfs(path,&filesystem)||(filesystem.f_flag&ST_RDONLY)||
        (uint64_t)filesystem.f_blocks*filesystem.f_frsize>4u*1024u*1024u) return -1;
    snprintf(path,sizeof(path),"/proc/%ld/root/var/run/dbus/system_bus_socket",(long)pid);
    if(stat(path,&info)||!S_ISSOCK(info.st_mode)||stat("/var/run/dbus/system_bus_socket",&host)||
        info.st_dev!=host.st_dev||info.st_ino!=host.st_ino) return -1;
    snprintf(path,sizeof(path),"/proc/%ld/root%s",(long)pid,DIAGNOSTICS_SHARED);
    if(lstat(path,&info)||!diagnostics_shared_valid(&info)||lstat(DIAGNOSTICS_SHARED,&host)||
        info.st_dev!=host.st_dev||info.st_ino!=host.st_ino) return -1;
    const char *hidden[]={"/proc/self","/proc/1","/proc/kmsg","/proc/mounts","/sys","/tmp/messages",
        "/data/quasar/data","/system/vendor/quasar/quasar.cfg","/dev/log"};
    for(unsigned i=0;i<sizeof(hidden)/sizeof(hidden[0]);++i) {
        snprintf(path,sizeof(path),"/proc/%ld/root%s",(long)pid,hidden[i]);
        if(!lstat(path,&info)||errno!=ENOENT) return -1;
    }
    return 0;
}
static inline int diagnostics_unix_connected(pid_t pid) {
    char path[64]; snprintf(path,sizeof(path),"/proc/%ld/fd",(long)pid);
    DIR *directory=opendir(path);
    if(!directory) return 0;
    uint64_t sockets[256]; unsigned count=0; struct dirent *entry;
    while((entry=readdir(directory))) {
        char *end; long fd=strtol(entry->d_name,&end,10);
        if(*end||fd<0||fd>INT_MAX) continue;
        struct stat info; snprintf(path,sizeof(path),"/proc/%ld/fd/%ld",(long)pid,fd);
        if(!stat(path,&info)&&S_ISSOCK(info.st_mode)) {
            if(count==256) { closedir(directory); return 0; }
            sockets[count++]=info.st_ino;
        }
    }
    closedir(directory);
    FILE *table=fopen("/proc/net/unix","r"); char line[512]; int connected=0;
    if(!table) return 0;
    while(fgets(line,sizeof(line),table)) {
        unsigned state; unsigned long long inode;
        if(sscanf(line,"%*s %*s %*s %*s %*s %x %llu",&state,&inode)!=2||state!=3) continue;
        for(unsigned i=0;i<count;++i) if(sockets[i]==inode) connected=1;
    }
    if(ferror(table)) connected=0;
    fclose(table); return connected;
}
/* Install after identity lock/chroot. The fixed monitor needs AF_UNIX for D-Bus.
 * Internet, netlink and packet sockets are denied; AF_UNIX remains an explicit
 * IPC dependency, not a claim of complete isolation from local services. */
static inline int diagnostics_extra_guard(void) {
    const int remove[]={CAP_SYS_ADMIN,CAP_SYS_CHROOT,CAP_SYSLOG,CAP_MKNOD,CAP_DAC_READ_SEARCH,CAP_DAC_OVERRIDE};
    struct __user_cap_header_struct header={_LINUX_CAPABILITY_VERSION_3,0};
    struct __user_cap_data_struct caps[2];
    if(syscall(SYS_capget,&header,caps)) return -1;
    for(unsigned i=0;i<sizeof(remove)/sizeof(remove[0]);++i) {
        unsigned bit=(unsigned)remove[i],word=bit/32,mask=1u<<(bit%32);
        if(prctl(PR_CAPBSET_DROP,bit,0,0,0)) return -1;
        caps[word].effective&=~mask; caps[word].permitted&=~mask; caps[word].inheritable&=~mask;
    }
    if(syscall(SYS_capset,&header,caps)) return -1;
#define DIAG_DENY(n) BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K,n,0,1), BPF_STMT(BPF_RET|BPF_K,SECCOMP_RET_ERRNO|EPERM)
    struct sock_filter filter[]={
        BPF_STMT(BPF_LD|BPF_W|BPF_ABS,offsetof(struct seccomp_data,arch)),
        BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K,AUDIT_ARCH_ARM,1,0),BPF_STMT(BPF_RET|BPF_K,SECCOMP_RET_KILL),
        BPF_STMT(BPF_LD|BPF_W|BPF_ABS,offsetof(struct seccomp_data,nr)),
        DIAG_DENY(SYS_chroot),DIAG_DENY(SYS_mknod),DIAG_DENY(SYS_mknodat),DIAG_DENY(SYS_syslog),
        DIAG_DENY(SYS_open_by_handle_at),DIAG_DENY(SYS_name_to_handle_at),
#ifdef SYS_socketcall
        DIAG_DENY(SYS_socketcall),
#endif
        BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K,SYS_socket,2,0),
        BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K,SYS_socketpair,1,0),BPF_STMT(BPF_RET|BPF_K,SECCOMP_RET_ALLOW),
        BPF_STMT(BPF_LD|BPF_W|BPF_ABS,offsetof(struct seccomp_data,args[0])),
        BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K,AF_UNIX,1,0),BPF_STMT(BPF_RET|BPF_K,SECCOMP_RET_ERRNO|EPERM),
        BPF_STMT(BPF_RET|BPF_K,SECCOMP_RET_ALLOW),
    };
#undef DIAG_DENY
    struct sock_fprog program={sizeof(filter)/sizeof(filter[0]),filter};
    return prctl(PR_SET_SECCOMP,SECCOMP_MODE_FILTER,&program);
}
#endif
