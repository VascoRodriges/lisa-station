/* Platform storage-only epoch. No host DATA, logs, proc, admin roots, D-Bus or
 * audio devices. Actual platform IPC/hardware compatibility is separate work.
 * Call in a disposable prepared child; failure requires child exit. The caller
 * closes all inherited host FDs except its bounded control/report pipes first.
 */
#ifndef LISA_PLATFORM_STORAGE_H
#define LISA_PLATFORM_STORAGE_H
#include "collector_guard.h"
#include "platform_seed.h"

static inline int platform_storage_bind_file(const char *root,const char *source,const char *destination,int executable){
    struct stat before,after;char target[PATH_MAX],pinned[64];
    int fd=open(source,O_RDONLY|O_NOFOLLOW|O_NONBLOCK|O_CLOEXEC);if(fd<0)return -1;
    int valid=!fstat(fd,&before)&&S_ISREG(before.st_mode)&&before.st_uid==0&&before.st_nlink==1&&before.st_size>0&&
        (executable?!(before.st_mode&(0022|S_ISUID|S_ISGID))&&(before.st_mode&0111):
                    (before.st_mode&07777)==0600&&before.st_size<=1024*1024);
    snprintf(pinned,sizeof(pinned),"/proc/self/fd/%d",fd);
    if(snprintf(target,sizeof(target),"%s%s",root,destination)>=(int)sizeof(target))valid=0;
    int failed=!valid||mount(pinned,target,NULL,MS_BIND,NULL)||
        mount(NULL,target,NULL,MS_BIND|MS_REMOUNT|MS_RDONLY|MS_NOSUID|MS_NODEV|(executable?0:MS_NOEXEC),NULL)||
        fstat(fd,&after)||!platform_seed_same(&before,&after);
    if(close(fd))failed=1;
    return failed?-1:0;
}
static inline int platform_storage_tmpfs(const char *root,const char *path,const char *options){
    char target[PATH_MAX];
    return snprintf(target,sizeof(target),"%s%s",root,path)>=(int)sizeof(target)||
        mount("tmpfs",target,"tmpfs",MS_NOSUID|MS_NODEV|MS_NOEXEC,options)?-1:0;
}
static inline int platform_storage_enter(const char *root,const char *seeds,const char *profile,const char *executable){
    struct stat info;int source=-1,destination=-1,failed=1;char target[PATH_MAX];
    if(lstat(root,&info)||!S_ISDIR(info.st_mode)||info.st_uid||(info.st_mode&07777)!=0700)return -1;
    source=open(seeds,O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC);
    if(source<0||!platform_seed_directory(source,0))goto done;
    /* Validate every source before any namespace mutation. */
    for(unsigned i=0;i<PLATFORM_SEED_COUNT;++i){int fd=platform_seed_open(source,0,i,&info);if(fd<0)goto done;if(close(fd))goto done;}
    if(unshare(CLONE_NEWNS)||mount(NULL,"/",NULL,MS_REC|MS_PRIVATE,NULL)||
        mount("tmpfs",root,"tmpfs",MS_NOSUID|MS_NODEV,"size=2m,mode=755"))goto done;
    const char *directories[]={"/lib","/usr","/usr/lib","/system","/system/vendor","/system/vendor/quasar",
        "/data","/data/quasar","/etc","/dev","/dev/shm","/tmp","/var","/var/log","/var/run","/proc"};
    for(unsigned i=0;i<sizeof(directories)/sizeof(directories[0]);++i)if(diagnostics_directory(root,directories[i]))goto done;
    if(diagnostics_text(root,"/etc/lisa-platform-storage","LISA_PLATFORM_STORAGE_V1\n")||
        diagnostics_text(root,"/etc/passwd","root:*:0:57342:Platform:/:/nonexistent\n")||
        diagnostics_text(root,"/etc/group","root:*:0:\nlisa-platform:*:57342:\n")||
        diagnostics_text(root,"/etc/nsswitch.conf","passwd: files\ngroup: files\nhosts: files dns\n")||
        diagnostics_bind(root,"/lib","/lib",0,0)||diagnostics_bind(root,"/usr/lib","/usr/lib",0,0)||
        diagnostics_bind(root,"/system/vendor/quasar","/system/vendor/quasar",0,0)||
        platform_storage_bind_file(root,profile,"/system/vendor/quasar/quasar.cfg",0)||
        platform_storage_bind_file(root,executable,"/system/vendor/quasar/maind",1)||
        diagnostics_bind(root,"/dev/null","/dev/null",1,1)||diagnostics_bind(root,"/dev/urandom","/dev/urandom",1,1))goto done;
    const char *files[]={"/etc/hosts","/etc/resolv.conf","/etc/localtime"};
    for(unsigned i=0;i<sizeof(files)/sizeof(files[0]);++i){
        if(!stat(files[i],&info)){if(!S_ISREG(info.st_mode)||diagnostics_bind(root,files[i],files[i],1,0))goto done;}
        else if(errno!=ENOENT)goto done;
    }
    if(platform_storage_tmpfs(root,"/data/quasar","size=32m,mode=700")||
        platform_storage_tmpfs(root,"/tmp","size=16m,mode=700")||
        platform_storage_tmpfs(root,"/dev/shm","size=4m,mode=700"))goto done;
    if(snprintf(target,sizeof(target),"%s/data/quasar",root)>=(int)sizeof(target))goto done;
    destination=open(target,O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC);if(destination<0)goto done;
    for(unsigned i=0;i<PLATFORM_SEED_COUNT;++i)if(platform_seed_copy(source,destination,0,i))goto done;
    if(close(source)){source=-1;goto done;}source=-1;
    if(close(destination)){destination=-1;goto done;}destination=-1;
    if(diagnostics_directory(root,"/data/quasar/data")||diagnostics_directory(root,"/data/quasar/daemons_logs")||
        mount(NULL,root,NULL,MS_REMOUNT|MS_RDONLY|MS_NOSUID|MS_NODEV,NULL)||chroot(root)||chdir("/"))goto done;
    failed=0;
done:
    if(source>=0)close(source);
    if(destination>=0)close(destination);
    return failed?-1:0;
}
/* Storage-only probe policy. Named/abstract UNIX sockets and host-directed
 * signals/keyrings are not justified by this narrow boundary. Anonymous
 * socketpairs remain available. Real SDK IPC compatibility requires reviewed
 * adapters rather than exposing the host bus or abstract namespace wholesale. */
static inline int platform_storage_guard(void){
    if(collector_extra_guard())return -1;
#define PLATFORM_DENY(n) BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K,n,0,1),BPF_STMT(BPF_RET|BPF_K,SECCOMP_RET_ERRNO|EPERM)
    struct sock_filter filter[]={
        BPF_STMT(BPF_LD|BPF_W|BPF_ABS,offsetof(struct seccomp_data,nr)),
        PLATFORM_DENY(SYS_kill),PLATFORM_DENY(SYS_tkill),PLATFORM_DENY(SYS_tgkill),
        PLATFORM_DENY(SYS_rt_sigqueueinfo),PLATFORM_DENY(SYS_rt_tgsigqueueinfo),
        PLATFORM_DENY(SYS_keyctl),PLATFORM_DENY(SYS_add_key),PLATFORM_DENY(SYS_request_key),
        BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K,SYS_socket,1,0),BPF_STMT(BPF_RET|BPF_K,SECCOMP_RET_ALLOW),
        BPF_STMT(BPF_LD|BPF_W|BPF_ABS,offsetof(struct seccomp_data,args[0])),
        BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K,AF_UNIX,0,1),BPF_STMT(BPF_RET|BPF_K,SECCOMP_RET_ERRNO|EPERM),
        BPF_STMT(BPF_RET|BPF_K,SECCOMP_RET_ALLOW),
    };
#undef PLATFORM_DENY
    struct sock_fprog program={sizeof(filter)/sizeof(filter[0]),filter};
    return prctl(PR_SET_SECCOMP,SECCOMP_MODE_FILTER,&program);
}
#endif
