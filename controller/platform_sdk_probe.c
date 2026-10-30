/* Audio-free, network-denied SDK diagnostic. Never starts the ordinary
 * launcher, never signals stock services, never reads real account/audio data.
 * Only syscall numbers/results and private file metadata are reported.
 * Bounded SDK stderr and failed pathname metadata stay in the generated private
 * lab directory. Trace never dereferences read/write/audio/credential buffers. */
#define _GNU_SOURCE
#include <dirent.h>
#include <elf.h>
#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <inttypes.h>
#include <limits.h>
#include <linux/capability.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ptrace.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <sys/uio.h>
#include <sys/wait.h>
#include <time.h>
#include "startup_guardian.h"
#include "vendor_identity.h"
#include "platform_sdk_guard.h"
#include "loopback_socket.h"
#ifndef __arm__
#error This SDK diagnostic requires the reviewed ARM register ABI
#endif
static int administrative_control(int family){
    struct pair pair={-1,-1};int ok=!make_pair(family,0,&pair)&&exchange(&pair);
    if(pair.client>=0)close(pair.client);
    if(pair.peer>=0)close(pair.peer);
    return ok;
}
static int equal(int root,const char *name,const char *text){
    char buffer[PATH_MAX];int fd=openat(root,name,O_RDONLY|O_NOFOLLOW|O_NONBLOCK|O_CLOEXEC);if(fd<0)return 0;
    ssize_t size=read(fd,buffer,sizeof(buffer));close(fd);return size==(ssize_t)strlen(text)&&!memcmp(text,buffer,(size_t)size);
}
static int put(int root,const char *name,const char *text){
    int fd=openat(root,name,O_WRONLY|O_CREAT|O_EXCL|O_NOFOLLOW|O_CLOEXEC,0600);if(fd<0)return -1;
    int failed=store_write_all(fd,text,strlen(text))||fsync(fd);if(close(fd))failed=1;return failed?-1:0;
}
static int directory(const char *base){
    const char prefix[]="/bkupgrade/data/opt/lisa-controller-lab/platform-sdk.";
    if(strncmp(base,prefix,sizeof(prefix)-1))return -1;
    const char *suffix=base+sizeof(prefix)-1;size_t size=strlen(suffix);if(size<6||size>16)return -1;
    for(size_t i=0;i<size;++i)if(!((suffix[i]>='a'&&suffix[i]<='z')||(suffix[i]>='A'&&suffix[i]<='Z')||(suffix[i]>='0'&&suffix[i]<='9')))return -1;
    int fd=open(base,O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC);
    if(fd<0||!platform_seed_directory(fd,0)){if(fd>=0)close(fd);return -1;}return fd;
}
static int record(int root,const char *name,pid_t pid){
    struct process_stamp stamp;char text[96];if(process_stamp(pid,&stamp))return -1;
    snprintf(text,sizeof(text),"%ld %" PRIu64 "\n",(long)pid,stamp.ticks);return put(root,name,text);
}
static int dead(int root,const char *name){
    int fd=openat(root,name,O_RDONLY|O_NOFOLLOW|O_NONBLOCK|O_CLOEXEC);if(fd<0)return errno==ENOENT;
    char text[96],canonical[96];struct stat info;ssize_t size=read(fd,text,sizeof(text)-1);
    int valid=!fstat(fd,&info)&&S_ISREG(info.st_mode)&&info.st_uid==0&&info.st_nlink==1&&(info.st_mode&07777)==0600;
    close(fd);if(!valid||size<=0||size>=(ssize_t)sizeof(text)-1)return 0;text[size]=0;
    long pid;unsigned long long ticks;int used=0;
    return sscanf(text,"%ld %llu\n%n",&pid,&ticks,&used)==2&&pid>1&&ticks&&used==size&&
        snprintf(canonical,sizeof(canonical),"%ld %llu\n",pid,ticks)==size&&!memcmp(canonical,text,(size_t)size)&&!process_live((pid_t)pid,ticks);
}
static int cleanup(const char *base){
    if(getuid()||geteuid()||getgid()||getegid())return 2;
    int root=directory(base);if(root<0)return 2;
    if(!dead(root,"run.owner")||!dead(root,"run.child")){close(root);return 3;}
    int seeds=openat(root,"seeds",O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC);int failed=0;
    if(seeds>=0){
        if(!platform_seed_directory(seeds,0)){close(seeds);close(root);return 3;}
        for(unsigned i=0;i<PLATFORM_SEED_COUNT;++i){struct stat info;const char *name=platform_seed_name(i);
            if(fstatat(seeds,name,&info,AT_SYMLINK_NOFOLLOW)<0){if(errno!=ENOENT)failed=1;continue;}
            if(!platform_seed_valid(&info,0,i)||!equal(seeds,name,i==0?"synthetic-identity\n":i==1?"{}\n":"")||unlinkat(seeds,name,0))failed=1;
        }
        close(seeds);if(unlinkat(root,"seeds",AT_REMOVEDIR))failed=1;
    }else if(errno!=ENOENT)failed=1;
    struct stat info;
    if(!fstatat(root,"profile.json",&info,AT_SYMLINK_NOFOLLOW)){
        if(!S_ISREG(info.st_mode)||info.st_uid||info.st_nlink!=1||(info.st_mode&07777)!=0600||info.st_size<=0||info.st_size>1024*1024||unlinkat(root,"profile.json",0))failed=1;
    }else if(errno!=ENOENT)failed=1;
    const char *names[]={"root0","root1","root2"};
    for(unsigned i=0;i<3;++i)if(unlinkat(root,names[i],AT_REMOVEDIR)&&errno!=ENOENT)failed=1;
    if(unlinkat(root,"run.owner",0)&&errno!=ENOENT)failed=1;
    if(unlinkat(root,"run.child",0)&&errno!=ENOENT)failed=1;
    close(root);return failed?3:0;
}
static int copy_profile(int root){
    struct stat before,after;int source=open("/system/vendor/quasar/quasar.cfg",O_RDONLY|O_NOFOLLOW|O_NONBLOCK|O_CLOEXEC);
    if(source<0)return -1;
    if(fstat(source,&before)||!S_ISREG(before.st_mode)||before.st_uid||before.st_nlink!=1||before.st_mode&0022||before.st_size<=0||before.st_size>1024*1024){close(source);return -1;}
    int target=openat(root,"profile.json",O_WRONLY|O_CREAT|O_EXCL|O_NOFOLLOW|O_CLOEXEC,0600);
    if(target<0){close(source);return -1;}
    char buffer[4096];ssize_t size;off_t total=0;int failed=0;
    while((size=read(source,buffer,sizeof(buffer)))>0){total+=size;if(total>before.st_size||store_write_all(target,buffer,(size_t)size)){failed=1;break;}}
    if(size<0||total!=before.st_size||fstat(source,&after)||!platform_seed_same(&before,&after)||fsync(target))failed=1;
    if(close(source))failed=1;
    if(close(target))failed=1;
    return failed?-1:0;
}
static int caps_zero(pid_t child){
    char path[80],line[256];snprintf(path,sizeof(path),"/proc/%ld/status",(long)child);FILE *file=fopen(path,"r");if(!file)return 0;
    /* This reviewed 4.9 kernel omits NoNewPrivs from status. The trusted
     * prepared child checks PR_GET_NO_NEW_PRIVS before its initial stop;
     * the irreversible setting survives exec. Reject any exported mismatch. */
    unsigned caps=0;int group=0,nnp=1,filter=0,one=0,tgid=0,valid=1,uid=0;
    while(fgets(line,sizeof(line),file)){
        unsigned long long value;
        if(sscanf(line,"CapInh: %llx",&value)==1||sscanf(line,"CapPrm: %llx",&value)==1||
            sscanf(line,"CapEff: %llx",&value)==1||sscanf(line,"CapBnd: %llx",&value)==1||sscanf(line,"CapAmb: %llx",&value)==1){++caps;if(value)valid=0;}
        unsigned a,b,c,d;
        if(sscanf(line,"Gid: %u %u %u %u",&a,&b,&c,&d)==4)group=a==57342&&b==a&&c==a&&d==a;
        if(sscanf(line,"Uid: %u %u %u %u",&a,&b,&c,&d)==4)uid=!(a|b|c|d);
        if(sscanf(line,"NoNewPrivs: %u",&a)==1)nnp=a==1;
        if(sscanf(line,"Seccomp: %u",&a)==1)filter=a==2;
        if(sscanf(line,"Threads: %u",&a)==1)one=a==1;
        if(sscanf(line,"Tgid: %u",&a)==1)tgid=a==(unsigned)child;
    }
    if(ferror(file))valid=0;
    fclose(file);return valid&&caps==5&&uid&&group&&nnp&&filter&&one&&tgid;
}
static int private_view(pid_t child,struct stat *data){
    char path[PATH_MAX],a[128],b[128];struct stat info,host;struct statvfs fs;
    snprintf(path,sizeof(path),"/proc/%ld/ns/mnt",(long)child);
    ssize_t x=readlink("/proc/self/ns/mnt",a,sizeof(a)),y=readlink(path,b,sizeof(b));
    if(x<=0||y<=0||(x==y&&!memcmp(a,b,(size_t)x))){fprintf(stderr,"sdk view stage %d\n",__LINE__);return 0;}
    snprintf(path,sizeof(path),"/proc/%ld/root",(long)child);if(statvfs(path,&fs)||!(fs.f_flag&ST_RDONLY)){fprintf(stderr,"sdk view stage %d\n",__LINE__);return 0;}
    const char *mounts[]={"/data/quasar","/tmp","/dev/shm"};
    for(unsigned i=0;i<3;++i){snprintf(path,sizeof(path),"/proc/%ld/root%s",(long)child,mounts[i]);
        if(stat(path,&info)||stat(mounts[i],&host)||info.st_dev==host.st_dev||statvfs(path,&fs)||
            fs.f_flag&ST_RDONLY||!(fs.f_flag&ST_NOEXEC)||(uint64_t)fs.f_blocks*fs.f_frsize>(i==0?32u:i==1?16u:4u)*1024*1024){fprintf(stderr,"sdk view stage %d\n",__LINE__);return 0;}
        if(!i)*data=info;
    }
    snprintf(path,sizeof(path),"/proc/%ld/root/proc/cmdline",(long)child);
    if(stat(path,&info)||stat("/proc/cmdline",&host)||!S_ISREG(info.st_mode)||info.st_dev!=host.st_dev||info.st_ino!=host.st_ino||
        statvfs(path,&fs)||!(fs.f_flag&ST_RDONLY)){fprintf(stderr,"sdk boot metadata mismatch\n");return 0;}
    const char *hidden[]={"/proc/self","/proc/1","/sys","/dev/snd","/dev/log","/dev/keymaster_svc",
        "/var/run/dbus/system_bus_socket","/bkupgrade","/data/opt","/tmp/messages","/dev/shm/alsa-audio-monitor-v2"};
    for(unsigned i=0;i<sizeof(hidden)/sizeof(hidden[0]);++i){snprintf(path,sizeof(path),"/proc/%ld/root%s",(long)child,hidden[i]);
        if(!lstat(path,&info)||errno!=ENOENT){fprintf(stderr,"sdk view stage %d\n",__LINE__);return 0;}}
    snprintf(path,sizeof(path),"/proc/%ld/fd",(long)child);DIR *fds=opendir(path);if(!fds){fprintf(stderr,"sdk view stage %d\n",__LINE__);return 0;}
    unsigned count=0;int valid=1;struct dirent *entry;
    if(stat("/dev/null",&host)){closedir(fds);{fprintf(stderr,"sdk view stage %d\n",__LINE__);return 0;}}
    while((entry=readdir(fds))){char *end;long n=strtol(entry->d_name,&end,10);if(*end)continue;
        if(n<0||n>2){valid=0;break;}
        ++count;snprintf(path,sizeof(path),"/proc/%ld/fd/%ld",(long)child,n);
        if(stat(path,&info)){valid=0;break;}
        if(n==2){struct stat log;snprintf(path,sizeof(path),"/proc/%ld/root/data/quasar/diagnostic.stderr",(long)child);
            if(stat(path,&log)||!S_ISREG(info.st_mode)||info.st_dev!=data->st_dev||info.st_ino!=log.st_ino||info.st_nlink!=1||(info.st_mode&07777)!=0600){valid=0;break;}}
        else if(!S_ISCHR(info.st_mode)||info.st_rdev!=host.st_rdev){valid=0;break;}
    }
    closedir(fds);
    if(!valid||count!=3||!caps_zero(child)){fprintf(stderr,"sdk view final %u %d\n",count,valid);return 0;}
    return 1;
}
static _Atomic int thread_ok,churn_ready;
static void *churn_thread(void *unused){(void)unused;atomic_fetch_add(&churn_ready,1);
    for(;;){struct timespec pause={0,1000000};nanosleep(&pause,NULL);}return NULL;
}
static void *own_thread(void *unused){(void)unused;atomic_store(&thread_ok,prctl(PR_GET_NO_NEW_PRIVS,0,0,0,0)==1&&socket(AF_INET,SOCK_STREAM,0)<0&&errno==EPERM);return NULL;}
static int own_actor(void){
    int fail=0,root=open("/",O_RDONLY|O_DIRECTORY|O_CLOEXEC);struct stat info;
    if(root<0||!equal(root,"etc/lisa-platform-storage","LISA_PLATFORM_STORAGE_V1\n"))return 9;
    close(root);
    const int families[]={AF_UNIX,AF_INET,AF_INET6};
    for(unsigned i=0;i<3;++i){errno=0;int fd=socket(families[i],SOCK_STREAM,0);if(fd>=0){close(fd);++fail;}else if(errno!=EPERM)++fail;}
    errno=0;if(kill(getppid(),0)!=-1||errno!=EPERM)++fail;
    if(kill(getpid(),0))++fail;
    pthread_t thread;if(pthread_create(&thread,NULL,own_thread,NULL))++fail;
    else if(pthread_join(thread,NULL)||!atomic_load(&thread_ok))++fail;
    if(!lstat("/dev/snd",&info)||errno!=ENOENT)++fail;
    errno=0;int missing=open("/lisa-sdk-missing-metadata",O_RDONLY|O_NOFOLLOW);
    if(missing>=0){close(missing);++fail;}else if(errno!=ENOENT)++fail;
    root=open("/data/quasar",O_RDONLY|O_DIRECTORY|O_CLOEXEC);if(root<0)return 9;
    if(!equal(root,"account_storage.dat","synthetic-identity\n")||put(root,"own-composition-proof","no audio\n"))++fail;
    close(root);if(fail)return 9;
    /* Exercise the tracer's group-exit race before any proprietary code runs. */
    pthread_t peers[8];
    for(unsigned i=0;i<8;++i)if(pthread_create(&peers[i],NULL,churn_thread,NULL))return 9;
    for(unsigned i=0;i<2000&&atomic_load(&churn_ready)!=8;++i){struct timespec pause={0,1000000};nanosleep(&pause,NULL);}
    if(atomic_load(&churn_ready)!=8)return 9;
    raise(SIGABRT);return 9;
}
#include "sdk_metadata_trace.h"
static int sdk_original_view(pid_t child,struct stat *data,void *unused){
    (void)unused;return private_view(child,data);
}
static int execute(const char *base,int rootdir,unsigned index,const char *seeds,const char *profile,const char *own){
    char root[PATH_MAX];snprintf(root,sizeof(root),"%s/root%u",base,index);if(mkdir(root,0700))return -1;
    pid_t parent=getpid(),child=fork();if(child<0)return -1;
    if(!child){
        if(prctl(PR_SET_PDEATHSIG,SIGKILL)||getppid()!=parent)_exit(80);
        struct rlimit stack={1024*1024,1024*1024},cpu={4,5},data={96u*1024*1024,96u*1024*1024},memory={256u*1024*1024,256u*1024*1024},files={128,128},core={0,0},size={2u*1024*1024,2u*1024*1024};
        if(setrlimit(RLIMIT_STACK,&stack)||setrlimit(RLIMIT_CPU,&cpu)||setrlimit(RLIMIT_DATA,&data)||setrlimit(RLIMIT_AS,&memory)||
            setrlimit(RLIMIT_CORE,&core)||setrlimit(RLIMIT_FSIZE,&size)||guardian_close_except(NULL,0))_exit(81);
        int null=open("/dev/null",O_RDWR|O_CLOEXEC);if(null<0)_exit(81);
        for(int fd=0;fd<3;++fd)if(dup2(null,fd)<0)_exit(81);
        if(null>2)close(null);
        const char *executable=index?"/system/vendor/quasar/maind":own;
        if(clearenv()||platform_storage_enter_mode(root,seeds,profile,executable,1)||chdir("/data/quasar"))_exit(82);
        if(setrlimit(RLIMIT_NOFILE,&files)||setenv("LD_LIBRARY_PATH","/system/vendor/quasar/libs",1)||
            setenv("GST_PLUGIN_PATH","/system/vendor/quasar/libs",1)||setenv("CA_CERTIFICATES","/system/vendor/quasar/ca-certificates.crt",1)||
            setenv("PWD",".",1)||setenv("MALLOC_ARENA_MAX","2",1))_exit(83);
        int log=open("/data/quasar/diagnostic.stderr",O_WRONLY|O_CREAT|O_EXCL|O_NOFOLLOW|O_CLOEXEC,0600);
        if(log<0||dup2(log,2)<0)_exit(84);
        if(log>2)close(log);
        if(ptrace(PTRACE_TRACEME,0,NULL,NULL))_exit(84);
        if(vendor_identity_prepare(57342))_exit(85);
        if(platform_sdk_guard(parent)||prctl(PR_GET_NO_NEW_PRIVS,0,0,0,0)!=1||prctl(PR_GET_SECCOMP,0,0,0,0)!=2)_exit(86);
        if(raise(SIGSTOP))_exit(87);
        execl("/system/vendor/quasar/maind","maind",index==0?"--own-actor":index==1?"--platformd":"--mediad",(char *)NULL);_exit(88);
    }
    if(record(rootdir,"run.child",child)){kill(child,SIGKILL);waitpid(child,NULL,0);return -1;}
    int status=0;pid_t waited;do{waited=waitpid(child,&status,0);}while(waited<0&&errno==EINTR);
    struct stat data;int good=waited==child&&WIFSTOPPED(status)&&WSTOPSIG(status)==SIGSTOP&&private_view(child,&data);
    if(!good){
        fprintf(stderr,"sdk preparation %u status %d waited %d\n",index,status,waited==child);
        if(waited==child&&WIFSTOPPED(status)){
            kill(child,SIGKILL);ptrace(PTRACE_CONT,child,NULL,(void *)(intptr_t)SIGKILL);waitpid(child,NULL,__WALL);}
        return -1;
    }
    long options=PTRACE_O_EXITKILL|PTRACE_O_TRACEEXEC|PTRACE_O_TRACECLONE|PTRACE_O_TRACESYSGOOD;
    if(ptrace(PTRACE_SETOPTIONS,child,NULL,(void *)options)||ptrace(PTRACE_SYSCALL,child,NULL,NULL)){kill(child,SIGKILL);waitpid(child,NULL,__WALL);return -1;}
    const char *path_name=index==0?"own-paths.private.txt":index==1?"platform-paths.private.txt":"media-paths.private.txt";
    int path_log=openat(rootdir,path_name,O_WRONLY|O_CREAT|O_EXCL|O_NOFOLLOW|O_CLOEXEC,0600);
    if(path_log<0){kill(child,SIGKILL);ptrace(PTRACE_CONT,child,NULL,(void *)(intptr_t)SIGKILL);waitpid(child,NULL,__WALL);return -1;}
    int retained=-1;struct observed result={0};int traced=sdk_trace_worker(child,index?"/system/vendor/quasar/maind":own,&retained,&result,path_log,sdk_original_view,NULL,0,NULL);
    if(close(path_log))good=0;
    unsigned objects=0;const char *paths[]={"soundLogStorageDir","soundLogStorage.dat","data/local_events.lmdb","data/capability_states.lmdb","session_storage.dat","own-composition-proof"};
    for(unsigned i=0;i<sizeof(paths)/sizeof(paths[0]);++i){struct stat object;
        if(retained>=0&&!fstatat(retained,paths[i],&object,AT_SYMLINK_NOFOLLOW)){if(object.st_dev!=data.st_dev)good=0;else objects|=1u<<i;}
        else if(errno!=ENOENT)good=0;
    }
    /* No SDK stderr is printed to the report stream. Only a bounded prefix is
     * saved in this generated root-private lab directory for local diagnosis. */
    unsigned log_bytes=0;int log_truncated=0;
    if(retained>=0){
        int input=openat(retained,"diagnostic.stderr",O_RDONLY|O_NOFOLLOW|O_NONBLOCK|O_CLOEXEC);struct stat meta;
        const char *name=index==0?"own-stderr.private.txt":index==1?"platform-stderr.private.txt":"media-stderr.private.txt";
        int output=openat(rootdir,name,O_WRONLY|O_CREAT|O_EXCL|O_NOFOLLOW|O_CLOEXEC,0600);
        if(input<0||output<0||fstat(input,&meta)||!S_ISREG(meta.st_mode)||meta.st_dev!=data.st_dev||meta.st_nlink!=1||meta.st_size<0||meta.st_size>(off_t)(2u*1024*1024))good=0;
        else{char buffer[4096];while(log_bytes<65536){ssize_t size=read(input,buffer,sizeof(buffer));
                if(size<0){good=0;break;}if(!size)break;
                if(store_write_all(output,buffer,(size_t)size)){good=0;break;}log_bytes+=(unsigned)size;}
            log_truncated=meta.st_size>(off_t)log_bytes;
        }
        if(input>=0)close(input);
        if(output>=0&&close(output))good=0;
        close(retained);
    }
    if(index==0&&(!WIFSIGNALED(result.status)||WTERMSIG(result.status)!=SIGABRT||objects!=(1u<<5)||!result.path_control||result.threads!=9))good=0;
    if(unlinkat(rootdir,"run.child",0)||rmdir(root))good=0;
    good=good&&!traced&&result.verified&&result.drained;
    printf("{\"event\":\"platform-sdk-diagnostic\",\"role\":\"%s\",\"boundary_ok\":%s,\"exec_verified\":%s,\"drained\":%s,\"syscalls\":%u,\"errors\":%u,\"denied\":%u,\"socket_attempts\":%u,\"open_attempts\":%u,\"clone_attempts\":%u,\"threads\":%u,\"bounded_stop\":%s,\"exit_code\":%d,\"exit_signal\":%d,\"private_objects_mask\":%u,\"lost_registers\":%u,\"path_control\":%s,\"private_stderr_bytes\":%u,\"private_stderr_truncated\":%s,\"synthetic_identity\":true,\"audio_opened\":false,\"functionality_verified\":false}\n",
        index==0?"own-elf":index==1?"platform":"media",good?"true":"false",result.verified?"true":"false",result.drained?"true":"false",result.entries,result.errors,result.denied,result.sockets,result.opens,result.clones,result.threads,result.bounded?"true":"false",
        WIFEXITED(result.status)?WEXITSTATUS(result.status):-1,WIFSIGNALED(result.status)?WTERMSIG(result.status):0,objects,result.lost_registers,result.path_control?"true":"false",log_bytes,log_truncated?"true":"false");
    fflush(stdout);return good?0:-1;
}
static int inspect(const char *base){
    struct stat info;struct statvfs fs;char compatible[128];
    if(getuid()||geteuid()||getgid()||getegid()||statvfs("/",&fs)||!(fs.f_flag&ST_RDONLY))return 2;
    if(!lstat("/bkupgrade/data/opt/lisa-station/state",&info)||errno!=ENOENT||!lstat("/run/lisa-station",&info)||errno!=ENOENT)return 2;
    int fd=open("/proc/device-tree/compatible",O_RDONLY|O_CLOEXEC);if(fd<0)return 2;
    ssize_t used=read(fd,compatible,sizeof(compatible));close(fd);
    if(used<19||memcmp(compatible,"yandex,station-midi",19))return 2;
    int core=open("/proc/sys/kernel/core_pattern",O_RDONLY|O_NOFOLLOW|O_CLOEXEC);char pattern[1024];
    if(core<0)return 2;
    ssize_t core_size=read(core,pattern,sizeof(pattern));close(core);
    /* Piped core handlers ignore RLIMIT_CORE. Refuse them rather than sending
     * an SDK memory image to any host helper. This never changes the sysctl. */
    if(core_size<=0||core_size==(ssize_t)sizeof(pattern)||pattern[0]=='|')return 2;
    int root=directory(base);if(root<0)return 2;
    int mutex=open("/data/opt/lisa-lab/trial.lock",O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC);
    if(mutex<0||!platform_seed_directory(mutex,0)||!equal(mutex,"platform-sdk.owner",base)){if(mutex>=0)close(mutex);close(root);return 2;}close(mutex);
    umask(077);signal(SIGPIPE,SIG_IGN);alarm(40);pid_t owner=getppid();
    if(owner<=1||prctl(PR_SET_PDEATHSIG,SIGKILL)||getppid()!=owner||record(root,"run.owner",getpid()))return 2;
    char seeds[PATH_MAX],profile[PATH_MAX],own[PATH_MAX];snprintf(seeds,sizeof(seeds),"%s/seeds",base);snprintf(profile,sizeof(profile),"%s/profile.json",base);
    if(mkdir(seeds,0700)||copy_profile(root))return 3;
    int source=open(seeds,O_RDONLY|O_DIRECTORY|O_CLOEXEC);if(source<0)return 3;
    for(unsigned i=0;i<PLATFORM_SEED_COUNT;++i)if(put(source,platform_seed_name(i),i==0?"synthetic-identity\n":i==1?"{}\n":""))return 3;
    close(source);ssize_t size=readlink("/proc/self/exe",own,sizeof(own)-1);if(size<=0||size>=(ssize_t)sizeof(own)-1)return 3;own[size]=0;
    for(unsigned i=0;i<3;++i)if(execute(base,root,i,seeds,profile,own)){close(root);return 4;}
    close(root);return administrative_control(AF_INET)&&administrative_control(AF_INET6)?0:4;
}
int main(int argc,char **argv){
    if(argc==2&&!strcmp(argv[1],"--own-actor"))return own_actor();
    if(argc==3&&!strcmp(argv[1],"--station-inspect"))return inspect(argv[2]);
    if(argc==3&&!strcmp(argv[1],"--cleanup"))return cleanup(argv[2]);
    return 2;
}
