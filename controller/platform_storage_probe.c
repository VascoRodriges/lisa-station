/* Synthetic seed/queue boundary only. Never run the proprietary SDK, read its
 * credentials/queues, or expose/open a microphone. No stock service changes. */
#define _GNU_SOURCE
#include <stdlib.h>
#include <sys/wait.h>
#include <unistd.h>
static ssize_t seed_fixture_read(int,void *,size_t);
#define read seed_fixture_read
#include "platform_seed.h"
#undef read

static int put(int directory,const char *name,const char *text){
    int fd=openat(directory,name,O_WRONLY|O_CREAT|O_EXCL|O_NOFOLLOW|O_CLOEXEC,0600);if(fd<0)return -1;
    int failed=store_write_all(fd,text,strlen(text));if(close(fd))failed=1;return failed?-1:0;
}
/* Deterministic race injection for the synthetic seed unit fixture only. */
static int replace_seed_directory=-1;static struct stat replace_seed_identity;
static ssize_t seed_fixture_read(int fd,void *buffer,size_t capacity){
    ssize_t used=read(fd,buffer,capacity);struct stat actual;
    if(used>0&&replace_seed_directory>=0&&!fstat(fd,&actual)&&actual.st_dev==replace_seed_identity.st_dev&&actual.st_ino==replace_seed_identity.st_ino){
        int directory=replace_seed_directory;replace_seed_directory=-1;
        if(unlinkat(directory,"account_storage.dat",0)||put(directory,"account_storage.dat","source-after\n")){errno=EIO;return -1;}
    }
    return used;
}
static int equal(int directory,const char *name,const char *text){
    char buffer[128];int fd=openat(directory,name,O_RDONLY|O_NOFOLLOW|O_CLOEXEC);if(fd<0)return 0;
    ssize_t size=read(fd,buffer,sizeof(buffer));close(fd);
    return size==(ssize_t)strlen(text)&&!memcmp(buffer,text,(size_t)size);
}
static int prepare_seeds(int directory){
    for(unsigned i=0;i<PLATFORM_SEED_COUNT;++i)
        if(put(directory,platform_seed_name(i),i==0?"synthetic-identity\n":i==1?"{}\n":""))return -1;
    return 0;
}
#define VERIFY(x) do{++checks;if(!(x)){fprintf(stderr,"platform seed fixture line %d\n",__LINE__);return 2;}}while(0)
static int seed_selftest(void){
    umask(077);unsigned checks=0;char path[]="/tmp/lisa-platform-seeds.XXXXXX";VERIFY(mkdtemp(path));
    int root=open(path,O_RDONLY|O_DIRECTORY|O_CLOEXEC);VERIFY(root>=0);
    VERIFY(!mkdirat(root,"source",0700)&&!mkdirat(root,"destination",0700));
    int source=openat(root,"source",O_RDONLY|O_DIRECTORY|O_CLOEXEC),destination=openat(root,"destination",O_RDONLY|O_DIRECTORY|O_CLOEXEC);
    uid_t owner=geteuid();VERIFY(source>=0&&destination>=0&&!prepare_seeds(source));
    struct stat before,after;VERIFY(!platform_seed_name(PLATFORM_SEED_COUNT));
    for(unsigned i=0;i<PLATFORM_SEED_COUNT;++i){
        if(i==0)umask(0777);
        VERIFY(!platform_seed_copy(source,destination,owner,i));
        umask(077);
        VERIFY(!fstatat(source,platform_seed_name(i),&before,AT_SYMLINK_NOFOLLOW)&&
            !fstatat(destination,platform_seed_name(i),&after,AT_SYMLINK_NOFOLLOW)&&
            before.st_ino!=after.st_ino&&before.st_size==after.st_size&&platform_seed_valid(&after,owner,i));
    }
    VERIFY(platform_seed_copy(source,destination,owner,0)<0&&equal(source,"account_storage.dat","synthetic-identity\n"));
    VERIFY(!unlinkat(destination,"account_storage.dat",0)&&!put(destination,"account_storage.dat","private refresh\n")&&equal(source,"account_storage.dat","synthetic-identity\n"));
    VERIFY(!fchmodat(source,"account_storage.dat",0644,0));
    int fd=platform_seed_open(source,owner,0,&before);VERIFY(fd<0);
    VERIFY(!fchmodat(source,"account_storage.dat",0600,0)&&!linkat(source,"account_storage.dat",source,"alias",0));
    VERIFY(platform_seed_open(source,owner,0,&before)<0);
    VERIFY(!unlinkat(source,"alias",0)&&!unlinkat(source,"account_storage.dat",0)&&!symlinkat("gsdkTokens.json",source,"account_storage.dat"));
    VERIFY(platform_seed_open(source,owner,0,&before)<0);
    VERIFY(!unlinkat(source,"account_storage.dat",0)&&!mkfifoat(source,"account_storage.dat",0600));
    VERIFY(platform_seed_open(source,owner,0,&before)<0);
    VERIFY(!unlinkat(source,"account_storage.dat",0)&&!mkdirat(source,"account_storage.dat",0700));
    VERIFY(platform_seed_open(source,owner,0,&before)<0);
    VERIFY(!unlinkat(source,"account_storage.dat",AT_REMOVEDIR)&&!put(source,"account_storage.dat",""));
    VERIFY(platform_seed_open(source,owner,0,&before)<0);
    fd=openat(source,"account_storage.dat",O_WRONLY|O_CLOEXEC);VERIFY(fd>=0&&!ftruncate(fd,65537)&&!close(fd));
    VERIFY(platform_seed_open(source,owner,0,&before)<0);
    VERIFY(!unlinkat(source,"registered",0)&&!put(source,"registered","unexpected payload\n"));
    VERIFY(platform_seed_open(source,owner,3,&before)<0);
    VERIFY(!fchmod(source,0755)&&platform_seed_open(source,owner,1,&before)<0&&!fchmod(source,0700));
    VERIFY(platform_seed_open(source,owner+1,1,&before)<0&&platform_seed_copy(source,destination,owner,99)<0);
    VERIFY(!unlinkat(source,"account_storage.dat",0)&&!put(source,"account_storage.dat","source-before\n")&&
        !unlinkat(destination,"account_storage.dat",0)&&!fstatat(source,"account_storage.dat",&replace_seed_identity,AT_SYMLINK_NOFOLLOW));
    replace_seed_directory=source;
    VERIFY(platform_seed_copy(source,destination,owner,0)<0&&replace_seed_directory==-1&&equal(source,"account_storage.dat","source-after\n"));
    VERIFY(fstatat(destination,"account_storage.dat",&after,AT_SYMLINK_NOFOLLOW)<0&&errno==ENOENT);
    VERIFY(!put(destination,"account_storage.dat","cleanup fixture\n"));
    for(unsigned i=0;i<PLATFORM_SEED_COUNT;++i){VERIFY(!unlinkat(source,platform_seed_name(i),0));VERIFY(!unlinkat(destination,platform_seed_name(i),0));}
    VERIFY(!close(source)&&!close(destination)&&!unlinkat(root,"source",AT_REMOVEDIR)&&!unlinkat(root,"destination",AT_REMOVEDIR)&&!close(root)&&!rmdir(path));
    printf("{\"selftest\":\"platform-seeds\",\"checks\":%u,\"ok\":true,\"synthetic_only\":true}\n",checks);return 0;
}
#undef VERIFY

#ifdef __arm__
#include <grp.h>
#include <linux/audit.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <stddef.h>
#include <sys/statvfs.h>
#include <sys/syscall.h>
#include "startup_guardian.h"
#include "vendor_identity.h"
#include "platform_storage.h"
#include "loopback_socket.h"

static unsigned checks,failures;
static void check(int ok){++checks;if(!ok){++failures;fprintf(stderr,"platform storage check %u\n",checks);}}
static int hidden(const char *path){struct stat info;return lstat(path,&info)<0&&errno==ENOENT;}
static int actor(int report,int control,const char *canary){
    if(!hidden("/proc/self"))return 2;
    int root=open("/",O_RDONLY|O_DIRECTORY|O_CLOEXEC);if(root<0)return 2;
    int prepared=equal(root,"etc/lisa-platform-storage","LISA_PLATFORM_STORAGE_V1\n");close(root);if(!prepared)return 2;
    struct statvfs fs;struct stat data,tmp,shm;int directory=open("/data/quasar",O_RDONLY|O_DIRECTORY|O_CLOEXEC);
    check(directory>=0&&getuid()==0&&geteuid()==0&&getgid()==57342&&getegid()==57342);
    check(!statvfs("/",&fs)&&(fs.f_flag&ST_RDONLY));
    const char *writable[]={"/data/quasar","/tmp","/dev/shm"};
    for(unsigned i=0;i<3;++i)check(!statvfs(writable[i],&fs)&&!(fs.f_flag&ST_RDONLY)&&(fs.f_flag&ST_NOEXEC)&&
        (uint64_t)fs.f_blocks*fs.f_frsize<=(i==0?32u:i==1?16u:4u)*1024*1024);
    check(!stat("/data/quasar",&data)&&!stat("/tmp",&tmp)&&!stat("/dev/shm",&shm)&&data.st_dev!=tmp.st_dev&&tmp.st_dev!=shm.st_dev&&shm.st_dev!=data.st_dev);
    /* Refuse an incorrectly invoked actor before reading or mutating DATA. */
    if(failures){if(directory>=0)close(directory);return 2;}
    check(equal(directory,"account_storage.dat","synthetic-identity\n")&&equal(directory,"gsdkTokens.json","{}\n"));
    const char *absent[]={"/proc/1/root","/proc/self/fd","/proc/cmdline","/sys","/bkupgrade","/data/opt","/etc/shadow",
        "/dev/snd","/dev/log","/dev/keymaster_svc","/var/run/dbus/system_bus_socket","/tmp/messages",
        "/tmp/teleme3d","/data/quasar/soundLogStorageDir","/data/quasar/soundLogStorage.dat",
        "/data/quasar/data/local_events.lmdb","/data/quasar/appmetrica","/data/quasar/data/capability_states.lmdb"};
    for(unsigned i=0;i<sizeof(absent)/sizeof(absent[0]);++i)check(hidden(absent[i]));
    check(hidden(canary));
    struct __user_cap_header_struct header={_LINUX_CAPABILITY_VERSION_3,0};struct __user_cap_data_struct caps[2];
    check(!syscall(SYS_capget,&header,caps)&&!(caps[0].effective|caps[0].permitted|caps[0].inheritable|caps[1].effective|caps[1].permitted|caps[1].inheritable));
    check(prctl(PR_GET_NO_NEW_PRIVS,0,0,0,0)==1);
    check(prctl(PR_GET_SECCOMP,0,0,0,0)==2);
    for(unsigned i=0;i<41;++i){int present=prctl(PR_CAPBSET_READ,i,0,0,0);if(present<0){check(errno==EINVAL);break;}check(present==0);}
    errno=0;check(chroot(".")<0&&errno==EPERM);
    errno=0;check(unshare(CLONE_NEWNS)<0&&errno==EPERM);
    errno=0;check(syscall(SYS_kill,getpid(),0)<0&&errno==EPERM);
    errno=0;check(syscall(SYS_keyctl,0,0,0,0,0)<0&&errno==EPERM);
    int fd=socket(AF_UNIX,SOCK_STREAM|SOCK_CLOEXEC,0);check(fd<0&&errno==EPERM);if(fd>=0)close(fd);
    const int pair_types[]={SOCK_STREAM,SOCK_DGRAM};
    for(unsigned i=0;i<2;++i){int pair[2];errno=0;int paired=socketpair(AF_UNIX,pair_types[i]|SOCK_CLOEXEC,0,pair);
        check(paired<0&&errno==EPERM);if(!paired){close(pair[0]);close(pair[1]);}}
    const int families[]={AF_INET,AF_INET6};for(unsigned i=0;i<2;++i){fd=socket(families[i],SOCK_DGRAM|SOCK_CLOEXEC,0);check(fd>=0);if(fd>=0)close(fd);}
    if(failures){uint64_t bad[]={checks,failures};(void)write(report,bad,sizeof(bad));close(directory);return 4;}
    check(!unlinkat(directory,"account_storage.dat",0)&&!put(directory,"account_storage.dat","private refresh\n"));
    check(!mkdirat(directory,"soundLogStorageDir",0700));
    int queue=open("/data/quasar/soundLogStorageDir/pending",O_RDWR|O_CREAT|O_EXCL|O_CLOEXEC,0600);
    check(queue>=0&&!store_write_all(queue,"synthetic queue\n",16));
    int event=open("/data/quasar/data/local_events.lmdb",O_RDWR|O_CREAT|O_EXCL|O_CLOEXEC,0600);
    check(event>=0&&!store_write_all(event,"synthetic event\n",16));
    check(!put(directory,"ephemeral-state","synthetic state\n"));
    close(directory);uint64_t results[]={checks,failures};
    if(write(report,results,sizeof(results))!=sizeof(results))return 4;
    struct pollfd wait={control,POLLIN,0};char command;
    int ok=poll(&wait,1,5000)==1&&read(control,&command,1)==1&&command=='X'&&!failures;
    if(queue>=0)close(queue);
    if(event>=0)close(event);
    return ok?0:4;
}
static int administrative_control(int family){
    struct pair pair={-1,-1};int ok=!make_pair(family,0,&pair)&&exchange(&pair);
    if(pair.client>=0)close(pair.client);
    if(pair.peer>=0)close(pair.peer);
    return ok;
}
static int private_view(pid_t child,const struct stat *data){
    char path[PATH_MAX],own_ns[128],child_ns[128];struct statvfs fs;struct stat info,tmp,shm,null;
    snprintf(path,sizeof(path),"/proc/%ld/ns/mnt",(long)child);
    ssize_t a=readlink("/proc/self/ns/mnt",own_ns,sizeof(own_ns)),b=readlink(path,child_ns,sizeof(child_ns));
    if(a<=0||b<=0||(a==b&&!memcmp(own_ns,child_ns,(size_t)a)))return 0;
    snprintf(path,sizeof(path),"/proc/%ld/root",(long)child);if(statvfs(path,&fs)||!(fs.f_flag&ST_RDONLY))return 0;
    snprintf(path,sizeof(path),"/proc/%ld/root/tmp",(long)child);if(stat(path,&tmp))return 0;
    snprintf(path,sizeof(path),"/proc/%ld/root/dev/shm",(long)child);if(stat(path,&shm)||stat("/dev/null",&null))return 0;
    snprintf(path,sizeof(path),"/proc/%ld/fd",(long)child);DIR *directory=opendir(path);if(!directory)return 0;
    struct dirent *entry;unsigned count=0;int valid=1;
    for(;;){
        errno=0;entry=readdir(directory);if(!entry){if(errno)valid=0;break;}
        char *end;long number=strtol(entry->d_name,&end,10);if(*end||number<0)continue;
        if(++count>64){valid=0;break;}
        snprintf(path,sizeof(path),"/proc/%ld/fd/%ld",(long)child,number);
        if(stat(path,&info)){valid=0;break;}
        if(S_ISREG(info.st_mode)){if(info.st_dev!=data->st_dev&&info.st_dev!=tmp.st_dev&&info.st_dev!=shm.st_dev)valid=0;}
        else if(S_ISCHR(info.st_mode)){if(info.st_rdev!=null.st_rdev)valid=0;}
        else if(!S_ISFIFO(info.st_mode))valid=0;
    }
    closedir(directory);return valid&&count>=5;
}
static int fixture_directory(const char *path){
    const char prefix[]="/bkupgrade/data/opt/lisa-controller-lab/platform-storage.";
    if(!path||strncmp(path,prefix,sizeof(prefix)-1))return -1;
    const char *suffix=path+sizeof(prefix)-1;size_t size=strlen(suffix);if(size<6||size>16)return -1;
    for(size_t i=0;i<size;++i)if(!((suffix[i]>='a'&&suffix[i]<='z')||(suffix[i]>='A'&&suffix[i]<='Z')||(suffix[i]>='0'&&suffix[i]<='9')))return -1;
    int fd=open(path,O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC);
    if(fd<0||!platform_seed_directory(fd,0)){if(fd>=0)close(fd);return -1;}return fd;
}
static int fixture_process_dead(int root,const char *name){
    int fd=openat(root,name,O_RDONLY|O_NOFOLLOW|O_NONBLOCK|O_CLOEXEC);if(fd<0)return errno==ENOENT;
    char text[96],canonical[96];ssize_t used=read(fd,text,sizeof(text)-1);struct stat info;
    int valid=!fstat(fd,&info)&&S_ISREG(info.st_mode)&&info.st_uid==0&&info.st_nlink==1&&(info.st_mode&07777)==0600;
    close(fd);if(used<=0||used>=(ssize_t)sizeof(text)-1||!valid)return 0;text[used]=0;
    long pid;unsigned long long ticks;int consumed=0;
    return sscanf(text,"%ld %llu\n%n",&pid,&ticks,&consumed)==2&&pid>=2&&ticks&&consumed==used&&
        snprintf(canonical,sizeof(canonical),"%ld %llu\n",pid,ticks)==used&&!memcmp(text,canonical,(size_t)used)&&!process_live((pid_t)pid,ticks);
}
static int cleanup_fixture(const char *base){
    if(getuid()||geteuid()||getgid()||getegid())return 2;
    int root=fixture_directory(base);if(root<0)return 3;int result=0;
    if(!fixture_process_dead(root,"run.owner")||!fixture_process_dead(root,"run.child")){close(root);return 3;}
    int source=openat(root,"seeds",O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC);
    if(source>=0){
        if(!platform_seed_directory(source,0)){close(source);close(root);return 3;}
        for(unsigned i=0;i<PLATFORM_SEED_COUNT;++i){
            const char *name=platform_seed_name(i),*expected=i==0?"synthetic-identity\n":i==1?"{}\n":"";struct stat info;
            if(fstatat(source,name,&info,AT_SYMLINK_NOFOLLOW)<0){if(errno!=ENOENT)result=3;continue;}
            if(!equal(source,name,expected)){result=3;continue;}
            if(unlinkat(source,name,0))result=3;
        }
        close(source);if(unlinkat(root,"seeds",AT_REMOVEDIR))result=3;
    }else if(errno!=ENOENT)result=3;
    const char *files[]={"profile.json","host-canary"},*expected[]={"{}\n","synthetic host canary\n"};
    for(unsigned i=0;i<2;++i){struct stat info;if(fstatat(root,files[i],&info,AT_SYMLINK_NOFOLLOW)<0){if(errno!=ENOENT)result=3;continue;}
        if(!equal(root,files[i],expected[i])||unlinkat(root,files[i],0))result=3;}
    const char *directories[]={"root0","root1"};
    for(unsigned i=0;i<2;++i)if(unlinkat(root,directories[i],AT_REMOVEDIR)&&errno!=ENOENT)result=3;
    if(unlinkat(root,"run.owner",0)&&errno!=ENOENT)result=3;
    if(unlinkat(root,"run.child",0)&&errno!=ENOENT)result=3;
    close(root);return result;
}
static int station_selftest(const char *base){
    struct stat info;struct statvfs fs;char compatible[128];
    if(getuid()||geteuid()||getgid()||getegid()||statvfs("/",&fs)||!(fs.f_flag&ST_RDONLY))return 2;
    if(!lstat("/bkupgrade/data/opt/lisa-station/state",&info)||errno!=ENOENT||!lstat("/run/lisa-station",&info)||errno!=ENOENT)return 2;
    int fd=open("/proc/device-tree/compatible",O_RDONLY|O_CLOEXEC);if(fd<0)return 2;
    ssize_t used=read(fd,compatible,sizeof(compatible));close(fd);
    if(used<0||!memmem(compatible,(size_t)used,"yandex,station-midi",19))return 2;
    int rootdir=fixture_directory(base);if(rootdir<0)return 3;
    int mutex=open("/data/opt/lisa-lab/trial.lock",O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC);
    if(mutex<0||!platform_seed_directory(mutex,0)||!equal(mutex,"platform-storage.owner",base)){if(mutex>=0)close(mutex);close(rootdir);return 3;}close(mutex);
    alarm(35);umask(077);signal(SIGPIPE,SIG_IGN);
    pid_t origin=getppid();if(prctl(PR_SET_PDEATHSIG,SIGKILL)||getppid()!=origin)return 3;
    struct process_stamp self;char owner[96];if(process_stamp(getpid(),&self))return 3;
    snprintf(owner,sizeof(owner),"%ld %" PRIu64 "\n",(long)getpid(),self.ticks);if(put(rootdir,"run.owner",owner))return 3;
    char seeds[PATH_MAX],profile[PATH_MAX],canary[PATH_MAX],executable[PATH_MAX];
    snprintf(seeds,sizeof(seeds),"%s/seeds",base);snprintf(profile,sizeof(profile),"%s/profile.json",base);snprintf(canary,sizeof(canary),"%s/host-canary",base);
    if(mkdir(seeds,0700))return 3;
    int source=open(seeds,O_RDONLY|O_DIRECTORY|O_CLOEXEC);
    if(source<0||rootdir<0||prepare_seeds(source)||put(rootdir,"profile.json","{}\n")||put(rootdir,"host-canary","synthetic host canary\n"))return 3;
    ssize_t size=readlink("/proc/self/exe",executable,sizeof(executable)-1);if(size<=0||size>=(ssize_t)sizeof(executable)-1)return 3;executable[size]=0;
    int retained[2]={-1,-1};struct stat epochs[2]={{0}};
    for(unsigned epoch=0;epoch<2;++epoch){
        char root[PATH_MAX];snprintf(root,sizeof(root),"%s/root%u",base,epoch);if(mkdir(root,0700))return 3;
        int reports[2],commands[2];if(pipe2(reports,O_CLOEXEC)||pipe2(commands,O_CLOEXEC))return 3;
        pid_t parent=getpid(),child=fork();if(child<0)return 3;
        if(!child){
            alarm(15);if(prctl(PR_SET_PDEATHSIG,SIGKILL)||getppid()!=parent)_exit(79);
            int keep[]={reports[1],commands[0]};if(guardian_close_except(keep,2))_exit(80);
            int null=open("/dev/null",O_RDWR|O_CLOEXEC);if(null<0)_exit(81);
            for(int i=0;i<3;++i)if(dup2(null,i)<0)_exit(81);
            if(null>2)close(null);
            if(clearenv()||platform_storage_enter(root,seeds,profile,executable)||vendor_identity_prepare(57342)||platform_storage_guard()||
                prctl(PR_SET_PDEATHSIG,SIGKILL)||getppid()!=parent||fcntl(reports[1],F_SETFD,0)||fcntl(commands[0],F_SETFD,0))_exit(82);
            char report[16],control[16];snprintf(report,sizeof(report),"%d",reports[1]);snprintf(control,sizeof(control),"%d",commands[0]);
            char *const args[]={"platform-storage-actor","--actor",report,control,canary,NULL};execv("/system/vendor/quasar/maind",args);_exit(83);
        }
        struct process_stamp spawned;char stamp[96];if(process_stamp(child,&spawned))return 3;
        snprintf(stamp,sizeof(stamp),"%ld %" PRIu64 "\n",(long)child,spawned.ticks);if(put(rootdir,"run.child",stamp))return 3;
        close(reports[1]);close(commands[0]);uint64_t result[2]={0,1};
        int received=guardian_readable(reports[0],10000)&&read(reports[0],result,sizeof(result))==sizeof(result);
        check(received);if(received){checks+=(unsigned)result[0];failures+=(unsigned)result[1];}
        char path[PATH_MAX];snprintf(path,sizeof(path),"/proc/%ld/root/data/quasar",(long)child);
        retained[epoch]=open(path,O_RDONLY|O_DIRECTORY|O_CLOEXEC);check(retained[epoch]>=0&&!fstat(retained[epoch],&epochs[epoch]));
        struct stat host;check(!stat("/data/quasar",&host)&&epochs[epoch].st_dev!=host.st_dev);
        check(private_view(child,&epochs[epoch]));
        check(administrative_control(AF_INET)&&administrative_control(AF_INET6));
        struct stat actual,expected;snprintf(path,sizeof(path),"/proc/%ld/exe",(long)child);
        check(!stat(path,&actual)&&!stat(executable,&expected)&&actual.st_dev==expected.st_dev&&actual.st_ino==expected.st_ino);
        snprintf(path,sizeof(path),"/proc/%ld/root/data/quasar/account_storage.dat",(long)child);
        check(!stat(path,&actual)&&!fstatat(source,"account_storage.dat",&expected,AT_SYMLINK_NOFOLLOW)&&actual.st_dev!=expected.st_dev);

        check(equal(source,"account_storage.dat","synthetic-identity\n")&&equal(source,"gsdkTokens.json","{}\n"));
        if(epoch)check(epochs[0].st_dev!=epochs[1].st_dev&&equal(retained[0],"ephemeral-state","synthetic state\n"));
        if(write(commands[1],"X",1)!=1)check(0);
        close(commands[1]);close(reports[0]);int status;
        check(waitpid(child,&status,0)==child&&WIFEXITED(status)&&WEXITSTATUS(status)==0);
        check(!unlinkat(rootdir,"run.child",0));
        check(!rmdir(root));
        printf("{\"event\":\"platform-storage-epoch\",\"epoch\":%u,\"checks\":%u,\"failures\":%u,\"synthetic_only\":true,\"audio_opened\":false}\n",epoch+1,checks,failures);fflush(stdout);
    }
    for(unsigned i=0;i<2;++i)if(retained[i]>=0)close(retained[i]);
    check(equal(source,"account_storage.dat","synthetic-identity\n")&&equal(source,"gsdkTokens.json","{}\n"));
    close(source);close(rootdir);
    printf("{\"selftest\":\"platform-storage\",\"checks\":%u,\"ok\":%s,\"synthetic_only\":true,\"audio_opened\":false,\"vendor_processes_changed\":false,\"isolation_verified\":false}\n",checks,failures?"false":"true");
    return failures?4:0;
}
#endif
int main(int argc,char **argv){
    if(argc==2&&!strcmp(argv[1],"--selftest"))return seed_selftest();
#ifdef __arm__
    if(argc==5&&!strcmp(argv[1],"--actor")){
        char *end;long report=strtol(argv[2],&end,10);if(*end||report<3||report>1024)return 2;
        long control=strtol(argv[3],&end,10);if(*end||control<3||control>1024||report==control)return 2;
        struct stat a,b;if(fstat((int)report,&a)||fstat((int)control,&b)||!S_ISFIFO(a.st_mode)||!S_ISFIFO(b.st_mode))return 2;
        return actor((int)report,(int)control,argv[4]);
    }
    if(argc==3&&!strcmp(argv[1],"--station-selftest"))return seed_selftest()||station_selftest(argv[2]);
    if(argc==3&&!strcmp(argv[1],"--cleanup"))return cleanup_fixture(argv[2]);
#endif
    return 2;
}
