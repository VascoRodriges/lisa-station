/* Own-ELF post-exec jail test. No stock daemon changes, log reads or audio IO. */
#define _GNU_SOURCE
#include <grp.h>
#include <linux/audit.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <stddef.h>
#include <sys/syscall.h>
#include "startup_guardian.h"
#include "vendor_identity.h"
#include "collector_guard.h"

static unsigned checks,failed;
static uint64_t failure_mask;
static void check(int ok) { if(!ok&&checks<64) failure_mask|=1ull<<checks; ++checks; failed+=!ok; }
static int actor(int report,int control) {
    struct stat info; struct statvfs fs;
    if(!stat("/proc/self",&info)||errno!=ENOENT) return 3;
    check(!statvfs("/",&fs)&&(fs.f_flag&ST_RDONLY));
    check(!statvfs("/data/quasar",&fs)&&(fs.f_flag&ST_RDONLY));
    check(!statvfs("/tmp",&fs)&&!(fs.f_flag&ST_RDONLY)&&(fs.f_flag&ST_NOEXEC));
    check(getuid()==0&&geteuid()==0&&getgid()==57344&&getegid()==57344);
    check(prctl(PR_GET_NO_NEW_PRIVS,0,0,0,0)==1);
    struct __user_cap_header_struct header={_LINUX_CAPABILITY_VERSION_3,0}; struct __user_cap_data_struct caps[2];
    check(!syscall(SYS_capget,&header,caps)&&!(caps[0].effective|caps[0].permitted|caps[0].inheritable|
        caps[1].effective|caps[1].permitted|caps[1].inheritable));
    const int bits[]={CAP_SYS_ADMIN,CAP_SYS_CHROOT,CAP_DAC_OVERRIDE,CAP_SETUID,CAP_SETGID,CAP_SYS_PTRACE,CAP_NET_RAW};
    for(unsigned i=0;i<sizeof(bits)/sizeof(bits[0]);++i) check(prctl(PR_CAPBSET_READ,bits[i],0,0,0)==0);
    const int allowed[]={AF_UNIX,AF_INET,AF_INET6};
    for(unsigned i=0;i<3;++i) { int fd=socket(allowed[i],SOCK_STREAM|SOCK_CLOEXEC,0); check(fd>=0); if(fd>=0) close(fd); }
    const int denied[]={AF_NETLINK,AF_PACKET};
    for(unsigned i=0;i<2;++i) { errno=0; int fd=socket(denied[i],SOCK_DGRAM,0); check(fd<0&&errno==EPERM); if(fd>=0) close(fd); }
    errno=0; check(chroot(".")==-1&&errno==EPERM);
    errno=0; check(syscall(SYS_syslog,10,NULL,0)==-1&&errno==EPERM);
    errno=0; check(unshare(CLONE_NEWNS)==-1&&errno==EPERM);
    const char *hidden[]={"/proc/1/root/tmp/messages","/proc/self/fd","/sys","/dev/snd","/dev/log",
        "/bkupgrade/data","/tmp/fluent-bit.db","/tmp/teleme3d"};
    for(unsigned i=0;i<sizeof(hidden)/sizeof(hidden[0]);++i) check(lstat(hidden[i],&info)==-1&&errno==ENOENT);
    struct stat a,b;
    check(!stat("/tmp/messages",&a)&&!stat("/var/log/messages",&b)&&a.st_size==0&&a.st_ino==b.st_ino&&a.st_dev==b.st_dev);
    /* Private rotation/replacement cannot expose the host log after rename. */
    check(!rename("/tmp/messages","/tmp/messages.0"));
    int fd=open("/tmp/messages",O_WRONLY|O_CREAT|O_EXCL|O_CLOEXEC,0600);
    check(fd>=0); if(fd>=0) close(fd);
    check(!stat("/var/log/messages",&b)&&b.st_size==0&&b.st_ino!=a.st_ino);
    fd=open("/tmp/lisa-collector/tail.db",O_WRONLY|O_CREAT|O_EXCL|O_CLOEXEC,0600);
    const char text[]="synthetic-epoch\n";
    check(fd>=0&&!store_write_all(fd,text,sizeof(text)-1)); if(fd>=0) close(fd);
    check(!rename("/tmp/lisa-collector/tail.db","/tmp/lisa-collector/tail.db-wal"));
    check(!unlink("/tmp/lisa-collector/tail.db-wal"));
    int queue=open("/tmp/lisa-collector/tail.db",O_RDWR|O_CREAT|O_EXCL|O_CLOEXEC,0600);
    int log=open("/tmp/lisa-collector/collector.log",O_RDWR|O_CREAT|O_EXCL|O_CLOEXEC,0600);
    check(queue>=0&&log>=0);
    uint64_t result[]={checks,failed,failure_mask};
    if(write(report,result,sizeof(result))!=sizeof(result)) return 4;
    struct pollfd ready={control,POLLIN,0}; char command;
    int ok=poll(&ready,1,4000)==1&&read(control,&command,1)==1&&command=='X'&&!failed;
    if(queue>=0) close(queue);
    if(log>=0) close(log);
    return ok?0:4;
}
int main(int argc,char **argv) {
    if(geteuid()) return 2;
    if(argc==4&&!strcmp(argv[1],"--actor")) {
        char *end; long report=strtol(argv[2],&end,10); if(*end||report<3||report>1024) return 2;
        long control=strtol(argv[3],&end,10); if(*end||control<3||control>1024||report==control) return 2;
        return actor((int)report,(int)control);
    }
    if(argc!=2||strcmp(argv[1],"--selftest")) return 2;
    alarm(20); umask(077); signal(SIGPIPE,SIG_IGN);
    char base[]="/data/opt/lisa-controller-lab/collector-guard.XXXXXX",root[PATH_MAX],profile[PATH_MAX],executable[PATH_MAX];
    if(!mkdtemp(base)||snprintf(root,sizeof(root),"%s/root",base)>=(int)sizeof(root)||mkdir(root,0700)||
        snprintf(profile,sizeof(profile),"%s/profile.json",base)>=(int)sizeof(profile)) return 3;
    int fd=open(profile,O_WRONLY|O_CREAT|O_EXCL|O_CLOEXEC,0600);
    if(fd<0||store_write_all(fd,"{}\n",3)||close(fd)) return 3;
    check(collector_profile_valid(profile));
    check(!collector_runtime_private(getpid()));
    check(!chmod(profile,0644)&&!collector_profile_valid(profile));
    if(chmod(profile,0600)) return 3;
    ssize_t size=readlink("/proc/self/exe",executable,sizeof(executable)-1);
    if(size<=0||size>=(ssize_t)sizeof(executable)-1) return 3;
    executable[size]=0;
    int channel[2],commands[2]; if(pipe2(channel,O_CLOEXEC)||pipe2(commands,O_CLOEXEC)) return 3;
    pid_t parent=getpid(),child=fork();
    if(!child) {
        alarm(15); if(prctl(PR_SET_PDEATHSIG,SIGKILL)||getppid()!=parent) _exit(79);
        close(channel[0]); close(commands[1]); int keep[]={channel[1],commands[0]};
        if(guardian_close_except(keep,2)) _exit(80);
        int null=open("/dev/null",O_RDWR|O_CLOEXEC);
        if(null<0) _exit(81);
        for(int number=0;number<3;++number) if(dup2(null,number)<0) _exit(81);
        if(null>2) close(null);
        if(clearenv()||collector_isolate(root,profile,executable)||vendor_identity_prepare(57344)||collector_extra_guard()||
            prctl(PR_SET_PDEATHSIG,SIGKILL)||getppid()!=parent||fcntl(channel[1],F_SETFD,0)||fcntl(commands[0],F_SETFD,0)) _exit(82);
        char report[16],control[16]; snprintf(report,sizeof(report),"%d",channel[1]); snprintf(control,sizeof(control),"%d",commands[0]);
        char *const args[]={"collector-guard-actor","--actor",report,control,NULL};
        execv("/system/vendor/quasar/maind",args); _exit(83);
    }
    close(channel[1]); close(commands[0]); if(child<2) return 3;
    uint64_t result[3]={0,1,0};
    if(guardian_readable(channel[0],8000)&&read(channel[0],result,sizeof(result))==sizeof(result)) {
        failure_mask|=result[2]<<checks; checks+=(unsigned)result[0]; failed+=(unsigned)result[1]; check(!collector_private_view(child));
        check(collector_runtime_private(child));
    } else check(0);
    if(write(commands[1],"X",1)!=1) check(0);
    close(commands[1]); close(channel[0]); int status;
    check(waitpid(child,&status,0)==child&&WIFEXITED(status)&&WEXITSTATUS(status)==0);
    check(!rmdir(root)&&!unlink(profile)&&!rmdir(base));
    printf("{\"selftest\":\"collector-guard\",\"checks\":%u,\"ok\":%s,\"audio_opened\":false,"
        "\"vendor_processes_changed\":false,\"synthetic_epoch_only\":true,\"failure_mask\":\"%016" PRIx64 "\"}\n",checks,failed?"false":"true",failure_mask);
    return failed?4:0;
}
