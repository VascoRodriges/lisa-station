/* Synthetic mapped LMDB/batch lifecycle inside the telemetry view. No vendor
 * service, old queue contents, microphone or real log payload is touched. */
#define _GNU_SOURCE
#include <grp.h>
#include <pwd.h>
#include <linux/audit.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <stddef.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include "startup_guardian.h"
#include "vendor_identity.h"
#include "telemetry_guard.h"

static unsigned checks,failed; static uint64_t mask;
static void check(int ok) { if(!ok&&checks<64) mask|=1ull<<checks; ++checks; failed+=!ok; }
static int receive(int control,char expected) {
    struct pollfd ready={control,POLLIN,0}; char command;
    return poll(&ready,1,4000)==1&&read(control,&command,1)==1&&command==expected;
}
static int actor(int report,int control) {
    struct stat info; struct statvfs fs;
    if(!stat("/proc/self",&info)||errno!=ENOENT) return 3;
    check(getuid()==0&&geteuid()==0&&getgid()==57345&&getegid()==57345);
    struct passwd *user=getpwuid(0); check(user&&user->pw_gid==57345);
    check(prctl(PR_GET_NO_NEW_PRIVS,0,0,0,0)==1);
    struct __user_cap_header_struct header={_LINUX_CAPABILITY_VERSION_3,0}; struct __user_cap_data_struct caps[2];
    check(!syscall(SYS_capget,&header,caps)&&!(caps[0].effective|caps[0].permitted|caps[0].inheritable|
        caps[1].effective|caps[1].permitted|caps[1].inheritable));
    check(prctl(PR_CAPBSET_READ,CAP_SYS_ADMIN,0,0,0)==0);
    check(!statvfs("/data/quasar",&fs)&&(fs.f_flag&ST_RDONLY));
    check(!statvfs("/data/quasar/appmetrica",&fs)&&!(fs.f_flag&ST_RDONLY)&&(fs.f_flag&ST_NOEXEC));
    struct stat tmp,app;
    check(!stat("/tmp",&tmp)&&!stat("/data/quasar/appmetrica",&app)&&tmp.st_dev==app.st_dev);
    const char *hidden[]={"/tmp/teleme3d","/tmp/messages.0","/proc/1/root","/sys","/dev/snd","/bkupgrade"};
    for(unsigned i=0;i<sizeof(hidden)/sizeof(hidden[0]);++i) check(lstat(hidden[i],&info)==-1&&errno==ENOENT);
    check(!mkdir("/tmp/lisa-telemetry/lmdb",0700));
    int db=open("/tmp/lisa-telemetry/lmdb/data.mdb",O_RDWR|O_CREAT|O_EXCL|O_CLOEXEC,0600);
    if(db<0||ftruncate(db,4096)) return 3;
    void *mapping=mmap(NULL,4096,PROT_READ|PROT_WRITE,MAP_SHARED,db,0); close(db);
    check(mapping!=MAP_FAILED);
    int log=open("/tmp/lisa-telemetry/telemetry.log",O_RDWR|O_CREAT|O_EXCL|O_CLOEXEC,0600); check(log>=0);
    int legacy=open("/data/quasar/appmetrica/persistedBatch",O_WRONLY|O_CREAT|O_EXCL|O_CLOEXEC,0600);
    check(legacy>=0); if(legacy>=0) close(legacy);
    struct stat alias;
    check(!stat("/tmp/lisa-telemetry/appmetrica/persistedBatch",&alias)&&alias.st_dev==tmp.st_dev);
    uint64_t result[]={checks,failed,mask};
    if(write(report,result,sizeof(result))!=sizeof(result)||!receive(control,'B')) return 4;
    int batch=open("/tmp/lisa-telemetry/persistedBatch",O_WRONLY|O_CREAT|O_EXCL|O_CLOEXEC,0600);
    if(batch<0||store_write_all(batch,"synthetic-batch\n",16)||close(batch)||write(report,"B",1)!=1||!receive(control,'U')) return 4;
    if(mapping==MAP_FAILED||munmap(mapping,4096)||write(report,"U",1)!=1||!receive(control,'X')) return 4;
    if(log>=0) close(log);
    return failed?4:0;
}
int main(int argc,char **argv) {
    if(geteuid()) return 2;
    if(argc==4&&!strcmp(argv[1],"--actor")) {
        char *end; long report=strtol(argv[2],&end,10); if(*end||report<3||report>1024) return 2;
        long control=strtol(argv[3],&end,10); if(*end||control<3||control>1024||report==control) return 2;
        return actor((int)report,(int)control);
    }
    if(argc!=2||strcmp(argv[1],"--selftest")) return 2;
    alarm(25); umask(077); signal(SIGPIPE,SIG_IGN);
    char base[]="/data/opt/lisa-controller-lab/telemetry-guard.XXXXXX",root[PATH_MAX],profile[PATH_MAX],executable[PATH_MAX];
    if(!mkdtemp(base)||snprintf(root,sizeof(root),"%s/root",base)>=(int)sizeof(root)||mkdir(root,0700)||
        snprintf(profile,sizeof(profile),"%s/profile.json",base)>=(int)sizeof(profile)) return 3;
    int file=open(profile,O_WRONLY|O_CREAT|O_EXCL|O_CLOEXEC,0600);
    if(file<0||store_write_all(file,"{}\n",3)||close(file)) return 3;
    ssize_t size=readlink("/proc/self/exe",executable,sizeof(executable)-1);
    if(size<=0||size>=(ssize_t)sizeof(executable)-1) return 3;
    executable[size]=0;
    int output[2],commands[2]; if(pipe2(output,O_CLOEXEC)||pipe2(commands,O_CLOEXEC)) return 3;
    pid_t parent=getpid(),child=fork();
    if(!child) {
        alarm(20); if(prctl(PR_SET_PDEATHSIG,SIGKILL)||getppid()!=parent) _exit(79);
        close(output[0]); close(commands[1]); int keep[]={output[1],commands[0]};
        if(guardian_close_except(keep,2)) _exit(80);
        int null=open("/dev/null",O_RDWR|O_CLOEXEC);
        if(null<0) _exit(81);
        for(int fd=0;fd<3;++fd) if(dup2(null,fd)<0) _exit(81);
        if(null>2) close(null);
        if(clearenv()||telemetry_isolate(root,profile,executable)||vendor_identity_prepare(57345)||collector_extra_guard()||
            prctl(PR_SET_PDEATHSIG,SIGKILL)||getppid()!=parent||fcntl(output[1],F_SETFD,0)||fcntl(commands[0],F_SETFD,0)) _exit(82);
        char report[16],control[16]; snprintf(report,sizeof(report),"%d",output[1]); snprintf(control,sizeof(control),"%d",commands[0]);
        char *const args[]={"telemetry-guard-actor","--actor",report,control,NULL};
        execv("/system/vendor/quasar/maind",args); _exit(83);
    }
    close(output[1]); close(commands[0]); if(child<2) return 3;
    uint64_t result[3]={0,1,0}; int materialized=0;
    if(guardian_readable(output[0],8000)&&read(output[0],result,sizeof(result))==sizeof(result)) {
        mask|=result[2]<<checks; checks+=(unsigned)result[0]; failed+=(unsigned)result[1];
        check(!telemetry_private_view(child));
        check(telemetry_runtime_private(child,&materialized)&&!materialized);
        if(write(commands[1],"B",1)!=1) check(0);
        char reply=0; check(guardian_readable(output[0],4000)&&read(output[0],&reply,1)==1&&reply=='B');
        check(telemetry_runtime_private(child,&materialized)&&materialized);
        if(write(commands[1],"U",1)!=1) check(0);
        check(guardian_readable(output[0],4000)&&read(output[0],&reply,1)==1&&reply=='U');
        check(!telemetry_runtime_private(child,&materialized));
    } else check(0);
    int observation[2]; pid_t observer=-1; struct process_stamp stamp;
    if(!pipe2(observation,O_CLOEXEC)&&!process_stamp(child,&stamp)) {
        observer=fork();
        if(!observer) {
            close(observation[0]); close(commands[1]); close(output[0]);
            if(dup2(observation[1],STDOUT_FILENO)<0) _exit(4);
            close(observation[1]);
            int result=telemetry_observe_close(child,stamp.ticks); fflush(stdout); _exit(result);
        }
        close(observation[1]);
    }
    char ready[256]={0}; ssize_t received=0;
    if(observer>1&&guardian_readable(observation[0],4000)) received=read(observation[0],ready,sizeof(ready)-1);
    check(received>0&&strstr(ready,"telemetry-observer-ready"));
    if(write(commands[1],"X",1)!=1) check(0);
    close(commands[1]); close(output[0]); int status;
    check(waitpid(child,&status,0)==child&&WIFEXITED(status)&&WEXITSTATUS(status)==0);
    char final[512]={0}; received=0;
    if(observer>1&&guardian_readable(observation[0],4000)) received=read(observation[0],final,sizeof(final)-1);
    check(received>0&&strstr(final,"\"actor_stopped\":true")&&strstr(final,"\"observer_fds_closed\":true")&&
        strstr(final,"\"batch_materialized\":true")&&strstr(final,"\"batch_paths\":1")&&strstr(final,"\"payload_read\":false"));
    if(observer>1) {
        close(observation[0]);
        check(waitpid(observer,&status,0)==observer&&WIFEXITED(status)&&WEXITSTATUS(status)==0);
    } else check(0);
    check(!rmdir(root)&&!unlink(profile)&&!rmdir(base));
    printf("{\"selftest\":\"telemetry-guard\",\"checks\":%u,\"ok\":%s,\"failure_mask\":\"%016" PRIx64 "\","
        "\"synthetic_epoch_only\":true,\"audio_opened\":false,\"vendor_processes_changed\":false}\n",checks,failed?"false":"true",mask);
    return failed?4:0;
}
