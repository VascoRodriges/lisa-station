/* Fixed quasar startup/stop backend. No shell, arbitrary PID, path or command.
 * Default production paths fail closed until a trusted controller installs and
 * authorizes state/permits. Lab commands require a bounded administrative trial.
 */
#define _GNU_SOURCE
#include <dirent.h>
#include <grp.h>
#include <linux/audit.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <stddef.h>
#include <sys/syscall.h>
#include "startup_guardian.h"
#include "vendor_identity.h"

#define VENDOR_GID 57342
static int lab;

static int secure_directory(const char *path) {
    if (*path!='/') return -1;
    char text[PATH_MAX];
    if (strlen(path)>=sizeof(text)) return -1;
    strcpy(text,path);
    int parent=open("/",O_RDONLY|O_DIRECTORY|O_CLOEXEC);
    if (parent<0) return -1;
    char *save=NULL,*part=strtok_r(text,"/",&save);
    while (part) {
        if (!strcmp(part,".") || !strcmp(part,"..")) { close(parent); return -1; }
        int next=openat(parent,part,O_RDONLY|O_DIRECTORY|O_CLOEXEC|O_NOFOLLOW);
        close(parent); parent=next;
        struct stat info;
        if (parent<0 || fstat(parent,&info) || info.st_uid || (info.st_mode&0022)) {
            if(parent>=0) close(parent); return -1;
        }
        part=strtok_r(NULL,"/",&save);
    }
    if (!store_directory_valid(parent,0)) { close(parent); return -1; }
    return parent;
}

static int role_status(pid_t pid,int strict) {
    char path[64],line[256]; snprintf(path,sizeof(path),"/proc/%ld/status",(long)pid);
    FILE *file=fopen(path,"r");
    if (!file) return -1;
    int gid=0,gid_seen=0,tagged=0,uid=0,seccomp=0,cap_fields=0,bad=0;
    unsigned long long mask=(1ull<<CAP_NET_ADMIN)|(1ull<<CAP_NET_RAW)|(1ull<<CAP_SYS_PTRACE);
    while (fgets(line,sizeof(line),file)) {
        unsigned a,b,c,d; unsigned long long caps;
        if (sscanf(line,"Gid: %u %u %u %u",&a,&b,&c,&d)==4) {
            gid_seen=1;
            gid=a==VENDOR_GID&&b==VENDOR_GID&&c==VENDOR_GID&&d==VENDOR_GID;
            tagged|=a==VENDOR_GID||b==VENDOR_GID||c==VENDOR_GID||d==VENDOR_GID;
        }
        if (!strncmp(line,"Groups:",7)) {
            char *at=line+7,*end;
            while (*at) {
                unsigned long value=strtoul(at,&end,10);
                if (end==at) break;
                tagged|=value==VENDOR_GID; at=end;
            }
        }
        if (sscanf(line,"Uid: %u %u %u %u",&a,&b,&c,&d)==4) uid=!a&&!b&&!c&&!d;
        if (sscanf(line,"Seccomp: %u",&a)==1) seccomp=a==2;
        if (sscanf(line,"CapEff: %llx",&caps)==1 || sscanf(line,"CapPrm: %llx",&caps)==1 ||
            sscanf(line,"CapInh: %llx",&caps)==1 || sscanf(line,"CapBnd: %llx",&caps)==1) {
            ++cap_fields; bad|=!!(caps&mask);
        }
    }
    int unreadable=ferror(file)||!gid_seen;
    fclose(file);
    if(unreadable) return -1;
    return strict ? !(gid&&uid&&seccomp&&cap_fields==4&&!bad) : !tagged;
}

static int actors_absent(const struct guardian_record *record) {
    (void)record;
    DIR *directory=opendir("/proc");
    if (!directory) return 0;
    int absent=1; struct dirent *entry;
    for (;;) {
        errno=0; entry=readdir(directory);
        if(!entry) { if(errno) absent=0; break; }
        char *end; long pid=strtol(entry->d_name,&end,10);
        if (*end || pid<2 || pid>INT_MAX) continue;
        struct process_stamp stamp;
        if (!process_stamp((pid_t)pid,&stamp) && stamp.state!='Z' && stamp.state!='X') {
            int status=role_status((pid_t)pid,0);
            if (!status || (status<0 && process_live((pid_t)pid,stamp.ticks))) absent=0;
        }
    }
    closedir(directory); return absent;
}
static int observe_quasar(pid_t pid) { return role_status(pid,1); }

static int legacy_clear(void) {
    DIR *directory=opendir("/proc");
    if (!directory) return 0;
    int clear=1; struct dirent *entry;
    for (;;) {
        errno=0; entry=readdir(directory);
        if(!entry) { if(errno) clear=0; break; }
        char *end; long pid=strtol(entry->d_name,&end,10);
        if (*end || pid<2 || pid>INT_MAX) continue;
        struct process_stamp stamp;
        if (process_stamp((pid_t)pid,&stamp) || stamp.state=='Z' || stamp.state=='X') continue;
        char path[64],executable[PATH_MAX]; snprintf(path,sizeof(path),"/proc/%ld/exe",pid);
        ssize_t length=readlink(path,executable,sizeof(executable)-1);
        if (length<0) continue;
        executable[length]=0;
        if (!strcmp(executable,"/system/vendor/quasar/maind")) clear=0;
        if (!strcmp(executable,"/system/vendor/quasar/quasar_launcher2") &&
            (!lab || (stamp.state!='T' && stamp.state!='t'))) clear=0;
    }
    closedir(directory); return clear;
}

static int prepare_quasar(void) {
    struct rlimit files={10240,10240},stack={1024*1024,1024*1024};
    if (!legacy_clear() || clearenv() || chdir("/data/quasar") ||
        setrlimit(RLIMIT_NOFILE,&files) || setrlimit(RLIMIT_STACK,&stack) ||
        setenv("CA_CERTIFICATES","/system/vendor/quasar/ca-certificates.crt",1) ||
        setenv("LD_LIBRARY_PATH","/system/vendor/quasar/libs",1) ||
        setenv("GST_PLUGIN_PATH","/system/vendor/quasar/libs",1) ||
        setenv("PATH","/system/vendor/quasar:/usr/sbin:/usr/bin:/sbin:/bin",1)) return -1;
    return vendor_identity_prepare(VENDOR_GID);
}

int main(int argc,char **argv) {
    if (geteuid() || argc<2 || argc>3) return 2;
    signal(SIGCHLD,SIG_DFL);
    const char *operation=argv[1];
    lab=!strncmp(operation,"--lab-",6);
    if ((lab&&argc!=3) || (!lab&&argc!=2)) return 2;
    const char *action=operation+(lab?6:2);
    if (strcmp(action,"start-quasar") && strcmp(action,"stop-quasar") && strcmp(action,"reconcile-quasar") &&
        (!lab || strcmp(action,"request-paused"))) return 2;
    int fd=open("/proc/device-tree/compatible",O_RDONLY|O_CLOEXEC);
    char compatible[512]; ssize_t size=fd>=0?read(fd,compatible,sizeof(compatible)):-1;
    if(fd>=0) close(fd);
    int supported=0; const char model[]="yandex,station-midi";
    for(ssize_t i=0;i+(ssize_t)sizeof(model)<=size;++i)
        if ((!i||!compatible[i-1])&&!memcmp(compatible+i,model,sizeof(model))) supported=1;
    if(!supported) return 3;
    char boot[38]; fd=open("/proc/sys/kernel/random/boot_id",O_RDONLY|O_CLOEXEC);
    size=fd>=0?read(fd,boot,sizeof(boot)):-1; if(fd>=0) close(fd);
    if(size!=37||boot[36]!='\n') return 3;
    boot[36]=0; if(!gate_boot_valid(boot)) return 3;
    char state_path[PATH_MAX],runtime_path[PATH_MAX];
    if(lab) {
        const char prefix[]="/bkupgrade/data/opt/lisa-controller-lab/guardian-startup.";
        size_t length=strlen(argv[2]);
        if(length<strlen(prefix)+6 || length>strlen(prefix)+16 || strncmp(argv[2],prefix,strlen(prefix))) return 2;
        const char *suffix=argv[2]+strlen(prefix);
        for(const char *c=suffix;*c;++c) if(!((*c>='a'&&*c<='z')||(*c>='A'&&*c<='Z')||(*c>='0'&&*c<='9'))) return 2;
        int trial=secure_directory("/bkupgrade/data/opt/lisa-lab/trial.lock");
        if(trial<0) return 3;
        close(trial);
        snprintf(state_path,sizeof(state_path),"%s/state",argv[2]);
        snprintf(runtime_path,sizeof(runtime_path),"%s/run",argv[2]);
    } else {
        strcpy(state_path,"/bkupgrade/data/opt/lisa-station/state"); strcpy(runtime_path,"/run/lisa-station");
    }
    int state=secure_directory(state_path),runtime=secure_directory(runtime_path);
    enum guardian_result result=GUARD_DENIED; struct guardian_started started={0};
    char *const args[]={"quasar_launcher2","/system/vendor/quasar/launch.json",NULL};
    struct guardian_spec spec={.role="quasar",.executable="/system/vendor/quasar/quasar_launcher2",.argv=args,
        .prepare=prepare_quasar,.observe=observe_quasar,.actors_absent=actors_absent,.maximum_seconds=lab?50:0};
    if(state>=0&&runtime>=0) {
        if(!strcmp(action,"start-quasar")) {
            if(!legacy_clear()||!actors_absent(NULL)) result=GUARD_BUSY;
            else result=guardian_start(state,runtime,0,boot,&spec,&started);
        } else if(!strcmp(action,"stop-quasar")) result=guardian_stop(runtime,0,boot,&spec);
        else if(!strcmp(action,"reconcile-quasar")) result=guardian_reconcile_closed(state,runtime,0,boot,&spec);
        else {
            struct mode_record current,next;
            if(mode_store_read(state,0,&current)==STORE_OK) {
                enum store_result changed=mode_store_request(state,0,current.revision,LISA_MODE_PAUSED,&next);
                result=changed==STORE_OK?GUARD_OK:changed==STORE_BUSY?GUARD_BUSY:GUARD_FAILED;
                if(result==GUARD_OK) started.record.revision=next.revision;
            }
        }
    }
    const char *names[]={"ok","denied","busy","recovery_required","failed"};
    printf("{\"event\":\"station-service\",\"operation\":\"%s\",\"result\":\"%s\",\"guardian_pid\":%ld,"
        "\"child_pid\":%ld,\"revision\":%" PRIu64 ",\"isolation_verified\":false}\n",action,names[result],
        (long)started.record.guardian,(long)started.record.child,started.record.revision);
    if(state>=0) close(state);
    if(runtime>=0) close(runtime);
    return result==GUARD_OK?0:4;
}
