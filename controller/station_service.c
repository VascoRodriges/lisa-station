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
#include "diagnostics_guard.h"
#include "collector_guard.h"
#include "telemetry_guard.h"
#include "closed_transition.h"
#include "policy_check.h"
#include "composite_roles.h"

#define VENDOR_GID 57342
#define DIAGNOSTICS_GID 57343
#define COLLECTOR_GID 57344
#define TELEMETRY_GID 57345
static int lab;
static unsigned selected_gid=VENDOR_GID;
static char diagnostics_root[PATH_MAX];
static char collector_root[PATH_MAX],collector_profile[PATH_MAX];
static char telemetry_root[PATH_MAX],telemetry_profile[PATH_MAX];

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
    if(selected_gid==DIAGNOSTICS_GID) mask=diagnostics_forbidden_caps();
    if(selected_gid==COLLECTOR_GID||selected_gid==TELEMETRY_GID) mask=UINT64_MAX;
    while (fgets(line,sizeof(line),file)) {
        unsigned a,b,c,d; unsigned long long caps;
        if (sscanf(line,"Gid: %u %u %u %u",&a,&b,&c,&d)==4) {
            gid_seen=1;
            gid=a==selected_gid&&b==selected_gid&&c==selected_gid&&d==selected_gid;
            tagged|=a==selected_gid||b==selected_gid||c==selected_gid||d==selected_gid;
        }
        if (!strncmp(line,"Groups:",7)) {
            char *at=line+7,*end;
            while (*at) {
                unsigned long value=strtoul(at,&end,10);
                if (end==at) break;
                tagged|=value==selected_gid; at=end;
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
        if (process_stamp((pid_t)pid,&stamp)) {
            /* Kernel threads may have zero start ticks. Their readable group
             * status can still classify them; unreadable live actors cannot.
             * Signal 0 checks existence only, never terminates a journal PID. */
            int status=role_status((pid_t)pid,0);
            if(!status || (status<0 && (!kill((pid_t)pid,0) || errno!=ESRCH))) absent=0;
        } else if(stamp.state!='Z' && stamp.state!='X') {
            int status=role_status((pid_t)pid,0);
            if (!status || (status<0 && process_live((pid_t)pid,stamp.ticks))) absent=0;
        }
    }
    closedir(directory); return absent;
}
static int observe_quasar(pid_t pid) { return role_status(pid,1); }
static int observe_diagnostics(pid_t pid) { return role_status(pid,1)||diagnostics_private_view(pid); }
static int observe_collector(pid_t pid) { return role_status(pid,1)||collector_private_view(pid); }
static int observe_telemetry(pid_t pid) { return role_status(pid,1)||telemetry_private_view(pid); }
/* Match only the fixed role flag; never export argv or accept a caller's PID. */
static int epoch_process(pid_t pid,const char *flag) {
    char path[64],exe[PATH_MAX],arguments[4096];
    snprintf(path,sizeof(path),"/proc/%ld/exe",(long)pid);
    ssize_t size=readlink(path,exe,sizeof(exe)-1);
    if(size<0) return -1;
    exe[size]=0; if(strcmp(exe,"/system/vendor/quasar/maind")) return 0;
    snprintf(path,sizeof(path),"/proc/%ld/cmdline",(long)pid);
    int file=open(path,O_RDONLY|O_CLOEXEC);
    if(file<0) return -1;
    size=read(file,arguments,sizeof(arguments)); close(file);
    if(size<=0||size==(ssize_t)sizeof(arguments)||arguments[size-1]) return -1;
    int matches=0;
    for(ssize_t at=0;at<size;at+=(ssize_t)strlen(arguments+at)+1)
        matches+=!strcmp(arguments+at,flag);
    return matches==1?1:matches?-1:0;
}
static int legacy_epoch_clear(const char *flag) {
    DIR *directory=opendir("/proc"); struct dirent *entry; int clear=1;
    if(!directory) return 0;
    for(;;) {
        errno=0; entry=readdir(directory);
        if(!entry) { if(errno) clear=0; break; }
        char *end; long pid=strtol(entry->d_name,&end,10);
        if(*end||pid<2||pid>INT_MAX) continue;
        struct process_stamp stamp;
        if(process_stamp((pid_t)pid,&stamp)||stamp.state=='Z'||stamp.state=='X') continue;
        char path[64],exe[PATH_MAX]; snprintf(path,sizeof(path),"/proc/%ld/exe",pid);
        ssize_t size=readlink(path,exe,sizeof(exe)-1);
        if(size<0) continue;
        exe[size]=0;
        if(!strcmp(exe,"/system/vendor/quasar/maind")&&epoch_process((pid_t)pid,flag)!=0&&
            (!lab||(stamp.state!='T'&&stamp.state!='t'))) clear=0;
    }
    closedir(directory); return clear;
}
static int prepare_epoch(int telemetry) {
    struct rlimit core={0,0},files={1024,1024};
    if(!legacy_epoch_clear(telemetry?"--telemetry":"--fluent-bitd")||clearenv()||setrlimit(RLIMIT_CORE,&core)||setrlimit(RLIMIT_NOFILE,&files)||
        setenv("LD_LIBRARY_PATH","/system/vendor/quasar/libs",1)||
        setenv("CA_CERTIFICATES","/system/vendor/quasar/ca-certificates.crt",1)||
        setenv("PATH","/usr/sbin:/usr/bin:/sbin:/bin",1)||
        (telemetry?telemetry_isolate(telemetry_root,telemetry_profile,"/system/vendor/quasar/maind"):
            collector_isolate(collector_root,collector_profile,"/system/vendor/quasar/maind"))||
        vendor_identity_prepare(telemetry?TELEMETRY_GID:COLLECTOR_GID)||collector_extra_guard()||chdir("/data/quasar")) return -1;
    return 0;
}
static int prepare_collector(void) { return prepare_epoch(0); }
static int prepare_telemetry(void) { return prepare_epoch(1); }

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

static int legacy_diagnostics_clear(void) {
    DIR *directory=opendir("/proc");
    if(!directory) return 0;
    int clear=1; struct dirent *entry;
    for(;;) {
        errno=0; entry=readdir(directory);
        if(!entry) { if(errno) clear=0; break; }
        char *end; long pid=strtol(entry->d_name,&end,10);
        if(*end || pid<2 || pid>INT_MAX) continue;
        struct process_stamp stamp;
        if(process_stamp((pid_t)pid,&stamp) || stamp.state=='Z' || stamp.state=='X') continue;
        char path[64],executable[PATH_MAX]; snprintf(path,sizeof(path),"/proc/%ld/exe",pid);
        ssize_t length=readlink(path,executable,sizeof(executable)-1);
        if(length<0) continue;
        executable[length]=0;
        if(!strcmp(executable,"/usr/bin/alsa-audio-monitord")) clear=0;
    }
    closedir(directory); return clear;
}
static int prepare_diagnostics(void) {
    struct rlimit core={0,0},files={256,256};
    if(!legacy_diagnostics_clear() || clearenv() || chdir("/") || setrlimit(RLIMIT_CORE,&core) ||
        setrlimit(RLIMIT_NOFILE,&files) || setenv("PATH","/usr/sbin:/usr/bin:/sbin:/bin",1) ||
        setenv("DBUS_SYSTEM_BUS_ADDRESS","unix:path=/var/run/dbus/system_bus_socket",1) ||
        diagnostics_isolate(diagnostics_root,"/usr/bin/alsa-audio-monitord") ||
        vendor_identity_prepare(DIAGNOSTICS_GID) || diagnostics_extra_guard()) return -1;
    return 0;
}

struct close_quasar_context {
    int state,runtime,policy_valid;
    const char *boot;
    const struct guardian_spec *spec;
    char chain[32];
};
static int deny_quasar(void *pointer) {
    struct close_quasar_context *context=pointer;
    return context->policy_valid && policy_group_denied(context->chain,selected_gid)?0:-1;
}
static int stop_quasar(void *pointer) {
    struct close_quasar_context *context=pointer;
    if(actors_absent(NULL)) return 0;
    (void)guardian_stop(context->runtime,0,context->boot,context->spec);
    for(unsigned i=0;i<30;++i) {
        if(actors_absent(NULL)) return 0;
        struct timespec delay={0,50000000}; nanosleep(&delay,NULL);
    }
    return -1;
}
static int verify_quasar_closed(void *pointer) {
    return !actors_absent(NULL) || deny_quasar(pointer);
}
static int deny_roles(void *pointer) {
    struct close_quasar_context *context=pointer;
    return context->policy_valid&&policy_groups_denied(context->chain,composite_groups,COMPOSITE_ROLE_COUNT)?0:-1;
}
static int absent_role(void *pointer,unsigned role) {
    (void)pointer; if(role>=COMPOSITE_ROLE_COUNT) return -1;
    unsigned previous=selected_gid; selected_gid=composite_groups[role];
    int absent=actors_absent(NULL); selected_gid=previous; return absent?0:-1;
}
static int stop_role(void *pointer,unsigned role) {
    struct close_quasar_context *context=pointer;
    if(role>=COMPOSITE_ROLE_COUNT) return -1;
    if(!absent_role(pointer,role)) return 0;
    struct guardian_spec spec={.role=composite_names[role]};
    (void)guardian_stop(context->runtime,0,context->boot,&spec);
    for(unsigned i=0;i<30;++i) {
        if(!absent_role(pointer,role)) return 0;
        struct timespec delay={0,50000000}; nanosleep(&delay,NULL);
    }
    return -1;
}

int main(int argc,char **argv) {
    if (geteuid() || argc<2 || argc>3) return 2;
    signal(SIGCHLD,SIG_DFL);
    const char *operation=argv[1];
    lab=!strncmp(operation,"--lab-",6);
    if ((lab&&argc!=3) || (!lab&&argc!=2)) return 2;
    const char *action=operation+(lab?6:2);
    int composite=!strcmp(action,"close-roles")||!strcmp(action,"check-roles-policy");
    int diagnostics=!strcmp(action,"start-diagnostics")||!strcmp(action,"stop-diagnostics")||
        !strcmp(action,"reconcile-diagnostics")||!strcmp(action,"close-diagnostics")||!strcmp(action,"check-diagnostics-policy")||
        !strcmp(action,"inspect-diagnostics");
    int collector=!strcmp(action,"start-collector")||!strcmp(action,"stop-collector")||
        !strcmp(action,"reconcile-collector")||!strcmp(action,"close-collector")||
        !strcmp(action,"check-collector-policy")||!strcmp(action,"inspect-collector");
    int telemetry=!strcmp(action,"start-telemetry")||!strcmp(action,"stop-telemetry")||
        !strcmp(action,"reconcile-telemetry")||!strcmp(action,"close-telemetry")||
        !strcmp(action,"check-telemetry-policy")||!strcmp(action,"inspect-telemetry")||!strcmp(action,"observe-telemetry-close");
    if (strcmp(action,"start-quasar") && strcmp(action,"stop-quasar") && strcmp(action,"reconcile-quasar") &&
        strcmp(action,"start-diagnostics") && strcmp(action,"stop-diagnostics") && strcmp(action,"reconcile-diagnostics") && strcmp(action,"inspect-diagnostics") &&
        strcmp(action,"start-collector") && strcmp(action,"stop-collector") && strcmp(action,"reconcile-collector") && strcmp(action,"inspect-collector") &&
        strcmp(action,"start-telemetry") && strcmp(action,"stop-telemetry") && strcmp(action,"reconcile-telemetry") && strcmp(action,"inspect-telemetry") &&
        (!lab || (strcmp(action,"request-paused") && strcmp(action,"close-quasar") && strcmp(action,"check-quasar-policy") &&
        strcmp(action,"close-diagnostics") && strcmp(action,"check-diagnostics-policy") &&
        strcmp(action,"close-collector") && strcmp(action,"check-collector-policy") &&
        strcmp(action,"close-telemetry") && strcmp(action,"check-telemetry-policy")&&strcmp(action,"observe-telemetry-close")&&
        strcmp(action,"close-roles")&&strcmp(action,"check-roles-policy")))) return 2;
    selected_gid=telemetry?TELEMETRY_GID:collector?COLLECTOR_GID:diagnostics?DIAGNOSTICS_GID:VENDOR_GID;
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
        snprintf(diagnostics_root,sizeof(diagnostics_root),"%s/diagnostics-root",argv[2]);
        snprintf(collector_root,sizeof(collector_root),"%s/collector-root",argv[2]);
        snprintf(collector_profile,sizeof(collector_profile),"%s/collector-profile.json",argv[2]);
        snprintf(telemetry_root,sizeof(telemetry_root),"%s/telemetry-root",argv[2]);
        snprintf(telemetry_profile,sizeof(telemetry_profile),"%s/telemetry-profile.json",argv[2]);
    } else {
        strcpy(state_path,"/bkupgrade/data/opt/lisa-station/state"); strcpy(runtime_path,"/run/lisa-station");
        strcpy(diagnostics_root,"/bkupgrade/data/opt/lisa-station/diagnostics-root");
        strcpy(collector_root,"/bkupgrade/data/opt/lisa-station/collector-root");
        strcpy(collector_profile,"/bkupgrade/data/opt/lisa-station/collector-profile.json");
        strcpy(telemetry_root,"/bkupgrade/data/opt/lisa-station/telemetry-root");
        strcpy(telemetry_profile,"/bkupgrade/data/opt/lisa-station/telemetry-profile.json");
    }
    int state=secure_directory(state_path),runtime=secure_directory(runtime_path);
    enum guardian_result result=GUARD_DENIED; struct guardian_started started={0};
    int diagnostics_live=0,diagnostics_identity=0,diagnostics_view=0,diagnostics_bus=0;
    int batch_materialized=0;
    int control4=0,control6=0;
    char *const args[]={"quasar_launcher2","/system/vendor/quasar/launch.json",NULL};
    char *const diagnostics_args[]={"alsa-audio-monitord","/etc/alsa-audio-diagnostics/devices/yandexmidi.json",
        "/etc/alsa-audio-diagnostics.conf",NULL};
    char *const collector_args[]={"maind","--fluent-bitd",NULL};
    char *const telemetry_args[]={"maind","--telemetry",NULL};
    struct guardian_spec spec={.role="quasar",.executable="/system/vendor/quasar/quasar_launcher2",.argv=args,
        .prepare=prepare_quasar,.observe=observe_quasar,.actors_absent=actors_absent,.maximum_seconds=lab?50:0};
    if(diagnostics) {
        spec.role="diagnostics"; spec.executable="/usr/bin/alsa-audio-monitord"; spec.argv=diagnostics_args;
        spec.prepare=prepare_diagnostics; spec.maximum_seconds=lab?20:0;
        spec.observe=observe_diagnostics;
    }
    if(collector) {
        spec.role="collector"; spec.executable="/system/vendor/quasar/maind"; spec.argv=collector_args;
        spec.prepare=prepare_collector; spec.observe=observe_collector; spec.maximum_seconds=lab?30:0;
    }
    if(telemetry) {
        spec.role="telemetry"; spec.executable="/system/vendor/quasar/maind"; spec.argv=telemetry_args;
        spec.prepare=prepare_telemetry; spec.observe=observe_telemetry; spec.maximum_seconds=lab?45:0;
    }
    if(state>=0&&runtime>=0) {
        if(!strcmp(action,"observe-telemetry-close")) {
            struct guardian_record record; struct gate_lease lease={-1,0}; int allowed=0;
            if(!guardian_read(runtime,0,"telemetry.child",&record)&&record.phase==G_RUNNING&&!strcmp(record.boot,boot)&&
                process_live(record.child,record.child_ticks)&&!observe_telemetry(record.child)&&
                gate_acquire_running(state,runtime,0,boot,&lease)==GATE_GRANTED&&lease.revision==record.revision) allowed=1;
            gate_release(&lease); /* Never block the exclusive close request. */
            int exit_code=allowed?telemetry_observe_close(record.child,record.child_ticks):4;
            close(state); close(runtime); return exit_code;
        }
        if(!strcmp(action,"start-quasar")||!strcmp(action,"start-diagnostics")||!strcmp(action,"start-collector")||!strcmp(action,"start-telemetry")) {
            int jail=telemetry?secure_directory(telemetry_root):collector?secure_directory(collector_root):diagnostics?secure_directory(diagnostics_root):-1;
            if(((diagnostics||collector||telemetry)&&jail<0)||(collector&&!collector_profile_valid(collector_profile))||
                (telemetry&&!collector_profile_valid(telemetry_profile))) result=GUARD_DENIED;
            else if(!(telemetry?legacy_epoch_clear("--telemetry"):collector?legacy_epoch_clear("--fluent-bitd"):
                diagnostics?legacy_diagnostics_clear():legacy_clear())||!actors_absent(NULL)) result=GUARD_BUSY;
            else result=guardian_start(state,runtime,0,boot,&spec,&started);
            if(jail>=0) close(jail);
        } else if(!strcmp(action,"stop-quasar")||!strcmp(action,"stop-diagnostics")||!strcmp(action,"stop-collector")||!strcmp(action,"stop-telemetry")) result=guardian_stop(runtime,0,boot,&spec);
        else if(!strcmp(action,"reconcile-quasar")||!strcmp(action,"reconcile-diagnostics")||!strcmp(action,"reconcile-collector")||!strcmp(action,"reconcile-telemetry")) result=guardian_reconcile_closed(state,runtime,0,boot,&spec);
        else if(!strcmp(action,"inspect-diagnostics")||!strcmp(action,"inspect-collector")||!strcmp(action,"inspect-telemetry")) {
            struct guardian_record record; struct gate_lease lease={-1,0};
            if(!guardian_read(runtime,0,telemetry?"telemetry.child":collector?"collector.child":"diagnostics.child",&record)&&record.phase==G_RUNNING&&!strcmp(record.boot,boot)) {
                started.record=record;
                diagnostics_live=process_live(record.child,record.child_ticks);
                if(diagnostics_live) {
                    diagnostics_identity=!role_status(record.child,1);
                    diagnostics_view=!(telemetry?telemetry_private_view(record.child):collector?collector_private_view(record.child):diagnostics_private_view(record.child));
                    diagnostics_bus=telemetry?telemetry_runtime_private(record.child,&batch_materialized):
                        collector?collector_runtime_private(record.child):diagnostics_unix_connected(record.child);
                }
                if(diagnostics_live&&diagnostics_identity&&diagnostics_view&&diagnostics_bus&&
                    gate_acquire_running(state,runtime,0,boot,&lease)==GATE_GRANTED&&lease.revision==record.revision&&
                    process_live(record.child,record.child_ticks)) result=GUARD_OK;
            }
            gate_release(&lease);
        }
        else if(!strcmp(action,"close-quasar") || !strcmp(action,"check-quasar-policy") ||
            !strcmp(action,"close-diagnostics") || !strcmp(action,"check-diagnostics-policy") ||
            !strcmp(action,"close-collector") || !strcmp(action,"check-collector-policy") ||
            !strcmp(action,"close-telemetry") || !strcmp(action,"check-telemetry-policy") || composite) {
            struct mode_record current; struct close_record pending;
            struct close_quasar_context context={.state=state,.runtime=runtime,.boot=boot,.spec=&spec};
            context.policy_valid=!policy_chain_read(runtime,0,context.chain,sizeof(context.chain));
            if(!strcmp(action,"check-quasar-policy")||!strcmp(action,"check-diagnostics-policy")||!strcmp(action,"check-collector-policy")||!strcmp(action,"check-telemetry-policy")||!strcmp(action,"check-roles-policy")) {
                result=(composite?deny_roles(&context):deny_quasar(&context))?GUARD_FAILED:GUARD_OK;
                if(result==GUARD_OK) {
                    control4=policy_control_socket(AF_INET); control6=policy_control_socket(AF_INET6);
                    if(!control4 || !control6) result=GUARD_FAILED;
                }
            }
            else if(mode_store_read(state,0,&current)==STORE_OK) {
                uint64_t base=current.revision;
                if(!close_read(state,0,&pending)) base=pending.base_revision;
                struct composite_roles roles={deny_roles,stop_role,absent_role,&context};
                struct close_ops ops={composite?composite_deny:deny_quasar,composite?composite_stop:stop_quasar,
                    composite?composite_verify:verify_quasar_closed,NULL,composite?(void*)&roles:(void*)&context};
                enum close_result closed=close_execute(state,runtime,0,base,LISA_MODE_PAUSED,&ops);
                result=closed==CLOSE_OK?GUARD_OK:closed==CLOSE_BUSY?GUARD_BUSY:GUARD_FAILED;
                if(result==GUARD_OK) started.record.revision=base+1;
            }
        }
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
    struct close_record closed_record;
    const char *phase=state>=0&&!close_read(state,0,&closed_record)?close_phase_name(closed_record.phase):"none";
    printf("{\"event\":\"station-service\",\"operation\":\"%s\",\"result\":\"%s\",\"guardian_pid\":%ld,"
        "\"child_pid\":%ld,\"revision\":%" PRIu64 ",\"transition_phase\":\"%s\",\"diagnostics_jail_verified\":%s,"
        "\"collector_jail_verified\":%s,\"telemetry_jail_verified\":%s,\"telemetry_batch_materialized\":%s,\"telemetry_batch_paths\":%u,\"closed_scope\":\"%s\","
        "\"inspection_live\":%s,\"inspection_identity\":%s,\"inspection_view\":%s,\"inspection_resources\":%s,\"isolation_verified\":false}\n",action,names[result],
        (long)started.record.guardian,(long)started.record.child,started.record.revision,phase,
        diagnostics&&result==GUARD_OK&&(!strcmp(action,"start-diagnostics")||!strcmp(action,"inspect-diagnostics"))?"true":"false",
        collector&&result==GUARD_OK&&(!strcmp(action,"start-collector")||!strcmp(action,"inspect-collector"))?"true":"false",
        telemetry&&result==GUARD_OK&&(!strcmp(action,"start-telemetry")||!strcmp(action,"inspect-telemetry"))?"true":"false",batch_materialized?"true":"false",(unsigned)batch_materialized,composite?"guarded_roles":"single_role",
        diagnostics_live?"true":"false",diagnostics_identity?"true":"false",diagnostics_view?"true":"false",diagnostics_bus?"true":"false");
    if((!strcmp(action,"check-quasar-policy")||!strcmp(action,"check-diagnostics-policy")||!strcmp(action,"check-collector-policy")||!strcmp(action,"check-telemetry-policy")||!strcmp(action,"check-roles-policy")) && result==GUARD_OK)
        printf("{\"event\":\"policy-controls\",\"ipv4\":%s,\"ipv6\":%s}\n",control4?"true":"false",control6?"true":"false");
    if(state>=0) close(state);
    if(runtime>=0) close(runtime);
    return result==GUARD_OK?0:4;
}
