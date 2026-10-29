/* Closed bootstrap coordinator. No Alice permit publication, stock fallback,
 * firmware/init write or device-wide ban. Other boot handlers follow separately. */
#define _GNU_SOURCE
#include <sys/statvfs.h>
#include "boot_ledger.h"
#include "relay_resources.h"

static int boot_directory(const char *path) {
    char copy[PATH_MAX]; if(!path||path[0]!='/'||strlen(path)>=sizeof(copy)) return -1;
    strcpy(copy,path); int parent=open("/",O_RDONLY|O_DIRECTORY|O_CLOEXEC);
    if(parent<0) return -1;
    char *save=NULL,*part=strtok_r(copy,"/",&save);
    while(part) {
        if(!strcmp(part,".")||!strcmp(part,"..")) { close(parent); return -1; }
        int next=openat(parent,part,O_RDONLY|O_DIRECTORY|O_CLOEXEC|O_NOFOLLOW); close(parent); parent=next;
        struct stat info;
        if(parent<0||fstat(parent,&info)||info.st_uid||(info.st_mode&0022)) { if(parent>=0) close(parent); return -1; }
        part=strtok_r(NULL,"/",&save);
    }
    if(!store_directory_valid(parent,0)) { close(parent); return -1; }
    return parent;
}
static int current_boot(char boot[37]) {
    char text[38]; int fd=open("/proc/sys/kernel/random/boot_id",O_RDONLY|O_CLOEXEC);
    ssize_t size=fd<0?-1:read(fd,text,sizeof(text)); if(fd>=0) close(fd);
    if(size!=37||text[36]!='\n') return -1;
    text[36]=0; if(!gate_boot_valid(text)) return -1;
    memcpy(boot,text,37); return 0;
}
static int installed(int base) {
    int fd=openat(base,"install.ready",O_RDONLY|O_NOFOLLOW|O_NONBLOCK|O_CLOEXEC);
    if(fd<0) return 0;
    char text[64]; ssize_t size=read(fd,text,sizeof(text));
    const char expected[]="LISA_STATION_INSTALL_V1\n";
    int valid=boot_ledger_file(fd,0)&&size==(ssize_t)sizeof(expected)-1&&!memcmp(text,expected,sizeof(expected)-1);
    close(fd); return valid;
}
static int process_scope(unsigned *legacy,unsigned *tagged) {
    *legacy=*tagged=0; DIR *directory=opendir("/proc"); struct dirent *entry; int ok=1;
    if(!directory) return -1;
    for(;;) {
        errno=0; entry=readdir(directory);
        if(!entry) { if(errno) ok=0; break; }
        char *end; long pid=strtol(entry->d_name,&end,10);
        if(*end||pid<2||pid>INT_MAX) continue;
        struct process_stamp stamp;
        if(process_stamp((pid_t)pid,&stamp)||stamp.state=='Z'||stamp.state=='X') continue;
        unsigned role=relay_role((pid_t)pid);
        if(role<4||relay_executable_is((pid_t)pid,"/usr/bin/hardvold")==1) ++*legacy;
        char path[64],line[1024]; snprintf(path,sizeof(path),"/proc/%ld/status",pid);
        FILE *file=fopen(path,"r");
        if(!file) { if(process_live((pid_t)pid,stamp.ticks)) ok=0; continue; }
        int member=0;
        while(fgets(line,sizeof(line),file)) {
            if(strncmp(line,"Gid:",4)&&strncmp(line,"Groups:",7)) continue;
            char *number=strchr(line,':')+1,*parsed;
            while(*number) {
                unsigned long value=strtoul(number,&parsed,10);
                if(parsed==number) break;
                if(value>=57342&&value<=57345) member=1;
                number=parsed;
            }
        }
        if(ferror(file)) ok=0;
        fclose(file); *tagged+=(unsigned)member;
    }
    closedir(directory); return ok?0:-1;
}
static int no_runtime_actors(int runtime) {
    const char *names[]={"vendor.permit","quasar.child","collector.child","telemetry.child","diagnostics.child"};
    for(unsigned i=0;i<sizeof(names)/sizeof(names[0]);++i) {
        struct stat info;
        if(!fstatat(runtime,names[i],&info,AT_SYMLINK_NOFOLLOW)||errno!=ENOENT) return 0;
    }
    return 1;
}
static int boot_lock(int directory,const char *name,int status) {
    int fd=openat(directory,name,O_RDWR|O_NOFOLLOW|O_NONBLOCK|O_CLOEXEC|(status?0:O_CREAT),0600);
    if(fd<0) return -1;
    if(!store_file_valid(fd,0)||flock(fd,(status?LOCK_SH:LOCK_EX)|LOCK_NB)) { close(fd); return -1; }
    return fd;
}
static int production_chain(int runtime,int status) {
    struct stat info;
    if(!fstatat(runtime,"policy.chain",&info,AT_SYMLINK_NOFOLLOW)) return 0;
    if(errno!=ENOENT||status) return -1;
    const char text[]="LISACQ_BOOT\n";
    int fd=openat(runtime,"policy.chain",O_WRONLY|O_CREAT|O_EXCL|O_NOFOLLOW|O_CLOEXEC,0600);
    if(fd<0) return -1;
    int failed=store_write_all(fd,text,sizeof(text)-1)||fsync(fd);
    if(close(fd)) failed=1;
    return failed||fsync(runtime)?-1:0;
}
int main(int argc,char **argv) {
    if(geteuid()||argc<2||argc>3) return 2;
    int lab=!strcmp(argv[1],"--lab-policy")||!strcmp(argv[1],"--lab-policy-status");
    int status=!strcmp(argv[1],"--status")||!strcmp(argv[1],"--lab-policy-status");
    if((lab&&argc!=3)||(!lab&&argc!=2)||(!lab&&!status&&strcmp(argv[1],"--bootstrap"))) return 2;
    alarm(10);
    uint64_t began=guardian_milliseconds(); const char *controls="null";
    char compatible[512],boot[37],state_path[PATH_MAX],runtime_path[PATH_MAX];
    int fd=open("/proc/device-tree/compatible",O_RDONLY|O_CLOEXEC);
    ssize_t size=fd<0?-1:read(fd,compatible,sizeof(compatible)); if(fd>=0) close(fd);
    const char model[]="yandex,station-midi"; int supported=0;
    for(ssize_t i=0;i+(ssize_t)sizeof(model)<=size;++i)
        if((!i||!compatible[i-1])&&!memcmp(compatible+i,model,sizeof(model))) supported=1;
    if(!supported||current_boot(boot)) return 3;
    int state=-1,runtime=-1,lock=-1,mode_lock=-1,ready=0,ownership=0,observed=0; unsigned legacy=0,tagged=0;
    const char *result="denied",*requested="unknown"; char chain[32]=""; struct mode_record mode;
    struct statvfs rootfs;
    if(statvfs("/",&rootfs)||!(rootfs.f_flag&ST_RDONLY)) goto done;
    if(lab) {
        const char prefix[]="/bkupgrade/data/opt/lisa-controller-lab/boot-policy.";
        if(strncmp(argv[2],prefix,sizeof(prefix)-1)) return 2;
        const char *suffix=argv[2]+sizeof(prefix)-1; size_t count=strlen(suffix);
        if(count<6||count>16) return 2;
        for(size_t i=0;i<count;++i) if(!((suffix[i]>='a'&&suffix[i]<='z')||(suffix[i]>='A'&&suffix[i]<='Z')||(suffix[i]>='0'&&suffix[i]<='9'))) return 2;
        struct stat info;
        if(!lstat("/bkupgrade/data/opt/lisa-station/state",&info)||errno!=ENOENT||
            !lstat("/run/lisa-station",&info)||errno!=ENOENT) goto done;
        int base=boot_directory(argv[2]); if(base<0) goto done; close(base);
        snprintf(state_path,sizeof(state_path),"%s/state",argv[2]); snprintf(runtime_path,sizeof(runtime_path),"%s/run",argv[2]);
    } else {
        int base=boot_directory("/bkupgrade/data/opt/lisa-station");
        if(base<0) goto done;
        int valid=installed(base); close(base); if(!valid) goto done;
        strcpy(state_path,"/bkupgrade/data/opt/lisa-station/state"); strcpy(runtime_path,"/run/lisa-station");
    }
    state=boot_directory(state_path);
    if(state<0) goto done;
    mode_lock=boot_lock(state,"mode.lock",status);
    if(mode_lock<0) { result="busy"; goto done; }
    if(mode_store_read(state,0,&mode)!=STORE_OK) goto done;
    requested=mode_name(mode.requested);
    if(mode.requested==LISA_MODE_ALICE||process_scope(&legacy,&tagged)) goto done;
    observed=1;
    if(tagged||(!lab&&legacy)) goto done;
    if(!lab&&!status) { if(mkdir(runtime_path,0700)&&errno!=EEXIST) goto done; }
    runtime=boot_directory(runtime_path);
    if(runtime<0||!no_runtime_actors(runtime)) goto done;
    lock=boot_lock(runtime,"boot.lock",status);
    if(lock<0) { result="busy"; goto done; }
    if((!lab&&production_chain(runtime,status))||policy_chain_read(runtime,0,chain,sizeof(chain))||(!lab&&strcmp(chain,"LISACQ_BOOT"))) goto done;
    int owner=boot_ledger_read(runtime,0,0,boot,chain),complete=boot_ledger_read(runtime,0,1,boot,chain);
    if(owner<0||complete<0||(owner==1&&complete!=1)) goto done;
    ownership=owner==0;
    struct label_policy_names names;
    if(label_policy_names(chain,&names)) goto done;
    if(status) {
        ready=ownership&&complete==0&&label_policy_verified(chain)&&!boot_policy_foreign_writers(&names,0);
        result=ready?"ok":"denied"; goto done;
    }
    if(owner==1) {
        if(boot_policy_foreign_writers(&names,1)||!boot_policy_unused_label()||boot_ledger_publish(runtime,0,0,boot,chain)) goto done;
        ownership=1;
    }
    if(boot_policy_install(chain)) { result="incomplete"; goto done; }
    int control4=policy_control_socket(AF_INET),control6=policy_control_socket(AF_INET6);
    controls=control4&&control6?"true":"false";
    if(!control4||!control6||boot_ledger_publish(runtime,0,1,boot,chain)) { result="incomplete"; goto done; }
    ready=label_policy_verified(chain); result=ready?"ok":"incomplete";
done: ;
    char legacy_text[16]="null",tagged_text[16]="null";
    if(observed) { snprintf(legacy_text,sizeof(legacy_text),"%u",legacy); snprintf(tagged_text,sizeof(tagged_text),"%u",tagged); }
    printf("{\"event\":\"station-boot\",\"operation\":\"%s\",\"result\":\"%s\",\"lab_policy_only\":%s,\"requested_mode\":\"%s\","
        "\"namespace_owned\":%s,\"policy_ready\":%s,\"known_legacy_actors\":%s,\"tagged_actors\":%s,\"vendor_started\":false,"
        "\"unrelated_controls_verified\":%s,\"elapsed_ms\":%" PRIu64 ",\"stock_fallback\":false,\"isolation_verified\":false}\n",argv[1]+2,result,lab?"true":"false",requested,ownership?"true":"false",ready?"true":"false",legacy_text,tagged_text,controls,guardian_milliseconds()-began);
    if(lock>=0) close(lock);
    if(mode_lock>=0) close(mode_lock);
    if(state>=0) close(state);
    if(runtime>=0) close(runtime);
    return ready?0:4;
}
