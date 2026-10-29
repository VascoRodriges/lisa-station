/* Foreground chronyd behind the independent supervisor. RUNNING is not a
 * claim that an NTP source has synchronized; lab evidence records that apart. */
#ifndef LISA_TIME_SERVICE_H
#define LISA_TIME_SERVICE_H
#include "time_profile.h"
#include "network_service.h"
#include "relay_resources.h"
static inline int time_actor_absent(const struct guardian_record *record) {
    return record->child<2||!process_live(record->child,record->child_ticks);
}
static inline int time_actor_observe(pid_t pid) {
    char path[PATH_MAX],line[512],own[128],child[128];struct stat info,host;struct statvfs filesystem;
    snprintf(path,sizeof(path),"/proc/%ld/status",(long)pid);FILE *file=fopen(path,"r");if(!file)return -1;
    int uid=0,gid=0,seccomp=0,bad=0;unsigned count=0,a,b,c,d;unsigned long long caps;
    while(fgets(line,sizeof(line),file)){
        if(sscanf(line,"Uid: %u %u %u %u",&a,&b,&c,&d)==4)uid=!a&&!b&&!c&&!d;
        if(sscanf(line,"Gid: %u %u %u %u",&a,&b,&c,&d)==4)gid=!a&&!b&&!c&&!d;
        if(sscanf(line,"Seccomp: %u",&a)==1)seccomp=a==2;
        if(sscanf(line,"NoNewPrivs: %u",&a)==1&&a!=1)bad=1;
        if(sscanf(line,"CapEff: %llx",&caps)==1||sscanf(line,"CapPrm: %llx",&caps)==1||sscanf(line,"CapBnd: %llx",&caps)==1){++count;bad|=caps!=(1u<<CAP_SYS_TIME);}
        if(sscanf(line,"CapInh: %llx",&caps)==1||sscanf(line,"CapAmb: %llx",&caps)==1){++count;bad|=caps!=0;}
    }
    if(ferror(file))bad=1;
    fclose(file);if(!uid||!gid||!seccomp||bad||count!=5)return -1;
    snprintf(path,sizeof(path),"/proc/%ld/ns/mnt",(long)pid);
    ssize_t x=readlink("/proc/self/ns/mnt",own,sizeof(own)),y=readlink(path,child,sizeof(child));
    if(x<=0||y<=0||(x==y&&!memcmp(own,child,(size_t)x)))return -1;
    snprintf(path,sizeof(path),"/proc/%ld/root",(long)pid);
    if(statvfs(path,&filesystem)||!(filesystem.f_flag&ST_RDONLY))return -1;
    const char *targets[]={time_runtime,time_drift_target};const char *sources[]={time_runtime,time_drift_source};
    for(unsigned i=0;i<2;++i){
        if(!targets[i][0]||!sources[i][0]||snprintf(path,sizeof(path),"/proc/%ld/root%s",(long)pid,targets[i])>=(int)sizeof(path)||
            stat(path,&info)||stat(sources[i],&host)||info.st_dev!=host.st_dev||info.st_ino!=host.st_ino||
            info.st_uid||(info.st_mode&07777)!=0700||statvfs(path,&filesystem)||(filesystem.f_flag&ST_RDONLY))return -1;
    }
    const char *hidden[]={"/proc","/sys","/data/quasar","/run/lisa-station","/dev/log","/dev/shm","/dev/snd",
        "/etc/chrony.conf","/etc/resolv.conf","/var/lib/chrony","/var/run/chrony/chronyd.sock"};
    for(unsigned i=0;i<sizeof(hidden)/sizeof(hidden[0]);++i){snprintf(path,sizeof(path),"/proc/%ld/root%s",(long)pid,hidden[i]);
        if(!lstat(path,&info)||errno!=ENOENT)return -1;}
    if(snprintf(path,sizeof(path),"%s/chronyd.pid",time_runtime)>=(int)sizeof(path))return -1;
    int fd=open(path,O_RDONLY|O_NOFOLLOW|O_NONBLOCK|O_CLOEXEC);if(fd<0)return -1;
    char text[32],expected[32];ssize_t used=read(fd,text,sizeof(text));int valid=store_file_valid(fd,0);close(fd);
    int size=snprintf(expected,sizeof(expected),"%ld\n",(long)pid);
    return valid&&used==size&&!memcmp(text,expected,(size_t)size)?0:-1;
}
static inline int time_operation(int runtime,const char *runtime_path,const char *base_path,const char *boot,int operation,int lab) {
    char parent[PATH_MAX],config_path[PATH_MAX];
    if(lab){
        if(snprintf(parent,sizeof(parent),"%s/network",base_path)>=(int)sizeof(parent)||
            snprintf(time_drift_source,sizeof(time_drift_source),"%s/time-drift",parent)>=(int)sizeof(time_drift_source))return 0;
        strcpy(time_drift_target,time_drift_source);strcpy(config_path,base_path);
    }else{
        strcpy(parent,"/run/lisa-station-net");
        if(snprintf(time_drift_source,sizeof(time_drift_source),"%s/time",base_path)>=(int)sizeof(time_drift_source)||
            snprintf(config_path,sizeof(config_path),"%s/config",base_path)>=(int)sizeof(config_path))return 0;
        strcpy(time_drift_target,"/data/opt/lisa-station/time");
    }
    if(snprintf(time_runtime,sizeof(time_runtime),"%s/time",parent)>=(int)sizeof(time_runtime)||
        snprintf(time_jail,sizeof(time_jail),"%s/time-jail",runtime_path)>=(int)sizeof(time_jail))return 0;
    time_proof_source[0]=0;
    if(operation==4){
        if(!lab||snprintf(time_proof_source,sizeof(time_proof_source),"%s/clock-proof.so",base_path)>=(int)sizeof(time_proof_source))return 0;
    }
    char *const arguments[]={"chronyd","-d","-f","/etc/lisa-time.conf",NULL};
    struct guardian_spec spec={.role="time",.executable="/usr/sbin/chronyd",.argv=arguments,.prepare=time_service_prepare,
        .observe=time_actor_observe,.actors_absent=time_actor_absent,.maximum_seconds=lab?45:0};
    struct guardian_record record;
    if(operation==3){
        int found=guardian_read(runtime,0,"time.child",&record);
        if(found==1)return 1;
        if(found||record.revision!=1||strcmp(record.boot,boot))return 0;
        if(!process_live(record.guardian,record.guardian_ticks)&&time_actor_absent(&record))return 1;
        return guardian_stop(runtime,0,boot,&spec)==GUARD_OK;
    }
    int config=open(config_path,O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC);if(config<0)return 0;
    int valid=store_directory_valid(config,0)&&!time_profile_read(config,time_runtime,time_drift_target);close(config);if(!valid)return 0;
    if(operation==2)return auxiliary_status(runtime,0,boot,&spec,&record)==GUARD_OK;
    if(auxiliary_status(runtime,0,boot,&spec,&record)==GUARD_OK)return 1;
    /* Never run a second clock controller, even on a separate port/profile. */
    DIR *directory=opendir("/proc");if(!directory)return 0;struct dirent *entry;int absent=1;
    while((entry=readdir(directory))){
        char *end;long pid=strtol(entry->d_name,&end,10);if(*end||pid<2||pid>INT_MAX)continue;
        struct process_stamp stamp;
        if(!process_stamp((pid_t)pid,&stamp)&&stamp.state!='Z'&&stamp.state!='X'&&relay_executable_is((pid_t)pid,"/usr/sbin/chronyd")==1){absent=0;break;}
    }
    closedir(directory);if(!absent)return 0;
    int made=!mkdir(parent,lab?0700:0755);if(!made&&errno!=EEXIST)return 0;
    int parent_fd=open(parent,O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC);if(parent_fd<0)return 0;
    struct stat info;int parent_ok=!(made&&fchmod(parent_fd,lab?0700:0755))&&!fstat(parent_fd,&info)&&!info.st_uid&&(info.st_mode&07777)==(lab?0700:0755);
    close(parent_fd);if(!parent_ok||network_role_directory(parent,"time",0,0700))return 0;
    if(lab){if(network_role_directory(parent,"time-drift",0,0700))return 0;}
    else if(network_role_directory(base_path,"time",0,0700))return 0;
    if(mkdir(time_jail,0700)&&errno!=EEXIST)return 0;
    struct guardian_started started;
    return auxiliary_start(runtime,0,boot,&spec,&started)==GUARD_OK;
}
#endif
