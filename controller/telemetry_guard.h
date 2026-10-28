/* Reuse the qualified read-only filesystem/capability boundary. Add a private
 * AppMetrica directory so old persistent batches cannot be read through DATA. */
#ifndef LISA_TELEMETRY_GUARD_H
#define LISA_TELEMETRY_GUARD_H
#include "collector_guard.h"

static inline int telemetry_isolate(const char *root,const char *profile,const char *executable) {
    struct stat host;
    if(lstat("/data/quasar/appmetrica",&host)||!S_ISDIR(host.st_mode)||host.st_uid||
        collector_isolate_as(root,profile,executable,57345)||mkdir("/tmp/lisa-telemetry",0700)||
        mkdir("/tmp/lisa-telemetry/appmetrica",0700)||
        mount("/tmp/lisa-telemetry/appmetrica","/data/quasar/appmetrica",NULL,MS_BIND,NULL)||
        mount(NULL,"/data/quasar/appmetrica",NULL,MS_BIND|MS_REMOUNT|MS_NOSUID|MS_NODEV|MS_NOEXEC,NULL)) return -1;
    return 0;
}
static inline int telemetry_private_view(pid_t pid) {
    if(collector_private_view(pid)) return -1;
    char path[PATH_MAX]; struct stat tmp,app,host; struct statvfs fs;
    snprintf(path,sizeof(path),"/proc/%ld/root/tmp",(long)pid);
    if(stat(path,&tmp)) return -1;
    snprintf(path,sizeof(path),"/proc/%ld/root/data/quasar/appmetrica",(long)pid);
    if(stat(path,&app)||stat("/data/quasar/appmetrica",&host)||app.st_dev!=tmp.st_dev||
        (app.st_dev==host.st_dev&&app.st_ino==host.st_ino)||statvfs(path,&fs)||(fs.f_flag&ST_RDONLY)) return -1;
    return 0;
}
static inline int telemetry_runtime_private(pid_t pid,int *batch_materialized) {
    char path[PATH_MAX]; struct stat tmp,host,db,log,batch,forbidden[6]; unsigned deny_count=0;
    *batch_materialized=0;
    snprintf(path,sizeof(path),"/proc/%ld/root/tmp",(long)pid);
    if(stat(path,&tmp)||stat("/tmp",&host)||tmp.st_dev==host.st_dev) return 0;
    snprintf(path,sizeof(path),"/proc/%ld/root/tmp/lisa-telemetry/lmdb/data.mdb",(long)pid);
    if(stat(path,&db)||!S_ISREG(db.st_mode)||db.st_dev!=tmp.st_dev) return 0;
    snprintf(path,sizeof(path),"/proc/%ld/root/tmp/lisa-telemetry/telemetry.log",(long)pid);
    if(stat(path,&log)||!S_ISREG(log.st_mode)||log.st_dev!=tmp.st_dev) return 0;
    const char *batch_paths[]={"/tmp/lisa-telemetry/persistedBatch","/data/quasar/appmetrica/persistedBatch",
        "/tmp/persistentMetricaBatch"};
    for(unsigned i=0;i<3;++i) {
        snprintf(path,sizeof(path),"/proc/%ld/root%s",(long)pid,batch_paths[i]);
        if(!stat(path,&batch)) {
            if(!S_ISREG(batch.st_mode)||batch.st_dev!=tmp.st_dev) return 0;
            if(batch.st_size>0&&batch.st_blocks>0) *batch_materialized|=1u<<i;
        } else if(errno!=ENOENT) return 0;
    }
    const char *names[]={"/tmp/teleme3d/data.mdb","/tmp/teleme3d/lock.mdb",
        "/data/quasar/appmetrica/persistedBatch","/tmp/messages","/tmp/messages.0","/tmp/persistentMetricaBatch"};
    for(unsigned i=0;i<6;++i) {
        if(!stat(names[i],&forbidden[deny_count])) ++deny_count;
        else if(errno!=ENOENT) return 0;
    }
    snprintf(path,sizeof(path),"/proc/%ld/fd",(long)pid); DIR *fds=opendir(path);
    if(!fds) return 0;
    int db_held=0,log_held=0,ok=1; unsigned seen=0; struct dirent *entry;
    for(;;) {
        errno=0; entry=readdir(fds);
        if(!entry) { if(errno) ok=0; break; }
        char *end; long fd=strtol(entry->d_name,&end,10);
        if(*end||fd<0||fd>INT_MAX) continue;
        if(++seen>1024) { ok=0; break; }
        struct stat actual; snprintf(path,sizeof(path),"/proc/%ld/fd/%ld",(long)pid,fd);
        if(stat(path,&actual)) { ok=0; break; }
        db_held|=actual.st_dev==db.st_dev&&actual.st_ino==db.st_ino;
        log_held|=actual.st_dev==log.st_dev&&actual.st_ino==log.st_ino;
        for(unsigned i=0;i<deny_count;++i)
            if(actual.st_dev==forbidden[i].st_dev&&actual.st_ino==forbidden[i].st_ino) ok=0;
    }
    closedir(fds);
    snprintf(path,sizeof(path),"/proc/%ld/maps",(long)pid); FILE *maps=fopen(path,"r"); char line[PATH_MAX+256];
    if(!maps) return 0;
    unsigned count=0;
    while(fgets(line,sizeof(line),maps)) {
        struct relay_row row;
        if(++count>RELAY_MAP_LIMIT||!strchr(line,'\n')||relay_parse_map(line,&row)) { ok=0; break; }
        db_held|=row.device==db.st_dev&&row.inode==db.st_ino;
        for(unsigned i=0;i<deny_count;++i)
            if(row.device==forbidden[i].st_dev&&row.inode==forbidden[i].st_ino) ok=0;
    }
    if(ferror(maps)) ok=0;
    fclose(maps); return ok&&db_held&&log_held;
}
/* Administrative observation only. Pin private directories, never payloads,
 * through child shutdown so deferred SDK writes can be observed before releasing
 * the last coordinator-owned references to its ephemeral filesystem. */
static inline int telemetry_observe_close(pid_t pid,uint64_t ticks) {
    char path[PATH_MAX]; int directories[3]={-1,-1,-1},ok=1; struct stat info; dev_t device=0;
    const char *names[]={"/tmp/lisa-telemetry","/data/quasar/appmetrica","/tmp"};
    for(unsigned i=0;i<3;++i) {
        snprintf(path,sizeof(path),"/proc/%ld/root%s",(long)pid,names[i]);
        directories[i]=open(path,O_RDONLY|O_DIRECTORY|O_CLOEXEC);
        if(directories[i]<0||fstat(directories[i],&info)||(i&&device!=info.st_dev)) { ok=0; break; }
        device=info.st_dev;
    }
    struct stat host;
    if(stat("/tmp",&host)||device==host.st_dev||!process_live(pid,ticks)) ok=0;
    if(!ok) {
        for(unsigned i=0;i<3;++i) if(directories[i]>=0) close(directories[i]);
        return 4;
    }
    printf("{\"event\":\"telemetry-observer-ready\",\"child_pid\":%ld,\"start_ticks\":%" PRIu64 "}\n",(long)pid,ticks);
    fflush(stdout);
    uint64_t deadline=guardian_milliseconds()+15000;
    while(process_live(pid,ticks)&&guardian_milliseconds()<deadline) {
        struct timespec pause={0,50000000}; nanosleep(&pause,NULL);
    }
    int stopped=!process_live(pid,ticks); unsigned found=0;
    const char *files[]={"persistedBatch","persistedBatch","persistentMetricaBatch"};
    if(stopped) for(unsigned i=0;i<3;++i) {
        if(!fstatat(directories[i],files[i],&info,AT_SYMLINK_NOFOLLOW)) {
            if(!S_ISREG(info.st_mode)||info.st_dev!=device) ok=0;
            else if(info.st_size>0&&info.st_blocks>0) found|=1u<<i;
        } else if(errno!=ENOENT) ok=0;
    }
    for(unsigned i=0;i<3;++i) if(close(directories[i])) ok=0;
    printf("{\"event\":\"telemetry-epoch-closed\",\"child_pid\":%ld,\"start_ticks\":%" PRIu64 ","
        "\"actor_stopped\":%s,\"observer_fds_closed\":%s,\"batch_materialized\":%s,\"batch_paths\":%u,"
        "\"payload_read\":false}\n",(long)pid,ticks,stopped?"true":"false",ok?"true":"false",found?"true":"false",found);
    return stopped&&ok?0:4;
}
#endif
