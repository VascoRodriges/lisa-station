/* Root, read-only census of known queue/log/shared-object holders. The self-test
 * touches only its own synthetic files/mappings and needs no root privileges. */
#define _GNU_SOURCE
#include <sys/mman.h>
#include "relay_resources.h"

struct relay_process { pid_t pid; unsigned role,start,end; struct relay_identity identity; };
static int boot_id(char boot[37]) {
    int file=open("/proc/sys/kernel/random/boot_id",O_RDONLY|O_CLOEXEC); char text[38];
    if(file<0) return -1;
    ssize_t size=read(file,text,sizeof(text)); close(file);
    if(size!=37||text[36]!='\n') return -1;
    text[36]=0; if(!gate_boot_valid(text)) return -1;
    memcpy(boot,text,37); return 0;
}
static int inventory(void) {
    if(geteuid()) return 2;
    int fd=open("/proc/device-tree/compatible",O_RDONLY|O_CLOEXEC); char model[512];
    ssize_t size=fd>=0?read(fd,model,sizeof(model)):-1; if(fd>=0) close(fd);
    const char expected[]="yandex,station-midi"; int supported=0;
    for(ssize_t i=0;i+(ssize_t)sizeof(expected)<=size;++i)
        if((!i||!model[i-1])&&!memcmp(model+i,expected,sizeof(expected))) supported=1;
    if(!supported) return 3;
    struct relay_row *rows=calloc(RELAY_LIMIT,sizeof(*rows)),*maps=calloc(RELAY_MAP_LIMIT,sizeof(*maps));
    struct relay_process *owners=calloc(RELAY_PROCESS_LIMIT,sizeof(*owners));
    if(!rows||!maps||!owners) { free(rows); free(maps); free(owners); return 3; }
    char boot[37],end_boot[37]; unsigned count=0,process_count=0,unreadable=0,unidentified=0,changed=0;
    int failed=boot_id(boot); DIR *processes=failed?NULL:opendir("/proc");
    if(!processes) { free(rows); free(maps); free(owners); return 3; }
    struct dirent *entry;
    while(!failed) {
        errno=0; entry=readdir(processes);
        if(!entry) { if(errno) ++unreadable; break; }
        char *end; long number=strtol(entry->d_name,&end,10);
        if(*end||number<1||number>INT_MAX||number==getpid()) continue;
        struct relay_identity identity;
        if(relay_identity((pid_t)number,&identity)) { ++unidentified; continue; }
        if(process_count==RELAY_PROCESS_LIMIT) { failed=1; break; }
        struct relay_process *owner=&owners[process_count++];
        *owner=(struct relay_process){(pid_t)number,relay_role((pid_t)number),count,count,identity};
        char path[64]; snprintf(path,sizeof(path),"/proc/%ld/fd",number);
        DIR *descriptors=opendir(path); struct dirent *descriptor;
        if(!descriptors) ++unreadable;
        else {
            unsigned seen=0;
            for(;;) {
                errno=0; descriptor=readdir(descriptors);
                if(!descriptor) { if(errno) ++unreadable; break; }
                long value=strtol(descriptor->d_name,&end,10);
                if(*end||value<0||value>INT_MAX) continue;
                if(++seen>8192) { failed=1; break; }
                struct relay_row row;
                char fd_path[80]; struct stat metadata;
                snprintf(fd_path,sizeof(fd_path),"/proc/%ld/fd/%ld",number,value);
                if(stat(fd_path,&metadata)) { ++unreadable; continue; }
                if(!S_ISREG(metadata.st_mode)) continue;
                if(relay_fd((pid_t)number,(unsigned)value,&row)) { ++unreadable; continue; }
                if(count==RELAY_LIMIT) { failed=1; break; }
                row.identity=identity; row.role=owner->role; rows[count++]=row;
            }
            closedir(descriptors);
        }
        unsigned map_count;
        if(relay_maps((pid_t)number,maps,&map_count)) ++unreadable;
        else for(unsigned i=0;i<map_count;++i) {
            if(count==RELAY_LIMIT) { failed=1; break; }
            maps[i].identity=identity; maps[i].role=owner->role; rows[count++]=maps[i];
        }
        owner->end=count;
    }
    closedir(processes);
    for(unsigned p=0;p<process_count&&!failed;++p) {
        struct relay_process *owner=&owners[p]; struct relay_identity current,after;
        int same=!relay_identity(owner->pid,&current)&&relay_same(&current,&owner->identity)&&relay_role(owner->pid)==owner->role;
        unsigned map_count=0;
        if(relay_maps(owner->pid,maps,&map_count)) { ++unreadable; same=0; }
        for(unsigned i=owner->start;i<owner->end;++i) {
            struct relay_row *row=&rows[i];
            if(!same) continue;
            if(!row->mapping) row->confirmed=relay_fd_matches(row);
            else for(unsigned m=0;m<map_count;++m) if(relay_map_matches(row,&maps[m])) { row->confirmed=1; break; }
        }
        if(!same||relay_identity(owner->pid,&after)||!relay_same(&after,&owner->identity)) {
            ++changed;
            for(unsigned i=owner->start;i<owner->end;++i) rows[i].confirmed=0;
        }
    }
    if(failed) { free(rows); free(maps); free(owners); return 4; }
    relay_join(rows,count);
    printf("{\"event\":\"relay-evidence-start\",\"boot_id\":\"%s\"}\n",boot);
    for(unsigned p=0;p<process_count;++p) {
        struct relay_process *owner=&owners[p];
        printf("{\"event\":\"relay-process\",\"pid\":%ld,\"start_ticks\":%" PRIu64 ",\"exe_device\":%" PRIu64 ","
            "\"exe_inode\":%" PRIu64 ",\"role\":\"%s\"}\n",(long)owner->pid,owner->identity.ticks,owner->identity.device,
            owner->identity.inode,relay_role_name(owner->role));
    }
    unsigned observations=0,confirmed=0;
    for(unsigned i=0;i<count;++i) {
        struct relay_row *row=&rows[i];
        if(!row->kind) continue;
        ++observations; confirmed+=row->confirmed;
        printf("{\"event\":\"relay-holder\",\"pid\":%ld,\"start_ticks\":%" PRIu64 ",\"device\":%" PRIu64 ","
            "\"inode\":%" PRIu64 ",\"source\":\"%s\",\"descriptor\":%u,\"flags\":%u,\"low\":%" PRIu64 ","
            "\"high\":%" PRIu64 ",\"offset\":%" PRIu64 ",\"kinds\":%u,\"readable\":%s,\"writable\":%s,"
            "\"shared\":%s,\"unlinked\":%s,\"deleted_hint\":%s,\"confirmed\":%s}\n",
            (long)row->pid,row->identity.ticks,row->device,row->inode,row->mapping?"mapping":"descriptor",
            row->descriptor,row->flags,row->low,row->high,row->offset,row->kind,row->readable?"true":"false",
            row->writable?"true":"false",row->shared?"true":"false",row->mapping?"null":row->deleted?"true":"false",
            row->mapping&&row->deleted?"true":"false",row->confirmed?"true":"false");
    }
    int stable=!boot_id(end_boot)&&!strcmp(boot,end_boot);
    printf("{\"event\":\"relay-evidence-summary\",\"processes\":%u,\"observations\":%u,\"confirmed\":%u,"
        "\"unreadable\":%u,\"unidentified\":%u,\"changed_processes\":%u,\"boot_stable\":%s,"
        "\"atomic_snapshot\":false,\"audio_opened\":false,\"payload_read\":false,\"apply_supported\":false}\n",
        process_count,observations,confirmed,unreadable,unidentified,changed,stable?"true":"false");
    free(rows); free(maps); free(owners); return stable?0:4;
}
static unsigned checks,failed;
static int check(const char *name,int ok) {
    ++checks; failed+=!ok;
    if(!ok) fprintf(stderr,"failed:%s\n",name);
    return ok;
}
static int selftest(void) {
    struct { const char *path; unsigned kind; } cases[]={
        {"/data/quasar/daemons_logs/test.log",RELAY_LOG},
        {"/bkupgrade/data/quasar/daemons_logs/test.log (deleted)",RELAY_LOG},
        {"/data/quasar/data/local_events.lmdb",RELAY_DATA},
        {"/data/quasar/launcher2.1.log",RELAY_LAUNCH_LOG},{"/data/quasar/launcher2.out",RELAY_LAUNCH_LOG},
        {"/tmp/messages",RELAY_SYSTEM_LOG},{"/tmp/messages.12",RELAY_SYSTEM_LOG},
        {"/tmp/teleme3d/data.mdb",RELAY_TELEMETRY},{"/tmp/fluent-bit.db-wal",RELAY_COLLECTOR},
        {"/dev/shm/alsa-audio-monitor-v2",RELAY_RMS},{"/memfd:queue_buffer (deleted)",RELAY_MEMFD},
        {"/dev/snd/pcmC0D2c",RELAY_DEVICE_MEMORY},{"/tmp/capability_states.lmdb",RELAY_RUNTIME_STATE},
        {"/tmp/messages.evil",0},{"/tmp/messages.",0},{"/tmp/fluent-bit.db-other",0},
        {"/data/quasar/daemons_logs-evil/x",0},{"/data/quasar/data/../secret",0},
        {"/tmp/teleme3d-other/data.mdb",0},{"/dev/shm/alsa-audio-monitor-v20",0},
    };
    for(unsigned i=0;i<sizeof(cases)/sizeof(cases[0]);++i) check("fixed_path_class",relay_classify(cases[i].path)==cases[i].kind);
    struct relay_row row;
    check("mapping_metadata",!relay_parse_map("1000-2000 rw-s 00000000 00:13 42 /tmp/teleme3d/data.mdb\n",&row)&&
        row.low==0x1000&&row.high==0x2000&&row.inode==42&&row.shared&&row.writable&&row.kind==RELAY_TELEMETRY);
    check("private_mapping",!relay_parse_map("1000-2000 rw-p 00000000 00:13 42 /tmp/messages\n",&row)&&!row.shared);
    const char *bad[]={"bad\n","2000-1000 rw-s 0 00:13 42 /tmp/messages\n","1000-2000 rw-z 0 00:13 42 x\n"};
    for(unsigned i=0;i<sizeof(bad)/sizeof(bad[0]);++i) check("malformed_map",relay_parse_map(bad[i],&row)<0);
    char directory[]="/tmp/lisa-relay-evidence.XXXXXX",file[PATH_MAX],alias[PATH_MAX];
    umask(077); if(!mkdtemp(directory)) return 3;
    snprintf(file,sizeof(file),"%s/own",directory); snprintf(alias,sizeof(alias),"%s/alias",directory);
    int descriptor=open(file,O_RDWR|O_CREAT|O_EXCL|O_CLOEXEC,0600),second=-1;
    struct relay_row *maps=calloc(RELAY_MAP_LIMIT,sizeof(*maps));
    if(descriptor<0||!maps||ftruncate(descriptor,8192)) return 3;
    check("own_fd_metadata",!relay_fd(getpid(),(unsigned)descriptor,&row)&&row.readable&&row.writable&&!row.deleted);
    check("own_identity",!relay_identity(getpid(),&row.identity));
    check("fd_reconfirmed",relay_fd_matches(&row));
    struct relay_row wrong=row; wrong.identity.ticks++; check("stale_ticks",!relay_fd_matches(&wrong));
    wrong=row; wrong.identity.inode++; check("wrong_executable",!relay_fd_matches(&wrong));
    wrong=row; wrong.inode++; check("wrong_file",!relay_fd_matches(&wrong));
    check("hardlink_created",!link(file,alias)&&(second=open(alias,O_RDONLY|O_CLOEXEC))>=0);
    struct relay_row other;
    check("alias_metadata",!relay_fd(getpid(),(unsigned)second,&other)&&other.device==row.device&&other.inode==row.inode&&other.readable&&!other.writable);
    row.kind=RELAY_TELEMETRY; other.kind=0; row.confirmed=other.confirmed=1;
    struct relay_row joined[]={row,other}; relay_join(joined,2);
    check("inode_alias_join",joined[0].kind==RELAY_TELEMETRY&&joined[1].kind==RELAY_TELEMETRY&&joined[0].confirmed&&joined[1].confirmed);
    joined[0]=row; joined[1]=other; joined[0].confirmed=0; joined[1].confirmed=1;
    relay_join(joined,2);
    check("stale_class_origin_rejected",!joined[0].confirmed&&!joined[1].confirmed);
    joined[0].kind=joined[1].kind=0; joined[0].role=0; joined[0].writable=1; relay_join(joined,2);
    check("unclassified_stale_origin_rejected",!joined[0].confirmed&&!joined[1].confirmed);
    joined[0].kind=joined[1].kind=0; joined[0].confirmed=joined[1].confirmed=1; relay_join(joined,2);
    check("unclassified_writer",joined[0].kind==RELAY_UNKNOWN_WRITE&&joined[1].kind==RELAY_UNKNOWN_WRITE);
    void *mapping=mmap(NULL,8192,PROT_READ|PROT_WRITE,MAP_SHARED,descriptor,0);
    check("own_mapping",mapping!=MAP_FAILED);
    unsigned count=0; struct relay_row saved={0};
    check("own_map_metadata",!relay_maps(getpid(),maps,&count));
    for(unsigned i=0;i<count;++i) if(maps[i].inode==row.inode&&maps[i].device==row.device) saved=maps[i];
    check("mapped_identity",saved.inode==row.inode&&saved.shared&&saved.writable);
    unlink(file); unlink(alias);
    struct relay_row unlinked;
    check("unlinked_fd_metadata",!relay_fd(getpid(),(unsigned)descriptor,&unlinked)&&unlinked.deleted);
    unlinked.identity=row.identity;
    check("unlinked_fd_reconfirmed",relay_fd_matches(&unlinked));
    struct relay_row changed_map=saved; changed_map.offset++;
    check("changed_map_offset",!relay_map_matches(&saved,&changed_map));
    changed_map=saved; changed_map.shared=!changed_map.shared;
    check("changed_map_sharing",!relay_map_matches(&saved,&changed_map));
    close(descriptor); close(second);
    check("closed_fd_stale",!relay_fd_matches(&row));
    check("deleted_map_remains",!relay_maps(getpid(),maps,&count));
    int seen=0;
    for(unsigned i=0;i<count;++i) if(maps[i].inode==row.inode&&maps[i].device==row.device) seen=maps[i].deleted;
    check("deleted_mapping_hint",seen);
    int replacement=open(file,O_RDWR|O_CREAT|O_EXCL|O_CLOEXEC,0600);
    check("fd_number_reuse",replacement>=0&&dup2(replacement,descriptor)==descriptor&&!relay_fd_matches(&row));
    if(replacement!=descriptor) close(replacement);
    close(descriptor);
    unlink(file);
    if(mapping!=MAP_FAILED) munmap(mapping,8192);
    check("unmapped_metadata",!relay_maps(getpid(),maps,&count)); seen=0;
    for(unsigned i=0;i<count;++i) if(relay_map_matches(&saved,&maps[i])) seen=1;
    check("unmapped_rejected",!seen);
    free(maps); check("fixture_removed",!rmdir(directory));
    printf("{\"selftest\":\"relay-evidence\",\"checks\":%u,\"ok\":%s,\"audio_opened\":false,"
        "\"payload_read\":false,\"vendor_processes_changed\":false}\n",checks,failed?"false":"true");
    return failed?4:0;
}
int main(int argc,char **argv) {
    if(argc!=2) return 2;
    alarm(25);
    if(!strcmp(argv[1],"--selftest")) return selftest();
    if(!strcmp(argv[1],"--inventory")) return inventory();
    return 2;
}
