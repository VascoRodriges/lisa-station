/* Metadata-only file/queue ownership evidence. Never open an observed file or
 * mapping for reading; only proc metadata and stat on descriptor links. */
#ifndef LISA_RELAY_RESOURCES_H
#define LISA_RELAY_RESOURCES_H
#include <sys/sysmacros.h>
#include "startup_guardian.h"

#define RELAY_LIMIT 32768
#define RELAY_PROCESS_LIMIT 1024
#define RELAY_MAP_LIMIT 8192
enum relay_kind { RELAY_LOG=1, RELAY_LAUNCH_LOG=2, RELAY_SYSTEM_LOG=4,
    RELAY_TELEMETRY=8, RELAY_COLLECTOR=16, RELAY_RMS=32, RELAY_DATA=64,
    RELAY_MEMFD=128, RELAY_UNKNOWN_WRITE=256, RELAY_DEVICE_MEMORY=512, RELAY_RUNTIME_STATE=1024 };
struct relay_identity { uint64_t ticks,device,inode; };
struct relay_row {
    pid_t pid;
    struct relay_identity identity;
    uint64_t device,inode,low,high,offset;
    unsigned descriptor,flags,kind,role,mapping,readable,writable,shared,deleted,confirmed;
};
static inline int relay_prefix(const char *path,const char *prefix) {
    return !strncmp(path,prefix,strlen(prefix));
}
static inline unsigned relay_classify(const char *original) {
    char path[PATH_MAX]; size_t size=strlen(original);
    if(size>=sizeof(path)) return 0;
    memcpy(path,original,size+1);
    const char suffix[]=" (deleted)";
    if(size>=sizeof(suffix)-1&&!strcmp(path+size-(sizeof(suffix)-1),suffix))
        path[size-(sizeof(suffix)-1)]=0;
    /* Proc renders resolved paths. Reject lexical lookalikes in fixtures or a
     * future kernel format rather than classifying them by a loose prefix. */
    if(strstr(path,"/../")||strstr(path,"/./")||strchr(path,'\\')) return 0;
    const char *data=path;
    if(relay_prefix(data,"/bkupgrade/data/")) data+=10;
    if(relay_prefix(data,"/data/quasar/daemons_logs/")) return RELAY_LOG;
    if(relay_prefix(data,"/data/quasar/data/")) return RELAY_DATA;
    if(relay_prefix(data,"/data/quasar/launcher2.")) {
        const char *name=data+strlen("/data/quasar/launcher2.");
        if(!strcmp(name,"out")) return RELAY_LAUNCH_LOG;
        while(*name>='0'&&*name<='9') ++name;
        if(!strcmp(name,"log")||!strcmp(name,".log")) return RELAY_LAUNCH_LOG;
    }
    if(!strcmp(path,"/tmp/messages")) return RELAY_SYSTEM_LOG;
    if(relay_prefix(path,"/tmp/messages.")) {
        const char *at=path+strlen("/tmp/messages.");
        if(!*at) return 0;
        for(;*at;++at) if(*at<'0'||*at>'9') return 0;
        return RELAY_SYSTEM_LOG;
    }
    if(relay_prefix(path,"/tmp/teleme3d/")) return RELAY_TELEMETRY;
    if(!strcmp(path,"/tmp/fluent-bit.db")||!strcmp(path,"/tmp/fluent-bit.db-wal")||
        !strcmp(path,"/tmp/fluent-bit.db-shm")||!strcmp(path,"/tmp/fluent-bit.db-journal")) return RELAY_COLLECTOR;
    if(!strcmp(path,"/dev/shm/alsa-audio-monitor-v2")) return RELAY_RMS;
    if(!strcmp(path,"/dev/snd/pcmC0D2c")||!strcmp(path,"/dev/fb0")) return RELAY_DEVICE_MEMORY;
    if(!strcmp(path,"/tmp/capability_states.lmdb")) return RELAY_RUNTIME_STATE;
    if(!strcmp(path,"/memfd:queue_buffer")) return RELAY_MEMFD;
    return 0;
}
static inline int relay_identity(pid_t pid,struct relay_identity *identity) {
    if(pid<1) return -1;
    char path[64],text[2048];
    snprintf(path,sizeof(path),"/proc/%ld/stat",(long)pid);
    int file=open(path,O_RDONLY|O_CLOEXEC);
    if(file<0) return -1;
    ssize_t size=read(file,text,sizeof(text)-1); close(file);
    if(size<=0||size==(ssize_t)sizeof(text)-1) return -1;
    text[size]=0; char *tail=strrchr(text,')');
    if(!tail||strlen(tail)<4||tail[1]!=' '||tail[3]!=' '||tail[2]=='Z'||tail[2]=='X') return -1;
    tail+=4; uint64_t ticks=0;
    for(unsigned field=4;field<=22;++field) {
        char *end=strchr(tail,' ');
        if(!end) return -1;
        if(field==22) {
            char *parsed; errno=0; ticks=strtoull(tail,&parsed,10);
            if(errno||parsed!=end||!ticks) return -1;
        }
        tail=end+1;
    }
    snprintf(path,sizeof(path),"/proc/%ld/exe",(long)pid);
    struct stat info;
    if(stat(path,&info)||!S_ISREG(info.st_mode)) return -1;
    *identity=(struct relay_identity){ticks,info.st_dev,info.st_ino}; return 0;
}
static inline int relay_same(const struct relay_identity *a,const struct relay_identity *b) {
    return a->ticks==b->ticks&&a->device==b->device&&a->inode==b->inode;
}
/* A bind-mounted executable can render under the jail's host-side pathname in
 * /proc/PID/exe. Compare the pinned firmware object, not its rendered alias. */
static inline int relay_executable_is(pid_t pid,const char *expected) {
    char path[64]; struct stat actual,source;
    if(pid<1||!expected||expected[0]!='/') return -1;
    snprintf(path,sizeof(path),"/proc/%ld/exe",(long)pid);
    if(stat(path,&actual)||stat(expected,&source)) return -1;
    return S_ISREG(actual.st_mode)&&S_ISREG(source.st_mode)&&actual.st_dev==source.st_dev&&actual.st_ino==source.st_ino;
}
static inline unsigned relay_role(pid_t pid) {
    const char *fixed[]={"/system/vendor/quasar/maind","/system/vendor/quasar/quasar_launcher2",NULL,"/usr/bin/alsa-audio-monitord"};
    for(unsigned i=0;i<4;++i) if(fixed[i]&&relay_executable_is(pid,fixed[i])==1) return i;
    char path[64],name[PATH_MAX]; snprintf(path,sizeof(path),"/proc/%ld/exe",(long)pid);
    ssize_t size=readlink(path,name,sizeof(name)-1);
    if(size<=0||size>=(ssize_t)sizeof(name)-1) return 4;
    name[size]=0;
    if(!strcmp(name,"/system/vendor/quasar/maind")) return 0;
    if(!strcmp(name,"/system/vendor/quasar/quasar_launcher2")) return 1;
    if(relay_prefix(name,"/system/vendor/quasar/")) return 2;
    if(!strcmp(name,"/usr/bin/alsa-audio-monitord")) return 3;
    return 4;
}
static inline const char *relay_role_name(unsigned role) {
    const char *names[]={"vendor-worker","vendor-launcher","vendor-helper","audio-diagnostics","other"};
    return role<5?names[role]:"unknown";
}
static inline int relay_fd(pid_t pid,unsigned descriptor,struct relay_row *row) {
    char path[80],target[PATH_MAX],again[PATH_MAX],line[128]; struct stat info,before,after;
    snprintf(path,sizeof(path),"/proc/%ld/fd/%u",(long)pid,descriptor);
    if(stat(path,&before)||!S_ISREG(before.st_mode)) return -1;
    ssize_t size=readlink(path,target,sizeof(target)-1);
    if(size<=0||size>=(ssize_t)sizeof(target)-1||stat(path,&info)||!S_ISREG(info.st_mode)||
        before.st_dev!=info.st_dev||before.st_ino!=info.st_ino||before.st_nlink!=info.st_nlink) return -1;
    target[size]=0;
    snprintf(path,sizeof(path),"/proc/%ld/fdinfo/%u",(long)pid,descriptor);
    FILE *file=fopen(path,"r"); unsigned flags=0; int found=0,failed=0;
    if(!file) return -1;
    while(fgets(line,sizeof(line),file)) {
        if(!strncmp(line,"flags:",6)) {
            char *end; errno=0; unsigned long value=strtoul(line+6,&end,8);
            while(*end==' '||*end=='\t'||*end=='\n') ++end;
            if(errno||*end||value>UINT_MAX||found) failed=1;
            else { flags=(unsigned)value; found=1; }
        }
    }
    if(ferror(file)) failed=1;
    fclose(file);
    if(failed||!found) return -1;
    snprintf(path,sizeof(path),"/proc/%ld/fd/%u",(long)pid,descriptor);
    ssize_t final_size=readlink(path,again,sizeof(again));
    if(final_size!=size||memcmp(target,again,(size_t)size)||stat(path,&after)||
        after.st_dev!=info.st_dev||after.st_ino!=info.st_ino||after.st_nlink!=info.st_nlink) return -1;
    *row=(struct relay_row){.pid=pid,.descriptor=descriptor,.flags=flags,.kind=relay_classify(target),
        .device=info.st_dev,.inode=info.st_ino,.deleted=info.st_nlink==0,
        .readable=!(flags&O_PATH)&&(flags&O_ACCMODE)!=O_WRONLY,
        .writable=!(flags&O_PATH)&&(flags&O_ACCMODE)!=O_RDONLY};
    return 0;
}
static inline int relay_parse_map(const char *line,struct relay_row *row) {
    unsigned long long low,high,offset,inode; unsigned major_id,minor_id;
    char permission[5]; int used=0;
    if(strlen(line)>=PATH_MAX+256||sscanf(line,"%llx-%llx %4s %llx %x:%x %llu %n",
        &low,&high,permission,&offset,&major_id,&minor_id,&inode,&used)!=7||!used||low>=high||
        strlen(permission)!=4||(permission[0]!='r'&&permission[0]!='-')||
        (permission[1]!='w'&&permission[1]!='-')||(permission[2]!='x'&&permission[2]!='-')||
        (permission[3]!='s'&&permission[3]!='p')) return -1;
    const char *path=line+used; size_t length=strcspn(path,"\n");
    char name[PATH_MAX];
    if(length>=sizeof(name)) return -1;
    memcpy(name,path,length); name[length]=0;
    *row=(struct relay_row){.mapping=1,.device=makedev(major_id,minor_id),.inode=inode,
        .low=low,.high=high,.offset=offset,.readable=permission[0]=='r',.writable=permission[1]=='w',
        .shared=permission[3]=='s',.kind=relay_classify(name),
        .deleted=length>=10&&!strcmp(name+length-10," (deleted)")};
    return 0;
}
static inline int relay_maps(pid_t pid,struct relay_row *rows,unsigned *count) {
    char path[64],line[PATH_MAX+256]; snprintf(path,sizeof(path),"/proc/%ld/maps",(long)pid);
    FILE *file=fopen(path,"r"); *count=0; int failed=0;
    if(!file) return -1;
    while(fgets(line,sizeof(line),file)) {
        struct relay_row row;
        if(!strchr(line,'\n')||relay_parse_map(line,&row)) { failed=1; break; }
        if(!row.inode) continue; /* No inode correlation for anonymous memory. */
        if(*count>=RELAY_MAP_LIMIT) { failed=1; break; }
        row.pid=pid; rows[(*count)++]=row;
    }
    if(ferror(file)) failed=1;
    fclose(file); return failed?-1:0;
}
static inline int relay_fd_matches(const struct relay_row *row) {
    struct relay_row now; struct relay_identity identity;
    return !row->mapping&&!relay_identity(row->pid,&identity)&&relay_same(&row->identity,&identity)&&
        !relay_fd(row->pid,row->descriptor,&now)&&now.device==row->device&&now.inode==row->inode&&
        now.flags==row->flags&&now.deleted==row->deleted;
}
static inline int relay_map_matches(const struct relay_row *row,const struct relay_row *now) {
    return row->mapping&&now->mapping&&row->device==now->device&&row->inode==now->inode&&
        row->low==now->low&&row->high==now->high&&row->offset==now->offset&&row->deleted==now->deleted&&
        row->readable==now->readable&&row->writable==now->writable&&row->shared==now->shared;
}
static inline int relay_compare(const void *a,const void *b) {
    const struct relay_row *x=a,*y=b;
    if(x->device!=y->device) return x->device<y->device?-1:1;
    return x->inode==y->inode?0:x->inode<y->inode?-1:1;
}
static inline void relay_join(struct relay_row *rows,unsigned count) {
    qsort(rows,count,sizeof(*rows),relay_compare);
    for(unsigned start=0;start<count;) {
        unsigned end=start,kind=0,trusted=0; int fallback=0,trusted_fallback=0;
        while(end<count&&!relay_compare(&rows[start],&rows[end])) {
            struct relay_row *row=&rows[end++]; kind|=row->kind;
            if(row->confirmed) trusted|=row->kind;
            if(row->role<4&&row->writable&&(!row->mapping||row->shared)) {
                fallback=1; trusted_fallback|=!!row->confirmed;
            }
        }
        int classified=kind?trusted==kind:trusted_fallback;
        if(!kind&&fallback) kind=RELAY_UNKNOWN_WRITE;
        for(unsigned i=start;i<end;++i) {
            rows[i].kind=kind;
            if(!classified) rows[i].confirmed=0;
        }
        start=end;
    }
}
#endif
