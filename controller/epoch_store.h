/* Staged durable ownership/mutation journal. NOT a policy installer, admission
 * permit or proof that a saved phase matches the kernel. Before first owner
 * publication the caller must verify unused labels/absent chains and actors.
 * Every later mutation still requires actual policy/inventory verification.
 */
#ifndef LISA_EPOCH_STORE_H
#define LISA_EPOCH_STORE_H
#include "boot_ledger.h"
#include "epoch_policy.h"
#include <sys/syscall.h>
#include <linux/fs.h>

enum epoch_phase { EPOCH_RESERVED, EPOCH_CLOSED, EPOCH_ARMING, EPOCH_ARMED, EPOCH_OPENING, EPOCH_OPEN, EPOCH_DENYING };
struct epoch_owner {char boot[37],chain[32];uint64_t initial_revision;};
struct epoch_record {uint64_t revision;unsigned epoch,previous;enum epoch_phase phase;};
struct epoch_lease {int descriptor,runtime;uid_t owner;};
static inline const char *epoch_phase_name(enum epoch_phase phase){
    const char *names[]={"reserved","closed","arming","armed","opening","open","denying"};
    return (unsigned)phase<sizeof(names)/sizeof(names[0])?names[phase]:NULL;
}
static inline int epoch_owner_format(const struct epoch_owner *record,char *text,size_t capacity){
    char validation[1024];
    if(!record||!text||!record->initial_revision||record->initial_revision==UINT64_MAX||
        !gate_boot_valid(record->boot)||policy_expected_groups(record->chain,composite_groups,COMPOSITE_ROLE_COUNT,validation,sizeof(validation))<0)return -1;
    int size=snprintf(text,capacity,"LISA_EPOCH_OWNER_V1 %s %s %" PRIu64 " " EPOCH_MASK_TEXT "\n",
        record->boot,record->chain,record->initial_revision);
    return size<0||(size_t)size>=capacity?-1:size;
}
static inline int epoch_record_format(const struct epoch_owner *owner,const struct epoch_record *record,char *text,size_t capacity){
    char validation[192];
    if(!record||!text||epoch_owner_format(owner,validation,sizeof(validation))<0||!record->revision||
        record->revision==UINT64_MAX||!epoch_valid(record->epoch)||!epoch_phase_name(record->phase))return -1;
    if(!record->previous){
        if(record->revision!=owner->initial_revision||record->epoch!=1||
            (record->phase!=EPOCH_RESERVED&&record->phase!=EPOCH_CLOSED&&record->phase!=EPOCH_DENYING))return -1;
    }else if(!epoch_valid(record->previous)||record->epoch==record->previous||
        record->revision<=owner->initial_revision||record->phase==EPOCH_RESERVED)return -1;
    int size=snprintf(text,capacity,"LISA_EPOCH_STATE_V1 %" PRIu64 " %u %u %s\n",
        record->revision,record->epoch,record->previous,epoch_phase_name(record->phase));
    return size<0||(size_t)size>=capacity?-1:size;
}
/* Fixed internal filenames only. 1 absent, 0 private bytes, -1 unsafe/I/O. */
static inline int epoch_store_read_file(int runtime,uid_t owner,const char *name,char *text,size_t capacity){
    if(!name||(strcmp(name,"epoch.owner")&&strcmp(name,"epoch.state"))||!text||!store_directory_valid(runtime,owner)||capacity<2)return -1;
    int fd=openat(runtime,name,O_RDONLY|O_NOFOLLOW|O_NONBLOCK|O_CLOEXEC);if(fd<0)return errno==ENOENT?1:-1;
    if(!boot_ledger_file(fd,owner)){close(fd);return -1;}
    size_t used=0;int failed=0;
    while(used<capacity-1){
        ssize_t count=read(fd,text+used,capacity-1-used);
        if(count<0&&errno==EINTR)continue;
        if(count<0){failed=1;break;}
        if(!count)break;
        used+=(size_t)count;
    }
    if(close(fd))failed=1;
    if(failed||!used||used==capacity-1||memchr(text,0,used))return -1;
    text[used]=0;return 0;
}
static inline int epoch_owner_read(int runtime,uid_t owner,struct epoch_owner *record){
    char text[192],expected[192];int found=epoch_store_read_file(runtime,owner,"epoch.owner",text,sizeof(text));
    if(found)return found;
    struct epoch_owner parsed={0};unsigned long long revision;int consumed=0;
    if(sscanf(text,"LISA_EPOCH_OWNER_V1 %36s %31s %llu " EPOCH_MASK_TEXT "\n%n",parsed.boot,parsed.chain,&revision,&consumed)!=3||
        consumed!=(int)strlen(text))return -1;
    parsed.initial_revision=revision;
    if(epoch_owner_format(&parsed,expected,sizeof(expected))<0||strcmp(text,expected))return -1;
    *record=parsed;return 0;
}
static inline int epoch_record_read(int runtime,uid_t owner,const struct epoch_owner *expected_owner,struct epoch_record *record){
    struct epoch_owner actual;char validation[192],expected[192];
    if(epoch_owner_read(runtime,owner,&actual)||epoch_owner_format(&actual,validation,sizeof(validation))<0||
        epoch_owner_format(expected_owner,expected,sizeof(expected))<0||strcmp(validation,expected))return -1;
    char text[192],phase[32];int found=epoch_store_read_file(runtime,owner,"epoch.state",text,sizeof(text));
    if(found)return found;
    unsigned long long revision;int consumed=0;struct epoch_record parsed={0};
    if(sscanf(text,"LISA_EPOCH_STATE_V1 %llu %u %u %31s\n%n",&revision,&parsed.epoch,&parsed.previous,phase,&consumed)!=4||
        consumed!=(int)strlen(text))return -1;
    parsed.revision=revision;
    while(parsed.phase<=EPOCH_DENYING&&strcmp(phase,epoch_phase_name(parsed.phase)))++parsed.phase;
    if(epoch_record_format(expected_owner,&parsed,expected,sizeof(expected))<0||strcmp(text,expected))return -1;
    *record=parsed;return 0;
}
/* EX/NB serializes policy operations; caller keeps runtime open and must not
 * transfer a writable lease to actors or concurrent workers. */
static inline int epoch_store_lock(int runtime,uid_t owner,struct epoch_lease *lease){
    if(!lease||lease->descriptor>=0||!store_directory_valid(runtime,owner))return -1;
    int fd=openat(runtime,"epoch.lock",O_RDWR|O_CREAT|O_NOFOLLOW|O_NONBLOCK|O_CLOEXEC,0600);
    if(fd<0)return -1;
    if(!boot_ledger_file(fd,owner)||flock(fd,LOCK_EX|LOCK_NB)){close(fd);return -1;}
    *lease=(struct epoch_lease){fd,runtime,owner};return 0;
}
static inline int epoch_store_lease_valid(const struct epoch_lease *lease){
    struct stat held,path;
    return lease&&lease->descriptor>=0&&store_directory_valid(lease->runtime,lease->owner)&&
        boot_ledger_file(lease->descriptor,lease->owner)&&!fstat(lease->descriptor,&held)&&
        !fstatat(lease->runtime,"epoch.lock",&path,AT_SYMLINK_NOFOLLOW)&&held.st_dev==path.st_dev&&held.st_ino==path.st_ino&&
        !flock(lease->descriptor,LOCK_EX|LOCK_NB);
}
static inline void epoch_store_unlock(struct epoch_lease *lease){
    if(lease&&lease->descriptor>=0){close(lease->descriptor);lease->descriptor=-1;lease->runtime=-1;}
}
/* No-overwrite atomic rename avoids an immutable-owner hardlink window. A
 * crash may leave an unpublished temporary, never a live owner with two links.
 * Unsupported no-replace rename fails; there is no overwrite fallback. */
static inline int epoch_store_write(const struct epoch_lease *lease,const char *name,const char *text,int immutable){
    uint64_t nonce;char temporary[64];
    if(!name||!text||(strcmp(name,"epoch.owner")&&strcmp(name,"epoch.state"))||
        immutable!=!strcmp(name,"epoch.owner")||!epoch_store_lease_valid(lease)||boot_ledger_nonce(&nonce))return -1;
    snprintf(temporary,sizeof(temporary),".epoch-%" PRIx64 ".tmp",nonce);
    int fd=openat(lease->runtime,temporary,O_WRONLY|O_CREAT|O_EXCL|O_NOFOLLOW|O_CLOEXEC,0600);if(fd<0)return -1;
    int failed=store_write_all(fd,text,strlen(text))||fsync(fd);
    if(close(fd))failed=1;
    if(!failed&&(immutable?syscall(SYS_renameat2,lease->runtime,temporary,lease->runtime,name,RENAME_NOREPLACE):
        renameat(lease->runtime,temporary,lease->runtime,name)))failed=1;
    if(failed&&unlinkat(lease->runtime,temporary,0))failed=1;
    if(!failed&&fsync(lease->runtime))failed=1;
    return failed?-1:0;
}
static inline int epoch_owner_publish(const struct epoch_lease *lease,const struct epoch_owner *record){
    char text[192],existing[192];struct epoch_owner previous;
    if(!epoch_store_lease_valid(lease)||epoch_owner_format(record,text,sizeof(text))<0)return -1;
    int found=epoch_owner_read(lease->runtime,lease->owner,&previous);
    if(found<0)return -1;
    if(found==0)return epoch_owner_format(&previous,existing,sizeof(existing))<0||strcmp(text,existing)?-1:
        fsync(lease->runtime);
    struct stat info;
    if(!fstatat(lease->runtime,"epoch.state",&info,AT_SYMLINK_NOFOLLOW)||errno!=ENOENT)return -1;
    return epoch_store_write(lease,"epoch.owner",text,1);
}
static inline int epoch_record_transition(const struct epoch_record *before,const struct epoch_record *after){
    if(before->revision!=after->revision||before->epoch!=after->epoch||before->previous!=after->previous)
        return before->phase==EPOCH_CLOSED&&after->phase==EPOCH_ARMING&&after->revision>before->revision&&
            after->previous==before->epoch&&after->epoch!=before->epoch;
    if(before->phase==after->phase)return 1;
    if(after->phase==EPOCH_DENYING)return 1;
    if(before->phase==EPOCH_RESERVED&&after->phase==EPOCH_CLOSED)return 1;
    if(before->phase==EPOCH_DENYING&&after->phase==EPOCH_CLOSED)return 1;
    if((before->phase==EPOCH_CLOSED||before->phase==EPOCH_ARMING)&&after->phase==EPOCH_ARMED)return after->previous!=0;
    if(before->phase==EPOCH_ARMED&&after->phase==EPOCH_OPENING)return 1;
    return before->phase==EPOCH_OPENING&&after->phase==EPOCH_OPEN;
}
static inline int epoch_record_publish(const struct epoch_lease *lease,const struct epoch_owner *owner,const struct epoch_record *record){
    char text[192];struct epoch_record previous;
    if(!epoch_store_lease_valid(lease)||epoch_record_format(owner,record,text,sizeof(text))<0)return -1;
    int found=epoch_record_read(lease->runtime,lease->owner,owner,&previous);
    if(found<0||(found==1&&record->phase!=EPOCH_RESERVED)||(found==0&&!epoch_record_transition(&previous,record)))return -1;
    return epoch_store_write(lease,"epoch.state",text,0);
}
#endif
