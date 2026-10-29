/* Explicit administrative Alice return. Compiled-in callbacks must prove the
 * actual closed scope, prepare the new marking epoch and release only its new
 * traffic. No service start, boot auto-resume, stock fallback or privacy claim.
 * Caller must never invoke this executor merely because HA/NAS is unavailable.
 */
#ifndef LISA_OPEN_TRANSITION_H
#define LISA_OPEN_TRANSITION_H
#include "closed_transition.h"
#include "service_gate.h"

enum open_phase { OPEN_REQUESTED, OPEN_PREPARED, OPEN_UNFENCED, OPEN_COMMITTED, OPEN_PERMITTED, OPEN_RELEASED, OPEN_COMPLETE };
enum open_result { OPEN_OK, OPEN_BUSY, OPEN_CONFLICT, OPEN_INVALID, OPEN_IO, OPEN_PREPARE, OPEN_RELEASE, OPEN_VERIFY, OPEN_RECOVERY };
struct open_record { uint64_t base_revision; char boot[37]; enum open_phase phase; };
struct open_ops {
    int (*deny)(void *context);
    int (*stop)(void *context);
    int (*prepare)(void *context,uint64_t revision,const char *boot);
    int (*release)(void *context);
    int (*verify)(void *context);
    void (*checkpoint)(void *context,enum open_phase phase);
    void *context;
};

static inline const char *open_phase_name(enum open_phase phase) {
    const char *names[]={"requested","prepared","closed_fence_cleared","intent_committed","permit_published","policy_released","complete"};
    return (unsigned)phase<sizeof(names)/sizeof(names[0])?names[phase]:NULL;
}
static inline int open_format(char *text,size_t capacity,const struct open_record *record) {
    if(!record->base_revision||record->base_revision==UINT64_MAX||!gate_boot_valid(record->boot)||!open_phase_name(record->phase))return -1;
    return snprintf(text,capacity,"LISA_OPEN_V1 %" PRIu64 " %s %s\n",record->base_revision,record->boot,open_phase_name(record->phase));
}
/* 1 absent, 0 canonical/private, -1 unsafe/corrupt. Presence always blocks boot
 * and new starts, independently of whether this diagnostic parser succeeds. */
static inline int open_read(int state,uid_t owner,struct open_record *record) {
    if(!store_directory_valid(state,owner))return -1;
    int fd=openat(state,"opening.request",O_RDONLY|O_NOFOLLOW|O_CLOEXEC|O_NONBLOCK);
    if(fd<0)return errno==ENOENT?1:-1;
    if(!store_file_valid(fd,owner)){close(fd);return -1;}
    char text[192],canonical[192],phase[32],boot[37]={0};size_t used=0;int failed=0;
    while(used<sizeof(text)-1){
        ssize_t count=read(fd,text+used,sizeof(text)-1-used);
        if(count<0&&errno==EINTR)continue;
        if(count<0){failed=1;break;}
        if(!count)break;
        used+=(size_t)count;
    }
    if(close(fd))failed=1;
    if(failed||!used||used==sizeof(text)-1||memchr(text,0,used))return -1;
    text[used]=0;unsigned long long revision;int consumed=0;
    if(sscanf(text,"LISA_OPEN_V1 %llu %36s %31s\n%n",&revision,boot,phase,&consumed)!=3||consumed!=(int)used)return -1;
    struct open_record parsed={.base_revision=revision,.phase=OPEN_REQUESTED};memcpy(parsed.boot,boot,37);
    while(parsed.phase<=OPEN_COMPLETE&&strcmp(phase,open_phase_name(parsed.phase)))++parsed.phase;
    if(open_format(canonical,sizeof(canonical),&parsed)!=(int)used||memcmp(text,canonical,used))return -1;
    *record=parsed;return 0;
}
/* Caller retains both transition.lock and mode.lock exclusively. A different
 * prior journal may be replaced only after an explicitly completed close. */
static inline int open_publish(int state,uid_t owner,const struct open_record *record,int supersede) {
    struct open_record previous;int existing=open_read(state,owner,&previous);
    if(existing<0||(existing==1&&record->phase!=OPEN_REQUESTED)||
        (existing==0&&!supersede&&(previous.base_revision!=record->base_revision||strcmp(previous.boot,record->boot))))return -1;
    char text[192],temporary[64];int size=open_format(text,sizeof(text),record);uint64_t nonce;
    if(size<0||size>=(int)sizeof(text)||getrandom(&nonce,sizeof(nonce),0)!=(ssize_t)sizeof(nonce))return -1;
    snprintf(temporary,sizeof(temporary),".open-%" PRIx64 ".tmp",nonce);
    int fd=openat(state,temporary,O_WRONLY|O_CREAT|O_EXCL|O_NOFOLLOW|O_CLOEXEC,0600);
    if(fd<0)return -1;
    int failed=store_write_all(fd,text,(size_t)size)||fsync(fd);
    if(close(fd))failed=1;
    if(!failed&&renameat(state,temporary,state,"opening.request"))failed=1;
    if(!failed&&fsync(state))failed=1;
    if(failed)unlinkat(state,temporary,0);
    return failed?-1:0;
}
static inline int open_checkpoint(int state,uid_t owner,struct open_record *record,enum open_phase phase,const struct open_ops *ops) {
    record->phase=phase;
    if(open_publish(state,owner,record,0))return -1;
    if(ops->checkpoint)ops->checkpoint(ops->context,phase);
    return 0;
}
static inline int open_permit_publish(int runtime,uid_t owner,uint64_t revision,const char *boot) {
    char text[160],temporary[64];uint64_t nonce;
    if(!store_directory_valid(runtime,owner)||!revision||!gate_boot_valid(boot)||
        getrandom(&nonce,sizeof(nonce),0)!=(ssize_t)sizeof(nonce))return -1;
    int size=snprintf(text,sizeof(text),"LISA_VENDOR_PERMIT_V1 %" PRIu64 " %s\n",revision,boot);
    if(size<0||size>=(int)sizeof(text))return -1;
    snprintf(temporary,sizeof(temporary),".permit-%" PRIx64 ".tmp",nonce);
    int fd=openat(runtime,temporary,O_WRONLY|O_CREAT|O_EXCL|O_NOFOLLOW|O_CLOEXEC,0600);
    if(fd<0)return -1;
    int failed=store_write_all(fd,text,(size_t)size)||fsync(fd);
    if(close(fd))failed=1;
    /* Never overwrite a permit, symlink or unknown object. */
    if(!failed&&linkat(runtime,temporary,runtime,"vendor.permit",0))failed=1;
    if(unlinkat(runtime,temporary,0))failed=1;
    if(!failed&&fsync(runtime))failed=1;
    return failed?-1:0;
}
static inline void open_safety_attempt(int runtime,const struct open_ops *ops) {
    /* Deny before revocation/teardown, including after a partial policy release.
     * Pending admission remains fenced even if denial cannot be reverified. */
    (void)ops->deny(ops->context);(void)close_revoke(runtime);(void)ops->stop(ops->context);
}
static inline int open_closed_record_matches(const struct close_record *closed,const struct mode_record *mode) {
    return close_completed_matches(closed,mode);
}

static inline enum open_result open_execute(int state,int runtime,uid_t owner,uint64_t base_revision,
                                             const char *boot,const struct open_ops *ops) {
    if(!ops||!ops->deny||!ops->stop||!ops->prepare||!ops->release||!ops->verify||!base_revision||
        base_revision>=UINT64_MAX-1||!gate_boot_valid(boot)||!store_directory_valid(state,owner)||
        !store_directory_valid(runtime,owner))return OPEN_INVALID;
    int lock=openat(state,"transition.lock",O_RDWR|O_CREAT|O_NOFOLLOW|O_NONBLOCK|O_CLOEXEC,0600);
    if(lock<0)return OPEN_IO;
    if(!store_file_valid(lock,owner)){close(lock);return OPEN_INVALID;}
    if(flock(lock,LOCK_EX|LOCK_NB)){close(lock);return OPEN_BUSY;}
    enum open_result result=OPEN_INVALID;int mode_lock=-1,published=0,supersede=0;
    struct open_record previous,pending={.base_revision=base_revision,.phase=OPEN_REQUESTED};memcpy(pending.boot,boot,37);
    if(mode_store_fault_pending(state,owner)){result=OPEN_RECOVERY;goto done;}
    int existing=open_read(state,owner,&previous);
    if(existing<0){open_safety_attempt(runtime,ops);goto done;}
    mode_lock=openat(state,"mode.lock",O_RDWR|O_CREAT|O_NOFOLLOW|O_NONBLOCK|O_CLOEXEC,0600);
    if(mode_lock<0){result=OPEN_IO;goto done;}
    if(!store_file_valid(mode_lock,owner))goto done;
    if(flock(mode_lock,LOCK_EX|LOCK_NB)){result=OPEN_BUSY;goto done;}
    struct mode_record mode;struct close_record closed;int fence=close_read(state,owner,&closed);
    if(mode_store_read(state,owner,&mode)!=STORE_OK||fence<0){
        if(existing==0)open_safety_attempt(runtime,ops);
        goto done;
    }
    int retry=existing==0&&previous.base_revision==base_revision&&!strcmp(previous.boot,boot);
    if(!retry){
        if(mode.revision!=base_revision||mode.requested==LISA_MODE_ALICE){result=OPEN_CONFLICT;goto done;}
        if(existing==0){
            if(previous.base_revision>=mode.revision||fence!=0||!open_closed_record_matches(&closed,&mode)){
                result=OPEN_RECOVERY;goto done;
            }
            supersede=1;
        }
    }else if(!((mode.revision==base_revision&&mode.requested!=LISA_MODE_ALICE)||
        (mode.revision==base_revision+1&&mode.requested==LISA_MODE_ALICE))){result=OPEN_CONFLICT;goto done;}
    if(fence==0&&!open_closed_record_matches(&closed,&mode))goto done;
    if(open_publish(state,owner,&pending,supersede)){result=OPEN_IO;goto failed;}
    published=1;
    if(ops->checkpoint)ops->checkpoint(ops->context,OPEN_REQUESTED);
    if(ops->deny(ops->context)||close_revoke(runtime)||ops->stop(ops->context)||
        ops->prepare(ops->context,base_revision+1,boot)){result=OPEN_PREPARE;goto failed;}
    if(open_checkpoint(state,owner,&pending,OPEN_PREPARED,ops)){result=OPEN_IO;goto failed;}
    /* Only a completed, matching close can be retired, and only inside this
     * explicit request. The opening journal remains the boot/start fence. */
    if(fence==0&&(unlinkat(state,"closed.request",0)||fsync(state))){result=OPEN_IO;goto failed;}
    if(open_checkpoint(state,owner,&pending,OPEN_UNFENCED,ops)){result=OPEN_IO;goto failed;}
    if(mode.revision==base_revision&&mode_store_commit_locked(state,owner,base_revision,LISA_MODE_ALICE,&mode)!=STORE_OK){result=OPEN_IO;goto failed;}
    if(open_checkpoint(state,owner,&pending,OPEN_COMMITTED,ops)){result=OPEN_IO;goto failed;}
    if(open_permit_publish(runtime,owner,base_revision+1,boot)||
        open_checkpoint(state,owner,&pending,OPEN_PERMITTED,ops)){result=OPEN_IO;goto failed;}
    if(ops->release(ops->context)){result=OPEN_RELEASE;goto failed;}
    if(open_checkpoint(state,owner,&pending,OPEN_RELEASED,ops)){result=OPEN_IO;goto failed;}
    if(ops->verify(ops->context)){result=OPEN_VERIFY;goto failed;}
    if(unlinkat(state,"opening.request",0)||fsync(state)){result=OPEN_IO;goto failed;}
    if(ops->checkpoint)ops->checkpoint(ops->context,OPEN_COMPLETE);
    result=OPEN_OK;goto done;
failed:
    /* If final directory fsync failed after unlink, recreate a durable fence as
     * far as possible. A failed transaction never removes its safety journal. */
    if(published&&mode_store_open_pending(state,owner)==0){pending.phase=OPEN_REQUESTED;(void)open_publish(state,owner,&pending,0);}
    open_safety_attempt(runtime,ops);
done:
    if(mode_lock>=0)close(mode_lock);
    close(lock);return result;
}
#endif
