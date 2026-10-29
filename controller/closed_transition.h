/* Durable closed-request transaction. Compiled-in callbacks must establish and
 * verify the declared scope; completion here is never whole-device privacy.
 * No Alice/open transition and no automatic removal of the persistent fence.
 */
#ifndef LISA_CLOSED_TRANSITION_H
#define LISA_CLOSED_TRANSITION_H
#include "mode_store.h"

enum close_phase { CLOSE_REQUESTED, CLOSE_DENIED, CLOSE_REVOKED, CLOSE_COMMITTED, CLOSE_STOPPED, CLOSE_COMPLETE };
enum close_result { CLOSE_OK, CLOSE_BUSY, CLOSE_CONFLICT, CLOSE_INVALID, CLOSE_IO, CLOSE_POLICY, CLOSE_STOP, CLOSE_VERIFY };
struct close_record { uint64_t base_revision; enum lisa_mode target; enum close_phase phase; };
struct close_ops {
    int (*deny)(void *context);
    int (*stop)(void *context);
    int (*verify)(void *context);
    void (*checkpoint)(void *context,enum close_phase phase);
    void *context;
};

static inline const char *close_phase_name(enum close_phase phase) {
    const char *names[]={"requested","network_denied","permit_revoked","intent_committed","actors_stopped","complete"};
    return (unsigned)phase<sizeof(names)/sizeof(names[0])?names[phase]:NULL;
}

static inline int close_format(char *text,size_t capacity,const struct close_record *record) {
    if(!record->base_revision || record->base_revision==UINT64_MAX ||
        (record->target!=LISA_MODE_LISA && record->target!=LISA_MODE_PAUSED) || !close_phase_name(record->phase)) return -1;
    return snprintf(text,capacity,"LISA_CLOSE_V1 %" PRIu64 " %s %s\n",record->base_revision,
                    mode_name(record->target),close_phase_name(record->phase));
}

/* 1 means missing; corrupt or unsafe files are not equivalent to no request. */
static inline int close_read(int state,uid_t owner,struct close_record *record) {
    if(!store_directory_valid(state,owner)) return -1;
    int file=openat(state,"closed.request",O_RDONLY|O_NOFOLLOW|O_CLOEXEC|O_NONBLOCK);
    if(file<0) return errno==ENOENT?1:-1;
    if(!store_file_valid(file,owner)) { close(file); return -1; }
    char text[160],canonical[160],mode[16],phase[32]; size_t used=0;
    while(used<sizeof(text)-1) {
        ssize_t count=read(file,text+used,sizeof(text)-1-used);
        if(count<0 && errno==EINTR) continue;
        if(count<0) { close(file); return -1; }
        if(!count) break;
        used+=(size_t)count;
    }
    close(file); text[used]=0;
    if(!used || used==sizeof(text)-1 || memchr(text,0,used)) return -1;
    unsigned long long revision; int consumed=0;
    if(sscanf(text,"LISA_CLOSE_V1 %llu %15s %31s\n%n",&revision,mode,phase,&consumed)!=3 || consumed!=(int)used) return -1;
    enum lisa_mode target=!strcmp(mode,"lisa")?LISA_MODE_LISA:!strcmp(mode,"paused")?LISA_MODE_PAUSED:LISA_MODE_ALICE;
    enum close_phase parsed=CLOSE_REQUESTED;
    while(parsed<=CLOSE_COMPLETE && strcmp(phase,close_phase_name(parsed))) ++parsed;
    struct close_record next={revision,target,parsed};
    if(close_format(canonical,sizeof(canonical),&next)!=(int)used || memcmp(text,canonical,used)) return -1;
    *record=next; return 0;
}

static inline int close_completed_matches(const struct close_record *closed,const struct mode_record *mode) {
    return closed->phase==CLOSE_COMPLETE&&closed->base_revision<UINT64_MAX&&
        closed->base_revision+1==mode->revision&&closed->target==mode->requested&&mode->requested!=LISA_MODE_ALICE;
}

static inline int close_publish(int state,uid_t owner,const struct close_record *record) {
    struct close_record previous;
    int existing=close_read(state,owner,&previous);
    if(existing<0 || (existing==1 && record->phase!=CLOSE_REQUESTED)) return -1;
    if(!existing&&(previous.base_revision!=record->base_revision||previous.target!=record->target)) {
        struct mode_record mode;
        /* A new explicit closed request atomically replaces only a completed
         * fence matching the current closed intent. There is no unfenced gap.
         * Advancing even an unchanged target invalidates a cancelled opener. */
        if(record->phase!=CLOSE_REQUESTED||mode_store_read(state,owner,&mode)!=STORE_OK||
            mode.revision!=record->base_revision||!close_completed_matches(&previous,&mode))return -1;
    }
    char text[160],temporary[64]; uint64_t nonce;
    int size=close_format(text,sizeof(text),record);
    if(size<0 || size>=(int)sizeof(text) || getrandom(&nonce,sizeof(nonce),0)!=(ssize_t)sizeof(nonce)) return -1;
    snprintf(temporary,sizeof(temporary),".close-%" PRIx64 ".tmp",nonce);
    int file=openat(state,temporary,O_WRONLY|O_CREAT|O_EXCL|O_NOFOLLOW|O_CLOEXEC,0600);
    if(file<0) return -1;
    int failed=store_write_all(file,text,(size_t)size)||fsync(file);
    if(close(file)) failed=1;
    if(!failed && renameat(state,temporary,state,"closed.request")) failed=1;
    if(!failed && fsync(state)) failed=1;
    if(failed) unlinkat(state,temporary,0);
    return failed?-1:0;
}

static inline int close_revoke(int runtime) {
    if(unlinkat(runtime,"vendor.permit",0) && errno!=ENOENT) return -1;
    return fsync(runtime);
}

/* On any internal failure keep the fence, retry denial, revoke and stop as far
 * as possible. Never reopen a policy or publish an Alice permit as rollback. */
static inline void close_safety_attempt(int runtime,const struct close_ops *ops) {
    (void)ops->deny(ops->context);
    (void)close_revoke(runtime);
    (void)ops->stop(ops->context);
}

static inline int close_checkpoint(int state,uid_t owner,struct close_record *record,
                                   enum close_phase phase,const struct close_ops *ops) {
    record->phase=phase;
    if(close_publish(state,owner,record)) return -1;
    if(ops->checkpoint) ops->checkpoint(ops->context,phase);
    return 0;
}

static inline enum close_result close_execute(int state,int runtime,uid_t owner,uint64_t base_revision,
                                              enum lisa_mode target,const struct close_ops *ops) {
    if(!ops || !ops->deny || !ops->stop || !ops->verify || !base_revision || base_revision==UINT64_MAX ||
        (target!=LISA_MODE_LISA && target!=LISA_MODE_PAUSED) ||
        !store_directory_valid(state,owner) || !store_directory_valid(runtime,owner)) return CLOSE_INVALID;
    int lock=openat(state,"transition.lock",O_RDWR|O_CREAT|O_NONBLOCK|O_NOFOLLOW|O_CLOEXEC,0600);
    if(lock<0) return CLOSE_IO;
    if(!store_file_valid(lock,owner)) { close(lock); return CLOSE_INVALID; }
    if(flock(lock,LOCK_EX|LOCK_NB)) { close(lock); return CLOSE_BUSY; }
    enum close_result result=CLOSE_INVALID;
    struct close_record pending; struct mode_record current;
    int existing=close_read(state,owner,&pending);
    if(existing<0) { close_safety_attempt(runtime,ops); goto done; }
    if(mode_store_read(state,owner,&current)!=STORE_OK) {
        if(existing==0) close_safety_attempt(runtime,ops);
        goto done;
    }
    if(existing==1) {
        if(current.revision!=base_revision) { result=CLOSE_CONFLICT; goto done; }
        pending=(struct close_record){base_revision,target,CLOSE_REQUESTED};
        if(close_checkpoint(state,owner,&pending,CLOSE_REQUESTED,ops)) {
            result=CLOSE_IO; close_safety_attempt(runtime,ops); goto done;
        }
    } else if(pending.base_revision!=base_revision || pending.target!=target) {
        if(current.revision!=base_revision||!close_completed_matches(&pending,&current)){
            result=CLOSE_CONFLICT; close_safety_attempt(runtime,ops); goto done;
        }
        pending=(struct close_record){base_revision,target,CLOSE_REQUESTED};
        if(close_checkpoint(state,owner,&pending,CLOSE_REQUESTED,ops)){
            result=CLOSE_IO;close_safety_attempt(runtime,ops);goto done;
        }
    }
    if(ops->deny(ops->context)) { result=CLOSE_POLICY; close_safety_attempt(runtime,ops); goto done; }
    if(close_checkpoint(state,owner,&pending,CLOSE_DENIED,ops)) { result=CLOSE_IO; goto failed; }
    if(close_revoke(runtime) || close_checkpoint(state,owner,&pending,CLOSE_REVOKED,ops)) { result=CLOSE_IO; goto failed; }
    if(mode_store_read(state,owner,&current)!=STORE_OK) { result=CLOSE_INVALID; goto failed; }
    if(current.revision==base_revision) {
        enum store_result changed=mode_store_request(state,owner,base_revision,target,&current);
        if(changed!=STORE_OK) {
            result=changed==STORE_BUSY?CLOSE_BUSY:changed==STORE_CONFLICT?CLOSE_CONFLICT:CLOSE_IO;
            goto failed;
        }
    } else if(current.revision!=base_revision+1 || current.requested!=target) {
        result=CLOSE_CONFLICT; goto failed;
    }
    if(close_checkpoint(state,owner,&pending,CLOSE_COMMITTED,ops)) { result=CLOSE_IO; goto failed; }
    if(ops->stop(ops->context)) { result=CLOSE_STOP; goto failed; }
    if(close_checkpoint(state,owner,&pending,CLOSE_STOPPED,ops)) { result=CLOSE_IO; goto failed; }
    if(ops->verify(ops->context)) { result=CLOSE_VERIFY; goto failed; }
    if(close_checkpoint(state,owner,&pending,CLOSE_COMPLETE,ops)) { result=CLOSE_IO; goto failed; }
    result=CLOSE_OK;
    goto done;
failed:
    close_safety_attempt(runtime,ops);
done:
    close(lock); return result;
}
#endif
