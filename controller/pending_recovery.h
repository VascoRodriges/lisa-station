/* Staged local-supervisor decision primitive. It never grants admission or
 * resumes an opening. CLEAR only means no unfinished journal action; the
 * caller must separately verify live policy, permit and actor inventory.
 * Caller retains a validated exclusive transition lease while inspecting.
 */
#ifndef LISA_PENDING_RECOVERY_H
#define LISA_PENDING_RECOVERY_H
#include "open_transition.h"

enum recovery_action { RECOVERY_CLEAR, RECOVERY_FINISH_CLOSE, RECOVERY_CANCEL_OPEN, RECOVERY_INVALID, RECOVERY_BUSY };
struct recovery_plan {enum recovery_action action;uint64_t base_revision;enum lisa_mode target;};
struct recovery_lease {int descriptor,state;uid_t owner;};
enum recovery_result { RECOVERY_IDLE, RECOVERY_RETRY, RECOVERY_DONE, RECOVERY_FAULT };
static inline enum recovery_action recovery_lock(int state,uid_t owner,struct recovery_lease *lease){
    if(!lease||lease->descriptor>=0||!store_directory_valid(state,owner))return RECOVERY_INVALID;
    int fd=openat(state,"transition.lock",O_RDWR|O_CREAT|O_NOFOLLOW|O_NONBLOCK|O_CLOEXEC,0600);
    if(fd<0)return RECOVERY_INVALID;
    if(!store_file_valid(fd,owner)){close(fd);return RECOVERY_INVALID;}
    if(flock(fd,LOCK_EX|LOCK_NB)){int busy=errno==EWOULDBLOCK;close(fd);return busy?RECOVERY_BUSY:RECOVERY_INVALID;}
    *lease=(struct recovery_lease){fd,state,owner};return RECOVERY_CLEAR;
}
static inline void recovery_unlock(struct recovery_lease *lease){
    if(lease&&lease->descriptor>=0){close(lease->descriptor);lease->descriptor=-1;lease->state=-1;}
}
static inline int recovery_lease_valid(const struct recovery_lease *lease){
    struct stat held,path;
    return lease&&lease->descriptor>=0&&store_directory_valid(lease->state,lease->owner)&&
        store_file_valid(lease->descriptor,lease->owner)&&!fstat(lease->descriptor,&held)&&
        !fstatat(lease->state,"transition.lock",&path,AT_SYMLINK_NOFOLLOW)&&held.st_dev==path.st_dev&&held.st_ino==path.st_ino&&
        !flock(lease->descriptor,LOCK_EX|LOCK_NB);
}
static inline enum recovery_action recovery_inspect(const struct recovery_lease *lease,struct recovery_plan *plan){
    if(!plan)return RECOVERY_INVALID;
    *plan=(struct recovery_plan){RECOVERY_INVALID,0,LISA_MODE_PAUSED};
    if(!recovery_lease_valid(lease))return plan->action;
    struct mode_record mode={0};struct close_record closed={0};struct open_record opening={0};
    if(mode_store_read(lease->state,lease->owner,&mode)!=STORE_OK)return plan->action;
    int cf=close_read(lease->state,lease->owner,&closed),of=open_read(lease->state,lease->owner,&opening);
    if(cf<0)return plan->action; /* Preserve unknown journals; do not fabricate intent. */
    if(cf==0&&closed.phase!=CLOSE_COMPLETE){
        if(mode.revision!=closed.base_revision&&
            !(mode.revision==closed.base_revision+1&&mode.requested==closed.target))return plan->action;
        *plan=(struct recovery_plan){RECOVERY_FINISH_CLOSE,closed.base_revision,closed.target};return plan->action;
    }
    if(of<0)return plan->action;
    if(cf==0&&!close_completed_matches(&closed,&mode))return plan->action;
    if(of==0){
        /* A completed newer close already cancelled this opener. Keeping its
         * fence does not authorize repeating a close/revision on every poll. */
        if(mode.requested!=LISA_MODE_ALICE&&cf==0&&opening.base_revision<mode.revision&&
            closed.base_revision>=opening.base_revision){
            plan->action=RECOVERY_CLEAR;return plan->action;
        }
        if(mode.revision==UINT64_MAX)return plan->action;
        if((mode.revision==opening.base_revision&&mode.requested!=LISA_MODE_ALICE)||
            (mode.revision==opening.base_revision+1&&mode.requested==LISA_MODE_ALICE)){
            *plan=(struct recovery_plan){RECOVERY_CANCEL_OPEN,mode.revision,LISA_MODE_PAUSED};return plan->action;
        }
        return plan->action;
    }
    plan->action=RECOVERY_CLEAR;return plan->action;
}
/* Release the inspection lease before the existing close executor acquires
 * its own. A competing request is revalidated there by revision/fence checks;
 * BUSY/conflict cause another inspection, never an automatic opening. */
static inline enum recovery_result recovery_attempt(int state,int runtime,uid_t owner,
    const struct close_ops *ops,struct recovery_plan *plan){
    if(!plan||!ops||!ops->deny||!ops->stop||!ops->verify)return RECOVERY_FAULT;
    struct recovery_lease lease={.descriptor=-1};enum recovery_action action=recovery_lock(state,owner,&lease);
    if(action==RECOVERY_BUSY)return RECOVERY_RETRY;
    if(action!=RECOVERY_CLEAR)return RECOVERY_FAULT;
    action=recovery_inspect(&lease,plan);recovery_unlock(&lease);
    if(action==RECOVERY_CLEAR)return RECOVERY_IDLE;
    if(action==RECOVERY_INVALID){close_safety_attempt(runtime,ops);return RECOVERY_FAULT;}
    enum close_result result=close_execute(state,runtime,owner,plan->base_revision,plan->target,ops);
    return result==CLOSE_OK?RECOVERY_DONE:result==CLOSE_BUSY||result==CLOSE_CONFLICT?RECOVERY_RETRY:RECOVERY_FAULT;
}
#endif
