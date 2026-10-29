/* Staged common supervisor decision path, not an installed daemon. The caller
 * supplies fixed compiled adapters for actual policy, reserved emergency denial
 * and actor inventory. A successful result covers only that declared scope.
 */
#ifndef LISA_SUPERVISOR_RECOVERY_H
#define LISA_SUPERVISOR_RECOVERY_H
#include "pending_recovery.h"

enum supervisor_scope { SUPERVISOR_SCOPE_SOUND, SUPERVISOR_SCOPE_BUSY, SUPERVISOR_SCOPE_BROKEN };
enum supervisor_result { SUPERVISOR_IDLE, SUPERVISOR_RETRY, SUPERVISOR_RECOVERED,
                         SUPERVISOR_FAULT_CLOSED, SUPERVISOR_FAULT_INCOMPLETE };
struct supervisor_closure {int barrier_verified,permit_revoked,fence_synced;};
struct supervisor_ops {
    /* Invoked with the validated exclusive transition lease. A policy-reader
     * lease is acquired here, after TRANS; valid contention returns BUSY. */
    enum supervisor_scope (*inspect_scope)(void *,const struct recovery_plan *);
    /* Emergency adapter must publish the fault, verify the independent barrier
     * and only then attempt revocation. Never repairs corrupt intent journals. */
    struct supervisor_closure (*emergency)(void *);
    int (*stop)(void *);
    int (*absent)(void *);
    const struct close_ops *close;
    void *context;
};
static inline enum supervisor_result supervisor_fault(const struct supervisor_ops *ops){
    struct supervisor_closure closed=ops->emergency(ops->context);
    /* Even an absent inventory cannot replace an unverified network barrier.
     * No stop callback on a failed/unknown barrier, including negative flags. */
    if(closed.barrier_verified!=1)return SUPERVISOR_FAULT_INCOMPLETE;
    int stopped=ops->stop(ops->context),absent=ops->absent(ops->context);
    return closed.permit_revoked==1&&closed.fence_synced==1&&!stopped&&!absent?
        SUPERVISOR_FAULT_CLOSED:SUPERVISOR_FAULT_INCOMPLETE;
}
static inline enum supervisor_result supervisor_attempt(int state,int runtime,uid_t owner,
    const struct supervisor_ops *ops,struct recovery_plan *plan){
    if(!ops||!plan||!ops->inspect_scope||!ops->emergency||!ops->stop||!ops->absent||
        !ops->close||!ops->close->deny||!ops->close->stop||!ops->close->verify)return SUPERVISOR_FAULT_INCOMPLETE;
    *plan=(struct recovery_plan){RECOVERY_INVALID,0,LISA_MODE_PAUSED};
    struct recovery_lease lease={.descriptor=-1};enum recovery_action action=recovery_lock(state,owner,&lease);
    if(action==RECOVERY_BUSY)return SUPERVISOR_RETRY;
    /* A damaged lock is not contention. Cached denial cannot depend on being
     * able to read the damaged primary journals or mint a new intent revision. */
    if(action!=RECOVERY_CLEAR)return supervisor_fault(ops);
    action=recovery_inspect(&lease,plan);
    if(action==RECOVERY_INVALID||mode_store_fault_pending(state,owner)){
        enum supervisor_result result=supervisor_fault(ops);recovery_unlock(&lease);return result;
    }
    enum supervisor_scope scope=ops->inspect_scope(ops->context,plan);
    if(scope==SUPERVISOR_SCOPE_BUSY){recovery_unlock(&lease);return SUPERVISOR_RETRY;}
    if(scope!=SUPERVISOR_SCOPE_SOUND){
        enum supervisor_result result=supervisor_fault(ops);recovery_unlock(&lease);return result;
    }
    recovery_unlock(&lease);
    if(action==RECOVERY_CLEAR)return SUPERVISOR_IDLE;
    /* The existing executor reacquires TRANS and revalidates the expected
     * revision/fence. Another explicit request may have won the intervening
     * race; failures are reinspected on the next tick, never opened as recovery. */
    enum close_result result=close_execute(state,runtime,owner,plan->base_revision,plan->target,ops->close);
    return result==CLOSE_OK?SUPERVISOR_RECOVERED:SUPERVISOR_RETRY;
}
#endif
