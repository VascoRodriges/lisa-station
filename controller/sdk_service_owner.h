/* Pure bookkeeping for one reviewed PRIVATE lab service. Fresh driver replies,
 * complete frames and exclusive SDK group admission are caller obligations.
 * This grants no role, channel, name or endpoint permission. Distinct objects. */
#ifndef LISA_SDK_SERVICE_OWNER_H
#define LISA_SDK_SERVICE_OWNER_H
#include "sdk_name_ledger.h"
#define SDK_SERVICE_NAME "ru.yandex.quasar"
struct sdk_service_owner {unsigned observed,retired;char name[MATCH_NAME];};
static inline int sdk_owner_valid(const struct sdk_service_owner *state){
    if(!state||state->observed>1||state->retired>1||!memchr(state->name,0,sizeof(state->name)))return 0;
    return state->observed?match_name(state->name):!state->retired&&!state->name[0];
}
/* Absence before first acquisition is not acquisition evidence. Owner changes
 * or disappearance during the live phase stop the epoch, without state reuse. */
static inline int sdk_owner_observe(struct sdk_service_owner *state,const struct sdk_name_ledger *names,const char *owner){
    if(!sdk_owner_valid(state)||state->retired||!sdk_ledger_valid(names)||names->finished)return -1;
    if(!owner)return state->observed?-1:0;
    if(!sdk_ledger_sender(names,owner)||(state->observed&&strcmp(state->name,owner)))return -1;
    strcpy(state->name,owner);state->observed=1;return 0;
}
/* Only an explicit fresh NameHasNoOwner after finished group retirement counts. */
static inline int sdk_owner_retire(struct sdk_service_owner *state,const struct sdk_name_ledger *names,int absent){
    if(!sdk_owner_valid(state)||!state->observed||!sdk_ledger_valid(names)||!names->finished||names->active||names->count!=2||absent!=1)return -1;
    unsigned found=0;for(unsigned i=0;i<names->count;++i)if(!strcmp(state->name,names->peak[i].name))found=1;
    if(!found)return -1;
    state->retired=1;return 0;
}
#endif
