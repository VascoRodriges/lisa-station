/* Lab metadata bookkeeping for TWO preadmitted SDK streams in one private bus.
 * Names identify the SDK GROUP, never a particular socket or authenticated role.
 * The caller proves exclusive channel ownership and fresh driver replies,
 * and retains immutable observer/provider baselines from their admission.
 * Valid distinct C objects, one serial trusted parent, no runtime I/O here. */
#ifndef LISA_SDK_NAME_LEDGER_H
#define LISA_SDK_NAME_LEDGER_H
#include "private_match_snapshot.h"
#define SDK_GROUP_NAMES 2u
struct sdk_name_ledger {unsigned count,active,finished;struct private_match_entry peak[SDK_GROUP_NAMES];};
static inline int sdk_entry_valid(const struct private_match_entry *entry){
    if(!memchr(entry->name,0,sizeof(entry->name))||!match_name(entry->name)||entry->rules>MATCH_RULES)return 0;
    for(unsigned i=0;i<entry->rules;++i){const char *rule=private_match_rule(entry,i);const char *end=memchr(rule,0,MATCH_RULE+1);
        if(!end||!match_utf8((const unsigned char *)rule,(size_t)(end-rule)))return 0;
    }return 1;
}
static inline int sdk_snapshot_valid(const struct private_match_snapshot *snapshot){
    if(!snapshot||snapshot->clients>MATCH_CLIENTS)return 0;
    unsigned rules=0;
    for(unsigned i=0;i<snapshot->clients;++i){if(!sdk_entry_valid(&snapshot->entry[i]))return 0;rules+=snapshot->entry[i].rules;
        for(unsigned j=0;j<i;++j)if(!strcmp(snapshot->entry[i].name,snapshot->entry[j].name))return 0;
    }return rules==snapshot->rules;
}
/* Preserve multiplicity, including two equal serialized rules. */
static inline int sdk_entry_includes(const struct private_match_entry *entry,const struct private_match_entry *prior){
    if(strcmp(entry->name,prior->name)||entry->rules<prior->rules)return 0;
    unsigned used=0;
    for(unsigned i=0;i<prior->rules;++i){unsigned j=0;
        for(;j<entry->rules;++j)if(!(used&(1u<<j))&&!strcmp(private_match_rule(entry,j),private_match_rule(prior,i))){used|=1u<<j;break;}
        if(j==entry->rules)return 0;
    }return 1;
}
static inline int sdk_ledger_valid(const struct sdk_name_ledger *ledger){
    if(!ledger||ledger->count>SDK_GROUP_NAMES||ledger->finished>1||ledger->active&~((1u<<ledger->count)-1u)||
        (ledger->finished&&ledger->active))return 0;
    for(unsigned i=0;i<ledger->count;++i){if(!sdk_entry_valid(&ledger->peak[i]))return 0;
        for(unsigned j=0;j<i;++j)if(!strcmp(ledger->peak[i].name,ledger->peak[j].name))return 0;
    }return 1;
}
/* Failure leaves the ledger unchanged. An absent name retires permanently. */
static inline int sdk_ledger_observe(struct sdk_name_ledger *ledger,const struct private_match_snapshot *snapshot,
    const struct private_match_entry *observer,const struct private_match_entry *provider){
    if(!sdk_ledger_valid(ledger)||ledger->finished||!sdk_snapshot_valid(snapshot)||!observer||!provider||
        !sdk_entry_valid(observer)||!sdk_entry_valid(provider)||!strcmp(observer->name,provider->name))return -1;
    for(unsigned i=0;i<ledger->count;++i)if(!strcmp(ledger->peak[i].name,observer->name)||!strcmp(ledger->peak[i].name,provider->name))return -1;
    const struct private_match_entry *own=private_match_find(snapshot,observer->name),*service=private_match_find(snapshot,provider->name);
    if(!own||!service||own->rules!=observer->rules||service->rules!=provider->rules||
        !sdk_entry_includes(own,observer)||!sdk_entry_includes(service,provider))return -1;
    struct sdk_name_ledger next=*ledger;next.active=0;
    for(unsigned i=0;i<snapshot->clients;++i){const struct private_match_entry *entry=&snapshot->entry[i];
        if(!strcmp(entry->name,observer->name)||!strcmp(entry->name,provider->name))continue;
        unsigned slot=0;for(;slot<ledger->count;++slot)if(!strcmp(entry->name,ledger->peak[slot].name))break;
        if(slot<ledger->count){
            if(!(ledger->active&(1u<<slot))||!sdk_entry_includes(entry,&ledger->peak[slot]))return -1;
        }else{if(next.count==SDK_GROUP_NAMES)return -1;slot=next.count++;}
        next.peak[slot]=*entry;next.active|=1u<<slot;
    }
    *ledger=next;return 0;
}
/* After both SDK streams and the provider close, require ONLY the observer. */
static inline int sdk_ledger_finish(struct sdk_name_ledger *ledger,const struct private_match_snapshot *snapshot,
    const struct private_match_entry *observer){
    if(!sdk_ledger_valid(ledger)||!sdk_snapshot_valid(snapshot)||!observer||!sdk_entry_valid(observer)||snapshot->clients!=1||
        snapshot->entry[0].rules!=observer->rules||!sdk_entry_includes(&snapshot->entry[0],observer))return -1;
    for(unsigned i=0;i<ledger->count;++i)if(!strcmp(ledger->peak[i].name,observer->name))return -1;
    ledger->active=0;ledger->finished=1;return 0;
}
static inline int sdk_ledger_sender(const struct sdk_name_ledger *ledger,const char *name){
    if(!sdk_ledger_valid(ledger)||ledger->finished||!name)return 0;
    for(unsigned i=0;i<ledger->count;++i)if((ledger->active&(1u<<i))&&!strcmp(ledger->peak[i].name,name))return 1;
    return 0;
}
#endif
