/* Exact-flow DROP installer. Never flushes or deletes rules during a closed
 * request. Chains are exclusively created/owned by the trusted caller. */
#ifndef LISA_FLOW_POLICY_H
#define LISA_FLOW_POLICY_H
#include "flow_store.h"
#include "policy_check.h"

#define FLOW_RULE_TEXT 256
static inline int flow_rule(const struct saved_flow *flow,const char *chain,int input,char *text,size_t capacity) {
    char source[INET6_ADDRSTRLEN],destination[INET6_ADDRSTRLEN]; int family;
    if(!flow_valid(flow) || flow_wire(flow,&family,source,destination)) return -1;
    unsigned mask=family==AF_INET?32:128;
    const char *protocol=flow->protocol==IPPROTO_TCP?"tcp":"udp";
    return snprintf(text,capacity,"-A %s -s %s/%u -d %s/%u -p %s -m %s --sport %u --dport %u -j DROP\n",
        chain,input?destination:source,mask,input?source:destination,mask,protocol,protocol,
        ntohs(input?flow->id.idiag_dport:flow->id.idiag_sport),ntohs(input?flow->id.idiag_sport:flow->id.idiag_dport));
}
static inline int flow_chain_name(const struct flow_plan *plan,int input,char *chain,size_t capacity) {
    if(!flow_chain_valid(plan->chain)) return -1;
    int size=snprintf(chain,capacity,"%s%c",plan->chain,input?'I':'O');
    return size>0&&(size_t)size<capacity?0:-1;
}
static inline int flow_tool(int family,char *const *args,char *output,size_t capacity) {
    return policy_capture(family==AF_INET?"/usr/sbin/iptables":"/usr/sbin/ip6tables",args,output,capacity);
}
/* Only a subset of this immutable plan's exact DROP rules may be adopted.
 * An unknown rule, duplicate or ACCEPT prevents completion; no table flush. */
static inline int flow_chain_scan(const struct flow_plan *plan,int family,int input,unsigned char *seen) {
    char chain[32],rules[16384],expected[FLOW_RULE_TEXT],declaration[64];
    if(flow_chain_name(plan,input,chain,sizeof(chain))) return -1;
    char *name=family==AF_INET?"iptables":"ip6tables";
    char *const args[]={name,"-S",chain,NULL};
    if(flow_tool(family,args,rules,sizeof(rules))) return -1;
    snprintf(declaration,sizeof(declaration),"-N %s\n",chain);
    size_t prefix=strlen(declaration);
    if(strncmp(rules,declaration,prefix)) return -1;
    memset(seen,0,FLOW_LIMIT);
    const char *line=rules+prefix;
    while(*line) {
        const char *end=strchr(line,'\n');
        if(!end) return -1;
        size_t size=(size_t)(end-line)+1; int matched=0;
        for(unsigned i=0;i<plan->count;++i) {
            char source[INET6_ADDRSTRLEN],destination[INET6_ADDRSTRLEN]; int wire;
            if(flow_wire(&plan->flows[i],&wire,source,destination)) return -1;
            if(wire!=family) continue;
            int length=flow_rule(&plan->flows[i],chain,input,expected,sizeof(expected));
            if(length<0 || length>=(int)sizeof(expected)) return -1;
            if((size_t)length==size && !memcmp(line,expected,size)) {
                if(seen[i]) return -1;
                seen[i]=1; matched=1; break;
            }
        }
        if(!matched) return -1;
        line=end+1;
    }
    return 0;
}
static inline int flow_hook_first(int family,const char *chain,int input) {
    char rules[16384],expected[64]; char *name=family==AF_INET?"iptables":"ip6tables";
    char *hook=input?"INPUT":"OUTPUT";
    char *const args[]={name,"-S",hook,NULL};
    if(flow_tool(family,args,rules,sizeof(rules))) return 0;
    snprintf(expected,sizeof(expected),"-P %s ",hook);
    if(strncmp(rules,expected,strlen(expected))) return 0;
    const char *first=strchr(rules,'\n');
    snprintf(expected,sizeof(expected),"-A %s -j %s\n",hook,chain);
    return first&&!strncmp(first+1,expected,strlen(expected));
}
static inline int flow_policy_verify(const struct flow_plan *plan) {
    if(!flow_plan_valid(plan)) return -1;
    for(unsigned version=0;version<2;++version) for(int input=0;input<2;++input) {
        int family=version?AF_INET6:AF_INET; unsigned char seen[FLOW_LIMIT]; char chain[32];
        if(flow_chain_name(plan,input,chain,sizeof(chain)) || flow_chain_scan(plan,family,input,seen) ||
            !flow_hook_first(family,chain,input)) return -1;
        for(unsigned i=0;i<plan->count;++i) {
            char source[INET6_ADDRSTRLEN],destination[INET6_ADDRSTRLEN]; int wire;
            if(flow_wire(&plan->flows[i],&wire,source,destination) || (wire==family && !seen[i])) return -1;
        }
    }
    return 0;
}
static inline int flow_policy_apply(const struct flow_plan *plan) {
    if(!flow_plan_valid(plan)) return -1;
    /* Inspect all owned chains before the first mutation. */
    for(unsigned version=0;version<2;++version) for(int input=0;input<2;++input) {
        unsigned char seen[FLOW_LIMIT];
        if(flow_chain_scan(plan,version?AF_INET6:AF_INET,input,seen)) return -1;
    }
    for(unsigned version=0;version<2;++version) for(int input=0;input<2;++input) {
        int family=version?AF_INET6:AF_INET; char chain[32],output[64]; unsigned char seen[FLOW_LIMIT];
        if(flow_chain_name(plan,input,chain,sizeof(chain)) || flow_chain_scan(plan,family,input,seen)) return -1;
        char *name=version?"ip6tables":"iptables";
        for(unsigned i=0;i<plan->count;++i) {
            char source[INET6_ADDRSTRLEN],destination[INET6_ADDRSTRLEN],sport[6],dport[6]; int wire;
            const struct saved_flow *flow=&plan->flows[i];
            if(flow_wire(flow,&wire,source,destination)) return -1;
            if(wire!=family || seen[i]) continue;
            snprintf(sport,sizeof(sport),"%u",ntohs(input?flow->id.idiag_dport:flow->id.idiag_sport));
            snprintf(dport,sizeof(dport),"%u",ntohs(input?flow->id.idiag_sport:flow->id.idiag_dport));
            char *protocol=flow->protocol==IPPROTO_TCP?"tcp":"udp";
            char *const args[]={name,"-A",chain,"-s",input?destination:source,"-d",input?source:destination,
                "-p",protocol,"--sport",sport,"--dport",dport,"-j","DROP",NULL};
            if(flow_tool(family,args,output,sizeof(output))) return -1;
        }
        if(!flow_hook_first(family,chain,input)) {
            char *hook=input?"INPUT":"OUTPUT";
            char *const check[]={name,"-C",hook,"-j",chain,NULL};
            if(!flow_tool(family,check,output,sizeof(output))) return -1;
            char *const add[]={name,"-I",hook,"1","-j",chain,NULL};
            if(flow_tool(family,add,output,sizeof(output))) return -1;
        }
    }
    return flow_policy_verify(plan);
}
#endif
