/* Canonical declared-role conntrack label policy. This verifier is not evidence
 * that labels preceded socket creation, nor an installer/old-flow migration. */
#ifndef LISA_LABEL_POLICY_H
#define LISA_LABEL_POLICY_H
#include "policy_check.h"
#include "composite_roles.h"

#define ROLE_LABEL_MARK "0x40000000/0x40000000"
struct label_policy_names { char group[32],mark[32],deny[32]; };
static inline int label_policy_names(const char *group,struct label_policy_names *names) {
    char validation[1024];
    if(!group||!names) return -1;
    size_t length=strlen(group);
    if(length<8||length>27) return -1;
    if(policy_expected_groups(group,composite_groups,COMPOSITE_ROLE_COUNT,validation,sizeof(validation))<0) return -1;
    memcpy(names->group,group,length+1);
    memcpy(names->mark,group,length+1);memcpy(names->mark,"LISACM_",7);
    memcpy(names->deny,group,length+1);memcpy(names->deny,"LISACL_",7);
    return 0;
}
static inline int label_policy_expected(const struct label_policy_names *names,int marking,char *text,size_t capacity) {
    struct label_policy_names canonical;
    if(!names||label_policy_names(names->group,&canonical)||strcmp(names->mark,canonical.mark)||strcmp(names->deny,canonical.deny)) return -1;
    int size=snprintf(text,capacity,"-N %s\n",marking?names->mark:names->deny);
    if(size<0||(size_t)size>=capacity) return -1;
    if(marking) {
        for(unsigned i=0;i<COMPOSITE_ROLE_COUNT;++i) {
            int more=snprintf(text+size,capacity-(size_t)size,"-A %s -m owner --gid-owner %u -j CONNMARK --set-xmark " ROLE_LABEL_MARK "\n",names->mark,composite_groups[i]);
            if(more<0||(size_t)more>=capacity-(size_t)size) return -1;
            size+=more;
        }
    } else {
        int more=snprintf(text+size,capacity-(size_t)size,"-A %s -m connmark --mark " ROLE_LABEL_MARK " -j DROP\n",names->deny);
        if(more<0||(size_t)more>=capacity-(size_t)size) return -1;
        size+=more;
    }
    return size;
}
/* Existing unrelated hooks may follow the owned prefix. A jump inserted before
 * or between these hooks must fail verification, even when DROP counts grow. */
static inline int label_policy_hook(const struct label_policy_names *names,const char *rules,const char *hook,int output,int marking) {
    if(!rules||!hook) return 0;
    char policy[64],expected[256];
    snprintf(policy,sizeof(policy),"-P %s ",hook);
    if(strncmp(rules,policy,strlen(policy))) return 0;
    const char *first=strchr(rules,'\n');
    if(!first) return 0;
    if(marking) snprintf(expected,sizeof(expected),"-A OUTPUT -j %s\n",names->mark);
    else if(output) snprintf(expected,sizeof(expected),"-A OUTPUT -j %s\n-A OUTPUT -j %s\n",names->group,names->deny);
    else snprintf(expected,sizeof(expected),"-A INPUT -j %s\n",names->deny);
    return !strncmp(first+1,expected,strlen(expected));
}
static inline int label_policy_marking_verified(const char *group) {
    struct label_policy_names names;
    if(label_policy_names(group,&names)) return 0;
    const char *programs[]={"/usr/sbin/iptables","/usr/sbin/ip6tables"};
    for(unsigned i=0;i<2;++i) {
        char *name=i?"ip6tables":"iptables"; char rules[8192],expected[2048];
        char *const mark[]={name,"-t","mangle","-S",names.mark,NULL};
        char *const hook[]={name,"-t","mangle","-S","OUTPUT",NULL};
        if(label_policy_expected(&names,1,expected,sizeof(expected))<0||policy_capture(programs[i],mark,rules,sizeof(rules))||strcmp(rules,expected)||
            policy_capture(programs[i],hook,rules,sizeof(rules))||!label_policy_hook(&names,rules,"OUTPUT",1,1)) return 0;
    }
    return 1;
}
static inline int label_policy_verified(const char *group) {
    struct label_policy_names names;
    if(label_policy_names(group,&names)||!label_policy_marking_verified(group)||
        !policy_groups_denied(group,composite_groups,COMPOSITE_ROLE_COUNT)) return 0;
    const char *programs[]={"/usr/sbin/iptables","/usr/sbin/ip6tables"};
    for(unsigned i=0;i<2;++i) {
        char *name=i?"ip6tables":"iptables"; char rules[8192],expected[2048];
        char *const mark[]={name,"-t","mangle","-S",names.mark,NULL};
        char *const deny[]={name,"-S",names.deny,NULL};
        char *const mark_hook[]={name,"-t","mangle","-S","OUTPUT",NULL};
        char *const output[]={name,"-S","OUTPUT",NULL};
        char *const input[]={name,"-S","INPUT",NULL};
        if(label_policy_expected(&names,1,expected,sizeof(expected))<0||policy_capture(programs[i],mark,rules,sizeof(rules))||strcmp(rules,expected)||
            label_policy_expected(&names,0,expected,sizeof(expected))<0||policy_capture(programs[i],deny,rules,sizeof(rules))||strcmp(rules,expected)||
            policy_capture(programs[i],mark_hook,rules,sizeof(rules))||!label_policy_hook(&names,rules,"OUTPUT",1,1)||
            policy_capture(programs[i],output,rules,sizeof(rules))||!label_policy_hook(&names,rules,"OUTPUT",1,0)||
            policy_capture(programs[i],input,rules,sizeof(rules))||!label_policy_hook(&names,rules,"INPUT",0,0)) return 0;
    }
    return 1;
}
#endif
