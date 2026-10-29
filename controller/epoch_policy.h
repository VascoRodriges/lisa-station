/* Staged replacement for the single-bit lab label policy. NOT installed or
 * admitted by station-service yet. A trusted caller must reserve the whole
 * namespace before its first flow, serialize changes and retain old denials.
 * Never infer ownership from these generated strings or a conntrack snapshot.
 */
#ifndef LISA_EPOCH_POLICY_H
#define LISA_EPOCH_POLICY_H
#include "label_policy.h"

#define EPOCH_MASK 0xff000000u
#define EPOCH_MASK_TEXT "0xff000000"
static inline int epoch_valid(unsigned epoch){return epoch>0&&epoch<256;}
static inline int epoch_policy_expected(const struct label_policy_names *names,unsigned kind,
                                        unsigned epoch,int closed,char *text,size_t capacity){
    struct label_policy_names canonical;
    if(!names||!text||!capacity||!epoch_valid(epoch)||kind>2||(closed!=0&&closed!=1)||
        label_policy_names(names->group,&canonical)||strcmp(names->mark,canonical.mark)||strcmp(names->deny,canonical.deny))return -1;
    const char *chain=kind==0?names->group:kind==1?names->mark:names->deny;
    int size=snprintf(text,capacity,"-N %s\n",chain);
    if(size<0||(size_t)size>=capacity)return -1;
    if(kind==0||kind==1){
        if(kind==0&&!closed)return size;
        for(unsigned i=0;i<COMPOSITE_ROLE_COUNT;++i){
            int more;
            if(kind==0)more=snprintf(text+size,capacity-(size_t)size,"-A %s -m owner --gid-owner %u -j DROP\n",chain,composite_groups[i]);
            else more=snprintf(text+size,capacity-(size_t)size,
                "-A %s -m owner --gid-owner %u -m connmark --mark 0x0/" EPOCH_MASK_TEXT " -j CONNMARK --set-xmark 0x%x/" EPOCH_MASK_TEXT "\n",
                chain,composite_groups[i],epoch<<24);
            if(more<0||(size_t)more>=capacity-(size_t)size)return -1;
            size+=more;
        }
    }else{
        int more;
        if(closed)more=snprintf(text+size,capacity-(size_t)size,"-A %s -m connmark ! --mark 0x0/" EPOCH_MASK_TEXT " -j DROP\n",chain);
        else more=snprintf(text+size,capacity-(size_t)size,
            "-A %s -m connmark --mark 0x0/" EPOCH_MASK_TEXT " -j RETURN\n"
            "-A %s -m connmark --mark 0x%x/" EPOCH_MASK_TEXT " -j RETURN\n-A %s -j DROP\n",chain,chain,epoch<<24,chain);
        if(more<0||(size_t)more>=capacity-(size_t)size)return -1;
        size+=more;
    }
    return size;
}
/* Snapshot used only to reject reuse of a retained label. Labels can appear
 * after a snapshot: the caller must already hold its private admission lock,
 * verify absent actors and the current closed policy before choosing a mark.
 * Zero is unrelated traffic and is never claimed, dropped or rewritten here. */
static inline int epoch_conntrack_used(FILE *file,unsigned char used[256]){
    if(!file||!used)return -1;
    memset(used,0,256);char line[8192];unsigned rows=0;
    while(fgets(line,sizeof(line),file)){
        if(++rows>65536||!strchr(line,'\n'))return -1;
        char *mark=strstr(line," mark="),*end;
        if(!mark||mark[6]<'0'||mark[6]>'9'||strstr(mark+1," mark="))return -1;
        errno=0;unsigned long long value=strtoull(mark+6,&end,10);
        if(errno||end==mark+6||(*end!=' '&&*end!='\n')||value>UINT32_MAX)return -1;
        unsigned epoch=(unsigned)((value&EPOCH_MASK)>>24);
        if(epoch)used[epoch]=1;
    }
    return ferror(file)?-1:0;
}
static inline unsigned epoch_next_unused(const unsigned char used[256],unsigned previous){
    if(!used||previous>255)return 0;
    for(unsigned offset=1;offset<=255;++offset){
        unsigned candidate=(previous+offset-1)%255+1;
        if(candidate!=previous&&!used[candidate])return candidate;
    }
    return 0; /* Exhaustion remains closed; never purge unrelated/live flows. */
}
static inline int epoch_policy_verified(const char *group,unsigned epoch,int closed){
    struct label_policy_names names;
    if(label_policy_names(group,&names)||!epoch_valid(epoch)||(closed!=0&&closed!=1))return 0;
    for(unsigned family=0;family<2;++family){
        const char *program=family?"/usr/sbin/ip6tables":"/usr/sbin/iptables";char *name=family?"ip6tables":"iptables";
        for(unsigned kind=0;kind<3;++kind){
            char expected[2048],actual[8192];char *chain=kind==0?names.group:kind==1?names.mark:names.deny;
            char *const args[]={name,"-t",kind==1?"mangle":"filter","-S",chain,NULL};
            if(epoch_policy_expected(&names,kind,epoch,closed,expected,sizeof(expected))<0||
                policy_capture(program,args,actual,sizeof(actual))||strcmp(actual,expected))return 0;
        }
        const char *hooks[]={"OUTPUT","OUTPUT","INPUT"};
        for(unsigned hook=0;hook<3;++hook){
            char actual[8192];char *const args[]={name,"-t",hook==0?"mangle":"filter","-S",(char*)hooks[hook],NULL};
            if(policy_capture(program,args,actual,sizeof(actual))||!label_policy_hook(&names,actual,hooks[hook],hook!=2,hook==0))return 0;
        }
    }
    return 1;
}
#endif
