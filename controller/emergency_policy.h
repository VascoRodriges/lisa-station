/* Independent pre-reserved denial path. Not installed or whole-device privacy.
 * The scope must be reserved under the primary epoch lease before admission.
 * A later failure can use this immutable owner without reading damaged primary
 * journals. No adoption, rule deletion, general internet ban or unlatching API.
 */
#ifndef LISA_EMERGENCY_POLICY_H
#define LISA_EMERGENCY_POLICY_H
#include "epoch_mutation.h"

struct emergency_cache {struct epoch_owner scope;uid_t owner;int ready;};
struct emergency_names {char group[32],label[32];};
static inline int emergency_names(const struct epoch_owner *scope,struct emergency_names *names){
    struct label_policy_names primary;char text[192];
    if(!names||epoch_owner_format(scope,text,sizeof(text))<0||label_policy_names(scope->chain,&primary))return -1;
    size_t size=strlen(primary.group)+1;
    memcpy(names->group,primary.group,size);memcpy(names->group,"LISACE_",7);
    memcpy(names->label,primary.group,size);memcpy(names->label,"LISACF_",7);return 0;
}
static inline int emergency_format(const struct epoch_owner *scope,int fault,char *text,size_t capacity){
    char validate[192];
    if(epoch_owner_format(scope,validate,sizeof(validate))<0||(fault!=0&&fault!=1))return -1;
    int size=snprintf(text,capacity,"LISA_%s_V1 %s %s %" PRIu64 " " EPOCH_MASK_TEXT "\n",
        fault?"FAULT":"EMERGENCY",scope->boot,scope->chain,scope->initial_revision);
    return size<0||(size_t)size>=capacity?-1:size;
}
/* 1 absent, 0 matching private record, -1 unsafe/corrupt/mismatched. */
static inline int emergency_read(int directory,uid_t owner,int fault,const struct epoch_owner *scope){
    char expected[192],actual[193];int size=emergency_format(scope,fault,expected,sizeof(expected));
    if(size<0||!store_directory_valid(directory,owner))return -1;
    int fd=openat(directory,fault?"fault.request":"emergency.owner",O_RDONLY|O_CLOEXEC|O_NOFOLLOW|O_NONBLOCK);
    if(fd<0)return errno==ENOENT?1:-1;
    int valid=boot_ledger_file(fd,owner);ssize_t used;
    do{used=read(fd,actual,sizeof(actual));}while(used<0&&errno==EINTR);
    if(close(fd))valid=0;
    return valid&&used==size&&!memcmp(expected,actual,(size_t)size)?0:-1;
}
static inline int emergency_publish(int directory,uid_t owner,int fault,const struct epoch_owner *scope){
    char text[192],temporary[64];uint64_t nonce;int size=emergency_format(scope,fault,text,sizeof(text));
    if(size<0||!store_directory_valid(directory,owner)||boot_ledger_nonce(&nonce))return -1;
    int found=emergency_read(directory,owner,fault,scope);if(found<0)return -1;
    const char *name=fault?"fault.request":"emergency.owner";
    if(found==0){
        int fd=openat(directory,name,O_RDONLY|O_NOFOLLOW|O_NONBLOCK|O_CLOEXEC);if(fd<0)return -1;
        int failed=!boot_ledger_file(fd,owner)||fsync(fd);if(close(fd))failed=1;
        return failed||fsync(directory)?-1:0;
    }
    snprintf(temporary,sizeof(temporary),".emergency-%" PRIx64 ".tmp",nonce);
    int fd=openat(directory,temporary,O_WRONLY|O_CREAT|O_EXCL|O_NOFOLLOW|O_CLOEXEC,0600);if(fd<0)return -1;
    int failed=store_write_all(fd,text,(size_t)size)||fsync(fd);if(close(fd))failed=1;
    if(!failed&&syscall(SYS_renameat2,directory,temporary,directory,name,RENAME_NOREPLACE))failed=1;
    if(failed)(void)unlinkat(directory,temporary,0);
    if(!failed&&fsync(directory))failed=1;
    return failed?-1:0;
}
static inline int emergency_expected(const struct emergency_names *names,unsigned kind,char *text,size_t capacity){
    if(!names||!text||kind>1)return -1;
    const char *chain=kind?names->label:names->group;
    int size=snprintf(text,capacity,"-N %s\n",chain);if(size<0||(size_t)size>=capacity)return -1;
    for(unsigned i=0;i<(kind?1u:COMPOSITE_ROLE_COUNT);++i){
        int more=kind?snprintf(text+size,capacity-(size_t)size,
            "-A %s -m connmark ! --mark 0x0/" EPOCH_MASK_TEXT " -j DROP\n",chain):
            snprintf(text+size,capacity-(size_t)size,"-A %s -m owner --gid-owner %u -j DROP\n",chain,composite_groups[i]);
        if(more<0||(size_t)more>=capacity-(size_t)size)return -1;
        size+=more;
    }
    return size;
}
/* This validator never moves a reference across unrelated rules or accepts
 * a foreign reference. Unhooked complete chains are the normal armed state. */
static inline int emergency_snapshot(const struct emergency_cache *cache,int require_full,int fresh,
                                     unsigned present[2][2][4],unsigned hooks[2][2][2]){
    struct emergency_names names;if(!cache||emergency_names(&cache->scope,&names))return -1;
    memset(present,0,2*2*4*sizeof(unsigned));memset(hooks,0,2*2*2*sizeof(unsigned));
    for(unsigned family=0;family<2;++family){
        char all[65536];char *name=family?"ip6tables":"iptables";
        const char *program=family?"/usr/sbin/ip6tables":"/usr/sbin/iptables";
        char *const whole[]={name,"-t","filter","-S",NULL};
        if(policy_capture(program,whole,all,sizeof(all)))return -1;
        char copy[65536];strcpy(copy,all);char *save=NULL;
        for(char *line=strtok_r(copy,"\n",&save);line;line=strtok_r(NULL,"\n",&save)){
            const char *chains[]={names.group,names.label};
            for(unsigned kind=0;kind<2;++kind)if(strstr(line,chains[kind])){
                if(fresh)return -1;
                char prefix[64],declaration[64],out[64],in[64];
                snprintf(prefix,sizeof(prefix),"-A %s ",chains[kind]);snprintf(declaration,sizeof(declaration),"-N %s",chains[kind]);
                snprintf(out,sizeof(out),"-A OUTPUT -j %s",chains[kind]);snprintf(in,sizeof(in),"-A INPUT -j %s",chains[kind]);
                if(strncmp(line,prefix,strlen(prefix))&&strcmp(line,declaration)&&strcmp(line,out)&&(!kind||strcmp(line,in)))return -1;
            }
        }
        for(unsigned kind=0;kind<2;++kind){
            char expected[1024],actual[8192],declaration[64];const char *chain=kind?names.label:names.group;
            char *const read[]={name,"-t","filter","-S",(char*)chain,NULL};
            if(emergency_expected(&names,kind,expected,sizeof(expected))<0)return -1;
            if(policy_capture(program,read,actual,sizeof(actual))){
                snprintf(declaration,sizeof(declaration),"-N %s\n",chain);
                if(require_full||strstr(all,declaration))return -1;
                strcpy(actual,declaration);
            }
            if(boot_policy_subset(actual,expected,present[family][kind])!=(kind?1:4))return -1;
            if(require_full&&strcmp(actual,expected))return -1;
        }
        for(unsigned input=0;input<2;++input){
            char actual[8192],*hook=input?"INPUT":"OUTPUT";
            const char *targets[]={input?names.label:names.group,names.label};
            char *const read[]={name,"-t","filter","-S",hook,NULL};
            if(policy_capture(program,read,actual,sizeof(actual))||
                boot_policy_hook_subset(actual,hook,targets,input?1:2,hooks[family][input]))return -1;
        }
        /* Reject references from every other table, including inactive chains. */
        char *const saved[]={family?"ip6tables-save":"iptables-save",NULL};
        if(policy_capture(family?"/usr/sbin/ip6tables-save":"/usr/sbin/iptables-save",saved,all,sizeof(all)))return -1;
        char *table=NULL;save=NULL;
        for(char *line=strtok_r(all,"\n",&save);line;line=strtok_r(NULL,"\n",&save)){
            if(line[0]=='*')table=line+1;
            if((strstr(line,names.group)||strstr(line,names.label))&&(!table||strcmp(table,"filter")))return -1;
        }
    }
    return 0;
}
static inline int emergency_armed(const struct emergency_cache *cache,int hooked){
    unsigned present[2][2][4],hooks[2][2][2];
    if(!cache||!cache->ready||emergency_snapshot(cache,1,0,present,hooks))return 0;
    for(unsigned family=0;family<2;++family)for(unsigned input=0;input<2;++input)
        for(unsigned i=0;i<(input?1u:2u);++i)if(hooks[family][input][i]!=(unsigned)hooked)return 0;
    return 1;
}
static inline int emergency_reserve(struct epoch_mutation *primary,struct emergency_cache *cache){
    if(!primary||!cache||epoch_mutation_load(primary)||primary->record.phase!=EPOCH_CLOSED||!epoch_mutation_verified(primary,1))return -1;
    *cache=(struct emergency_cache){primary->owner,primary->lease->owner,0};
    unsigned present[2][2][4],hooks[2][2][2];struct emergency_names names;
    int found=emergency_read(primary->lease->runtime,cache->owner,0,&cache->scope);
    if(found<0||emergency_names(&cache->scope,&names)||emergency_snapshot(cache,0,found==1,present,hooks))return -1;
    for(unsigned f=0;f<2;++f)for(unsigned h=0;h<2;++h)if(hooks[f][h][0]||hooks[f][h][1])return -1;
    if(emergency_publish(primary->lease->runtime,cache->owner,0,&cache->scope))return -1;
    for(unsigned family=0;family<2;++family)for(unsigned kind=0;kind<2;++kind){
        char *name=family?"ip6tables":"iptables",*chain=kind?names.label:names.group,actual[8192];
        char *const read[]={name,"-t","filter","-S",chain,NULL};
        if(policy_capture(family?"/usr/sbin/ip6tables":"/usr/sbin/iptables",read,actual,sizeof(actual))){
            char *const create[]={name,"-t","filter","-N",chain,NULL};if(boot_policy_command(family,create))return -1;
        }
        for(unsigned i=0;i<(kind?1u:4u);++i)if(!present[family][kind][i]){
            char position[4],group[16];snprintf(position,sizeof(position),"%u",i+1);snprintf(group,sizeof(group),"%u",composite_groups[i]);
            char *const drop[]={name,"-t","filter","-I",chain,position,"-m","owner","--gid-owner",group,"-j","DROP",NULL};
            char *const label[]={name,"-t","filter","-I",chain,position,"-m","connmark","!","--mark","0x0/" EPOCH_MASK_TEXT,"-j","DROP",NULL};
            if(boot_policy_command(family,kind?label:drop))return -1;
        }
    }
    cache->ready=1;if(!emergency_armed(cache,0)){cache->ready=0;return -1;}return 0;
}
/* Caller serializes admission. Publication precedes hooks; hooks precede permit
 * revocation/actor shutdown. A failed publication still attempts selective
 * denial, but cannot be reported as durably closed. Never repairs primary files. */
static inline int emergency_activate(const struct emergency_cache *cache,int state,int runtime){
    if(!cache||!cache->ready)return -1;
    int durable=emergency_publish(state,cache->owner,1,&cache->scope)==0;
    unsigned present[2][2][4],hooks[2][2][2];struct emergency_names names;
    if(emergency_names(&cache->scope,&names)||emergency_snapshot(cache,1,0,present,hooks))return -1;
    for(unsigned family=0;family<2;++family)for(unsigned input=0;input<2;++input){
        char *name=family?"ip6tables":"iptables",*hook=input?"INPUT":"OUTPUT";
        char *targets[]={input?names.label:names.group,names.label};
        for(unsigned i=0;i<(input?1u:2u);++i)if(!hooks[family][input][i]){
            char position[4];snprintf(position,sizeof(position),"%u",i+1);
            char *const insert[]={name,"-t","filter","-I",hook,position,"-j",targets[i],NULL};
            if(boot_policy_command(family,insert))return -1;
        }
    }
    if(!emergency_armed(cache,1))return -1;
    int revoked=close_revoke(runtime)==0;
    return durable&&revoked?0:-1;
}
#endif
