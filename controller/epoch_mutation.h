/* Journalled selective policy mutation. Not an installed boot hook or complete
 * vendor isolation. The caller retains its epoch lease and, for opening, the
 * exclusive intent/transition leases. No stock service or general internet ban.
 */
#ifndef LISA_EPOCH_MUTATION_H
#define LISA_EPOCH_MUTATION_H
#include "epoch_store.h"
#include "open_transition.h"

struct epoch_mutation {
    struct epoch_lease *lease;
    struct epoch_owner owner;
    struct epoch_record record;
    unsigned steps;
    void (*checkpoint)(void *context,unsigned step);
    void *context;
};
struct epoch_chain_shape {int missing,head;unsigned present[4],newer[4],tails;};
struct epoch_snapshot {struct epoch_chain_shape chains[2][3];unsigned hooks[2][3][2];};
static inline void epoch_mutation_checkpoint(struct epoch_mutation *mutation){
    ++mutation->steps;if(mutation->checkpoint)mutation->checkpoint(mutation->context,mutation->steps);
}
static inline int epoch_mutation_command(struct epoch_mutation *mutation,unsigned family,char *const *args){
    if(boot_policy_command(family,args))return -1;
    epoch_mutation_checkpoint(mutation);return 0;
}
static inline int epoch_mutation_phase(struct epoch_mutation *mutation,enum epoch_phase phase){
    mutation->record.phase=phase;
    if(epoch_record_publish(mutation->lease,&mutation->owner,&mutation->record))return -1;
    epoch_mutation_checkpoint(mutation);return 0;
}
static inline int epoch_mutation_load(struct epoch_mutation *mutation){
    return !mutation||!epoch_store_lease_valid(mutation->lease)||
        epoch_record_read(mutation->lease->runtime,mutation->lease->owner,&mutation->owner,&mutation->record)?-1:0;
}
static inline int epoch_mark_subset(const char *actual,const struct label_policy_names *names,
                                   const struct epoch_record *record,struct epoch_chain_shape *shape){
    char a[2048],old[2048],next[2048],*al[5]={0},*ol[5]={0},*nl[5]={0};
    if(!actual||strlen(actual)>=sizeof(a)||epoch_policy_expected(names,1,record->epoch,1,next,sizeof(next))<0||
        epoch_policy_expected(names,1,record->previous?record->previous:record->epoch,1,old,sizeof(old))<0)return -1;
    strcpy(a,actual);int ac=boot_policy_lines(a,al,5),oc=boot_policy_lines(old,ol,5),nc=boot_policy_lines(next,nl,5);
    if(ac<1||oc!=5||nc!=5||strcmp(al[0],nl[0]))return -1;
    unsigned cursor=1;
    for(int i=1;i<ac;++i){
        while(cursor<5&&strcmp(al[i],nl[cursor])&&strcmp(al[i],ol[cursor]))++cursor;
        if(cursor==5)return -1;
        shape->present[cursor-1]=1;shape->newer[cursor-1]=!strcmp(al[i],nl[cursor]);++cursor;
    }
    return 0;
}
/* A closed first DROP protects any ordered subset left while deleting the
 * known open tail. Without it only a complete open chain or fresh empty chain
 * is accepted. Unknown/reordered/duplicate rules are never removed/adopted. */
static inline int epoch_deny_subset(const char *actual,const struct label_policy_names *names,
                                   unsigned epoch,struct epoch_chain_shape *shape){
    char a[2048],closed[2048],opened[2048],*al[5]={0},*cl[2]={0},*ol[4]={0};
    if(!actual||strlen(actual)>=sizeof(a)||epoch_policy_expected(names,2,epoch,1,closed,sizeof(closed))<0||
        epoch_policy_expected(names,2,epoch,0,opened,sizeof(opened))<0)return -1;
    strcpy(a,actual);int ac=boot_policy_lines(a,al,5),cc=boot_policy_lines(closed,cl,2),oc=boot_policy_lines(opened,ol,4);
    if(ac<1||cc!=2||oc!=4||strcmp(al[0],cl[0]))return -1;
    int first=1;
    if(ac>1&&!strcmp(al[1],cl[1])){shape->head=1;first=2;}
    unsigned cursor=1;
    for(int i=first;i<ac;++i){
        while(cursor<4&&strcmp(al[i],ol[cursor]))++cursor;
        if(cursor==4)return -1;
        ++shape->tails;++cursor;
    }
    return !shape->head&&shape->tails&&shape->tails!=3?-1:0;
}
static inline int epoch_chain_snapshot(unsigned family,const struct label_policy_names *names,unsigned kind,
                                       char *actual,size_t capacity,int *missing){
    char *name=family?"ip6tables":"iptables",*table=kind==1?"mangle":"filter";
    const char *program=family?"/usr/sbin/ip6tables":"/usr/sbin/iptables";
    char *chain=(char*)(kind==0?names->group:kind==1?names->mark:names->deny);
    char *const read[]={name,"-t",table,"-S",chain,NULL};*missing=0;
    if(!policy_capture(program,read,actual,capacity))return 0;
    /* A failed per-chain query is not absence evidence. Check the table before
     * trying a no-overwrite chain creation in our durably reserved namespace. */
    char all[65536],declaration[64];char *const whole[]={name,"-t",table,"-S",NULL};
    snprintf(declaration,sizeof(declaration),"-N %s\n",chain);
    if(policy_capture(program,whole,all,sizeof(all))||strstr(all,declaration))return -1;
    int size=snprintf(actual,capacity,"%s",declaration);if(size<0||(size_t)size>=capacity)return -1;
    *missing=1;return 0;
}
static inline int epoch_policy_foreign(const struct label_policy_names *names,int fresh){
    for(unsigned family=0;family<2;++family){
        char output[65536];char *const args[]={family?"ip6tables-save":"iptables-save",NULL};
        if(policy_capture(family?"/usr/sbin/ip6tables-save":"/usr/sbin/iptables-save",args,output,sizeof(output)))return -1;
        char *save=NULL,*table=NULL;
        for(char *line=strtok_r(output,"\n",&save);line;line=strtok_r(NULL,"\n",&save)){
            if(line[0]=='*'){table=line+1;continue;}
            int own_mark=0;
            const char *chains[]={names->group,names->mark,names->deny};
            for(unsigned kind=0;kind<3;++kind){
                if(!strstr(line,chains[kind]))continue;
                if(fresh||!table||strcmp(table,kind==1?"mangle":"filter"))return -1;
                char prefix[64],declaration[64],hook[64];
                snprintf(prefix,sizeof(prefix),"-A %s ",chains[kind]);
                snprintf(declaration,sizeof(declaration),":%s - [",chains[kind]);
                snprintf(hook,sizeof(hook),"-A OUTPUT -j %s",chains[kind]);
                int allowed=!strncmp(line,prefix,strlen(prefix))||!strncmp(line,declaration,strlen(declaration))||!strcmp(line,hook);
                if(kind==2){snprintf(hook,sizeof(hook),"-A INPUT -j %s",chains[kind]);allowed|=!strcmp(line,hook);}
                if(!allowed)return -1;
                if(kind==1&&!strncmp(line,prefix,strlen(prefix)))own_mark=1;
            }
            if(strstr(line,"CONNMARK")&&(fresh||!own_mark))return -1;
        }
    }
    return 0;
}
static inline int epoch_mutation_snapshot(struct epoch_mutation *mutation,struct epoch_snapshot *snapshot){
    struct label_policy_names names;
    if(label_policy_names(mutation->owner.chain,&names)||epoch_policy_foreign(&names,0))return -1;
    memset(snapshot,0,sizeof(*snapshot));
    for(unsigned family=0;family<2;++family){
        char *name=family?"ip6tables":"iptables";const char *program=family?"/usr/sbin/ip6tables":"/usr/sbin/iptables";
        for(unsigned kind=0;kind<3;++kind){
            char actual[8192],expected[2048];struct epoch_chain_shape *shape=&snapshot->chains[family][kind];
            if(epoch_chain_snapshot(family,&names,kind,actual,sizeof(actual),&shape->missing))return -1;
            if(kind==0){
                if(epoch_policy_expected(&names,kind,mutation->record.epoch,1,expected,sizeof(expected))<0||
                    boot_policy_subset(actual,expected,shape->present)!=4)return -1;
            }else if(kind==1){if(epoch_mark_subset(actual,&names,&mutation->record,shape))return -1;}
            else if(epoch_deny_subset(actual,&names,mutation->record.epoch,shape))return -1;
        }
        for(unsigned kind=0;kind<3;++kind){
            char *table=kind==0?"mangle":"filter",*hook=kind==2?"INPUT":"OUTPUT",actual[8192];
            const char *targets[]={kind==0?names.mark:kind==1?names.group:names.deny,names.deny};
            char *const args[]={name,"-t",table,"-S",hook,NULL};
            if(policy_capture(program,args,actual,sizeof(actual))||
                boot_policy_hook_subset(actual,hook,targets,kind==1?2:1,snapshot->hooks[family][kind]))return -1;
        }
    }
    return 0;
}
static inline int epoch_mutation_verified(struct epoch_mutation *mutation,int closed){
    struct label_policy_names names;
    return !label_policy_names(mutation->owner.chain,&names)&&epoch_policy_verified(names.group,mutation->record.epoch,closed)&&
        !epoch_policy_foreign(&names,0);
}
static inline int epoch_mutation_deny(struct epoch_mutation *mutation){
    struct epoch_snapshot snapshot;struct label_policy_names names;
    if(epoch_mutation_load(mutation)||label_policy_names(mutation->owner.chain,&names)||
        epoch_mutation_snapshot(mutation,&snapshot)||epoch_mutation_phase(mutation,EPOCH_DENYING))return -1;
    /* Install both-family barriers before touching old marking rows. */
    for(unsigned family=0;family<2;++family){
        char *name=family?"ip6tables":"iptables";
        for(unsigned kind=0;kind<3;++kind)if(snapshot.chains[family][kind].missing){
            char *const args[]={name,"-t",kind==1?"mangle":"filter","-N",kind==0?names.group:kind==1?names.mark:names.deny,NULL};
            if(epoch_mutation_command(mutation,family,args))return -1;
        }
        if(!snapshot.chains[family][2].head){
            char *const args[]={name,"-I",names.deny,"1","-m","connmark","!","--mark","0x0/" EPOCH_MASK_TEXT,"-j","DROP",NULL};
            if(epoch_mutation_command(mutation,family,args))return -1;
        }
        for(unsigned i=0;i<4;++i)if(!snapshot.chains[family][0].present[i]){
            char position[4],group[16];snprintf(position,sizeof(position),"%u",i+1);snprintf(group,sizeof(group),"%u",composite_groups[i]);
            char *const args[]={name,"-I",names.group,position,"-m","owner","--gid-owner",group,"-j","DROP",NULL};
            if(epoch_mutation_command(mutation,family,args))return -1;
        }
        for(unsigned kind=0;kind<3;++kind){
            char *table=kind==0?"mangle":"filter",*hook=kind==2?"INPUT":"OUTPUT";
            char *targets[]={kind==0?names.mark:kind==1?names.group:names.deny,names.deny};
            for(unsigned i=0;i<(kind==1?2u:1u);++i)if(!snapshot.hooks[family][kind][i]){
                char position[4];snprintf(position,sizeof(position),"%u",i+1);
                char *const args[]={name,"-t",table,"-I",hook,position,"-j",targets[i],NULL};
                if(epoch_mutation_command(mutation,family,args))return -1;
            }
        }
    }
    for(unsigned family=0;family<2;++family){
        char *name=family?"ip6tables":"iptables";
        for(unsigned i=0;i<snapshot.chains[family][2].tails;++i){char *const args[]={name,"-D",names.deny,"2",NULL};if(epoch_mutation_command(mutation,family,args))return -1;}
        for(unsigned i=0;i<4;++i){
            struct epoch_chain_shape *shape=&snapshot.chains[family][1];if(shape->present[i]&&shape->newer[i])continue;
            char position[4],group[16],mark[32];snprintf(position,sizeof(position),"%u",i+1);snprintf(group,sizeof(group),"%u",composite_groups[i]);
            snprintf(mark,sizeof(mark),"0x%x/" EPOCH_MASK_TEXT,mutation->record.epoch<<24);
            char *const args[]={name,"-t","mangle",shape->present[i]?"-R":"-I",names.mark,position,"-m","owner","--gid-owner",group,
                "-m","connmark","--mark","0x0/" EPOCH_MASK_TEXT,"-j","CONNMARK","--set-xmark",mark,NULL};
            if(epoch_mutation_command(mutation,family,args))return -1;
        }
    }
    return !epoch_mutation_verified(mutation,1)||epoch_mutation_phase(mutation,EPOCH_CLOSED)?-1:0;
}
static inline int epoch_mutation_reserve(struct epoch_mutation *mutation,int (*scope_absent)(void *),void *scope){
    if(!mutation||!epoch_store_lease_valid(mutation->lease)||!scope_absent||!scope_absent(scope))return -1;
    struct epoch_owner previous;char expected[192],actual[192];struct label_policy_names names;
    if(epoch_owner_format(&mutation->owner,expected,sizeof(expected))<0||label_policy_names(mutation->owner.chain,&names))return -1;
    int found=epoch_owner_read(mutation->lease->runtime,mutation->lease->owner,&previous);
    if(found<0||(found==0&&(epoch_owner_format(&previous,actual,sizeof(actual))<0||strcmp(expected,actual))))return -1;
    int state=found?1:epoch_record_read(mutation->lease->runtime,mutation->lease->owner,&mutation->owner,&mutation->record);
    if(state<0)return -1;
    if(found==1||state==1){
        unsigned char used[256];FILE *file=fopen("/proc/net/nf_conntrack","r");
        if(!file)return -1;
        int ok=!epoch_conntrack_used(file,used);if(fclose(file))ok=0;
        for(unsigned i=1;i<256;++i)if(used[i])ok=0;
        if(!ok||epoch_policy_foreign(&names,1))return -1;
        if(epoch_owner_publish(mutation->lease,&mutation->owner))return -1;
        epoch_mutation_checkpoint(mutation);
        mutation->record=(struct epoch_record){mutation->owner.initial_revision,1,0,EPOCH_RESERVED};
        if(epoch_record_publish(mutation->lease,&mutation->owner,&mutation->record))return -1;
        epoch_mutation_checkpoint(mutation);
    }
    /* Reservation/restart can only establish CLOSED. It never resumes OPEN. */
    return epoch_mutation_deny(mutation);
}
static inline int epoch_mutation_prepare(struct epoch_mutation *mutation,uint64_t revision,
                                         int (*scope_absent)(void *),void *scope){
    if(!scope_absent||!scope_absent(scope)||!revision||revision==UINT64_MAX||epoch_mutation_load(mutation)||
        !epoch_mutation_verified(mutation,1))return -1;
    if(revision==mutation->record.revision&&mutation->record.previous&&
        (mutation->record.phase==EPOCH_CLOSED||mutation->record.phase==EPOCH_ARMED))
        return epoch_mutation_phase(mutation,EPOCH_ARMED);
    if(mutation->record.phase!=EPOCH_CLOSED||revision<=mutation->record.revision)return -1;
    unsigned char used[256];FILE *file=fopen("/proc/net/nf_conntrack","r");if(!file)return -1;
    int ok=!epoch_conntrack_used(file,used);if(fclose(file))ok=0;if(!ok)return -1;
    unsigned next=epoch_next_unused(used,mutation->record.epoch);if(!next)return -1;
    mutation->record=(struct epoch_record){revision,next,mutation->record.epoch,EPOCH_ARMING};
    if(epoch_record_publish(mutation->lease,&mutation->owner,&mutation->record))return -1;
    epoch_mutation_checkpoint(mutation);
    return epoch_mutation_deny(mutation)||epoch_mutation_phase(mutation,EPOCH_ARMED)?-1:0;
}
static inline int epoch_mutation_release(struct epoch_mutation *mutation,int state){
    if(epoch_mutation_load(mutation)||mutation->record.phase!=EPOCH_ARMED||!epoch_mutation_verified(mutation,1))return -1;
    struct mode_record mode;struct open_record opening;uid_t owner=mutation->lease->owner;
    if(mode_store_read(state,owner,&mode)!=STORE_OK||mode.requested!=LISA_MODE_ALICE||mode.revision!=mutation->record.revision||
        open_read(state,owner,&opening)||opening.phase!=OPEN_PERMITTED||opening.base_revision+1!=mode.revision||
        strcmp(opening.boot,mutation->owner.boot)||mode_store_close_pending(state,owner)||
        !gate_permit_valid(mutation->lease->runtime,owner,mode.revision,mutation->owner.boot))return -1;
    struct label_policy_names names;if(label_policy_names(mutation->owner.chain,&names)||epoch_mutation_phase(mutation,EPOCH_OPENING))return -1;
    for(unsigned family=0;family<2;++family){
        char *name=family?"ip6tables":"iptables",mark[32];snprintf(mark,sizeof(mark),"0x%x/" EPOCH_MASK_TEXT,mutation->record.epoch<<24);
        char *const unmarked[]={name,"-A",names.deny,"-m","connmark","--mark","0x0/" EPOCH_MASK_TEXT,"-j","RETURN",NULL};
        char *const active[]={name,"-A",names.deny,"-m","connmark","--mark",mark,"-j","RETURN",NULL};
        char *const retired[]={name,"-A",names.deny,"-j","DROP",NULL};
        char *const remove[]={name,"-D",names.deny,"1",NULL};
        if(epoch_mutation_command(mutation,family,unmarked)||epoch_mutation_command(mutation,family,active)||
            epoch_mutation_command(mutation,family,retired)||epoch_mutation_command(mutation,family,remove))return -1;
        for(unsigned i=0;i<4;++i){
            char group[16];snprintf(group,sizeof(group),"%u",composite_groups[i]);
            char *const args[]={name,"-D",names.group,"-m","owner","--gid-owner",group,"-j","DROP",NULL};
            if(epoch_mutation_command(mutation,family,args))return -1;
        }
    }
    return !epoch_mutation_verified(mutation,0)||epoch_mutation_phase(mutation,EPOCH_OPEN)?-1:0;
}
#endif
