/* Pure structured metadata fixtures. No SDK, bus, socket, identity or audio. */
#include <stdio.h>
#include "sdk_name_ledger.h"
static unsigned checks,failures;
static void check(int good){++checks;if(!good){++failures;fprintf(stderr,"SDK ledger check %u\n",checks);}}
static struct private_match_entry entry(const char *name,const char *first,const char *second){
    struct private_match_entry result={0};strcpy(result.name,name);
    if(first){strcpy(result.rule,first);result.rules=1;}
    if(second){strcpy(result.extra[0],second);result.rules=2;}return result;
}
static struct private_match_snapshot snapshot(const struct private_match_entry *entries,unsigned count){
    struct private_match_snapshot result={0};result.clients=count;
    for(unsigned i=0;i<count&&i<MATCH_CLIENTS;++i){result.entry[i]=entries[i];result.rules+=entries[i].rules;}return result;
}
static void bad(struct sdk_name_ledger *ledger,const struct private_match_snapshot *s,const struct private_match_entry *own,const struct private_match_entry *provider){
    struct sdk_name_ledger before=*ledger;check(sdk_ledger_observe(ledger,s,own,provider)<0&&!memcmp(ledger,&before,sizeof(before)));
}
int main(int argc,char **argv){
    if(argc!=2||strcmp(argv[1],"--selftest"))return 2;
    struct private_match_entry own=entry(":1.0","observer",NULL),provider=entry(":1.1",NULL,NULL);
    struct private_match_entry entries[]={own,provider,entry(":1.2","one",NULL),entry(":1.3",NULL,NULL)};
    struct sdk_name_ledger ledger={0};struct private_match_snapshot s=snapshot(entries,2);
    check(!sdk_ledger_observe(&ledger,&s,&own,&provider)&&!ledger.count&&!ledger.active);
    s=snapshot(entries,3);check(!sdk_ledger_observe(&ledger,&s,&own,&provider)&&ledger.count==1&&ledger.active==1);
    check(sdk_ledger_sender(&ledger,":1.2")&&!sdk_ledger_sender(&ledger,":1.3")&&!sdk_ledger_sender(&ledger,provider.name));
    entries[2]=entry(":1.2","two","one");s=snapshot(entries,4);
    check(!sdk_ledger_observe(&ledger,&s,&own,&provider)&&ledger.count==2&&ledger.active==3&&ledger.peak[0].rules==2&&!ledger.peak[1].rules);
    entries[3]=entry(":1.3","three",NULL);
    /* All 24 entry orders preserve both independent name records. */
    for(unsigned a=0;a<4;++a)for(unsigned b=0;b<4;++b)for(unsigned c=0;c<4;++c)for(unsigned d=0;d<4;++d){
        if(a==b||a==c||a==d||b==c||b==d||c==d)continue;
        struct private_match_entry reordered[]={entries[a],entries[b],entries[c],entries[d]};s=snapshot(reordered,4);
        check(!sdk_ledger_observe(&ledger,&s,&own,&provider)&&ledger.count==2&&ledger.active==3&&ledger.peak[1].rules==1);
    }
    struct sdk_name_ledger full=ledger;
    s=snapshot(entries,4);s.entry[2]=entry(":1.2","one",NULL);--s.rules;bad(&ledger,&s,&own,&provider);
    s=snapshot(entries,4);s.entry[0]=entry(own.name,"changed",NULL);bad(&ledger,&s,&own,&provider);
    s=snapshot(entries,4);s.entry[1]=entry(provider.name,"changed",NULL);++s.rules;bad(&ledger,&s,&own,&provider);
    s=snapshot(entries,4);s.entry[3]=entry(":1.4","new",NULL);bad(&ledger,&s,&own,&provider);
    struct private_match_entry retired[]={own,provider,entries[3]};s=snapshot(retired,3);
    check(!sdk_ledger_observe(&ledger,&s,&own,&provider)&&ledger.count==2&&ledger.active==2);
    check(!sdk_ledger_sender(&ledger,":1.2")&&sdk_ledger_sender(&ledger,":1.3"));
    s=snapshot(entries,4);bad(&ledger,&s,&own,&provider);
    retired[2]=entry(":1.4",NULL,NULL);s=snapshot(retired,3);bad(&ledger,&s,&own,&provider);
    struct private_match_snapshot only_own=snapshot(&own,1);struct sdk_name_ledger before=ledger;
    s=snapshot(entries,4);check(sdk_ledger_finish(&ledger,&s,&own)<0&&!memcmp(&ledger,&before,sizeof(before)));
    check(!sdk_ledger_finish(&ledger,&only_own,&own)&&ledger.finished&&!ledger.active&&ledger.count==2);
    check(!sdk_ledger_sender(&ledger,":1.3")&&!sdk_ledger_sender(&ledger,NULL)&&!sdk_ledger_sender(NULL,":1.2"));
    check(!sdk_ledger_finish(&ledger,&only_own,&own));bad(&ledger,&s,&own,&provider);
    /* A serialized rule multiset may contain equal strings; preserve counts. */
    struct sdk_name_ledger duplicates={0};entries[2]=entry(":1.2","same","same");s=snapshot(entries,3);
    check(!sdk_ledger_observe(&duplicates,&s,&own,&provider));
    s.entry[2]=entry(":1.2","same","other");bad(&duplicates,&s,&own,&provider);
    struct private_match_entry maximum=entry(":1.2","one","two");strcpy(maximum.extra[1],"three");strcpy(maximum.extra[2],"four");maximum.rules=4;
    struct private_match_entry maximum_entries[]={own,provider,maximum};struct sdk_name_ledger maximum_ledger={0};s=snapshot(maximum_entries,3);
    check(!sdk_ledger_observe(&maximum_ledger,&s,&own,&provider)&&maximum_ledger.peak[0].rules==4);
    const char *const rules[]={"one","two","three","four"};
    for(unsigned a=0;a<4;++a)for(unsigned b=0;b<4;++b)for(unsigned c=0;c<4;++c)for(unsigned d=0;d<4;++d){
        if(a==b||a==c||a==d||b==c||b==d||c==d)continue;
        maximum_entries[2]=entry(":1.2",rules[a],rules[b]);strcpy(maximum_entries[2].extra[1],rules[c]);strcpy(maximum_entries[2].extra[2],rules[d]);maximum_entries[2].rules=4;
        s=snapshot(maximum_entries,3);check(!sdk_ledger_observe(&maximum_ledger,&s,&own,&provider));
    }
    s.entry[2].rules=5;++s.rules;bad(&maximum_ledger,&s,&own,&provider);
    entries[2]=full.peak[0];entries[3]=full.peak[1];ledger=full;s=snapshot(entries,4);
    check(!sdk_ledger_observe(&ledger,&s,&own,&provider));
    /* Every malformed input leaves the previous VALID ledger intact. */
    for(unsigned mutation=0;mutation<12;++mutation){ledger=full;s=snapshot(entries,4);
        if(mutation==0)s.clients=5;
        if(mutation==1)++s.rules;
        if(mutation==2)strcpy(s.entry[3].name,s.entry[2].name);
        if(mutation==3)memset(s.entry[2].name,'x',sizeof(s.entry[2].name));
        if(mutation==4)strcpy(s.entry[2].name,":one");
        if(mutation==5)s.entry[2].rules=MATCH_RULES+1;
        if(mutation==6)memset(s.entry[2].rule,'x',sizeof(s.entry[2].rule));
        if(mutation==7){s.entry[2].rule[0]=(char)0xff;s.entry[2].rule[1]=0;}
        if(mutation==8)ledger.count=3;
        if(mutation==9)ledger.active=4;
        if(mutation==10)ledger.finished=2;
        if(mutation==11){ledger.finished=1;ledger.active=1;}
        bad(&ledger,&s,&own,&provider);
    }
    ledger=full;s=snapshot(entries,4);bad(&ledger,NULL,&own,&provider);bad(&ledger,&s,NULL,&provider);bad(&ledger,&s,&own,NULL);bad(&ledger,&s,&own,&own);
    check(!sdk_ledger_valid(NULL)&&sdk_ledger_observe(NULL,&s,&own,&provider)<0&&sdk_ledger_finish(NULL,&only_own,&own)<0);
    ledger.count=UINT32_MAX;check(!sdk_ledger_sender(&ledger,":1.2"));
    ledger=full;struct private_match_entry impersonated=ledger.peak[0];s=snapshot(&impersonated,1);before=ledger;
    check(sdk_ledger_finish(&ledger,&s,&impersonated)<0&&!memcmp(&ledger,&before,sizeof(before)));
    printf("{\"selftest\":\"sdk-name-ledger\",\"checks\":%u,\"failures\":%u,\"ok\":%s,\"synthetic_only\":true}\n",checks,failures,failures?"false":"true");return failures?2:0;
}
