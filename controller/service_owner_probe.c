/* Synthetic owner observation/retirement controls, no live bus or SDK. */
#include <stdio.h>
#include "sdk_service_owner.h"
static unsigned checks,failures;
static void check(int good){++checks;if(!good){++failures;fprintf(stderr,"Service owner check %u\n",checks);}}
int main(int argc,char **argv){
    if(argc!=2||strcmp(argv[1],"--selftest"))return 2;
    struct sdk_name_ledger names={.count=2,.active=3};strcpy(names.peak[0].name,":1.2");strcpy(names.peak[1].name,":1.3");
    for(unsigned slot=0;slot<2;++slot){struct sdk_service_owner state={0},before=state;const char *owner=names.peak[slot].name;
        check(!sdk_owner_observe(&state,&names,NULL)&&!memcmp(&state,&before,sizeof(state)));
        check(!sdk_owner_observe(&state,&names,owner)&&state.observed&&!state.retired&&!strcmp(state.name,owner));
        before=state;
        check(!sdk_owner_observe(&state,&names,owner)&&!memcmp(&state,&before,sizeof(state)));
        const char *const invalid[]={NULL,"",":1.0",":1.1",":1.4","ru.yandex.quasar",names.peak[1-slot].name};
        for(unsigned i=0;i<sizeof(invalid)/sizeof(invalid[0]);++i)
            check(sdk_owner_observe(&state,&names,invalid[i])<0&&!memcmp(&state,&before,sizeof(state)));
        struct sdk_name_ledger retired=names;retired.active&=~(1u<<slot);
        check(sdk_owner_observe(&state,&retired,owner)<0&&!memcmp(&state,&before,sizeof(state)));
        check(sdk_owner_retire(&state,&retired,1)<0&&!memcmp(&state,&before,sizeof(state)));
        retired.active=0;retired.finished=1;
        check(sdk_owner_retire(&state,&retired,0)<0&&!memcmp(&state,&before,sizeof(state)));
        check(sdk_owner_retire(&state,&retired,2)<0&&!memcmp(&state,&before,sizeof(state)));
        check(!sdk_owner_retire(&state,&retired,1)&&state.retired&&!strcmp(state.name,owner));before=state;
        check(!sdk_owner_retire(&state,&retired,1)&&!memcmp(&state,&before,sizeof(state)));
        check(sdk_owner_observe(&state,&names,owner)<0&&!memcmp(&state,&before,sizeof(state)));
        struct sdk_name_ledger changed=retired;strcpy(changed.peak[slot].name,":1.8");
        check(sdk_owner_retire(&state,&changed,1)<0&&!memcmp(&state,&before,sizeof(state)));
    }
    struct sdk_service_owner state={0},before=state;struct sdk_name_ledger finished=names;finished.active=0;finished.finished=1;
    check(sdk_owner_retire(&state,&finished,1)<0&&!memcmp(&state,&before,sizeof(state)));
    check(sdk_owner_observe(&state,&finished,":1.2")<0&&!memcmp(&state,&before,sizeof(state)));
    check(sdk_owner_observe(&state,NULL,":1.2")<0&&!memcmp(&state,&before,sizeof(state)));
    check(sdk_owner_retire(&state,NULL,1)<0&&!memcmp(&state,&before,sizeof(state)));
    check(sdk_owner_observe(NULL,&names,":1.2")<0&&sdk_owner_retire(NULL,&finished,1)<0);
    for(unsigned i=0;i<4;++i){struct sdk_service_owner invalid={0};
        if(i==0)invalid.observed=2;else if(i==1)invalid.retired=1;else if(i==2)strcpy(invalid.name,":1.2");else memset(invalid.name,'x',sizeof(invalid.name));
        before=invalid;check(!sdk_owner_valid(&invalid)&&sdk_owner_observe(&invalid,&names,":1.2")<0&&!memcmp(&invalid,&before,sizeof(invalid)));
    }
    printf("{\"kind\":\"sdk-service-owner\",\"checks\":%u,\"failures\":%u}\n",checks,failures);return failures?1:0;
}
