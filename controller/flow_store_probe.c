/* Synthetic flow evidence only. No network calls or real service mutation. */
#define _GNU_SOURCE
#include "flow_store.h"

static const char BOOT[]="11111111-2222-4333-8444-555555555555";
static void fixture_plan(struct flow_plan *plan) {
    memset(plan,0,sizeof(*plan)); plan->revision=1; plan->count=6;
    strcpy(plan->boot,BOOT); strcpy(plan->chain,"LISAFT_FIXTURE");
    for(unsigned i=0;i<6;++i) {
        struct saved_flow *f=&plan->flows[i]; f->family=i<2?AF_INET:AF_INET6;
        f->protocol=i%2?IPPROTO_UDP:IPPROTO_TCP; f->inode=100+i;
        const char *address=i<2?"127.0.0.1":i<4?"::1":"::ffff:127.0.0.1";
        (void)inet_pton(f->family,address,f->id.idiag_src); (void)inet_pton(f->family,address,f->id.idiag_dst);
        f->id.idiag_sport=htons((uint16_t)(20000+i)); f->id.idiag_dport=htons((uint16_t)(30000+i));
        f->id.idiag_cookie[0]=i%2?INET_DIAG_NOCOOKIE:200+i;
        f->id.idiag_cookie[1]=i%2?INET_DIAG_NOCOOKIE:300+i;
    }
}
static int fixture_file(int state,const char *text,size_t size) {
    unlinkat(state,"flows.state",0);
    int file=openat(state,"flows.state",O_WRONLY|O_CREAT|O_EXCL|O_NOFOLLOW|O_CLOEXEC,0600);
    if(file<0) return -1;
    int failed=store_write_all(file,text,size); if(close(file)) failed=1; return failed?-1:0;
}
#define CHECK(condition,name) do { ++checks; if(!(condition)) { \
    fprintf(stderr,"failed:%s\n",name); failed=1; goto cleanup; } } while(0)
int main(int argc,char **argv) {
    umask(077); const char *base="/tmp";
    if(argc==2 && !strcmp(argv[1],"--station-storage") && !geteuid()) base="/data/opt/lisa-controller-lab";
    else if(argc!=1) return 2;
    char path[256]; snprintf(path,sizeof(path),"%s/flow-store-test.XXXXXX",base);
    if(!mkdtemp(path)) return 3;
    int state=open(path,O_RDONLY|O_DIRECTORY|O_CLOEXEC),failed=0; unsigned checks=0; uid_t owner=geteuid();
    struct flow_plan plan,parsed,changed; fixture_plan(&plan);
    char text[FLOW_TEXT_LIMIT],copy[FLOW_TEXT_LIMIT]; int size=flow_plan_format(&plan,text,sizeof(text));
    CHECK(state>=0 && size>0 && !flow_plan_parse(text,(size_t)size,&parsed),"canonical_v4_v6_mapped_roundtrip");
    CHECK(flow_plan_read(state,owner,1,BOOT,&parsed)==1,"missing_is_not_empty_evidence");
    for(unsigned i=0;i<6;++i) {
        CHECK(parsed.count==6 && parsed.flows[i].family==plan.flows[i].family && parsed.flows[i].inode==plan.flows[i].inode &&
            !memcmp(&parsed.flows[i].id,&plan.flows[i].id,sizeof(plan.flows[i].id)),"tuple_cookie_inode_preserved");
    }
    for(unsigned fault=0;fault<24;++fault) {
        changed=plan; struct saved_flow *f=&changed.flows[0];
        switch(fault) {
            case 0: changed.revision=0; break;
            case 1: changed.revision=UINT64_MAX; break;
            case 2: changed.boot[0]='X'; break;
            case 3: strcpy(changed.chain,"LISAFT_1;id"); break;
            case 4: changed.count=0; break;
            case 5: changed.count=FLOW_LIMIT+1; break;
            case 6: f->inode=0; break;
            case 7: f->id.idiag_sport=0; break;
            case 8: f->id.idiag_dport=0; break;
            case 9: f->id.idiag_if=3; break;
            case 10: f->id.idiag_cookie[0]=f->id.idiag_cookie[1]=INET_DIAG_NOCOOKIE; break;
            case 11: changed.flows[1].id.idiag_cookie[0]=1; break;
            case 12: f->protocol=IPPROTO_ICMP; break;
            case 13: f->family=AF_UNIX; break;
            case 14: f->id.idiag_src[3]=1; break;
            case 15: memset(f->id.idiag_src,0,16); break;
            case 16: ((unsigned char*)f->id.idiag_src)[0]=224; break;
            case 17: (void)inet_pton(AF_INET6,"fe80::1",changed.flows[2].id.idiag_src); break;
            case 18: (void)inet_pton(AF_INET6,"ff02::1",changed.flows[2].id.idiag_src); break;
            case 19: (void)inet_pton(AF_INET6,"::1",changed.flows[4].id.idiag_dst); break;
            case 20: f->id.idiag_dport=f->id.idiag_sport; break;
            case 21: changed.flows[1]=*f; break;
            case 22: changed.flows[4].id.idiag_sport=f->id.idiag_sport; changed.flows[4].id.idiag_dport=f->id.idiag_dport; break;
            case 23: strcpy(changed.chain,"LISAFT_"); break;
        }
        CHECK(flow_plan_format(&changed,copy,sizeof(copy))<0,"unsafe_or_ambiguous_flow_rejected");
    }
    CHECK(flow_plan_parse(text,(size_t)size-1,&parsed)<0,"missing_final_newline_rejected");
    memcpy(copy,text,(size_t)size); copy[size]='\n';
    CHECK(flow_plan_parse(copy,(size_t)size+1,&parsed)<0,"extra_blank_line_rejected");
    copy[size]=0;
    CHECK(flow_plan_parse(copy,(size_t)size+1,&parsed)<0,"embedded_nul_rejected");
    memcpy(copy+1,text,(size_t)size); copy[0]=' ';
    CHECK(flow_plan_parse(copy,(size_t)size+1,&parsed)<0,"noncanonical_whitespace_rejected");
    CHECK(flow_plan_format(&plan,copy,32)<0,"short_output_buffer_rejected");
    CHECK(!flow_plan_publish(state,owner,&plan) && !flow_plan_read(state,owner,1,BOOT,&parsed),"atomic_evidence_published");
    CHECK(!flow_plan_publish(state,owner,&plan),"same_evidence_publication_idempotent");
    CHECK(flow_plan_read(state,owner,2,BOOT,&parsed)<0 &&
        flow_plan_read(state,owner,1,"aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee",&parsed)<0,"revision_and_boot_bound");
    changed=plan; ++changed.flows[0].inode;
    CHECK(flow_plan_publish(state,owner,&changed)<0 && !flow_plan_read(state,owner,1,BOOT,&parsed) &&
        parsed.flows[0].inode==plan.flows[0].inode,"conflicting_evidence_never_replaced");
    CHECK(!fchmodat(state,"flows.state",0644,0) && flow_plan_read(state,owner,1,BOOT,&parsed)<0 &&
        flow_plan_publish(state,owner,&plan)<0,"public_file_denied");
    CHECK(!fchmodat(state,"flows.state",0600,0) && !linkat(state,"flows.state",state,"hard",0) &&
        flow_plan_read(state,owner,1,BOOT,&parsed)<0 && flow_plan_publish(state,owner,&plan)<0,"hardlinked_evidence_denied");
    CHECK(!unlinkat(state,"flows.state",0) && !symlinkat("hard",state,"flows.state") &&
        flow_plan_read(state,owner,1,BOOT,&parsed)<0 && flow_plan_publish(state,owner,&plan)<0,"symlink_evidence_denied");
    CHECK(!fixture_file(state,"broken\n",7) && flow_plan_publish(state,owner,&plan)<0 &&
        flow_plan_read(state,owner,1,BOOT,&parsed)<0,"corrupt_evidence_not_replaced");
    CHECK(!fixture_file(state,text,(size_t)size) && flow_plan_read(state,owner+1,1,BOOT,&parsed)<0,"wrong_owner_denied");
    CHECK(!fchmod(state,0755) && flow_plan_read(state,owner,1,BOOT,&parsed)<0 &&
        flow_plan_publish(state,owner,&plan)<0,"public_state_denied");
    CHECK(!fchmod(state,0700),"reset_fixture_permissions");
    memset(copy,'A',sizeof(copy));
    CHECK(!fixture_file(state,copy,sizeof(copy)) && flow_plan_read(state,owner,1,BOOT,&parsed)<0,"oversized_evidence_denied");
cleanup:
    if(state>=0) { (void)fchmod(state,0700); unlinkat(state,"flows.state",0); unlinkat(state,"hard",0); close(state); }
    int removed=!rmdir(path);
    printf("{\"selftest\":\"flow-store\",\"checks\":%u,\"ok\":%s,\"temporary_directory_removed\":%s,"
        "\"network_changed\":false,\"production_mode_changed\":false}\n",checks,failed?"false":"true",removed?"true":"false");
    return failed||!removed?4:0;
}
