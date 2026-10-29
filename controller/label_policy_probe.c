/* Pure canonical rule fixtures; no firewall commands or real processes. */
#define _GNU_SOURCE
#include "label_policy.h"
static unsigned checks;
#define CHECK(condition) do { ++checks; if(!(condition)) { fprintf(stderr,"label-policy-check:%u\n",checks); return 4; } } while(0)
int main(void) {
    struct label_policy_names names;
    CHECK(!label_policy_names("LISACQ_TEST_1",&names));
    CHECK(!strcmp(names.mark,"LISACM_TEST_1")&&!strcmp(names.deny,"LISACL_TEST_1"));
    const char *invalid[]={"LISACQ_","OTHER_TEST","LISACQ_bad","LISACQ_A;","LISACQ_123456789012345678901","LISACQ_A\n"};
    for(unsigned i=0;i<sizeof(invalid)/sizeof(invalid[0]);++i) CHECK(label_policy_names(invalid[i],&names)<0);
    CHECK(!label_policy_names("LISACQ_TEST_1",&names));
    char mark[2048],deny[512],short_text[8];
    CHECK(label_policy_expected(&names,1,mark,sizeof(mark))>0);
    CHECK(label_policy_expected(&names,0,deny,sizeof(deny))>0);
    CHECK(!strcmp(deny,"-N LISACL_TEST_1\n-A LISACL_TEST_1 -m connmark --mark 0x40000000/0x40000000 -j DROP\n"));
    for(unsigned i=0;i<COMPOSITE_ROLE_COUNT;++i) {
        char rule[256]; snprintf(rule,sizeof(rule),"--gid-owner %u -j CONNMARK --set-xmark " ROLE_LABEL_MARK "\n",composite_groups[i]);
        CHECK(strstr(mark,rule)!=NULL);
    }
    CHECK(label_policy_expected(&names,1,short_text,sizeof(short_text))<0);
    CHECK(label_policy_expected(&names,0,short_text,sizeof(short_text))<0);
    strcpy(names.deny,"LISACL_OTHER"); CHECK(label_policy_expected(&names,0,deny,sizeof(deny))<0);
    CHECK(!label_policy_names("LISACQ_TEST_1",&names));
    const char *output="-P OUTPUT ACCEPT\n-A OUTPUT -j LISACQ_TEST_1\n-A OUTPUT -j LISACL_TEST_1\n-A OUTPUT -j OTHER\n";
    CHECK(label_policy_hook(&names,output,"OUTPUT",1,0));
    CHECK(!label_policy_hook(&names,"-P OUTPUT ACCEPT\n-A OUTPUT -j LISACL_TEST_1\n-A OUTPUT -j LISACQ_TEST_1\n","OUTPUT",1,0));
    CHECK(!label_policy_hook(&names,"-P OUTPUT ACCEPT\n-A OUTPUT -j LISACQ_TEST_1\n-A OUTPUT -j OTHER\n-A OUTPUT -j LISACL_TEST_1\n","OUTPUT",1,0));
    CHECK(!label_policy_hook(&names,"-P OUTPUT ACCEPT\n-A OUTPUT -j LISACQ_TEST_1\n","OUTPUT",1,0));
    CHECK(label_policy_hook(&names,"-P OUTPUT ACCEPT\n-A OUTPUT -j LISACM_TEST_1\n","OUTPUT",1,1));
    CHECK(!label_policy_hook(&names,output,"OUTPUT",1,1));
    CHECK(label_policy_hook(&names,"-P INPUT ACCEPT\n-A INPUT -j LISACL_TEST_1\n","INPUT",0,0));
    CHECK(!label_policy_hook(&names,"-P INPUT ACCEPT\n-A INPUT -j OTHER\n-A INPUT -j LISACL_TEST_1\n","INPUT",0,0));
    CHECK(!label_policy_hook(&names,"-P INPUT ACCEPT","INPUT",0,0));
    printf("{\"selftest\":\"label-policy\",\"checks\":%u,\"ok\":true,\"firewall_changed\":false}\n",checks);
    return 0;
}
