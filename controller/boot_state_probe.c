/* Pure policy recovery plans and own temporary ledger files only. */
#define _GNU_SOURCE
#include <linux/audit.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <stddef.h>
#include <sys/syscall.h>
#include "boot_ledger.h"
static unsigned checks;
#define CHECK(condition) do { ++checks; if(!(condition)) { fprintf(stderr,"boot-state-check:%u\n",checks); return 4; } } while(0)
static int nonce_fixture(int runtime,uid_t owner,const char *boot,const char *chain,unsigned error) {
    pid_t child=fork(); if(child<0) return 0;
    if(!child) {
#if defined(__arm__)
        const unsigned architecture=AUDIT_ARCH_ARM;
#elif defined(__x86_64__)
        const unsigned architecture=AUDIT_ARCH_X86_64;
#else
#error Unsupported own nonce test architecture
#endif
        struct sock_filter instructions[]={
            BPF_STMT(BPF_LD|BPF_W|BPF_ABS,offsetof(struct seccomp_data,arch)),
            BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K,architecture,1,0),BPF_STMT(BPF_RET|BPF_K,SECCOMP_RET_KILL),
            BPF_STMT(BPF_LD|BPF_W|BPF_ABS,offsetof(struct seccomp_data,nr)),
            BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K,SYS_getrandom,0,1),
            BPF_STMT(BPF_RET|BPF_K,SECCOMP_RET_ERRNO|error),BPF_STMT(BPF_RET|BPF_K,SECCOMP_RET_ALLOW)};
        struct sock_fprog program={sizeof(instructions)/sizeof(instructions[0]),instructions};
        if(prctl(PR_SET_NO_NEW_PRIVS,1,0,0,0)||prctl(PR_SET_SECCOMP,SECCOMP_MODE_FILTER,&program)) _exit(2);
        char byte; errno=0;
        if(getrandom(&byte,1,GRND_NONBLOCK)!=-1||errno!=(int)error) _exit(3);
        int result=boot_ledger_publish(runtime,owner,0,boot,chain);
        _exit(error==EIO?(result<0?0:4):(result==0?0:4));
    }
    int status; pid_t waited;
    do { waited=waitpid(child,&status,0); } while(waited<0&&errno==EINTR);
    return waited==child&&WIFEXITED(status)&&WEXITSTATUS(status)==0;
}
int main(void) {
    alarm(15);
    const char *boot="11111111-2222-4333-8444-555555555555",*chain="LISACQ_TEST_BOOT";
    struct label_policy_names names; CHECK(!label_policy_names(chain,&names));
    for(unsigned kind=0;kind<3;++kind) {
        char expected[2048],copy[2048],*lines[5];
        CHECK(boot_policy_expected(&names,kind,expected,sizeof(expected))>0);
        strcpy(copy,expected); int count=boot_policy_lines(copy,lines,5); CHECK(count==((kind==2)?2:5));
        for(unsigned mask=0;mask<(1u<<(count-1));++mask) {
            char subset[2048]; int used=snprintf(subset,sizeof(subset),"%s\n",lines[0]);
            for(int i=1;i<count;++i) if(mask&(1u<<(i-1))) used+=snprintf(subset+used,sizeof(subset)-(size_t)used,"%s\n",lines[i]);
            unsigned present[4]; CHECK(boot_policy_subset(subset,expected,present)==count-1);
            for(int i=1;i<count;++i) CHECK(present[i-1]==!!(mask&(1u<<(i-1))));
        }
        unsigned present[4]; char bad[4096];
        snprintf(bad,sizeof(bad),"%s%s\n",expected,lines[1]); CHECK(boot_policy_subset(bad,expected,present)<0);
        snprintf(bad,sizeof(bad),"%s-A %s -j ACCEPT\n",expected,kind==0?names.group:kind==1?names.mark:names.deny); CHECK(boot_policy_subset(bad,expected,present)<0);
        if(kind!=2) {
            snprintf(bad,sizeof(bad),"%s\n%s\n%s\n",lines[0],lines[2],lines[1]); CHECK(boot_policy_subset(bad,expected,present)<0);
        }
        snprintf(bad,sizeof(bad),"%s\n",expected); CHECK(boot_policy_subset(bad,expected,present)<0);
    }
    unsigned present[2]; const char *targets[]={names.group,names.deny};
    CHECK(!boot_policy_hook_subset("-P OUTPUT ACCEPT\n","OUTPUT",targets,2,present)&&!present[0]&&!present[1]);
    CHECK(!boot_policy_hook_subset("-P OUTPUT ACCEPT\n-A OUTPUT -j LISACL_TEST_BOOT\n-A OUTPUT -j OTHER\n","OUTPUT",targets,2,present)&&!present[0]&&present[1]);
    CHECK(!boot_policy_hook_subset("-P OUTPUT ACCEPT\n-A OUTPUT -j LISACQ_TEST_BOOT\n-A OUTPUT -j LISACL_TEST_BOOT\n-A OUTPUT -j OTHER\n","OUTPUT",targets,2,present)&&present[0]&&present[1]);
    CHECK(boot_policy_hook_subset("-P OUTPUT ACCEPT\n-A OUTPUT -j OTHER\n-A OUTPUT -j LISACQ_TEST_BOOT\n","OUTPUT",targets,2,present)<0);
    CHECK(boot_policy_hook_subset("-P OUTPUT ACCEPT\n-A OUTPUT -j LISACL_TEST_BOOT\n-A OUTPUT -j LISACQ_TEST_BOOT\n","OUTPUT",targets,2,present)<0);
    CHECK(boot_policy_hook_subset("-P OUTPUT ACCEPT\n-A OUTPUT -p tcp -j LISACQ_TEST_BOOT\n","OUTPUT",targets,2,present)<0);
    CHECK(boot_policy_hook_subset("-P OUTPUT ACCEPT\n-A OUTPUT -j LISACQ_TEST_BOOT\n-A OUTPUT -j LISACQ_TEST_BOOT\n","OUTPUT",targets,2,present)<0);
    char directory[]="/tmp/lisa-boot-state.XXXXXX"; CHECK(mkdtemp(directory)!=NULL);
    int runtime=open(directory,O_RDONLY|O_DIRECTORY|O_CLOEXEC); CHECK(runtime>=0); uid_t owner=geteuid();
    for(unsigned kind=0;kind<2;++kind) {
        CHECK(boot_ledger_read(runtime,owner,kind,boot,chain)==1);
        CHECK(!boot_ledger_publish(runtime,owner,kind,boot,chain));
        CHECK(!boot_ledger_read(runtime,owner,kind,boot,chain));
        CHECK(!boot_ledger_publish(runtime,owner,kind,boot,chain));
        CHECK(boot_ledger_publish(runtime,owner,kind,"21111111-2222-4333-8444-555555555555",chain)<0);
        CHECK(boot_ledger_read(runtime,owner,kind,boot,"LISACQ_OTHER")<0);
        const char *name=boot_ledger_name(kind);
        CHECK(!linkat(runtime,name,runtime,"alias",0)); CHECK(boot_ledger_read(runtime,owner,kind,boot,chain)<0);
        CHECK(!unlinkat(runtime,"alias",0)); CHECK(!fchmodat(runtime,name,0644,0));
        CHECK(boot_ledger_read(runtime,owner,kind,boot,chain)<0); CHECK(!fchmodat(runtime,name,0600,0));
        int fd=openat(runtime,name,O_WRONLY|O_APPEND|O_CLOEXEC); CHECK(fd>=0&&write(fd,"X",1)==1&&!close(fd));
        CHECK(boot_ledger_read(runtime,owner,kind,boot,chain)<0); CHECK(boot_ledger_publish(runtime,owner,kind,boot,chain)<0);
        CHECK(!unlinkat(runtime,name,0)); CHECK(!symlinkat("missing",runtime,name));
        CHECK(boot_ledger_publish(runtime,owner,kind,boot,chain)<0); CHECK(!unlinkat(runtime,name,0));
    }
    CHECK(nonce_fixture(runtime,owner,boot,chain,EAGAIN));
    CHECK(!boot_ledger_read(runtime,owner,0,boot,chain)); CHECK(!unlinkat(runtime,"boot.policy",0));
    CHECK(nonce_fixture(runtime,owner,boot,chain,ENOSYS));
    CHECK(!boot_ledger_read(runtime,owner,0,boot,chain)); CHECK(!unlinkat(runtime,"boot.policy",0));
    CHECK(nonce_fixture(runtime,owner,boot,chain,EIO)); CHECK(boot_ledger_read(runtime,owner,0,boot,chain)==1);
    CHECK(!close(runtime)&&!rmdir(directory));
    printf("{\"selftest\":\"boot-state\",\"checks\":%u,\"ok\":true,\"firewall_changed\":false,\"services_changed\":false}\n",checks);
    return 0;
}
