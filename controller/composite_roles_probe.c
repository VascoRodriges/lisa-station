/* Synthetic durable-state fixtures only. No real services/firewall/audio. */
#define _GNU_SOURCE
#include "composite_roles.h"
#include "service_gate.h"
#include "policy_check.h"

static const char BOOT[]="11111111-2222-4333-8444-555555555555";
struct fixture {
    int state,runtime,deny_calls,bad,next,phase;
    unsigned policy_mask,live_mask,stop_fail,verify_fail,stopped,verified; uid_t owner;
};
static int deny(void *pointer) {
    struct fixture *f=pointer; ++f->deny_calls;
    if(!mode_store_close_pending(f->state,f->owner)) f->bad=1;
    return f->policy_mask==15?0:-1;
}
static int stop(void *pointer,unsigned role) {
    struct fixture *f=pointer;
    if(role>=4) return -1;
    struct stat info;
    if((unsigned)f->next!=role||f->policy_mask!=15||!f->deny_calls||!fstatat(f->runtime,"vendor.permit",&info,AT_SYMLINK_NOFOLLOW)||errno!=ENOENT) f->bad=1;
    f->next=(f->next+1)%4; f->stopped|=1u<<role;
    if(f->stop_fail&(1u<<role)) return -1;
    f->live_mask&=~(1u<<role); return 0;
}
static int absent(void *pointer,unsigned role) {
    struct fixture *f=pointer;
    if(role>=4) return -1;
    f->verified|=1u<<role;
    return ((f->live_mask|f->verify_fail)&(1u<<role))?-1:0;
}
static void checkpoint(void *pointer,enum close_phase phase) {
    struct composite_roles *roles=pointer; struct fixture *f=roles->context;
    if(f->phase==(int)phase) _exit(90+(int)phase);
}
static int write_fixture(int directory,const char *name,const char *text) {
    unlinkat(directory,name,0); int fd=openat(directory,name,O_WRONLY|O_CREAT|O_EXCL|O_CLOEXEC,0600);
    if(fd<0) return -1;
    int failed=store_write_all(fd,text,strlen(text)); if(close(fd)) failed=1; return failed?-1:0;
}
static int reset(struct fixture *f,int state,int runtime) {
    unlinkat(state,"closed.request",0); unlinkat(state,"transition.lock",0);
    unlinkat(state,"mode.state",0); unlinkat(state,"mode.lock",0); unlinkat(runtime,"vendor.permit",0);
    *f=(struct fixture){.state=state,.runtime=runtime,.policy_mask=15,.live_mask=15,.owner=geteuid(),.phase=-1};
    struct mode_record record; char permit[160];
    snprintf(permit,sizeof(permit),"LISA_VENDOR_PERMIT_V1 1 %s\n",BOOT);
    return mode_store_request(state,geteuid(),0,LISA_MODE_ALICE,&record)!=STORE_OK||write_fixture(runtime,"vendor.permit",permit);
}
static unsigned checks,failures;
static int check(int ok) { ++checks; if(!ok) { ++failures; fprintf(stderr,"failed:%u\n",checks); } return ok; }
int main(int argc,char **argv) {
    const char *base="/tmp";
    if(argc==2&&!strcmp(argv[1],"--station-storage")&&!geteuid()) base="/data/opt/lisa-controller-lab";
    else if(argc!=1) return 2;
    alarm(20); umask(077); signal(SIGPIPE,SIG_IGN);
    char path[256]; snprintf(path,sizeof(path),"%s/composite-roles.XXXXXX",base);
    if(!mkdtemp(path)) return 3;
    int directory=open(path,O_RDONLY|O_DIRECTORY|O_CLOEXEC),state=-1,runtime=-1;
    if(directory<0||mkdirat(directory,"state",0700)||mkdirat(directory,"run",0700)) return 3;
    state=openat(directory,"state",O_RDONLY|O_DIRECTORY|O_CLOEXEC); runtime=openat(directory,"run",O_RDONLY|O_DIRECTORY|O_CLOEXEC);
    if(state<0||runtime<0) return 3;
    struct fixture f; struct composite_roles roles={deny,stop,absent,&f};
    struct close_ops ops={composite_deny,composite_stop,composite_verify,checkpoint,&roles};
    struct gate_lease lease={-1,0}; struct close_record record;
    for(unsigned missing=0;missing<4;++missing) {
        if(!check(!reset(&f,state,runtime))) goto cleanup;
        f.policy_mask&=~(1u<<missing);
        check(close_execute(state,runtime,geteuid(),1,LISA_MODE_PAUSED,&ops)==CLOSE_POLICY);
        check(!f.bad&&f.stopped==0&&f.live_mask==15&&gate_permit_valid(runtime,geteuid(),1,BOOT));
        check(!close_read(state,geteuid(),&record)&&record.phase!=CLOSE_COMPLETE&&
            gate_acquire(state,runtime,geteuid(),BOOT,&lease)==GATE_DENIED);
        f.policy_mask=15;
        check(close_execute(state,runtime,geteuid(),1,LISA_MODE_PAUSED,&ops)==CLOSE_OK&&f.verified==15&&!f.bad);
    }
    for(unsigned failed=0;failed<4;++failed) {
        if(!check(!reset(&f,state,runtime))) goto cleanup;
        f.stop_fail=1u<<failed;
        check(close_execute(state,runtime,geteuid(),1,LISA_MODE_LISA,&ops)==CLOSE_STOP);
        check(f.stopped==15&&f.live_mask==(1u<<failed)&&!f.bad&&mode_store_boot_choice(state,geteuid())==LISA_MODE_PAUSED);
        f.stop_fail=0;
        check(close_execute(state,runtime,geteuid(),1,LISA_MODE_LISA,&ops)==CLOSE_OK&&f.verified==15&&!f.bad);
        if(!check(!reset(&f,state,runtime))) goto cleanup;
        f.verify_fail=1u<<failed;
        check(close_execute(state,runtime,geteuid(),1,LISA_MODE_PAUSED,&ops)==CLOSE_VERIFY&&f.verified==15&&f.stopped==15&&!f.bad);
    }
    for(int phase=CLOSE_REQUESTED;phase<=CLOSE_COMPLETE;++phase) {
        if(!check(!reset(&f,state,runtime))) goto cleanup;
        f.phase=phase; pid_t child=fork();
        if(!check(child>=0)) goto cleanup;
        if(!child) { (void)close_execute(state,runtime,geteuid(),1,LISA_MODE_PAUSED,&ops); _exit(120); }
        int status;
        check(waitpid(child,&status,0)==child&&WIFEXITED(status)&&WEXITSTATUS(status)==90+phase);
        check(mode_store_boot_choice(state,geteuid())==LISA_MODE_PAUSED&&gate_acquire(state,runtime,geteuid(),BOOT,&lease)==GATE_DENIED);
        f.phase=-1;
        check(close_execute(state,runtime,geteuid(),1,LISA_MODE_PAUSED,&ops)==CLOSE_OK&&f.stopped==15&&f.verified==15&&!f.bad);
    }
    char expected[1024];
    check(policy_expected_groups("LISACQ_TEST",composite_groups,4,expected,sizeof(expected))>0&&
        strstr(expected,"--gid-owner 57342 -j DROP\n")&&strstr(expected,"--gid-owner 57345 -j DROP\n"));
    check(policy_expected_groups("LISACQ_TEST",composite_groups,0,expected,sizeof(expected))<0);
    check(policy_expected_groups("LISACQ_TEST",composite_groups,4,expected,8)<0);
    const unsigned duplicate[]={57342,57342},unordered[]={57343,57342},unknown[]={0};
    check(policy_expected_groups("LISACQ_TEST",duplicate,2,expected,sizeof(expected))<0);
    check(policy_expected_groups("LISACQ_TEST",unordered,2,expected,sizeof(expected))<0);
    check(policy_expected_groups("LISACQ_TEST",unknown,1,expected,sizeof(expected))<0);
    check(policy_expected_groups("OUTPUT",composite_groups,4,expected,sizeof(expected))<0);
    check(policy_expected_groups("LISACQ_BAD\n",composite_groups,4,expected,sizeof(expected))<0);
    struct composite_roles invalid={0};
    check(composite_deny(&invalid)<0&&composite_stop(&invalid)<0&&composite_verify(&invalid)<0);
cleanup:
    gate_release(&lease);
    const char *files[]={"closed.request","transition.lock","mode.state","mode.lock"};
    for(unsigned i=0;i<sizeof(files)/sizeof(files[0]);++i) unlinkat(state,files[i],0);
    unlinkat(runtime,"vendor.permit",0); close(state); close(runtime);
    check(!unlinkat(directory,"state",AT_REMOVEDIR)&&!unlinkat(directory,"run",AT_REMOVEDIR));
    close(directory); check(!rmdir(path));
    printf("{\"selftest\":\"composite-roles\",\"checks\":%u,\"ok\":%s,\"fixture_only\":true,"
        "\"audio_opened\":false,\"vendor_processes_changed\":false}\n",checks,failures?"false":"true");
    return failures?4:0;
}
