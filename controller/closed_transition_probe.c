/* Transaction/crash fixtures only; callback ordering is tested without changing
 * any real firewall or service. A separate role trial verifies real integration.
 */
#define _GNU_SOURCE
#include <stdlib.h>
#include <sys/wait.h>
#include "closed_transition.h"
#include "service_gate.h"

static const char BOOT[]="11111111-2222-4333-8444-555555555555";
struct fixture {
    int state,runtime,deny_calls,stop_calls,verify_calls,denied,stopped,bad;
    int deny_fail,stop_fail,verify_fail,crash_phase;
    uid_t owner;
};
static int deny_callback(void *pointer) {
    struct fixture *f=pointer;
    ++f->deny_calls;
    if(!mode_store_close_pending(f->state,f->owner)) f->bad=1;
    if(f->deny_fail) return -1;
    f->denied=1; return 0;
}
static int stop_callback(void *pointer) {
    struct fixture *f=pointer; ++f->stop_calls;
    struct stat info;
    if(!f->deny_calls || !fstatat(f->runtime,"vendor.permit",&info,AT_SYMLINK_NOFOLLOW) || errno!=ENOENT) f->bad=1;
    if(f->stop_fail) return -1;
    f->stopped=1; return 0;
}
static int verify_callback(void *pointer) {
    struct fixture *f=pointer; ++f->verify_calls;
    if(!f->denied || !f->stopped) f->bad=1;
    return f->verify_fail?-1:0;
}
static void checkpoint(void *pointer,enum close_phase phase) {
    struct fixture *f=pointer;
    if(f->crash_phase==(int)phase) _exit(90+(int)phase);
}
static int write_fixture(int directory,const char *name,const char *text) {
    unlinkat(directory,name,0);
    int fd=openat(directory,name,O_WRONLY|O_CREAT|O_EXCL|O_CLOEXEC,0600);
    if(fd<0) return -1;
    int failed=store_write_all(fd,text,strlen(text)); if(close(fd)) failed=1; return failed?-1:0;
}
static int permit_fixture(int runtime,uint64_t revision) {
    char text[160]; snprintf(text,sizeof(text),"LISA_VENDOR_PERMIT_V1 %" PRIu64 " %s\n",revision,BOOT);
    return write_fixture(runtime,"vendor.permit",text);
}
static int reset_fixture(struct fixture *f,int state,int runtime,uid_t owner) {
    unlinkat(state,"closed.request",0); unlinkat(state,"transition.lock",0);
    unlinkat(state,"mode.state",0); unlinkat(state,"mode.lock",0); unlinkat(runtime,"vendor.permit",0);
    *f=(struct fixture){.state=state,.runtime=runtime,.owner=owner,.crash_phase=-1};
    struct mode_record record;
    return mode_store_request(state,owner,0,LISA_MODE_ALICE,&record)!=STORE_OK || permit_fixture(runtime,1);
}
#define CHECK(condition,name) do { ++checks; if(!(condition)) { \
    fprintf(stderr,"failed:%s\n",name); failed=1; goto cleanup; } } while(0)

int main(int argc,char **argv) {
    umask(077);
    const char *base="/tmp";
    if(argc==2 && !strcmp(argv[1],"--station-storage") && !geteuid()) base="/data/opt/lisa-controller-lab";
    else if(argc!=1) return 2;
    char path[256]; snprintf(path,sizeof(path),"%s/closed-transition-test.XXXXXX",base);
    if(!mkdtemp(path)) return 3;
    int directory=open(path,O_RDONLY|O_DIRECTORY|O_CLOEXEC),state=-1,runtime=-1,held=-1,failed=0;
    unsigned checks=0; uid_t owner=geteuid(); struct fixture f={0};
    struct gate_lease lease={-1,0};
    CHECK(directory>=0 && !mkdirat(directory,"state",0700) && !mkdirat(directory,"run",0700),"private_fixture");
    state=openat(directory,"state",O_RDONLY|O_DIRECTORY|O_CLOEXEC);
    runtime=openat(directory,"run",O_RDONLY|O_DIRECTORY|O_CLOEXEC);
    CHECK(state>=0 && runtime>=0,"open_fixture");
    struct close_ops ops={deny_callback,stop_callback,verify_callback,checkpoint,&f};
    struct mode_record mode; struct close_record pending;
    for(int phase=CLOSE_REQUESTED;phase<=CLOSE_COMPLETE;++phase) {
        CHECK(!reset_fixture(&f,state,runtime,owner),"reset_crash_fixture");
        f.crash_phase=phase;
        pid_t child=fork();
        CHECK(child>=0,"checkpoint_crash_fork");
        if(!child) { (void)close_execute(state,runtime,owner,1,LISA_MODE_PAUSED,&ops); _exit(120); }
        int status;
        CHECK(waitpid(child,&status,0)==child && WIFEXITED(status) && WEXITSTATUS(status)==90+phase,
              "coordinator_exited_at_durable_checkpoint");
        CHECK(!close_read(state,owner,&pending) && pending.phase==(enum close_phase)phase &&
            mode_store_boot_choice(state,owner)==LISA_MODE_PAUSED &&
            gate_acquire(state,runtime,owner,BOOT,&lease)==GATE_DENIED,"checkpoint_never_boots_stale_alice");
        CHECK(mode_store_read(state,owner,&mode)==STORE_OK && mode.revision==(phase<CLOSE_COMMITTED?1u:2u),
              "checkpoint_intent_revision_consistent");
        f.crash_phase=-1;
        CHECK(close_execute(state,runtime,owner,1,LISA_MODE_PAUSED,&ops)==CLOSE_OK &&
            !close_read(state,owner,&pending) && pending.phase==CLOSE_COMPLETE,"resume_reestablishes_closed_scope");
        CHECK(f.deny_calls>0 && f.stop_calls>0 && f.verify_calls==1 && !f.bad &&
            mode_store_read(state,owner,&mode)==STORE_OK && mode.revision==2 && mode.requested==LISA_MODE_PAUSED,
            "resume_does_not_trust_cached_policy_or_double_commit");
    }
    for(int failure=0;failure<3;++failure) {
        CHECK(!reset_fixture(&f,state,runtime,owner),"reset_failure_fixture");
        f.deny_fail=failure==0; f.stop_fail=failure==1; f.verify_fail=failure==2;
        enum close_result expected=failure==0?CLOSE_POLICY:failure==1?CLOSE_STOP:CLOSE_VERIFY;
        CHECK(close_execute(state,runtime,owner,1,LISA_MODE_LISA,&ops)==expected && !f.bad &&
            mode_store_close_pending(state,owner) && mode_store_boot_choice(state,owner)==LISA_MODE_PAUSED,
            "phase_failure_keeps_closed_fence");
        CHECK(!gate_permit_valid(runtime,owner,1,BOOT) &&
            gate_acquire(state,runtime,owner,BOOT,&lease)==GATE_DENIED,"phase_failure_revokes_alice");
        f.deny_fail=f.stop_fail=f.verify_fail=0;
        CHECK(close_execute(state,runtime,owner,1,LISA_MODE_LISA,&ops)==CLOSE_OK &&
            mode_store_read(state,owner,&mode)==STORE_OK && mode.revision==2 && mode.requested==LISA_MODE_LISA,
            "retry_same_request_commits_only_once");
    }
    CHECK(!reset_fixture(&f,state,runtime,owner) &&
        close_execute(state,runtime,owner,2,LISA_MODE_PAUSED,&ops)==CLOSE_CONFLICT &&
        !mode_store_close_pending(state,owner) && !f.deny_calls,"stale_new_request_does_not_modify_state");
    CHECK(gate_acquire(state,runtime,owner,BOOT,&lease)==GATE_GRANTED &&
        close_execute(state,runtime,owner,1,LISA_MODE_PAUSED,&ops)==CLOSE_BUSY &&
        mode_store_boot_choice(state,owner)==LISA_MODE_PAUSED,"busy_start_cannot_prevent_durable_close_fence");
    gate_release(&lease);
    CHECK(close_execute(state,runtime,owner,1,LISA_MODE_PAUSED,&ops)==CLOSE_OK,"retry_after_start_lease_released");
    CHECK(mode_store_request(state,owner,2,LISA_MODE_ALICE,&mode)==STORE_OK && !permit_fixture(runtime,3) &&
        gate_acquire(state,runtime,owner,BOOT,&lease)==GATE_DENIED &&
        mode_store_boot_choice(state,owner)==LISA_MODE_PAUSED,"raw_alice_write_cannot_bypass_close_fence");
    CHECK(close_execute(state,runtime,owner,1,LISA_MODE_PAUSED,&ops)==CLOSE_CONFLICT &&
        !gate_permit_valid(runtime,owner,3,BOOT),"unexpected_epoch_remains_closed");
    CHECK(!reset_fixture(&f,state,runtime,owner) && !write_fixture(state,"closed.request","bad\n") &&
        close_execute(state,runtime,owner,1,LISA_MODE_PAUSED,&ops)==CLOSE_INVALID && f.deny_calls && f.stop_calls &&
        close_read(state,owner,&pending)<0 && mode_store_boot_choice(state,owner)==LISA_MODE_PAUSED,
        "corrupt_fence_preserved_with_best_effort_denial");
    CHECK(!reset_fixture(&f,state,runtime,owner),"reset_serialization_fixture");
    held=openat(state,"transition.lock",O_RDWR|O_CREAT|O_CLOEXEC,0600);
    CHECK(held>=0 && !flock(held,LOCK_EX|LOCK_NB) &&
        close_execute(state,runtime,owner,1,LISA_MODE_PAUSED,&ops)==CLOSE_BUSY &&
        !f.deny_calls && !mode_store_close_pending(state,owner),"requests_serialized_without_partial_side_effects");
    close(held); held=-1;
    CHECK(close_execute(state,runtime,owner,UINT64_MAX,LISA_MODE_PAUSED,&ops)==CLOSE_INVALID &&
        close_execute(state,runtime,owner,1,LISA_MODE_ALICE,&ops)==CLOSE_INVALID,"overflow_and_open_transition_rejected");
cleanup:
    gate_release(&lease); if(held>=0) close(held);
    if(runtime>=0) { unlinkat(runtime,"vendor.permit",0); close(runtime); }
    if(state>=0) {
        unlinkat(state,"closed.request",0); unlinkat(state,"transition.lock",0);
        unlinkat(state,"mode.state",0); unlinkat(state,"mode.lock",0); close(state);
    }
    unlinkat(directory,"run",AT_REMOVEDIR); unlinkat(directory,"state",AT_REMOVEDIR); close(directory);
    int removed=!rmdir(path);
    printf("{\"selftest\":\"closed-transition\",\"checks\":%u,\"ok\":%s,\"temporary_directory_removed\":%s,"
        "\"production_mode_changed\":false,\"real_packet_policy_changed\":false}\n",checks,failed?"false":"true",removed?"true":"false");
    return failed||!removed?4:0;
}
