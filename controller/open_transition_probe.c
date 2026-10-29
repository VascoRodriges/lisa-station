/* Own crash/persistence fixtures only. No vendor, network, audio or real mode
 * changes; callback success is deliberately not a platform isolation proof. */
#define _GNU_SOURCE
#include <stdlib.h>
#include <sys/wait.h>
#include <unistd.h>
#include <errno.h>
#include <sys/syscall.h>
static unsigned fsync_calls,fsync_fail_at;
static int fixture_fsync(int fd){
    if(++fsync_calls==fsync_fail_at){errno=EIO;return -1;}
    return (int)syscall(SYS_fsync,fd);
}
#define fsync fixture_fsync
#include "open_transition.h"
#undef fsync

static const char BOOT[]="11111111-2222-4333-8444-555555555555";
static const char NEXT_BOOT[]="21111111-2222-4333-8444-555555555555";
struct fixture {
    int state,runtime,deny_calls,stop_calls,prepare_calls,release_calls,verify_calls;
    int denied,stopped,prepared,released,bad,failure,crash_phase;
    uint64_t revision;const char *boot;uid_t owner;
};
static int fixture_write(int directory,const char *name,const char *text){
    if(unlinkat(directory,name,0)&&errno!=ENOENT)return -1;
    int fd=openat(directory,name,O_WRONLY|O_CREAT|O_EXCL|O_CLOEXEC,0600);
    if(fd<0)return -1;
    int failed=store_write_all(fd,text,strlen(text));if(close(fd))failed=1;return failed?-1:0;
}
static int deny_callback(void *pointer){
    struct fixture *f=pointer;++f->deny_calls;
    if(!mode_store_open_pending(f->state,f->owner)&&!mode_store_close_pending(f->state,f->owner))f->bad=1;
    if(f->failure==1||(f->failure==6&&f->deny_calls==1))return -1;
    f->denied=1;f->released=0;return 0;
}
static int stop_callback(void *pointer){
    struct fixture *f=pointer;++f->stop_calls;struct stat info;
    if(!f->denied||!fstatat(f->runtime,"vendor.permit",&info,AT_SYMLINK_NOFOLLOW)||errno!=ENOENT)f->bad=1;
    if(f->failure==2)return -1;
    f->stopped=1;return 0;
}
static int prepare_callback(void *pointer,uint64_t revision,const char *boot){
    struct fixture *f=pointer;++f->prepare_calls;
    struct mode_record record;struct gate_lease lease={-1,0};
    if(!f->denied||!f->stopped||revision!=f->revision||strcmp(boot,f->boot)||
        mode_store_boot_choice(f->state,f->owner)!=LISA_MODE_PAUSED||
        gate_acquire(f->state,f->runtime,f->owner,boot,&lease)!=GATE_DENIED||
        mode_store_request(f->state,f->owner,revision-1,LISA_MODE_ALICE,&record)!=STORE_BUSY)f->bad=1;
    gate_release(&lease);
    if(f->failure==3)return -1;
    f->prepared=1;return 0;
}
static int release_callback(void *pointer){
    struct fixture *f=pointer;++f->release_calls;struct mode_record mode;struct open_record pending;
    if(!f->denied||!f->prepared||!f->stopped||!mode_store_open_pending(f->state,f->owner)||
        mode_store_close_pending(f->state,f->owner)||mode_store_read(f->state,f->owner,&mode)!=STORE_OK||
        mode.revision!=f->revision||mode.requested!=LISA_MODE_ALICE||
        !gate_permit_valid(f->runtime,f->owner,mode.revision,f->boot)||open_read(f->state,f->owner,&pending)||
        pending.phase!=OPEN_PERMITTED)f->bad=1;
    if(f->failure==4)return -1;
    f->released=1;
    if(f->failure==7){f->failure=1;f->denied=0;return -1;}
    return 0;
}
static int verify_callback(void *pointer){
    struct fixture *f=pointer;++f->verify_calls;
    if(!f->released||!f->prepared||mode_store_boot_choice(f->state,f->owner)!=LISA_MODE_PAUSED)f->bad=1;
    return f->failure==5?-1:0;
}
static void checkpoint(void *pointer,enum open_phase phase){
    struct fixture *f=pointer;
    if(f->crash_phase==(int)phase)_exit(90+(int)phase);
}
static int closed_callback(void *pointer){(void)pointer;return 0;}
static int reset_fixture(struct fixture *f,int state,int runtime,uid_t owner){
    const char *names[]={"opening.request","closed.request","fault.request","transition.lock","mode.state","mode.lock"};
    for(unsigned i=0;i<sizeof(names)/sizeof(names[0]);++i)if(unlinkat(state,names[i],0)&&errno!=ENOENT)return -1;
    if(unlinkat(runtime,"vendor.permit",0)&&errno!=ENOENT)return -1;
    *f=(struct fixture){.state=state,.runtime=runtime,.owner=owner,.revision=3,.boot=BOOT,.crash_phase=-1};
    return fixture_write(state,"mode.state","LISA_MODE_V1 2 paused\n")||
        fixture_write(state,"closed.request","LISA_CLOSE_V1 1 paused complete\n");
}
#define CHECK(condition,name) do{++checks;if(!(condition)){fprintf(stderr,"failed:%s\n",name);failed=1;goto cleanup;}}while(0)
int main(int argc,char **argv){
    umask(077);alarm(25);const char *base="/tmp";
    if(argc==2&&!strcmp(argv[1],"--station-storage")&&!geteuid())base="/data/opt/lisa-controller-lab";
    else if(argc!=1)return 2;
    char path[256];snprintf(path,sizeof(path),"%s/open-transition-test.XXXXXX",base);
    if(!mkdtemp(path))return 3;
    int directory=open(path,O_RDONLY|O_DIRECTORY|O_CLOEXEC),state=-1,runtime=-1,held=-1,failed=0;unsigned checks=0;
    uid_t owner=geteuid();struct fixture f={0};struct gate_lease lease={-1,0};
    CHECK(directory>=0&&!mkdirat(directory,"state",0700)&&!mkdirat(directory,"run",0700),"private_fixture");
    state=openat(directory,"state",O_RDONLY|O_DIRECTORY|O_CLOEXEC);runtime=openat(directory,"run",O_RDONLY|O_DIRECTORY|O_CLOEXEC);
    CHECK(state>=0&&runtime>=0,"open_fixture");
    struct open_ops ops={deny_callback,stop_callback,prepare_callback,release_callback,verify_callback,checkpoint,&f};
    struct mode_record mode;struct open_record pending;
    for(int phase=OPEN_REQUESTED;phase<=OPEN_COMPLETE;++phase){
        CHECK(!reset_fixture(&f,state,runtime,owner),"reset_crash_fixture");f.crash_phase=phase;
        pid_t child=fork();CHECK(child>=0,"crash_fork");
        if(!child){(void)open_execute(state,runtime,owner,2,BOOT,&ops);_exit(120);}
        int status;CHECK(waitpid(child,&status,0)==child&&WIFEXITED(status)&&WEXITSTATUS(status)==90+phase,"durable_checkpoint_crash");
        CHECK(mode_store_read(state,owner,&mode)==STORE_OK&&mode.revision==(phase<OPEN_COMMITTED?2u:3u),"crash_revision_consistent");
        if(phase<OPEN_COMPLETE){
            CHECK(!open_read(state,owner,&pending)&&pending.phase==(enum open_phase)phase&&
                mode_store_boot_choice(state,owner)==LISA_MODE_PAUSED&&
                gate_acquire(state,runtime,owner,BOOT,&lease)==GATE_DENIED,"interrupted_return_never_boots_or_starts_alice");
            f.crash_phase=-1;
            CHECK(open_execute(state,runtime,owner,2,NEXT_BOOT,&ops)!=OPEN_OK&&
                mode_store_boot_choice(state,owner)==LISA_MODE_PAUSED,"new_boot_never_auto_resumes_opening");
            CHECK(open_execute(state,runtime,owner,2,BOOT,&ops)==OPEN_OK&&!f.bad&&f.deny_calls==1&&f.stop_calls==1&&
                f.prepare_calls==1&&f.release_calls==1&&f.verify_calls==1,"explicit_retry_reestablishes_all_callbacks");
        }
        CHECK(mode_store_read(state,owner,&mode)==STORE_OK&&mode.revision==3&&mode.requested==LISA_MODE_ALICE&&
            !mode_store_close_pending(state,owner)&&!mode_store_open_pending(state,owner)&&
            gate_permit_valid(runtime,owner,3,BOOT)&&mode_store_boot_choice(state,owner)==LISA_MODE_ALICE&&
            gate_acquire(state,runtime,owner,BOOT,&lease)==GATE_GRANTED,"only_completed_explicit_return_grants_admission");
        gate_release(&lease);
    }
    for(int failure=1;failure<=5;++failure){
        CHECK(!reset_fixture(&f,state,runtime,owner),"reset_callback_failure");f.failure=failure;
        enum open_result expected=failure<=3?OPEN_PREPARE:failure==4?OPEN_RELEASE:OPEN_VERIFY;
        CHECK(open_execute(state,runtime,owner,2,BOOT,&ops)==expected&&!f.bad&&f.deny_calls>=2&&(failure==1?f.stop_calls==0:f.stop_calls>=1)&&
            !gate_permit_valid(runtime,owner,3,BOOT)&&mode_store_boot_choice(state,owner)==LISA_MODE_PAUSED&&
            gate_acquire(state,runtime,owner,BOOT,&lease)==GATE_DENIED,"failed_open_denies_before_revoke_and_stop");
        f.failure=0;
        CHECK(open_execute(state,runtime,owner,2,BOOT,&ops)==OPEN_OK&&!f.bad,"explicit_retry_after_failure");
    }
    CHECK(!reset_fixture(&f,state,runtime,owner),"reset_partial_release_then_denial_failure");f.failure=7;
    CHECK(open_execute(state,runtime,owner,2,BOOT,&ops)==OPEN_RELEASE&&!f.bad&&f.stop_calls==1&&
        gate_permit_valid(runtime,owner,3,BOOT)&&mode_store_open_pending(state,owner)&&mode_store_boot_choice(state,owner)==LISA_MODE_PAUSED,
        "partial_release_does_not_revoke_or_teardown_before_recovered_barrier");
    CHECK(gate_acquire(state,runtime,owner,BOOT,&lease)==GATE_DENIED&&
        gate_acquire_running(state,runtime,owner,BOOT,&lease)==GATE_GRANTED,"pending_fault_fences_starts_without_premature_guardian_reset");
    gate_release(&lease);f.failure=0;
    CHECK(open_execute(state,runtime,owner,2,BOOT,&ops)==OPEN_OK&&!f.bad,"explicit_retry_reestablishes_barrier_after_partial_release");
    CHECK(!reset_fixture(&f,state,runtime,owner),"reset_transient_open_denial_failure");f.failure=6;
    CHECK(open_execute(state,runtime,owner,2,BOOT,&ops)==OPEN_PREPARE&&f.deny_calls==2&&f.stop_calls==1&&!f.bad,
        "open_safety_retries_barrier_before_teardown");
    f.failure=0;CHECK(open_execute(state,runtime,owner,2,BOOT,&ops)==OPEN_OK&&!f.bad,"explicit_retry_after_transient_denial");
    CHECK(!reset_fixture(&f,state,runtime,owner)&&open_execute(state,runtime,owner,1,BOOT,&ops)==OPEN_CONFLICT&&
        !f.deny_calls&&!mode_store_open_pending(state,owner),"stale_request_cannot_modify_closed_state");
    held=openat(state,"transition.lock",O_RDWR|O_CREAT|O_CLOEXEC,0600);
    CHECK(held>=0&&!flock(held,LOCK_EX|LOCK_NB)&&open_execute(state,runtime,owner,2,BOOT,&ops)==OPEN_BUSY&&
        !f.deny_calls&&!mode_store_open_pending(state,owner),"serialized_against_close_executor");close(held);held=-1;
    held=openat(state,"mode.lock",O_RDWR|O_CREAT|O_CLOEXEC,0600);
    CHECK(held>=0&&!flock(held,LOCK_SH|LOCK_NB)&&open_execute(state,runtime,owner,2,BOOT,&ops)==OPEN_BUSY&&
        !f.deny_calls&&!mode_store_open_pending(state,owner),"active_start_lease_blocks_open_request");close(held);held=-1;
    CHECK(!reset_fixture(&f,state,runtime,owner),"reset_cancel_case");f.failure=4;
    CHECK(open_execute(state,runtime,owner,2,BOOT,&ops)==OPEN_RELEASE,"cancel_interrupted_open");
    struct close_ops close_ops={closed_callback,closed_callback,closed_callback,NULL,NULL};
    CHECK(close_execute(state,runtime,owner,3,LISA_MODE_PAUSED,&close_ops)==CLOSE_OK&&
        mode_store_open_pending(state,owner)&&mode_store_boot_choice(state,owner)==LISA_MODE_PAUSED,"explicit_close_retains_open_fence");
    f.failure=0;f.revision=5;f.boot=NEXT_BOOT;
    CHECK(open_execute(state,runtime,owner,4,NEXT_BOOT,&ops)==OPEN_OK&&!f.bad&&gate_permit_valid(runtime,owner,5,NEXT_BOOT),
        "new_explicit_request_can_supersede_only_after_completed_close");
    CHECK(!reset_fixture(&f,state,runtime,owner),"prepare_early_open_cancellation");f.failure=3;
    CHECK(open_execute(state,runtime,owner,2,BOOT,&ops)==OPEN_PREPARE&&mode_store_open_pending(state,owner),
        "early_open_failed_before_old_close_fence_retirement");
    CHECK(close_execute(state,runtime,owner,2,LISA_MODE_PAUSED,&close_ops)==CLOSE_OK&&
        mode_store_read(state,owner,&mode)==STORE_OK&&mode.revision==3&&mode.requested==LISA_MODE_PAUSED&&
        mode_store_open_pending(state,owner),"explicit_cancel_advances_unchanged_closed_intent");
    CHECK(open_execute(state,runtime,owner,2,BOOT,&ops)==OPEN_CONFLICT&&mode_store_boot_choice(state,owner)==LISA_MODE_PAUSED,
        "cancelled_open_cannot_retry_stale_revision");
    f.failure=0;f.revision=4;
    CHECK(open_execute(state,runtime,owner,3,BOOT,&ops)==OPEN_OK&&!f.bad&&gate_permit_valid(runtime,owner,4,BOOT),
        "fresh_explicit_open_after_early_cancellation");
    CHECK(!reset_fixture(&f,state,runtime,owner)&&!unlinkat(state,"closed.request",0)&&
        open_execute(state,runtime,owner,2,BOOT,&ops)==OPEN_OK&&!f.bad,"initial_closed_intent_without_old_close_journal");
    CHECK(open_execute(state,runtime,owner,3,BOOT,&ops)==OPEN_CONFLICT,"open_is_never_implicit_alice_restart");
    CHECK(!reset_fixture(&f,state,runtime,owner),"reset_fsync_measurement");fsync_calls=0;
    CHECK(open_execute(state,runtime,owner,2,BOOT,&ops)==OPEN_OK&&!f.bad,"count_real_durability_boundaries");
    unsigned boundaries=fsync_calls;
    CHECK(boundaries>=15&&boundaries<64,"bounded_fsync_fault_matrix");
    for(unsigned point=1;point<=boundaries;++point){
        CHECK(!reset_fixture(&f,state,runtime,owner),"reset_fsync_fault");fsync_calls=0;fsync_fail_at=point;
        CHECK(open_execute(state,runtime,owner,2,BOOT,&ops)!=OPEN_OK&&!f.bad&&
            mode_store_boot_choice(state,owner)==LISA_MODE_PAUSED&&!gate_permit_valid(runtime,owner,3,BOOT),
            "each_fsync_failure_keeps_or_recreates_closed_fence");
        fsync_fail_at=0;
        CHECK(open_execute(state,runtime,owner,2,BOOT,&ops)==OPEN_OK&&!f.bad,"explicit_retry_after_each_fsync_failure");
    }
    fsync_fail_at=0;
    const char *bad[]={"bad\n","LISA_OPEN_V1 0 11111111-2222-4333-8444-555555555555 requested\n",
        "LISA_OPEN_V1 02 11111111-2222-4333-8444-555555555555 requested\n",
        "LISA_OPEN_V1 -1 11111111-2222-4333-8444-555555555555 requested\n",
        "LISA_OPEN_V1 18446744073709551615 11111111-2222-4333-8444-555555555555 requested\n",
        "LISA_OPEN_V1 2 invalid requested\n","LISA_OPEN_V1 2 11111111-2222-4333-8444-555555555555 unknown\n",
        "LISA_OPEN_V1 2 11111111-2222-4333-8444-555555555555 requested",
        "LISA_OPEN_V1 2 11111111-2222-4333-8444-555555555555 requested\n\n"};
    for(unsigned i=0;i<sizeof(bad)/sizeof(bad[0]);++i){
        CHECK(!reset_fixture(&f,state,runtime,owner)&&!fixture_write(state,"opening.request",bad[i])&&
            open_execute(state,runtime,owner,2,BOOT,&ops)==OPEN_INVALID&&f.deny_calls&&f.stop_calls&&
            open_read(state,owner,&pending)<0&&mode_store_boot_choice(state,owner)==LISA_MODE_PAUSED,"corrupt_open_fence_preserved");
    }
    CHECK(!reset_fixture(&f,state,runtime,owner)&&!symlinkat("mode.state",state,"opening.request")&&
        open_execute(state,runtime,owner,2,BOOT,&ops)==OPEN_INVALID&&mode_store_boot_choice(state,owner)==LISA_MODE_PAUSED,
        "symlink_open_fence_never_followed");
    CHECK(!reset_fixture(&f,state,runtime,owner)&&open_execute(state,runtime,owner,UINT64_MAX,BOOT,&ops)==OPEN_INVALID&&
        open_execute(state,runtime,owner,UINT64_MAX-1,BOOT,&ops)==OPEN_INVALID&&
        open_execute(state,runtime,owner,2,"invalid",&ops)==OPEN_INVALID&&!f.deny_calls,"invalid_request_rejected_without_callbacks");
    CHECK(!reset_fixture(&f,state,runtime,owner)&&!fixture_write(state,"fault.request","damaged\n")&&
        open_execute(state,runtime,owner,2,BOOT,&ops)==OPEN_RECOVERY&&!f.deny_calls&&!f.prepare_calls&&
        mode_store_boot_choice(state,owner)==LISA_MODE_PAUSED,"latched_fault_refuses_explicit_open_without_mutating_it");
    CHECK(!unlinkat(state,"fault.request",0)&&!symlinkat("missing",state,"fault.request")&&
        open_execute(state,runtime,owner,2,BOOT,&ops)==OPEN_RECOVERY,"unsafe_fault_also_refuses_explicit_open");
cleanup:
    gate_release(&lease);if(held>=0)close(held);
    if(runtime>=0){unlinkat(runtime,"vendor.permit",0);close(runtime);}
    if(state>=0){const char *names[]={"opening.request","closed.request","fault.request","transition.lock","mode.state","mode.lock"};
        for(unsigned i=0;i<sizeof(names)/sizeof(names[0]);++i)unlinkat(state,names[i],0);
        close(state);}
    unlinkat(directory,"run",AT_REMOVEDIR);unlinkat(directory,"state",AT_REMOVEDIR);close(directory);int removed=!rmdir(path);
    printf("{\"selftest\":\"open-transition\",\"checks\":%u,\"ok\":%s,\"temporary_directory_removed\":%s,"
        "\"production_mode_changed\":false,\"real_packet_policy_changed\":false,\"audio_opened\":false}\n",checks,failed?"false":"true",removed?"true":"false");
    return failed||!removed?4:0;
}
