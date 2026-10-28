/* Own sleep processes and private fixtures only. No speaker service is started. */
#define _GNU_SOURCE
#include <dirent.h>
#include "startup_guardian.h"

static const char BOOT[]="11111111-2222-4333-8444-555555555555";
static const char OLD_BOOT[]="aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee";
static int copy_actor(int directory) {
    int input=open("/proc/self/exe",O_RDONLY|O_CLOEXEC);
    int output=openat(directory,"actor",O_WRONLY|O_CREAT|O_EXCL|O_CLOEXEC,0700);
    if (input<0 || output<0) { if(input>=0) close(input); if(output>=0) close(output); return -1; }
    char buffer[8192]; int result=0;
    for (;;) {
        ssize_t size=read(input,buffer,sizeof(buffer));
        if (size<0 || (size>0 && store_write_all(output,buffer,(size_t)size))) { result=-1; break; }
        if (!size) break;
    }
    close(input); if(close(output)) result=-1; return result;
}
static int delayed_prepare(void) {
    /* Root hardware tests exercise credential changes clearing PDEATHSIG,
     * including a guardian crash inside this preparation window. */
    if (!geteuid() && setgid(57341)) return -1;
    struct timespec delay={1,500000000}; nanosleep(&delay,NULL); return 0;
}
static int reject_observation(pid_t pid) { (void)pid; return -1; }
static int absence_unknown(const struct guardian_record *record) { (void)record; return 0; }
static int group_absent(const struct guardian_record *record) {
    if (record->child<2) return 1;
    DIR *directory=opendir("/proc");
    if (!directory) return 0;
    struct dirent *entry; int absent=1;
    while ((entry=readdir(directory))) {
        char *end; long pid=strtol(entry->d_name,&end,10);
        if (*end || pid<2 || pid>INT_MAX) continue;
        struct process_stamp stamp;
        if (!process_stamp((pid_t)pid,&stamp) && stamp.state!='Z' && stamp.state!='X' && stamp.group==record->child) absent=0;
    }
    closedir(directory); return absent;
}
static int fixture_permit(int runtime,uint64_t revision) {
    char text[160]; int size=snprintf(text,sizeof(text),"LISA_VENDOR_PERMIT_V1 %" PRIu64 " %s\n",revision,BOOT);
    unlinkat(runtime,"vendor.permit",0);
    int fd=openat(runtime,"vendor.permit",O_WRONLY|O_CREAT|O_EXCL|O_CLOEXEC,0600);
    if (fd<0) return -1;
    int result=store_write_all(fd,text,(size_t)size); close(fd); return result;
}
static int fixture_record(int runtime,const char *text) {
    unlinkat(runtime,"fixture.child",0);
    int fd=openat(runtime,"fixture.child",O_WRONLY|O_CREAT|O_EXCL|O_CLOEXEC,0600);
    if (fd<0) return -1;
    int result=store_write_all(fd,text,strlen(text)); close(fd); return result;
}
static enum store_result request_mode(int state,uid_t owner,uint64_t revision,enum lisa_mode mode,struct mode_record *next) {
    for (unsigned i=0;i<100;++i) {
        enum store_result result=mode_store_request(state,owner,revision,mode,next);
        if (result!=STORE_BUSY) return result;
        struct timespec delay={0,10000000}; nanosleep(&delay,NULL);
    }
    return STORE_BUSY;
}
static int reap(pid_t child) {
    int status;
    for (unsigned i=0;i<100;++i) {
        pid_t result=waitpid(child,&status,WNOHANG);
        if (result==child) return 1;
        if (result<0 && errno==ECHILD) return 1;
        struct timespec delay={0,20000000}; nanosleep(&delay,NULL);
    }
    return 0;
}
static int gone(pid_t child,uint64_t ticks) {
    for (unsigned i=0;i<100;++i) {
        if (!process_live(child,ticks)) return 1;
        struct timespec delay={0,20000000}; nanosleep(&delay,NULL);
    }
    return 0;
}
static pid_t contender(int state,int runtime,uid_t owner,uint64_t revision,int report,int crash) {
    pid_t child=fork();
    if (child) return child;
    alarm(5);
    for (unsigned i=0;i<200;++i) {
        struct guardian_record record;
        if (!guardian_read(runtime,owner,"fixture.child",&record) && record.phase==G_FORKED) {
            if (crash) {
                struct process_stamp stamp;
                if (process_stamp(record.guardian,&stamp) || stamp.parent!=getppid()) _exit(12);
                /* A sibling which our common parent has not reaped; PID pinned. */
                if (kill(record.guardian,SIGKILL)) _exit(13);
                if(write(report,"K",1)!=1) _exit(16);
                _exit(0);
            }
            struct mode_record next;
            char result=mode_store_request(state,owner,revision,LISA_MODE_PAUSED,&next)==STORE_BUSY ? 'B' : 'F';
            if(write(report,&result,1)!=1) _exit(16);
            _exit(result=='B'?0:14);
        }
        struct timespec delay={0,10000000}; nanosleep(&delay,NULL);
    }
    _exit(15);
}

#define CHECK(condition,name) do { ++checks; if (!(condition)) { \
    fprintf(stderr,"failed:%s\n",name); failed=1; goto cleanup; } } while(0)

int main(int argc,char **argv) {
    if (argc==2 && !strcmp(argv[1],"--fixture-actor")) {
        int death_signal=0;
        if (prctl(PR_GET_PDEATHSIG,&death_signal) || death_signal!=SIGKILL || getpgrp()!=getpid()) return 81;
        for (int fd=3;fd<1024;++fd) if (fcntl(fd,F_GETFD)!=-1 || errno!=EBADF) return 82;
        struct timespec delay={20,0}; nanosleep(&delay,NULL); return 0;
    }
    umask(077); alarm(45);
    if (prctl(PR_SET_CHILD_SUBREAPER,1)) return 2;
    const char *base="/tmp";
    if (argc==2 && !strcmp(argv[1],"--station-storage") && !geteuid()) base="/data/opt/lisa-controller-lab";
    else if (argc!=1) return 2;
    char path[256],target[PATH_MAX];
    snprintf(path,sizeof(path),"%s/guardian-test.XXXXXX",base);
    if (!mkdtemp(path)) return 3;
    snprintf(target,sizeof(target),"%s/actor",path);
    int directory=open(path,O_RDONLY|O_DIRECTORY|O_CLOEXEC),state=-1,runtime=-1,failed=0,inherited=-1,lowered=0;
    struct rlimit original_limit;
    unsigned checks=0;
    pid_t sentinel=-1,watcher=-1;
    struct guardian_started started={0},duplicate={0};
    struct guardian_record record={0};
    struct mode_record intent={0};
    uid_t owner=geteuid();
    char *const args[]={"guardian-fixture","--fixture-actor",NULL};
    struct guardian_spec spec={.role="fixture",.executable=target,.argv=args,.actors_absent=group_absent,.maximum_seconds=15};
    CHECK(directory>=0 && !mkdirat(directory,"state",0700) && !mkdirat(directory,"run",0700) &&
        !copy_actor(directory),"private_fixture");
    state=openat(directory,"state",O_RDONLY|O_DIRECTORY|O_CLOEXEC);
    runtime=openat(directory,"run",O_RDONLY|O_DIRECTORY|O_CLOEXEC);
    CHECK(state>=0 && runtime>=0 && mode_store_boot_choice(state,owner)==LISA_MODE_PAUSED &&
        guardian_start(state,runtime,owner,BOOT,&spec,&started)==GUARD_DENIED,"missing_mode_never_spawns");
    CHECK(request_mode(state,owner,0,LISA_MODE_ALICE,&intent)==STORE_OK &&
        guardian_start(state,runtime,owner,BOOT,&spec,&started)==GUARD_DENIED,"alice_without_permit_never_spawns");
    CHECK(!fixture_permit(runtime,intent.revision),"explicit_fixture_permit");
    CHECK(!fchmodat(directory,"actor",04700,0) &&
        guardian_start(state,runtime,owner,BOOT,&spec,&started)==GUARD_FAILED &&
        !fchmodat(directory,"actor",0700,0),"setuid_target_rejected_before_exec");
    sentinel=fork();
    CHECK(sentinel>=0,"unrelated_control_fork");
    if (!sentinel) { alarm(35); for (;;) pause(); }
    struct process_stamp control;
    CHECK(!process_stamp(sentinel,&control),"unrelated_control_identity");
    int channel[2]; CHECK(!pipe(channel),"race_channel");
    watcher=contender(state,runtime,owner,intent.revision,channel[1],0);
    CHECK(watcher>1,"transition_contender");
    close(channel[1]); spec.prepare=delayed_prepare;
    CHECK(!getrlimit(RLIMIT_NOFILE,&original_limit) && original_limit.rlim_cur>=512,"descriptor_test_limit");
    int source=open("/dev/null",O_RDONLY|O_CLOEXEC);
    if(source>=0) { inherited=fcntl(source,F_DUPFD,300); close(source); }
    struct rlimit limited=original_limit; limited.rlim_cur=64;
    CHECK(inherited>=300 && inherited<1024 && !setrlimit(RLIMIT_NOFILE,&limited),"inherited_fd_above_soft_limit");
    lowered=1;
    enum guardian_result first=guardian_start(state,runtime,owner,BOOT,&spec,&started);
    if (first!=GUARD_OK) {
        struct guardian_record diagnostic;
        int present=guardian_read(runtime,owner,"fixture.child",&diagnostic);
        fprintf(stderr,"start_result=%d journal=%d phase=%d child=%ld\n",first,present,
            present ? -1 : (int)diagnostic.phase,present ? 0L : (long)diagnostic.child);
    }
    CHECK(first==GUARD_OK,"guarded_exec_confirmed");
    CHECK(!setrlimit(RLIMIT_NOFILE,&original_limit),"parent_descriptor_limit_restored");
    lowered=0; close(inherited); inherited=-1;
    char result;
    CHECK(read(channel[0],&result,1)==1 && result=='B' && reap(watcher),"mode_commit_excluded_during_prepare");
    watcher=-1; close(channel[0]); spec.prepare=NULL;
    CHECK(!guardian_read(runtime,owner,"fixture.child",&record) && record.phase==G_RUNNING &&
        record.child==started.record.child && process_live(record.child,record.child_ticks),"running_journal_matches_process");
    CHECK(guardian_start(state,runtime,owner,BOOT,&spec,&duplicate)==GUARD_BUSY,"duplicate_start_rejected");
    CHECK(guardian_stop(runtime,owner,BOOT,&spec)==GUARD_OK && reap(started.record.guardian) &&
        gone(record.child,record.child_ticks),"stop_over_verified_unix_control");
    CHECK(process_live(sentinel,control.ticks),"unrelated_process_survives_stop");
    CHECK(guardian_start(state,runtime,owner,BOOT,&spec,&duplicate)==GUARD_RECOVERY &&
        guardian_reconcile_closed(state,runtime,owner,BOOT,&spec)==GUARD_DENIED,"no_implicit_alice_restart");
    CHECK(request_mode(state,owner,intent.revision,LISA_MODE_PAUSED,&intent)==STORE_OK &&
        guardian_reconcile_closed(state,runtime,owner,BOOT,&spec)==GUARD_OK,"closed_reconcile_clears_terminal_journal");
    CHECK(gate_permit_valid(runtime,owner,1,BOOT)==0 &&
        guardian_start(state,runtime,owner,BOOT,&spec,&duplicate)==GUARD_DENIED,"closed_recovery_revokes_permit");
    CHECK(request_mode(state,owner,intent.revision,LISA_MODE_ALICE,&intent)==STORE_OK &&
        !fixture_permit(runtime,intent.revision) &&
        guardian_start(state,runtime,owner,BOOT,&spec,&started)==GUARD_OK,"explicit_alice_restart");
    CHECK(!unlinkat(runtime,"vendor.permit",0) && reap(started.record.guardian) &&
        gone(started.record.child,started.record.child_ticks),"permit_revocation_stops_service");
    CHECK(request_mode(state,owner,intent.revision,LISA_MODE_PAUSED,&intent)==STORE_OK &&
        guardian_reconcile_closed(state,runtime,owner,BOOT,&spec)==GUARD_OK,"revocation_recovery_closed");
    CHECK(request_mode(state,owner,intent.revision,LISA_MODE_ALICE,&intent)==STORE_OK &&
        !fixture_permit(runtime,intent.revision) &&
        guardian_start(state,runtime,owner,BOOT,&spec,&started)==GUARD_OK,"start_before_closed_transition");
    CHECK(request_mode(state,owner,intent.revision,LISA_MODE_PAUSED,&intent)==STORE_OK &&
        reap(started.record.guardian) && gone(started.record.child,started.record.child_ticks),
        "closed_mode_stops_existing_guardian");
    CHECK(guardian_reconcile_closed(state,runtime,owner,BOOT,&spec)==GUARD_OK,"closed_transition_reconciled");
    CHECK(request_mode(state,owner,intent.revision,LISA_MODE_ALICE,&intent)==STORE_OK &&
        !fixture_permit(runtime,intent.revision),"prepare_failure_case_intent");
    spec.observe=reject_observation;
    CHECK(guardian_start(state,runtime,owner,BOOT,&spec,&started)==GUARD_FAILED &&
        !guardian_read(runtime,owner,"fixture.child",&record) && record.phase==G_FAILED &&
        !process_live(record.child,record.child_ticks),"failed_exec_observation_never_reports_running");
    spec.observe=NULL;
    CHECK(request_mode(state,owner,intent.revision,LISA_MODE_PAUSED,&intent)==STORE_OK &&
        guardian_reconcile_closed(state,runtime,owner,BOOT,&spec)==GUARD_OK,"failed_start_recovery_closed");
    CHECK(request_mode(state,owner,intent.revision,LISA_MODE_ALICE,&intent)==STORE_OK &&
        !fixture_permit(runtime,intent.revision) &&
        guardian_start(state,runtime,owner,BOOT,&spec,&started)==GUARD_OK,"start_before_guardian_crash");
    CHECK(!kill(started.record.guardian,SIGKILL) && reap(started.record.guardian) &&
        gone(started.record.child,started.record.child_ticks),"parent_death_kills_direct_service");
    (void)reap(started.record.child);
    CHECK(guardian_start(state,runtime,owner,BOOT,&spec,&duplicate)==GUARD_RECOVERY &&
        guardian_reconcile_closed(state,runtime,owner,BOOT,&spec)==GUARD_DENIED,"crash_never_automatically_restarts");
    CHECK(request_mode(state,owner,intent.revision,LISA_MODE_PAUSED,&intent)==STORE_OK &&
        guardian_reconcile_closed(state,runtime,owner,BOOT,&spec)==GUARD_OK,"interrupted_running_recovered_closed");
    CHECK(request_mode(state,owner,intent.revision,LISA_MODE_ALICE,&intent)==STORE_OK &&
        !fixture_permit(runtime,intent.revision) && !pipe(channel),"prepare_interrupted_start");
    watcher=contender(state,runtime,owner,intent.revision,channel[1],1);
    CHECK(watcher>1,"crash_contender_fork");
    close(channel[1]); spec.prepare=delayed_prepare;
    CHECK(guardian_start(state,runtime,owner,BOOT,&spec,&started)==GUARD_FAILED &&
        read(channel[0],&result,1)==1 && result=='K' && reap(watcher),"crash_during_prepare_never_succeeds");
    watcher=-1; close(channel[0]); spec.prepare=NULL;
    CHECK(!guardian_read(runtime,owner,"fixture.child",&record) && record.phase==G_FORKED &&
        gone(record.child,record.child_ticks),"pre_exec_crash_retains_recoverable_journal");
    (void)reap(record.child);
    CHECK(request_mode(state,owner,intent.revision,LISA_MODE_PAUSED,&intent)==STORE_OK &&
        guardian_reconcile_closed(state,runtime,owner,BOOT,&spec)==GUARD_OK,"pre_exec_crash_recovered_closed");
    CHECK(request_mode(state,owner,intent.revision,LISA_MODE_ALICE,&intent)==STORE_OK &&
        !fixture_permit(runtime,intent.revision),"prepare_unknown_inventory_case");
    spec.actors_absent=absence_unknown;
    CHECK(guardian_start(state,runtime,owner,BOOT,&spec,&started)==GUARD_OK &&
        guardian_stop(runtime,owner,BOOT,&spec)==GUARD_RECOVERY && reap(started.record.guardian),
        "unknown_inventory_never_reports_stopped");
    CHECK(!guardian_read(runtime,owner,"fixture.child",&record) && record.phase==G_FAILED &&
        !process_live(record.child,record.child_ticks),"unknown_inventory_preserves_failure_journal");
    CHECK(request_mode(state,owner,intent.revision,LISA_MODE_PAUSED,&intent)==STORE_OK &&
        guardian_reconcile_closed(state,runtime,owner,BOOT,&spec)==GUARD_RECOVERY,
        "unknown_inventory_blocks_reconciliation");
    spec.actors_absent=group_absent;
    CHECK(guardian_reconcile_closed(state,runtime,owner,BOOT,&spec)==GUARD_OK,"verified_inventory_allows_closed_recovery");
    CHECK(!fixture_record(runtime,"broken\n") &&
        guardian_reconcile_closed(state,runtime,owner,BOOT,&spec)==GUARD_RECOVERY,"corrupt_journal_not_discarded");
    struct guardian_record stale={.revision=intent.revision,.guardian=sentinel,.guardian_ticks=control.ticks,.phase=G_FAILED};
    memcpy(stale.boot,OLD_BOOT,37);
    char text[256]; int length=guardian_format(text,sizeof(text),&stale);
    CHECK(length>0 && !fixture_record(runtime,text) &&
        guardian_stop(runtime,owner,BOOT,&spec)==GUARD_RECOVERY &&
        guardian_reconcile_closed(state,runtime,owner,BOOT,&spec)==GUARD_RECOVERY &&
        process_live(sentinel,control.ticks),"stale_boot_cannot_stop_unrelated_pid");
cleanup:
    if(lowered) (void)setrlimit(RLIMIT_NOFILE,&original_limit);
    if(inherited>=0) close(inherited);
    if (runtime>=0) (void)guardian_stop(runtime,owner,BOOT,&spec);
    if (started.record.guardian>1) (void)reap(started.record.guardian);
    if (watcher>1) { kill(watcher,SIGKILL); (void)reap(watcher); }
    if (sentinel>1) { kill(sentinel,SIGTERM); (void)reap(sentinel); }
    int status; while(waitpid(-1,&status,WNOHANG)>0) {}
    if (runtime>=0) {
        unlinkat(runtime,"fixture.child",0); unlinkat(runtime,"fixture.start-lock",0);
        unlinkat(runtime,"fixture.control",0); unlinkat(runtime,"vendor.permit",0); close(runtime);
    }
    if (state>=0) { unlinkat(state,"mode.state",0); unlinkat(state,"mode.lock",0); close(state); }
    unlinkat(directory,"run",AT_REMOVEDIR); unlinkat(directory,"state",AT_REMOVEDIR);
    unlinkat(directory,"actor",0); close(directory);
    int removed=!rmdir(path);
    printf("{\"selftest\":\"startup-guardian\",\"checks\":%u,\"ok\":%s,\"temporary_directory_removed\":%s,"
        "\"production_mode_changed\":false}\n",checks,failed?"false":"true",removed?"true":"false");
    return failed||!removed?4:0;
}
