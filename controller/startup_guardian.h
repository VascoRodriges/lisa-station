/* Fixed-role guardian engine. Callers supply only trusted compiled-in specs.
 * Journals track processes, not privacy. Whole vendor isolation is separate.
 */
#ifndef LISA_STARTUP_GUARDIAN_H
#define LISA_STARTUP_GUARDIAN_H
#include <limits.h>
#include <dirent.h>
#include <poll.h>
#include <signal.h>
#include <stdlib.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <sys/xattr.h>
#include <time.h>
#include "service_gate.h"

enum guardian_result { GUARD_OK, GUARD_DENIED, GUARD_BUSY, GUARD_RECOVERY, GUARD_FAILED };
enum guardian_phase { G_RESERVING, G_FORKED, G_PREPARED, G_RUNNING, G_STOPPED, G_FAILED, G_EXITED };
struct process_stamp { uint64_t ticks; pid_t group, parent; char state; };
struct guardian_record {
    uint64_t revision, guardian_ticks, child_ticks;
    pid_t guardian, child;
    char boot[37];
    enum guardian_phase phase;
};
struct guardian_spec {
    const char *role, *executable;
    char *const *argv;
    int (*prepare)(void);
    int (*observe)(pid_t);
    int (*actors_absent)(const struct guardian_record *);
    unsigned maximum_seconds; /* 0 for an installed service, bounded in trials. */
};
struct guardian_started { enum guardian_result result; struct guardian_record record; };
static volatile sig_atomic_t guardian_termination;
static void guardian_signal(int signal_number) { (void)signal_number; guardian_termination = 1; }

static inline uint64_t guardian_milliseconds(void) {
    struct timespec now;
    if (clock_gettime(CLOCK_MONOTONIC, &now)) return 0;
    return (uint64_t)now.tv_sec * 1000 + (unsigned)now.tv_nsec / 1000000;
}

static inline int process_stamp(pid_t pid, struct process_stamp *stamp) {
    if (pid < 2) return -1;
    char path[64], data[2048]; snprintf(path, sizeof(path), "/proc/%ld/stat", (long)pid);
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) return -1;
    ssize_t size = read(fd, data, sizeof(data)-1); close(fd);
    if (size <= 0 || size == sizeof(data)-1) return -1;
    data[size] = 0;
    char *tail = strrchr(data, ')');
    if (!tail || tail[1] != ' ' || !tail[2] || tail[3] != ' ') return -1;
    memset(stamp, 0, sizeof(*stamp)); stamp->state = tail[2]; tail += 4;
    for (unsigned field = 4; field <= 22; ++field) {
        char *end = strchr(tail, ' ');
        if (!end) return -1;
        if (field == 4 || field == 5 || field == 22) {
            char *parsed;
            errno = 0;
            unsigned long long value = strtoull(tail, &parsed, 10);
            if (errno || parsed != end || (field != 22 && value > INT_MAX)) return -1;
            if (field == 4) stamp->parent = (pid_t)value;
            else if (field == 5) stamp->group = (pid_t)value;
            else stamp->ticks = value;
        }
        tail = end + 1;
    }
    return stamp->ticks ? 0 : -1;
}

static inline int process_live(pid_t pid, uint64_t ticks) {
    struct process_stamp stamp;
    return !process_stamp(pid, &stamp) && stamp.ticks == ticks && stamp.state != 'Z' && stamp.state != 'X';
}

static inline int guardian_names(const struct guardian_spec *spec, char *record, char *lock, char *socket_name) {
    size_t length = strlen(spec->role);
    if (!length || length > 16) return -1;
    for (size_t i = 0; i < length; ++i)
        if (spec->role[i] < 'a' || spec->role[i] > 'z') return -1;
    snprintf(record, 32, "%s.child", spec->role);
    snprintf(lock, 32, "%s.start-lock", spec->role);
    snprintf(socket_name, 32, "%s.control", spec->role);
    return 0;
}

static inline const char *guardian_phase_name(enum guardian_phase phase) {
    const char *names[] = {"reserving", "forked", "prepared", "running", "stopped", "failed", "exited"};
    return (unsigned)phase < sizeof(names)/sizeof(names[0]) ? names[phase] : NULL;
}

static inline int guardian_format(char *text, size_t capacity, const struct guardian_record *record) {
    if (!record->revision || record->guardian < 2 || !record->guardian_ticks ||
        !gate_boot_valid(record->boot) || !guardian_phase_name(record->phase) ||
        (record->child == 0 ? record->child_ticks || (record->phase != G_RESERVING && record->phase != G_FAILED) :
            record->child < 2 || !record->child_ticks)) return -1;
    return snprintf(text, capacity, "LISA_CHILD_V1 %" PRIu64 " %s %ld %" PRIu64 " %ld %" PRIu64 " %s\n",
        record->revision, record->boot, (long)record->guardian, record->guardian_ticks,
        (long)record->child, record->child_ticks, guardian_phase_name(record->phase));
}

/* 1 means missing; invalid content is never silently replaced. */
static inline int guardian_read(int runtime, uid_t owner, const char *name, struct guardian_record *record) {
    if (!store_directory_valid(runtime, owner)) return -1;
    int fd = openat(runtime, name, O_RDONLY | O_NONBLOCK | O_NOFOLLOW | O_CLOEXEC);
    if (fd < 0) return errno == ENOENT ? 1 : -1;
    if (!store_file_valid(fd, owner)) { close(fd); return -1; }
    char text[256], canonical[256], phase[24], boot[40]; size_t used = 0;
    while (used < sizeof(text)-1) {
        ssize_t count = read(fd, text + used, sizeof(text)-1-used);
        if (count < 0 && errno == EINTR) continue;
        if (count < 0) { close(fd); return -1; }
        if (!count) break;
        used += (size_t)count;
    }
    close(fd); text[used] = 0;
    if (!used || used == sizeof(text)-1 || memchr(text, 0, used)) return -1;
    unsigned long long revision, gticks, cticks; long guardian, child; int consumed = 0;
    if (sscanf(text, "LISA_CHILD_V1 %llu %39s %ld %llu %ld %llu %23s\n%n", &revision, boot,
        &guardian, &gticks, &child, &cticks, phase, &consumed) != 7 || consumed != (int)used ||
        guardian < 2 || guardian > INT_MAX || child < 0 || child > INT_MAX || !gate_boot_valid(boot)) return -1;
    enum guardian_phase parsed = G_RESERVING;
    while (parsed <= G_EXITED && strcmp(phase, guardian_phase_name(parsed))) ++parsed;
    struct guardian_record next = {.revision=revision, .guardian_ticks=gticks, .child_ticks=cticks,
        .guardian=(pid_t)guardian, .child=(pid_t)child, .phase=parsed};
    memcpy(next.boot, boot, 37);
    if (guardian_format(canonical, sizeof(canonical), &next) != (int)used || memcmp(text, canonical, used)) return -1;
    *record = next;
    return 0;
}

static inline int guardian_save(int runtime, uid_t owner, const char *name, struct guardian_record *record) {
    struct guardian_record previous;
    int existing = guardian_read(runtime, owner, name, &previous);
    if (existing < 0 || (existing == 1 && record->phase != G_RESERVING) ||
        (existing == 0 && (previous.guardian != record->guardian ||
                         previous.guardian_ticks != record->guardian_ticks))) return -1;
    char text[256], temporary[64]; uint64_t nonce;
    int size = guardian_format(text, sizeof(text), record);
    if (size < 0 || size >= (int)sizeof(text) || getrandom(&nonce, sizeof(nonce), 0) != sizeof(nonce)) return -1;
    snprintf(temporary, sizeof(temporary), ".child-%" PRIx64 ".tmp", nonce);
    int fd = openat(runtime, temporary, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
    if (fd < 0) return -1;
    int failed = store_write_all(fd, text, (size_t)size) || fsync(fd);
    if (close(fd)) failed = 1;
    if (!failed && renameat(runtime, temporary, runtime, name)) failed = 1;
    if (!failed && fsync(runtime)) failed = 1;
    if (failed) unlinkat(runtime, temporary, 0);
    return failed ? -1 : 0;
}

static inline int guardian_role_lock(int runtime, uid_t owner, const char *name) {
    int fd = openat(runtime, name, O_RDWR | O_CREAT | O_NONBLOCK | O_NOFOLLOW | O_CLOEXEC, 0600);
    if (fd < 0) return -1;
    if (!store_file_valid(fd, owner) || flock(fd, LOCK_EX | LOCK_NB)) { close(fd); return -1; }
    return fd;
}

static inline int guardian_address(int runtime, const char *name, struct sockaddr_un *address) {
    memset(address, 0, sizeof(*address)); address->sun_family = AF_UNIX;
    int size = snprintf(address->sun_path, sizeof(address->sun_path), "/proc/self/fd/%d/%s", runtime, name);
    return size > 0 && size < (int)sizeof(address->sun_path) ? 0 : -1;
}

static inline int guardian_readable(int fd, int timeout) {
    struct pollfd ready = {fd, POLLIN, 0};
    int rc;
    do { rc = poll(&ready, 1, timeout); } while (rc < 0 && errno == EINTR && !guardian_termination);
    return rc == 1 && (ready.revents & (POLLIN | POLLHUP));
}

static inline int guardian_close_except(const int *keep,size_t count) {
    DIR *directory=opendir("/proc/self/fd");
    if(!directory) return -1;
    int listing=dirfd(directory),failed=0; struct dirent *entry;
    for(;;) {
        errno=0; entry=readdir(directory);
        if(!entry) { if(errno) failed=1; break; }
        char *end; long value=strtol(entry->d_name,&end,10);
        if(*end||value<3||value>INT_MAX||value==listing) continue;
        int preserve=0;
        for(size_t i=0;i<count;++i) if(value==keep[i]) preserve=1;
        if(!preserve && close((int)value) && errno!=EBADF) failed=1;
    }
    closedir(directory); return failed?-1:0;
}

/* Keep the direct child unreaped until group teardown, so its PID cannot be
 * reused as an unrelated process/group. No negative/unknown PIDs are accepted. */
static inline int guardian_teardown(pid_t child) {
    if (child < 2) return -1;
    siginfo_t owned={0};
    if(waitid(P_PID,child,&owned,WEXITED|WNOHANG|WNOWAIT)) return -1;
    kill(-child, SIGTERM); kill(child, SIGTERM);
    struct timespec delay = {0, 200000000}; nanosleep(&delay, NULL);
    kill(-child, SIGKILL); kill(child, SIGKILL);
    int status;
    pid_t reaped;
    do { reaped=waitpid(child,&status,0); } while(reaped<0 && errno==EINTR);
    while (waitpid(-1, &status, WNOHANG) > 0) {}
    return reaped==child?0:-1;
}

static inline int guardian_target(const struct guardian_spec *spec, struct stat *identity) {
    int fd = open(spec->executable, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0) return -1;
    char capability[64]; errno = 0;
    ssize_t size = fgetxattr(fd, "security.capability", capability, sizeof(capability));
    int valid = size < 0 && (errno == ENODATA || errno == EOPNOTSUPP) && !fstat(fd, identity) &&
        S_ISREG(identity->st_mode) && (identity->st_uid == 0 ||
            (geteuid() != 0 && identity->st_uid == geteuid())) &&
        !(identity->st_mode & (0022 | S_ISUID | S_ISGID));
    close(fd); return valid ? 0 : -1;
}

static inline int guardian_exec_observed(pid_t child, uint64_t ticks, const struct stat *expected,
                                          const struct guardian_spec *spec) {
    char path[64]; snprintf(path, sizeof(path), "/proc/%ld/exe", (long)child);
    struct stat actual;
    return process_live(child, ticks) && !stat(path, &actual) && actual.st_ino == expected->st_ino &&
        actual.st_dev == expected->st_dev && (!spec->observe || !spec->observe(child)) && process_live(child, ticks);
}

static inline void guardian_child(const struct guardian_spec *spec, pid_t parent, int report, int go) {
    const int keep[]={report,go};
    if(guardian_close_except(keep,sizeof(keep)/sizeof(keep[0]))) _exit(70);
    signal(SIGTERM, SIG_DFL); signal(SIGINT, SIG_DFL); signal(SIGHUP, SIG_DFL); signal(SIGPIPE, SIG_DFL);
    if (setpgid(0, 0) || prctl(PR_SET_PDEATHSIG, SIGKILL) || getppid() != parent ||
        (spec->prepare && spec->prepare())) _exit(71);
    /* Effective/filesystem credential changes clear PDEATHSIG: arm it again
     * after the fixed child preparation and recheck the parent race. */
    if (prctl(PR_SET_PDEATHSIG, SIGKILL) || getppid() != parent ||
        write(report, "P", 1) != 1 || !guardian_readable(go, 4000)) _exit(72);
    char ready;
    if (read(go, &ready, 1) != 1 || ready != 'G' || getppid() != parent) _exit(73);
    close(go);
    execv(spec->executable, spec->argv);
    if(write(report,"F",1)!=1) _exit(78);
    _exit(74);
}

static inline void guardian_run(int state, int runtime, uid_t owner, const char *boot,
    const struct guardian_spec *spec, int notify, int role_lock, struct gate_lease *lease,
    const char *record_name, const char *socket_name) {
    guardian_termination = 0;
    umask(077);
    signal(SIGPIPE, SIG_IGN); signal(SIGTERM, guardian_signal); signal(SIGINT, guardian_signal);
    signal(SIGHUP, guardian_signal); signal(SIGALRM, guardian_signal); signal(SIGCHLD, SIG_DFL);
    alarm(8);
    struct guardian_started response = {.result=GUARD_FAILED};
    struct guardian_record *record = &response.record;
    struct process_stamp self;
    int setup[2] = {-1,-1}, go[2] = {-1,-1}, control=-1, stop_client=-1, announced=0, bound=0, teardown=0;
    pid_t child = -1;
    const int keep[]={state,runtime,notify,role_lock,lease->descriptor};
    if(guardian_close_except(keep,sizeof(keep)/sizeof(keep[0]))) goto finish;
    int null=open("/dev/null",O_RDWR|O_CLOEXEC);
    if (null<0) goto finish;
    for (int fd=0;fd<3;++fd) if (dup2(null,fd)<0) { close(null); goto finish; }
    if (null>2) close(null);
    if (setsid() < 0 || prctl(PR_SET_CHILD_SUBREAPER, 1) || process_stamp(getpid(), &self)) goto finish;
    *record = (struct guardian_record){.revision=lease->revision, .guardian=getpid(), .guardian_ticks=self.ticks,
                                       .phase=G_RESERVING};
    memcpy(record->boot, boot, 37);
    struct stat expected;
    if (guardian_target(spec, &expected) || guardian_save(runtime, owner, record_name, record)) goto finish;
    struct sockaddr_un address;
    control = socket(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC | SOCK_NONBLOCK, 0);
    if (control < 0 || guardian_address(runtime, socket_name, &address) ||
        bind(control, (struct sockaddr *)&address, sizeof(address))) goto finish;
    bound=1;
    if (listen(control,2) || pipe2(setup,O_CLOEXEC) || pipe2(go,O_CLOEXEC) || guardian_termination) goto finish;
    pid_t parent=getpid();
    child = fork();
    if (!child) { close(setup[0]); close(go[1]); guardian_child(spec, parent, setup[1], go[0]); _exit(75); }
    if (child < 0) goto finish;
    close(setup[1]); setup[1]=-1; close(go[0]); go[0]=-1;
    char token;
    struct process_stamp stamp;
    if (process_stamp(child,&stamp)) goto finish;
    record->child=child; record->child_ticks=stamp.ticks; record->phase=G_FORKED;
    if (guardian_save(runtime,owner,record_name,record) || !guardian_readable(setup[0],4000) ||
        read(setup[0],&token,1)!=1 || token!='P' || guardian_termination) goto finish;
    record->child=child; record->child_ticks=stamp.ticks; record->phase=G_PREPARED;
    if (guardian_save(runtime, owner, record_name, record) || mode_store_close_pending(state,owner) ||
        !gate_permit_valid(runtime,owner,lease->revision,boot) || write(go[1], "G", 1) != 1) goto finish;
    close(go[1]); go[1]=-1;
    if (!guardian_readable(setup[0], 4000) || read(setup[0], &token, 1) != 0 ||
        !guardian_exec_observed(child, stamp.ticks, &expected, spec) || guardian_termination) goto finish;
    record->phase=G_RUNNING;
    if (guardian_save(runtime, owner, record_name, record)) goto finish;
    response.result=GUARD_OK;
    gate_release(lease); /* Startup is journaled and observed before replying. */
    if (write(notify, &response, sizeof(response)) != sizeof(response)) goto finish;
    announced=1;
    alarm(0);
    close(notify); notify=-1;
    uint64_t deadline = spec->maximum_seconds ? guardian_milliseconds() + spec->maximum_seconds*1000u : 0;
    while (!guardian_termination && (!deadline || guardian_milliseconds() < deadline)) {
        siginfo_t status = {0};
        if (waitid(P_PID, child, &status, WEXITED | WNOHANG | WNOWAIT) || status.si_pid) break;
        struct gate_lease current = {-1,0};
        enum gate_result allowed = gate_acquire_running(state, runtime, owner, boot, &current);
        /* A contended mode lock is not evidence of permit revocation. Keep
         * serving the authenticated stop channel and recheck after release;
         * shutdown before the close executor installs denial can emit traffic. */
        int same = allowed == GATE_BUSY || (allowed == GATE_GRANTED && current.revision == record->revision);
        gate_release(&current);
        if (!same) break;
        if (guardian_readable(control, 100)) {
            int peer = accept4(control, NULL, NULL, SOCK_CLOEXEC | SOCK_NONBLOCK);
            if (peer >= 0) {
                struct ucred credentials; socklen_t size=sizeof(credentials); char command[2];
                if (!getsockopt(peer, SOL_SOCKET, SO_PEERCRED, &credentials, &size) && credentials.uid == owner && credentials.gid == getegid() &&
                    guardian_readable(peer, 200) && recv(peer, command, sizeof(command), MSG_TRUNC) == 1 && command[0] == 'S') {
                    stop_client=peer; break;
                }
                close(peer);
            }
        }
    }
finish:
    teardown=child>1?guardian_teardown(child):0;
    int absent = 0;
    for (unsigned attempt=0;attempt<20;++attempt) {
        absent=spec->actors_absent && spec->actors_absent(record);
        if (absent) break;
        int status; while(waitpid(-1,&status,WNOHANG)>0) {}
        struct timespec delay={0,50000000}; nanosleep(&delay,NULL);
    }
    record->phase = announced && absent && !teardown ? G_STOPPED : G_FAILED;
    int saved = record->guardian > 1 && !guardian_save(runtime, owner, record_name, record);
    if (control >= 0) close(control);
    if (bound) unlinkat(runtime,socket_name,0);
    if (stop_client >= 0) {
        if(send(stop_client,saved&&absent&&!teardown?"S":"F",1,MSG_NOSIGNAL)!=1) saved=0;
        close(stop_client);
    }
    for (unsigned i=0; i<2; ++i) { if (setup[i]>=0) close(setup[i]); if (go[i]>=0) close(go[i]); }
    gate_release(lease);
    if (!announced && notify >= 0) {
        response.result=GUARD_FAILED;
        if(write(notify,&response,sizeof(response))!=sizeof(response)) saved=0;
        close(notify);
    }
    close(role_lock);
    _exit(saved ? 0 : 76);
}

static inline enum guardian_result guardian_start(int state, int runtime, uid_t owner, const char *boot,
    const struct guardian_spec *spec, struct guardian_started *started) {
    memset(started, 0, sizeof(*started)); started->result=GUARD_DENIED;
    struct sigaction child_signal;
    if (sigaction(SIGCHLD,NULL,&child_signal) || child_signal.sa_handler!=SIG_DFL ||
        (child_signal.sa_flags&SA_NOCLDWAIT)) return GUARD_DENIED;
    char record_name[32], lock_name[32], socket_name[32];
    if (!spec->actors_absent || guardian_names(spec, record_name, lock_name, socket_name)) return GUARD_DENIED;
    struct gate_lease lease={-1,0};
    enum gate_result admission=gate_acquire(state, runtime, owner, boot, &lease);
    if (admission != GATE_GRANTED) return admission == GATE_BUSY ? GUARD_BUSY : GUARD_DENIED;
    int role_lock=guardian_role_lock(runtime, owner, lock_name);
    if (role_lock < 0) { gate_release(&lease); return GUARD_BUSY; }
    struct guardian_record previous;
    if (guardian_read(runtime, owner, record_name, &previous) != 1) {
        close(role_lock); gate_release(&lease); return GUARD_RECOVERY;
    }
    int result[2];
    if (pipe2(result, O_CLOEXEC)) { close(role_lock); gate_release(&lease); return GUARD_FAILED; }
    pid_t process=fork();
    if (!process) {
        close(result[0]); guardian_run(state,runtime,owner,boot,spec,result[1],role_lock,&lease,record_name,socket_name);
    }
    close(result[1]); close(role_lock); gate_release(&lease);
    enum guardian_result answer=GUARD_FAILED;
    if (process > 1 && guardian_readable(result[0], 10000) &&
        read(result[0], started, sizeof(*started)) == sizeof(*started)) answer=started->result;
    close(result[0]);
    if (process>1 && answer!=GUARD_OK) {
        int status, reaped=0;
        kill(process,SIGTERM); /* Own unreaped child, not a journal-supplied PID. */
        for (unsigned i=0;i<30;++i) {
            if (waitpid(process,&status,WNOHANG)==process) { reaped=1; break; }
            struct timespec delay={0,50000000}; nanosleep(&delay,NULL);
        }
        if (!reaped) {
            kill(process,SIGKILL);
            for (unsigned i=0;i<10;++i) {
                if (waitpid(process,&status,WNOHANG)==process) break;
                struct timespec delay={0,50000000}; nanosleep(&delay,NULL);
            }
        }
    }
    return answer;
}

static inline enum guardian_result guardian_stop(int runtime, uid_t owner, const char *boot, const struct guardian_spec *spec) {
    if (!store_directory_valid(runtime, owner)) return GUARD_DENIED;
    char record[32], lock[32], name[32]; struct sockaddr_un address;
    if (guardian_names(spec,record,lock,name) || guardian_address(runtime,name,&address)) return GUARD_DENIED;
    struct guardian_record expected;
    if (guardian_read(runtime,owner,record,&expected) || strcmp(expected.boot,boot)) return GUARD_RECOVERY;
    int fd=socket(AF_UNIX,SOCK_SEQPACKET|SOCK_CLOEXEC|SOCK_NONBLOCK,0);
    if (fd<0) return GUARD_FAILED;
    enum guardian_result result=GUARD_RECOVERY;
    struct ucred peer; socklen_t length=sizeof(peer); char response;
    if (!connect(fd,(struct sockaddr*)&address,sizeof(address)) &&
        !getsockopt(fd,SOL_SOCKET,SO_PEERCRED,&peer,&length) && peer.uid==owner && peer.gid==getegid() && peer.pid==expected.guardian &&
        process_live(peer.pid,expected.guardian_ticks) &&
        send(fd,"S",1,MSG_NOSIGNAL)==1 && guardian_readable(fd,4000) && recv(fd,&response,1,0)==1 && response=='S') result=GUARD_OK;
    close(fd); return result;
}

/* Explicit closed recovery only. No signals, no startup and no Alice permit.
 * Caller supplies a role-specific inventory proving no remaining actors. */
static inline enum guardian_result guardian_reconcile_closed(int state,int runtime,uid_t owner,const char *boot,
    const struct guardian_spec *spec) {
    if (!store_directory_valid(state,owner) || !store_directory_valid(runtime,owner) || !gate_boot_valid(boot)) return GUARD_DENIED;
    int mode_lock=guardian_role_lock(state,owner,"mode.lock");
    if (mode_lock<0) return GUARD_BUSY;
    char name[32], lock[32], socket_name[32]; int role_lock=-1;
    enum guardian_result result=GUARD_DENIED; struct mode_record requested; struct guardian_record record;
    if (guardian_names(spec,name,lock,socket_name) || mode_store_read(state,owner,&requested)!=STORE_OK ||
        requested.requested==LISA_MODE_ALICE) goto done;
    if ((unlinkat(runtime,"vendor.permit",0) && errno!=ENOENT) || fsync(runtime)) goto done;
    role_lock=guardian_role_lock(runtime,owner,lock);
    if (role_lock<0) { result=GUARD_BUSY; goto done; }
    if (guardian_read(runtime,owner,name,&record) || strcmp(record.boot,boot) ||
        process_live(record.guardian,record.guardian_ticks) || process_live(record.child,record.child_ticks) ||
        !spec->actors_absent || !spec->actors_absent(&record)) { result=GUARD_RECOVERY; goto done; }
    struct stat info;
    if (!fstatat(runtime,socket_name,&info,AT_SYMLINK_NOFOLLOW)) {
        if (!S_ISSOCK(info.st_mode) || info.st_uid!=owner || unlinkat(runtime,socket_name,0)) goto done;
    } else if (errno!=ENOENT) goto done;
    if (!unlinkat(runtime,name,0) && !fsync(runtime)) result=GUARD_OK;
done:
    if (role_lock>=0) close(role_lock);
    close(mode_lock); return result;
}
#endif
