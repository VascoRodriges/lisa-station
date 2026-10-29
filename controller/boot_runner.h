/* Bounded fixed boot-helper execution. Caller supplies only compiled-in specs;
 * no shell, caller PID, command string or external target path is accepted. */
#ifndef LISA_BOOT_RUNNER_H
#define LISA_BOOT_RUNNER_H
#include "startup_guardian.h"

enum boot_run_result { BOOT_RUN_OK, BOOT_RUN_INVALID, BOOT_RUN_FAILED, BOOT_RUN_TIMEOUT };
static inline enum boot_run_result boot_run(const char *executable,char *const *argv,unsigned milliseconds) {
    if(!executable||executable[0]!='/'||!argv||!argv[0]||!milliseconds||milliseconds>60000) return BOOT_RUN_INVALID;
    struct guardian_spec spec={.executable=executable}; struct stat expected;
    struct sigaction child_signal;
    if(guardian_target(&spec,&expected)||expected.st_nlink!=1||sigaction(SIGCHLD,NULL,&child_signal)||
        child_signal.sa_handler!=SIG_DFL||(child_signal.sa_flags&SA_NOCLDWAIT)) return BOOT_RUN_INVALID;
    uint64_t began=guardian_milliseconds();
    if(!began) return BOOT_RUN_FAILED;
    pid_t parent=getpid(),child=fork();
    if(child<0) return BOOT_RUN_FAILED;
    if(!child) {
        signal(SIGTERM,SIG_DFL); signal(SIGINT,SIG_DFL); signal(SIGHUP,SIG_DFL); signal(SIGPIPE,SIG_DFL);
        struct rlimit core={0,0}; umask(077);
        if(setpgid(0,0)||prctl(PR_SET_PDEATHSIG,SIGKILL)||getppid()!=parent||guardian_close_except(NULL,0)||
            setrlimit(RLIMIT_CORE,&core)||chdir("/")||clearenv()) _exit(80);
        int null=open("/dev/null",O_RDWR|O_CLOEXEC);
        if(null<0) _exit(81);
        for(int fd=0;fd<3;++fd) if(dup2(null,fd)<0||fcntl(fd,F_SETFD,0)) _exit(81);
        if(null>2) close(null);
        if(setenv("PATH","/usr/sbin:/usr/bin:/sbin:/bin",1)||setenv("LC_ALL","C",1)||
            prctl(PR_SET_PDEATHSIG,SIGKILL)||getppid()!=parent) _exit(82);
        execv(executable,argv); _exit(83);
    }
    /* Keep the child unreaped while signalling its own group; no journal PID
     * can be mistaken for an unrelated actor after PID reuse. */
    for(;;) {
        siginfo_t exited={0};
        if(waitid(P_PID,child,&exited,WEXITED|WNOHANG|WNOWAIT)) {
            if(errno==EINTR) continue;
            return BOOT_RUN_FAILED;
        }
        if(exited.si_pid) {
            /* A successful one-shot helper must not leave ordinary children
             * in this group. Intentional daemons have their own guarded session. */
            kill(-child,SIGKILL);
            int status; pid_t result;
            do { result=waitpid(child,&status,0); } while(result<0&&errno==EINTR);
            return result==child&&WIFEXITED(status)&&WEXITSTATUS(status)==0?BOOT_RUN_OK:BOOT_RUN_FAILED;
        }
        uint64_t now=guardian_milliseconds();
        if(!now||now-began>=milliseconds) {
            kill(-child,SIGTERM); kill(child,SIGTERM);
            struct timespec pause={0,100000000}; nanosleep(&pause,NULL);
            kill(-child,SIGKILL); kill(child,SIGKILL);
            int status; pid_t result;
            do { result=waitpid(child,&status,0); } while(result<0&&errno==EINTR);
            return result==child?BOOT_RUN_TIMEOUT:BOOT_RUN_FAILED;
        }
        struct timespec pause={0,10000000}; nanosleep(&pause,NULL);
    }
}
#endif
