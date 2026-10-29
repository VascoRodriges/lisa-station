#define _GNU_SOURCE
#include <fcntl.h>
#include <limits.h>
#include <poll.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <time.h>
#include "platform_worker_guard.h"

_Static_assert(ATOMIC_INT_LOCK_FREE==2,"Signal counters require lock-free ints");
static unsigned checks,failures;
static void check(int ok){++checks;if(!ok){++failures;fprintf(stderr,"worker check %u\n",checks);}}
#define DENIED(expression) do{errno=0;long value=(expression);check(value==-1&&errno==EPERM);}while(0)
/* A filter regression must fail the fixture without leaving forked workers. */
static long fork_attempt(int use_vfork){
    long child=use_vfork?vfork():fork();
    if(child==0)_exit(5);
    if(child>0){int status;kill((pid_t)child,SIGKILL);while(waitpid((pid_t)child,&status,0)<0&&errno==EINTR){} _exit(5);}
    return child;
}
static int unexpected_clone(void *unused){(void)unused;return 5;}
static long clone_attempt(unsigned flags,void *stack){
    long child=clone(unexpected_clone,stack,(int)flags,NULL,NULL,NULL,NULL);
    if(child>=0)_exit(5);
    return child;
}
static _Atomic int signals,thread_tid,thread_ok;
static void handled(int value){(void)value;atomic_fetch_add(&signals,1);}
static int pause_until(_Atomic int *value,int minimum){
    struct timespec delay={0,1000000};
    for(int i=0;i<2000;++i){if(atomic_load(value)>=minimum)return 1;nanosleep(&delay,NULL);}return 0;
}
static void *thread_main(void *argument){
    pid_t parent=*(pid_t *)argument;errno=0;
    int good=prctl(PR_GET_NO_NEW_PRIVS,0,0,0,0)==1&&prctl(PR_GET_SECCOMP,0,0,0,0)==2&&
        syscall(SYS_kill,parent,0)==-1&&errno==EPERM;
    errno=0;good=good&&fork_attempt(0)==-1&&errno==EPERM;
    good=good&&syscall(SYS_tgkill,getpid(),syscall(SYS_gettid),0)==0;
    atomic_store(&thread_ok,good);atomic_store(&thread_tid,(int)syscall(SYS_gettid));
    for(;;){struct timespec delay={0,1000000};nanosleep(&delay,NULL);pthread_testcancel();}
    return NULL;
}
struct result{unsigned checks,failures;pid_t process,parent,peer;};
static int actor(pid_t parent,pid_t peer,int report){
    alarm(12);check(getppid()==parent&&getpid()!=peer);
    int death=0;check(!prctl(PR_GET_PDEATHSIG,&death,0,0,0)&&death==SIGKILL);
    check(prctl(PR_GET_NO_NEW_PRIVS,0,0,0,0)==1&&prctl(PR_GET_SECCOMP,0,0,0,0)==2);
    struct sigaction action={0};action.sa_handler=handled;sigemptyset(&action.sa_mask);
    check(!sigaction(SIGUSR1,&action,NULL)&&!sigaction(SIGUSR2,&action,NULL));
    check(!kill(getpid(),0)&&!kill(getpid(),SIGUSR1)&&pause_until(&signals,1));
    check(!syscall(SYS_tgkill,getpid(),syscall(SYS_gettid),SIGUSR1)&&pause_until(&signals,2));
    union sigval value={.sival_int=7};
    check(!sigqueue(getpid(),SIGUSR2,value)&&pause_until(&signals,3));
    siginfo_t info={0};info.si_signo=SIGUSR2;info.si_code=SI_QUEUE;info.si_pid=getpid();info.si_uid=getuid();
    check(!syscall(SYS_rt_tgsigqueueinfo,getpid(),syscall(SYS_gettid),SIGUSR2,&info)&&pause_until(&signals,4));
    DENIED(syscall(SYS_kill,parent,0));DENIED(syscall(SYS_kill,peer,0));
    DENIED(syscall(SYS_kill,0,0));DENIED(syscall(SYS_kill,-1,0));DENIED(syscall(SYS_kill,-getpgrp(),0));
    DENIED(syscall(SYS_tgkill,parent,parent,0));DENIED(syscall(SYS_tgkill,peer,peer,0));
    errno=0;check(syscall(SYS_tgkill,getpid(),parent,0)==-1&&errno==ESRCH);
    DENIED(syscall(SYS_tkill,syscall(SYS_gettid),0));
    DENIED(syscall(SYS_rt_sigqueueinfo,parent,SIGUSR2,&info));
    DENIED(syscall(SYS_rt_tgsigqueueinfo,parent,parent,SIGUSR2,&info));
    DENIED(prctl(PR_SET_PDEATHSIG,0,0,0,0));
    DENIED(syscall(SYS_unshare,CLONE_FILES));DENIED(syscall(SYS_setns,-1,0));
#ifdef SYS_pidfd_send_signal
    DENIED(syscall(SYS_pidfd_send_signal,-1,0,NULL,0));
#endif
#ifdef SYS_close_range
    DENIED(syscall(SYS_close_range,10000,10001,2));
#endif
#ifdef SYS_clone3
    errno=0;check(syscall(SYS_clone3,NULL,0)==-1&&errno==ENOSYS);
#endif
    /* Separate scratch stack and an exit-only callback contain a regression:
     * even an unexpectedly accepted clone must not continue this fixture. */
    DENIED(fork_attempt(0));DENIED(fork_attempt(1));
    unsigned required=CLONE_VM|CLONE_FS|CLONE_FILES|CLONE_SIGHAND|CLONE_THREAD;
    const unsigned forbidden[]={0,SIGCHLD,CLONE_VM,required|SIGCHLD,required|CLONE_NEWNS,
        required|CLONE_VFORK,required|CLONE_PARENT,required&~CLONE_FILES,
        required&~CLONE_FS,required&~CLONE_THREAD,required|0x80000000u};
    void *stack=mmap(NULL,65536,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0);
    check(stack!=MAP_FAILED);
    if(stack!=MAP_FAILED){
        for(unsigned i=0;i<sizeof(forbidden)/sizeof(forbidden[0]);++i)
            DENIED(clone_attempt(forbidden[i],(char *)stack+65536));
        check(!munmap(stack,65536));
    }
#ifdef __x86_64__
    DENIED(syscall(SYS_clone,(1ul<<32)|required,NULL,NULL,NULL,0));
    DENIED(syscall(0x40000000u|SYS_getpid));
#endif
    pthread_t thread;int created=pthread_create(&thread,NULL,thread_main,&parent);
    check(!created);
    if(!created){
        check(pause_until(&thread_tid,1)&&atomic_load(&thread_ok));
        int before=atomic_load(&signals);
        check(!syscall(SYS_tgkill,getpid(),atomic_load(&thread_tid),SIGUSR1)&&pause_until(&signals,before+1));
        check(!pthread_kill(thread,0));
        check(!pthread_cancel(thread));void *status=NULL;
        check(!pthread_join(thread,&status)&&status==PTHREAD_CANCELED);
    }
    struct result result={checks,failures,getpid(),parent,peer};
    if(write(report,&result,sizeof(result))!=(ssize_t)sizeof(result))return 3;
    close(report);return failures?2:0;
}
static int read_full(int fd,void *buffer,size_t count){
    size_t used=0;while(used<count){struct pollfd poller={fd,POLLIN,0};
        int ready=poll(&poller,1,15000);if(ready<0&&errno==EINTR)continue;
        if(ready!=1)return -1;
        ssize_t size=read(fd,(char *)buffer+used,count-used);
        if(size<0&&errno==EINTR)continue;
        if(size<=0)return -1;
        used+=(size_t)size;
    }
    return 0;
}
static int parent_death_trial(void){
    int control[2],report[2];pid_t parent=getpid();
    check(!prctl(PR_SET_CHILD_SUBREAPER,1,0,0,0)&&!pipe2(control,O_CLOEXEC)&&!pipe2(report,O_CLOEXEC));
    if(failures)return -1;
    pid_t manager=fork();check(manager>=0);if(manager<0)return -1;
    if(manager==0){
        close(control[1]);close(report[0]);
        if(prctl(PR_SET_PDEATHSIG,SIGKILL,0,0,0)||getppid()!=parent)_exit(6);
        int gate[2];if(pipe2(gate,O_CLOEXEC))_exit(6);
        pid_t worker=fork();if(worker<0)_exit(6);
        if(worker==0){
            close(control[0]);close(gate[1]);char start=0;
            if(read_full(gate[0],&start,1)||start!='G')_exit(6);
            close(gate[0]);
            pid_t manager_pid=getppid();
            if(platform_worker_guard(manager_pid))_exit(6);
            atomic_store(&thread_tid,0);atomic_store(&thread_ok,0);
            pthread_t thread;if(pthread_create(&thread,NULL,thread_main,&manager_pid)||!pause_until(&thread_tid,1))_exit(6);
            int ready=atomic_load(&thread_ok);if(write(report[1],&ready,sizeof(ready))!=(ssize_t)sizeof(ready))_exit(6);
            close(report[1]);
            /* Leave the worker's pthread alive after the leader exits. The
             * parent-death signal must still close that entire thread group. */
            syscall(SYS_exit,0);__builtin_unreachable();
        }
        close(gate[0]);
        if(write(report[1],&worker,sizeof(worker))!=(ssize_t)sizeof(worker)||write(gate[1],"G",1)!=1)_exit(6);
        close(gate[1]);
        close(report[1]);char token=0;if(read_full(control[0],&token,1)||token!='X')_exit(6);
        _exit(0);
    }
    close(control[0]);close(report[1]);pid_t worker=0;int ready=0;
    /* The private gate orders the manager PID record before readiness. */
    int valid=!read_full(report[0],&worker,sizeof(worker))&&worker>1&&
        !read_full(report[0],&ready,sizeof(ready))&&ready==1;
    close(report[0]);check(valid);
    if(!valid){
        kill(manager,SIGKILL);waitpid(manager,NULL,0);close(control[1]);
        if(worker>1){int status=0;pid_t owned=waitpid(worker,&status,WNOHANG);
            if(owned==0){kill(worker,SIGKILL);while(waitpid(worker,&status,0)<0&&errno==EINTR){}}}
        return -1;
    }
    /* The /proc leader must be a zombie while a thread is still alive. */
    char path[80],line[1024];snprintf(path,sizeof(path),"/proc/%ld/stat",(long)worker);
    int leader_exited=0;
    for(unsigned i=0;i<2000;++i){FILE *file=fopen(path,"r");
        if(file){if(fgets(line,sizeof(line),file)){char *end=strrchr(line,')');if(end&&end[1]==' '&&end[2]=='Z')leader_exited=1;}fclose(file);}
        if(leader_exited)break;
        struct timespec delay={0,1000000};nanosleep(&delay,NULL);
    }
    check(leader_exited);
    check(write(control[1],"X",1)==1);close(control[1]);
    int status=0;check(waitpid(manager,&status,0)==manager&&WIFEXITED(status)&&!WEXITSTATUS(status));
    int reaped=0;
    for(unsigned i=0;i<2000;++i){pid_t done=waitpid(worker,&status,WNOHANG);
        if(done==worker){reaped=1;break;}
        if(done<0&&errno!=EINTR)break;
        struct timespec delay={0,1000000};nanosleep(&delay,NULL);
    }
    check(reaped&&WIFSIGNALED(status)&&WTERMSIG(status)==SIGKILL);
    if(!reaped){kill(worker,SIGKILL);while(waitpid(worker,&status,0)<0&&errno==EINTR){}}
    return reaped?0:-1;
}
static int selftest(const char *executable){
    /* Only these two newly forked own-ELF workers are signalled or reaped. */
    int control[2][2],report[2][2];pid_t worker[2]={0};pid_t parent=getpid();
    pid_t owner=getppid();
    if(owner<=1||prctl(PR_SET_PDEATHSIG,SIGKILL,0,0,0)||getppid()!=owner)return 2;
    alarm(40);
    check(!pipe2(control[0],O_CLOEXEC)&&!pipe2(control[1],O_CLOEXEC)&&
        !pipe2(report[0],O_CLOEXEC)&&!pipe2(report[1],O_CLOEXEC));
    if(failures)return 2;
    for(int index=0;index<2;++index){
        worker[index]=fork();check(worker[index]>=0);
        if(worker[index]==0){
            if(prctl(PR_SET_PDEATHSIG,SIGKILL,0,0,0)||getppid()!=parent)_exit(4);
            for(int j=0;j<2;++j){close(control[j][1]);close(report[j][0]);
                if(j!=index){close(control[j][0]);close(report[j][1]);}}
            struct rlimit cpu={3,4},data={64u*1024*1024,64u*1024*1024},core={0,0};
            if(setrlimit(RLIMIT_CPU,&cpu)||setrlimit(RLIMIT_DATA,&data)||setrlimit(RLIMIT_CORE,&core))_exit(4);
            alarm(15);pid_t peer=0;if(read_full(control[index][0],&peer,sizeof(peer)))_exit(4);
            close(control[index][0]);
            if(platform_worker_guard(parent)||fcntl(report[index][1],F_SETFD,0))_exit(4);
            char p[32],q[32],r[32];snprintf(p,sizeof(p),"%ld",(long)parent);
            snprintf(q,sizeof(q),"%ld",(long)peer);snprintf(r,sizeof(r),"%d",report[index][1]);
            execl(executable,executable,"--actor",p,q,r,(char *)NULL);_exit(4);
        }
        if(worker[index]<0){for(int j=0;j<index;++j){kill(worker[j],SIGKILL);waitpid(worker[j],NULL,0);}return 2;}
    }
    unsigned total=0;
    for(int index=0;index<2;++index){
        close(control[index][0]);close(report[index][1]);
        check(write(control[index][1],&worker[1-index],sizeof(pid_t))==(ssize_t)sizeof(pid_t));close(control[index][1]);
    }
    for(int index=0;index<2;++index){
        struct result result={0};int valid=!read_full(report[index][0],&result,sizeof(result));close(report[index][0]);
        check(valid&&result.process==worker[index]&&result.parent==parent&&result.peer==worker[1-index]&&
            result.checks>=40&&result.checks<=80&&!result.failures);
        if(valid)total+=result.checks;
        if(!valid)kill(worker[index],SIGKILL);
        int status=0;check(waitpid(worker[index],&status,0)==worker[index]&&WIFEXITED(status)&&!WEXITSTATUS(status));
    }
    /* The unfiltered trusted parent remains able to create and reap children. */
    pid_t control_child=fork();check(control_child>=0);if(control_child==0)_exit(0);
    if(control_child>0){int status=0;check(waitpid(control_child,&status,0)==control_child&&WIFEXITED(status)&&!WEXITSTATUS(status));}
    if(!failures)parent_death_trial();
    printf("{\"selftest\":\"platform-worker\",\"checks\":%u,\"worker_checks\":%u,\"exec_workers\":2,\"parent_death_workers\":1,\"failures\":%u,\"ok\":%s,\"own_elf_only\":true,\"audio_opened\":false,\"isolation_verified\":false}\n",
        checks,total,failures,failures?"false":"true");
    return failures?2:0;
}
int main(int argc,char **argv){
    if(argc==5&&!strcmp(argv[1],"--actor")){
        char *end;long parent=strtol(argv[2],&end,10);if(*end||parent<=1||parent>INT_MAX)return 2;
        long peer=strtol(argv[3],&end,10);if(*end||peer<=1||peer>INT_MAX)return 2;
        long report=strtol(argv[4],&end,10);if(*end||report<3||report>1024)return 2;
        int death=0;struct stat info;
        if(prctl(PR_GET_NO_NEW_PRIVS,0,0,0,0)!=1||prctl(PR_GET_SECCOMP,0,0,0,0)!=2||
            prctl(PR_GET_PDEATHSIG,&death,0,0,0)||death!=SIGKILL||fstat((int)report,&info)||!S_ISFIFO(info.st_mode))return 2;
        return actor((pid_t)parent,(pid_t)peer,(int)report);
    }
    if(argc!=2||strcmp(argv[1],"--selftest"))return 2;
    char executable[PATH_MAX];if(!realpath(argv[0],executable))return 2;
    return selftest(executable);
}
