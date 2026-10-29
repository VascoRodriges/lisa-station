/* Own synthetic queue only. Child cannot consume it after filter/exec; the
 * unfiltered parent must still read its own byte and remove its own queue. */
#define _GNU_SOURCE
#include <sys/msg.h>
#include "startup_guardian.h"
#include "vendor_ipc_guard.h"

static unsigned checks,failures;
static void check(int ok) { ++checks; if(!ok) { ++failures; fprintf(stderr,"failed:%u\n",checks); } }
static int actor(int queue) {
    check(prctl(PR_GET_NO_NEW_PRIVS,0,0,0,0)==1&&prctl(PR_GET_SECCOMP,0,0,0,0)==2);
    errno=0; check(msgctl(-1,IPC_STAT,NULL)==-1&&errno==EPERM);
    /* Reinstall before using even the own queue argument. Invoking this actor
     * entry point directly cannot read an arbitrary queue's contents. */
    if(vendor_ipc_guard()) return 3;
    struct { long type; char byte; } message={0};
    errno=0; check(msgrcv(queue,&message,1,0,IPC_NOWAIT)==-1&&errno==EPERM);
#define DENIED(n) do { errno=0; long value=syscall(n,-1L,0L,0L,0L,0L,0L); check(value==-1&&errno==EPERM); } while(0)
#ifdef SYS_ipc
    DENIED(SYS_ipc);
#endif
#ifdef SYS_msgget
    DENIED(SYS_msgget);
#endif
#ifdef SYS_msgctl
    DENIED(SYS_msgctl);
#endif
#ifdef SYS_msgsnd
    DENIED(SYS_msgsnd);
#endif
#ifdef SYS_msgrcv
    DENIED(SYS_msgrcv);
#endif
#ifdef SYS_shmget
    DENIED(SYS_shmget);
#endif
#ifdef SYS_shmat
    DENIED(SYS_shmat);
#endif
#ifdef SYS_shmdt
    DENIED(SYS_shmdt);
#endif
#ifdef SYS_shmctl
    DENIED(SYS_shmctl);
#endif
#ifdef SYS_semget
    DENIED(SYS_semget);
#endif
#ifdef SYS_semctl
    DENIED(SYS_semctl);
#endif
#ifdef SYS_semop
    DENIED(SYS_semop);
#endif
#ifdef SYS_semtimedop
    DENIED(SYS_semtimedop);
#endif
#ifdef SYS_semtimedop_time64
    DENIED(SYS_semtimedop_time64);
#endif
#ifdef SYS_mq_open
    DENIED(SYS_mq_open);
#endif
#ifdef SYS_mq_unlink
    DENIED(SYS_mq_unlink);
#endif
#ifdef SYS_mq_timedsend
    DENIED(SYS_mq_timedsend);
#endif
#ifdef SYS_mq_timedreceive
    DENIED(SYS_mq_timedreceive);
#endif
#ifdef SYS_mq_timedsend_time64
    DENIED(SYS_mq_timedsend_time64);
#endif
#ifdef SYS_mq_timedreceive_time64
    DENIED(SYS_mq_timedreceive_time64);
#endif
#ifdef SYS_mq_notify
    DENIED(SYS_mq_notify);
#endif
#ifdef SYS_mq_getsetattr
    DENIED(SYS_mq_getsetattr);
#endif
#if defined(__x86_64__)
    DENIED(0x40000000u|SYS_msgget);
#endif
#undef DENIED
    int pair[2]={-1,-1}; char byte=0;
    check(!socketpair(AF_UNIX,SOCK_STREAM|SOCK_CLOEXEC,0,pair)&&send(pair[0],"x",1,MSG_NOSIGNAL)==1&&recv(pair[1],&byte,1,0)==1&&byte=='x');
    if(pair[0]>=0) close(pair[0]);
    if(pair[1]>=0) close(pair[1]);
    int v4=socket(AF_INET,SOCK_STREAM|SOCK_CLOEXEC,0),v6=socket(AF_INET6,SOCK_STREAM|SOCK_CLOEXEC,0);
    check(v4>=0&&v6>=0);
    if(v4>=0) close(v4);
    if(v6>=0) close(v6);
    printf("IPC_RESULT %u %u\n",checks,failures); return failures?4:0;
}
int main(int argc,char **argv) {
    if(argc==3&&!strcmp(argv[1],"--actor")) {
        alarm(5); char *end; errno=0; long queue=strtol(argv[2],&end,10);
        if(errno||*end||queue<0||queue>INT_MAX) return 2;
        return actor((int)queue);
    }
    if(argc!=2||strcmp(argv[1],"--selftest")) return 2;
    umask(077); signal(SIGPIPE,SIG_IGN);
    int queue=msgget(IPC_PRIVATE,0600|IPC_CREAT);
    if(queue<0) return 3;
    struct { long type; char byte; } message={1,'x'};
    int result=3,output[2]={-1,-1};
    if(msgsnd(queue,&message,1,IPC_NOWAIT)||pipe2(output,O_CLOEXEC)) goto cleanup;
    char executable[PATH_MAX]; ssize_t length=readlink("/proc/self/exe",executable,sizeof(executable)-1);
    if(length<=0||length>=(ssize_t)sizeof(executable)-1) goto cleanup;
    executable[length]=0;
    pid_t child=fork();
    if(!child) {
        close(output[0]);
        if(dup2(output[1],STDOUT_FILENO)<0||guardian_close_except(NULL,0)||vendor_ipc_guard()) _exit(80);
        char number[32]; snprintf(number,sizeof(number),"%d",queue);
        char *const args[]={"ipc-guard-actor","--actor",number,NULL};
        execv(executable,args); _exit(81);
    }
    close(output[1]); output[1]=-1;
    if(child<0) goto cleanup;
    FILE *reply=fdopen(output[0],"r"); unsigned child_checks=0,child_failures=1;
    if(reply) { check(fscanf(reply,"IPC_RESULT %u %u",&child_checks,&child_failures)==2); fclose(reply); output[0]=-1; }
    else check(0);
    int status; check(waitpid(child,&status,0)==child&&WIFEXITED(status)&&WEXITSTATUS(status)==0);
    checks+=child_checks; failures+=child_failures;
    message.byte=0;
    check(msgrcv(queue,&message,1,0,IPC_NOWAIT)==1&&message.type==1&&message.byte=='x');
    check(!msgctl(queue,IPC_RMID,NULL)); queue=-1;
    printf("{\"selftest\":\"ipc-guard\",\"checks\":%u,\"ok\":%s,\"exec_inheritance\":true,"
        "\"own_queue_only\":true,\"audio_opened\":false,\"vendor_processes_changed\":false}\n",checks,failures?"false":"true");
    result=failures?4:0;
cleanup:
    if(queue>=0) msgctl(queue,IPC_RMID,NULL);
    for(unsigned i=0;i<2;++i) if(output[i]>=0) close(output[i]);
    return result;
}
