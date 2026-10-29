/* Own bounded fixture processes and files only; never starts speaker services. */
#define _GNU_SOURCE
#include "boot_runner.h"

static unsigned checks;
#define CHECK(condition) do { ++checks; if(!(condition)) { fprintf(stderr,"boot-runner-check:%u\n",checks); return 4; } } while(0)
int main(int argc,char **argv) {
    if(argc==2&&!strcmp(argv[1],"--fixture-ok")) {
        int signal=0;
        struct rlimit core;
        if(prctl(PR_GET_PDEATHSIG,&signal)||signal!=SIGKILL||getpgrp()!=getpid()||getenv("LISA_BOOT_SENTINEL")) return 90;
        if(getrlimit(RLIMIT_CORE,&core)||core.rlim_cur||core.rlim_max) return 92;
        for(int fd=3;fd<1024;++fd) if(fcntl(fd,F_GETFD)!=-1||errno!=EBADF) return 91;
        return 0;
    }
    if(argc==2&&!strcmp(argv[1],"--fixture-fail")) return 9;
    if(argc==2&&!strcmp(argv[1],"--fixture-hang")) { for(;;) pause(); }
    if(argc!=1) return 2;
    alarm(15);
    char path[PATH_MAX]; ssize_t size=readlink("/proc/self/exe",path,sizeof(path)-1);
    CHECK(size>0&&size<(ssize_t)sizeof(path)-1); path[size]=0;
    char *const ok[]={"boot-fixture","--fixture-ok",NULL};
    char *const fail[]={"boot-fixture","--fixture-fail",NULL};
    char *const hang[]={"boot-fixture","--fixture-hang",NULL};
    CHECK(boot_run(path,ok,0)==BOOT_RUN_INVALID);
    CHECK(boot_run(path,ok,60001)==BOOT_RUN_INVALID);
    CHECK(boot_run("relative",ok,100)==BOOT_RUN_INVALID);
    CHECK(boot_run(path,NULL,100)==BOOT_RUN_INVALID);
    CHECK(boot_run("/missing-lisa-boot-helper",ok,100)==BOOT_RUN_INVALID);
    CHECK(signal(SIGCHLD,SIG_IGN)!=SIG_ERR);
    CHECK(boot_run(path,ok,100)==BOOT_RUN_INVALID);
    CHECK(signal(SIGCHLD,SIG_DFL)!=SIG_ERR);
    CHECK(!setenv("LISA_BOOT_SENTINEL","must-not-inherit",1));
    int source=open("/dev/null",O_RDONLY|O_CLOEXEC); CHECK(source>=0);
    int inherited=fcntl(source,F_DUPFD,300); close(source); CHECK(inherited>=300);
    CHECK(boot_run(path,ok,1000)==BOOT_RUN_OK);
    close(inherited);
    CHECK(boot_run(path,fail,1000)==BOOT_RUN_FAILED);
    uint64_t began=guardian_milliseconds();
    CHECK(boot_run(path,hang,150)==BOOT_RUN_TIMEOUT);
    CHECK(guardian_milliseconds()-began>=150&&guardian_milliseconds()-began<1500);
    CHECK(boot_run(path,ok,1000)==BOOT_RUN_OK);
    CHECK(waitpid(-1,NULL,WNOHANG)<0&&errno==ECHILD);
    printf("{\"selftest\":\"boot-runner\",\"checks\":%u,\"ok\":true,\"services_changed\":false,\"audio_opened\":false}\n",checks);
    return 0;
}
