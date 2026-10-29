/* Own-child filter boundaries, never a valid time-setting value. */
#define _GNU_SOURCE
#include "time_profile.h"
static unsigned checks;
#define CHECK(x) do{++checks;if(!(x)){fprintf(stderr,"check %u line %d: %s\n",checks,__LINE__,#x);return 1;}}while(0)
static int filter_child(int control) {
    struct __user_cap_header_struct header={_LINUX_CAPABILITY_VERSION_3,0};
    struct __user_cap_data_struct caps[2]={{0},{0}};
    /* Even an unexpected pointer mapping must not permit a clock update. */
    if(syscall(SYS_capset,&header,caps)||prctl(PR_SET_NO_NEW_PRIVS,1,0,0,0)||
        network_service_filter(control)||(control&&time_realtime_filter()))return 1;
    const int expected=control?EFAULT:EPERM;
    errno=0;if(syscall(SYS_clock_settime,CLOCK_REALTIME,NULL)!=-1||errno!=expected)return 2;
    errno=0;if(syscall(SYS_clock_adjtime,CLOCK_REALTIME,NULL)!=-1||errno!=expected)return 3;
    errno=0;if(syscall(SYS_clock_settime,CLOCK_MONOTONIC,NULL)!=-1||errno!=EPERM)return 4;
    errno=0;if(syscall(SYS_clock_adjtime,CLOCK_MONOTONIC,NULL)!=-1||errno!=EPERM)return 5;
    errno=0;if(syscall(SYS_settimeofday,(void*)1,NULL)!=-1||errno!=expected)return 6;
    errno=0;if(syscall(SYS_adjtimex,(void*)1)!=-1||errno!=expected)return 7;
    errno=0;if(setgid(getgid())!=-1||errno!=EPERM)return 8;
    errno=0;if(kill(getppid(),0)!=-1||errno!=EPERM)return 9;
    int fd=socket(AF_INET,SOCK_DGRAM|SOCK_CLOEXEC,0);if(fd<0)return 10;close(fd);
    errno=0;if(socket(AF_UNIX,SOCK_STREAM,0)!=-1||errno!=EPERM)return 11;
    return 0;
}
int main(int argc,char **argv) {
    if(argc==2&&!strcmp(argv[1],"--validate-production")){
        char text[8192];size_t size=fread(text,1,sizeof(text)-1,stdin);
        if(ferror(stdin)||!feof(stdin)||memchr(text,0,size))return 2;
        text[size]=0;return time_profile_validate(text,"/run/lisa-station-net/time","/data/opt/lisa-station/time")?3:0;
    }
    if(argc!=1)return 2;
    for(int control=0;control<=1;++control){
        pid_t child=fork();CHECK(child>=0);if(!child)_exit(filter_child(control));int status;
        CHECK(waitpid(child,&status,0)==child);
        if(WIFEXITED(status)&&WEXITSTATUS(status))fprintf(stderr,"mode %d failure %d\n",control,WEXITSTATUS(status));
        CHECK(WIFEXITED(status)&&!WEXITSTATUS(status));
    }
    printf("{\"selftest\":\"time-guard\",\"checks\":%u,\"modes\":2,\"ok\":true,\"invalid_pointer_calls_only\":true,\"clock_changed\":false}\n",checks);
    return 0;
}
