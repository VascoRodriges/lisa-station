/* Own mock channels only: no host bus, real SDK, account or audio access. */
#define _GNU_SOURCE
#include <dirent.h>
#include <fcntl.h>
#include <grp.h>
#include <limits.h>
#include <poll.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/statvfs.h>
#include <sys/uio.h>
#include <sys/wait.h>
#include <time.h>
#include "platform_worker_guard.h"
#include "unix_byte_channel.h"
#include "loopback_socket.h"
#ifdef __arm__
#include "startup_guardian.h"
#include "vendor_identity.h"
#include "collector_guard.h"
#endif
static unsigned checks,failures;
static void check(int good){++checks;if(!good){++failures;fprintf(stderr,"channel check %u\n",checks);}}
#define DENIED(expression) do{errno=0;long value=(expression);check(value==-1&&errno==EPERM);}while(0)
static int read_full(int fd,void *target,size_t capacity){
    size_t used=0;while(used<capacity){struct pollfd ready={fd,POLLIN,0};int result=poll(&ready,1,3000);
        if(result<0&&errno==EINTR)continue;
        if(result!=1)return -1;
        ssize_t size=read(fd,(char *)target+used,capacity-used);
        if(size<0&&errno==EINTR)continue;
        if(size<=0)return -1;
        used+=(size_t)size;
    }return 0;
}
static int close_except(const int *keep,unsigned count){
    DIR *directory=opendir("/proc/self/fd");if(!directory)return -1;int own=dirfd(directory),bad=0;struct dirent *entry;
    while((entry=readdir(directory))){char *end;long value=strtol(entry->d_name,&end,10);
        if(*end||value<0||value==own)continue;
        int retained=0;for(unsigned i=0;i<count;++i)retained|=value==keep[i];
        if(!retained&&close((int)value)&&errno!=EBADF)bad=1;
    }
    if(closedir(directory))bad=1;
    return bad?-1:0;
}
static int fd_count(void){
    DIR *directory=opendir("/proc/self/fd");if(!directory)return -1;int own=dirfd(directory),count=0;struct dirent *entry;
    while((entry=readdir(directory))){char *end;long value=strtol(entry->d_name,&end,10);if(!*end&&value>=0&&value!=own)++count;}
    closedir(directory);return count;
}
struct report{unsigned checks,failures,epoch;pid_t process;};
static int actor(int channel,int output,int control,pid_t parent,const char *name,unsigned epoch){
    alarm(12);check(unix_byte_channel_valid(channel,parent));
    check(prctl(PR_GET_NO_NEW_PRIVS,0,0,0,0)==1&&prctl(PR_GET_SECCOMP,0,0,0,0)==2);
    check(fd_count()==6);
    struct sockaddr_un target={.sun_family=AF_UNIX};
    size_t size=strlen(name);if(size>sizeof(target.sun_path)-2)return 9;
    memcpy(target.sun_path+1,name,size);socklen_t length=(socklen_t)(offsetof(struct sockaddr_un,sun_path)+1+size);
    struct sockaddr unspec={.sa_family=AF_UNSPEC};
    DENIED(connect(channel,(struct sockaddr *)&target,length));
    DENIED(connect(channel,&unspec,sizeof(unspec)));
    DENIED(bind(channel,(struct sockaddr *)&target,length));DENIED(listen(channel,1));
    DENIED(accept(channel,NULL,NULL));DENIED(accept4(channel,NULL,NULL,SOCK_CLOEXEC));
    DENIED(socket(AF_UNIX,SOCK_STREAM,0));DENIED(socket(AF_INET,SOCK_STREAM,0));DENIED(socket(AF_INET6,SOCK_DGRAM,0));
    int pair[2];DENIED(socketpair(AF_UNIX,SOCK_STREAM,0,pair));DENIED(socketpair(AF_UNIX,SOCK_DGRAM,0,pair));
    DENIED(sendto(channel,"X",1,MSG_NOSIGNAL,(struct sockaddr *)&target,length));
    DENIED(sendto(channel,"X",1,MSG_FASTOPEN|MSG_NOSIGNAL,(struct sockaddr *)&target,length));
    char byte=0;union{struct cmsghdr alignment;char bytes[CMSG_SPACE(sizeof(int))];} ancillary={0};
    struct iovec item={&byte,1};struct msghdr message={0};
    message.msg_iov=&item;message.msg_iovlen=1;message.msg_control=ancillary.bytes;message.msg_controllen=sizeof(ancillary.bytes);
    DENIED(recvmsg(channel,&message,MSG_DONTWAIT));
    struct cmsghdr *rights=CMSG_FIRSTHDR(&message);rights->cmsg_level=SOL_SOCKET;rights->cmsg_type=SCM_RIGHTS;rights->cmsg_len=CMSG_LEN(sizeof(int));
    memcpy(CMSG_DATA(rights),&channel,sizeof(channel));byte='X';DENIED(sendmsg(channel,&message,MSG_NOSIGNAL));
    struct mmsghdr multi={0};multi.msg_hdr=message;
    DENIED(sendmmsg(channel,&multi,1,MSG_NOSIGNAL));DENIED(recvmmsg(channel,&multi,1,MSG_DONTWAIT,NULL));
    DENIED(recvfrom(channel,&byte,1,MSG_DONTWAIT,NULL,NULL));
#ifdef SYS_send
    DENIED(syscall(SYS_send,channel,&byte,1,MSG_NOSIGNAL));
#endif
#ifdef SYS_recv
    DENIED(syscall(SYS_recv,channel,&byte,1,MSG_DONTWAIT));
#endif
#ifdef SYS_socketcall
    DENIED(syscall(SYS_socketcall,1,NULL));
#elif defined(__arm__)
    DENIED(syscall(102,1,NULL));
#endif
#ifdef __arm__
    DENIED(syscall(113,0,NULL));DENIED(syscall(117,0,NULL));
#endif
#ifdef SYS_recvmmsg_time64
    DENIED(syscall(SYS_recvmmsg_time64,channel,&multi,1,MSG_DONTWAIT,NULL));
#endif
#ifdef SYS_pidfd_getfd
    DENIED(syscall(SYS_pidfd_getfd,-1,0,0));
#endif
#ifdef SYS_io_uring_setup
    DENIED(syscall(SYS_io_uring_setup,1,NULL));
#endif
    struct iovec input={&byte,1};check(readv(channel,&input,1)==1&&byte=='K');check(fd_count()==6);
    char a='O',b='K';struct iovec reply[2]={{&a,1},{&b,1}};check(writev(channel,reply,2)==2);
    int alias=dup(channel);check(alias>=0);if(alias<0)return 9;
    check(!close(channel)&&fd_count()==6);check(write(alias,"D",1)==1);
    char command=0;check(!read_full(control,&command,1)&&command=='C');
    char tail[4];check(!read_full(alias,tail,sizeof(tail))&&!memcmp(tail,"TAIL",sizeof(tail)));
    errno=0;check(write(alias,"X",1)==-1&&errno==EPIPE);
    check(!close(alias)&&fd_count()==5);
    struct report result={checks,failures,epoch,getpid()};
    if(write(output,&result,sizeof(result))!=(ssize_t)sizeof(result))return 9;
    return failures?9:0;
}
static int send_right(int channel,int descriptor){
    char value='K';struct iovec item={&value,1};union{struct cmsghdr alignment;char bytes[CMSG_SPACE(sizeof(int))];} space={0};
    struct msghdr message={0};message.msg_iov=&item;message.msg_iovlen=1;message.msg_control=space.bytes;message.msg_controllen=sizeof(space.bytes);
    struct cmsghdr *rights=CMSG_FIRSTHDR(&message);rights->cmsg_level=SOL_SOCKET;rights->cmsg_type=SCM_RIGHTS;rights->cmsg_len=CMSG_LEN(sizeof(int));
    memcpy(CMSG_DATA(rights),&descriptor,sizeof(descriptor));return sendmsg(channel,&message,MSG_NOSIGNAL)==1?0:-1;
}
static int loopback_control(int family){struct pair pair={-1,-1};int good=!make_pair(family,0,&pair)&&exchange(&pair);
    if(pair.client>=0)close(pair.client);
    if(pair.peer>=0)close(pair.peer);
    return good;
}
static int selftest(const char *executable){
    pid_t owner=getppid();if(owner<=1||prctl(PR_SET_PDEATHSIG,SIGKILL)||getppid()!=owner)return 2;
    alarm(35);signal(SIGPIPE,SIG_IGN);umask(077);
    int listener=socket(AF_UNIX,SOCK_STREAM|SOCK_CLOEXEC|SOCK_NONBLOCK,0);check(listener>=0);if(listener<0)return 2;
    struct timespec now;check(!clock_gettime(CLOCK_MONOTONIC,&now));char name[80];
    snprintf(name,sizeof(name),"lisa-channel-%ld-%ld",(long)getpid(),now.tv_nsec);
    struct sockaddr_un address={.sun_family=AF_UNIX};memcpy(address.sun_path+1,name,strlen(name));
    socklen_t length=(socklen_t)(offsetof(struct sockaddr_un,sun_path)+1+strlen(name));
    check(!bind(listener,(struct sockaddr *)&address,length)&&!listen(listener,2));
    /* Invalid candidates fail before the filter is installed in this parent. */
    int null=open("/dev/null",O_RDWR|O_CLOEXEC),pipefd[2];check(null>=0&&!pipe2(pipefd,O_CLOEXEC));
    check(unix_byte_channel_guard(null,owner)<0&&errno==EINVAL);
    check(!unix_byte_channel_valid(pipefd[0],owner)&&!unix_byte_channel_valid(listener,owner));
    close(null);close(pipefd[0]);close(pipefd[1]);
    const int types[]={SOCK_DGRAM,SOCK_SEQPACKET};int invalid[2][2];
    for(unsigned i=0;i<2;++i)check(!socketpair(AF_UNIX,types[i]|SOCK_CLOEXEC,0,invalid[i]));
    int held[2]={-1,-1};struct stat first={0};unsigned total=0;
    for(unsigned epoch=0;epoch<2;++epoch){
        int pair[2],reports[2],commands[2];check(!socketpair(AF_UNIX,SOCK_STREAM|SOCK_CLOEXEC,0,pair)&&!pipe2(reports,O_CLOEXEC)&&!pipe2(commands,O_CLOEXEC));
        if(failures)return 2;
        held[epoch]=dup(pair[1]);struct stat identity;check(held[epoch]>=0&&!fstat(held[epoch],&identity));
        if(epoch)check(identity.st_ino!=first.st_ino||identity.st_dev!=first.st_dev);else first=identity;
        char temporary[]="/tmp/lisa-channel-canary.XXXXXX";int canary=mkstemp(temporary);check(canary>=0&&!unlink(temporary));
        pid_t parent=getpid(),child=fork();check(child>=0);if(child<0)return 2;
        if(!child){
            if(prctl(PR_SET_PDEATHSIG,SIGKILL)||getppid()!=parent)_exit(80);
            if(!unix_byte_channel_valid(pair[1],parent)||unix_byte_channel_valid(pair[1],parent+1)||
                unix_byte_channel_valid(invalid[0][1],parent)||unix_byte_channel_valid(invalid[1][1],parent)||
                unix_byte_channel_valid(listener,parent)||unix_byte_channel_valid(reports[1],parent))_exit(81);
            int keep[]={pair[1],reports[1],commands[0]};if(close_except(keep,3))_exit(81);
            int zero=open("/dev/null",O_RDWR|O_CLOEXEC);if(zero<0)_exit(81);
            for(int fd=0;fd<3;++fd)if(dup2(zero,fd)<0||fcntl(fd,F_SETFD,0))_exit(81);
            if(zero>2)close(zero);
            struct rlimit cpu={3,4},data={32u*1024*1024,32u*1024*1024},core={0,0};
            if(setrlimit(RLIMIT_CPU,&cpu)||setrlimit(RLIMIT_DATA,&data)||setrlimit(RLIMIT_CORE,&core))_exit(82);
#ifdef __arm__
            if(vendor_identity_prepare(57342)||collector_extra_guard())_exit(83);
#endif
            if(platform_worker_guard(parent)||unix_byte_channel_guard(pair[1],parent))_exit(84);
            for(unsigned i=0;i<3;++i)if(fcntl(keep[i],F_SETFD,0))_exit(85);
            char a[24],b[24],c[24],p[24],e[24];snprintf(a,sizeof(a),"%d",keep[0]);snprintf(b,sizeof(b),"%d",keep[1]);snprintf(c,sizeof(c),"%d",keep[2]);
            snprintf(p,sizeof(p),"%ld",(long)parent);snprintf(e,sizeof(e),"%u",epoch+1);
            execl(executable,executable,"--actor",a,b,c,p,name,e,(char *)NULL);_exit(86);
        }
        close(pair[1]);close(reports[1]);close(commands[0]);
        check(!send_right(pair[0],canary));close(canary);
        char reply[3];int good=!read_full(pair[0],reply,sizeof(reply))&&!memcmp(reply,"OKD",sizeof(reply));check(good);
        check(write(pair[0],"TAILSTALE",9)==9);close(pair[0]);
        check(write(commands[1],"C",1)==1);close(commands[1]);
        struct report result={0};good=!read_full(reports[0],&result,sizeof(result));close(reports[0]);
        check(good&&result.process==child&&result.epoch==epoch+1&&!result.failures&&result.checks>=30&&result.checks<=64);
        if(good)total+=result.checks;else kill(child,SIGKILL);
        int status;check(waitpid(child,&status,0)==child&&WIFEXITED(status)&&!WEXITSTATUS(status));
        struct pollfd ready={listener,POLLIN,0};check(poll(&ready,1,0)==0);
        printf("{\"event\":\"unix-channel-epoch\",\"epoch\":%u,\"actor_checks\":%u,\"failures\":%u,\"own_mock_only\":true}\n",epoch+1,result.checks,result.failures);fflush(stdout);
    }
    for(unsigned i=0;i<2;++i){char stale[5];check(!read_full(held[i],stale,sizeof(stale))&&!memcmp(stale,"STALE",5));close(held[i]);}
    for(unsigned i=0;i<2;++i){close(invalid[i][0]);close(invalid[i][1]);}
    int client=socket(AF_UNIX,SOCK_STREAM|SOCK_CLOEXEC,0);check(client>=0&&!connect(client,(struct sockaddr *)&address,length));
    int accepted=accept4(listener,NULL,NULL,SOCK_CLOEXEC);check(accepted>=0);if(client>=0)close(client);if(accepted>=0)close(accepted);close(listener);
    check(loopback_control(AF_INET)&&loopback_control(AF_INET6));
    printf("{\"selftest\":\"unix-channel\",\"checks\":%u,\"actor_checks\":%u,\"epochs\":2,\"failures\":%u,\"ok\":%s,\"own_mock_only\":true,\"audio_opened\":false,\"isolation_verified\":false}\n",checks,total,failures,failures?"false":"true");
    return failures?2:0;
}
int main(int argc,char **argv){
    if(argc==8&&!strcmp(argv[1],"--actor")){
        long value[5];const int indices[]={2,3,4,5,7};
        for(unsigned i=0;i<5;++i){char *end;value[i]=strtol(argv[indices[i]],&end,10);if(*end||value[i]<1||value[i]>INT_MAX)return 2;}
        if(value[0]<3||value[1]<3||value[2]<3||value[0]==value[1]||value[0]==value[2]||value[1]==value[2]||value[4]>2)return 2;
        struct stat output,control;int death=0;long broker,nanosecond;int used=0;char canonical[80];
        if(fstat((int)value[1],&output)||!S_ISFIFO(output.st_mode)||fstat((int)value[2],&control)||!S_ISFIFO(control.st_mode)||
            getppid()!=(pid_t)value[3]||prctl(PR_GET_NO_NEW_PRIVS,0,0,0,0)!=1||prctl(PR_GET_SECCOMP,0,0,0,0)!=2||
            prctl(PR_GET_PDEATHSIG,&death,0,0,0)||death!=SIGKILL||
            sscanf(argv[6],"lisa-channel-%ld-%ld%n",&broker,&nanosecond,&used)!=2||used!=(int)strlen(argv[6])||broker!=value[3]||
            nanosecond<0||nanosecond>=1000000000||snprintf(canonical,sizeof(canonical),"lisa-channel-%ld-%ld",broker,nanosecond)!=used||strcmp(canonical,argv[6])||
            !unix_byte_channel_valid((int)value[0],(pid_t)value[3]))return 2;
        return actor((int)value[0],(int)value[1],(int)value[2],(pid_t)value[3],argv[6],(unsigned)value[4]);
    }
    if(argc!=2||strcmp(argv[1],"--selftest"))return 2;
    char executable[PATH_MAX];if(!realpath(argv[0],executable))return 2;return selftest(executable);
}
