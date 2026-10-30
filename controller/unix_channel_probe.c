/* Own mock channels only: no host bus, real SDK, account or audio access. */
#define _GNU_SOURCE
#include <dirent.h>
#include <fcntl.h>
#include <grp.h>
#include <limits.h>
#include <poll.h>
#include <pthread.h>
#include <stdatomic.h>
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
#include "unix_byte_adapter.h"
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
    struct unix_byte_adapter adapter,wrong;
    check(!unix_byte_adapter_init(&adapter,channel,parent));
    errno=0;check(unix_byte_adapter_init(&wrong,output,parent)<0&&errno==EPERM);
    errno=0;check(unix_byte_adapter_send(&adapter,NULL,0)<0&&errno==EFAULT);
    errno=0;check(unix_byte_adapter_receive(&adapter,NULL,0)<0&&errno==EFAULT);
    struct iovec input={&byte,1};struct msghdr bytes={.msg_iov=&input,.msg_iovlen=1};
    struct msghdr invalid=bytes;invalid.msg_control=ancillary.bytes;invalid.msg_controllen=sizeof(ancillary.bytes);
    errno=0;check(unix_byte_adapter_send(&adapter,&invalid,0)<0&&errno==EOPNOTSUPP);
    invalid=bytes;invalid.msg_name=&target;invalid.msg_namelen=length;
    errno=0;check(unix_byte_adapter_send(&adapter,&invalid,0)<0&&errno==EOPNOTSUPP);
    invalid=bytes;invalid.msg_iovlen=BYTE_ADAPTER_VECTORS+1;
    errno=0;check(unix_byte_adapter_send(&adapter,&invalid,0)<0&&errno==EMSGSIZE);
    invalid=bytes;invalid.msg_iov=NULL;
    errno=0;check(unix_byte_adapter_send(&adapter,&invalid,0)<0&&errno==EFAULT);
    struct iovec no_buffer={NULL,1};invalid=bytes;invalid.msg_iov=&no_buffer;
    errno=0;check(unix_byte_adapter_receive(&adapter,&invalid,0)<0&&errno==EFAULT);
    struct unix_byte_adapter mismatched=adapter;mismatched.inode^=1;
    errno=0;check(unix_byte_adapter_send(&mismatched,&bytes,0)<0&&errno==EPERM);
    struct iovec large={&byte,BYTE_ADAPTER_BYTES+1};invalid=bytes;invalid.msg_iov=&large;
    errno=0;check(unix_byte_adapter_send(&adapter,&invalid,0)<0&&errno==EMSGSIZE);
    errno=0;check(unix_byte_adapter_send(&adapter,&bytes,MSG_FASTOPEN)<0&&errno==EOPNOTSUPP);
    errno=0;check(unix_byte_adapter_receive(&adapter,&bytes,MSG_PEEK)<0&&errno==EOPNOTSUPP);
    errno=0;check(unix_byte_adapter_receive(&adapter,&bytes,MSG_DONTWAIT)<0&&errno==EOPNOTSUPP);
    struct sigaction action={0};action.sa_handler=SIG_DFL;sigemptyset(&action.sa_mask);
    check(!sigaction(SIGPIPE,&action,NULL));
    errno=0;check(unix_byte_adapter_send(&adapter,&bytes,MSG_NOSIGNAL)<0&&errno==EOPNOTSUPP);
    action.sa_handler=SIG_IGN;check(!sigaction(SIGPIPE,&action,NULL));
    bytes.msg_control=ancillary.bytes;bytes.msg_controllen=sizeof(ancillary.bytes);bytes.msg_flags=123;
    check(unix_byte_adapter_receive(&adapter,&bytes,MSG_CMSG_CLOEXEC)==1&&byte=='K'&&
        !bytes.msg_controllen&&!bytes.msg_namelen&&!bytes.msg_flags);check(fd_count()==6);
    struct msghdr empty={0};check(unix_byte_adapter_send(&adapter,&empty,0)==0);
    check(unix_byte_adapter_receive(&adapter,&empty,0)==0);
    int original_mode=fcntl(channel,F_GETFL);check(original_mode>=0&&!fcntl(channel,F_SETFL,original_mode|O_NONBLOCK));
    errno=0;check(unix_byte_adapter_receive(&adapter,&bytes,MSG_DONTWAIT|MSG_CMSG_CLOEXEC)<0&&(errno==EAGAIN||errno==EWOULDBLOCK));
    check(!fcntl(channel,F_SETFL,original_mode));
    char a='O',b='K';struct iovec reply[2]={{&a,1},{&b,1}};struct msghdr response={.msg_iov=reply,.msg_iovlen=2};
    check(unix_byte_adapter_send(&adapter,&response,MSG_NOSIGNAL)==2);
    int alias=dup(channel);check(alias>=0);if(alias<0)return 9;
    struct unix_byte_adapter duplicate;check(!unix_byte_adapter_init(&duplicate,alias,parent));
    check(!close(channel)&&fd_count()==6);
    errno=0;check(unix_byte_adapter_send(&adapter,&response,0)<0&&errno==EBADF);
    char token='D';struct iovec data={&token,1};response.msg_iov=&data;response.msg_iovlen=1;
    check(unix_byte_adapter_send(&duplicate,&response,MSG_NOSIGNAL)==1);
    char command=0;check(!read_full(control,&command,1)&&command=='C');
    char tail[4];check(!read_full(alias,tail,sizeof(tail))&&!memcmp(tail,"TAIL",sizeof(tail)));
    if(epoch==2){struct msghdr ended={.msg_iov=&data,.msg_iovlen=1,.msg_flags=123};
        check(unix_byte_adapter_receive(&duplicate,&ended,0)==0&&!ended.msg_flags&&!ended.msg_controllen&&!ended.msg_namelen);}
    errno=0;check(unix_byte_adapter_send(&duplicate,&response,MSG_NOSIGNAL)==-1&&errno==EPIPE);
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
        const char *queued=epoch?"TAIL":"TAILSTALE";size_t queued_size=strlen(queued);
        check(write(pair[0],queued,queued_size)==(ssize_t)queued_size);close(pair[0]);
        check(write(commands[1],"C",1)==1);close(commands[1]);
        struct report result={0};good=!read_full(reports[0],&result,sizeof(result));close(reports[0]);
        check(good&&result.process==child&&result.epoch==epoch+1&&!result.failures&&result.checks>=45&&result.checks<=80);
        if(good)total+=result.checks;else kill(child,SIGKILL);
        int status;check(waitpid(child,&status,0)==child&&WIFEXITED(status)&&!WEXITSTATUS(status));
        struct pollfd ready={listener,POLLIN,0};check(poll(&ready,1,0)==0);
        printf("{\"event\":\"unix-channel-epoch\",\"epoch\":%u,\"actor_checks\":%u,\"failures\":%u,\"own_mock_only\":true}\n",epoch+1,result.checks,result.failures);fflush(stdout);
    }
    char stale[5];check(!read_full(held[0],stale,sizeof(stale))&&!memcmp(stale,"STALE",5));close(held[0]);
    check(read(held[1],stale,1)==0);close(held[1]);
    for(unsigned i=0;i<2;++i){close(invalid[i][0]);close(invalid[i][1]);}
    int client=socket(AF_UNIX,SOCK_STREAM|SOCK_CLOEXEC,0);check(client>=0&&!connect(client,(struct sockaddr *)&address,length));
    int accepted=accept4(listener,NULL,NULL,SOCK_CLOEXEC);check(accepted>=0);if(client>=0)close(client);if(accepted>=0)close(accepted);close(listener);
    check(loopback_control(AF_INET)&&loopback_control(AF_INET6));
    printf("{\"selftest\":\"unix-channel\",\"checks\":%u,\"actor_checks\":%u,\"epochs\":2,\"failures\":%u,\"ok\":%s,\"own_mock_only\":true,\"audio_opened\":false,\"isolation_verified\":false}\n",checks,total,failures,failures?"false":"true");
    return failures?2:0;
}
static int factory_actor(int output,int control,pid_t parent){
    alarm(12);check(getppid()==parent&&prctl(PR_GET_NO_NEW_PRIVS,0,0,0,0)==1&&prctl(PR_GET_SECCOMP,0,0,0,0)==2);
    check(fd_count()==7);
    /* Refuse an unguarded direct invocation before any symbolic bus address
     * can be used. The library is not the kernel security boundary. */
    errno=0;long raw=syscall(SYS_socket,AF_UNIX,SOCK_STREAM|SOCK_CLOEXEC,0);
    int gated=raw==-1&&errno==EPERM;check(gated);
    if(!gated){if(raw>=0)close((int)raw);return 9;}
    DENIED(socket(AF_INET,SOCK_STREAM,0));DENIED(socket(AF_UNIX,SOCK_DGRAM,0));DENIED(socket(AF_UNIX,SOCK_STREAM,1));
    int first=socket(AF_UNIX,SOCK_STREAM|SOCK_CLOEXEC|SOCK_NONBLOCK,0);check(first>=3);if(first<3)return 9;
    check((fcntl(first,F_GETFD)&FD_CLOEXEC)!=0);check((fcntl(first,F_GETFL)&O_NONBLOCK)!=0);
    struct sockaddr_un address={.sun_family=AF_UNIX};strcpy(address.sun_path,"/lisa-rejected-bus");
    DENIED(connect(first,(struct sockaddr *)&address,sizeof(address)));
    memset(address.sun_path,0,sizeof(address.sun_path));memcpy(address.sun_path+1,"lisa-rejected-abstract",22);
    DENIED(connect(first,(struct sockaddr *)&address,sizeof(address)));
    memset(address.sun_path,0,sizeof(address.sun_path));strcpy(address.sun_path,"/var/run/dbus/system_bus_socket");
    char byte='X';struct iovec item={&byte,1};struct msghdr message={.msg_iov=&item,.msg_iovlen=1};
    errno=0;check(sendmsg(first,&message,MSG_NOSIGNAL|MSG_DONTWAIT)<0&&errno==ENOTCONN);
    DENIED(syscall(SYS_connect,first,&address,sizeof(address)));
    check(!connect(first,(struct sockaddr *)&address,sizeof(address)));
    errno=0;check(connect(first,(struct sockaddr *)&address,sizeof(address))<0&&errno==EISCONN);
    DENIED(syscall(SYS_sendmsg,first,&message,0));
    union{struct cmsghdr alignment;char bytes[CMSG_SPACE(sizeof(int))];} ancillary={0};
    message.msg_control=ancillary.bytes;message.msg_controllen=sizeof(ancillary.bytes);
    DENIED(syscall(SYS_recvmsg,first,&message,MSG_DONTWAIT));
    check(recvmsg(first,&message,MSG_DONTWAIT|MSG_CMSG_CLOEXEC)==1&&byte=='K'&&!message.msg_controllen&&!message.msg_namelen&&!message.msg_flags);
    check(fd_count()==7);
    message.msg_control=ancillary.bytes;message.msg_controllen=sizeof(ancillary.bytes);
    errno=0;check(sendmsg(first,&message,MSG_NOSIGNAL)<0&&errno==EOPNOTSUPP);
    message.msg_control=NULL;message.msg_controllen=0;message.msg_name=&address;message.msg_namelen=sizeof(address);
    errno=0;check(sendmsg(first,&message,MSG_NOSIGNAL)<0&&errno==EOPNOTSUPP);
    message.msg_name=NULL;message.msg_namelen=0;
    errno=0;check(recvmsg(first,&message,MSG_PEEK)<0&&errno==EOPNOTSUPP);
    byte='A';check(sendmsg(first,&message,MSG_NOSIGNAL|MSG_DONTWAIT)==1);
    int second=socket(AF_UNIX,SOCK_STREAM,0);check(second>=3);if(second<3)return 9;
    check(!(fcntl(second,F_GETFD)&FD_CLOEXEC));check(!(fcntl(second,F_GETFL)&O_NONBLOCK));
    memset(address.sun_path,0,sizeof(address.sun_path));strcpy(address.sun_path,"/run/dbus/system_bus_socket");
    check(!connect(second,(struct sockaddr *)&address,sizeof(address)));
    check(recvmsg(second,&message,0)==1&&byte=='L');byte='B';check(sendmsg(second,&message,MSG_NOSIGNAL)==1);
    int alias=dup(first);check(alias>=3);if(alias<3)return 9;
    check(!close(first));byte='D';check(sendmsg(alias,&message,MSG_NOSIGNAL|MSG_DONTWAIT)==1);
    errno=0;check(socket(AF_UNIX,SOCK_STREAM,0)<0&&errno==EMFILE);
    DENIED(connect(output,(struct sockaddr *)&address,sizeof(address)));
    check(!close(alias)&&!close(second));check(fd_count()==5);
    errno=0;check(socket(AF_UNIX,SOCK_STREAM,0)<0&&errno==EMFILE);
    struct report result={checks,failures,2,getpid()};
    if(write(output,&result,sizeof(result))!=(ssize_t)sizeof(result))return 9;
    (void)control;return failures?9:0;
}
struct concurrent_client{_Atomic int *ready,*start;int good;char token;};
static void *factory_client_thread(void *argument){
    struct concurrent_client *client=argument;atomic_fetch_add(client->ready,1);
    while(!atomic_load(client->start)){struct timespec pause={0,1000000};nanosleep(&pause,NULL);}
    int fd=socket(AF_UNIX,SOCK_STREAM|SOCK_NONBLOCK|SOCK_CLOEXEC,0);if(fd<3)return NULL;
    struct sockaddr_un address={.sun_family=AF_UNIX};strcpy(address.sun_path,"/run/dbus/system_bus_socket");
    char value=0;struct iovec item={&value,1};struct msghdr message={.msg_iov=&item,.msg_iovlen=1};
    int good=(fcntl(fd,F_GETFD)&FD_CLOEXEC)&&(fcntl(fd,F_GETFL)&O_NONBLOCK)&&
        !connect(fd,(struct sockaddr *)&address,sizeof(address))&&
        recvmsg(fd,&message,MSG_DONTWAIT|MSG_CMSG_CLOEXEC)==1&&(value=='K'||value=='L')&&
        !message.msg_controllen&&sendmsg(fd,&message,MSG_DONTWAIT|MSG_NOSIGNAL)==1;
    int closed=!close(fd);client->token=value;client->good=good&&closed;return NULL;
}
static int factory_concurrent_actor(int output,int control,pid_t parent){
    alarm(12);check(getppid()==parent&&fd_count()==7);
    errno=0;long raw=syscall(SYS_socket,AF_UNIX,SOCK_STREAM|SOCK_CLOEXEC,0);int gated=raw==-1&&errno==EPERM;check(gated);
    if(!gated){if(raw>=0)close((int)raw);return 9;}
    _Atomic int ready=0,start=0;struct concurrent_client clients[2]={{&ready,&start,0,0},{&ready,&start,0,0}};pthread_t threads[2];int created[2];
    /* A runner's inherited stack limit can make glibc reserve tens of MiB
     * per pthread and exhaust the deliberately small child DATA budget.
     * Bound our own tiny fixture stacks independently of that default. */
    pthread_attr_t attributes;
    if(pthread_attr_init(&attributes))return 9;
    if(pthread_attr_setstacksize(&attributes,1024u*1024)){pthread_attr_destroy(&attributes);return 9;}
    for(unsigned i=0;i<2;++i){created[i]=!pthread_create(&threads[i],&attributes,factory_client_thread,&clients[i]);check(created[i]);}
    if(pthread_attr_destroy(&attributes))return 9;
    for(unsigned i=0;i<2000&&atomic_load(&ready)!=2;++i){struct timespec pause={0,1000000};nanosleep(&pause,NULL);}
    check(atomic_load(&ready)==2);atomic_store(&start,1);
    for(unsigned i=0;i<2;++i){if(created[i])check(!pthread_join(threads[i],NULL)&&clients[i].good);else check(0);}
    check((clients[0].token=='K'&&clients[1].token=='L')||(clients[0].token=='L'&&clients[1].token=='K'));
    errno=0;check(socket(AF_UNIX,SOCK_STREAM,0)<0&&errno==EMFILE);check(fd_count()==5);
    struct report result={checks,failures,2,getpid()};if(write(output,&result,sizeof(result))!=(ssize_t)sizeof(result))return 9;
    (void)control;return failures?9:0;
}
static int factory_selftest(const char *executable,const char *library){
    pid_t owner=getppid();if(owner<=1||prctl(PR_SET_PDEATHSIG,SIGKILL)||getppid()!=owner)return 2;
    alarm(35);signal(SIGPIPE,SIG_IGN);umask(077);
    struct stat image;check(!lstat(library,&image)&&S_ISREG(image.st_mode)&&image.st_uid==geteuid()&&image.st_nlink==1&&!(image.st_mode&0022)&&image.st_size>0);
    if(failures)return 2;
    unsigned actor_total=0;
    for(unsigned variant=0;variant<7;++variant){
        int channel[2][2],reports[2],commands[2];
        check(!socketpair(AF_UNIX,SOCK_STREAM|SOCK_CLOEXEC,0,channel[0])&&
            !socketpair(AF_UNIX,SOCK_STREAM|SOCK_CLOEXEC,0,channel[1])&&!pipe2(reports,O_CLOEXEC)&&!pipe2(commands,O_CLOEXEC));
        if(failures)return 2;
        char temporary[]="/tmp/lisa-factory-canary.XXXXXX";int canary=mkstemp(temporary);
        check(canary>=0&&!unlink(temporary)&&!send_right(channel[0][0],canary));if(canary>=0)close(canary);
        check(write(channel[1][0],"L",1)==1);
        int duplicate_source=-1;
        if(variant==4){duplicate_source=fcntl(channel[0][1],F_DUPFD_CLOEXEC,3);check(duplicate_source>=3);if(duplicate_source<3)return 2;}
        pid_t parent=getpid(),child=fork();check(child>=0);if(child<0)return 2;
        if(!child){
            if(prctl(PR_SET_PDEATHSIG,SIGKILL)||getppid()!=parent)_exit(80);
            int keep[]={channel[0][1],duplicate_source>=0?duplicate_source:channel[1][1],reports[1],commands[0]};
            if(!unix_byte_channel_valid(keep[0],parent)||!unix_byte_channel_valid(keep[1],parent)||close_except(keep,4))_exit(81);
            int zero=open("/dev/null",O_RDWR|O_CLOEXEC);if(zero<0)_exit(81);
            for(int i=0;i<3;++i)if(dup2(zero,i)<0||fcntl(i,F_SETFD,0))_exit(81);
            if(zero>2)close(zero);
            struct rlimit cpu={3,4},data={32u*1024*1024,32u*1024*1024},core={0,0};
            if(setrlimit(RLIMIT_CPU,&cpu)||setrlimit(RLIMIT_DATA,&data)||setrlimit(RLIMIT_CORE,&core)||clearenv())_exit(82);
#ifdef __arm__
            if(vendor_identity_prepare(57342)||collector_extra_guard())_exit(83);
#endif
            if(platform_worker_guard(parent)||unix_byte_channel_guard(keep[0],parent))_exit(84);
            for(unsigned i=0;i<4;++i)if(fcntl(keep[i],F_SETFD,0))_exit(85);
            char pool[64],report[24],command[24],pid[24];
            snprintf(pool,sizeof(pool),"%d,%d",keep[0],variant==2?keep[0]:variant==3?keep[2]:keep[1]);
            if(variant==5)strcpy(pool,"03");
            if(variant==6&&setenv("LISA_FACTORY_CONCURRENT","1",1))_exit(85);
            if(setenv("LD_PRELOAD",library,1)||setenv("LD_BIND_NOW","1",1)||(variant!=1&&setenv("LISA_BYTE_FDS",pool,1)))_exit(85);
            snprintf(report,sizeof(report),"%d",keep[2]);snprintf(command,sizeof(command),"%d",keep[3]);snprintf(pid,sizeof(pid),"%ld",(long)parent);
            execl(executable,executable,"--factory-actor",report,command,pid,(char *)NULL);_exit(86);
        }
        for(unsigned i=0;i<2;++i)close(channel[i][1]);
        if(duplicate_source>=0)close(duplicate_source);
        close(reports[1]);close(commands[0]);
        struct report result={0};int received=0;
        int rejected=variant>=1&&variant<=5;
        if(!rejected){
            char reply[2]={0},other=0;
            check(!read_full(channel[0][0],reply,variant?1:2)&&(variant?reply[0]=='K':!memcmp(reply,"AD",2)));
            check(!read_full(channel[1][0],&other,1)&&other==(variant?'L':'B'));
            received=!read_full(reports[0],&result,sizeof(result));
            check(received&&result.process==child&&result.epoch==2&&result.checks==(variant?10u:37u)&&!result.failures);
            if(received)actor_total+=result.checks;else kill(child,SIGKILL);
        }
        int status;pid_t done;do{done=waitpid(child,&status,0);}while(done<0&&errno==EINTR);
        check(done==child&&WIFEXITED(status)&&WEXITSTATUS(status)==(rejected?125:0));
        for(unsigned i=0;i<2;++i)close(channel[i][0]);
        close(reports[0]);close(commands[1]);
        printf("{\"event\":\"unix-factory-case\",\"case\":%u,\"actor_checks\":%u,\"failures\":%u,\"expected_rejection\":%s,\"exit_code\":%d,\"exit_signal\":%d,\"own_mock_only\":true}\n",
            variant,rejected?0:result.checks,rejected?0:result.failures,rejected?"true":"false",WIFEXITED(status)?WEXITSTATUS(status):-1,WIFSIGNALED(status)?WTERMSIG(status):0);fflush(stdout);
    }
    check(loopback_control(AF_INET)&&loopback_control(AF_INET6));
    printf("{\"selftest\":\"unix-factory\",\"checks\":%u,\"actor_checks\":%u,\"cases\":7,\"failures\":%u,\"ok\":%s,\"own_mock_only\":true,\"audio_opened\":false,\"isolation_verified\":false}\n",
        checks,actor_total,failures,failures?"false":"true");return failures?2:0;
}
int main(int argc,char **argv){
    if(argc==5&&!strcmp(argv[1],"--factory-actor")){
        long values[3];for(unsigned i=0;i<3;++i){char *end;values[i]=strtol(argv[i+2],&end,10);if(*end||values[i]<3||values[i]>INT_MAX)return 2;}
        struct stat a,b;int death=0;
        if(values[0]==values[1]||getppid()!=values[2]||fstat((int)values[0],&a)||!S_ISFIFO(a.st_mode)||
            fstat((int)values[1],&b)||!S_ISFIFO(b.st_mode)||prctl(PR_GET_NO_NEW_PRIVS,0,0,0,0)!=1||
            prctl(PR_GET_SECCOMP,0,0,0,0)!=2||prctl(PR_GET_PDEATHSIG,&death,0,0,0)||death!=SIGKILL)return 2;
        return getenv("LISA_FACTORY_CONCURRENT")?factory_concurrent_actor((int)values[0],(int)values[1],(pid_t)values[2]):factory_actor((int)values[0],(int)values[1],(pid_t)values[2]);
    }
    if(argc==3&&!strcmp(argv[1],"--factory-selftest")){
        char executable[PATH_MAX],library[PATH_MAX];if(!realpath(argv[0],executable)||!realpath(argv[2],library))return 2;
        return factory_selftest(executable,library);
    }
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
