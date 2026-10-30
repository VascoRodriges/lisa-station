/* Own socketpairs only. Host fixture has no private filesystem or SDK/audio. */
#define _GNU_SOURCE
#include <dirent.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/wait.h>
#include "platform_worker_guard.h"
#include "bus_byte_relay.h"
static unsigned checks,failures;
static void check(int good){++checks;if(!good){++failures;fprintf(stderr,"relay check %u errno %d\n",checks,errno);}}
static int close_except(const int *keep,unsigned count){
    DIR *directory=opendir("/proc/self/fd");if(!directory)return -1;int own=dirfd(directory),failed=0;struct dirent *entry;
    while((entry=readdir(directory))){char *end;long fd=strtol(entry->d_name,&end,10);if(*end||fd<0||fd==own)continue;
        int retained=0;for(unsigned i=0;i<count;++i)retained|=fd==keep[i];
        if(!retained&&close((int)fd)&&errno!=EBADF)failed=1;
    }if(closedir(directory))failed=1;return failed?-1:0;
}
static int io_full(int fd,void *data,size_t size,int sending){
    uint64_t end=bus_relay_now()+5000;size_t used=0;
    while(used<size){if(bus_relay_now()>=end)return -1;
        ssize_t amount=sending?write(fd,(char *)data+used,size-used):read(fd,(char *)data+used,size-used);
        if(amount>0){used+=(size_t)amount;continue;}
        if(!amount)return -1;
        if(errno==EINTR)continue;
        if(errno!=EAGAIN&&errno!=EWOULDBLOCK)return -1;
        struct pollfd ready={fd,sending?POLLOUT:POLLIN,0};if(poll(&ready,1,50)<0&&errno!=EINTR)return -1;
    }return 0;
}
static int eof(int fd){
    struct pollfd item={fd,POLLIN,0};char value;
    return poll(&item,1,2000)==1&&read(fd,&value,1)==0;
}
static unsigned char pattern(size_t index,unsigned seed){return (unsigned char)((index*31+index/257+seed)&255);}
static int transfer(int source,int destination,unsigned seed){
    const size_t total=256u*1024;size_t sent=0,received=0;uint64_t start=bus_relay_now(),end=start+5000;
    unsigned char buffer[8192];
    while(received<total){
        uint64_t now=bus_relay_now();if(now>=end)return -1;
        int hold=now<start+150;
        if(sent<total){size_t size=total-sent;if(size>sizeof(buffer))size=sizeof(buffer);
            for(size_t i=0;i<size;++i)buffer[i]=pattern(sent+i,seed);
            ssize_t count=write(source,buffer,size);if(count>0)sent+=(size_t)count;
            else if(count==0||(errno!=EINTR&&errno!=EAGAIN&&errno!=EWOULDBLOCK))return -1;
        }
        if(!hold){ssize_t count=read(destination,buffer,sizeof(buffer));
            if(count>0){if((size_t)count>total-received)return -1;
                for(ssize_t i=0;i<count;++i)if(buffer[i]!=pattern(received+(size_t)i,seed))return -1;
                received+=(size_t)count;
            }else if(count==0||(errno!=EINTR&&errno!=EAGAIN&&errno!=EWOULDBLOCK))return -1;
        }
        struct pollfd ready[2]={{source,sent<total?POLLOUT:0,0},{destination,hold?0:POLLIN,0}};
        if(poll(ready,2,10)<0&&errno!=EINTR)return -1;
    }return sent==total?0:-1;
}
struct report {struct bus_relay_stats stats;int retained;};
static int run_case(unsigned variant){
    int client[2],backend[2],reports[2],invalid[2]={-1,-1};
    check(!socketpair(AF_UNIX,SOCK_STREAM|SOCK_CLOEXEC|SOCK_NONBLOCK,0,client)&&
        !socketpair(AF_UNIX,SOCK_STREAM|SOCK_CLOEXEC|SOCK_NONBLOCK,0,backend)&&!pipe2(reports,O_CLOEXEC));
    if(failures)return -1;
    int small=1024;check(!setsockopt(client[1],SOL_SOCKET,SO_SNDBUF,&small,sizeof(small))&&
        !setsockopt(backend[1],SOL_SOCKET,SO_SNDBUF,&small,sizeof(small)));
    int selected=backend[1];
    if(variant==3)check(!fcntl(selected,F_SETFL,fcntl(selected,F_GETFL)&~O_NONBLOCK));
    if(variant==4){selected=dup(client[1]);check(selected>=3);}
    if(variant==5){check(!pipe2(invalid,O_CLOEXEC));selected=invalid[0];}
    if(variant==6){check(!socketpair(AF_UNIX,SOCK_DGRAM|SOCK_CLOEXEC|SOCK_NONBLOCK,0,invalid));selected=invalid[0];}
    pid_t parent=getpid(),child=fork();check(child>=0);if(child<0)return -1;
    if(!child){
        int keep[]={0,1,2,client[1],selected,reports[1]};
        if(close_except(keep,6)||platform_worker_guard(parent)||unix_byte_channel_guard(client[1],parent))_exit(8);
        alarm(10);struct report result={0};
        if(variant==7)signal(SIGPIPE,SIG_DFL);
        bus_relay_run(client[1],selected,variant==8?parent+1:parent,8000,&result.stats);
        if(variant>=3){struct stat a,b;result.retained=!fstat(client[1],&a)&&!fstat(selected,&b);close(client[1]);close(selected);}
        if(write(reports[1],&result,sizeof(result))!=(ssize_t)sizeof(result))_exit(8);
        close(reports[1]);_exit(0);
    }
    close(client[1]);close(backend[1]);close(reports[1]);
    if(variant==4)close(selected);
    for(unsigned i=0;i<2;++i)if(invalid[i]>=0)close(invalid[i]);
    if(!variant){
        static const char request[]="\0AUTH EXTERNAL 30\r\nNEGOTIATE_UNIX_FD\r\nBEGIN\r\n\1\0\2\xff";
        static const char initial[]="\0AUTH EXTERNAL 30\r\n",reply[]="OK 0123456789abcdef0123456789abcdef\r\n",denied[]="ERROR Unix FD passing disabled\r\n";
        char buffer[256]={0};check(!io_full(client[0],(void *)request,sizeof(request)-1,1));
        check(!io_full(backend[0],buffer,sizeof(initial)-1,0)&&!memcmp(buffer,initial,sizeof(initial)-1));
        struct pollfd quiet={backend[0],POLLIN,0};check(poll(&quiet,1,20)==0);
        check(!io_full(backend[0],(void *)reply,sizeof(reply)-1,1));
        check(!io_full(client[0],buffer,sizeof(reply)+sizeof(denied)-2,0)&&!memcmp(buffer,reply,sizeof(reply)-1)&&
            !memcmp(buffer+sizeof(reply)-1,denied,sizeof(denied)-1));
        static const char tail[]="BEGIN\r\n\1\0\2\xff";
        check(!io_full(backend[0],buffer,sizeof(tail)-1,0)&&!memcmp(buffer,tail,sizeof(tail)-1));
        check(!transfer(client[0],backend[0],7));check(!transfer(backend[0],client[0],113));
        close(client[0]);client[0]=-1;check(eof(backend[0]));
    }else if(variant==2){static const char bad[]="\0AUTH ANONYMOUS\r\n";check(!io_full(client[0],(void *)bad,sizeof(bad)-1,1));}
    struct report result;check(!io_full(reports[0],&result,sizeof(result),0));close(reports[0]);
    int status=0;pid_t done;do{done=waitpid(child,&status,0);}while(done<0&&errno==EINTR);
    check(done==child&&WIFEXITED(status)&&!WEXITSTATUS(status));
    check(result.stats.result==(!variant?RELAY_EOF:variant<3?RELAY_AUTH:RELAY_REJECTED));
    if(!variant){check(result.stats.origin==BUS_CLIENT&&result.stats.short_writes>0&&result.stats.eagain>0&&result.stats.backpressure>0);
        check(result.stats.maximum_output<=2*BUS_AUTH_OUTPUT&&result.stats.maximum_output>0&&
            result.stats.maximum_pending<=1024&&result.stats.maximum_pending>0);
        check(result.stats.read_bytes[0]>=256u*1024&&result.stats.read_bytes[1]>=256u*1024&&
            result.stats.written_bytes[0]>=256u*1024&&result.stats.written_bytes[1]>=256u*1024);
    }else if(variant>=3)check(result.retained);
    if(client[0]>=0){check(eof(client[0]));close(client[0]);}close(backend[0]);
    printf("{\"event\":\"bus-relay-case\",\"case\":%u,\"result\":%d,\"short_writes\":%u,\"eagain\":%u,\"backpressure\":%u,\"maximum_output\":%zu,\"maximum_pending\":%zu}\n",
        variant,result.stats.result,result.stats.short_writes,result.stats.eagain,result.stats.backpressure,result.stats.maximum_output,result.stats.maximum_pending);
    return failures?-1:0;
}
int main(int argc,char **argv){
    if(argc!=2||strcmp(argv[1],"--selftest"))return 2;
    alarm(25);signal(SIGPIPE,SIG_IGN);
    for(unsigned i=0;i<9;++i)if(run_case(i))break;
    printf("{\"selftest\":\"bus-byte-relay\",\"checks\":%u,\"failures\":%u,\"ok\":%s,\"own_mock_only\":true}\n",checks,failures,failures?"false":"true");
    return failures?2:0;
}
