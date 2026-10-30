/* Diagnostic-only libc binding for preapproved, one-shot byte channels.
 * Never installed globally. Hooks provide compatibility; independent kernel
 * guards enforce endpoint/ancillary denial even when hooks are bypassed. */
#define _GNU_SOURCE
#include <pthread.h>
#include <stdatomic.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
#include "unix_byte_adapter.h"
#include "unix_byte_signal.h"
#define BUS_FACTORY_SLOTS 4u
struct bus_slot{struct unix_byte_adapter identity;int source;_Atomic int active,connected,bound;};
static struct bus_slot slots[BUS_FACTORY_SLOTS];
static unsigned slot_count;
static _Atomic unsigned next_slot;
static pthread_once_t once=PTHREAD_ONCE_INIT;
static int diagnostic;
static void initialize(void){
    int death=0;pid_t parent=getppid();const char *text=getenv("LISA_BYTE_FDS");
    if(parent<=1||prctl(PR_GET_NO_NEW_PRIVS,0,0,0,0)!=1||prctl(PR_GET_SECCOMP,0,0,0,0)!=2||
        prctl(PR_GET_PDEATHSIG,&death,0,0,0)||death!=SIGKILL||!text||!*text)_exit(125);
    while(*text){
        if(slot_count>=BUS_FACTORY_SLOTS||*text<'1'||*text>'9')_exit(125);
        unsigned number=0;
        do{number=number*10+(unsigned)(*text-'0');if(number>1023)_exit(125);++text;}while(*text>='0'&&*text<='9');
        if(number<3||unix_byte_adapter_init(&slots[slot_count].identity,(int)number,parent))_exit(125);
        for(unsigned i=0;i<slot_count;++i)if(slots[i].source==(int)number||
            (slots[i].identity.device==slots[slot_count].identity.device&&slots[i].identity.inode==slots[slot_count].identity.inode))_exit(125);
        slots[slot_count].source=(int)number;++slot_count;
        if(!*text)break;
        if(*text++!=','||!*text)_exit(125);
    }
    if(!slot_count||getppid()!=parent)_exit(125);
    const char *trace=getenv("LISA_BYTE_DIAGNOSTIC");diagnostic=trace&&!strcmp(trace,"1");
}
static void ensure_initialized(void){if(pthread_once(&once,initialize))_exit(125);}
__attribute__((constructor)) static void prepare(void){ensure_initialized();}
static struct bus_slot *find_slot(int fd,struct unix_byte_adapter *adapter){
    ensure_initialized();struct stat info;if(fstat(fd,&info)||!S_ISSOCK(info.st_mode)){errno=EPERM;return NULL;}
    for(unsigned i=0;i<slot_count;++i){
        if(atomic_load_explicit(&slots[i].active,memory_order_acquire)&&
            slots[i].identity.device==info.st_dev&&slots[i].identity.inode==info.st_ino){
            *adapter=slots[i].identity;adapter->fd=fd;
            if(unix_byte_adapter_ready(adapter,0,1))return NULL;
            return &slots[i];
        }
    }
    errno=EPERM;return NULL;
}
int socket(int domain,int type,int protocol){
    ensure_initialized();
    if(domain!=AF_UNIX||(type&~(SOCK_CLOEXEC|SOCK_NONBLOCK))!=SOCK_STREAM||protocol){errno=EPERM;return -1;}
    unsigned index=atomic_load(&next_slot);
    for(;;){if(index>=slot_count){errno=EMFILE;return -1;}
        if(atomic_compare_exchange_weak(&next_slot,&index,index+1))break;}
    struct bus_slot *slot=&slots[index];
    if(unix_byte_adapter_ready(&slot->identity,0,1))return -1;
    int fd=fcntl(slot->source,type&SOCK_CLOEXEC?F_DUPFD_CLOEXEC:F_DUPFD,3);
    if(fd<0){int error=errno;close(slot->source);errno=error;return -1;}
    int mode=fcntl(fd,F_GETFL);
    if(mode<0||fcntl(fd,F_SETFL,type&SOCK_NONBLOCK?mode|O_NONBLOCK:mode&~O_NONBLOCK)){
        int error=errno;close(fd);close(slot->source);errno=error;return -1;}
    if(close(slot->source)){int error=errno;close(fd);errno=error;return -1;}
    atomic_store_explicit(&slot->active,1,memory_order_release);return fd;
}
static int approved_address(const struct sockaddr *address,socklen_t length){
    if(!address||length<offsetof(struct sockaddr_un,sun_path)+1||length>sizeof(struct sockaddr_un)||address->sa_family!=AF_UNIX)return 0;
    const struct sockaddr_un *local=(const struct sockaddr_un *)address;
    size_t available=length - offsetof(struct sockaddr_un,sun_path),size=strnlen(local->sun_path,available);
    if(size==available||!size)return 0;
    for(size_t i=size+1;i<available;++i)if(local->sun_path[i])return 0;
    return !strcmp(local->sun_path,"/run/dbus/system_bus_socket")||!strcmp(local->sun_path,"/var/run/dbus/system_bus_socket");
}
/* The reviewed client labels itself with @<hex>/bus/<part>/<part> before
 * connect. This optional logical label NEVER binds or renames the already
 * connected kernel object. The preapproved peer and later connect allowlist
 * remain unchanged; arbitrary named/abstract addresses are rejected. */
static int approved_client_label(const struct sockaddr *address,socklen_t length){
    size_t offset=offsetof(struct sockaddr_un,sun_path);
    if(!address||length<=offset+1||length>sizeof(struct sockaddr_un)||address->sa_family!=AF_UNIX)return 0;
    const struct sockaddr_un *local=(const struct sockaddr_un *)address;
    if(local->sun_path[0])return 0;
    size_t size=length-offset,position=1;
    if(!local->sun_path[size-1])--size;
    while(position<size&&((local->sun_path[position]>='0'&&local->sun_path[position]<='9')||
        (local->sun_path[position]>='a'&&local->sun_path[position]<='f')))++position;
    if(position<2||position>17||size-position<8||memcmp(local->sun_path+position,"/bus/",5))return 0;
    position+=5;unsigned separators=0,part=0;
    for(;position<size;++position){unsigned char value=(unsigned char)local->sun_path[position];
        if(value=='/'){if(!part||separators++)return 0;part=0;}
        else{if(value<33||value>126)return 0;++part;}
    }
    return separators==1&&part>0;
}
int bind(int fd,const struct sockaddr *address,socklen_t length){
    struct unix_byte_adapter adapter;struct bus_slot *slot=find_slot(fd,&adapter);
    if(!slot||!approved_client_label(address,length)){errno=EPERM;return -1;}
    if(atomic_load(&slot->connected)){errno=EISCONN;return -1;}
    int expected=0;if(!atomic_compare_exchange_strong(&slot->bound,&expected,1)){errno=EINVAL;return -1;}
    return 0;
}
int connect(int fd,const struct sockaddr *address,socklen_t length){
    struct unix_byte_adapter adapter;struct bus_slot *slot=find_slot(fd,&adapter);
    if(!slot||!approved_address(address,length)){errno=EPERM;return -1;}
    int expected=0;if(!atomic_compare_exchange_strong(&slot->connected,&expected,1)){errno=EISCONN;return -1;}
    return 0;
}
/* Opt-in lab stderr contains scalar call metadata only, never buffer contents,
 * addresses or pointers. The trusted caller owns the private stderr sink. */
static ssize_t message_result(const char *operation,ssize_t result,const struct msghdr *message,int flags){
    if(result>=0||!diagnostic)return result;
    int saved=errno;struct sigaction action;int ignored=!sigaction(SIGPIPE,NULL,&action)&&action.sa_handler==SIG_IGN;
    char row[256];int size=snprintf(row,sizeof(row),"byte-factory %s error=%d flags=%d vectors=%zu control=%zu name=%u sigpipe_ignored=%d\n",
        operation,saved,flags,message?(size_t)message->msg_iovlen:0,message?(size_t)message->msg_controllen:0,message?(unsigned)message->msg_namelen:0,ignored);
    if(size>0&&size<(int)sizeof(row)){ssize_t written=write(2,row,(size_t)size);(void)written;}
    errno=saved;return result;
}
ssize_t sendmsg(int fd,const struct msghdr *message,int flags){
    struct unix_byte_adapter adapter;struct bus_slot *slot=find_slot(fd,&adapter);
    if(!slot)return -1;
    if(!atomic_load(&slot->connected)){errno=ENOTCONN;return -1;}
    return message_result("sendmsg",unix_byte_signal_send(&adapter,message,flags),message,flags);
}
ssize_t recvmsg(int fd,struct msghdr *message,int flags){
    struct unix_byte_adapter adapter;struct bus_slot *slot=find_slot(fd,&adapter);
    if(!slot)return -1;
    if(!atomic_load(&slot->connected)){errno=ENOTCONN;return -1;}
    return message_result("recvmsg",unix_byte_adapter_receive(&adapter,message,flags),message,flags);
}
