/* Per-child compatibility for one pre-listening private stream endpoint.
 * Independent kernel filters deny all new/retargeted sockets and raw ancillary
 * calls. This library is not globally installed or a production D-Bus broker. */
#define _GNU_SOURCE
#include <stdatomic.h>
#include <stdlib.h>
#include "unix_byte_adapter.h"
#ifdef LISA_PRIVATE_ERROR_AUDIT
#include "driver_error_hook.h"
#endif
static struct stat listener;
static int source;
static pid_t parent;
static _Atomic int claimed,bound,listening;
static _Atomic unsigned used;
static int reload_sources[2];
static struct unix_byte_adapter reload_channels[2];
static _Atomic int reload_claimed;
struct client_slot{struct unix_byte_adapter adapter;_Atomic int active;};
static struct client_slot clients[4];
__attribute__((constructor)) static void prepare(void){
    const char *text=getenv("LISA_LISTENER_FD");int death=0,domain=0,type=0,accepting=0;unsigned number=0;
    parent=getppid();
    if(parent<=1||!text||*text<'1'||*text>'9'||prctl(PR_GET_NO_NEW_PRIVS,0,0,0,0)!=1||prctl(PR_GET_SECCOMP,0,0,0,0)!=2||
        prctl(PR_GET_PDEATHSIG,&death,0,0,0)||death!=SIGKILL)_exit(125);
    do{number=number*10+(unsigned)(*text++-'0');if(number>1023)_exit(125);}while(*text>='0'&&*text<='9');
    source=(int)number;
    socklen_t size=sizeof(domain);
    if(*text||source<3||fstat(source,&listener)||!S_ISSOCK(listener.st_mode)||
        getsockopt(source,SOL_SOCKET,SO_DOMAIN,&domain,&size)||size!=sizeof(domain)||domain!=AF_UNIX)_exit(125);
    size=sizeof(type);if(getsockopt(source,SOL_SOCKET,SO_TYPE,&type,&size)||size!=sizeof(type)||type!=SOCK_STREAM)_exit(125);
    int mode=fcntl(source,F_GETFL);
    size=sizeof(accepting);if(getsockopt(source,SOL_SOCKET,SO_ACCEPTCONN,&accepting,&size)||size!=sizeof(accepting)||!accepting||
        mode<0||!(mode&O_NONBLOCK)||getppid()!=parent)_exit(125);
    text=getenv("LISA_RELOAD_FDS");if(!text)_exit(125);
    for(unsigned i=0;i<2;++i){
        if(*text<'1'||*text>'9')_exit(125);
        number=0;
        do{number=number*10+(unsigned)(*text++-'0');if(number>1023)_exit(125);}while(*text>='0'&&*text<='9');
        if(number<3||number==(unsigned)source||unix_byte_adapter_init(&reload_channels[i],(int)number,parent))_exit(125);
        reload_sources[i]=(int)number;if(i==0){if(*text++!=',')_exit(125);}else if(*text)_exit(125);
    }
    if(reload_channels[0].device==reload_channels[1].device&&reload_channels[0].inode==reload_channels[1].inode)_exit(125);
#ifdef LISA_PRIVATE_ERROR_AUDIT
    text=getenv("LISA_DRIVER_ERROR_AUDIT");
    if(!text||(strcmp(text,"0")&&strcmp(text,"1"))||driver_error_prepare(!strcmp(text,"1")))_exit(125);
#endif
}
static int same_listener(int fd){struct stat info;return getppid()==parent&&!fstat(fd,&info)&&info.st_dev==listener.st_dev&&info.st_ino==listener.st_ino;}
int socket(int domain,int type,int protocol){
    if(domain!=AF_UNIX||(type&~(SOCK_NONBLOCK|SOCK_CLOEXEC))!=SOCK_STREAM||protocol){errno=EPERM;return -1;}
    int expected=0;if(!atomic_compare_exchange_strong(&claimed,&expected,1)){errno=EMFILE;return -1;}
    if(!same_listener(source)){errno=EPERM;return -1;}
    int fd=fcntl(source,type&SOCK_CLOEXEC?F_DUPFD_CLOEXEC:F_DUPFD,3);int saved=errno;close(source);errno=saved;
    /* Trusted preparation starts the listener nonblocking. Its caller must
     * maintain that policy while using this supervised event loop. */
    return fd;
}
int bind(int fd,const struct sockaddr *address,socklen_t length){
    static const char path[]="/run/lisa/bus";
    if(!same_listener(fd)||!address||length<offsetof(struct sockaddr_un,sun_path)+sizeof(path)-1||
        length>sizeof(struct sockaddr_un)||address->sa_family!=AF_UNIX){errno=EPERM;return -1;}
    const struct sockaddr_un *local=(const struct sockaddr_un *)address;size_t available=length - offsetof(struct sockaddr_un,sun_path);
    if(memcmp(local->sun_path,path,sizeof(path)-1)){errno=EPERM;return -1;}
    for(size_t i=sizeof(path)-1;i<available;++i)if(local->sun_path[i]){errno=EPERM;return -1;}
    int expected=0;if(!atomic_compare_exchange_strong(&bound,&expected,1)){errno=EINVAL;return -1;}return 0;
}
int listen(int fd,int backlog){
    if(!same_listener(fd)||!atomic_load(&bound)||backlog<1){errno=EPERM;return -1;}
    int expected=0;if(!atomic_compare_exchange_strong(&listening,&expected,1)){errno=EINVAL;return -1;}return 0;
}
int accept4(int fd,struct sockaddr *address,socklen_t *length,int flags){
    if(!same_listener(fd)||!atomic_load(&listening)||(address&&!length)||flags&~(SOCK_CLOEXEC|SOCK_NONBLOCK)){errno=EPERM;return -1;}
    if(atomic_load(&used)>=4){errno=EMFILE;return -1;}
    /* Address arguments are kernel OUTPUT here, never a retargeting input. */
    int accepted=(int)syscall(SYS_accept4,fd,address,length,flags);if(accepted<0)return -1;
    unsigned index=atomic_load(&used);
    for(;;){if(index>=4){close(accepted);errno=EMFILE;return -1;}if(atomic_compare_exchange_weak(&used,&index,index+1))break;}
    if(unix_byte_adapter_init(&clients[index].adapter,accepted,parent)){int saved=errno;close(accepted);errno=saved;return -1;}
    atomic_store_explicit(&clients[index].active,1,memory_order_release);return accepted;
}
int accept(int fd,struct sockaddr *address,socklen_t *length){return accept4(fd,address,length,0);}
int socketpair(int domain,int type,int protocol,int pair[2]){
    if(!pair||domain!=AF_UNIX||(type&~(SOCK_NONBLOCK|SOCK_CLOEXEC))!=SOCK_STREAM||protocol){errno=EPERM;return -1;}
    int expected=0;if(!atomic_compare_exchange_strong(&reload_claimed,&expected,1)){errno=EMFILE;return -1;}
    int copies[2]={-1,-1},failed=0,saved=0;
    for(unsigned i=0;i<2&&!failed;++i){
        if(unix_byte_adapter_ready(&reload_channels[i],0,1)){failed=1;saved=errno;break;}
        copies[i]=fcntl(reload_sources[i],type&SOCK_CLOEXEC?F_DUPFD_CLOEXEC:F_DUPFD,3);
        if(copies[i]<0){failed=1;saved=errno;break;}
        int mode=fcntl(copies[i],F_GETFL);
        if(mode<0||fcntl(copies[i],F_SETFL,type&SOCK_NONBLOCK?mode|O_NONBLOCK:mode&~O_NONBLOCK)){failed=1;saved=errno;}
    }
    for(unsigned i=0;i<2;++i)if(close(reload_sources[i])&&!failed){failed=1;saved=errno;}
    if(failed){for(unsigned i=0;i<2;++i)if(copies[i]>=0)close(copies[i]);errno=saved;return -1;}
    for(unsigned i=0;i<2;++i)pair[i]=copies[i];
    return 0;
}
static int lookup(int fd,struct unix_byte_adapter *adapter){
    struct stat info;if(fstat(fd,&info)||!S_ISSOCK(info.st_mode)){errno=EPERM;return -1;}
    for(unsigned i=0;i<4;++i)if(atomic_load_explicit(&clients[i].active,memory_order_acquire)&&
        info.st_dev==clients[i].adapter.device&&info.st_ino==clients[i].adapter.inode){*adapter=clients[i].adapter;adapter->fd=fd;return 0;}
    if(atomic_load(&reload_claimed))for(unsigned i=0;i<2;++i)if(info.st_dev==reload_channels[i].device&&info.st_ino==reload_channels[i].inode){*adapter=reload_channels[i];adapter->fd=fd;return 0;}
    errno=EPERM;return -1;
}
ssize_t sendmsg(int fd,const struct msghdr *message,int flags){struct unix_byte_adapter adapter;if(lookup(fd,&adapter))return -1;return unix_byte_adapter_send(&adapter,message,flags);}
ssize_t recvmsg(int fd,struct msghdr *message,int flags){struct unix_byte_adapter adapter;if(lookup(fd,&adapter))return -1;return unix_byte_adapter_receive(&adapter,message,flags);}
ssize_t send(int fd,const void *buffer,size_t size,int flags){
    struct iovec item={(void *)buffer,size};struct msghdr message={.msg_iov=&item,.msg_iovlen=1};return sendmsg(fd,&message,flags);
}
ssize_t recv(int fd,void *buffer,size_t size,int flags){
    struct iovec item={buffer,size};struct msghdr message={.msg_iov=&item,.msg_iovlen=1};return recvmsg(fd,&message,flags);
}
