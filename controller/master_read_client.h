/* Serialized GET transport for an exclusively admitted SEQPACKET descriptor.
 * Caller owns the FD on successful init and MUST serialize every operation,
 * including close. Initialize the object with fd=-1 before first use. This is
 * not descriptor admission or role authentication. */
#ifndef LISA_MASTER_READ_CLIENT_H
#define LISA_MASTER_READ_CLIENT_H
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <stdint.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>
#include "master_read_protocol.h"
struct master_read_client {int fd;unsigned sequence;unsigned char epoch[MASTER_EPOCH_BYTES];};
static inline uint64_t master_client_time(void){struct timespec t;if(clock_gettime(CLOCK_MONOTONIC,&t))return 0;return (uint64_t)t.tv_sec*1000+(unsigned)t.tv_nsec/1000000;}
static inline int master_client_close(struct master_read_client *client){
    if(!client)return -EINVAL;
    int fd=client->fd;client->fd=-1;client->sequence=0;memset(client->epoch,0,sizeof(client->epoch));
    return fd>=3&&close(fd)?-errno:0;
}
static inline int master_client_init(struct master_read_client *client,int fd,const unsigned char *epoch){
    if(!client)return -EINVAL;
    if(client->fd>=3)return -EBUSY;
    *client=(struct master_read_client){.fd=-1};
    if(fd<3||!master_epoch_valid(epoch))return -EINVAL;
    int type=0,domain=0,listening=1;socklen_t n=sizeof(type);
    if(getsockopt(fd,SOL_SOCKET,SO_TYPE,&type,&n)||n!=sizeof(type)||type!=SOCK_SEQPACKET)return -EINVAL;
    n=sizeof(domain);if(getsockopt(fd,SOL_SOCKET,SO_DOMAIN,&domain,&n)||n!=sizeof(domain)||domain!=AF_UNIX)return -EINVAL;
    n=sizeof(listening);if(getsockopt(fd,SOL_SOCKET,SO_ACCEPTCONN,&listening,&n)||n!=sizeof(listening)||listening)return -EINVAL;
    struct sockaddr local,remote;socklen_t a=sizeof(local),b=sizeof(remote);
    if(getsockname(fd,&local,&a)||getpeername(fd,&remote,&b)||a!=sizeof(sa_family_t)||b!=sizeof(sa_family_t))return -EINVAL;
    int flags=fcntl(fd,F_GETFL);if(flags<0||fcntl(fd,F_SETFL,flags|O_NONBLOCK))return -errno;
    client->fd=fd;client->sequence=1;memcpy(client->epoch,epoch,MASTER_EPOCH_BYTES);return 0;
}
static inline int master_client_wait(int fd,short events,uint64_t end){
    for(;;){uint64_t now=master_client_time();if(!now||now>=end)return -ETIMEDOUT;
        struct pollfd p={fd,events,0};int n=poll(&p,1,(int)(end-now));if(n<0&&errno==EINTR)continue;
        if(n<0)return -errno;
        if(!n)return -ETIMEDOUT;
        if(p.revents&POLLNVAL)return -EBADF;
        if(p.revents&events)return 0;
        return -EPIPE;
    }
}
/* write() works under the byte-only guard. Block SIGPIPE only in this thread,
 * drain only a newly generated signal on EPIPE, then restore the original mask.
 * Do not change the SDK's process-wide signal handler or require sendto rights. */
static inline int master_client_write(int fd,const void *data,size_t size){
    sigset_t blocked,old,pending;sigemptyset(&blocked);sigaddset(&blocked,SIGPIPE);
    int error=pthread_sigmask(SIG_BLOCK,&blocked,&old);if(error)return -error;
    int result;if(sigpending(&pending)){result=-errno;}else{
        ssize_t n=write(fd,data,size);result=n<0?-errno:n==(ssize_t)size?0:-EPROTO;
        if(result==-EPIPE&&!sigismember(&pending,SIGPIPE)){
            struct timespec zero={0};int signal_result;do{signal_result=sigtimedwait(&blocked,NULL,&zero);}while(signal_result<0&&errno==EINTR);
            /* SIG_IGN can discard it before it becomes pending. */
            if(signal_result!=SIGPIPE&&!(signal_result<0&&errno==EAGAIN))result=-EIO;
        }
    }
    error=pthread_sigmask(SIG_SETMASK,&old,NULL);return error?-error:result;
}
/* One bounded exchange, no cached success. Any error retires the FD/epoch and
 * clears output; a later request cannot silently reconnect or retry it. */
static inline int master_client_get(struct master_read_client *client,unsigned *value){
    if(!value)return -EINVAL;
    *value=0;
    if(!client||client->fd<3||!master_sequence_valid(client->sequence)||!master_epoch_valid(client->epoch))return -ENOTCONN;
    unsigned char request[MASTER_REQUEST_BYTES],reply[MASTER_REPLY_BYTES+1];struct master_read_value decoded;
    int result=master_request_encode(client->epoch,client->sequence,request,sizeof(request))?-EPROTO:0;
    uint64_t now=master_client_time(),end=now+200;if(!now)result=-EIO;
    while(!result){result=master_client_wait(client->fd,POLLOUT,end);if(result)break;
        result=master_client_write(client->fd,request,sizeof(request));if(result==-EINTR||result==-EAGAIN||result==-EWOULDBLOCK){result=0;continue;}break;
    }
    while(!result){result=master_client_wait(client->fd,POLLIN,end);if(result)break;
        ssize_t n=read(client->fd,reply,sizeof(reply));if(n<0&&(errno==EINTR||errno==EAGAIN||errno==EWOULDBLOCK)){result=0;continue;}
        if(n<0)result=-errno;else if(!n)result=-EPIPE;else if(n!=(ssize_t)MASTER_REPLY_BYTES||master_reply_decode(reply,(size_t)n,client->epoch,client->sequence,&decoded))result=-EPROTO;
        else if(decoded.error)result=-(int)decoded.error;
        else *value=decoded.value;
        break;
    }
    if(result){*value=0;master_client_close(client);return result;}
    if(client->sequence==MASTER_READ_LIMIT){master_client_close(client);}else ++client->sequence;
    return 0;
}
#endif
