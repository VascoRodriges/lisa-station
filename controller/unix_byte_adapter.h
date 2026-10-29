/* Explicit byte-only message adapter, not a libc interposer or security
 * boundary. Requires the independent channel guard and a byte-only peer.
 * At most 16 vectors / 64 KiB per call. No endpoint or ancillary transport.
 */
#ifndef LISA_UNIX_BYTE_ADAPTER_H
#define LISA_UNIX_BYTE_ADAPTER_H
#include <fcntl.h>
#include <signal.h>
#include <string.h>
#include <sys/uio.h>
#include "unix_byte_channel.h"
#define BYTE_ADAPTER_VECTORS 16u
#define BYTE_ADAPTER_BYTES 65536u
struct unix_byte_adapter{int fd;pid_t parent;dev_t device;ino_t inode;};
static inline int unix_byte_adapter_init(struct unix_byte_adapter *adapter,int fd,pid_t parent){
    if(!adapter){errno=EFAULT;return -1;}
    *adapter=(struct unix_byte_adapter){.fd=-1};struct stat info;
    if(!unix_byte_channel_valid(fd,parent)||fstat(fd,&info)){errno=EPERM;return -1;}
    *adapter=(struct unix_byte_adapter){fd,parent,info.st_dev,info.st_ino};return 0;
}
static inline int unix_byte_adapter_ready(const struct unix_byte_adapter *adapter,int flags,int receive){
    if(!adapter||adapter->fd<0){errno=EBADF;return -1;}
    struct stat info;
    if(fstat(adapter->fd,&info))return -1;
    if(info.st_dev!=adapter->device||info.st_ino!=adapter->inode||!unix_byte_channel_valid(adapter->fd,adapter->parent)){errno=EPERM;return -1;}
    const int allowed=MSG_DONTWAIT|(receive?MSG_CMSG_CLOEXEC:MSG_NOSIGNAL);
    if(flags&~allowed){errno=EOPNOTSUPP;return -1;}
    int mode=fcntl(adapter->fd,F_GETFL);if(mode<0)return -1;
    /* Do not silently turn a per-call request into a shared OFD flag change. */
    if((flags&MSG_DONTWAIT)&&!(mode&O_NONBLOCK)){errno=EOPNOTSUPP;return -1;}
    if(!receive&&(flags&MSG_NOSIGNAL)){
        struct sigaction action;if(sigaction(SIGPIPE,NULL,&action))return -1;
        /* The trusted preparation already ignores SIGPIPE. This adapter does
         * not change any process-wide handler or consume pending signals. */
        if(action.sa_handler!=SIG_IGN){errno=EOPNOTSUPP;return -1;}
    }
    return 0;
}
static inline int unix_byte_adapter_vectors(const struct msghdr *message,struct iovec vectors[BYTE_ADAPTER_VECTORS]){
    if(!message){errno=EFAULT;return -1;}
    if(message->msg_iovlen>BYTE_ADAPTER_VECTORS){errno=EMSGSIZE;return -1;}
    if(message->msg_iovlen&&!message->msg_iov){errno=EFAULT;return -1;}
    size_t total=0;
    for(size_t i=0;i<message->msg_iovlen;++i){
        vectors[i]=message->msg_iov[i];
        if(vectors[i].iov_len>BYTE_ADAPTER_BYTES-total){errno=EMSGSIZE;return -1;}
        if(vectors[i].iov_len&&!vectors[i].iov_base){errno=EFAULT;return -1;}
        total+=vectors[i].iov_len;
    }
    return (int)message->msg_iovlen;
}
static inline ssize_t unix_byte_adapter_send(const struct unix_byte_adapter *adapter,const struct msghdr *message,int flags){
    if(!message){errno=EFAULT;return -1;}
    if(message->msg_name||message->msg_namelen||message->msg_controllen){errno=EOPNOTSUPP;return -1;}
    struct iovec vectors[BYTE_ADAPTER_VECTORS];int count=unix_byte_adapter_vectors(message,vectors);
    if(count<0||unix_byte_adapter_ready(adapter,flags,0))return -1;
    return writev(adapter->fd,vectors,count);
}
static inline ssize_t unix_byte_adapter_receive(const struct unix_byte_adapter *adapter,struct msghdr *message,int flags){
    struct iovec vectors[BYTE_ADAPTER_VECTORS];int count=unix_byte_adapter_vectors(message,vectors);
    if(count<0||unix_byte_adapter_ready(adapter,flags,1))return -1;
    ssize_t size=readv(adapter->fd,vectors,count);
    if(size>=0){
        /* The peer contract carries bytes only. No credentials/FDs are
         * fabricated, exposed or negotiated. Kernel readv discards control. */
        message->msg_namelen=0;message->msg_controllen=0;message->msg_flags=0;
    }
    return size;
}
#endif
