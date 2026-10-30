/* MSG_NOSIGNAL compatibility for a trusted owner of an admitted byte stream.
 * Never changes a process-wide handler. The caller synchronizes descriptor
 * lifetimes and does not concurrently inject SIGPIPE into this sending thread.
 * The existing adapter's endpoint, flags, vectors and ancillary checks remain. */
#ifndef LISA_UNIX_BYTE_SIGNAL_H
#define LISA_UNIX_BYTE_SIGNAL_H
#include <pthread.h>
#include "unix_byte_adapter.h"
static inline ssize_t unix_byte_signal_send(const struct unix_byte_adapter *adapter,const struct msghdr *message,int flags){
    if(!(flags&MSG_NOSIGNAL))return unix_byte_adapter_send(adapter,message,flags);
    sigset_t one,before,pending;sigemptyset(&one);sigaddset(&one,SIGPIPE);
    int error=pthread_sigmask(SIG_BLOCK,&one,&before);if(error){errno=error;return -1;}
    if(sigpending(&pending)){
        error=errno;if(pthread_sigmask(SIG_SETMASK,&before,NULL))_exit(125);errno=error;return -1;
    }
    int already_pending=sigismember(&pending,SIGPIPE);
    /* writev is safe with SIGPIPE blocked in THIS thread, even when the SDK
     * installs a process handler. No raw send syscall becomes available. */
    ssize_t result=unix_byte_adapter_send(adapter,message,flags&~MSG_NOSIGNAL);error=errno;
    if(result<0&&error==EPIPE&&!already_pending){
        struct timespec zero={0,0};int signal;
        do{signal=sigtimedwait(&one,NULL,&zero);}while(signal<0&&errno==EINTR);
        if(signal!=SIGPIPE&&(signal>=0||errno!=EAGAIN))_exit(125);
    }
    if(pthread_sigmask(SIG_SETMASK,&before,NULL))_exit(125);
    errno=error;return result;
}
#endif
