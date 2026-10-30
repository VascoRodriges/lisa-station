/* Bounded laboratory relay over TWO admitted parent-created byte streams.
 * Validated descriptors transfer to this call and are closed on every exit.
 * Rejected inputs stay caller-owned. This is not a filesystem/capability guard
 * or a production supervisor. Endpoint holder ownership is the parent's job. */
#ifndef LISA_BUS_BYTE_RELAY_H
#define LISA_BUS_BYTE_RELAY_H
#include <poll.h>
#include <time.h>
#include "bus_auth_gate.h"
#include "unix_byte_adapter.h"
enum bus_relay_result { RELAY_EOF, RELAY_REJECTED, RELAY_AUTH, RELAY_IO, RELAY_DEADLINE };
struct bus_relay_stats {
    uint64_t read_bytes[2],written_bytes[2];
    unsigned polls,eagain,short_writes,backpressure,authenticated;
    size_t maximum_output,maximum_pending;
    enum bus_relay_result result;
    int origin,error;
};
static inline uint64_t bus_relay_now(void){
    struct timespec now;if(clock_gettime(CLOCK_MONOTONIC,&now))return 0;
    return (uint64_t)now.tv_sec*1000+(unsigned)now.tv_nsec/1000000;
}
static inline size_t bus_relay_credit(const struct bus_auth_gate *gate,unsigned direction){
    size_t credit=gate->phase==BUS_BINARY?BUS_AUTH_OUTPUT-gate->outgoing[1-direction]:BUS_AUTH_INPUT-gate->incoming[direction];
    return credit<512?credit:512;
}
static inline enum bus_relay_result bus_relay_run(int client,int backend,pid_t parent,unsigned lifetime_ms,struct bus_relay_stats *stats){
    struct bus_relay_stats local={.result=RELAY_REJECTED,.origin=-1};
    if(stats)*stats=local;
    struct unix_byte_adapter channels[2];int descriptors[]={client,backend},death=0;
    uint64_t now=bus_relay_now();
    if(!stats||client<3||backend<3||client==backend||!lifetime_ms||lifetime_ms>60000||!now||now>UINT64_MAX-lifetime_ms||
        prctl(PR_GET_NO_NEW_PRIVS,0,0,0,0)!=1||prctl(PR_GET_SECCOMP,0,0,0,0)!=2||
        prctl(PR_GET_PDEATHSIG,&death,0,0,0)||death!=SIGKILL||
        unix_byte_adapter_init(&channels[0],client,parent)||unix_byte_adapter_init(&channels[1],backend,parent)||
        (channels[0].device==channels[1].device&&channels[0].inode==channels[1].inode))return RELAY_REJECTED;
    for(unsigned i=0;i<2;++i){
        int flags=fcntl(descriptors[i],F_GETFL);
        if(flags<0||!(flags&O_NONBLOCK)||unix_byte_adapter_ready(&channels[i],MSG_DONTWAIT|MSG_NOSIGNAL,0))return RELAY_REJECTED;
    }
    /* From this point, both objects belong exclusively to this call. */
    uint64_t end=now+lifetime_ms;struct bus_auth_gate gate;
    unsigned char pending[2][512]={{0}};size_t pending_size[2]={0};
    if(bus_auth_init(&gate,now)!=BUS_OK){local.result=RELAY_AUTH;goto done;}
    for(;;){
        now=bus_relay_now();
        if(!now||now>=end){local.result=RELAY_DEADLINE;break;}
        if(bus_auth_tick(&gate,now)!=BUS_OK){local.result=RELAY_AUTH;break;}
        /* Retained chunks are retried before any new reads. A blocked feed
         * consumed nothing, so bytes cannot disappear or be replayed. */
        for(unsigned i=0;i<2;++i)if(pending_size[i]){
            enum bus_auth_result result=bus_auth_feed(&gate,i,pending[i],pending_size[i],now);
            if(result==BUS_BAD){local.result=RELAY_AUTH;goto done;}
            if(result==BUS_OK){if(gate.phase==BUS_BINARY)local.authenticated=1;memset(pending[i],0,pending_size[i]);pending_size[i]=0;}
        }
        size_t output=gate.outgoing[0]+gate.outgoing[1],held=pending_size[0]+pending_size[1];
        if(output>local.maximum_output)local.maximum_output=output;
        if(held>local.maximum_pending)local.maximum_pending=held;
        for(unsigned i=0;i<2;++i)if(gate.outgoing[i]){
            size_t wanted=gate.outgoing[i];struct iovec item={gate.output[i],wanted};struct msghdr message={.msg_iov=&item,.msg_iovlen=1};
            ssize_t size=unix_byte_adapter_send(&channels[i],&message,MSG_DONTWAIT|MSG_NOSIGNAL);
            if(size<0){
                if(errno==EINTR)continue;
                if(errno==EAGAIN||errno==EWOULDBLOCK){++local.eagain;continue;}
                local.result=RELAY_IO;local.origin=(int)i;local.error=errno;goto done;
            }
            if(!size){local.result=RELAY_IO;local.origin=(int)i;local.error=EIO;goto done;}
            if((size_t)size<wanted)++local.short_writes;
            local.written_bytes[i]+=(uint64_t)size;
            if(bus_auth_consume(&gate,i,(size_t)size)!=BUS_OK){local.result=RELAY_AUTH;goto done;}
        }
        struct pollfd ready[2];
        for(unsigned i=0;i<2;++i){
            ready[i]=(struct pollfd){.fd=descriptors[i]};
            if(gate.outgoing[i])ready[i].events|=POLLOUT;
            if(!pending_size[i]&&bus_relay_credit(&gate,i))ready[i].events|=POLLIN;
            else ++local.backpressure;
        }
        uint64_t until=end;
        if(gate.phase!=BUS_BINARY&&gate.deadline<until)until=gate.deadline;
        now=bus_relay_now();if(!now)continue;
        int delay=now>=until?0:(until-now>100?100:(int)(until-now));
        int result=poll(ready,2,delay);++local.polls;
        if(result<0){if(errno==EINTR)continue;local.result=RELAY_IO;local.error=errno;break;}
        for(unsigned i=0;i<2;++i){
            if(ready[i].revents&POLLNVAL){local.result=RELAY_IO;local.origin=(int)i;local.error=EBADF;goto done;}
            /* Even a full destination must not keep a disconnected peer
             * alive forever. No half-open replay or queue transfer is used. */
            if(ready[i].revents&POLLERR){local.result=RELAY_IO;local.origin=(int)i;local.error=EIO;goto done;}
            if(ready[i].revents&POLLHUP){local.result=RELAY_EOF;local.origin=(int)i;goto done;}
            if((ready[i].revents&POLLIN)&&!pending_size[i]){
                size_t capacity=bus_relay_credit(&gate,i);if(!capacity)continue;
                struct iovec item={pending[i],capacity};struct msghdr message={.msg_iov=&item,.msg_iovlen=1};
                ssize_t size=unix_byte_adapter_receive(&channels[i],&message,MSG_DONTWAIT);
                if(size<0){
                    if(errno==EINTR)continue;
                    if(errno==EAGAIN||errno==EWOULDBLOCK){++local.eagain;continue;}
                    local.result=RELAY_IO;local.origin=(int)i;local.error=errno;goto done;
                }
                if(!size){local.result=RELAY_EOF;local.origin=(int)i;goto done;}
                pending_size[i]=(size_t)size;local.read_bytes[i]+=(uint64_t)size;
                held=pending_size[0]+pending_size[1];if(held>local.maximum_pending)local.maximum_pending=held;
            }
        }
    }
done:
    bus_auth_close(&gate);memset(pending,0,sizeof(pending));memset(pending_size,0,sizeof(pending_size));
    for(unsigned i=0;i<2;++i)close(descriptors[i]);
    *stats=local;return local.result;
}
#endif
