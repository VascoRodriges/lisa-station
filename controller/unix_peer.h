/* Metadata-only UNIX_DIAG census. Never request socket names, destroy sockets,
 * duplicate another process's FD or receive an application's queued payload.
 * Linux UAPI: include/uapi/linux/unix_diag.h (including Linux v4.9). */
#ifndef LISA_UNIX_PEER_H
#define LISA_UNIX_PEER_H
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <linux/sock_diag.h>
#include <linux/unix_diag.h>
#include "relay_resources.h"

#define UNIX_PEER_LIMIT 8192
struct unix_peer {
    uint32_t inode,cookie[2],peer,receive,write;
    unsigned type,state,have_peer,have_queue;
};
static inline int unix_peer_parse(const struct nlmsghdr *header,struct unix_peer *row) {
    if(header->nlmsg_type!=SOCK_DIAG_BY_FAMILY||header->nlmsg_len<NLMSG_LENGTH(sizeof(struct unix_diag_msg))) return -1;
    struct unix_diag_msg value; memcpy(&value,NLMSG_DATA(header),sizeof(value));
    if(value.udiag_family!=AF_UNIX||!value.udiag_ino||!value.udiag_state||value.udiag_state>12||
        (value.udiag_type!=SOCK_STREAM&&value.udiag_type!=SOCK_DGRAM&&value.udiag_type!=SOCK_SEQPACKET)||
        (value.udiag_cookie[0]==UINT32_MAX&&value.udiag_cookie[1]==UINT32_MAX)) return -1;
    *row=(struct unix_peer){.inode=value.udiag_ino,.cookie={value.udiag_cookie[0],value.udiag_cookie[1]},
        .type=value.udiag_type,.state=value.udiag_state};
    unsigned left=header->nlmsg_len-NLMSG_LENGTH(sizeof(value));
    struct rtattr *attribute=(struct rtattr*)((char*)NLMSG_DATA(header)+NLMSG_ALIGN(sizeof(value)));
    while(RTA_OK(attribute,left)) {
        if(RTA_ALIGN(attribute->rta_len)>left) return -1;
        if(attribute->rta_type==UNIX_DIAG_PEER) {
            if(row->have_peer||RTA_PAYLOAD(attribute)!=sizeof(uint32_t)) return -1;
            memcpy(&row->peer,RTA_DATA(attribute),sizeof(row->peer)); row->have_peer=1;
        } else if(attribute->rta_type==UNIX_DIAG_RQLEN) {
            if(row->have_queue||RTA_PAYLOAD(attribute)!=sizeof(struct unix_diag_rqlen)) return -1;
            struct unix_diag_rqlen queue; memcpy(&queue,RTA_DATA(attribute),sizeof(queue));
            row->receive=queue.udiag_rqueue; row->write=queue.udiag_wqueue; row->have_queue=1;
        }
        attribute=RTA_NEXT(attribute,left);
    }
    return left?-1:0;
}
static inline int unix_peer_same(const struct unix_peer *a,const struct unix_peer *b) {
    return a->inode==b->inode&&a->cookie[0]==b->cookie[0]&&a->cookie[1]==b->cookie[1]&&
        a->type==b->type&&a->state==b->state&&a->have_peer==b->have_peer&&a->peer==b->peer&&
        a->have_queue==b->have_queue;
}
static inline struct unix_peer *unix_peer_find(struct unix_peer *rows,unsigned count,uint32_t inode) {
    for(unsigned i=0;i<count;++i) if(rows[i].inode==inode) return &rows[i];
    return NULL;
}
static inline int unix_peer_snapshot(struct unix_peer *rows,unsigned *count) {
    *count=0;
    int fd=socket(AF_NETLINK,SOCK_RAW|SOCK_CLOEXEC,NETLINK_SOCK_DIAG);
    if(fd<0) return -errno;
    int result=-EPROTO,done=0; unsigned packets=0;
    struct sockaddr_nl local={.nl_family=AF_NETLINK},kernel={.nl_family=AF_NETLINK};
    if(bind(fd,(struct sockaddr*)&local,sizeof(local))) { result=-errno; goto finish; }
    struct { struct nlmsghdr header; struct unix_diag_req request; } message={
        .header={.nlmsg_len=NLMSG_LENGTH(sizeof(struct unix_diag_req)),.nlmsg_type=SOCK_DIAG_BY_FAMILY,
            .nlmsg_flags=NLM_F_REQUEST|NLM_F_DUMP,.nlmsg_seq=1},
        .request={.sdiag_family=AF_UNIX,.udiag_states=UINT32_MAX,.udiag_show=UDIAG_SHOW_PEER|UDIAG_SHOW_RQLEN}};
    if(sendto(fd,&message,message.header.nlmsg_len,0,(struct sockaddr*)&kernel,sizeof(kernel))!=(ssize_t)message.header.nlmsg_len) goto finish;
    uint64_t deadline=guardian_milliseconds()+3000;
    while(!done) {
        uint64_t now=guardian_milliseconds(); struct pollfd ready={fd,POLLIN,0};
        if(now>=deadline||++packets>256||poll(&ready,1,(int)(deadline-now))!=1) { result=-ETIMEDOUT; goto finish; }
        union { struct nlmsghdr align; unsigned char bytes[65536]; } buffer;
        struct sockaddr_nl sender={0}; struct iovec iov={buffer.bytes,sizeof(buffer.bytes)};
        struct msghdr response={.msg_name=&sender,.msg_namelen=sizeof(sender),.msg_iov=&iov,.msg_iovlen=1};
        ssize_t bytes=recvmsg(fd,&response,MSG_DONTWAIT);
        if(bytes<=0||(response.msg_flags&(MSG_TRUNC|MSG_CTRUNC))||response.msg_namelen!=sizeof(sender)||
            sender.nl_family!=AF_NETLINK||sender.nl_pid||sender.nl_groups) goto finish;
        unsigned left=(unsigned)bytes;
        for(struct nlmsghdr *header=(struct nlmsghdr*)buffer.bytes;NLMSG_OK(header,left);header=NLMSG_NEXT(header,left)) {
            if(done||NLMSG_ALIGN(header->nlmsg_len)>left||header->nlmsg_seq!=1||(header->nlmsg_flags&NLM_F_DUMP_INTR)) goto finish;
            if(header->nlmsg_type==NLMSG_DONE) {
                unsigned payload=header->nlmsg_len-NLMSG_HDRLEN;
                if(payload) {
                    int error; if(payload!=sizeof(error)) goto finish;
                    memcpy(&error,NLMSG_DATA(header),sizeof(error)); if(error) goto finish;
                }
                done=1; continue;
            }
            if(header->nlmsg_type==NLMSG_ERROR||*count==UNIX_PEER_LIMIT||
                unix_peer_parse(header,&rows[*count])||unix_peer_find(rows,*count,rows[*count].inode)) goto finish;
            ++*count;
        }
        if(left) goto finish;
    }
    result=0;
finish:
    close(fd); if(result) *count=0; return result;
}
static inline int unix_peer_fd(pid_t pid,unsigned descriptor,uint32_t *inode) {
    char path[80]; struct stat info;
    snprintf(path,sizeof(path),"/proc/%ld/fd/%u",(long)pid,descriptor);
    if(stat(path,&info)||!S_ISSOCK(info.st_mode)||!info.st_ino||(uint64_t)info.st_ino>UINT32_MAX) return -1;
    *inode=(uint32_t)info.st_ino; return 0;
}
#endif
