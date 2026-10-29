/* Read-only UDP socket metadata. Cookies identify endpoints, not destinations
 * of sendto() on an unconnected socket. No socket destruction or payload read. */
#ifndef LISA_UDP_OWNER_H
#define LISA_UDP_OWNER_H
#include <linux/rtnetlink.h>
#include "tcp_owner.h"

#define UDP_OWNER_LIMIT 2048
struct udp_owner {
    struct inet_diag_msg value;
    int v6only; /* -1 when the kernel did not supply this attribute. */
};
static inline int udp_owner_parse(const struct nlmsghdr *header,struct udp_owner *row) {
    if(header->nlmsg_type!=SOCK_DIAG_BY_FAMILY||header->nlmsg_len<NLMSG_LENGTH(sizeof(struct inet_diag_msg))) return -1;
    struct inet_diag_msg value; memcpy(&value,NLMSG_DATA(header),sizeof(value));
    if((value.idiag_family!=AF_INET&&value.idiag_family!=AF_INET6)||!value.idiag_inode||!value.id.idiag_sport||
        (value.idiag_state!=1&&value.idiag_state!=7)||
        (value.id.idiag_cookie[0]==UINT32_MAX&&value.id.idiag_cookie[1]==UINT32_MAX)) return -1;
    if(value.idiag_family==AF_INET) for(unsigned i=1;i<4;++i)
        if(value.id.idiag_src[i]||value.id.idiag_dst[i]) return -1;
    if(value.idiag_state==1&&!value.id.idiag_dport) return -1;
    if(value.idiag_state==7&&(value.id.idiag_dport||value.id.idiag_dst[0]||value.id.idiag_dst[1]||
        value.id.idiag_dst[2]||value.id.idiag_dst[3])) return -1;
    *row=(struct udp_owner){.value=value,.v6only=-1};
    unsigned left=header->nlmsg_len-NLMSG_LENGTH(sizeof(value));
    struct rtattr *attribute=(struct rtattr*)((char*)NLMSG_DATA(header)+NLMSG_ALIGN(sizeof(value)));
    while(RTA_OK(attribute,left)) {
        if(RTA_ALIGN(attribute->rta_len)>left) return -1;
        if(attribute->rta_type==INET_DIAG_SKV6ONLY) {
            unsigned char flag;
            if(row->v6only!=-1||value.idiag_family!=AF_INET6||RTA_PAYLOAD(attribute)!=sizeof(flag)) return -1;
            memcpy(&flag,RTA_DATA(attribute),sizeof(flag));
            if(flag>1) return -1;
            row->v6only=flag;
        }
        attribute=RTA_NEXT(attribute,left);
    }
    return left?-1:0;
}
static inline int udp_owner_same(const struct udp_owner *a,const struct udp_owner *b) {
    const struct inet_diag_msg *x=&a->value,*y=&b->value;
    return x->idiag_family==y->idiag_family&&x->idiag_state==y->idiag_state&&x->idiag_uid==y->idiag_uid&&
        x->idiag_inode==y->idiag_inode&&x->id.idiag_if==y->id.idiag_if&&diag_same_tuple(&x->id,&y->id)&&
        !memcmp(x->id.idiag_cookie,y->id.idiag_cookie,sizeof(x->id.idiag_cookie))&&a->v6only==b->v6only;
}
/* Explicit lower-strength fallback for kernels built without UDP_DIAG. Cookie
 * sentinel and unknown v6only survive in evidence; never convert these rows to
 * a cookie-qualified flow plan. */
static inline int udp_owner_proc_snapshot(struct udp_owner *rows,unsigned *count) {
    const char *paths[]={"/proc/net/udp","/proc/net/udp6"}; *count=0;
    for(unsigned i=0;i<2;++i) {
        FILE *file=fopen(paths[i],"r"); char line[512]; int failed=0;
        if(!file) return -errno;
        if(!fgets(line,sizeof(line),file)||!strstr(line,"local_address")) failed=1;
        while(!failed&&fgets(line,sizeof(line),file)) {
            struct tcp_owner_row source;
            if(!strchr(line,'\n')||*count==UDP_OWNER_LIMIT||tcp_owner_parse(line,i?AF_INET6:AF_INET,&source)||
                !source.inode||source.inode>UINT32_MAX||!source.id.idiag_sport||(source.state!=1&&source.state!=7)) failed=1;
            else {
                struct udp_owner value={.v6only=-1,.value={.idiag_family=source.family,.idiag_state=source.state,
                    .idiag_uid=source.uid,.idiag_inode=(uint32_t)source.inode,.id=source.id}};
                rows[(*count)++]=value;
            }
        }
        if(ferror(file)) failed=1;
        fclose(file); if(failed) { *count=0; return -EPROTO; }
    }
    return 0;
}
static inline struct udp_owner *udp_owner_find(struct udp_owner *rows,unsigned count,uint64_t inode) {
    for(unsigned i=0;i<count;++i) if(rows[i].value.idiag_inode==inode) return &rows[i];
    return NULL;
}
static inline int udp_owner_snapshot(struct udp_owner *rows,unsigned *count) {
    *count=0; int fd=socket(AF_NETLINK,SOCK_RAW|SOCK_CLOEXEC,NETLINK_SOCK_DIAG);
    if(fd<0) return -errno;
    int result=-EPROTO;
    struct sockaddr_nl local={.nl_family=AF_NETLINK},kernel={.nl_family=AF_NETLINK};
    if(bind(fd,(struct sockaddr*)&local,sizeof(local))) { result=-errno; goto finish; }
    for(unsigned family_index=0;family_index<2;++family_index) {
        unsigned family=family_index?AF_INET6:AF_INET,sequence=family_index+1,packets=0; int done=0;
        struct { struct nlmsghdr header; struct inet_diag_req_v2 request; } message={
            .header={.nlmsg_len=NLMSG_LENGTH(sizeof(struct inet_diag_req_v2)),.nlmsg_type=SOCK_DIAG_BY_FAMILY,
                .nlmsg_flags=NLM_F_REQUEST|NLM_F_DUMP,.nlmsg_seq=sequence},
            .request={.sdiag_family=family,.sdiag_protocol=IPPROTO_UDP,.idiag_states=UINT32_MAX}};
        if(sendto(fd,&message,message.header.nlmsg_len,0,(struct sockaddr*)&kernel,sizeof(kernel))!=(ssize_t)message.header.nlmsg_len) { result=-EIO; goto finish; }
        uint64_t deadline=guardian_milliseconds()+3000;
        while(!done) {
            uint64_t now=guardian_milliseconds(); struct pollfd ready={fd,POLLIN,0};
            if(now>=deadline||++packets>256||poll(&ready,1,(int)(deadline-now))!=1) { result=-ETIMEDOUT; goto finish; }
            union { struct nlmsghdr align; unsigned char bytes[65536]; } buffer;
            struct sockaddr_nl sender={0}; struct iovec iov={buffer.bytes,sizeof(buffer.bytes)};
            struct msghdr response={.msg_name=&sender,.msg_namelen=sizeof(sender),.msg_iov=&iov,.msg_iovlen=1};
            ssize_t bytes=recvmsg(fd,&response,MSG_DONTWAIT);
            if(bytes<=0||(response.msg_flags&(MSG_TRUNC|MSG_CTRUNC))||response.msg_namelen!=sizeof(sender)||
                sender.nl_family!=AF_NETLINK||sender.nl_pid||sender.nl_groups) { result=-ENOBUFS; goto finish; }
            unsigned left=(unsigned)bytes;
            for(struct nlmsghdr *header=(struct nlmsghdr*)buffer.bytes;NLMSG_OK(header,left);header=NLMSG_NEXT(header,left)) {
                if(done||NLMSG_ALIGN(header->nlmsg_len)>left||header->nlmsg_seq!=sequence||(header->nlmsg_flags&NLM_F_DUMP_INTR)) { result=-ESTALE; goto finish; }
                if(header->nlmsg_type==NLMSG_DONE) {
                    unsigned payload=header->nlmsg_len-NLMSG_HDRLEN;
                    if(payload) {
                        int error; if(payload!=sizeof(error)) { result=-EINVAL; goto finish; }
                        memcpy(&error,NLMSG_DATA(header),sizeof(error)); if(error) { result=error<0?error:-EPROTO; goto finish; }
                    }
                    done=1; continue;
                }
                if(header->nlmsg_type==NLMSG_ERROR) {
                    if(header->nlmsg_len>=NLMSG_LENGTH(sizeof(struct nlmsgerr))) {
                        struct nlmsgerr error; memcpy(&error,NLMSG_DATA(header),sizeof(error));
                        if(error.error<0&&error.error>=-4095) result=error.error;
                    }
                    goto finish;
                }
                if(*count==UDP_OWNER_LIMIT) { result=-EOVERFLOW; goto finish; }
                if(udp_owner_parse(header,&rows[*count])) { result=-EBADMSG; goto finish; }
                if(rows[*count].value.idiag_family!=family) { result=-EAFNOSUPPORT; goto finish; }
                if(udp_owner_find(rows,*count,rows[*count].value.idiag_inode)) { result=-EEXIST; goto finish; }
                ++*count;
            }
            if(left) { result=-EMSGSIZE; goto finish; }
        }
    }
    result=0;
finish:
    close(fd); if(result) *count=0; return result;
}
/* The two kernel dumps bracket this holder census. Per-holder identity checks
 * do not make the entire sequence atomic, or exclude a concurrent sendto(). */
static inline int udp_owner_holder(pid_t pid,int fd,uint64_t ticks,const struct tcp_executable *executable,uint64_t expected) {
    struct tcp_executable first,last; uint64_t inode;
    if(!process_live(pid,ticks)||tcp_owner_executable(pid,&first)||first.device!=executable->device||
        first.inode!=executable->inode||tcp_owner_fd(pid,fd,&inode)||inode!=expected||
        tcp_owner_fd(pid,fd,&inode)||inode!=expected||tcp_owner_executable(pid,&last)||
        first.device!=last.device||first.inode!=last.inode||!process_live(pid,ticks)) return 0;
    return 1;
}
#endif
