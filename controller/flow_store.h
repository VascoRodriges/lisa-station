/* Immutable, revision/boot-bound exact-flow evidence. Callers must establish
 * attribution/completeness before publishing; this file is not privacy proof. */
#ifndef LISA_FLOW_STORE_H
#define LISA_FLOW_STORE_H
#include <arpa/inet.h>
#include <stdlib.h>
#include "service_gate.h"
#include "socket_diag.h"

#define FLOW_LIMIT 32
#define FLOW_TEXT_LIMIT 8192
struct saved_flow {
    int family,protocol;
    uint64_t inode;
    struct inet_diag_sockid id;
};
struct flow_plan {
    uint64_t revision;
    char boot[37],chain[28];
    unsigned count;
    struct saved_flow flows[FLOW_LIMIT];
};

static inline int flow_chain_valid(const char *chain) {
    size_t size=strnlen(chain,28);
    if(size<8 || size>25 || strncmp(chain,"LISAFT_",7)) return 0;
    for(size_t i=7;i<size;++i) if(!((chain[i]>='0'&&chain[i]<='9') ||
        (chain[i]>='A'&&chain[i]<='Z') || chain[i]=='_')) return 0;
    return 1;
}
static inline int flow_mapped(const void *address) {
    const unsigned char prefix[12]={0,0,0,0,0,0,0,0,0,0,255,255};
    return !memcmp(address,prefix,12);
}
/* The socket family is retained for inet_diag; mapped sockets use IPv4 rules.
 * Scoped/link-local and multicast addresses are unsupported, never skipped. */
static inline int flow_wire(const struct saved_flow *flow,int *family,char *source,char *destination) {
    const unsigned char *src=(const void*)flow->id.idiag_src,*dst=(const void*)flow->id.idiag_dst;
    int mapped=flow->family==AF_INET6 && flow_mapped(src) && flow_mapped(dst);
    if(flow->family==AF_INET6 && flow_mapped(src)!=flow_mapped(dst)) return -1;
    *family=flow->family;
    if(mapped) { *family=AF_INET; src+=12; dst+=12; }
    if(*family==AF_INET) {
        const unsigned char zero[12]={0};
        if(!mapped && (memcmp((const unsigned char*)flow->id.idiag_src+4,zero,12) ||
            memcmp((const unsigned char*)flow->id.idiag_dst+4,zero,12))) return -1;
        if(!src[0] || !dst[0] || src[0]>=224 || dst[0]>=224) return -1;
    } else if(*family==AF_INET6) {
        const unsigned char zero[16]={0};
        if(!memcmp(src,zero,16) || !memcmp(dst,zero,16) || src[0]==255 || dst[0]==255 ||
            (src[0]==254 && (src[1]&192)==128) || (dst[0]==254 && (dst[1]&192)==128)) return -1;
    } else return -1;
    return inet_ntop(*family,src,source,INET6_ADDRSTRLEN) &&
        inet_ntop(*family,dst,destination,INET6_ADDRSTRLEN)?0:-1;
}
static inline int flow_valid(const struct saved_flow *flow) {
    char source[INET6_ADDRSTRLEN],destination[INET6_ADDRSTRLEN]; int family;
    if(!flow->inode || !flow->id.idiag_sport || !flow->id.idiag_dport || flow->id.idiag_if ||
        flow_wire(flow,&family,source,destination) ||
        (!strcmp(source,destination) && flow->id.idiag_sport==flow->id.idiag_dport)) return 0;
    int no_cookie=flow->id.idiag_cookie[0]==INET_DIAG_NOCOOKIE && flow->id.idiag_cookie[1]==INET_DIAG_NOCOOKIE;
    return flow->protocol==IPPROTO_TCP?!no_cookie:flow->protocol==IPPROTO_UDP&&no_cookie;
}
static inline int flow_plan_valid(const struct flow_plan *plan) {
    if(!plan->revision || plan->revision==UINT64_MAX || strnlen(plan->boot,sizeof(plan->boot))!=36 || !gate_boot_valid(plan->boot) ||
        !flow_chain_valid(plan->chain) || !plan->count || plan->count>FLOW_LIMIT) return 0;
    for(unsigned i=0;i<plan->count;++i) {
        if(!flow_valid(&plan->flows[i])) return 0;
        for(unsigned j=0;j<i;++j) {
            char a[INET6_ADDRSTRLEN],b[INET6_ADDRSTRLEN],c[INET6_ADDRSTRLEN],d[INET6_ADDRSTRLEN]; int x,y;
            if(flow_wire(&plan->flows[i],&x,a,b) || flow_wire(&plan->flows[j],&y,c,d)) return 0;
            if(x==y && plan->flows[i].protocol==plan->flows[j].protocol && !strcmp(a,c) && !strcmp(b,d) &&
                plan->flows[i].id.idiag_sport==plan->flows[j].id.idiag_sport &&
                plan->flows[i].id.idiag_dport==plan->flows[j].id.idiag_dport) return 0;
        }
    }
    return 1;
}
static inline void flow_hex(const void *address,char *hex) {
    const unsigned char *bytes=address;
    for(unsigned i=0;i<16;++i) snprintf(hex+i*2,3,"%02x",bytes[i]);
}
static inline int flow_unhex(const char *hex,void *address) {
    if(strlen(hex)!=32) return -1;
    unsigned char *bytes=address;
    for(unsigned i=0;i<16;++i) {
        unsigned value=0;
        for(unsigned j=0;j<2;++j) {
            char c=hex[i*2+j]; unsigned digit;
            if(c>='0'&&c<='9') digit=c-'0';
            else if(c>='a'&&c<='f') digit=c-'a'+10;
            else return -1;
            value=value*16+digit;
        }
        bytes[i]=(unsigned char)value;
    }
    return 0;
}
static inline int flow_plan_format(const struct flow_plan *plan,char *text,size_t capacity) {
    if(!flow_plan_valid(plan)) return -1;
    int size=snprintf(text,capacity,"LISA_FLOWS_V1 %" PRIu64 " %s %s %u\n",plan->revision,plan->boot,plan->chain,plan->count);
    if(size<0 || (size_t)size>=capacity) return -1;
    for(unsigned i=0;i<plan->count;++i) {
        const struct saved_flow *f=&plan->flows[i]; char source[33],destination[33];
        flow_hex(f->id.idiag_src,source); flow_hex(f->id.idiag_dst,destination);
        int added=snprintf(text+size,capacity-(size_t)size,"%u %s %s %u %s %u %" PRIu64 " %08x %08x\n",
            f->family==AF_INET?4:6,f->protocol==IPPROTO_TCP?"tcp":"udp",source,ntohs(f->id.idiag_sport),
            destination,ntohs(f->id.idiag_dport),f->inode,f->id.idiag_cookie[0],f->id.idiag_cookie[1]);
        if(added<0 || (size_t)added>=capacity-(size_t)size) return -1;
        size+=added;
    }
    return size;
}
static inline int flow_plan_parse(const char *text,size_t size,struct flow_plan *plan) {
    if(!size || size>=FLOW_TEXT_LIMIT || memchr(text,0,size)) return -1;
    char copy[FLOW_TEXT_LIMIT],canonical[FLOW_TEXT_LIMIT]; memcpy(copy,text,size); copy[size]=0;
    struct flow_plan parsed={0}; char *save,*line=strtok_r(copy,"\n",&save); unsigned long long revision;
    int consumed=0;
    if(!line || sscanf(line,"LISA_FLOWS_V1 %llu %36s %27s %u%n",&revision,parsed.boot,parsed.chain,
        &parsed.count,&consumed)!=4 || line[consumed] || !parsed.count || parsed.count>FLOW_LIMIT) return -1;
    parsed.revision=revision;
    for(unsigned i=0;i<parsed.count;++i) {
        line=strtok_r(NULL,"\n",&save); struct saved_flow *f=&parsed.flows[i];
        char source[33],destination[33],protocol[8]; unsigned family,sport,dport,a,b; unsigned long long inode;
        consumed=0;
        if(!line || sscanf(line,"%u %7s %32s %u %32s %u %llu %x %x%n",&family,protocol,source,&sport,
            destination,&dport,&inode,&a,&b,&consumed)!=9 || line[consumed] || !sport || sport>65535 || !dport || dport>65535 ||
            (family!=4&&family!=6) || (strcmp(protocol,"tcp")&&strcmp(protocol,"udp")) ||
            flow_unhex(source,f->id.idiag_src) || flow_unhex(destination,f->id.idiag_dst)) return -1;
        f->family=family==4?AF_INET:AF_INET6; f->protocol=!strcmp(protocol,"tcp")?IPPROTO_TCP:IPPROTO_UDP;
        f->inode=inode; f->id.idiag_sport=htons((uint16_t)sport); f->id.idiag_dport=htons((uint16_t)dport);
        f->id.idiag_cookie[0]=a; f->id.idiag_cookie[1]=b;
    }
    if(strtok_r(NULL,"\n",&save) || flow_plan_format(&parsed,canonical,sizeof(canonical))!=(int)size ||
        memcmp(text,canonical,size)) return -1;
    *plan=parsed; return 0;
}
/* 1 means absent. Existing unknown files are never replaced or treated empty. */
static inline int flow_plan_read(int state,uid_t owner,uint64_t revision,const char *boot,struct flow_plan *plan) {
    if(!store_directory_valid(state,owner) || !gate_boot_valid(boot)) return -1;
    int fd=openat(state,"flows.state",O_RDONLY|O_NOFOLLOW|O_NONBLOCK|O_CLOEXEC);
    if(fd<0) return errno==ENOENT?1:-1;
    if(!store_file_valid(fd,owner)) { close(fd); return -1; }
    char text[FLOW_TEXT_LIMIT]; size_t used=0;
    while(used<sizeof(text)) {
        ssize_t count=read(fd,text+used,sizeof(text)-used);
        if(count<0 && errno==EINTR) continue;
        if(count<0) { close(fd); return -1; }
        if(!count) break;
        used+=(size_t)count;
    }
    close(fd);
    struct flow_plan parsed;
    if(flow_plan_parse(text,used,&parsed) || parsed.revision!=revision || strcmp(parsed.boot,boot)) return -1;
    *plan=parsed; return 0;
}
/* Atomic no-replace publication, fsync before any socket is destroyed. The
 * caller serializes snapshot/publication with transition ownership. */
static inline int flow_plan_publish(int state,uid_t owner,const struct flow_plan *plan) {
    if(!store_directory_valid(state,owner)) return -1;
    char text[FLOW_TEXT_LIMIT]; int size=flow_plan_format(plan,text,sizeof(text));
    if(size<0) return -1;
    struct flow_plan existing;
    int present=flow_plan_read(state,owner,plan->revision,plan->boot,&existing);
    if(!present) {
        char previous[FLOW_TEXT_LIMIT]; int old=flow_plan_format(&existing,previous,sizeof(previous));
        if(old!=size || memcmp(previous,text,(size_t)size)) return -1;
        /* Visibility is not durability: an earlier directory fsync may have
         * failed after publication. A retry must sync the existing evidence. */
        int fd=openat(state,"flows.state",O_RDONLY|O_NOFOLLOW|O_NONBLOCK|O_CLOEXEC);
        if(fd<0) return -1;
        int failed=!store_file_valid(fd,owner)||fsync(fd);
        if(close(fd)) failed=1;
        if(!failed && fsync(state)) failed=1;
        return failed?-1:0;
    }
    if(present<0) return -1;
    uint64_t nonce; char temporary[64];
    if(getrandom(&nonce,sizeof(nonce),0)!=(ssize_t)sizeof(nonce)) return -1;
    snprintf(temporary,sizeof(temporary),".flows-%" PRIx64 ".tmp",nonce);
    int fd=openat(state,temporary,O_WRONLY|O_CREAT|O_EXCL|O_NOFOLLOW|O_CLOEXEC,0600);
    if(fd<0) return -1;
    int failed=store_write_all(fd,text,(size_t)size)||fsync(fd);
    if(close(fd)) failed=1;
    /* linkat is atomic and refuses replacement. After unlink + directory fsync
     * the canonical file has a single link; interrupted multi-links deny read. */
    if(!failed && linkat(state,temporary,state,"flows.state",0)) failed=1;
    if(unlinkat(state,temporary,0)) failed=1;
    if(!failed && fsync(state)) failed=1;
    return failed?-1:0;
}
#endif
