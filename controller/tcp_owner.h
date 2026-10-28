/* Read-only, per-FD TCP ownership evidence. No frozen/global snapshot or socket
 * destruction. Confirm process/executable/FD identity around inet_diag lookup. */
#ifndef LISA_TCP_OWNER_H
#define LISA_TCP_OWNER_H
#include "startup_guardian.h"
#include "socket_diag.h"

#define TCP_OWNER_LIMIT 1024
#if __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error TCP proc-word decoding is qualified only for little-endian hosts
#endif
struct tcp_owner_row { int family; unsigned state,uid; uint64_t inode; struct inet_diag_sockid id; };
struct tcp_executable { dev_t device; ino_t inode; };
static inline int tcp_owner_endpoint(char *text,int family,void *address,uint16_t *port) {
    char *colon=strchr(text,':'); size_t digits=family==AF_INET?8:32;
    if(!colon || (size_t)(colon-text)!=digits || strlen(colon+1)!=4) return -1;
    for(size_t i=0;i<digits;++i) if(!((text[i]>='0'&&text[i]<='9')||(text[i]>='A'&&text[i]<='F'))) return -1;
    for(char *at=colon+1;*at;++at) if(!((*at>='0'&&*at<='9')||(*at>='A'&&*at<='F'))) return -1;
    memset(address,0,16);
    for(size_t i=0;i<digits/8;++i) {
        char word[9]; memcpy(word,text+i*8,8); word[8]=0;
        uint32_t value=(uint32_t)strtoul(word,NULL,16); memcpy((char*)address+i*4,&value,4);
    }
    *port=htons((uint16_t)strtoul(colon+1,NULL,16)); return 0;
}
static inline int tcp_owner_parse(const char *line,int family,struct tcp_owner_row *row) {
    if((family!=AF_INET&&family!=AF_INET6) || strlen(line)>=512) return -1;
    char copy[512]; strcpy(copy,line); char *tokens[10],*save=NULL;
    for(unsigned i=0;i<10;++i) {
        tokens[i]=strtok_r(i?NULL:copy," \t\r\n",&save);
        if(!tokens[i]) return -1;
    }
    size_t slot=strlen(tokens[0]);
    if(slot<2 || tokens[0][slot-1]!=':') return -1;
    for(size_t i=0;i<slot-1;++i) if(tokens[0][i]<'0'||tokens[0][i]>'9') return -1;
    for(unsigned i=0;i<2;++i) {
        const char *number=tokens[i?9:7];
        for(const char *at=number;*at;++at) if(*at<'0'||*at>'9') return -1;
    }
    char *end; errno=0; unsigned long state=strtoul(tokens[3],&end,16);
    if(errno || *end || state>255) return -1;
    errno=0; unsigned long uid=strtoul(tokens[7],&end,10);
    if(errno || *end || uid>UINT_MAX) return -1;
    errno=0; unsigned long long inode=strtoull(tokens[9],&end,10);
    if(errno || *end) return -1;
    struct tcp_owner_row parsed={.family=family,.state=(unsigned)state,.uid=(unsigned)uid,.inode=inode};
    if(tcp_owner_endpoint(tokens[1],family,parsed.id.idiag_src,&parsed.id.idiag_sport) ||
        tcp_owner_endpoint(tokens[2],family,parsed.id.idiag_dst,&parsed.id.idiag_dport)) return -1;
    parsed.id.idiag_cookie[0]=parsed.id.idiag_cookie[1]=INET_DIAG_NOCOOKIE;
    *row=parsed; return 0;
}
static inline int tcp_owner_tables(struct tcp_owner_row *rows,unsigned *count) {
    const char *paths[]={"/proc/net/tcp","/proc/net/tcp6"}; *count=0;
    for(unsigned i=0;i<2;++i) {
        FILE *file=fopen(paths[i],"r"); char line[512]; int failed=0;
        if(!file) return -1;
        if(!fgets(line,sizeof(line),file) || !strstr(line,"local_address")) failed=1;
        while(!failed && fgets(line,sizeof(line),file)) {
            if(!strchr(line,'\n') || *count>=TCP_OWNER_LIMIT || tcp_owner_parse(line,i?AF_INET6:AF_INET,&rows[*count])) failed=1;
            else ++*count;
        }
        if(ferror(file)) failed=1;
        fclose(file); if(failed) return -1;
    }
    return 0;
}
static inline int tcp_owner_executable(pid_t pid,struct tcp_executable *executable) {
    char path[64]; struct stat info; snprintf(path,sizeof(path),"/proc/%ld/exe",(long)pid);
    if(stat(path,&info) || !S_ISREG(info.st_mode)) return -1;
    *executable=(struct tcp_executable){info.st_dev,info.st_ino}; return 0;
}
static inline int tcp_owner_fd(pid_t pid,int descriptor,uint64_t *inode) {
    char path[80],target[96]; snprintf(path,sizeof(path),"/proc/%ld/fd/%d",(long)pid,descriptor);
    ssize_t size=readlink(path,target,sizeof(target)-1);
    if(size<0 || size>=(ssize_t)sizeof(target)-1) return -1;
    target[size]=0; unsigned long long value; int consumed=0;
    if(sscanf(target,"socket:[%llu]%n",&value,&consumed)!=1 || target[consumed] || !value) return -1;
    *inode=value; return 0;
}
static inline int tcp_owner_confirm(pid_t pid,int descriptor,uint64_t ticks,const struct tcp_executable *executable,
    const struct tcp_owner_row *row,struct inet_diag_msg *answer) {
    struct process_stamp before,after; struct tcp_executable first,last; uint64_t inode;
    if(!row->inode || !row->id.idiag_sport || !row->id.idiag_dport || row->state!=1 ||
        process_stamp(pid,&before) || before.ticks!=ticks || before.state=='Z' || before.state=='X' ||
        tcp_owner_executable(pid,&first) || first.device!=executable->device || first.inode!=executable->inode ||
        tcp_owner_fd(pid,descriptor,&inode) || inode!=row->inode) return -1;
    struct inet_diag_msg found;
    if(diag_exchange(row->family,&row->id,0,&found) || found.idiag_inode!=row->inode || found.idiag_uid!=row->uid ||
        found.idiag_state!=row->state || tcp_owner_fd(pid,descriptor,&inode) || inode!=row->inode ||
        process_stamp(pid,&after) || after.ticks!=ticks || after.state=='Z' || after.state=='X' ||
        tcp_owner_executable(pid,&last) || last.device!=first.device || last.inode!=first.inode) return -1;
    *answer=found; return 0;
}
#endif
