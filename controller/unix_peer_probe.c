/* Root read-only IPC holder census; own-socket self-tests need no root. */
#define _GNU_SOURCE
#include "unix_peer.h"

#define UNIX_HOLDER_LIMIT 16384
struct unix_holder {
    pid_t pid; struct relay_identity identity;
    uint32_t inode; unsigned descriptor,role,confirmed;
};
static int ipc_boot(char boot[37]) {
    int file=open("/proc/sys/kernel/random/boot_id",O_RDONLY|O_CLOEXEC); char text[38];
    if(file<0) return -1;
    ssize_t count=read(file,text,sizeof(text)); close(file);
    if(count!=37||text[36]!='\n') return -1;
    text[36]=0; if(!gate_boot_valid(text)) return -1;
    memcpy(boot,text,37); return 0;
}
static int inventory(void) {
    if(geteuid()) return 2;
    int device=open("/proc/device-tree/compatible",O_RDONLY|O_CLOEXEC); char model[512];
    ssize_t size=device>=0?read(device,model,sizeof(model)):-1; if(device>=0) close(device);
    const char expected[]="yandex,station-midi"; int supported=0;
    for(ssize_t i=0;i+(ssize_t)sizeof(expected)<=size;++i)
        if((!i||!model[i-1])&&!memcmp(model+i,expected,sizeof(expected))) supported=1;
    if(!supported) return 3;
    struct unix_peer *before=calloc(UNIX_PEER_LIMIT,sizeof(*before)),*after=calloc(UNIX_PEER_LIMIT,sizeof(*after));
    struct unix_holder *holders=calloc(UNIX_HOLDER_LIMIT,sizeof(*holders));
    if(!before||!after||!holders) { free(before); free(after); free(holders); return 3; }
    char boot[37],end_boot[37]; unsigned count=0,after_count=0,total=0,unreadable=0,unidentified=0;
    int failed=ipc_boot(boot)||unix_peer_snapshot(before,&count);
    DIR *processes=failed?NULL:opendir("/proc"); struct dirent *entry;
    if(!processes) { free(before); free(after); free(holders); return 3; }
    while(!failed) {
        errno=0; entry=readdir(processes);
        if(!entry) { if(errno) ++unreadable; break; }
        char *end; long pid=strtol(entry->d_name,&end,10);
        if(*end||pid<1||pid>INT_MAX||pid==getpid()) continue;
        struct relay_identity identity;
        if(relay_identity((pid_t)pid,&identity)) { ++unidentified; continue; }
        unsigned role=relay_role((pid_t)pid); char path[64];
        snprintf(path,sizeof(path),"/proc/%ld/fd",pid);
        DIR *fds=opendir(path); struct dirent *descriptor; unsigned seen=0;
        if(!fds) { ++unreadable; continue; }
        for(;;) {
            errno=0; descriptor=readdir(fds);
            if(!descriptor) { if(errno) ++unreadable; break; }
            long fd=strtol(descriptor->d_name,&end,10);
            if(*end||fd<0||fd>INT_MAX) continue;
            if(++seen>8192) { failed=1; break; }
            uint32_t inode;
            if(unix_peer_fd((pid_t)pid,(unsigned)fd,&inode)||!unix_peer_find(before,count,inode)) continue;
            if(total==UNIX_HOLDER_LIMIT) { failed=1; break; }
            holders[total++]=(struct unix_holder){(pid_t)pid,identity,inode,(unsigned)fd,role,0};
        }
        closedir(fds);
    }
    closedir(processes);
    if(!failed) failed=unix_peer_snapshot(after,&after_count);
    unsigned confirmed=0,stable_sockets=0;
    for(unsigned i=0;i<total&&!failed;++i) {
        struct unix_holder *holder=&holders[i]; struct relay_identity current,final; uint32_t inode;
        struct unix_peer *old=unix_peer_find(before,count,holder->inode),*now=unix_peer_find(after,after_count,holder->inode);
        holder->confirmed=old&&now&&unix_peer_same(old,now)&&!relay_identity(holder->pid,&current)&&
            relay_same(&holder->identity,&current)&&relay_role(holder->pid)==holder->role&&
            !unix_peer_fd(holder->pid,holder->descriptor,&inode)&&inode==holder->inode&&
            !relay_identity(holder->pid,&final)&&relay_same(&current,&final);
        confirmed+=holder->confirmed;
    }
    if(failed) { free(before); free(after); free(holders); return 4; }
    printf("{\"event\":\"ipc-evidence-start\",\"boot_id\":\"%s\"}\n",boot);
    for(unsigned i=0;i<count;++i) {
        struct unix_peer *row=&before[i],*now=unix_peer_find(after,after_count,row->inode);
        int stable=now&&unix_peer_same(row,now); stable_sockets+=stable;
        printf("{\"event\":\"ipc-socket\",\"inode\":%u,\"cookie\":[%u,%u],\"type\":%u,\"state\":%u,"
            "\"peer\":%u,\"peer_reported\":%s,\"queue_reported\":%s,\"receive_before\":%u,\"receive_after\":%u,"
            "\"write_before\":%u,\"write_after\":%u,\"stable\":%s}\n",row->inode,row->cookie[0],row->cookie[1],row->type,row->state,
            row->peer,row->have_peer?"true":"false",row->have_queue?"true":"false",row->receive,stable?now->receive:0,
            row->write,stable?now->write:0,stable?"true":"false");
    }
    for(unsigned i=0;i<total;++i) {
        struct unix_holder *holder=&holders[i];
        printf("{\"event\":\"ipc-holder\",\"pid\":%ld,\"start_ticks\":%" PRIu64 ",\"exe_device\":%" PRIu64 ","
            "\"exe_inode\":%" PRIu64 ",\"role\":\"%s\",\"descriptor\":%u,\"inode\":%u,\"confirmed\":%s}\n",
            (long)holder->pid,holder->identity.ticks,holder->identity.device,holder->identity.inode,
            relay_role_name(holder->role),holder->descriptor,holder->inode,holder->confirmed?"true":"false");
    }
    int same_boot=!ipc_boot(end_boot)&&!strcmp(boot,end_boot);
    printf("{\"event\":\"ipc-evidence-summary\",\"sockets\":%u,\"stable_sockets\":%u,\"holders\":%u,\"confirmed\":%u,"
        "\"unreadable\":%u,\"unidentified\":%u,\"boot_stable\":%s,\"atomic_snapshot\":false,"
        "\"payload_read\":false,\"names_read\":false,\"audio_opened\":false,\"apply_supported\":false}\n",
        count,stable_sockets,total,confirmed,unreadable,unidentified,same_boot?"true":"false");
    free(before); free(after); free(holders); return same_boot?0:4;
}
static unsigned checks,failed;
static void check(int ok) { ++checks; if(!ok) { ++failed; fprintf(stderr,"failed:%u\n",checks); } }
static int selftest(void) {
    struct unix_peer *rows=calloc(UNIX_PEER_LIMIT,sizeof(*rows));
    if(!rows) return 3;
    for(unsigned kind=0;kind<3;++kind) {
        const int types[]={SOCK_STREAM,SOCK_DGRAM,SOCK_SEQPACKET}; int pair[2]; unsigned count=0;
        if(socketpair(AF_UNIX,types[kind]|SOCK_CLOEXEC,0,pair)) { check(0); continue; }
        uint32_t a=0,b=0;
        check(!unix_peer_fd(getpid(),(unsigned)pair[0],&a)&&!unix_peer_fd(getpid(),(unsigned)pair[1],&b)&&a!=b);
        int result=unix_peer_snapshot(rows,&count); check(!result);
        struct unix_peer *left=result?NULL:unix_peer_find(rows,count,a),*right=result?NULL:unix_peer_find(rows,count,b);
        check(left&&right&&left->type==(unsigned)types[kind]&&right->type==left->type);
        check(left&&right&&left->have_peer&&right->have_peer&&left->peer==b&&right->peer==a);
        check(left&&right&&left->have_queue&&right->have_queue&&!left->receive&&!right->receive);
        struct unix_peer saved=left?*left:(struct unix_peer){0};
        check(send(pair[0],"x",1,MSG_NOSIGNAL)==1&&!unix_peer_snapshot(rows,&count));
        right=unix_peer_find(rows,count,b); left=unix_peer_find(rows,count,a);
        check(right&&right->have_queue&&right->receive>0);
        check(left&&unix_peer_same(&saved,left));
        struct unix_peer wrong=saved; ++wrong.cookie[0]; check(!unix_peer_same(&saved,&wrong));
        wrong=saved; ++wrong.peer; check(!unix_peer_same(&saved,&wrong));
        wrong=saved; ++wrong.type; check(!unix_peer_same(&saved,&wrong));
        char data=0; check(recv(pair[1],&data,1,0)==1&&data=='x');
        close(pair[0]); close(pair[1]);
        check(unix_peer_fd(getpid(),(unsigned)pair[0],&a)==-1);
    }
    union { struct nlmsghdr align; unsigned char bytes[128]; } packet={0};
    struct nlmsghdr *header=(struct nlmsghdr*)packet.bytes;
    *header=(struct nlmsghdr){.nlmsg_type=SOCK_DIAG_BY_FAMILY,.nlmsg_len=NLMSG_LENGTH(sizeof(struct unix_diag_msg))};
    struct unix_diag_msg *value=NLMSG_DATA(header);
    *value=(struct unix_diag_msg){.udiag_family=AF_UNIX,.udiag_type=SOCK_STREAM,.udiag_state=1,.udiag_ino=1,.udiag_cookie={1,2}};
    struct unix_peer parsed; check(!unix_peer_parse(header,&parsed)&&parsed.inode==1&&!parsed.have_peer&&!parsed.have_queue);
    value->udiag_family=AF_INET; check(unix_peer_parse(header,&parsed)); value->udiag_family=AF_UNIX;
    value->udiag_cookie[0]=value->udiag_cookie[1]=UINT32_MAX; check(unix_peer_parse(header,&parsed)); value->udiag_cookie[0]=1;
    value->udiag_ino=0; check(unix_peer_parse(header,&parsed)); value->udiag_ino=1;
    struct rtattr *attribute=(struct rtattr*)(packet.bytes+header->nlmsg_len);
    attribute->rta_type=UNIX_DIAG_PEER; attribute->rta_len=RTA_LENGTH(4); uint32_t peer=2;
    memcpy(RTA_DATA(attribute),&peer,sizeof(peer)); header->nlmsg_len+=RTA_ALIGN(attribute->rta_len);
    check(!unix_peer_parse(header,&parsed)&&parsed.have_peer&&parsed.peer==2);
    attribute->rta_len=RTA_LENGTH(3); check(unix_peer_parse(header,&parsed)); attribute->rta_len=RTA_LENGTH(4);
    struct rtattr *duplicate=(struct rtattr*)(packet.bytes+header->nlmsg_len);
    memcpy(duplicate,attribute,RTA_ALIGN(attribute->rta_len)); header->nlmsg_len+=RTA_ALIGN(attribute->rta_len);
    check(unix_peer_parse(header,&parsed));
    free(rows);
    printf("{\"selftest\":\"unix-peer\",\"checks\":%u,\"ok\":%s,\"own_sockets_only\":true,"
        "\"audio_opened\":false,\"vendor_processes_changed\":false}\n",checks,failed?"false":"true");
    return failed?4:0;
}
int main(int argc,char **argv) {
    if(argc!=2) return 2;
    alarm(20); signal(SIGPIPE,SIG_IGN);
    if(!strcmp(argv[1],"--selftest")) return selftest();
    if(!strcmp(argv[1],"--inventory")) return inventory();
    return 2;
}
