/* Fixed read-only UDP audit and own-loopback tests; no firmware payloads. */
#define _GNU_SOURCE
#include <arpa/inet.h>
#include "udp_owner.h"
#include "relay_resources.h"

#define UDP_HOLDER_LIMIT 4096
struct holder { pid_t pid; int fd; uint64_t ticks,inode; struct tcp_executable exe; unsigned role; int confirmed; };
static struct udp_owner first[UDP_OWNER_LIMIT],last[UDP_OWNER_LIMIT];
static struct holder holders[UDP_HOLDER_LIMIT];
static int boot_id(char text[37]) {
    int fd=open("/proc/sys/kernel/random/boot_id",O_RDONLY|O_CLOEXEC); char value[38];
    ssize_t size=fd<0?-1:read(fd,value,sizeof(value)); if(fd>=0) close(fd);
    if(size!=37||value[36]!='\n') return -1;
    value[36]=0; if(!gate_boot_valid(value)) return -1;
    memcpy(text,value,37); return 0;
}
static int census(void) {
    if(geteuid()) return 2;
    int fd=open("/proc/device-tree/compatible",O_RDONLY|O_CLOEXEC); char model[512];
    ssize_t size=fd<0?-1:read(fd,model,sizeof(model)); if(fd>=0) close(fd);
    const char expected[]="yandex,station-midi"; int supported=0;
    for(ssize_t i=0;i+(ssize_t)sizeof(expected)<=size;++i)
        if((!i||!model[i-1])&&!memcmp(model+i,expected,sizeof(expected))) supported=1;
    char boot[37],end_boot[37]; unsigned before=0,after=0,count=0,unreadable=0;
    if(!supported||boot_id(boot)) return 3;
    int diag_error=udp_owner_snapshot(first,&before),diag_available=!diag_error;
    if(diag_error) {
        if(diag_error!=-ENOENT&&diag_error!=-EOPNOTSUPP&&diag_error!=-EPROTONOSUPPORT) return 3;
        if(udp_owner_proc_snapshot(first,&before)) return 3;
    }
    DIR *processes=opendir("/proc"); struct dirent *entry;
    if(!processes) return 3;
    for(;;) {
        errno=0; entry=readdir(processes);
        if(!entry) { if(errno) ++unreadable; break; }
        char *end; long pid=strtol(entry->d_name,&end,10);
        if(*end||pid<2||pid>INT_MAX) continue;
        struct process_stamp stamp; struct tcp_executable executable;
        if(process_stamp((pid_t)pid,&stamp)||stamp.state=='Z'||stamp.state=='X') continue;
        char path[64]; snprintf(path,sizeof(path),"/proc/%ld/fd",pid);
        DIR *fds=opendir(path); struct dirent *descriptor;
        if(!fds) { if(process_live((pid_t)pid,stamp.ticks)) ++unreadable; continue; }
        int exe_ok=!tcp_owner_executable((pid_t)pid,&executable); unsigned role=relay_role((pid_t)pid);
        for(;;) {
            errno=0; descriptor=readdir(fds);
            if(!descriptor) { if(errno) ++unreadable; break; }
            long number=strtol(descriptor->d_name,&end,10); uint64_t inode;
            if(*end||number<0||number>INT_MAX||tcp_owner_fd((pid_t)pid,(int)number,&inode)||
                !udp_owner_find(first,before,inode)) continue;
            if(count==UDP_HOLDER_LIMIT) { closedir(fds); closedir(processes); return 4; }
            struct holder *h=&holders[count++];
            *h=(struct holder){.pid=(pid_t)pid,.fd=(int)number,.ticks=stamp.ticks,.inode=inode,.role=role};
            if(exe_ok) { h->exe=executable; h->confirmed=udp_owner_holder(h->pid,h->fd,h->ticks,&h->exe,inode); }
        }
        closedir(fds);
    }
    closedir(processes);
    if((diag_available?udp_owner_snapshot(last,&after):udp_owner_proc_snapshot(last,&after))||boot_id(end_boot)) return 4;
    printf("{\"event\":\"udp-evidence-start\",\"boot_id\":\"%s\",\"diag_available\":%s,\"diag_error\":%d}\n",boot,diag_available?"true":"false",diag_error);
    unsigned stable=0,confirmed=0;
    for(unsigned i=0;i<before;++i) {
        struct udp_owner *row=&first[i],*later=udp_owner_find(last,after,row->value.idiag_inode);
        int same=later&&udp_owner_same(row,later); stable+=same;
        struct inet_diag_msg *v=&row->value; char local[INET6_ADDRSTRLEN],remote[INET6_ADDRSTRLEN],receive[32],write[32],interface[32];
        if(diag_available) {
            snprintf(receive,sizeof(receive),"%u",v->idiag_rqueue); snprintf(write,sizeof(write),"%u",v->idiag_wqueue);
            snprintf(interface,sizeof(interface),"%u",v->id.idiag_if);
        } else { strcpy(receive,"null"); strcpy(write,"null"); strcpy(interface,"null"); }
        if(!inet_ntop(v->idiag_family,v->id.idiag_src,local,sizeof(local))||
            !inet_ntop(v->idiag_family,v->id.idiag_dst,remote,sizeof(remote))) return 4;
        printf("{\"event\":\"udp-socket\",\"inode\":%u,\"family\":%u,\"state\":%u,\"uid\":%u,"
            "\"local\":{\"address\":\"%s\",\"port\":%u},\"remote\":{\"address\":\"%s\",\"port\":%u},"
            "\"interface\":%s,\"cookie\":[%u,%u],\"v6only\":%s,\"receive_queue\":%s,\"write_queue\":%s,\"stable\":%s}\n",
            v->idiag_inode,v->idiag_family==AF_INET?4:6,v->idiag_state,v->idiag_uid,local,ntohs(v->id.idiag_sport),
            remote,ntohs(v->id.idiag_dport),interface,v->id.idiag_cookie[0],v->id.idiag_cookie[1],
            row->v6only<0?"null":row->v6only?"true":"false",receive,write,same?"true":"false");
    }
    for(unsigned i=0;i<count;++i) {
        struct holder *h=&holders[i]; struct udp_owner *a=udp_owner_find(first,before,h->inode),*b=udp_owner_find(last,after,h->inode);
        int ok=h->confirmed&&a&&b&&udp_owner_same(a,b)&&udp_owner_holder(h->pid,h->fd,h->ticks,&h->exe,h->inode)&&relay_role(h->pid)==h->role;
        confirmed+=ok;
        printf("{\"event\":\"udp-holder\",\"pid\":%ld,\"descriptor\":%d,\"start_ticks\":%" PRIu64 ","
            "\"exe_device\":%" PRIu64 ",\"exe_inode\":%" PRIu64 ",\"inode\":%" PRIu64 ",\"role\":\"%s\",\"confirmed\":%s}\n",
            (long)h->pid,h->fd,h->ticks,(uint64_t)h->exe.device,(uint64_t)h->exe.inode,h->inode,relay_role_name(h->role),ok?"true":"false");
    }
    int same_boot=!strcmp(boot,end_boot);
    printf("{\"event\":\"udp-evidence-summary\",\"sockets\":%u,\"stable_sockets\":%u,\"holders\":%u,\"confirmed_holders\":%u,"
        "\"unreadable\":%u,\"boot_stable\":%s,\"atomic_snapshot\":false,\"payload_read\":false,\"apply_supported\":false}\n",
        before,stable,count,confirmed,unreadable,same_boot?"true":"false");
    return same_boot?0:4;
}
static unsigned checks;
#define CHECK(label,condition) do { ++checks; if(!(condition)) { fprintf(stderr,"failed:%s:%u\n",label,checks); return 4; } } while(0)
static int selftest(void) {
    int diag_available=1,diag_error=0;
    for(unsigned index=0;index<5;++index) {
        int family=index<2?AF_INET:AF_INET6,connected=index==1||index==4,only=index==2;
        int fd=socket(family,SOCK_DGRAM|SOCK_CLOEXEC,0),peer=socket(family,SOCK_DGRAM|SOCK_CLOEXEC,0);
        CHECK("own_sockets",fd>=0&&peer>=0);
        if(family==AF_INET6) CHECK("v6_mode",!setsockopt(fd,IPPROTO_IPV6,IPV6_V6ONLY,&only,sizeof(only)));
        struct sockaddr_storage address={0}; socklen_t length;
        if(family==AF_INET) { struct sockaddr_in *a=(struct sockaddr_in*)&address; a->sin_family=AF_INET; a->sin_addr.s_addr=htonl(INADDR_LOOPBACK); length=sizeof(*a); }
        else { struct sockaddr_in6 *a=(struct sockaddr_in6*)&address; a->sin6_family=AF_INET6; a->sin6_addr=in6addr_loopback; length=sizeof(*a); }
        CHECK("own_bind",!bind(fd,(struct sockaddr*)&address,length)&&!bind(peer,(struct sockaddr*)&address,length));
        CHECK("peer_metadata",!getsockname(peer,(struct sockaddr*)&address,&length));
        if(connected) CHECK("own_connect",!connect(fd,(struct sockaddr*)&address,length));
        struct stat info; unsigned count; struct process_stamp stamp; struct tcp_executable executable;
        CHECK("own_identity",!fstat(fd,&info)&&!process_stamp(getpid(),&stamp)&&!tcp_owner_executable(getpid(),&executable));
        int snapshot=udp_owner_snapshot(first,&count);
        if(snapshot) {
            CHECK("explicit_missing_diag",snapshot==-ENOENT||snapshot==-EOPNOTSUPP||snapshot==-EPROTONOSUPPORT);
            diag_available=0; diag_error=snapshot;
            CHECK("proc_fallback",!udp_owner_proc_snapshot(first,&count));
        }
        CHECK("dump_or_explicit_fallback",!snapshot||!diag_available);
        struct udp_owner *row=udp_owner_find(first,count,info.st_ino);
        CHECK("cookie_and_state",row&&row->value.idiag_state==(unsigned)(connected?1:7));
        if(!connected&&family==AF_INET6) {
            int effective=-1; socklen_t option_length=sizeof(effective);
            CHECK("effective_v6_mode",!getsockopt(fd,IPPROTO_IPV6,IPV6_V6ONLY,&effective,&option_length)&&option_length==sizeof(effective));
            CHECK("v6only_not_invented",row->v6only==-1||row->v6only==effective);
        }
        CHECK("cookie_capability",(row->value.id.idiag_cookie[0]==UINT32_MAX&&row->value.id.idiag_cookie[1]==UINT32_MAX)==!diag_available);
        CHECK("holder",udp_owner_holder(getpid(),fd,stamp.ticks,&executable,info.st_ino));
        CHECK("wrong_ticks",!udp_owner_holder(getpid(),fd,stamp.ticks+1,&executable,info.st_ino));
        struct tcp_executable wrong=executable; ++wrong.inode;
        CHECK("wrong_executable",!udp_owner_holder(getpid(),fd,stamp.ticks,&wrong,info.st_ino));
        CHECK("wrong_inode",!udp_owner_holder(getpid(),fd,stamp.ticks,&executable,info.st_ino+1));
        unsigned after; CHECK("second_dump",!(diag_available?udp_owner_snapshot(last,&after):udp_owner_proc_snapshot(last,&after)));
        struct udp_owner *later=udp_owner_find(last,after,info.st_ino);
        CHECK("stable_cookie",later&&udp_owner_same(row,later));
        struct udp_owner changed=*row; changed.value.id.idiag_cookie[0]^=1;
        CHECK("cookie_reuse",!udp_owner_same(row,&changed));
        changed=*row; changed.value.id.idiag_dport^=htons(1);
        CHECK("reconnected",!udp_owner_same(row,&changed));
        int alias=dup(fd); CHECK("shared_descriptor",alias>=0&&udp_owner_holder(getpid(),alias,stamp.ticks,&executable,info.st_ino));
        close(alias); close(fd);
        int null=open("/dev/null",O_RDONLY|O_CLOEXEC);
        CHECK("fd_reuse",null>=0&&dup2(null,fd)==fd&&!udp_owner_holder(getpid(),fd,stamp.ticks,&executable,info.st_ino));
        if(null!=fd) close(null);
        close(fd); close(peer);
    }
    struct { struct nlmsghdr header; struct inet_diag_msg value; unsigned char attrs[16]; } fixture={
        .header={.nlmsg_type=SOCK_DIAG_BY_FAMILY,.nlmsg_len=NLMSG_LENGTH(sizeof(struct inet_diag_msg))},
        .value={.idiag_family=AF_INET,.idiag_state=7,.idiag_inode=100,.id={.idiag_sport=htons(40000),.idiag_cookie={1,2}}}};
    struct udp_owner row; CHECK("valid_fixture",!udp_owner_parse(&fixture.header,&row));
    fixture.value.id.idiag_cookie[0]=fixture.value.id.idiag_cookie[1]=UINT32_MAX;
    CHECK("missing_cookie",udp_owner_parse(&fixture.header,&row)<0);
    fixture.value.id.idiag_cookie[0]=1; fixture.value.id.idiag_dport=htons(5);
    CHECK("unconnected_peer",udp_owner_parse(&fixture.header,&row)<0);
    fixture.value.id.idiag_dport=0; fixture.header.nlmsg_len++;
    CHECK("malformed_attribute",udp_owner_parse(&fixture.header,&row)<0);
    printf("{\"selftest\":\"udp-evidence\",\"checks\":%u,\"ok\":true,\"diag_available\":%s,\"diag_error\":%d,\"payload_read\":false,\"vendor_processes_changed\":false}\n",checks,diag_available?"true":"false",diag_error);
    return 0;
}
int main(int argc,char **argv) {
    if(argc!=2) return 2;
    alarm(25);
    if(!strcmp(argv[1],"--selftest")) return selftest();
    if(!strcmp(argv[1],"--read-only-census")) return census();
    return 2;
}
