/* Root metadata-only census and unprivileged own-loopback self-test. No payload
 * reads, SOCK_DESTROY, process signals, firewall changes or arbitrary targets. */
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <ifaddrs.h>
#include <net/if.h>
#include "tcp_owner.h"
#include "loopback_socket.h"
#include "relay_resources.h"

static const char *role(pid_t pid) {
    const char *executables[]={"/system/vendor/quasar/maind","/system/vendor/quasar/quasar_launcher2",
        "/usr/bin/alsa-audio-monitord","/usr/sbin/unbound","/usr/sbin/chronyd"};
    const char *names[]={"vendor-worker","vendor-launcher","audio-diagnostics","dns","time"};
    for(unsigned i=0;i<5;++i) if(relay_executable_is(pid,executables[i])==1) return names[i];
    char path[64],executable[PATH_MAX]; snprintf(path,sizeof(path),"/proc/%ld/exe",(long)pid);
    ssize_t size=readlink(path,executable,sizeof(executable)-1);
    if(size<0 || size>=(ssize_t)sizeof(executable)-1) return "unknown";
    executable[size]=0;
    if(!strcmp(executable,"/system/vendor/quasar/maind")) return "vendor-worker";
    if(!strcmp(executable,"/system/vendor/quasar/quasar_launcher2")) return "vendor-launcher";
    if(!strncmp(executable,"/system/vendor/quasar/",22)) return "vendor-helper";
    if(!strcmp(executable,"/usr/bin/alsa-audio-monitord")) return "audio-diagnostics";
    if(!strcmp(executable,"/usr/sbin/unbound")) return "dns";
    if(!strcmp(executable,"/usr/sbin/chronyd")) return "time";
    return "other";
}
static int current_boot(char boot[37]) {
    char text[38]; int file=open("/proc/sys/kernel/random/boot_id",O_RDONLY|O_CLOEXEC);
    if(file<0) return -1;
    ssize_t size=read(file,text,sizeof(text)); close(file);
    if(size!=37 || text[36]!='\n') return -1;
    text[36]=0; if(!gate_boot_valid(text)) return -1;
    memcpy(boot,text,37); return 0;
}
static int census(void) {
    if(geteuid()) return 2;
    int device=open("/proc/device-tree/compatible",O_RDONLY|O_CLOEXEC); char model[512];
    ssize_t size=device>=0?read(device,model,sizeof(model)):-1; if(device>=0) close(device);
    int supported=0; const char expected[]="yandex,station-midi";
    for(ssize_t i=0;i+(ssize_t)sizeof(expected)<=size;++i)
        if((!i||!model[i-1])&&!memcmp(model+i,expected,sizeof(expected))) supported=1;
    if(!supported) return 3;
    char boot[37],end_boot[37]; struct tcp_owner_row rows[TCP_OWNER_LIMIT]; unsigned count;
    if(current_boot(boot) || tcp_owner_tables(rows,&count)) return 3;
    printf("{\"event\":\"tcp-evidence-start\",\"boot_id\":\"%s\"}\n",boot);
    struct ifaddrs *addresses;
    if(getifaddrs(&addresses)) return 3;
    for(struct ifaddrs *at=addresses;at;at=at->ifa_next) {
        if(!at->ifa_addr || !(at->ifa_flags&IFF_UP)) continue;
        int family=at->ifa_addr->sa_family;
        if(family!=AF_INET&&family!=AF_INET6) continue;
        void *value=family==AF_INET?(void*)&((struct sockaddr_in*)at->ifa_addr)->sin_addr:
            (void*)&((struct sockaddr_in6*)at->ifa_addr)->sin6_addr;
        char text[INET6_ADDRSTRLEN];
        if(!inet_ntop(family,value,text,sizeof(text))) { freeifaddrs(addresses); return 3; }
        printf("{\"event\":\"host-address\",\"family\":%u,\"address\":\"%s\"}\n",family==AF_INET?4:6,text);
    }
    freeifaddrs(addresses);
    unsigned observations=0,confirmed=0,unreadable=0; DIR *processes=opendir("/proc");
    if(!processes) return 3;
    struct dirent *entry;
    for(;;) {
        errno=0; entry=readdir(processes);
        if(!entry) { if(errno) ++unreadable; break; }
        char *end; long number=strtol(entry->d_name,&end,10);
        if(*end || number<2 || number>INT_MAX) continue;
        pid_t pid=(pid_t)number; struct process_stamp stamp;
        if(process_stamp(pid,&stamp) || stamp.state=='Z' || stamp.state=='X') continue;
        char path[64]; snprintf(path,sizeof(path),"/proc/%ld/fd",number);
        DIR *descriptors=opendir(path);
        if(!descriptors) { if(process_live(pid,stamp.ticks)) ++unreadable; continue; }
        struct tcp_executable executable; int executable_ok=!tcp_owner_executable(pid,&executable);
        const char *name=role(pid); struct dirent *descriptor;
        for(;;) {
            errno=0; descriptor=readdir(descriptors);
            if(!descriptor) { if(errno) ++unreadable; break; }
            long fd=strtol(descriptor->d_name,&end,10);
            if(*end || fd<0 || fd>INT_MAX) continue;
            uint64_t inode;
            if(tcp_owner_fd(pid,(int)fd,&inode)) continue;
            for(unsigned i=0;i<count;++i) {
                struct tcp_owner_row *row=&rows[i];
                if(row->inode!=inode || row->state!=1 || !row->id.idiag_dport) continue;
                if(++observations>4096) { closedir(descriptors); closedir(processes); return 4; }
                struct inet_diag_msg found={0};
                int ok=executable_ok&&!tcp_owner_confirm(pid,(int)fd,stamp.ticks,&executable,row,&found);
                confirmed+=ok;
                char source[INET6_ADDRSTRLEN],destination[INET6_ADDRSTRLEN];
                if(!inet_ntop(row->family,row->id.idiag_src,source,sizeof(source)) ||
                    !inet_ntop(row->family,row->id.idiag_dst,destination,sizeof(destination))) return 4;
                printf("{\"event\":\"tcp-owner-evidence\",\"pid\":%ld,\"start_ticks\":%" PRIu64 ",\"descriptor\":%ld,"
                    "\"role\":\"%s\",\"inode\":%" PRIu64 ",\"family\":%u,\"local\":{\"address\":\"%s\",\"port\":%u},"
                    "\"remote\":{\"address\":\"%s\",\"port\":%u},\"uid\":%u,\"interface\":%u,\"cookie\":[%u,%u],\"confirmed\":%s}\n",
                    number,stamp.ticks,fd,name,inode,row->family==AF_INET?4:6,source,ntohs(row->id.idiag_sport),destination,
                    ntohs(row->id.idiag_dport),row->uid,found.id.idiag_if,found.id.idiag_cookie[0],found.id.idiag_cookie[1],ok?"true":"false");
            }
        }
        closedir(descriptors);
    }
    closedir(processes);
    int stable=!current_boot(end_boot)&&!strcmp(boot,end_boot);
    printf("{\"event\":\"tcp-evidence-summary\",\"observations\":%u,\"confirmed\":%u,\"unreadable\":%u,"
        "\"boot_stable\":%s,\"atomic_snapshot\":false,\"audio_opened\":false,\"apply_supported\":false}\n",
        observations,confirmed,unreadable,stable?"true":"false");
    return stable?0:4;
}
static unsigned checks,failed;
static int check(const char *name,unsigned index,int ok) {
    ++checks; failed+=!ok;
    if(!ok) fprintf(stderr,"failed:%s:%u\n",name,index);
    return ok;
}
static int selftest(void) {
    struct tcp_owner_row rows[TCP_OWNER_LIMIT]; unsigned count;
    for(unsigned index=0;index<3;++index) {
        struct pair target={-1,-1},control={-1,-1}; int family=index?AF_INET6:AF_INET,mapped=index==2;
        if(!check("own_loopback_baseline",index,!make_pair(family,mapped,&target)&&!make_pair(family,mapped,&control)&&
            exchange(&target)&&exchange(&control))) return 4;
        struct stat info; struct process_stamp stamp; struct tcp_executable executable;
        if(!check("own_metadata",index,!fstat(target.client,&info)&&!process_stamp(getpid(),&stamp)&&
            !tcp_owner_executable(getpid(),&executable)&&!tcp_owner_tables(rows,&count))) return 4;
        struct tcp_owner_row *row=NULL;
        for(unsigned i=0;i<count;++i) if(rows[i].inode==info.st_ino) row=&rows[i];
        struct inet_diag_msg found;
        if(!check("confirmed_fd_cookie",index,row&&!tcp_owner_confirm(getpid(),target.client,stamp.ticks,&executable,row,&found)&&
            found.idiag_inode==info.st_ino)) return 4;
        if(!check("wrong_start_ticks_denied",index,tcp_owner_confirm(getpid(),target.client,stamp.ticks+1,&executable,row,&found)<0)) return 4;
        struct tcp_executable wrong=executable; ++wrong.inode;
        if(!check("wrong_executable_denied",index,tcp_owner_confirm(getpid(),target.client,stamp.ticks,&wrong,row,&found)<0)) return 4;
        struct tcp_owner_row wrong_row=*row; ++wrong_row.inode;
        if(!check("wrong_inode_denied",index,tcp_owner_confirm(getpid(),target.client,stamp.ticks,&executable,&wrong_row,&found)<0)) return 4;
        wrong_row=*row; wrong_row.uid^=1;
        if(!check("wrong_socket_uid_denied",index,tcp_owner_confirm(getpid(),target.client,stamp.ticks,&executable,&wrong_row,&found)<0)) return 4;
        wrong_row=*row; wrong_row.id.idiag_sport=0;
        if(!check("missing_port_denied",index,tcp_owner_confirm(getpid(),target.client,stamp.ticks,&executable,&wrong_row,&found)<0)) return 4;
        wrong_row=*row; wrong_row.id.idiag_dport=htons((uint16_t)(ntohs(row->id.idiag_dport)==65535?1:65535));
        if(!check("wrong_tuple_denied",index,tcp_owner_confirm(getpid(),target.client,stamp.ticks,&executable,&wrong_row,&found)<0)) return 4;
        int stale=target.client; close(stale); target.client=-1;
        int null=open("/dev/null",O_RDONLY|O_CLOEXEC);
        if(!check("descriptor_reuse_denied",index,null>=0&&dup2(null,stale)==stale&&
            tcp_owner_confirm(getpid(),stale,stamp.ticks,&executable,row,&found)<0&&exchange(&control))) return 4;
        if(null!=stale) close(null);
        close(stale); close(target.peer); close(control.client); close(control.peer);
    }
    const char *malformed[]={
        "0: 0100007F:1234 0100007F:1235 01 0:0 00:0 0 -1 0 300\n",
        "0: 0100007F:1234 0100007F:1235 01 0:0 00:0 0 0 0 -1\n",
        "X: 0100007F:1234 0100007F:1235 01 0:0 00:0 0 0 0 300\n",
        "0: 0100007G:1234 0100007F:1235 01 0:0 00:0 0 0 0 300\n",
    };
    for(unsigned i=0;i<sizeof(malformed)/sizeof(malformed[0]);++i)
        if(!check("malformed_metadata_denied",i,tcp_owner_parse(malformed[i],AF_INET,&rows[0])<0)) return 4;
    printf("{\"selftest\":\"tcp-evidence\",\"checks\":%u,\"ok\":true,\"audio_opened\":false,\"vendor_processes_changed\":false}\n",checks);
    return failed?4:0;
}
int main(int argc,char **argv) {
    if(argc!=2) return 2;
    alarm(25);
    if(!strcmp(argv[1],"--selftest")) return selftest();
    if(!strcmp(argv[1],"--read-only-census")) return census();
    return 2;
}
