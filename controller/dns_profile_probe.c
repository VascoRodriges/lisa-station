/* Configuration boundary and own-child kernel checks. No service replacement. */
#define _GNU_SOURCE
#include "network_service.h"
static unsigned checks;
#define CHECK(x) do{++checks;if(!(x)){fprintf(stderr,"check %u line %d: %s\n",checks,__LINE__,#x);return 1;}}while(0)
static int profile(char *text,size_t capacity,const char *runtime,unsigned port,const char *servers) {
    int size=dns_profile_prefix(text,capacity,runtime,port);
    return size<0||strlen(servers)>=capacity-(size_t)size?-1:(strcpy(text+size,servers),0);
}
static int filter_child(void) {
    if(prctl(PR_SET_NO_NEW_PRIVS,1,0,0,0)||network_dns_filter())return 1;
    const int allowed[]={AF_INET,AF_INET6};
    for(unsigned i=0;i<2;++i){int fd=socket(allowed[i],SOCK_DGRAM|SOCK_CLOEXEC,0);if(fd<0)return 2;close(fd);}
    int fd=socket(AF_NETLINK,SOCK_RAW|SOCK_CLOEXEC,NETLINK_ROUTE);if(fd<0)return 3;close(fd);
    errno=0;if(socket(AF_NETLINK,SOCK_RAW,NETLINK_USERSOCK)!=-1||errno!=EPERM)return 4;
    errno=0;if(socket(AF_UNIX,SOCK_STREAM,0)!=-1||errno!=EPERM)return 5;
    errno=0;if(socket(AF_PACKET,SOCK_RAW,0)!=-1||errno!=EPERM)return 6;
    errno=0;if(syscall(SYS_fork)!=-1||errno!=EPERM)return 7;
    errno=0;if(setgid(getgid())!=-1||errno!=EPERM)return 8;
    errno=0;if(syscall(SYS_clock_settime,CLOCK_REALTIME,NULL)!=-1||errno!=EPERM)return 9;
    errno=0;if(kill(getppid(),0)!=-1||errno!=EPERM)return 10;
    if(kill(getpid(),0))return 11;
    return 0;
}
int main(int argc,char **argv) {
    if(argc==3&&!strcmp(argv[1],"--query-local")){
        char *end;unsigned long port=strtoul(argv[2],&end,10);
        if(*end||!argv[2][0]||(port!=53&&(port<1024||port>65535)))return 2;
        network_dns_port=(unsigned)port;
        return network_dns_local_query(AF_INET)&&network_dns_local_query(AF_INET6)?0:3;
    }
    if(argc==2&&!strcmp(argv[1],"--validate-production")){
        char text[16384];size_t size=fread(text,1,sizeof(text)-1,stdin);
        if(ferror(stdin)||!feof(stdin)||memchr(text,0,size))return 2;
        text[size]=0;unsigned port;return dns_profile_validate(text,"/run/lisa-station-net/dns",0,&port)?3:0;
    }
    if(argc!=1)return 2;
    unsigned char question[16]={1,2,1,0,0,1},answer[32]={1,2,0x81,0x80,0,1,0,1};
    CHECK(network_dns_reply_valid(question,sizeof(question),answer,sizeof(answer)));
    answer[2]|=4;CHECK(network_dns_reply_valid(question,sizeof(question),answer,sizeof(answer)));
    answer[2]|=2;CHECK(!network_dns_reply_valid(question,sizeof(question),answer,sizeof(answer)));answer[2]&=~2;
    answer[2]|=8;CHECK(!network_dns_reply_valid(question,sizeof(question),answer,sizeof(answer)));answer[2]&=~8;
    answer[2]&=~0x80;CHECK(!network_dns_reply_valid(question,sizeof(question),answer,sizeof(answer)));answer[2]|=0x80;
    answer[0]=3;CHECK(!network_dns_reply_valid(question,sizeof(question),answer,sizeof(answer)));answer[0]=1;
    answer[3]|=3;CHECK(!network_dns_reply_valid(question,sizeof(question),answer,sizeof(answer)));answer[3]&=~3;
    CHECK(!network_dns_reply_valid(question,sizeof(question),answer,10));
    const char runtime[]="/run/lisa-station-net/dns";char text[16384],bad[16384];unsigned port=0;
    CHECK(!profile(text,sizeof(text),runtime,53,"    forward-addr: \"203.0.113.1\"\n    forward-addr: \"2001:db8::1\"\n"));
    CHECK(!dns_profile_validate(text,runtime,0,&port)&&port==53);
    CHECK(dns_profile_validate(text,"/run/lisa-station",0,&port));
    const char *invalid[]={"","    forward-addr: \"127.0.0.1\"\n","    forward-addr: \"::1\"\n",
        "    forward-addr: \"0.0.0.0\"\n","    forward-addr: \"::\"\n","    forward-addr: \"255.255.255.255\"\n",
        "    forward-addr: \"224.0.0.1\"\n","    forward-addr: \"ff02::1\"\n","    forward-addr: \"fe80::1\"\n",
        "    forward-addr: \"169.254.1.1\"\n","    forward-addr: \"::ffff:203.0.113.1\"\n",
        "    forward-addr: \"2001:0db8::1\"\n","    forward-addr: \"resolver.example\"\n",
        "    forward-addr: \"203.0.113.1@555\"\n","    forward-addr: \"203.0.113.1\"\n    forward-addr: \"203.0.113.1\"\n",
        "    forward-addr: \"203.0.113.1\"\ninclude: /etc/other\n","    forward-addr: \"203.0.113.1\"",
        "    forward-addr: \"203.0.113.1\"\n\n"};
    for(unsigned i=0;i<sizeof(invalid)/sizeof(invalid[0]);++i){CHECK(!profile(bad,sizeof(bad),runtime,53,invalid[i]));CHECK(dns_profile_validate(bad,runtime,0,&port));}
    strcpy(bad,text);char *logging=strstr(bad,"log-queries: no");CHECK(logging!=NULL);logging[13]='y';CHECK(dns_profile_validate(bad,runtime,0,&port));
    CHECK(!profile(bad,sizeof(bad),runtime,25053,"    forward-addr: \"203.0.113.1\"\n"));
    CHECK(dns_profile_validate(bad,runtime,0,&port));CHECK(!dns_profile_validate(bad,runtime,1,&port)&&port==25053);
    pid_t child=fork();CHECK(child>=0);if(!child)_exit(filter_child());int status;
    CHECK(waitpid(child,&status,0)==child);CHECK(WIFEXITED(status)&&!WEXITSTATUS(status));
    printf("{\"selftest\":\"dns-profile\",\"checks\":%u,\"ok\":true,\"services_changed\":false}\n",checks);return 0;
}
