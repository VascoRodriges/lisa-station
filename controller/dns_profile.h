/* Accept only the numeric-forwarder profile emitted by service_profiles.py.
 * An arbitrary root config is not an instruction to expose files or services. */
#ifndef LISA_DNS_PROFILE_H
#define LISA_DNS_PROFILE_H
#include <arpa/inet.h>
#include "network_guard.h"

static inline int dns_profile_prefix(char *text,size_t capacity,const char *runtime,unsigned port) {
    int size=snprintf(text,capacity,
        "server:\n    interface: \"127.0.0.1\"\n    interface: \"::1\"\n    port: %u\n"
        "    username: \"\"\n    chroot: \"\"\n    directory: \"%s\"\n    pidfile: \"%s/unbound.pid\"\n"
        "    do-ip4: yes\n    do-ip6: yes\n    do-udp: yes\n    do-tcp: yes\n    so-reuseport: no\n"
        "    module-config: \"iterator\"\n    use-syslog: no\n    verbosity: 0\n"
        "    log-queries: no\n    log-replies: no\n    hide-identity: yes\n    hide-version: yes\n"
        "    msg-cache-size: 2m\n    rrset-cache-size: 2m\nremote-control:\n    control-enable: no\n"
        "forward-zone:\n    name: \".\"\n    forward-first: no\n",port,runtime,runtime);
    return size<0||(size_t)size>=capacity?-1:size;
}
static inline int dns_profile_address(const char *text,int *family,unsigned char bytes[16]) {
    memset(bytes,0,16);char canonical[INET6_ADDRSTRLEN];
    if(inet_pton(AF_INET,text,bytes)==1){
        uint32_t value;memcpy(&value,bytes,4);value=ntohl(value);*family=AF_INET;
        if(!value||value==UINT32_MAX||(value>>24)==127||(value>>28)==14||(value>>16)==0xa9fe)return -1;
    }else if(inet_pton(AF_INET6,text,bytes)==1){
        struct in6_addr address;memcpy(&address,bytes,16);*family=AF_INET6;
        if(IN6_IS_ADDR_UNSPECIFIED(&address)||IN6_IS_ADDR_LOOPBACK(&address)||IN6_IS_ADDR_MULTICAST(&address)||
            IN6_IS_ADDR_LINKLOCAL(&address)||IN6_IS_ADDR_V4MAPPED(&address))return -1;
    }else return -1;
    return inet_ntop(*family,bytes,canonical,sizeof(canonical))&&!strcmp(text,canonical)?0:-1;
}
static inline int dns_profile_validate(const char *text,const char *runtime,int laboratory,unsigned *port) {
    const char first[]="server:\n    interface: \"127.0.0.1\"\n    interface: \"::1\"\n    port: ";
    if(!text||!runtime||strncmp(text,first,sizeof(first)-1)||strlen(text)>=16384)return -1;
    unsigned parsed;int consumed=0;
    if(sscanf(text+sizeof(first)-1,"%u\n%n",&parsed,&consumed)!=1||consumed<1||
        (parsed!=53&&(!laboratory||parsed<1024||parsed>65535)))return -1;
    char expected[12288];int prefix=dns_profile_prefix(expected,sizeof(expected),runtime,parsed);
    if(prefix<0||strncmp(text,expected,(size_t)prefix))return -1;
    const char *line=text+prefix,*marker="    forward-addr: \"";unsigned count=0;int families[4];unsigned char servers[4][16];
    while(*line){
        if(count==4||strncmp(line,marker,strlen(marker)))return -1;
        line+=strlen(marker);const char *end=strchr(line,'"');char address[INET6_ADDRSTRLEN];
        if(!end||end[1]!='\n'||end==line||(size_t)(end-line)>=sizeof(address))return -1;
        memcpy(address,line,(size_t)(end-line));address[end-line]=0;
        if(dns_profile_address(address,&families[count],servers[count]))return -1;
        for(unsigned i=0;i<count;++i)if(families[i]==families[count]&&!memcmp(servers[i],servers[count],16))return -1;
        ++count;line=end+2;
    }
    if(!count)return -1;
    *port=parsed;return 0;
}
static inline int dns_profile_read(int directory,const char *name,const char *runtime,int lab,unsigned *port) {
    int fd=openat(directory,name,O_RDONLY|O_NOFOLLOW|O_NONBLOCK|O_CLOEXEC);
    if(fd<0)return -1;
    size_t used=0;int failed=!store_file_valid(fd,0);
    while(!failed&&used<sizeof(network_dns_profile)-1){
        ssize_t bytes=read(fd,network_dns_profile+used,sizeof(network_dns_profile)-1-used);
        if(bytes<0&&errno==EINTR)continue;
        if(bytes<0){failed=1;break;}if(!bytes)break;used+=(size_t)bytes;
    }
    if(close(fd))failed=1;
    network_dns_profile[used]=0;
    return failed||!used||used==sizeof(network_dns_profile)-1||memchr(network_dns_profile,0,used)?-1:
        dns_profile_validate(network_dns_profile,runtime,lab,port);
}
#endif
