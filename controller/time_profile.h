/* Canonical client-only clock configuration, independent of stock providers. */
#ifndef LISA_TIME_PROFILE_H
#define LISA_TIME_PROFILE_H
#include "dns_profile.h"
#include "time_guard.h"
static inline int time_profile_validate(const char *text,const char *runtime,const char *drift) {
    if(!text||strlen(text)>=sizeof(time_profile))return -1;
    const char *line=text;unsigned count=0;int families[4];unsigned char servers[4][16];
    while(!strncmp(line,"server ",7)){
        if(count==4)return -1;
        line+=7;const char *end=strchr(line,' ');char address[INET6_ADDRSTRLEN];
        if(!end||end==line||(size_t)(end-line)>=sizeof(address)||strncmp(end," iburst\n",8))return -1;
        memcpy(address,line,(size_t)(end-line));address[end-line]=0;
        if(dns_profile_address(address,&families[count],servers[count]))return -1;
        for(unsigned i=0;i<count;++i)if(families[i]==families[count]&&!memcmp(servers[i],servers[count],16))return -1;
        ++count;line=end+8;
    }
    char expected[3*PATH_MAX];
    int size=snprintf(expected,sizeof(expected),"pidfile %s/chronyd.pid\nport 0\ncmdport 0\nbindcmdaddress /\n"
        "driftfile %s/drift\nmakestep 1.0 3\nrtcsync\n",runtime,drift);
    return !count||size<0||(size_t)size>=sizeof(expected)||strcmp(line,expected)?-1:0;
}
static inline int time_profile_read(int directory,const char *runtime,const char *drift) {
    int fd=openat(directory,"time.profile",O_RDONLY|O_NOFOLLOW|O_NONBLOCK|O_CLOEXEC);
    if(fd<0)return -1;
    size_t used=0;int failed=!store_file_valid(fd,0);
    while(!failed&&used<sizeof(time_profile)-1){
        ssize_t size=read(fd,time_profile+used,sizeof(time_profile)-1-used);
        if(size<0&&errno==EINTR)continue;
        if(size<0){failed=1;break;}if(!size)break;used+=(size_t)size;
    }
    if(close(fd))failed=1;
    time_profile[used]=0;
    return failed||!used||used==sizeof(time_profile)-1||memchr(time_profile,0,used)?-1:time_profile_validate(time_profile,runtime,drift);
}
#endif
