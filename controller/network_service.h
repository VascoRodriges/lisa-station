/* Fixed independent DNS service. No stock service stop, vendor permit or mode
 * transition here. A missing/malformed profile never starts an alternate one. */
#ifndef LISA_NETWORK_SERVICE_H
#define LISA_NETWORK_SERVICE_H
#include "dns_profile.h"
static unsigned network_dns_port;

static inline int network_role_directory(const char *parent,const char *name,uid_t owner,mode_t mode) {
    int base=open(parent,O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC);struct stat info;
    if(base<0)return -1;
    if(fstat(base,&info)||!S_ISDIR(info.st_mode)||info.st_uid||(info.st_mode&0022)){close(base);return -1;}
    int created=!mkdirat(base,name,mode);
    if(!created&&errno!=EEXIST){close(base);return -1;}
    int fd=openat(base,name,O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC);close(base);
    if(fd<0)return -1;
    int failed=created&&(fchown(fd,owner,owner)||fchmod(fd,mode));
    if(!failed&&(fstat(fd,&info)||!S_ISDIR(info.st_mode)||info.st_uid!=owner||info.st_gid!=owner||
        (info.st_mode&07777)!=mode))failed=1;
    if(close(fd))failed=1;
    return failed?-1:0;
}
static inline int network_dns_reply_valid(const unsigned char *question,size_t question_size,const unsigned char *answer,ssize_t size) {
    return question_size>=12&&size>(ssize_t)question_size&&!memcmp(answer,question,2)&&(answer[2]&0xfa)==0x80&&
        !(answer[3]&15)&&!answer[4]&&answer[5]==1&&(answer[6]||answer[7])&&
        !memcmp(answer+12,question+12,question_size-12);
}
static inline int network_dns_local_query(int family) {
    unsigned char question[]={0,0,1,0,0,1,0,0,0,0,0,0,9,'l','o','c','a','l','h','o','s','t',0,0,1,0,1};
    uint64_t nonce;if(boot_ledger_nonce(&nonce))return 0;memcpy(question,&nonce,2);
    int fd=socket(family,SOCK_DGRAM|SOCK_CLOEXEC,0);if(fd<0)return 0;
    struct timeval limit={0,150000};struct sockaddr_storage address={0};socklen_t length;
    if(family==AF_INET){struct sockaddr_in *a=(void*)&address;a->sin_family=AF_INET;a->sin_port=htons(network_dns_port);
        a->sin_addr.s_addr=htonl(INADDR_LOOPBACK);length=sizeof(*a);
    }else{struct sockaddr_in6 *a=(void*)&address;a->sin6_family=AF_INET6;a->sin6_port=htons(network_dns_port);
        a->sin6_addr=in6addr_loopback;length=sizeof(*a);}
    unsigned char answer[512];int ok=0;
    if(setsockopt(fd,SOL_SOCKET,SO_RCVTIMEO,&limit,sizeof(limit))||setsockopt(fd,SOL_SOCKET,SO_SNDTIMEO,&limit,sizeof(limit))||
        connect(fd,(struct sockaddr*)&address,length)||send(fd,question,sizeof(question),MSG_NOSIGNAL)!=(ssize_t)sizeof(question))goto done;
    ssize_t size=recv(fd,answer,sizeof(answer),0);
    ok=network_dns_reply_valid(question,sizeof(question),answer,size);
done:close(fd);return ok;
}
/* This kernel has no UDP_DIAG. Match each bound endpoint to a current socket
 * FD of this child; a reply from another resolver is not startup evidence. */
static inline int network_dns_listeners(pid_t pid) {
    char path[128];snprintf(path,sizeof(path),"/proc/%ld/fd",(long)pid);
    DIR *directory=opendir(path);if(!directory)return 0;
    uint64_t sockets[1024];unsigned count=0;int ok=1;struct dirent *entry;
    while((entry=readdir(directory))){
        char *end;long fd=strtol(entry->d_name,&end,10);if(*end||fd<0||fd>INT_MAX)continue;
        struct stat info;
        if(fstatat(dirfd(directory),entry->d_name,&info,0)){ok=0;break;}
        if(S_ISSOCK(info.st_mode)){if(count==1024){ok=0;break;}sockets[count++]=info.st_ino;}
    }
    closedir(directory);if(!ok||!count)return 0;
    const char *tables[]={"/proc/net/udp","/proc/net/tcp","/proc/net/udp6","/proc/net/tcp6"};
    for(unsigned table=0;table<4;++table){
        char expected[64],remote[64];
        if(table<2){snprintf(expected,sizeof(expected),"%08X:%04X",htonl(INADDR_LOOPBACK),network_dns_port);strcpy(remote,"00000000:0000");}
        else{uint32_t words[4];struct in6_addr loop=in6addr_loopback;memcpy(words,&loop,16);
            snprintf(expected,sizeof(expected),"%08X%08X%08X%08X:%04X",words[0],words[1],words[2],words[3],network_dns_port);
            strcpy(remote,"00000000000000000000000000000000:0000");}
        FILE *file=fopen(tables[table],"r");if(!file)return 0;
        char line[1024],local[65],peer[65];unsigned state,rows=0;unsigned long long inode;int found=0;
        if(!fgets(line,sizeof(line),file)){fclose(file);return 0;}
        while(fgets(line,sizeof(line),file)){
            if(++rows>65536||!strchr(line,'\n')){ok=0;break;}
            if(sscanf(line,"%*u: %64s %64s %x %*s %*s %*s %*u %*u %llu",local,peer,&state,&inode)!=4){ok=0;break;}
            if(strcmp(local,expected)||strcmp(peer,remote)||state!=(table%2?10u:7u))continue;
            for(unsigned i=0;i<count;++i)if(sockets[i]==inode)found=1;
        }
        if(ferror(file))ok=0;
        fclose(file);if(!ok||!found)return 0;
    }
    return 1;
}
static inline int network_dns_observe(pid_t pid) {
    char path[PATH_MAX],line[512],own[128],child[128];struct stat info,host;struct statvfs filesystem;
    snprintf(path,sizeof(path),"/proc/%ld/status",(long)pid);FILE *file=fopen(path,"r");if(!file)return -1;
    int uid=0,gid=0,seccomp=0,bad=0;unsigned fields=0,a,b,c,d;unsigned long long caps;
    while(fgets(line,sizeof(line),file)){
        if(sscanf(line,"Uid: %u %u %u %u",&a,&b,&c,&d)==4)uid=a==65534&&b==a&&c==a&&d==a;
        if(sscanf(line,"Gid: %u %u %u %u",&a,&b,&c,&d)==4)gid=a==65534&&b==a&&c==a&&d==a;
        if(sscanf(line,"Seccomp: %u",&a)==1)seccomp=a==2;
        if(sscanf(line,"NoNewPrivs: %u",&a)==1&&a!=1)bad=1;
        if(sscanf(line,"CapEff: %llx",&caps)==1||sscanf(line,"CapPrm: %llx",&caps)==1||sscanf(line,"CapInh: %llx",&caps)==1||
            sscanf(line,"CapBnd: %llx",&caps)==1||sscanf(line,"CapAmb: %llx",&caps)==1){++fields;bad|=caps!=(1u<<CAP_NET_BIND_SERVICE);}
    }
    if(ferror(file))bad=1;
    fclose(file);if(!uid||!gid||!seccomp||bad||fields!=5)return -1;
    snprintf(path,sizeof(path),"/proc/%ld/ns/mnt",(long)pid);
    ssize_t x=readlink("/proc/self/ns/mnt",own,sizeof(own)),y=readlink(path,child,sizeof(child));
    if(x<=0||y<=0||(x==y&&!memcmp(own,child,(size_t)x)))return -1;
    snprintf(path,sizeof(path),"/proc/%ld/root",(long)pid);
    if(statvfs(path,&filesystem)||!(filesystem.f_flag&ST_RDONLY))return -1;
    if(snprintf(path,sizeof(path),"/proc/%ld/root%s",(long)pid,network_dns_runtime)>=(int)sizeof(path))return -1;
    if(stat(path,&info)||stat(network_dns_runtime,&host)||info.st_dev!=host.st_dev||info.st_ino!=host.st_ino||
        info.st_uid!=65534||(info.st_mode&07777)!=0700||statvfs(path,&filesystem)||(filesystem.f_flag&ST_RDONLY))return -1;
    const char *hidden[]={"/proc","/sys","/data/quasar","/bkupgrade/data/opt/lisa-station","/run/lisa-station",
        "/dev/log","/dev/shm","/dev/snd","/etc/unbound","/etc/resolv.conf","/etc/passwd"};
    for(unsigned i=0;i<sizeof(hidden)/sizeof(hidden[0]);++i){snprintf(path,sizeof(path),"/proc/%ld/root%s",(long)pid,hidden[i]);
        if(!lstat(path,&info)||errno!=ENOENT)return -1;}
    if(snprintf(path,sizeof(path),"%s/unbound.pid",network_dns_runtime)>=(int)sizeof(path))return -1;
    int fd=open(path,O_RDONLY|O_NOFOLLOW|O_NONBLOCK|O_CLOEXEC);if(fd<0)return -1;
    char text[32],expected[32];ssize_t used=read(fd,text,sizeof(text));
    int valid=store_file_valid(fd,65534);close(fd);int count=snprintf(expected,sizeof(expected),"%ld\n",(long)pid);
    if(!valid||used!=count||memcmp(text,expected,(size_t)count))return -1;
    return network_dns_listeners(pid)&&network_dns_local_query(AF_INET)&&network_dns_local_query(AF_INET6)?0:-1;
}
static inline int network_dns_absent(const struct guardian_record *record) {
    return record->child<2||!process_live(record->child,record->child_ticks);
}
static inline int network_dns_operation(int runtime,const char *runtime_path,const char *base_path,const char *boot,int operation,int lab) {
    char parent[PATH_MAX];
    if(lab){if(snprintf(parent,sizeof(parent),"%s/network",base_path)>=(int)sizeof(parent))return 0;}
    else strcpy(parent,"/run/lisa-station-net");
    if(snprintf(network_dns_runtime,sizeof(network_dns_runtime),"%s/dns",parent)>=(int)sizeof(network_dns_runtime)||
        snprintf(network_jail,sizeof(network_jail),"%s/dns-jail",runtime_path)>=(int)sizeof(network_jail))return 0;
    char *const arguments[]={"unbound","-d","-c","/etc/lisa-dns.conf",NULL};
    struct guardian_spec spec={.role="dns",.executable="/usr/sbin/unbound",.argv=arguments,.prepare=network_dns_prepare,
        .observe=network_dns_observe,.actors_absent=network_dns_absent,.maximum_seconds=lab?35:0};
    struct guardian_record record;
    if(operation==3){
        int found=guardian_read(runtime,0,"dns.child",&record);
        if(found==1)return 1;
        if(found||record.revision!=1||strcmp(record.boot,boot))return 0;
        if(!process_live(record.guardian,record.guardian_ticks)&&network_dns_absent(&record))return 1;
        return guardian_stop(runtime,0,boot,&spec)==GUARD_OK;
    }
    char config_path[PATH_MAX];
    if(lab)strcpy(config_path,base_path);
    else if(snprintf(config_path,sizeof(config_path),"%s/config",base_path)>=(int)sizeof(config_path))return 0;
    int config=open(config_path,O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC);
    if(config<0)return 0;
    int valid=store_directory_valid(config,0)&&!dns_profile_read(config,"dns.profile",network_dns_runtime,lab,&network_dns_port);
    close(config);if(!valid)return 0;
    if(operation==2)return auxiliary_status(runtime,0,boot,&spec,&record)==GUARD_OK;
    if(auxiliary_status(runtime,0,boot,&spec,&record)==GUARD_OK)return 1;
    int made=!mkdir(parent,lab?0700:0755);
    if(!made&&errno!=EEXIST)return 0;
    int parent_fd=open(parent,O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC);if(parent_fd<0)return 0;
    struct stat info;int parent_ok=!(made&&fchmod(parent_fd,lab?0700:0755))&&
        !fstat(parent_fd,&info)&&S_ISDIR(info.st_mode)&&!info.st_uid&&(info.st_mode&07777)==(lab?0700:0755);
    close(parent_fd);if(!parent_ok)return 0;
    if(network_role_directory(parent,"dns",65534,0700))return 0;
    if(mkdir(network_jail,0700)&&errno!=EEXIST)return 0;
    struct guardian_started started;
    return auxiliary_start(runtime,0,boot,&spec,&started)==GUARD_OK;
}
#endif
