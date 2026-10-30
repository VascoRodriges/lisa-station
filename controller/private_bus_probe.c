/* Private standard-bus diagnostic, with an explicit audio-free SDK lab mode.
 * Namespace/capability preparation precedes every instruction of the daemon.
 * The wire helpers below are bounded OWN test clients, not a production parser. */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <inttypes.h>
#include <linux/capability.h>
#include <stdint.h>
#include <stdio.h>
#include <pthread.h>
#include <stdatomic.h>
#include <sys/sysmacros.h>
#include <stdlib.h>
#include <string.h>
#include <sys/statvfs.h>
#include <sys/wait.h>
#include <unistd.h>
#include "vendor_identity.h"
#include "platform_storage.h"
#include "platform_worker_guard.h"
#include "loopback_socket.h"
#include "bus_byte_relay.h"
#include "platform_sdk_guard.h"
#include "sdk_metadata_trace.h"
#include "private_match_snapshot.h"
#include "private_empty_objects.h"
#include "private_adapter_objects.h"
#include "sdk_name_ledger.h"
#include "driver_denial_record.h"
#include "sdk_service_owner.h"
#ifndef __arm__
#error This namespace diagnostic requires the reviewed ARM device ABI
#endif
static unsigned checks,failures;
static int sdk_bluez;
static int sdk_dual;
static int sdk_errors;
static int sdk_owner;
static void check(int ok){++checks;if(!ok){++failures;fprintf(stderr,"private bus check %u errno %d\n",checks,errno);}}
static int full(int fd,void *buffer,size_t size){
    uint64_t end=guardian_milliseconds()+3000;size_t used=0;
    while(used<size){uint64_t now=guardian_milliseconds();if(!now||now>=end)return -1;
        struct pollfd item={fd,POLLIN,0};int result=poll(&item,1,(int)(end-now));
        if(result<0&&errno==EINTR)continue;if(result!=1)return -1;
        ssize_t got=read(fd,(char *)buffer+used,size-used);if(got<0&&errno==EINTR)continue;
        if(got<=0)return -1;used+=(size_t)got;
    }return 0;
}
static int close_except(const int *keep,unsigned count){
    DIR *list=opendir("/proc/self/fd");if(!list)return -1;struct dirent *entry;int own=dirfd(list),bad=0;
    while((entry=readdir(list))){char *end;long value=strtol(entry->d_name,&end,10);if(*end||value<0||value==own)continue;
        int retained=0;for(unsigned i=0;i<count;++i)retained|=value==keep[i];
        if(!retained&&close((int)value)&&errno!=EBADF)bad=1;
    }if(closedir(list))bad=1;return bad?-1:0;
}
static const char configuration_prefix[]=
    "<busconfig><type>session</type><listen>unix:path=/run/lisa/bus</listen><auth>EXTERNAL</auth>"
    "<limit name=\"max_incoming_bytes\">65536</limit><limit name=\"max_outgoing_bytes\">65536</limit>"
    "<limit name=\"max_message_size\">8192</limit><limit name=\"max_incoming_unix_fds\">1</limit>"
    "<limit name=\"max_outgoing_unix_fds\">1</limit><limit name=\"max_message_unix_fds\">1</limit>"
    "<limit name=\"auth_timeout\">2000</limit><limit name=\"max_completed_connections\">4</limit>"
    "<limit name=\"max_incomplete_connections\">4</limit><limit name=\"max_connections_per_user\">4</limit>";
static const char configuration_policy[]=
    "<limit name=\"max_replies_per_connection\">4</limit><policy context=\"default\">"
    "<allow user=\"root\"/><deny own=\"*\"/><deny send_type=\"method_call\"/>"
    "<allow send_destination=\"org.freedesktop.DBus\" send_interface=\"org.freedesktop.DBus\" send_member=\"Hello\"/>"
    "<allow send_destination=\"org.freedesktop.DBus\" send_interface=\"org.freedesktop.DBus\" send_member=\"GetId\"/>";
static int bus_configuration(const char *root,int subscriptions){
    char text[4096];int size=snprintf(text,sizeof(text),"%s<limit name=\"max_names_per_connection\">%u</limit><limit name=\"max_match_rules_per_connection\">%u</limit>%s%s%s%s%s%s%s</policy></busconfig>\n",configuration_prefix,
        subscriptions>=3?2:1,subscriptions?MATCH_RULES:1,configuration_policy,
        subscriptions?"<allow send_destination=\"org.freedesktop.DBus\" send_interface=\"org.freedesktop.DBus\" send_member=\"AddMatch\"/>":"",
        subscriptions?"<allow send_destination=\"org.freedesktop.DBus\" send_interface=\"org.freedesktop.DBus.Debug.Stats\" send_member=\"GetAllMatchRules\"/>":"",
        subscriptions==2||subscriptions==4?"<allow send_type=\"signal\" send_interface=\"org.example.LisaProbe\" send_member=\"UnexpectedPeer\" send_path=\"/org/example/LisaProbe\"/>":"",
        "<deny receive_sender=\"*\"/><allow receive_sender=\"org.freedesktop.DBus\"/>",
        sdk_owner&&subscriptions>=3?"<allow own=\"" SDK_SERVICE_NAME "\"/><allow send_destination=\"org.freedesktop.DBus\" send_interface=\"org.freedesktop.DBus\" send_member=\"GetNameOwner\"/>":"",
        subscriptions>=3?"<allow own=\"org.bluez\"/><allow send_destination=\"org.freedesktop.DBus\" send_interface=\"org.freedesktop.DBus\" send_member=\"RequestName\"/>"
        "<allow send_destination=\"org.bluez\" send_type=\"method_call\" send_path=\"/\" send_interface=\"org.freedesktop.DBus.ObjectManager\" send_member=\"GetManagedObjects\"/>"
        "<allow receive_type=\"method_call\" receive_path=\"/\" receive_interface=\"org.freedesktop.DBus.ObjectManager\" receive_member=\"GetManagedObjects\"/>"
        "<allow send_type=\"method_return\" send_requested_reply=\"true\"/><allow receive_sender=\"org.bluez\" receive_type=\"method_return\" receive_requested_reply=\"true\"/>":"");
    return size<=0||size>=(int)sizeof(text)?-1:diagnostics_text(root,"/etc/private-bus.conf",text);
}
static int isolate_profile(const char *root,const char *image,const char *binding,int subscriptions){
    if(subscriptions<0||subscriptions>4)return -1;
    struct stat info;if(lstat(root,&info)||!S_ISDIR(info.st_mode)||info.st_uid||(info.st_mode&07777)!=0700)return -1;
    if(unshare(CLONE_NEWNS)||mount(NULL,"/",NULL,MS_REC|MS_PRIVATE,NULL)||
        mount("tmpfs",root,"tmpfs",MS_NOSUID|MS_NODEV,"size=2m,mode=755"))return -1;
    const char *dirs[]={"/lib","/usr","/usr/lib","/usr/bin","/etc","/dev","/run","/tmp","/var","/var/lib","/var/lib/dbus","/opt","/opt/lisa"};
    for(unsigned i=0;i<sizeof(dirs)/sizeof(dirs[0]);++i)if(diagnostics_directory(root,dirs[i]))return -1;
    if(diagnostics_text(root,"/etc/passwd","root:*:0:57346:Private bus:/:/nonexistent\n")||
        diagnostics_text(root,"/etc/group","root:*:0:\nlisa-bus:*:57346:\n")||
        diagnostics_text(root,"/etc/nsswitch.conf","passwd: files\ngroup: files\nhosts: files\n")||
        diagnostics_text(root,"/etc/lisa-private-bus","LISA_PRIVATE_BUS_V1\n")||
        diagnostics_text(root,"/etc/machine-id","0123456789abcdef0123456789abcdef\n")||
        diagnostics_text(root,"/var/lib/dbus/machine-id","0123456789abcdef0123456789abcdef\n")||
        bus_configuration(root,subscriptions)||
        diagnostics_bind(root,"/lib","/lib",0,0)||diagnostics_bind(root,"/usr/lib","/usr/lib",0,0)||
        diagnostics_text(root,"/usr/bin/dbus-daemon","")||
        platform_storage_bind_file(root,image,"/usr/bin/dbus-daemon",1)||
        diagnostics_bind(root,"/dev/null","/dev/null",1,1)||diagnostics_bind(root,"/dev/urandom","/dev/urandom",1,1))return -1;
    if(binding&&(diagnostics_text(root,"/opt/lisa/server.so","")||platform_storage_bind_file(root,binding,"/opt/lisa/server.so",1)))return -1;
    if(platform_storage_tmpfs(root,"/run","size=1m,mode=700")||platform_storage_tmpfs(root,"/tmp","size=1m,mode=700")||
        diagnostics_directory(root,"/run/lisa")||mount(NULL,root,NULL,MS_REMOUNT|MS_RDONLY|MS_NOSUID|MS_NODEV,NULL)||
        chroot(root)||chdir("/"))return -1;
    return 0;
}
static int isolate(const char *root,const char *image,const char *binding){return isolate_profile(root,image,binding,0);}
static int bus_guard(pid_t parent){
    if(vendor_identity_prepare(57346)||collector_extra_guard()||platform_worker_guard(parent))return -1;
#define BUS_DENY(n) BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K,n,0,1),BPF_STMT(BPF_RET|BPF_K,SECCOMP_RET_ERRNO|EPERM)
    struct sock_filter filter[]={
        BPF_STMT(BPF_LD|BPF_W|BPF_ABS,offsetof(struct seccomp_data,nr)),
        BUS_DENY(SYS_socket),BUS_DENY(SYS_socketpair),BUS_DENY(SYS_bind),BUS_DENY(SYS_listen),
        BUS_DENY(SYS_connect),BUS_DENY(SYS_sendto),BUS_DENY(SYS_sendmsg),BUS_DENY(SYS_sendmmsg),
        BUS_DENY(SYS_recvmsg),BUS_DENY(SYS_recvfrom),BUS_DENY(SYS_recvmmsg),
#ifdef SYS_recvmmsg_time64
        BUS_DENY(SYS_recvmmsg_time64),
#endif
#ifdef SYS_send
        BUS_DENY(SYS_send),
#endif
#ifdef SYS_recv
        BUS_DENY(SYS_recv),
#endif
        BUS_DENY(SYS_keyctl),BUS_DENY(SYS_add_key),BUS_DENY(SYS_request_key),
        BUS_DENY(102),BUS_DENY(113),BUS_DENY(117),
#ifdef SYS_io_uring_setup
        BUS_DENY(SYS_io_uring_setup),
#endif
#ifdef SYS_pidfd_getfd
        BUS_DENY(SYS_pidfd_getfd),
#endif
        BPF_STMT(BPF_RET|BPF_K,SECCOMP_RET_ALLOW),
    };
#undef BUS_DENY
    struct sock_fprog program={sizeof(filter)/sizeof(filter[0]),filter};return prctl(PR_SET_SECCOMP,SECCOMP_MODE_FILTER,&program);
}
static int private_view(pid_t pid,int listener_fd,const int reload[2],int before_exec,int relay){
    char path[PATH_MAX];struct stat a,b;struct statvfs fs;
    snprintf(path,sizeof(path),"/proc/%ld/ns/mnt",(long)pid);if(stat(path,&a)||stat("/proc/self/ns/mnt",&b)||a.st_ino==b.st_ino)return 0;
    snprintf(path,sizeof(path),"/proc/%ld/root",(long)pid);if(statvfs(path,&fs)||!(fs.f_flag&ST_RDONLY))return 0;
    const char *writable[]={"/run","/tmp"};
    for(unsigned i=0;i<2;++i){snprintf(path,sizeof(path),"/proc/%ld/root%s",(long)pid,writable[i]);
        if(statvfs(path,&fs)||(fs.f_flag&ST_RDONLY)||!(fs.f_flag&ST_NOEXEC)||!(fs.f_flag&ST_NOSUID)||!(fs.f_flag&ST_NODEV)||
            (uint64_t)fs.f_blocks*fs.f_frsize>1024u*1024)return 0;}
    const char *hidden[]={"/proc","/sys","/data","/bkupgrade","/dev/snd","/dev/shm","/dev/log","/system","/var/run/dbus/system_bus_socket"};
    for(unsigned i=0;i<sizeof(hidden)/sizeof(hidden[0]);++i){snprintf(path,sizeof(path),"/proc/%ld/root%s",(long)pid,hidden[i]);if(!lstat(path,&a)||errno!=ENOENT)return 0;}
    if(before_exec){
    snprintf(path,sizeof(path),"/proc/%ld/fd",(long)pid);DIR *fds=opendir(path);if(!fds)return 0;
    struct dirent *entry;unsigned seen=0;int safe=1;
    while((entry=readdir(fds))){char *end;long number=strtol(entry->d_name,&end,10);if(*end||number<0)continue;
        snprintf(path,sizeof(path),"/proc/%ld/fd/%ld",(long)pid,number);
        if(number>2){
            int expected=(number==listener_fd)?listener_fd:(number==reload[0])?reload[0]:(number==reload[1])?reload[1]:-1;
            if(expected<3||stat(path,&a)||fstat(expected,&b)||(relay&&number==reload[1]?!S_ISFIFO(a.st_mode):!S_ISSOCK(a.st_mode))||a.st_dev!=b.st_dev||a.st_ino!=b.st_ino){safe=0;break;}
        }else if(stat(path,&a)||(!S_ISFIFO(a.st_mode)&&!S_ISCHR(a.st_mode))||(number==2&&!(relay?S_ISCHR(a.st_mode):S_ISFIFO(a.st_mode)))){safe=0;break;}++seen;
    }closedir(fds);if(!safe||seen!=(listener_fd>=3?6u:3u))return 0;
    }
    snprintf(path,sizeof(path),"/proc/%ld/status",(long)pid);FILE *file=fopen(path,"r");if(!file)return 0;
    char line[256];unsigned caps=0;int good=1,group=0,seccomp=0;
    while(fgets(line,sizeof(line),file)){unsigned long long value;unsigned x,y,z,w;
        if(sscanf(line,"CapInh: %llx",&value)==1||sscanf(line,"CapPrm: %llx",&value)==1||sscanf(line,"CapEff: %llx",&value)==1||
            sscanf(line,"CapBnd: %llx",&value)==1||sscanf(line,"CapAmb: %llx",&value)==1){++caps;if(value)good=0;}
        if(sscanf(line,"Gid: %u %u %u %u",&x,&y,&z,&w)==4)group=x==57346&&y==x&&z==x&&w==x;
        if(sscanf(line,"Seccomp: %u",&x)==1)seccomp=x==2;
    }if(ferror(file))good=0;fclose(file);
    return good&&caps==5&&group&&seccomp;
}
static int own_actor(void){
    struct stat info;struct statvfs fs;char marker[32]={0};int fd=open("/etc/lisa-private-bus",O_RDONLY|O_CLOEXEC);
    if(fd<0)return 9;ssize_t size=read(fd,marker,sizeof(marker));close(fd);
    if(size!=20||memcmp(marker,"LISA_PRIVATE_BUS_V1\n",20)||statvfs("/",&fs)||!(fs.f_flag&ST_RDONLY)||
        !lstat("/proc",&info)||errno!=ENOENT||prctl(PR_GET_NO_NEW_PRIVS,0,0,0,0)!=1)return 9;
    int families[]={AF_INET,AF_INET6,AF_NETLINK,AF_PACKET,AF_UNIX};
    for(unsigned i=0;i<sizeof(families)/sizeof(families[0]);++i){errno=0;int value=socket(families[i],SOCK_STREAM,0);check(value<0&&errno==EPERM);if(value>=0)close(value);}
    struct sockaddr_un address={.sun_family=AF_UNIX};strcpy(address.sun_path,"/run/lisa/forbidden");
    errno=0;check(connect(0,(struct sockaddr *)&address,sizeof(address))<0&&errno==EPERM);
    errno=0;check(sendto(0,"X",1,0,(struct sockaddr *)&address,sizeof(address))<0&&errno==EPERM);
    int pair[2];errno=0;check(socketpair(AF_UNIX,SOCK_STREAM,0,pair)<0&&errno==EPERM);
    errno=0;check(bind(0,(struct sockaddr *)&address,sizeof(address))<0&&errno==EPERM);
    errno=0;check(listen(0,1)<0&&errno==EPERM);
    struct msghdr message={0};errno=0;check(sendmsg(0,&message,0)<0&&errno==EPERM);
    errno=0;check(recvmsg(0,&message,0)<0&&errno==EPERM);
    errno=0;check(fork()<0&&errno==EPERM);errno=0;check(unshare(CLONE_NEWNET)<0&&errno==EPERM);
    errno=0;check(open("/etc/private-bus.conf",O_WRONLY)<0&&errno==EROFS);
    printf("{\"event\":\"private-bus-control\",\"checks\":%u,\"failures\":%u}\n",checks,failures);return failures?9:0;
}
static int line(int fd,char *text,size_t capacity){
    for(size_t i=0;i+1<capacity;++i){if(full(fd,text+i,1))return -1;
        if(i&&text[i-1]=='\r'&&text[i]=='\n'){text[i-1]=0;return 0;}}
    return -1;
}
static int text_send(int fd,const char *text){return store_write_all(fd,text,strlen(text));}
static int auth(int fd,char guid[33]){
    static const char request[]="\0AUTH EXTERNAL 30\r\n";char response[128];
    if(store_write_all(fd,request,sizeof(request)-1)||line(fd,response,sizeof(response))||strlen(response)!=35||strncmp(response,"OK ",3))return -1;
    for(unsigned i=3;i<35;++i)if(!((response[i]>='0'&&response[i]<='9')||(response[i]>='a'&&response[i]<='f')))return -1;
    memcpy(guid,response+3,32);guid[32]=0;return 0;
}
static int relay_auth(int fd,char guid[33]){
    static const char request[]="\0AUTH EXTERNAL 30\r\nNEGOTIATE_UNIX_FD\r\nBEGIN\r\n";
    char response[128];
    if(store_write_all(fd,request,sizeof(request)-1)||line(fd,response,sizeof(response))||!bus_auth_ok_line(response))return -1;
    memcpy(guid,response+3,32);guid[32]=0;
    return line(fd,response,sizeof(response))||strcmp(response,"ERROR Unix FD passing disabled")?-1:0;
}
static int relay_auth_implicit(int fd,char guid[33]){
    static const char request[]="\0AUTH EXTERNAL\r\nDATA\r\nNEGOTIATE_UNIX_FD\r\nBEGIN\r\n";char response[128];
    if(store_write_all(fd,request,sizeof(request)-1)||line(fd,response,sizeof(response))||strcmp(response,"DATA")||
        line(fd,response,sizeof(response))||!bus_auth_ok_line(response))return -1;
    memcpy(guid,response+3,32);guid[32]=0;
    return line(fd,response,sizeof(response))||strcmp(response,"ERROR Unix FD passing disabled")?-1:0;
}
static uint32_t u32(const unsigned char *p){return (uint32_t)p[0]|(uint32_t)p[1]<<8|(uint32_t)p[2]<<16|(uint32_t)p[3]<<24;}
static void put32(unsigned char *p,uint32_t value){for(unsigned i=0;i<4;++i)p[i]=(unsigned char)(value>>(8*i));}
static size_t string_field(unsigned char *frame,size_t used,unsigned code,char type,const char *value){
    used=(used+7)&~(size_t)7;frame[used++]=(unsigned char)code;frame[used++]=1;frame[used++]=(unsigned char)type;frame[used++]=0;
    size_t length=strlen(value);put32(frame+used,(uint32_t)length);used+=4;memcpy(frame+used,value,length+1);return used+length+1;
}
static int method(int fd,const char *member,unsigned serial,int expected_error,char *body,size_t capacity){
    unsigned char request[512]={ 'l',1,0,1 };put32(request+8,serial);
    size_t used=string_field(request,16,1,'o',"/org/freedesktop/DBus");
    used=string_field(request,used,2,'s',"org.freedesktop.DBus");used=string_field(request,used,3,'s',member);
    used=string_field(request,used,6,'s',"org.freedesktop.DBus");put32(request+12,(uint32_t)(used-16));used=(used+7)&~(size_t)7;
    if(store_write_all(fd,(const char *)request,used))return -1;
    for(unsigned messages=0;messages<8;++messages){
        unsigned char response[8192]={0};if(full(fd,response,16)||response[0]!='l'||response[3]!=1)return -1;
        uint32_t fields=u32(response+12),payload=u32(response+4);size_t start=(16+(size_t)fields+7)&~(size_t)7;
        if(fields>4096||payload>4096||start+payload>sizeof(response)||full(fd,response+16,start+payload-16))return -1;
        if(response[1]==4)continue;
        uint32_t reply=0;int denied=0;size_t cursor=16;
        while(cursor<16+fields){cursor=(cursor+7)&~(size_t)7;if(cursor+4>16+fields)return -1;
            unsigned code=response[cursor],type=response[cursor+2];if(response[cursor+1]!=1||response[cursor+3])return -1;cursor+=4;
            if(type=='u'){if(cursor+4>16+fields)return -1;if(code==5)reply=u32(response+cursor);cursor+=4;}
            else if(type=='s'||type=='o'){if(cursor+4>16+fields)return -1;size_t length=u32(response+cursor);cursor+=4;
                if(length>=16+fields-cursor||response[cursor+length])return -1;
                if(code==4)denied=length==strlen("org.freedesktop.DBus.Error.AccessDenied")&&!memcmp(response+cursor,"org.freedesktop.DBus.Error.AccessDenied",length);
                cursor+=length+1;
            }else if(type=='g'){if(cursor>=16+fields)return -1;size_t length=response[cursor++];if(length>=16+fields-cursor||response[cursor+length])return -1;cursor+=length+1;}
            else return -1;
        }
        if(reply!=serial)return -1;
        if(expected_error)return response[1]==3&&denied?0:-1;
        if(response[1]!=2||payload<5)return -1;size_t length=u32(response+start);
        if(length+5!=payload||length>=capacity||response[start+4+length])return -1;
        memcpy(body,response+start+4,length+1);return 0;
    }return -1;
}
static int connect_bus(const char *path){
    struct sockaddr_un address={.sun_family=AF_UNIX};if(snprintf(address.sun_path,sizeof(address.sun_path),"%s",path)>=(int)sizeof(address.sun_path))return -1;
    int fd=socket(AF_UNIX,SOCK_STREAM|SOCK_CLOEXEC,0);if(fd<0)return -1;
    if(connect(fd,(struct sockaddr *)&address,sizeof(address))){close(fd);return -1;}
    struct ucred peer;socklen_t length=sizeof(peer);
    if(getsockopt(fd,SOL_SOCKET,SO_PEERCRED,&peer,&length)||length!=sizeof(peer)||peer.pid!=getpid()||peer.uid){close(fd);return -1;}return fd;
}
/* Fixed OWN policy fixtures only. This bounded reader/builder is not used to
 * inspect SDK buffers, forward a host bus, or authorize production messages. */
struct policy_frame {
    unsigned char bytes[8192];size_t start,payload;unsigned type,reply;
    char path[128],interface[128],member[96],sender[96],destination[MATCH_NAME],error[128],signature[16];
};
static uint64_t policy_io_end;static int policy_read_vectors;
static int policy_io(int fd,void *buffer,size_t size,int sending){
    uint64_t now=now_ms(),end=policy_io_end?policy_io_end:now+3000;size_t used=0;
    while(used<size){
        now=now_ms();if(!now||now>=end){errno=ETIMEDOUT;return -1;}
        struct pollfd ready={fd,sending?POLLOUT:POLLIN,0};uint64_t left=end-now;
        int result=poll(&ready,1,left>3000?3000:(int)left);
        if(result<0&&errno==EINTR)continue;if(result!=1)return -1;
        struct iovec item={(char *)buffer+used,size-used};
        ssize_t got=sending?write(fd,(char *)buffer+used,size-used):policy_read_vectors?readv(fd,&item,1):read(fd,(char *)buffer+used,size-used);
        if(got<0&&(errno==EINTR||errno==EAGAIN||errno==EWOULDBLOCK))continue;
        if(got<=0)return -1;used+=(size_t)got;
    }return 0;
}
static int policy_frame_read(int fd,struct policy_frame *frame){
    memset(frame,0,sizeof(*frame));unsigned char *bytes=frame->bytes;
    if(policy_io(fd,bytes,16,0)||bytes[0]!='l'||bytes[3]!=1||!u32(bytes+8))return -1;
    size_t fields=u32(bytes+12);frame->payload=u32(bytes+4);frame->type=bytes[1];
    if(fields>4096||frame->payload>4096||frame->type<2||frame->type>4)return -1;
    frame->start=(16+fields+7)&~(size_t)7;
    if(frame->start+frame->payload>sizeof(frame->bytes)||policy_io(fd,bytes+16,frame->start+frame->payload-16,0))return -1;
    size_t cursor=16;unsigned seen=0;
    while(cursor<16+fields){
        cursor=(cursor+7)&~(size_t)7;if(cursor+4>16+fields)return -1;
        unsigned code=bytes[cursor],type=bytes[cursor+2];
        if(!code||code>9||(seen&(1u<<code))||bytes[cursor+1]!=1||bytes[cursor+3])return -1;
        seen|=1u<<code;cursor+=4;
        if(type=='u'){
            if((code!=5&&code!=9)||cursor+4>16+fields)return -1;
            unsigned value=u32(bytes+cursor);if(code==5)frame->reply=value;else if(value)return -1;cursor+=4;
        }else if(type=='s'||type=='o'||type=='g'){
            size_t size;if(type=='g'){if(code!=8||cursor>=16+fields)return -1;size=bytes[cursor++];}
            else{if(cursor+4>16+fields)return -1;size=u32(bytes+cursor);cursor+=4;}
            if(size>=16+fields-cursor||bytes[cursor+size]||memchr(bytes+cursor,0,size))return -1;
            char *target=NULL;size_t capacity=0;
            switch(code){
                case 1:if(type!='o')return -1;target=frame->path;capacity=sizeof(frame->path);break;
                case 2:target=frame->interface;capacity=sizeof(frame->interface);break;
                case 3:target=frame->member;capacity=sizeof(frame->member);break;
                case 4:target=frame->error;capacity=sizeof(frame->error);break;
                case 6:target=frame->destination;capacity=sizeof(frame->destination);break;
                case 7:target=frame->sender;capacity=sizeof(frame->sender);break;
                case 8:target=frame->signature;capacity=sizeof(frame->signature);break;
                default:return -1;
            }
            if(code!=1&&code!=8&&type!='s')return -1;
            if(target){if(size>=capacity)return -1;memcpy(target,bytes+cursor,size+1);}
            cursor+=size+1;
        }else return -1;
    }
    return cursor==16+fields?0:-1;
}
static int policy_reply(int fd,unsigned serial,const char *error){
    for(unsigned i=0;i<12;++i){struct policy_frame frame;if(policy_frame_read(fd,&frame)||strcmp(frame.sender,"org.freedesktop.DBus"))return -1;
        if(frame.type==4)continue;
        if(frame.reply!=serial)return -1;
        if(error)return frame.type==3&&!strcmp(frame.error,error)?0:-1;
        return frame.type==2&&!frame.payload&&!frame.signature[0]?0:-1;
    }return -1;
}
/* body: 0 none, 1 string, 2 string+zero uint, 3 empty string-array+zero uint,
 * 4 string+DO_NOT_QUEUE uint, only for the explicit owned lab provider. */
static int policy_request(int fd,const char *interface,const char *member,unsigned serial,unsigned body,const char *argument){
    if(body>4||strlen(interface)>96||strlen(member)>80||((body==1||body==2||body==4)&&(!argument||strlen(argument)>1024)))return -1;
    unsigned char bytes[1536]={'l',1,0,1};put32(bytes+8,serial);
    size_t used=string_field(bytes,16,1,'o',"/org/freedesktop/DBus");
    used=string_field(bytes,used,2,'s',interface);used=string_field(bytes,used,3,'s',member);
    used=string_field(bytes,used,6,'s',"org.freedesktop.DBus");
    const char *signature=body==1?"s":body==2||body==4?"su":body==3?"asu":"";
    if(body){size_t size=strlen(signature);used=(used+7)&~(size_t)7;bytes[used++]=8;bytes[used++]=1;bytes[used++]='g';bytes[used++]=0;
        bytes[used++]=(unsigned char)size;memcpy(bytes+used,signature,size+1);used+=size+1;}
    put32(bytes+12,(uint32_t)(used-16));used=(used+7)&~(size_t)7;size_t start=used;
    if(body==1||body==2||body==4){size_t size=strlen(argument);put32(bytes+used,(uint32_t)size);used+=4;memcpy(bytes+used,argument,size+1);used+=size+1;}
    if(body==2||body==4){used=(used+3)&~(size_t)3;put32(bytes+used,body==4?4:0);used+=4;}
    if(body==3){put32(bytes+used,0);put32(bytes+used+4,0);used+=8;}
    if(used>sizeof(bytes))return -1;put32(bytes+4,(uint32_t)(used-start));
    return policy_io(fd,bytes,used,1);
}
static int policy_call(int fd,const char *interface,const char *member,unsigned serial,unsigned body,const char *argument,const char *error){
    return policy_request(fd,interface,member,serial,body,argument)||policy_reply(fd,serial,error)?-1:0;
}
static int policy_primary_owner(int fd,unsigned serial){
    if(policy_request(fd,"org.freedesktop.DBus","RequestName",serial,4,SDK_SERVICE_NAME))return -1;
    for(unsigned i=0;i<12;++i){struct policy_frame frame;
        if(policy_frame_read(fd,&frame)||strcmp(frame.sender,"org.freedesktop.DBus"))return -1;
        if(frame.type==4)continue;
        return frame.type==2&&frame.reply==serial&&!strcmp(frame.signature,"u")&&frame.payload==4&&u32(frame.bytes+frame.start)==1?0:-1;
    }return -1;
}
/* One fixed reviewed service; result 1 has a unique owner, 0 is explicit
 * NameHasNoOwner, -1 is any other error. Never interpret error text as rights. */
static int policy_owner_lookup(int fd,unsigned serial,const char *receiver,char owner[MATCH_NAME]){
    memset(owner,0,MATCH_NAME);
    if(policy_request(fd,"org.freedesktop.DBus","GetNameOwner",serial,1,SDK_SERVICE_NAME))return -1;
    for(unsigned i=0;i<12;++i){struct policy_frame frame;
        if(policy_frame_read(fd,&frame)||strcmp(frame.sender,"org.freedesktop.DBus"))return -1;
        if(frame.type==4)continue;
        struct private_error_text text;
        if(frame.reply!=serial||strcmp(frame.destination,receiver)||private_error_decode(frame.signature,frame.bytes+frame.start,frame.payload,&text))return -1;
        if(frame.type==2&&text.size<MATCH_NAME&&match_name(text.text)){memcpy(owner,text.text,text.size+1);return 1;}
        if(frame.type==3&&!strcmp(frame.error,"org.freedesktop.DBus.Error.NameHasNoOwner")&&text.size)return 0;
        return -1;
    }return -1;
}
static int policy_peer_signal(int fd){
    unsigned char bytes[512]={'l',4,0,1};put32(bytes+8,90);
    size_t used=string_field(bytes,16,1,'o',"/org/example/LisaProbe");
    used=string_field(bytes,used,2,'s',"org.example.LisaProbe");used=string_field(bytes,used,3,'s',"UnexpectedPeer");
    put32(bytes+12,(uint32_t)(used-16));used=(used+7)&~(size_t)7;
    return store_write_all(fd,(const char *)bytes,used);
}
static int policy_driver_transition_read(int fd,char strings[3][96]){
    for(unsigned i=0;i<12;++i){struct policy_frame frame;if(policy_frame_read(fd,&frame)||frame.type!=4||strcmp(frame.sender,"org.freedesktop.DBus"))return -1;
        if(strcmp(frame.member,"NameOwnerChanged"))return -1;
        if(strcmp(frame.interface,"org.freedesktop.DBus")||strcmp(frame.path,"/org/freedesktop/DBus")||strcmp(frame.signature,"sss"))return -1;
        size_t cursor=frame.start;
        for(unsigned j=0;j<3;++j){cursor=(cursor+3)&~(size_t)3;if(cursor+4>frame.start+frame.payload)return -1;
            size_t size=u32(frame.bytes+cursor);cursor+=4;
            if(size>=96||cursor+size>=frame.start+frame.payload||frame.bytes[cursor+size]||memchr(frame.bytes+cursor,0,size))return -1;
            memcpy(strings[j],frame.bytes+cursor,size+1);cursor+=size+1;}
        if(cursor!=frame.start+frame.payload)return -1;
        return 0;
    }return -1;
}
static int policy_driver_transition_owner(int fd,const char *name,const char *owner,int lost){
    char strings[3][96];if(policy_driver_transition_read(fd,strings))return -1;
    return !strcmp(strings[0],name)&&(lost?(!strcmp(strings[1],owner)&&!strings[2][0]):(!strings[1][0]&&!strcmp(strings[2],owner)))?0:-1;
}
static int policy_driver_transition(int fd,const char *name,int lost){return policy_driver_transition_owner(fd,name,name,lost);}
static int policy_driver_change(int fd,const char *name){return policy_driver_transition(fd,name,0);}
static int policy_driver_owner_pair_lost(int fd,const char *unique){
    unsigned seen=0;
    for(unsigned i=0;i<2;++i){char strings[3][96];if(policy_driver_transition_read(fd,strings)||strcmp(strings[1],unique)||strings[2][0])return -1;
        unsigned slot=!strcmp(strings[0],unique)?1:!strcmp(strings[0],SDK_SERVICE_NAME)?2:0;
        if(!slot||(seen&slot))return -1;seen|=slot;
    }return seen==3?0:-1;
}
struct sdk_empty_provider {
    int fd;unsigned serial,calls,signals,owned,closed;uint64_t spent;
    char name[MATCH_NAME];struct stat identity;
};
static int empty_call_request(int fd,unsigned serial,const char *path,const char *interface,const char *member){
    unsigned char bytes[512]={'l',1,2,1};put32(bytes+8,serial);
    size_t used=string_field(bytes,16,1,'o',path);used=string_field(bytes,used,2,'s',interface);
    used=string_field(bytes,used,3,'s',member);used=string_field(bytes,used,6,'s',"org.bluez");
    put32(bytes+12,(uint32_t)(used-16));used=(used+7)&~(size_t)7;return policy_io(fd,bytes,used,1);
}
static int provider_admit(int fd,const char *name,struct sdk_empty_provider *provider){
    struct stat identity;if(fd<3||!empty_objects_name_size(name)||fstat(fd,&identity)||!S_ISSOCK(identity.st_mode))return -1;
    int flags=fcntl(fd,F_GETFL);if(flags<0||fcntl(fd,F_SETFL,flags|O_NONBLOCK)||policy_io_end)return -1;
    policy_io_end=now_ms()+50;int good=0;
    if(!policy_request(fd,"org.freedesktop.DBus","RequestName",70,4,"org.bluez"))for(unsigned i=0;i<12;++i){struct policy_frame frame;
        if(policy_frame_read(fd,&frame)||strcmp(frame.sender,"org.freedesktop.DBus"))break;
        if(frame.type==4)continue;
        good=frame.type==2&&frame.reply==70&&!strcmp(frame.signature,"u")&&frame.payload==4&&u32(frame.bytes+frame.start)==1;break;
    }
    policy_io_end=0;if(!good)return -1;
    memset(provider,0,sizeof(*provider));provider->fd=fd;provider->identity=identity;provider->serial=200;provider->owned=1;strcpy(provider->name,name);return 0;
}
static int provider_open(const char *endpoint,struct sdk_empty_provider *provider){
    int fd=connect_bus(endpoint);char guid[33],name[128];if(fd<3)return -1;
    if(auth(fd,guid)||text_send(fd,"BEGIN\r\n")||method(fd,"Hello",1,0,name,sizeof(name))||provider_admit(fd,name,provider)){close(fd);return -1;}
    return 0;
}
static int provider_pump(struct sdk_empty_provider *provider,const char *sender,const char *second_sender){
    if(!provider)return 0;
    struct stat actual;
    if(provider->fd<3||policy_io_end||fstat(provider->fd,&actual)||actual.st_dev!=provider->identity.st_dev||actual.st_ino!=provider->identity.st_ino)return -1;
    struct pollfd ready={provider->fd,POLLIN,0};int available=poll(&ready,1,0);if(available<0&&errno==EINTR)return 0;
    if(!available)return 0;if(available!=1||!(ready.revents&POLLIN))return -1;
    unsigned char first[2];ssize_t peek=recv(provider->fd,first,sizeof(first),MSG_PEEK|MSG_DONTWAIT);
    if(peek<0&&(errno==EAGAIN||errno==EWOULDBLOCK||errno==EINTR))return 0;
    if(peek<=0)return -1;if(peek<2)return 0;
    if(provider->spent>=1000)return -1;
    uint64_t start=now_ms(),left=1000-provider->spent;if(!start)return -1;
    policy_io_end=start+(left<50?left:50);int good=0;
    if(first[0]=='l'&&first[1]==4){struct policy_frame frame;
        good=provider->signals<16&&!policy_frame_read(provider->fd,&frame)&&frame.type==4&&!strcmp(frame.sender,"org.freedesktop.DBus");
        if(good)++provider->signals;
    }else if(first[0]=='l'&&first[1]==1&&provider->calls<4&&(empty_objects_name_size(sender)||empty_objects_name_size(second_sender))){
        unsigned char bytes[EMPTY_OBJECTS_FRAME];struct private_empty_request request;size_t written=0;
        if(!policy_io(provider->fd,bytes,16,0)){size_t fields=u32(bytes+12),length=(16+fields+7)&~(size_t)7;
            if(!u32(bytes+4)&&fields<=4096&&length<=sizeof(bytes)&&!policy_io(provider->fd,bytes+16,length-16,0)&&
                (!private_empty_request_decode(bytes,length,sender,&request)||!private_empty_request_decode(bytes,length,second_sender,&request))&&
                !(sdk_bluez==2?private_adapter_reply(&request,++provider->serial,bytes,sizeof(bytes),&written):private_empty_reply(&request,++provider->serial,bytes,sizeof(bytes),&written))&&
                !policy_io(provider->fd,bytes,written,1)){++provider->calls;good=1;}
        }
    }
    policy_io_end=0;uint64_t finish=now_ms();if(!finish||finish<start)return -1;provider->spent+=finish-start;
    return good?0:-1;
}
static int provider_close(struct sdk_empty_provider *provider){
    if(!provider||provider->fd<3)return -1;int fd=provider->fd;provider->fd=-1;int result=close(fd);errno=0;
    if(result||fcntl(fd,F_GETFD)>=0||errno!=EBADF)return -1;provider->closed=1;return 0;
}
struct sdk_match_observer {
    int fd;unsigned serial,queries,reads,second_reads,captured,post_absent,closed;uint64_t spent;
    char name[MATCH_NAME];
    struct stat identity;struct private_match_entry baseline,peak,provider;
    struct sdk_name_ledger names;
    struct sdk_service_owner service;unsigned owner_queries;
};
static const char *const own_match_rules[]={"type='signal'","type='signal',interface='org.example.LisaObserver'"};
static const char own_second_rule[]="type='signal',interface='org.example.LisaSecond'";
static int match_contains(const struct private_match_entry *entry,const char *rule){
    for(unsigned i=0;i<entry->rules;++i)if(!strcmp(private_match_rule(entry,i),rule))return 1;
    return 0;
}
static int match_includes(const struct private_match_entry *entry,const struct private_match_entry *prior){
    if(strcmp(entry->name,prior->name)||entry->rules<prior->rules)return 0;
    for(unsigned i=0;i<prior->rules;++i)if(!match_contains(entry,private_match_rule(prior,i)))return 0;
    return 1;
}
static int observer_query(struct sdk_match_observer *observer,struct private_match_snapshot *snapshot){
    memset(snapshot,0,sizeof(*snapshot));struct stat actual;
    if(observer->fd<3||policy_io_end||observer->queries>=40||observer->spent>=1000||
        fstat(observer->fd,&actual)||actual.st_dev!=observer->identity.st_dev||actual.st_ino!=observer->identity.st_ino)return -1;
    uint64_t start=now_ms(),left=1000-observer->spent;if(!start)return -1;
    policy_io_end=start+(left<50?left:50);unsigned serial=++observer->serial;int good=0;++observer->queries;
    if(!policy_request(observer->fd,"org.freedesktop.DBus.Debug.Stats","GetAllMatchRules",serial,0,NULL)){
        for(unsigned i=0;i<12;++i){struct policy_frame frame;
            if(policy_frame_read(observer->fd,&frame)||strcmp(frame.sender,"org.freedesktop.DBus"))break;
            if(frame.type==4)continue;
            if(frame.type==2&&frame.reply==serial&&!strcmp(frame.signature,"a{sas}")&&
                !private_match_decode_limit(frame.bytes+frame.start,frame.payload,MATCH_RULES,snapshot))good=1;
            break;
        }
    }
    policy_io_end=0;uint64_t finish=now_ms();if(!finish||finish<start)return -1;
    observer->spent+=finish-start;return good?0:-1;
}
static int observer_owner_query(struct sdk_match_observer *observer,int retire){
    struct stat actual;
    if(observer->fd<3||policy_io_end||observer->queries>=40||observer->spent>=1000||observer->owner_queries>=(retire?15u:14u)||
        fstat(observer->fd,&actual)||actual.st_dev!=observer->identity.st_dev||actual.st_ino!=observer->identity.st_ino)return -1;
    uint64_t start=now_ms(),left=1000-observer->spent;if(!start)return -1;
    policy_io_end=start+(left<50?left:50);++observer->queries;++observer->owner_queries;
    char owner[MATCH_NAME];int found=policy_owner_lookup(observer->fd,++observer->serial,observer->name,owner),result=-1;
    if(found>=0)result=retire?sdk_owner_retire(&observer->service,&observer->names,found==0):sdk_owner_observe(&observer->service,&observer->names,found?owner:NULL);
    policy_io_end=0;uint64_t finish=now_ms();if(!finish||finish<start)return -1;
    observer->spent+=finish-start;return result;
}
static int observer_admit(int fd,const char *name,struct sdk_match_observer *observer,const struct sdk_empty_provider *provider){
    memset(observer,0,sizeof(*observer));observer->fd=fd;observer->serial=100;
    if(fd<3||strlen(name)>=sizeof(observer->name)||!match_name(name)||fstat(fd,&observer->identity)||!S_ISSOCK(observer->identity.st_mode))return -1;
    int flags=fcntl(fd,F_GETFL);if(flags<0||fcntl(fd,F_SETFL,flags|O_NONBLOCK))return -1;
    strcpy(observer->name,name);struct private_match_snapshot snapshot;
    if(observer_query(observer,&snapshot)||snapshot.clients!=(provider?2u:1u))return -1;
    if(provider){const struct private_match_entry *entry=private_match_find(&snapshot,provider->name);if(!entry)return -1;observer->provider=*entry;}
    const struct private_match_entry *entry=private_match_find(&snapshot,name);
    if(!entry||entry->rules!=1)return -1;observer->baseline=*entry;return 0;
}
static int observer_open(const char *endpoint,struct sdk_match_observer *observer,const struct sdk_empty_provider *provider){
    int fd=connect_bus(endpoint);char guid[33],name[128];
    if(fd<3)return -1;
    if(auth(fd,guid)||text_send(fd,"BEGIN\r\n")||method(fd,"Hello",1,0,name,sizeof(name))||
        policy_call(fd,"org.freedesktop.DBus","AddMatch",2,1,"type='signal'",NULL)||observer_admit(fd,name,observer,provider)){
        close(fd);observer->fd=-1;return -1;
    }return 0;
}
static int observer_snapshot(struct sdk_match_observer *observer,unsigned source){
    if(!sdk_dual&&observer->captured==MATCH_RULES)return 0;
    if(source>1)return -1;
    unsigned *reads=source?&observer->second_reads:&observer->reads;if(++*reads>32)return -1;
    struct private_match_snapshot snapshot;if(observer_query(observer,&snapshot))return -1;
    if(sdk_dual){
        if(sdk_ledger_observe(&observer->names,&snapshot,&observer->baseline,&observer->provider))return -1;
        observer->captured=0;for(unsigned i=0;i<observer->names.count;++i)observer->captured+=observer->names.peak[i].rules;
        if(sdk_owner&&observer->names.count==2&&!observer->service.observed&&observer_owner_query(observer,0))return -1;
        return 0;
    }
    const struct private_match_entry *self=private_match_find(&snapshot,observer->name);
    if(!self||self->rules!=observer->baseline.rules||!match_includes(self,&observer->baseline)||snapshot.clients>(observer->provider.name[0]?3u:2u))return -1;
    if(observer->provider.name[0]){const struct private_match_entry *entry=private_match_find(&snapshot,observer->provider.name);
        if(!entry||entry->rules!=observer->provider.rules||!match_includes(entry,&observer->provider))return -1;}
    for(unsigned i=0;i<snapshot.clients;++i){const struct private_match_entry *entry=&snapshot.entry[i];
        if(!strcmp(entry->name,observer->name)||!strcmp(entry->name,observer->provider.name)||!entry->rules)continue;
        if(observer->captured&&!match_includes(entry,&observer->peak))return -1;
        observer->peak=*entry;observer->captured=entry->rules;
    }return 0;
}
static int observer_after_sdk(struct sdk_match_observer *observer,int policy_only){
    uint64_t end=now_ms()+300;
    if(!policy_only&&!observer->captured)return -1;
    do{struct private_match_snapshot snapshot;if(observer_query(observer,&snapshot))return -1;
        const struct private_match_entry *self=private_match_find(&snapshot,observer->name);
        if(!self||self->rules!=observer->baseline.rules||!match_includes(self,&observer->baseline))return -1;
        if(snapshot.clients==1&&!private_match_find(&snapshot,observer->peak.name)){
            if(sdk_dual&&sdk_ledger_finish(&observer->names,&snapshot,&observer->baseline))return -1;
            if(sdk_owner&&!policy_only&&observer_owner_query(observer,1))return -1;
            observer->post_absent=1;return 0;
        }
        struct timespec pause={0,5000000};nanosleep(&pause,NULL);
    }while(now_ms()<end);
    return -1;
}
static int observer_close(struct sdk_match_observer *observer){
    if(observer->fd<3)return -1;int fd=observer->fd;observer->fd=-1;
    int result=close(fd);errno=0;
    if(result||fcntl(fd,F_GETFD)>=0||errno!=EBADF)return -1;
    observer->closed=1;return 0;
}
static int observer_save(const char *base,unsigned role,const struct sdk_match_observer *observer){
    if(!observer->captured)return -1;
    char path[PATH_MAX],header[160];
    if((!sdk_dual&&observer->captured>MATCH_RULES)||snprintf(path,sizeof(path),"%s/sdk%u-match.private.txt",base,role)>=(int)sizeof(path))return -1;
    if(sdk_dual){
        if(!sdk_ledger_valid(&observer->names)||!observer->names.finished||observer->names.count!=2)return -1;
        int fd=open(path,O_WRONLY|O_CREAT|O_EXCL|O_NOFOLLOW|O_CLOEXEC,0600);if(fd<0)return -1;
        const char preamble[]="PRIVATE_MATCH_V3\ngroup_names 2\n";int failed=store_write_all(fd,preamble,sizeof(preamble)-1);
        for(unsigned i=0;!failed&&i<2;++i){const struct private_match_entry *entry=&observer->names.peak[i];
            int n=snprintf(header,sizeof(header),"name %s\nrules %u\n",entry->name,entry->rules);
            failed=n<=0||n>=(int)sizeof(header)||store_write_all(fd,header,(size_t)n);
            for(unsigned j=0;!failed&&j<entry->rules;++j){const char *rule=private_match_rule(entry,j);size_t size=strlen(rule);
                n=snprintf(header,sizeof(header),"rule_bytes %zu\n",size);
                failed=n<=0||n>=(int)sizeof(header)||store_write_all(fd,header,(size_t)n)||store_write_all(fd,rule,size)||store_write_all(fd,"\n",1);
            }
        }if(close(fd))failed=1;return failed?-1:0;
    }
    int length=snprintf(header,sizeof(header),"PRIVATE_MATCH_V2\nname %s\nrules %u\n",observer->peak.name,observer->captured);
    if(length<=0||length>=(int)sizeof(header))return -1;
    int fd=open(path,O_WRONLY|O_CREAT|O_EXCL|O_NOFOLLOW|O_CLOEXEC,0600);if(fd<0)return -1;
    int failed=store_write_all(fd,header,(size_t)length);
    for(unsigned i=0;!failed&&i<observer->captured;++i){const char *rule=private_match_rule(&observer->peak,i);size_t size=strlen(rule);
        length=snprintf(header,sizeof(header),"rule_bytes %zu\n",size);
        failed=size>MATCH_RULE||length<=0||length>=(int)sizeof(header)||store_write_all(fd,header,(size_t)length)||store_write_all(fd,rule,size)||store_write_all(fd,"\n",1);
    }
    if(close(fd))failed=1;return failed?-1:0;
}
static unsigned subscription_checks;static int subscription_ok,subscription_observer_closed;
static int subscription_policy(const char *endpoint,struct sdk_match_observer *observer,struct sdk_empty_provider *provider){
    int connections[3]={-1,-1,-1};char guid[33],name[128],body[128],first_name[128];int good=0;
    const char *driver="org.freedesktop.DBus",*denied="org.freedesktop.DBus.Error.AccessDenied";
    subscription_checks=0;subscription_ok=subscription_observer_closed=0;
    #define POLICY(c) do{++subscription_checks;if(!(c)){fprintf(stderr,"subscription control %u line %d errno %d\n",subscription_checks,__LINE__,errno);goto done;}}while(0)
    connections[0]=connect_bus(endpoint);POLICY(connections[0]>=3);
    POLICY(!auth(connections[0],guid)&&!text_send(connections[0],"BEGIN\r\n")&&!method(connections[0],"Hello",1,0,body,sizeof(body)));
    strcpy(first_name,body);
    POLICY(!policy_call(connections[0],driver,"AddMatch",2,1,"type='signal',eavesdrop='true'",NULL));
    const char *const additional[]={"type='signal',interface='org.example.LisaProbe'","type='signal',member='OwnSecond'","type='signal',member='OwnThird'"};
    for(unsigned i=0;i<3;++i)POLICY(!policy_call(connections[0],driver,"AddMatch",3+i,1,additional[i],NULL));
    POLICY(!policy_call(connections[0],driver,"AddMatch",6,1,"type='signal',member='OverQuota'","org.freedesktop.DBus.Error.LimitsExceeded"));
    const struct {const char *interface,*member;unsigned body;const char *argument;} forbidden[]={
        {"org.freedesktop.DBus","ListNames",0,NULL},{"org.freedesktop.DBus","ReloadConfig",0,NULL},
        {"org.freedesktop.DBus","RemoveMatch",1,"type='signal',eavesdrop='true'"},
        {"org.freedesktop.DBus.Monitoring","BecomeMonitor",3,NULL},
        {"org.freedesktop.DBus","StartServiceByName",2,"org.example.LisaDenied"},
        {"org.freedesktop.DBus","RequestName",2,"org.example.LisaDenied"},
        {"org.freedesktop.DBus","GetNameOwner",1,"org.example.LisaDenied"},
        {"org.example.LisaDenied","Hello",0,NULL}};
    for(unsigned i=0;i<sizeof(forbidden)/sizeof(forbidden[0]);++i)
        POLICY(!policy_call(connections[0],forbidden[i].interface,forbidden[i].member,7+i,forbidden[i].body,forbidden[i].argument,
            sdk_owner&&!strcmp(forbidden[i].member,"GetNameOwner")?"org.freedesktop.DBus.Error.NameHasNoOwner":denied));
    connections[1]=connect_bus(endpoint);POLICY(connections[1]>=3);
    POLICY(!auth(connections[1],guid)&&!text_send(connections[1],"BEGIN\r\n")&&!method(connections[1],"Hello",1,0,name,sizeof(name)));
    POLICY(!policy_driver_change(connections[0],name));
    POLICY(!policy_peer_signal(connections[1])&&!method(connections[1],"GetId",2,0,body,sizeof(body)));
    struct pollfd receiver={connections[0],POLLIN,0};POLICY(poll(&receiver,1,300)==0);
    if(sdk_owner){char owner[MATCH_NAME];
        POLICY(!policy_call(connections[1],driver,"RequestName",20,4,SDK_SERVICE_NAME ".Other",denied));
        POLICY(!policy_call(connections[1],driver,"RequestName",21,4,SDK_SERVICE_NAME "Other",denied));
        POLICY(!policy_primary_owner(connections[1],22));
        POLICY(policy_owner_lookup(connections[1],23,name,owner)==1&&!strcmp(owner,name));
    }
    int closed=1;
    if(provider){if(provider_admit(connections[0],first_name,provider))closed=0;else{
        connections[0]=-1;
        const char *const paths[]={"/denied","/","/"};
        const char *const interfaces[]={"org.freedesktop.DBus.ObjectManager","org.example.LisaDenied","org.freedesktop.DBus.ObjectManager"};
        const char *const members[]={"GetManagedObjects","GetManagedObjects","UnknownMethod"};
        for(unsigned i=0;i<3;++i)POLICY(!empty_call_request(connections[1],80+i,paths[i],interfaces[i],members[i])&&!policy_reply(connections[1],80+i,denied));
    }}
    else{if(close(connections[0]))closed=0;connections[0]=-1;}
    if(close(connections[1]))closed=0;connections[1]=-1;POLICY(closed);
    connections[2]=connect_bus(endpoint);POLICY(connections[2]>=3);
    POLICY(!auth(connections[2],guid)&&!text_send(connections[2],"BEGIN\r\n")&&!method(connections[2],"Hello",1,0,name,sizeof(name)));
    POLICY(!policy_call(connections[2],driver,"AddMatch",2,1,"type='signal',eavesdrop='true'",NULL));
    POLICY(!observer_admit(connections[2],name,observer,provider));connections[2]=-1;
    if(sdk_owner){char owner[MATCH_NAME];POLICY(policy_owner_lookup(observer->fd,++observer->serial,observer->name,owner)==0);}
    good=1;subscription_ok=1;
done:
    for(unsigned i=0;i<3;++i)if(connections[i]>=0)close(connections[i]);
    if(!good&&connections[2]<0&&observer->fd>=3)observer_close(observer);
    if(!good)observer->fd=-1;
    #undef POLICY
    return good?0:-1;
}
static int client_equal(const char *path,const char *expected);
struct sdk_bus_context {int channel_fd[2],log_known;unsigned channels;struct stat channel[2],binding,log;struct sdk_match_observer *observer;struct sdk_empty_provider *provider;};
static int sdk_provider_idle(pid_t child,void *opaque){
    (void)child;struct sdk_bus_context *context=opaque;
    struct sdk_match_observer *observer=context->observer;
    const char *first=observer->peak.name,*second=NULL;
    if(sdk_dual){
        first=observer->names.count>0&&(observer->names.active&1)?observer->names.peak[0].name:NULL;
        second=observer->names.count>1&&(observer->names.active&2)?observer->names.peak[1].name:NULL;
    }
    return provider_pump(context->provider,first,second);
}
static int sdk_observer_received(pid_t child,unsigned fd,int32_t size,void *opaque){
    struct sdk_bus_context *context=opaque;
    if(context->channels!=(sdk_dual?2u:1u))return -1;
    if(!context->observer||(!sdk_dual&&context->observer->captured==MATCH_RULES)||fd<3||fd>INT_MAX||size<=0)return 0;
    char path[80];struct stat identity;snprintf(path,sizeof(path),"/proc/%ld/fd/%u",(long)child,fd);
    if(stat(path,&identity))return errno==ENOENT||errno==ESRCH?0:-1;
    unsigned source=0;for(;source<context->channels;++source)if(S_ISSOCK(identity.st_mode)&&identity.st_dev==context->channel[source].st_dev&&identity.st_ino==context->channel[source].st_ino)break;
    if(source==context->channels)return 0;
    return observer_snapshot(context->observer,source);
}
static int sdk_bus_caps_zero(pid_t child){
    char path[80],line[256];snprintf(path,sizeof(path),"/proc/%ld/status",(long)child);FILE *file=fopen(path,"r");if(!file)return 0;
    /* This reviewed 4.9 kernel omits NoNewPrivs from status. The trusted
     * prepared child checks PR_GET_NO_NEW_PRIVS before its initial stop;
     * the irreversible setting survives exec. Reject any exported mismatch. */
    unsigned caps=0;int group=0,nnp=1,filter=0,one=0,tgid=0,valid=1,uid=0;
    while(fgets(line,sizeof(line),file)){
        unsigned long long value;
        if(sscanf(line,"CapInh: %llx",&value)==1||sscanf(line,"CapPrm: %llx",&value)==1||
            sscanf(line,"CapEff: %llx",&value)==1||sscanf(line,"CapBnd: %llx",&value)==1||sscanf(line,"CapAmb: %llx",&value)==1){++caps;if(value)valid=0;}
        unsigned a,b,c,d;
        if(sscanf(line,"Gid: %u %u %u %u",&a,&b,&c,&d)==4)group=a==57342&&b==a&&c==a&&d==a;
        if(sscanf(line,"Uid: %u %u %u %u",&a,&b,&c,&d)==4)uid=!(a|b|c|d);
        if(sscanf(line,"NoNewPrivs: %u",&a)==1)nnp=a==1;
        if(sscanf(line,"Seccomp: %u",&a)==1)filter=a==2;
        if(sscanf(line,"Threads: %u",&a)==1)one=a==1;
        if(sscanf(line,"Tgid: %u",&a)==1)tgid=a==(unsigned)child;
    }
    if(ferror(file))valid=0;
    fclose(file);return valid&&caps==5&&uid&&group&&nnp&&filter&&one&&tgid;
}
static int sdk_bus_view(pid_t child,struct stat *data,void *opaque){
    struct sdk_bus_context *context=opaque;
    if(context->channels!=(sdk_dual?2u:1u))return 0;
    char path[PATH_MAX],a[128],b[128];struct stat info,host;struct statvfs fs;
    snprintf(path,sizeof(path),"/proc/%ld/ns/mnt",(long)child);
    ssize_t x=readlink("/proc/self/ns/mnt",a,sizeof(a)),y=readlink(path,b,sizeof(b));
    if(x<=0||y<=0||(x==y&&!memcmp(a,b,(size_t)x))){fprintf(stderr,"sdk view stage %d\n",__LINE__);return 0;}
    snprintf(path,sizeof(path),"/proc/%ld/root",(long)child);if(statvfs(path,&fs)||!(fs.f_flag&ST_RDONLY)){fprintf(stderr,"sdk view stage %d\n",__LINE__);return 0;}
    const char *mounts[]={"/data/quasar","/tmp","/dev/shm"};dev_t devices[3];
    for(unsigned i=0;i<3;++i){snprintf(path,sizeof(path),"/proc/%ld/root%s",(long)child,mounts[i]);
        if(stat(path,&info)||stat(mounts[i],&host)||info.st_dev==host.st_dev||statvfs(path,&fs)||
            fs.f_flag&ST_RDONLY||!(fs.f_flag&ST_NOEXEC)||!(fs.f_flag&ST_NOSUID)||!(fs.f_flag&ST_NODEV)||
            (uint64_t)fs.f_blocks*fs.f_frsize>(i==0?32u:i==1?16u:4u)*1024*1024){fprintf(stderr,"sdk view stage %d\n",__LINE__);return 0;}
        devices[i]=info.st_dev;if(!i)*data=info;
    }
    if(devices[0]==devices[1]||devices[0]==devices[2]||devices[1]==devices[2])return 0;
    snprintf(path,sizeof(path),"/proc/%ld/root/proc/cmdline",(long)child);
    if(stat(path,&info)||stat("/proc/cmdline",&host)||!S_ISREG(info.st_mode)||info.st_dev!=host.st_dev||info.st_ino!=host.st_ino||
        statvfs(path,&fs)||!(fs.f_flag&ST_RDONLY)){fprintf(stderr,"sdk boot metadata mismatch\n");return 0;}
    const char *hidden[]={"/proc/self","/proc/1","/sys","/dev/snd","/dev/log","/dev/keymaster_svc",
        "/var/run/dbus/system_bus_socket","/bkupgrade","/data/opt","/tmp/messages","/dev/shm/alsa-audio-monitor-v2"};
    for(unsigned i=0;i<sizeof(hidden)/sizeof(hidden[0]);++i){snprintf(path,sizeof(path),"/proc/%ld/root%s",(long)child,hidden[i]);
        if(!lstat(path,&info)||errno!=ENOENT){fprintf(stderr,"sdk view stage %d\n",__LINE__);return 0;}}
    snprintf(path,sizeof(path),"/proc/%ld/fd",(long)child);DIR *fds=opendir(path);if(!fds){fprintf(stderr,"sdk view stage %d\n",__LINE__);return 0;}
    unsigned count=0,source_mask=0;int valid=context->channels>=1&&context->channels<=2;struct dirent *entry;
    if(stat("/dev/null",&host)){closedir(fds);{fprintf(stderr,"sdk view stage %d\n",__LINE__);return 0;}}
    while((entry=readdir(fds))){char *end;long n=strtol(entry->d_name,&end,10);if(*end)continue;
        unsigned source=0;while(source<context->channels&&n!=context->channel_fd[source])++source;
        if(n<0||(n>2&&source==context->channels)){valid=0;break;}
        ++count;snprintf(path,sizeof(path),"/proc/%ld/fd/%ld",(long)child,n);
        if(stat(path,&info)){valid=0;break;}
        if(source<context->channels){if(!S_ISSOCK(info.st_mode)||info.st_dev!=context->channel[source].st_dev||info.st_ino!=context->channel[source].st_ino||(source_mask&(1u<<source))){valid=0;break;}source_mask|=1u<<source;}
        else if(n==2){struct stat log;snprintf(path,sizeof(path),"/proc/%ld/root/data/quasar/diagnostic.stderr",(long)child);
            if(stat(path,&log)||!S_ISREG(info.st_mode)||info.st_dev!=data->st_dev||info.st_ino!=log.st_ino||info.st_nlink!=1||(info.st_mode&07777)!=0600){valid=0;break;}
            if(context->log_known&&(info.st_dev!=context->log.st_dev||info.st_ino!=context->log.st_ino)){valid=0;break;}
            context->log=info;context->log_known=1;}
        else if(!S_ISCHR(info.st_mode)||info.st_rdev!=host.st_rdev){valid=0;break;}
    }
    closedir(fds);
    if(!valid||count!=3+context->channels||source_mask!=(1u<<context->channels)-1u||!sdk_bus_caps_zero(child)){fprintf(stderr,"sdk view final %u %d\n",count,valid);return 0;}
    snprintf(path,sizeof(path),"/proc/%ld/root/opt/lisa/client.so",(long)child);
    if(stat(path,&info)||info.st_dev!=context->binding.st_dev||info.st_ino!=context->binding.st_ino||
        statvfs(path,&fs)||!(fs.f_flag&ST_RDONLY)||!(fs.f_flag&ST_NOSUID)||!(fs.f_flag&ST_NODEV))return 0;
    return 1;
}
static int sdk_binding_mapped(pid_t child,void *opaque){
    const struct sdk_bus_context *context=opaque;char path[80],line[PATH_MAX+256];snprintf(path,sizeof(path),"/proc/%ld/maps",(long)child);
    FILE *maps=fopen(path,"r");if(!maps)return errno==ENOENT||errno==ESRCH?0:-1;
    int found=0,valid=1;unsigned count=0;
    while(fgets(line,sizeof(line),maps)){
        unsigned major,minor;unsigned long long inode;
        if(++count>8192||!strchr(line,'\n')){valid=0;break;}
        if(sscanf(line,"%*s %*s %*s %x:%x %llu",&major,&minor,&inode)==3&&
            makedev(major,minor)==context->binding.st_dev&&inode==(unsigned long long)context->binding.st_ino)found=1;
    }if(ferror(maps))valid=0;fclose(maps);return valid?found:-1;
}
static _Atomic int sdk_control_ready;
static void *sdk_control_thread(void *unused){(void)unused;atomic_fetch_add(&sdk_control_ready,1);
    for(;;){struct timespec pause={0,1000000};nanosleep(&pause,NULL);}return NULL;}
static int sdk_bus_control(int source,pid_t parent,const char *provider,int adapter,int dual,int errors,int owner){
    if(!client_equal("/etc/lisa-platform-storage","LISA_PLATFORM_STORAGE_V1\n")||getppid()!=parent||
        prctl(PR_GET_NO_NEW_PRIVS,0,0,0,0)!=1||!unix_byte_channel_valid(source,parent))return 9;
    errno=0;int missing=open("/lisa-sdk-missing-metadata",O_RDONLY|O_NOFOLLOW|O_CLOEXEC);if(missing>=0||errno!=ENOENT)return 9;
    errno=0;if(syscall(SYS_socket,AF_UNIX,SOCK_STREAM|SOCK_CLOEXEC|SOCK_NONBLOCK,0)>=0||errno!=EPERM)return 9;
    struct sockaddr_un address={.sun_family=AF_UNIX};strcpy(address.sun_path,"/var/run/dbus/system_bus_socket");
    int fd=socket(AF_UNIX,SOCK_STREAM|SOCK_CLOEXEC,0);char guid[33],body[128];
    struct sockaddr_un label={.sun_family=AF_UNIX};memcpy(label.sun_path+1,"abc/bus/own/control",19);
    if(fd<3||bind(fd,(struct sockaddr *)&label,(socklen_t)(offsetof(struct sockaddr_un,sun_path)+20))||
        connect(fd,(struct sockaddr *)&address,sizeof(address))||relay_auth_implicit(fd,guid)||
        method(fd,"Hello",1,0,body,sizeof(body))||method(fd,"GetId",2,0,body,sizeof(body)))return 9;
    /* Two known rules plus readv replies give the parent's metadata-only callback
     * an independent positive control before any proprietary SDK is admitted. */
    policy_read_vectors=1;
    for(unsigned i=0;i<2;++i)if(policy_call(fd,"org.freedesktop.DBus","AddMatch",3+i,1,own_match_rules[i],NULL))return 9;
    if(provider){
        struct policy_frame response;
        if(empty_call_request(fd,5,"/","org.freedesktop.DBus.ObjectManager","GetManagedObjects")||policy_frame_read(fd,&response)||response.type!=2||response.reply!=5||strcmp(response.sender,provider)||
            strcmp(response.signature,"a{oa{sa{sv}}}"))return 9;
        if(adapter){unsigned char expected[ADAPTER_BODY];size_t count=0;
            if(private_adapter_body(expected,sizeof(expected),&count)||response.payload!=count||memcmp(response.bytes+response.start,expected,count))return 9;
        }else if(response.payload!=8||u32(response.bytes+response.start)||u32(response.bytes+response.start+4))return 9;
    }
    if(dual){
        int next=socket(AF_UNIX,SOCK_STREAM|SOCK_CLOEXEC,0);char next_name[128];
        if(next<3||connect(next,(struct sockaddr *)&address,sizeof(address))||relay_auth_implicit(next,guid)||
            method(next,"Hello",1,0,next_name,sizeof(next_name))||method(next,"GetId",2,0,body,sizeof(body))||
            policy_call(next,"org.freedesktop.DBus","AddMatch",3,1,own_second_rule,NULL)||
            (errors&&policy_call(next,"org.freedesktop.DBus","RequestName",4,4,"org.example.LisaDenied","org.freedesktop.DBus.Error.AccessDenied"))||
            (owner&&(policy_primary_owner(next,4)||policy_call(next,"org.freedesktop.DBus","RequestName",5,4,SDK_SERVICE_NAME ".Other","org.freedesktop.DBus.Error.AccessDenied")))||
            policy_driver_change(fd,next_name)||(owner&&policy_driver_transition_owner(fd,SDK_SERVICE_NAME,next_name,0))||close(next)||
            (owner?policy_driver_owner_pair_lost(fd,next_name):policy_driver_transition(fd,next_name,1))||method(fd,"GetId",6,0,body,sizeof(body)))return 9;
    }
    if(close(fd))return 9;
    int marker=open("/data/quasar/own-bus-gate-proof",O_WRONLY|O_CREAT|O_EXCL|O_NOFOLLOW|O_CLOEXEC,0600);
    if(marker<0||store_write_all(marker,"no audio\n",9)||close(marker))return 9;
    pthread_t threads[9];for(unsigned i=0;i<9;++i)if(pthread_create(&threads[i],NULL,sdk_control_thread,NULL))return 9;
    for(unsigned i=0;i<2000&&atomic_load(&sdk_control_ready)!=9;++i){struct timespec pause={0,1000000};nanosleep(&pause,NULL);}
    if(atomic_load(&sdk_control_ready)!=9)return 9;
    raise(SIGABRT);return 9;
}
struct relay_report {struct bus_relay_stats stats;unsigned checks,failures;};
struct relay_handle {pid_t pid;int report;char root[PATH_MAX];};
struct client_ready {uint32_t magic;int channel;};
struct client_report {unsigned phase,checks,failures;char guid[33];};
struct client_handle {pid_t pid;int report,control;char root[PATH_MAX],stage[PATH_MAX];};
static int client_equal(const char *path,const char *expected){
    char value[64];int fd=open(path,O_RDONLY|O_NOFOLLOW|O_NONBLOCK|O_CLOEXEC);if(fd<0)return 0;
    ssize_t size=read(fd,value,sizeof(value));close(fd);return size==(ssize_t)strlen(expected)&&!memcmp(value,expected,(size_t)size);
}
static int client_eof(int fd){
    for(unsigned i=0;i<32;++i){struct pollfd item={fd,POLLIN,0};char data[256];if(poll(&item,1,1000)!=1)return 0;
        ssize_t size=read(fd,data,sizeof(data));if(!size)return 1;if(size<0)return 0;}
    return 0;
}
static int client_actor(int source,int output,int control,pid_t parent,unsigned epoch){
    struct statvfs fs;struct stat info;
    if(!client_equal("/etc/lisa-platform-storage","LISA_PLATFORM_STORAGE_V1\n")||
        !client_equal("/etc/lisa-client-binding","LISA_CLIENT_BINDING_V1\n")||
        statvfs("/",&fs)||!(fs.f_flag&ST_RDONLY)||getgid()!=57342||
        fstat(output,&info)||!S_ISFIFO(info.st_mode)||fstat(control,&info)||!S_ISFIFO(info.st_mode))return 9;
    check(getppid()==parent&&prctl(PR_GET_NO_NEW_PRIVS,0,0,0,0)==1&&prctl(PR_GET_SECCOMP,0,0,0,0)==2);
    check(unix_byte_channel_valid(source,parent));
    errno=0;check(syscall(SYS_socket,AF_UNIX,SOCK_STREAM,0)<0&&errno==EPERM);
    struct sockaddr_un address={.sun_family=AF_UNIX};strcpy(address.sun_path,"/var/run/dbus/system_bus_socket");
    errno=0;check(syscall(SYS_connect,source,&address,sizeof(address))<0&&errno==EPERM);
    struct msghdr message={0};errno=0;check(syscall(SYS_sendmsg,source,&message,0)<0&&errno==EPERM);
    errno=0;check(syscall(SYS_recvmsg,source,&message,0)<0&&errno==EPERM);
    errno=0;check(accept4(source,NULL,NULL,SOCK_CLOEXEC)<0&&errno==EPERM);
    errno=0;check(fork()<0&&errno==EPERM);
    errno=0;check(open("/opt/lisa/client.so",O_WRONLY)<0&&errno==EROFS);
    errno=0;check(lstat("/var/run/dbus/system_bus_socket",&info)<0&&errno==ENOENT);
    check(!statvfs("/opt/lisa/client.so",&fs)&&(fs.f_flag&ST_RDONLY));
    check(client_equal("/data/quasar/account_storage.dat","synthetic-identity\n")&&client_equal("/data/quasar/gsdkTokens.json","{}\n"));
    if(failures)return 9;
    int fd=socket(AF_UNIX,SOCK_STREAM|SOCK_CLOEXEC,0);check(fd>=3);if(fd<3)return 9;
    errno=0;check(fcntl(source,F_GETFD)<0&&errno==EBADF);
    check(unix_byte_channel_valid(fd,parent));
    check(!connect(fd,(struct sockaddr *)&address,sizeof(address)));
    strcpy(address.sun_path,"/unreviewed/private/client");errno=0;check(connect(fd,(struct sockaddr *)&address,sizeof(address))<0&&errno==EPERM);
    if(failures){close(fd);return 9;}
    struct client_ready ready={0x4c435931u,fd};if(write(output,&ready,sizeof(ready))!=(ssize_t)sizeof(ready))return 9;
    char command=0;check(!full(control,&command,1)&&command=='G');
    char guid[33]={0},body[128]={0};check(!relay_auth(fd,guid));
    check(!method(fd,"Hello",1,0,body,sizeof(body))&&!strncmp(body,":1.",3));
    check(!method(fd,"GetId",2,0,body,sizeof(body))&&strlen(body)==32);
    check(!method(fd,"ListNames",3,1,body,sizeof(body)));
    check(!method(fd,"ReloadConfig",4,1,body,sizeof(body)));
    check(!policy_call(fd,"org.freedesktop.DBus.Debug.Stats","GetAllMatchRules",5,0,NULL,"org.freedesktop.DBus.Error.AccessDenied"));
    struct client_report report={.phase=1,.checks=checks,.failures=failures};memcpy(report.guid,guid,sizeof(guid));
    if(write(output,&report,sizeof(report))!=(ssize_t)sizeof(report))return 9;
    check(!full(control,&command,1)&&command==(epoch==1?'E':'C'));
    int closed=0;if(epoch==1){closed=client_eof(fd);if(close(fd))closed=0;}else closed=!close(fd);
    check(closed);errno=0;check(fcntl(fd,F_GETFD)<0&&errno==EBADF);
    report.phase=2;report.checks=checks;report.failures=failures;
    return write(output,&report,sizeof(report))==(ssize_t)sizeof(report)&&!failures?0:9;
}
static int client_view(pid_t pid,const char *binding,const char *image,const int child_fds[3],const int parent_fds[3],int executed){
    char path[PATH_MAX];struct stat actual,expected;struct statvfs fs;
    snprintf(path,sizeof(path),"/proc/%ld/ns/mnt",(long)pid);
    if(stat(path,&actual)||stat("/proc/self/ns/mnt",&expected)||actual.st_ino==expected.st_ino)return 0;
    snprintf(path,sizeof(path),"/proc/%ld/root",(long)pid);if(statvfs(path,&fs)||!(fs.f_flag&ST_RDONLY))return 0;
    snprintf(path,sizeof(path),"/proc/%ld/root/opt/lisa/client.so",(long)pid);
    if(stat(path,&actual)||stat(binding,&expected)||actual.st_dev!=expected.st_dev||actual.st_ino!=expected.st_ino||
        statvfs(path,&fs)||!(fs.f_flag&ST_RDONLY)||!(fs.f_flag&ST_NOSUID)||!(fs.f_flag&ST_NODEV))return 0;
    if(executed){snprintf(path,sizeof(path),"/proc/%ld/exe",(long)pid);
        if(stat(path,&actual)||stat(image,&expected)||actual.st_dev!=expected.st_dev||actual.st_ino!=expected.st_ino)return 0;}
    const char *writable[]={"/data/quasar","/tmp","/dev/shm"};dev_t devices[3];
    for(unsigned i=0;i<3;++i){snprintf(path,sizeof(path),"/proc/%ld/root%s",(long)pid,writable[i]);
        if(stat(path,&actual)||stat(writable[i],&expected)||actual.st_dev==expected.st_dev||statvfs(path,&fs)||
            (fs.f_flag&ST_RDONLY)||!(fs.f_flag&ST_NOEXEC)||!(fs.f_flag&ST_NOSUID)||!(fs.f_flag&ST_NODEV)||
            (uint64_t)fs.f_blocks*fs.f_frsize>(i==0?32u:i==1?16u:4u)*1024*1024)return 0;
        devices[i]=actual.st_dev;}
    if(devices[0]==devices[1]||devices[0]==devices[2]||devices[1]==devices[2])return 0;
    const char *hidden[]={"/proc/self","/proc/1","/proc/cmdline","/sys","/bkupgrade","/dev/snd","/dev/log","/dev/keymaster_svc","/var/run/dbus/system_bus_socket","/etc/shadow"};
    for(unsigned i=0;i<sizeof(hidden)/sizeof(hidden[0]);++i){snprintf(path,sizeof(path),"/proc/%ld/root%s",(long)pid,hidden[i]);if(!lstat(path,&actual)||errno!=ENOENT)return 0;}
    struct stat null;if(stat("/dev/null",&null))return 0;
    snprintf(path,sizeof(path),"/proc/%ld/fd",(long)pid);DIR *fds=opendir(path);if(!fds)return 0;
    int valid=1;unsigned seen=0;struct dirent *entry;
    while((entry=readdir(fds))){char *end;long fd=strtol(entry->d_name,&end,10);if(*end||fd<0)continue;
        snprintf(path,sizeof(path),"/proc/%ld/fd/%ld",(long)pid,fd);if(stat(path,&actual)){valid=0;break;}
        if(fd<3){if(!S_ISCHR(actual.st_mode)||actual.st_rdev!=null.st_rdev){valid=0;break;}}
        else{unsigned i=0;for(;i<3&&fd!=child_fds[i];++i){}
            if(i==3||fstat(parent_fds[i],&expected)||actual.st_dev!=expected.st_dev||actual.st_ino!=expected.st_ino||
                (i==0?!S_ISSOCK(actual.st_mode):!S_ISFIFO(actual.st_mode))){valid=0;break;}}
        ++seen;
    }closedir(fds);if(!valid||seen!=6)return 0;
    snprintf(path,sizeof(path),"/proc/%ld/status",(long)pid);FILE *status=fopen(path,"r");if(!status)return 0;
    char line[256];unsigned caps=0;int group=0,uid=0,filter=0;
    while(fgets(line,sizeof(line),status)){unsigned long long value;unsigned a,b,c,d;
        if(sscanf(line,"CapInh: %llx",&value)==1||sscanf(line,"CapPrm: %llx",&value)==1||sscanf(line,"CapEff: %llx",&value)==1||
            sscanf(line,"CapBnd: %llx",&value)==1||sscanf(line,"CapAmb: %llx",&value)==1){++caps;if(value)valid=0;}
        if(sscanf(line,"Gid: %u %u %u %u",&a,&b,&c,&d)==4)group=a==57342&&b==a&&c==a&&d==a;
        if(sscanf(line,"Uid: %u %u %u %u",&a,&b,&c,&d)==4)uid=!(a|b|c|d);
        if(sscanf(line,"Seccomp: %u",&a)==1)filter=a==2;
    }if(ferror(status))valid=0;fclose(status);return valid&&caps==5&&group&&uid&&filter;
}
static int copy_sdk_profile(const char *path){
    struct stat before,after;int source=open("/system/vendor/quasar/quasar.cfg",O_RDONLY|O_NOFOLLOW|O_NONBLOCK|O_CLOEXEC);
    if(source<0)return -1;
    if(fstat(source,&before)||!S_ISREG(before.st_mode)||before.st_uid||before.st_nlink!=1||before.st_mode&0022||before.st_size<=0||before.st_size>1024*1024){close(source);return -1;}
    int target=open(path,O_WRONLY|O_CREAT|O_EXCL|O_NOFOLLOW|O_CLOEXEC,0600);
    if(target<0){close(source);return -1;}
    char buffer[4096];ssize_t size;off_t total=0;int failed=0;
    while((size=read(source,buffer,sizeof(buffer)))>0){total+=size;if(total>before.st_size||store_write_all(target,buffer,(size_t)size)){failed=1;break;}}
    if(size<0||total!=before.st_size||fstat(source,&after)||!platform_seed_same(&before,&after)||fsync(target))failed=1;
    if(close(source))failed=1;
    if(close(target))failed=1;
    return failed?-1:0;
}
/* Stage files exist only on a disposable private tmpfs, never the host DATA. */
static int client_stage(const char *stage,char seeds[PATH_MAX],char profile[PATH_MAX],int firmware){
    if(unshare(CLONE_NEWNS)||mount(NULL,"/",NULL,MS_REC|MS_PRIVATE,NULL)||
        mount("tmpfs",stage,"tmpfs",MS_NOSUID|MS_NODEV|MS_NOEXEC,"size=1m,mode=700")||
        snprintf(seeds,PATH_MAX,"%s/seeds",stage)>=PATH_MAX||mkdir(seeds,0700)||
        snprintf(profile,PATH_MAX,"%s/profile.json",stage)>=PATH_MAX)return -1;
    if(firmware){if(copy_sdk_profile(profile))return -1;}
    else if(diagnostics_text(stage,"/profile.json","{}\n"))return -1;
    int root=open(seeds,O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC);if(root<0)return -1;int failed=0;
    for(unsigned i=0;i<PLATFORM_SEED_COUNT;++i){int fd=openat(root,platform_seed_name(i),O_WRONLY|O_CREAT|O_EXCL|O_NOFOLLOW|O_CLOEXEC,0600);
        const char *text=i==0?"synthetic-identity\n":i==1?"{}\n":"";
        if(fd<0){failed=1;break;}
        int written=store_write_all(fd,text,strlen(text));if(close(fd))written=-1;if(written){failed=1;break;}}
    if(close(root))failed=1;return failed?-1:0;
}
/* Consumes the coordinator's sole client capability on success and failure. */
static int start_client(const char *root,const char *image,const char *binding,int channel,unsigned epoch,struct client_handle *handle,char guid[33]){
    handle->pid=-1;handle->report=handle->control=-1;int reports[2]={-1,-1},commands[2]={-1,-1},live=0;pid_t child=-1;
    if(snprintf(handle->root,sizeof(handle->root),"%s-client",root)>=(int)sizeof(handle->root)||mkdir(handle->root,0700)||
        snprintf(handle->stage,sizeof(handle->stage),"%s-client-stage",root)>=(int)sizeof(handle->stage)||mkdir(handle->stage,0700)||
        pipe2(reports,O_CLOEXEC)||pipe2(commands,O_CLOEXEC))goto failed;
    pid_t parent=getpid();child=fork();if(child<0)goto failed;
    if(!child){
        if(prctl(PR_SET_PDEATHSIG,SIGKILL)||getppid()!=parent)_exit(80);
        char path[PATH_MAX],text[96];struct process_stamp stamp;
        if(process_stamp(getpid(),&stamp)||snprintf(path,sizeof(path),"%s.child",handle->root)>=(int)sizeof(path))_exit(80);
        int file=open(path,O_WRONLY|O_CREAT|O_EXCL|O_NOFOLLOW|O_CLOEXEC,0600);int size=snprintf(text,sizeof(text),"%ld %" PRIu64 "\n",(long)getpid(),stamp.ticks);
        if(file<0||store_write_all(file,text,(size_t)size)||fsync(file)||close(file))_exit(80);
        int zero=open("/dev/null",O_RDWR|O_CLOEXEC);if(zero<0)_exit(81);
        for(int i=0;i<3;++i)if(dup2(zero,i)<0||fcntl(i,F_SETFD,0))_exit(81);
        int keep[]={0,1,2,channel,reports[1],commands[0]};char seeds[PATH_MAX],profile[PATH_MAX];
        if(close_except(keep,6)||clearenv()||client_stage(handle->stage,seeds,profile,0)||
            platform_storage_enter_with_binding(handle->root,seeds,profile,image,0,binding))_exit(82);
        struct rlimit cpu={3,4},data={32u*1024*1024,32u*1024*1024},core={0,0};
        if(setrlimit(RLIMIT_CPU,&cpu)||setrlimit(RLIMIT_DATA,&data)||setrlimit(RLIMIT_CORE,&core)||
            vendor_identity_prepare(57342)||platform_sdk_guard(parent)||unix_byte_channel_guard(channel,parent))_exit(83);
        for(unsigned i=3;i<6;++i)if(fcntl(keep[i],F_SETFD,0))_exit(84);
        char a[24],b[24],c[24],d[24],e[8];snprintf(a,sizeof(a),"%d",channel);snprintf(b,sizeof(b),"%d",reports[1]);
        snprintf(c,sizeof(c),"%d",commands[0]);snprintf(d,sizeof(d),"%ld",(long)parent);snprintf(e,sizeof(e),"%u",epoch);
        if(setenv("LISA_BYTE_FDS",a,1)||setenv("LD_PRELOAD","/opt/lisa/client.so",1)||setenv("LD_BIND_NOW","1",1))_exit(84);
        alarm(12);if(raise(SIGSTOP))_exit(84);
        execl("/system/vendor/quasar/maind","private-bus-client","--client-actor",a,b,c,d,e,(char *)NULL);_exit(85);
    }
    live=1;int status=0;pid_t waited;do{waited=waitpid(child,&status,WUNTRACED);}while(waited<0&&errno==EINTR);
    int stopped=waited==child&&WIFSTOPPED(status)&&WSTOPSIG(status)==SIGSTOP;
    if(!stopped){if((waited==child&&(WIFEXITED(status)||WIFSIGNALED(status)))||(waited<0&&errno==ECHILD))live=0;goto failed;}
    int expected[]={channel,reports[1],commands[0]};
    if(!client_view(child,binding,image,expected,expected,0)||kill(child,SIGCONT))goto failed;
    struct client_ready ready={0};if(full(reports[0],&ready,sizeof(ready))||ready.magic!=0x4c435931u||ready.channel<3||ready.channel>1023)goto failed;
    int actual[]={ready.channel,reports[1],commands[0]};if(!client_view(child,binding,image,actual,expected,1))goto failed;
    close(channel);channel=-1;close(reports[1]);reports[1]=-1;close(commands[0]);commands[0]=-1;
    if(write(commands[1],"G",1)!=1)goto failed;
    struct client_report report={0};
    if(full(reports[0],&report,sizeof(report))||report.phase!=1||report.checks!=24||report.failures||strnlen(report.guid,sizeof(report.guid))!=32)goto failed;
    memcpy(guid,report.guid,33);handle->pid=child;handle->report=reports[0];handle->control=commands[1];return 0;
failed:
    if(live){int status;kill(child,SIGKILL);while(waitpid(child,&status,0)<0&&errno==EINTR){}}
    if(channel>=0)close(channel);
    for(unsigned i=0;i<2;++i){if(reports[i]>=0)close(reports[i]);if(commands[i]>=0)close(commands[i]);}return -1;
}
static void finish_client(struct client_handle *handle,unsigned epoch){
    if(handle->pid<2)return;
    check(write(handle->control,epoch==1?"E":"C",1)==1);close(handle->control);handle->control=-1;
    struct client_report report={0};int received=!full(handle->report,&report,sizeof(report));close(handle->report);handle->report=-1;
    int status=0;pid_t done;do{done=waitpid(handle->pid,&status,0);}while(done<0&&errno==EINTR);
    check(received&&report.phase==2&&report.checks==27&&!report.failures);
    check(done==handle->pid&&WIFEXITED(status)&&!WEXITSTATUS(status));
    check(!rmdir(handle->root)&&!rmdir(handle->stage));handle->pid=-1;
    printf("{\"event\":\"private-bus-client\",\"epoch\":%u,\"actor_checks\":%u,\"failures\":%u,\"client_binding\":true}\n",epoch,report.checks,report.failures);
}
static int relay_actor(int client,int backend,int output,pid_t parent){
    struct stat info;struct statvfs fs;char marker[32]={0};int fd=open("/etc/lisa-private-bus",O_RDONLY|O_CLOEXEC);
    if(fd<0)return 9;ssize_t size=read(fd,marker,sizeof(marker));close(fd);int death=0;
    if(size!=20||memcmp(marker,"LISA_PRIVATE_BUS_V1\n",20)||statvfs("/",&fs)||!(fs.f_flag&ST_RDONLY)||
        prctl(PR_GET_PDEATHSIG,&death,0,0,0)||death!=SIGKILL||fstat(output,&info)||!S_ISFIFO(info.st_mode))return 9;
    check(getppid()==parent&&prctl(PR_GET_NO_NEW_PRIVS,0,0,0,0)==1&&prctl(PR_GET_SECCOMP,0,0,0,0)==2);
    check(unix_byte_channel_valid(client,parent)&&unix_byte_channel_valid(backend,parent));
    errno=0;check(socket(AF_INET,SOCK_STREAM,0)<0&&errno==EPERM);
    struct sockaddr_un address={.sun_family=AF_UNIX};strcpy(address.sun_path,"/var/run/dbus/system_bus_socket");
    errno=0;check(connect(client,(struct sockaddr *)&address,sizeof(address))<0&&errno==EPERM);
    struct msghdr message={0};errno=0;check(sendmsg(client,&message,0)<0&&errno==EPERM);
    errno=0;check(recvmsg(client,&message,0)<0&&errno==EPERM);
    errno=0;check(accept4(client,NULL,NULL,SOCK_CLOEXEC)<0&&errno==EPERM);
    errno=0;check(fork()<0&&errno==EPERM);
    errno=0;check(lstat("/data/quasar/account_storage.dat",&info)<0&&errno==ENOENT);
    if(failures)return 9;
    uint32_t ready=0x4c525931u;if(write(output,&ready,sizeof(ready))!=(ssize_t)sizeof(ready))return 9;
    struct relay_report result={0};bus_relay_run(client,backend,parent,8000,&result.stats);
    errno=0;check(fcntl(client,F_GETFD)<0&&errno==EBADF);errno=0;check(fcntl(backend,F_GETFD)<0&&errno==EBADF);
    result.checks=checks;result.failures=failures;
    return write(output,&result,sizeof(result))==(ssize_t)sizeof(result)&&!failures&&result.stats.result==RELAY_EOF?0:9;
}
/* Returns the OWN client endpoint. Consumes backend on every path. */
static int start_relay(const char *root,const char *image,int backend,struct relay_handle *handle){
    handle->pid=-1;handle->report=-1;int pair[2]={-1,-1},reports[2]={-1,-1},live=0;pid_t child=-1;
    if(snprintf(handle->root,sizeof(handle->root),"%s-relay",root)>=(int)sizeof(handle->root)||mkdir(handle->root,0700)||
        socketpair(AF_UNIX,SOCK_STREAM|SOCK_CLOEXEC,0,pair)||pipe2(reports,O_CLOEXEC))goto failed;
    if(fcntl(pair[1],F_SETFL,fcntl(pair[1],F_GETFL)|O_NONBLOCK)||fcntl(backend,F_SETFL,fcntl(backend,F_GETFL)|O_NONBLOCK))goto failed;
    pid_t parent=getpid();child=fork();if(child<0)goto failed;
    if(!child){
        if(prctl(PR_SET_PDEATHSIG,SIGKILL)||getppid()!=parent)_exit(80);
        char path[PATH_MAX],text[96];struct process_stamp stamp;
        if(process_stamp(getpid(),&stamp)||snprintf(path,sizeof(path),"%s.child",handle->root)>=(int)sizeof(path))_exit(80);
        int own=open(path,O_WRONLY|O_CREAT|O_EXCL|O_NOFOLLOW|O_CLOEXEC,0600);
        int size=snprintf(text,sizeof(text),"%ld %" PRIu64 "\n",(long)getpid(),stamp.ticks);
        if(own<0||store_write_all(own,text,(size_t)size)||fsync(own)||close(own))_exit(80);
        int zero=open("/dev/null",O_RDWR|O_CLOEXEC);if(zero<0)_exit(81);
        for(int i=0;i<3;++i)if(dup2(zero,i)<0||fcntl(i,F_SETFD,0))_exit(81);
        int keep[]={0,1,2,pair[1],backend,reports[1]};
        if(close_except(keep,6)||isolate(handle->root,image,NULL)||clearenv())_exit(82);
        struct rlimit cpu={3,4},data={32u*1024*1024,32u*1024*1024},core={0,0};
        if(setrlimit(RLIMIT_CPU,&cpu)||setrlimit(RLIMIT_DATA,&data)||setrlimit(RLIMIT_CORE,&core)||bus_guard(parent)||unix_byte_channel_guard(pair[1],parent))_exit(83);
        for(unsigned i=3;i<6;++i)if(fcntl(keep[i],F_SETFD,0))_exit(84);
        alarm(12);if(raise(SIGSTOP))_exit(84);
        char a[24],b[24],c[24],d[24];snprintf(a,sizeof(a),"%d",pair[1]);snprintf(b,sizeof(b),"%d",backend);
        snprintf(c,sizeof(c),"%d",reports[1]);snprintf(d,sizeof(d),"%ld",(long)parent);
        execl("/usr/bin/dbus-daemon","private-bus-relay","--relay-actor",a,b,c,d,(char *)NULL);_exit(85);
    }
    live=1;int status=0;pid_t waited;
    do{waited=waitpid(child,&status,WUNTRACED);}while(waited<0&&errno==EINTR);
    int stopped=waited==child&&WIFSTOPPED(status)&&WSTOPSIG(status)==SIGSTOP;
    if(!stopped){
        if((waited==child&&(WIFEXITED(status)||WIFSIGNALED(status)))||(waited<0&&errno==ECHILD))live=0;
        goto failed;
    }
    int extras[]={backend,reports[1]};
    if(!private_view(child,pair[1],extras,1,1))goto failed;
    close(backend);backend=-1;close(pair[1]);pair[1]=-1;close(reports[1]);reports[1]=-1;
    if(kill(child,SIGCONT))goto failed;
    uint32_t marker=0;
    if(full(reports[0],&marker,sizeof(marker))||marker!=0x4c525931u)goto failed;
    char path[80];struct stat expected,actual;snprintf(path,sizeof(path),"/proc/%ld/exe",(long)child);
    if(stat(image,&expected)||stat(path,&actual)||actual.st_dev!=expected.st_dev||actual.st_ino!=expected.st_ino||
        !private_view(child,-1,extras,0,1))goto failed;
    handle->pid=child;handle->report=reports[0];return pair[0];
failed:
    if(live){int status;kill(child,SIGKILL);while(waitpid(child,&status,0)<0&&errno==EINTR){}}
    if(backend>=0)close(backend);
    for(unsigned i=0;i<2;++i){if(pair[i]>=0)close(pair[i]);if(reports[i]>=0)close(reports[i]);}
    return -1;
}
static void finish_relay(struct relay_handle *handle,unsigned epoch,int origin){
    if(handle->pid<2)return;
    struct relay_report report={0};int received=!full(handle->report,&report,sizeof(report));close(handle->report);handle->report=-1;
    int status=0;pid_t done;do{done=waitpid(handle->pid,&status,0);}while(done<0&&errno==EINTR);
    check(received&&report.checks==11&&!report.failures&&report.stats.result==RELAY_EOF&&report.stats.origin==origin&&report.stats.authenticated);
    check(done==handle->pid&&WIFEXITED(status)&&!WEXITSTATUS(status));
    check(received&&report.stats.maximum_output<=2*BUS_AUTH_OUTPUT&&report.stats.maximum_pending<=1024&&
        report.stats.read_bytes[0]&&report.stats.read_bytes[1]&&report.stats.written_bytes[0]&&report.stats.written_bytes[1]);
    check(!rmdir(handle->root));handle->pid=-1;
    printf("{\"event\":\"private-bus-relay\",\"epoch\":%u,\"actor_checks\":%u,\"failures\":%u,\"result\":%d,\"origin\":%d,\"bounded\":%s}\n",
        epoch,report.checks,report.failures,report.stats.result,report.stats.origin,received&&report.stats.maximum_output<=2*BUS_AUTH_OUTPUT&&report.stats.maximum_pending<=1024?"true":"false");
}
static int capture_sdk_log(int retained,const char *base,unsigned role,const struct sdk_bus_context *context,unsigned *bytes,int *truncated){
    int input=openat(retained,"diagnostic.stderr",O_RDONLY|O_NOFOLLOW|O_NONBLOCK|O_CLOEXEC);struct stat info;char path[PATH_MAX];
    if(input<0)return -1;
    if(fstat(input,&info)||!S_ISREG(info.st_mode)||info.st_dev!=context->log.st_dev||info.st_ino!=context->log.st_ino||
        info.st_nlink!=1||(info.st_mode&07777)!=0600||info.st_size<0||info.st_size>2*1024*1024||
        snprintf(path,sizeof(path),"%s/sdk%u-stderr.private.txt",base,role)>=(int)sizeof(path)){close(input);return -1;}
    int output=open(path,O_WRONLY|O_CREAT|O_EXCL|O_NOFOLLOW|O_CLOEXEC,0600),failed=output<0;
    char buffer[4096];*bytes=0;
    while(!failed&&*bytes<65536){ssize_t size=read(input,buffer,sizeof(buffer));if(size<0){failed=1;break;}if(!size)break;
        if(store_write_all(output,buffer,(size_t)size)){failed=1;break;}*bytes+=(unsigned)size;}
    *truncated=info.st_size>(off_t)*bytes;close(input);if(output>=0&&close(output))failed=1;return failed?-1:0;
}
static int run_sdk(const char *base,const char *root,const char *own,const char *binding,int channel,int second,unsigned role,struct sdk_match_observer *observer,struct sdk_empty_provider *provider){
    if(channel<3||(second!=-1&&second<3))return -1;
    char sdk_root[PATH_MAX],stage[PATH_MAX];struct sdk_bus_context context={.channel_fd={channel,second},.channels=second>=3?2:1,.observer=observer,.provider=provider};
    if(snprintf(sdk_root,sizeof(sdk_root),"%s-sdk",root)>=(int)sizeof(sdk_root)||mkdir(sdk_root,0700)||
        snprintf(stage,sizeof(stage),"%s-sdk-stage",root)>=(int)sizeof(stage)||mkdir(stage,0700)||
        fstat(channel,&context.channel[0])||(second>=3&&(second==channel||fstat(second,&context.channel[1])||
            (context.channel[0].st_dev==context.channel[1].st_dev&&context.channel[0].st_ino==context.channel[1].st_ino)))||stat(binding,&context.binding)){
        close(channel);if(second>=3&&second!=channel)close(second);return -1;}
    pid_t parent=getpid(),child=fork();if(child<0){close(channel);if(second>=3)close(second);return -1;}
    if(!child){
        if(prctl(PR_SET_PDEATHSIG,SIGKILL)||getppid()!=parent)_exit(80);
        char path[PATH_MAX],stamp_text[96];struct process_stamp stamp;
        if(process_stamp(getpid(),&stamp)||snprintf(path,sizeof(path),"%s.child",sdk_root)>=(int)sizeof(path))_exit(80);
        int record=open(path,O_WRONLY|O_CREAT|O_EXCL|O_NOFOLLOW|O_CLOEXEC,0600);
        int size=snprintf(stamp_text,sizeof(stamp_text),"%ld %" PRIu64 "\n",(long)getpid(),stamp.ticks);
        if(record<0||store_write_all(record,stamp_text,(size_t)size)||fsync(record)||close(record))_exit(80);
        int keep[]={channel,second};if(guardian_close_except(keep,context.channels))_exit(81);
        int zero=open("/dev/null",O_RDWR|O_CLOEXEC);if(zero<0)_exit(81);
        for(int i=0;i<3;++i)if(dup2(zero,i)<0||fcntl(i,F_SETFD,0))_exit(81);if(zero>2)close(zero);
        struct rlimit stack={1024*1024,1024*1024},cpu={4,5},data={96u*1024*1024,96u*1024*1024},memory={256u*1024*1024,256u*1024*1024},files={128,128},core={0,0},size_limit={2u*1024*1024,2u*1024*1024};
        if(setrlimit(RLIMIT_STACK,&stack)||setrlimit(RLIMIT_CPU,&cpu)||setrlimit(RLIMIT_DATA,&data)||setrlimit(RLIMIT_AS,&memory)||
            setrlimit(RLIMIT_CORE,&core)||setrlimit(RLIMIT_FSIZE,&size_limit)||clearenv())_exit(81);
        char seeds[PATH_MAX],profile[PATH_MAX];const char *image=role?"/system/vendor/quasar/maind":own;
        if(client_stage(stage,seeds,profile,1)||platform_storage_enter_with_binding(sdk_root,seeds,profile,image,1,binding)||chdir("/data/quasar"))_exit(82);
        char fd_text[32],primary_text[24],parent_text[24];snprintf(primary_text,sizeof(primary_text),"%d",channel);
        if(second>=3)snprintf(fd_text,sizeof(fd_text),"%d,%d",channel,second);else snprintf(fd_text,sizeof(fd_text),"%d",channel);
        snprintf(parent_text,sizeof(parent_text),"%ld",(long)parent);
        if(setrlimit(RLIMIT_NOFILE,&files)||fcntl(channel,F_SETFD,0)||(second>=3&&(fcntl(second,F_SETFD,0)||!unix_byte_channel_valid(second,parent)))||setenv("LISA_BYTE_FDS",fd_text,1)||
            setenv("LD_PRELOAD","/opt/lisa/client.so",1)||setenv("LD_BIND_NOW","1",1)||setenv("LISA_BYTE_DIAGNOSTIC","1",1)||
            setenv("LD_LIBRARY_PATH","/system/vendor/quasar/libs",1)||setenv("GST_PLUGIN_PATH","/system/vendor/quasar/libs",1)||
            setenv("CA_CERTIFICATES","/system/vendor/quasar/ca-certificates.crt",1)||setenv("PWD",".",1)||setenv("MALLOC_ARENA_MAX","2",1))_exit(83);
        int log=open("/data/quasar/diagnostic.stderr",O_WRONLY|O_CREAT|O_EXCL|O_NOFOLLOW|O_CLOEXEC,0600);
        if(log<0||dup2(log,2)<0)_exit(84);if(log>2)close(log);
        if(ptrace(PTRACE_TRACEME,0,NULL,NULL)||vendor_identity_prepare(57342)||platform_sdk_guard(parent)||unix_byte_channel_guard(channel,parent))_exit(85);
        if(raise(SIGSTOP))_exit(86);
        if(role)execl("/system/vendor/quasar/maind","maind","--platformd",(char *)NULL);
        else if(provider)execl("/system/vendor/quasar/maind","sdk-bus-control",sdk_owner?"--sdk-owner-control":sdk_errors?"--sdk-error-control":sdk_dual?"--sdk-two-control":sdk_bluez==2?"--sdk-adapter-control":"--sdk-bluez-control",primary_text,parent_text,provider->name,(char *)NULL);
        else execl("/system/vendor/quasar/maind","sdk-bus-control","--sdk-control",fd_text,parent_text,(char *)NULL);
        _exit(87);
    }
    int status=0;pid_t waited;do{waited=waitpid(child,&status,0);}while(waited<0&&errno==EINTR);
    struct stat data;int stopped=waited==child&&WIFSTOPPED(status)&&WSTOPSIG(status)==SIGSTOP;
    int good=stopped&&sdk_bus_view(child,&data,&context);check(good);
    unsigned admission_checks=0;
    if(good&&sdk_dual&&!role){
        unsigned before=failures;int expected_fd=context.channel_fd[1];struct stat expected_object=context.channel[1];
        context.channels=1;++admission_checks;check(!sdk_bus_view(child,&data,&context));context.channels=2;
        context.channel_fd[1]=context.channel_fd[0];++admission_checks;check(!sdk_bus_view(child,&data,&context));context.channel_fd[1]=expected_fd;
        context.channel[1]=context.channel[0];++admission_checks;check(!sdk_bus_view(child,&data,&context));context.channel[1]=expected_object;
        context.channel_fd[1]=INT_MAX;++admission_checks;check(!sdk_bus_view(child,&data,&context));context.channel_fd[1]=expected_fd;
        ++admission_checks;check(sdk_bus_view(child,&data,&context));good=failures==before;
    }
    close(channel);if(second>=3)close(second);
    if(!good){if(stopped){kill(child,SIGKILL);ptrace(PTRACE_CONT,child,NULL,(void *)(intptr_t)SIGKILL);while(waitpid(child,&status,__WALL)<0&&errno==EINTR){}}return -1;}
    long options=PTRACE_O_EXITKILL|PTRACE_O_TRACEEXEC|PTRACE_O_TRACECLONE|PTRACE_O_TRACESYSGOOD;
    char path[PATH_MAX];if(snprintf(path,sizeof(path),"%s/sdk%u-paths.private.txt",base,role)>=(int)sizeof(path))return -1;
    int paths=open(path,O_WRONLY|O_CREAT|O_EXCL|O_NOFOLLOW|O_CLOEXEC,0600);
    if(paths<0||ptrace(PTRACE_SETOPTIONS,child,NULL,(void *)options)||ptrace(PTRACE_SYSCALL,child,NULL,NULL)){
        kill(child,SIGKILL);ptrace(PTRACE_CONT,child,NULL,(void *)(intptr_t)SIGKILL);while(waitpid(child,&status,__WALL)<0&&errno==EINTR){}if(paths>=0)close(paths);return -1;}
    struct observed result={0};int retained=-1;
    int traced=sdk_trace_worker(child,role?"/system/vendor/quasar/maind":own,&retained,&result,paths,sdk_bus_view,&context,1,sdk_binding_mapped,sdk_observer_received,provider?sdk_provider_idle:NULL);
    if(close(paths))good=0;
    unsigned log_bytes=0,objects=0;int truncated=0;
    const char *names[]={"own-bus-gate-proof","soundLogStorageDir","soundLogStorage.dat","data/local_events.lmdb","data/capability_states.lmdb","session_storage.dat"};
    if(retained>=0){
        for(unsigned i=0;i<sizeof(names)/sizeof(names[0]);++i){struct stat info;
            if(!fstatat(retained,names[i],&info,AT_SYMLINK_NOFOLLOW)){if(info.st_dev!=data.st_dev)good=0;else objects|=1u<<i;}
            else if(errno!=ENOENT)good=0;}
        if(capture_sdk_log(retained,base,role,&context,&log_bytes,&truncated))good=0;
        close(retained);
    }else good=0;
    good=good&&!traced&&result.verified&&result.drained&&result.binding_seen;
    if(!role&&(!WIFSIGNALED(result.status)||WTERMSIG(result.status)!=SIGABRT||result.threads!=9||!(objects&1)||!result.path_control))good=0;
    if(rmdir(sdk_root)||rmdir(stage))good=0;
    char admission[96]={0};if(sdk_dual)snprintf(admission,sizeof(admission),",\"source_channels\":2,\"source_admission_checks\":%u",admission_checks);
    printf("{\"event\":\"sdk-bus-diagnostic\",\"role\":\"%s\",\"boundary_ok\":%s,\"exec_verified\":%s,\"binding_mapped\":%s,\"drained\":%s,\"threads\":%u,\"syscalls\":%u,\"denied\":%u,\"socket_attempts\":%u,\"lost_registers\":%u,\"bounded_stop\":%s,\"exit_code\":%d,\"exit_signal\":%d,\"private_objects_mask\":%u,\"path_control\":%s,\"private_stderr_bytes\":%u,\"private_stderr_truncated\":%s,\"synthetic_identity\":true,\"audio_opened\":false,\"functionality_verified\":false%s}\n",
        role?"platform":"own-elf",good?"true":"false",result.verified?"true":"false",result.binding_seen?"true":"false",result.drained?"true":"false",result.threads,result.entries,result.denied,result.sockets,result.lost_registers,result.bounded?"true":"false",
        WIFEXITED(result.status)?WEXITSTATUS(result.status):-1,WIFSIGNALED(result.status)?WTERMSIG(result.status):0,objects,result.path_control?"true":"false",log_bytes,truncated?"true":"false",admission);fflush(stdout);
    return good?0:-1;
}
static int finish_sdk_relay(struct relay_handle *handle,unsigned role,unsigned slot){
    struct relay_report report={0};int received=handle->pid>=2&&!full(handle->report,&report,sizeof(report));
    if(handle->report>=0)close(handle->report);int status=0;pid_t done=-1;
    if(handle->pid>=2)do{done=waitpid(handle->pid,&status,0);}while(done<0&&errno==EINTR);
    int good=received&&report.checks==11&&!report.failures&&report.stats.result!=RELAY_REJECTED&&
        report.stats.maximum_output<=2*BUS_AUTH_OUTPUT&&report.stats.maximum_pending<=1024&&done==handle->pid&&WIFEXITED(status)&&
        WEXITSTATUS(status)==(report.stats.result==RELAY_EOF?0:9);
    int traffic=report.stats.read_bytes[0]>0&&report.stats.read_bytes[1]>0&&report.stats.written_bytes[0]>0&&report.stats.written_bytes[1]>0;
    if(!role&&(!traffic||report.stats.result!=RELAY_EOF||report.stats.origin!=BUS_CLIENT))good=0;
    if(rmdir(handle->root))good=0;handle->pid=-1;
    printf("{\"event\":\"sdk-bus-relay\",\"role\":\"%s\",\"boundary_ok\":%s,\"actor_checks\":%u,\"result\":%d,\"origin\":%d,\"protocol_traffic\":%s,\"auth_verified\":%s%s}\n",
        role?"platform":"own-elf",good?"true":"false",report.checks,report.stats.result,report.stats.origin,traffic?"true":"false",report.stats.authenticated?"true":"false",sdk_dual?(slot?",\"slot\":1":",\"slot\":0"):"");fflush(stdout);return good?0:-1;
}
static int audit_pipe_view(pid_t child,int audit,int log){
    char path[80];struct stat expected,actual,other;
    snprintf(path,sizeof(path),"/proc/%ld/fd/1",(long)child);
    return audit>=3&&log>=3&&!fstat(audit,&expected)&&S_ISFIFO(expected.st_mode)&&!fstat(log,&other)&&
        (expected.st_dev!=other.st_dev||expected.st_ino!=other.st_ino)&&!stat(path,&actual)&&S_ISFIFO(actual.st_mode)&&
        actual.st_dev==expected.st_dev&&actual.st_ino==expected.st_ino;
}
static int save_driver_denials(const char *base,unsigned role,int fd,const struct sdk_match_observer *observer,int reaped,int attested){
    unsigned char bytes[DRIVER_DENIAL_LIMIT*DRIVER_DENIAL_WIRE+1];size_t used=0;int valid=reaped&&attested,closed=0,saved=0,known=0;
    ssize_t got=0;while(used<sizeof(bytes)&&(got=read(fd,bytes+used,sizeof(bytes)-used))>0)used+=(size_t)got;
    if(got<0||used==sizeof(bytes)||used%DRIVER_DENIAL_WIRE||!used||!observer->names.finished||observer->names.active)valid=0;
    if(!close(fd))closed=1;else valid=0;
    unsigned count=(unsigned)(used/DRIVER_DENIAL_WIRE);
    for(unsigned i=0;valid&&i<count;++i){struct driver_denial_record record;unsigned belongs=0;
        if(driver_denial_decode(bytes+i*DRIVER_DENIAL_WIRE,DRIVER_DENIAL_WIRE,&record)){valid=0;break;}
        for(unsigned j=0;j<observer->names.count;++j)if(!strcmp(record.sender,observer->names.peak[j].name))belongs=1;
        if(!belongs){valid=0;break;}
        if(count==1&&strstr(record.body.text,"org.example.LisaDenied"))known=1;
    }
    if(valid){char path[PATH_MAX];int n=snprintf(path,sizeof(path),"%s/sdk%u-driver-errors.private.bin",base,role);
        if(n>0&&n<(int)sizeof(path)){int output=open(path,O_WRONLY|O_CREAT|O_EXCL|O_NOFOLLOW|O_CLOEXEC,0600);
            if(output>=0){int failed=store_write_all(output,(const char *)bytes,used)||fsync(output);if(close(output))failed=1;if(!failed)saved=1;}
        }
    }
    printf("{\"event\":\"sdk-driver-denials\",\"role\":\"%s\",\"records\":%u,\"sdk_history_only\":%s,\"private_saved\":%s,\"pipe_attested\":%s,\"pipe_closed\":%s,\"own_denial_verified\":%s}\n",
        role?"platform":"own-elf",count,valid?"true":"false",saved?"true":"false",attested?"true":"false",closed?"true":"false",!role&&known?"true":"false");fflush(stdout);
    memset(bytes,0,sizeof(bytes));return valid&&saved&&closed&&(role||known)?0:-1;
}
static int sdk_bus_epoch(const char *base,const char *own,const char *server_binding,const char *client_binding,unsigned role,int policy_only){
    unsigned directory=policy_only?2:role;char root[PATH_MAX];struct sockaddr_un endpoint={.sun_family=AF_UNIX};int reload[2];
    if(snprintf(root,sizeof(root),"%s/root%u",base,directory)>=(int)sizeof(root)||mkdir(root,0700)||
        snprintf(endpoint.sun_path,sizeof(endpoint.sun_path),"%s/listener%u",base,directory)>=(int)sizeof(endpoint.sun_path))return -1;
    int listener=socket(AF_UNIX,SOCK_STREAM|SOCK_CLOEXEC|SOCK_NONBLOCK,0);
    if(listener<0||bind(listener,(struct sockaddr *)&endpoint,sizeof(endpoint))||listen(listener,4)||socketpair(AF_UNIX,SOCK_STREAM|SOCK_CLOEXEC,0,reload))return -1;
    int logs[2],audit[2]={-1,-1};if(pipe2(logs,O_CLOEXEC))return -1;
    if(sdk_errors&&(pipe2(audit,O_CLOEXEC)||fcntl(audit[1],F_GETPIPE_SZ)<(int)(DRIVER_DENIAL_LIMIT*DRIVER_DENIAL_WIRE)))return -1;
    pid_t parent=getpid(),bus=fork();if(bus<0)return -1;
    if(!bus){
        if(prctl(PR_SET_PDEATHSIG,SIGKILL)||getppid()!=parent)_exit(80);
        char path[PATH_MAX],text[96];struct process_stamp stamp;if(process_stamp(getpid(),&stamp)||snprintf(path,sizeof(path),"%s.child",root)>=(int)sizeof(path))_exit(80);
        int file=open(path,O_WRONLY|O_CREAT|O_EXCL|O_NOFOLLOW|O_CLOEXEC,0600);int used=snprintf(text,sizeof(text),"%ld %" PRIu64 "\n",(long)getpid(),stamp.ticks);
        if(file<0||store_write_all(file,text,(size_t)used)||close(file))_exit(80);
        int zero=open("/dev/null",O_RDWR|O_CLOEXEC);if(zero<0)_exit(81);
        if(dup2(zero,0)<0||dup2(sdk_errors?audit[1]:zero,1)<0||dup2(logs[1],2)<0)_exit(81);for(int i=0;i<3;++i)if(fcntl(i,F_SETFD,0))_exit(81);
        /* Own controls can emit exactly their canary signal, so its absence
         * at the subscriber tests RECEIVE policy rather than default SEND
         * denial. The actual SDK never receives that fixture-only permission. */
        int keep[]={0,1,2,listener,reload[0],reload[1]};if(close_except(keep,6)||isolate_profile(root,"/usr/bin/dbus-daemon",server_binding,sdk_bluez?(role?3:4):(role?1:2))||clearenv())_exit(82);
        char fd[24],pair[48];snprintf(fd,sizeof(fd),"%d",listener);snprintf(pair,sizeof(pair),"%d,%d",reload[0],reload[1]);
        for(unsigned i=3;i<6;++i)if(fcntl(keep[i],F_SETFD,0))_exit(83);
        struct rlimit cpu={3,4},data={32u*1024*1024,32u*1024*1024},files={64,64},core={0,0};
        if((sdk_errors&&setenv("LISA_DRIVER_ERROR_AUDIT",policy_only?"0":"1",1))||setenv("LD_PRELOAD","/opt/lisa/server.so",1)||setenv("LD_BIND_NOW","1",1)||setenv("LISA_LISTENER_FD",fd,1)||setenv("LISA_RELOAD_FDS",pair,1)||
            setrlimit(RLIMIT_CPU,&cpu)||setrlimit(RLIMIT_DATA,&data)||setrlimit(RLIMIT_NOFILE,&files)||setrlimit(RLIMIT_CORE,&core)||bus_guard(parent))_exit(83);
        alarm(20);if(raise(SIGSTOP))_exit(84);
        execl("/usr/bin/dbus-daemon","dbus-daemon","--nofork","--nosyslog","--nopidfile","--config-file=/etc/private-bus.conf",(char *)NULL);_exit(85);
    }
    close(logs[1]);if(sdk_errors)close(audit[1]);int status=0;pid_t done;do{done=waitpid(bus,&status,WUNTRACED);}while(done<0&&errno==EINTR);
    int attested=!sdk_errors||audit_pipe_view(bus,audit[0],logs[0]);
    int good=done==bus&&WIFSTOPPED(status)&&WSTOPSIG(status)==SIGSTOP&&private_view(bus,listener,reload,1,0)&&attested;check(good);
    struct relay_handle relay[2]={{.pid=-1,.report=-1},{.pid=-1,.report=-1}};struct sdk_match_observer observer={.fd=-1};struct sdk_empty_provider provider={.fd=-1};
    if(good){
        if(kill(bus,SIGCONT))good=0;
        char path[80];struct stat expected,actual;snprintf(path,sizeof(path),"/proc/%ld/exe",(long)bus);int ready=0;
        if(!stat("/usr/bin/dbus-daemon",&expected))for(unsigned i=0;i<300;++i){if(!stat(path,&actual)&&actual.st_dev==expected.st_dev&&actual.st_ino==expected.st_ino){ready=1;break;}struct timespec pause={0,10000000};nanosleep(&pause,NULL);}
        if(sdk_errors)attested=attested&&audit_pipe_view(bus,audit[0],logs[0]);
        if(!ready||!private_view(bus,listener,reload,0,0)||!attested)good=0;
        if(good&&!policy_only&&(role||sdk_dual)&&sdk_bluez&&provider_open(endpoint.sun_path,&provider))good=0;
        if(good&&((policy_only||(!role&&!sdk_dual))?subscription_policy(endpoint.sun_path,&observer,sdk_bluez?&provider:NULL):observer_open(endpoint.sun_path,&observer,sdk_bluez?&provider:NULL)))good=0;
        int clients[2]={-1,-1};unsigned streams=sdk_dual?2:1;
        if(!policy_only){
            for(unsigned i=0;good&&i<streams;++i){char channel_root[PATH_MAX];const char *relay_base=root;
                if(sdk_dual){int n=snprintf(channel_root,sizeof(channel_root),"%s-channel%u",root,i);if(n<0||n>=(int)sizeof(channel_root)){good=0;break;}relay_base=channel_root;}
                int backend=connect_bus(endpoint.sun_path);clients[i]=backend>=0?start_relay(relay_base,own,backend,&relay[i]):-1;
                if(clients[i]<0)good=0;
            }
            if(good){if(run_sdk(base,root,own,client_binding,clients[0],clients[1],role,&observer,sdk_bluez?&provider:NULL))good=0;clients[0]=clients[1]=-1;}
            for(unsigned i=0;i<streams;++i){if(clients[i]>=3)close(clients[i]);if(relay[i].pid>=2&&finish_sdk_relay(&relay[i],role,i))good=0;}
        }
        if(sdk_bluez){
            if(provider.fd>=3&&provider_close(&provider))good=0;
            if(!provider.owned||!provider.closed||(!policy_only&&(provider.calls<1||provider.calls>4||(!role&&provider.calls!=1))))good=0;
            if(!policy_only){printf("{\"event\":\"%s\",\"role\":\"%s\",\"primary_owner\":%s,\"calls\":%u,\"closed\":%s,\"%s\":true,\"hardware_opened\":false}\n",
                sdk_bluez==2?"sdk-adapter-provider":"sdk-empty-provider",role?"platform":"own-elf",provider.owned?"true":"false",provider.calls,provider.closed?"true":"false",sdk_bluez==2?"synthetic_adapter":"empty_tree_only");fflush(stdout);}
        }
        if(observer.fd>=3){
            if(sdk_dual){
                if(observer_after_sdk(&observer,policy_only))good=0;
                else if(good&&!policy_only&&observer_save(base,role,&observer))good=0;
            }else if(good&&(observer_after_sdk(&observer,policy_only)||(!policy_only&&observer_save(base,role,&observer))))good=0;
            if(observer_close(&observer))good=0;
            if(policy_only||(!role&&!sdk_dual)){++subscription_checks;subscription_observer_closed=observer.closed;}
        }
        if(!policy_only){
            int fixture_match=!role&&observer.captured==2&&match_contains(&observer.peak,own_match_rules[0])&&match_contains(&observer.peak,own_match_rules[1]);
            if(sdk_dual){unsigned known=0;
                for(unsigned i=0;i<observer.names.count;++i){const struct private_match_entry *entry=&observer.names.peak[i];
                    if(entry->rules==2&&match_contains(entry,own_match_rules[0])&&match_contains(entry,own_match_rules[1]))known|=1;
                    if(entry->rules==1&&match_contains(entry,own_second_rule))known|=2;
                }fixture_match=!role&&observer.names.count==2&&known==3;
            }
            if(!observer.captured||!observer.post_absent||!observer.closed||(!role&&!fixture_match)||(sdk_dual&&observer.names.count!=2))good=0;
            printf("{\"event\":\"%s\",\"role\":\"%s\",\"snapshot_captured\":%s,\"own_fixture_match\":%s,\"sdk_subscription_removed\":%s,\"observer_closed\":%s,\"queries\":%u,\"peak_rules\":%u,\"private_metadata_only\":true",
                sdk_dual?"sdk-group-observer":"sdk-match-observer",role?"platform":"own-elf",observer.captured?"true":"false",fixture_match?"true":"false",observer.post_absent?"true":"false",observer.closed?"true":"false",observer.queries,observer.captured);
            if(sdk_dual)printf(",\"sdk_names\":%u,\"active_names\":%u,\"group_finished\":%s",observer.names.count,observer.names.active,observer.names.finished?"true":"false");
            if(sdk_owner){if(!observer.service.observed||!observer.service.retired)good=0;
                printf(",\"service_owner_observed\":%s,\"service_owner_retired\":%s,\"owner_queries\":%u",observer.service.observed?"true":"false",observer.service.retired?"true":"false",observer.owner_queries);}
            printf("}\n");fflush(stdout);
        }
        if(kill(bus,SIGTERM))good=0;
        do{done=waitpid(bus,&status,0);}while(done<0&&errno==EINTR);
        if(done!=bus||!WIFEXITED(status)||WEXITSTATUS(status))good=0;
    }else if(done==bus&&WIFSTOPPED(status)){kill(bus,SIGKILL);waitpid(bus,&status,0);}
    if(sdk_errors){
        if(!policy_only){if(save_driver_denials(base,role,audit[0],&observer,done==bus&&WIFEXITED(status)&&!WEXITSTATUS(status),attested))good=0;}
        else{char unexpected;ssize_t n=read(audit[0],&unexpected,1);int closed=close(audit[0]);if(n||closed)good=0;}
    }
    char private_log[8192],path[PATH_MAX];size_t size=0;ssize_t got;
    while(size<sizeof(private_log)&&(got=read(logs[0],private_log+size,sizeof(private_log)-size))>0)size+=(size_t)got;close(logs[0]);
    if(snprintf(path,sizeof(path),"%s/sdk%u-bus-stderr.private.txt",base,directory)>=(int)sizeof(path))good=0;
    else{int log=open(path,O_WRONLY|O_CREAT|O_EXCL|O_NOFOLLOW|O_CLOEXEC,0600);if(log<0)good=0;else{if(store_write_all(log,private_log,size))good=0;if(close(log))good=0;}}
    close(listener);close(reload[0]);close(reload[1]);if(unlink(endpoint.sun_path))good=0;
    int released=!rmdir(root);if(!released)good=0;
    if(policy_only){
        int reaped=done==bus&&WIFEXITED(status)&&!WEXITSTATUS(status);
        printf("{\"event\":\"sdk-policy-epoch\",\"ok\":%s,\"checks\":%u,\"provider_closed\":%s,\"observer_only\":%s,\"observer_closed\":%s,\"bus_reaped\":%s,\"private_view_released\":%s}\n",
            good?"true":"false",subscription_checks,provider.closed?"true":"false",observer.post_absent?"true":"false",observer.closed?"true":"false",reaped?"true":"false",released?"true":"false");fflush(stdout);
    }
    return good?0:-1;
}
static int sdk_bus_coordinator(const char *base,const char *own,const char *server,const char *client){
    pid_t parent=getppid();if(parent<=1||prctl(PR_SET_PDEATHSIG,SIGKILL)||getppid()!=parent)return 2;alarm(40);
    if(sdk_dual&&sdk_bus_epoch(base,own,server,client,0,1))return 2;
    for(unsigned role=0;role<2;++role)if(sdk_bus_epoch(base,own,server,client,role,0))return 2;
    if(!subscription_ok||!subscription_observer_closed||subscription_checks!=(sdk_owner?34u:sdk_bluez?29u:26u))return 2;
    printf("{\"event\":\"sdk-subscription-policy\",\"checks\":%u,\"failures\":0,\"driver_signal_received\":true,\"peer_signal_blocked\":true,\"rule_limit\":4,\"connections_closed\":true,\"own_controls_only\":true}\n",subscription_checks);
    printf("{\"selftest\":\"sdk-private-bus\",\"ok\":true,\"sdk_executed\":true,\"audio_opened\":false,\"functionality_verified\":false}\n");fflush(stdout);return 0;
}
static int run_epoch(const char *root,const char *executable,const char *binding,const char *client_binding,int listener_fd,const int reload[2],const char *endpoint,unsigned epoch,char guid[33]){
    int logs[2];check(!pipe2(logs,O_CLOEXEC));if(failures)return -1;
    pid_t parent=getpid(),child=fork();check(child>=0);if(child<0)return -1;
    if(!child){
        if(prctl(PR_SET_PDEATHSIG,SIGKILL)||getppid()!=parent)_exit(80);
        char stamp_path[PATH_MAX],stamp_text[96];struct process_stamp stamp;
        if(process_stamp(getpid(),&stamp)||snprintf(stamp_path,sizeof(stamp_path),"%s.child",root)>=(int)sizeof(stamp_path))_exit(80);
        int stamp_fd=open(stamp_path,O_WRONLY|O_CREAT|O_EXCL|O_NOFOLLOW|O_CLOEXEC,0600);
        int stamp_size=snprintf(stamp_text,sizeof(stamp_text),"%ld %" PRIu64 "\n",(long)getpid(),stamp.ticks);
        if(stamp_fd<0||store_write_all(stamp_fd,stamp_text,(size_t)stamp_size)||fsync(stamp_fd)||close(stamp_fd))_exit(80);
        close(logs[0]);int zero=open("/dev/null",O_RDWR|O_CLOEXEC);if(zero<0)_exit(81);
        if(dup2(zero,0)<0||dup2(epoch?zero:logs[1],1)<0||dup2(logs[1],2)<0)_exit(81);
        for(int i=0;i<3;++i)if(fcntl(i,F_SETFD,0))_exit(81);
        int keep[]={0,1,2,listener_fd,reload[0],reload[1]};if(close_except(keep,epoch?6:3)||isolate(root,epoch?"/usr/bin/dbus-daemon":executable,epoch?binding:NULL)||clearenv())_exit(82);
        if(epoch){char fd_text[24],reload_text[48];snprintf(fd_text,sizeof(fd_text),"%d",listener_fd);snprintf(reload_text,sizeof(reload_text),"%d,%d",reload[0],reload[1]);
            if(fcntl(listener_fd,F_SETFD,0)||fcntl(reload[0],F_SETFD,0)||fcntl(reload[1],F_SETFD,0)||setenv("LISA_RELOAD_FDS",reload_text,1)||setenv("LD_PRELOAD","/opt/lisa/server.so",1)||setenv("LD_BIND_NOW","1",1)||setenv("LISA_LISTENER_FD",fd_text,1))_exit(82);}
        struct rlimit cpu={3,4},data={32u*1024*1024,32u*1024*1024},files={64,64},core={0,0};
        if(setrlimit(RLIMIT_CPU,&cpu)||setrlimit(RLIMIT_DATA,&data)||setrlimit(RLIMIT_NOFILE,&files)||setrlimit(RLIMIT_CORE,&core)||bus_guard(parent))_exit(83);
        alarm(15);if(raise(SIGSTOP))_exit(84);
        if(epoch)execl("/usr/bin/dbus-daemon","dbus-daemon","--nofork","--nosyslog","--nopidfile","--config-file=/etc/private-bus.conf",(char *)NULL);
        else execl("/usr/bin/dbus-daemon","private-bus-control","--actor",(char *)NULL);
        _exit(85);
    }
    close(logs[1]);int status=0;pid_t waited;do{waited=waitpid(child,&status,WUNTRACED);}while(waited<0&&errno==EINTR);
    check(waited==child&&WIFSTOPPED(status)&&WSTOPSIG(status)==SIGSTOP);
    if(waited!=child||!WIFSTOPPED(status)){close(logs[0]);return -1;}
    int admitted=WIFSTOPPED(status)&&private_view(child,listener_fd,reload,1,0);check(admitted);
    if(admitted)check(!kill(child,SIGCONT));else kill(child,SIGKILL);
    int client=-1;struct relay_handle relay={.pid=-1,.report=-1};struct client_handle own_client={.pid=-1,.report=-1,.control=-1};
    if(admitted&&epoch){
        char image[80];struct stat actual,expected;snprintf(image,sizeof(image),"/proc/%ld/exe",(long)child);int ready=0;
        if(!stat("/usr/bin/dbus-daemon",&expected))for(unsigned i=0;i<300;++i){
            if(!stat(image,&actual)&&actual.st_dev==expected.st_dev&&actual.st_ino==expected.st_ino){ready=1;break;}
            struct timespec pause={0,10000000};nanosleep(&pause,NULL);}
        check(ready);check(ready&&private_view(child,listener_fd,reload,0,0));
        if(ready){int backend=connect_bus(endpoint);if(backend>=0)client=start_relay(root,executable,backend,&relay);}check(client>=0);
        if(client>=0){
            check(!start_client(root,executable,client_binding,client,epoch,&own_client,guid));client=-1;
            if(epoch==2&&own_client.pid>=2){finish_client(&own_client,epoch);finish_relay(&relay,epoch,BUS_CLIENT);}
        }
        /* Observe transport negotiation separately from small FD-count limits.
         * The byte adapter does not implement negotiated descriptor passing. */
        int negotiation=connect_bus(endpoint);check(negotiation>=0);
        if(negotiation>=0){char other[33],response[128];check(!auth(negotiation,other)&&!strcmp(other,guid));
            check(!text_send(negotiation,"NEGOTIATE_UNIX_FD\r\n")&&!line(negotiation,response,sizeof(response))&&!strcmp(response,"AGREE_UNIX_FD"));close(negotiation);}
        check(!kill(child,SIGTERM));
    }
    do{waited=waitpid(child,&status,0);}while(waited<0&&errno==EINTR);
    check(waited==child&&WIFEXITED(status)&&WEXITSTATUS(status)==0);
    if(relay.pid>=2)finish_relay(&relay,epoch,BUS_BACKEND);
    if(own_client.pid>=2)finish_client(&own_client,epoch);
    /* Bounded private stderr only; never a shared system log. */
    char log[8192];size_t bytes=0;ssize_t got;
    while(bytes<sizeof(log)&&(got=read(logs[0],log+bytes,sizeof(log)-bytes))>0)bytes+=(size_t)got;
    close(logs[0]);
    if(!epoch){
        static const char expected[]="{\"event\":\"private-bus-control\",\"checks\":15,\"failures\":0}\n";
        check(bytes==sizeof(expected)-1&&!memcmp(log,expected,bytes));
        if(bytes==sizeof(expected)-1&&!memcmp(log,expected,bytes))fputs(expected,stdout);
    }else if(bytes)fprintf(stderr,"epoch %u own private log: %.*s\n",epoch,(int)bytes,log);
    printf("{\"event\":\"private-bus-epoch\",\"epoch\":%u,\"checks\":%u,\"failures\":%u,\"actual_daemon\":%s,\"fd_negotiation_disabled\":false,\"auth_gate_verified\":%s}\n",epoch,checks,failures,epoch?"true":"false",epoch?"true":"false");fflush(stdout);
    return failures?-1:0;
}
static int coordinator(const char *base,const char *executable,const char *binding,const char *client_binding){
    pid_t parent=getppid();if(parent<=1||prctl(PR_SET_PDEATHSIG,SIGKILL)||getppid()!=parent)return 2;alarm(40);
    char root[PATH_MAX],previous[33]={0};
    for(unsigned epoch=0;epoch<3;++epoch){
        if(snprintf(root,sizeof(root),"%s/root%u",base,epoch)>=(int)sizeof(root)||mkdir(root,0700))return 2;
        int listener_fd=-1,reload[2]={-1,-1};struct sockaddr_un endpoint={.sun_family=AF_UNIX};
        if(epoch){
            if(snprintf(endpoint.sun_path,sizeof(endpoint.sun_path),"%s/listener%u",base,epoch)>=(int)sizeof(endpoint.sun_path))return 2;
            listener_fd=socket(AF_UNIX,SOCK_STREAM|SOCK_CLOEXEC|SOCK_NONBLOCK,0);
            if(listener_fd<0||bind(listener_fd,(struct sockaddr *)&endpoint,sizeof(endpoint))||listen(listener_fd,4)||socketpair(AF_UNIX,SOCK_STREAM|SOCK_CLOEXEC,0,reload))return 2;
        }
        char guid[33]={0};int result=run_epoch(root,executable,binding,client_binding,listener_fd,reload,epoch?endpoint.sun_path:NULL,epoch,guid);
        if(listener_fd>=0){close(listener_fd);close(reload[0]);close(reload[1]);if(unlink(endpoint.sun_path))return 2;}
        if(result)return 2;
        if(epoch==2)check(strcmp(previous,guid)!=0);memcpy(previous,guid,sizeof(previous));
        if(rmdir(root))return 2;
    }
    printf("{\"selftest\":\"private-bus\",\"checks\":%u,\"failures\":%u,\"ok\":%s,\"sdk_executed\":false,\"audio_opened\":false,\"isolation_verified\":false}\n",checks,failures,failures?"false":"true");fflush(stdout);return failures?2:0;
}
int main(int argc,char **argv){
    if(argc==2&&!strcmp(argv[1],"--actor"))return own_actor();
    if((argc==4&&!strcmp(argv[1],"--sdk-control"))||(argc==5&&(!strcmp(argv[1],"--sdk-bluez-control")||!strcmp(argv[1],"--sdk-adapter-control")||!strcmp(argv[1],"--sdk-two-control")||!strcmp(argv[1],"--sdk-error-control")||!strcmp(argv[1],"--sdk-owner-control")))){
        long values[2];for(unsigned i=0;i<2;++i){char *end;values[i]=strtol(argv[i+2],&end,10);if(*end||values[i]<3||values[i]>INT_MAX)return 2;}
        if(getppid()!=values[1])return 2;
        if(argc==5&&!empty_objects_name_size(argv[4]))return 2;
        int errors=!strcmp(argv[1],"--sdk-error-control"),owner=!strcmp(argv[1],"--sdk-owner-control"),dual=owner||errors||!strcmp(argv[1],"--sdk-two-control");
        return sdk_bus_control((int)values[0],(pid_t)values[1],argc==5?argv[4]:NULL,dual||!strcmp(argv[1],"--sdk-adapter-control"),dual,errors,owner);
    }
    if(argc==7&&!strcmp(argv[1],"--client-actor")){
        long values[5];for(unsigned i=0;i<5;++i){char *end;values[i]=strtol(argv[i+2],&end,10);if(*end||values[i]<(i==4?1:3)||values[i]>INT_MAX)return 2;}
        if(values[0]==values[1]||values[0]==values[2]||values[1]==values[2]||getppid()!=values[3]||values[4]>2)return 2;
        return client_actor((int)values[0],(int)values[1],(int)values[2],(pid_t)values[3],(unsigned)values[4]);
    }
    if(argc==6&&!strcmp(argv[1],"--relay-actor")){
        long values[4];for(unsigned i=0;i<4;++i){char *end;values[i]=strtol(argv[i+2],&end,10);if(*end||values[i]<3||values[i]>INT_MAX)return 2;}
        if(values[0]==values[1]||values[0]==values[2]||values[1]==values[2]||getppid()!=values[3])return 2;
        return relay_actor((int)values[0],(int)values[1],(int)values[2],(pid_t)values[3]);
    }
    if(argc!=5||(strcmp(argv[1],"--run")&&strcmp(argv[1],"--run-sdk")&&strcmp(argv[1],"--run-sdk-bluez")&&strcmp(argv[1],"--run-sdk-adapter")&&strcmp(argv[1],"--run-sdk-two")&&strcmp(argv[1],"--run-sdk-error-audit")&&strcmp(argv[1],"--run-sdk-owner"))||getuid()||geteuid()||getgid()||getegid())return 2;
    sdk_owner=!strcmp(argv[1],"--run-sdk-owner");sdk_errors=!strcmp(argv[1],"--run-sdk-error-audit");sdk_dual=sdk_owner||sdk_errors||!strcmp(argv[1],"--run-sdk-two");sdk_bluez=(sdk_dual||!strcmp(argv[1],"--run-sdk-adapter"))?2:!strcmp(argv[1],"--run-sdk-bluez");int sdk=sdk_bluez||!strcmp(argv[1],"--run-sdk");
    if(sdk){
        char pattern[1024];int fd=open("/proc/sys/kernel/core_pattern",O_RDONLY|O_NOFOLLOW|O_CLOEXEC);if(fd<0)return 2;
        ssize_t count=read(fd,pattern,sizeof(pattern));int closed=close(fd);
        if(count<=0||count>=(ssize_t)sizeof(pattern)||closed||pattern[0]=='|')return 2;
    }
    const char prefix[]="/bkupgrade/data/opt/lisa-controller-lab/private-bus.";const char *base=argv[2];
    if(strncmp(base,prefix,sizeof(prefix)-1))return 2;size_t suffix=strlen(base+sizeof(prefix)-1);if(suffix<6||suffix>16)return 2;
    for(size_t i=sizeof(prefix)-1;base[i];++i)if(!((base[i]>='a'&&base[i]<='z')||(base[i]>='A'&&base[i]<='Z')||(base[i]>='0'&&base[i]<='9')))return 2;
    struct stat info;if(lstat(base,&info)||!S_ISDIR(info.st_mode)||info.st_uid||(info.st_mode&07777)!=0700)return 2;
    const char *production[]={"/bkupgrade/data/opt/lisa-station/state","/run/lisa-station"};
    for(unsigned i=0;i<2;++i)if(!lstat(production[i],&info)||errno!=ENOENT)return 2;
    pid_t owner=getppid();if(owner<=1||prctl(PR_SET_PDEATHSIG,SIGKILL)||getppid()!=owner||prctl(PR_SET_CHILD_SUBREAPER,1))return 2;alarm(50);signal(SIGPIPE,SIG_IGN);
    char executable[PATH_MAX];ssize_t size=readlink("/proc/self/exe",executable,sizeof(executable)-1);if(size<=0||size>=(ssize_t)sizeof(executable)-1)return 2;executable[size]=0;
    int canary=socket(AF_UNIX,SOCK_STREAM|SOCK_CLOEXEC,0);if(canary<0)return 2;
    struct sockaddr_un address={.sun_family=AF_UNIX};snprintf(address.sun_path+1,sizeof(address.sun_path)-1,"lisa-private-bus-%ld",(long)getpid());
    socklen_t length=(socklen_t)(offsetof(struct sockaddr_un,sun_path)+1+strlen(address.sun_path+1));
    if(bind(canary,(struct sockaddr *)&address,length)||listen(canary,1))return 2;
    pid_t child=fork();if(child<0)return 2;
    if(!child){close(canary);int keep[]={0,1,2};if(close_except(keep,3))_exit(2);_exit(sdk?sdk_bus_coordinator(base,executable,argv[3],argv[4]):coordinator(base,executable,argv[3],argv[4]));}
    int status=0;pid_t done;do{done=waitpid(child,&status,0);}while(done<0&&errno==EINTR);
    check(done==child&&WIFEXITED(status)&&WEXITSTATUS(status)==0);
    int control=socket(AF_UNIX,SOCK_STREAM|SOCK_CLOEXEC,0);check(control>=0&&!connect(control,(struct sockaddr *)&address,length));if(control>=0)close(control);close(canary);
    /* Any abnormal coordinator exit adopts only our own new descendants.
     * Their irreversible PDEATH chain kills them; reap before claiming done. */
    int drained=0;
    for(unsigned i=0;i<200;++i){pid_t orphan=waitpid(-1,&status,WNOHANG);if(orphan<0&&errno==ECHILD){drained=1;break;}
        if(orphan<0&&errno!=EINTR)break;if(!orphan){struct timespec pause={0,10000000};nanosleep(&pause,NULL);}}
    check(drained);
    struct pair pair={-1,-1};check(!make_pair(AF_INET,0,&pair)&&exchange(&pair));if(pair.client>=0)close(pair.client);if(pair.peer>=0)close(pair.peer);
    pair.client=pair.peer=-1;check(!make_pair(AF_INET6,0,&pair)&&exchange(&pair));if(pair.client>=0)close(pair.client);if(pair.peer>=0)close(pair.peer);
    printf("{\"event\":\"private-bus-parent\",\"checks\":%u,\"failures\":%u,\"unrelated_internet_controls\":true}\n",checks,failures);return failures?2:0;
}
