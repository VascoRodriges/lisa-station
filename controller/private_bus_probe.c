/* Private standard-bus diagnostic, not a host-bus forwarder or SDK runner.
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
#include <stdlib.h>
#include <string.h>
#include <sys/statvfs.h>
#include <sys/wait.h>
#include <unistd.h>
#include "vendor_identity.h"
#include "platform_storage.h"
#include "platform_worker_guard.h"
#include "loopback_socket.h"
#include "bus_auth_gate.h"
#ifndef __arm__
#error This namespace diagnostic requires the reviewed ARM device ABI
#endif
static unsigned checks,failures;
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
static const char configuration[]=
    "<busconfig><type>session</type><listen>unix:path=/run/lisa/bus</listen><auth>EXTERNAL</auth>"
    "<limit name=\"max_incoming_bytes\">65536</limit><limit name=\"max_outgoing_bytes\">65536</limit>"
    "<limit name=\"max_message_size\">8192</limit><limit name=\"max_incoming_unix_fds\">1</limit>"
    "<limit name=\"max_outgoing_unix_fds\">1</limit><limit name=\"max_message_unix_fds\">1</limit>"
    "<limit name=\"auth_timeout\">2000</limit><limit name=\"max_completed_connections\">4</limit>"
    "<limit name=\"max_incomplete_connections\">4</limit><limit name=\"max_connections_per_user\">4</limit>"
    "<limit name=\"max_names_per_connection\">1</limit><limit name=\"max_match_rules_per_connection\">1</limit>"
    "<limit name=\"max_replies_per_connection\">4</limit><policy context=\"default\">"
    "<allow user=\"root\"/><deny own=\"*\"/><deny send_type=\"method_call\"/>"
    "<allow send_destination=\"org.freedesktop.DBus\" send_interface=\"org.freedesktop.DBus\" send_member=\"Hello\"/>"
    "<allow send_destination=\"org.freedesktop.DBus\" send_interface=\"org.freedesktop.DBus\" send_member=\"GetId\"/>"
    "<deny receive_sender=\"*\"/><allow receive_sender=\"org.freedesktop.DBus\"/></policy></busconfig>\n";
static int isolate(const char *root,const char *image,const char *binding){
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
        diagnostics_text(root,"/etc/private-bus.conf",configuration)||
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
static int private_view(pid_t pid,int listener_fd,const int reload[2],int before_exec){
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
            if(expected<3||stat(path,&a)||fstat(expected,&b)||!S_ISSOCK(a.st_mode)||a.st_dev!=b.st_dev||a.st_ino!=b.st_ino){safe=0;break;}
        }else if(stat(path,&a)||(!S_ISFIFO(a.st_mode)&&!S_ISCHR(a.st_mode))||(number==2&&!S_ISFIFO(a.st_mode))){safe=0;break;}++seen;
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
static int gated_auth(int fd,char guid[33]){
    /* An own in-memory client intentionally pipelines negotiation and BEGIN.
     * Only the real private daemon can supply OK; negotiation never reaches it.
     * This verifies the state machine, not an installed relay actor. */
    struct bus_auth_gate gate;uint64_t now=guardian_milliseconds();
    static const char request[]="\0AUTH EXTERNAL 30\r\nNEGOTIATE_UNIX_FD\r\nBEGIN\r\n";
    static const char initial[]="\0AUTH EXTERNAL 30\r\n";
    if(bus_auth_init(&gate,now)!=BUS_OK||bus_auth_feed(&gate,BUS_CLIENT,request,sizeof(request)-1,now)!=BUS_OK||
        gate.outgoing[BUS_BACKEND]!=sizeof(initial)-1||memcmp(gate.output[BUS_BACKEND],initial,sizeof(initial)-1))return -1;
    if(store_write_all(fd,(const char *)gate.output[BUS_BACKEND],gate.outgoing[BUS_BACKEND])||
        bus_auth_consume(&gate,BUS_BACKEND,gate.outgoing[BUS_BACKEND])!=BUS_OK)return -1;
    char response[128];if(line(fd,response,sizeof(response))||!bus_auth_ok_line(response))return -1;
    memcpy(guid,response+3,32);guid[32]=0;
    size_t size=strlen(response);memcpy(response+size,"\r\n",3);
    if(bus_auth_feed(&gate,BUS_BACKEND,response,size+2,guardian_milliseconds())!=BUS_OK||gate.phase!=BUS_BINARY||!gate.negotiated||
        gate.outgoing[BUS_BACKEND]!=7||memcmp(gate.output[BUS_BACKEND],"BEGIN\r\n",7))return -1;
    static const char disabled[]="ERROR Unix FD passing disabled\r\n";
    if(gate.outgoing[BUS_CLIENT]!=size+2+sizeof(disabled)-1||memcmp(gate.output[BUS_CLIENT],response,size+2)||
        memcmp(gate.output[BUS_CLIENT]+size+2,disabled,sizeof(disabled)-1))return -1;
    int result=store_write_all(fd,(const char *)gate.output[BUS_BACKEND],gate.outgoing[BUS_BACKEND]);
    bus_auth_close(&gate);return result;
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
static int run_epoch(const char *root,const char *executable,const char *binding,int listener_fd,const int reload[2],const char *endpoint,unsigned epoch,char guid[33]){
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
    int admitted=WIFSTOPPED(status)&&private_view(child,listener_fd,reload,1);check(admitted);
    if(admitted)check(!kill(child,SIGCONT));else kill(child,SIGKILL);
    int held=-1,client=-1;
    if(admitted&&epoch){
        char image[80];struct stat actual,expected;snprintf(image,sizeof(image),"/proc/%ld/exe",(long)child);int ready=0;
        if(!stat("/usr/bin/dbus-daemon",&expected))for(unsigned i=0;i<300;++i){
            if(!stat(image,&actual)&&actual.st_dev==expected.st_dev&&actual.st_ino==expected.st_ino){ready=1;break;}
            struct timespec pause={0,10000000};nanosleep(&pause,NULL);}
        check(ready);check(ready&&private_view(child,listener_fd,reload,0));
        if(ready)client=connect_bus(endpoint);check(client>=0);
        if(client>=0){
            char body[128]={0};check(!gated_auth(client,guid));check(strlen(guid)==32);
            check(!method(client,"Hello",1,0,body,sizeof(body))&&!strncmp(body,":1.",3));
            check(!method(client,"GetId",2,0,body,sizeof(body))&&strlen(body)==32);
            check(!method(client,"ListNames",3,1,body,sizeof(body)));
            check(!method(client,"ReloadConfig",4,1,body,sizeof(body)));
            held=dup(client);check(held>=0);close(client);client=-1;
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
    /* Bounded private stderr only; never a shared system log. */
    char log[8192];size_t bytes=0;ssize_t got;
    while(bytes<sizeof(log)&&(got=read(logs[0],log+bytes,sizeof(log)-bytes))>0)bytes+=(size_t)got;
    close(logs[0]);
    if(!epoch){
        static const char expected[]="{\"event\":\"private-bus-control\",\"checks\":15,\"failures\":0}\n";
        check(bytes==sizeof(expected)-1&&!memcmp(log,expected,bytes));
        if(bytes==sizeof(expected)-1&&!memcmp(log,expected,bytes))fputs(expected,stdout);
    }else if(bytes)fprintf(stderr,"epoch %u own private log: %.*s\n",epoch,(int)bytes,log);
    if(held>=0){
        unsigned drained=0;int eof=0;
        while(drained<8192){struct pollfd pending={held,POLLIN,0};char bytes[256];if(poll(&pending,1,1000)!=1)break;
            ssize_t count=read(held,bytes,sizeof(bytes));if(!count){eof=1;break;}if(count<0)break;drained+=(unsigned)count;}
        check(eof);close(held);
    }
    printf("{\"event\":\"private-bus-epoch\",\"epoch\":%u,\"checks\":%u,\"failures\":%u,\"actual_daemon\":%s,\"fd_negotiation_disabled\":false,\"auth_gate_verified\":%s}\n",epoch,checks,failures,epoch?"true":"false",epoch?"true":"false");fflush(stdout);
    return failures?-1:0;
}
static int coordinator(const char *base,const char *executable,const char *binding){
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
        char guid[33]={0};int result=run_epoch(root,executable,binding,listener_fd,reload,epoch?endpoint.sun_path:NULL,epoch,guid);
        if(listener_fd>=0){close(listener_fd);close(reload[0]);close(reload[1]);if(unlink(endpoint.sun_path))return 2;}
        if(result)return 2;
        if(epoch==2)check(strcmp(previous,guid)!=0);memcpy(previous,guid,sizeof(previous));
        if(rmdir(root))return 2;
    }
    printf("{\"selftest\":\"private-bus\",\"checks\":%u,\"failures\":%u,\"ok\":%s,\"sdk_executed\":false,\"audio_opened\":false,\"isolation_verified\":false}\n",checks,failures,failures?"false":"true");fflush(stdout);return failures?2:0;
}
int main(int argc,char **argv){
    if(argc==2&&!strcmp(argv[1],"--actor"))return own_actor();
    if(argc!=4||strcmp(argv[1],"--run")||getuid()||geteuid()||getgid()||getegid())return 2;
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
    if(!child){close(canary);int keep[]={0,1,2};if(close_except(keep,3))_exit(2);_exit(coordinator(base,executable,argv[3]));}
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
