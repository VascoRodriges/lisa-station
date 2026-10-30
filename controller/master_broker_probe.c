/* Standalone GET-only hardware lab. OWN client only; never a vendor launcher,
 * SDK adapter, boot hook, PCM endpoint or production mode controller. */
#define _GNU_SOURCE
#include <dirent.h>
#include <fcntl.h>
#include <grp.h>
#include <inttypes.h>
#include <limits.h>
#include <poll.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/ptrace.h>
#include <sys/resource.h>
#include <sys/statvfs.h>
#include <sys/sysmacros.h>
#include <sys/wait.h>
#include <time.h>
#include "master_read_protocol.h"
#include "master_read_guard.h"
#include "hardvolume_mixer.h"
#include "platform_storage.h"
#ifndef __arm__
#error This filesystem and real hardware composition requires the reviewed ARM ABI
#endif
#define MASTER_GROUP 57347u
static unsigned checks,failures;
static void check(int good){++checks;if(!good)++failures;}
#define DENIED(c) do{errno=0;long outcome=(c);check(outcome==-1&&errno==EPERM);}while(0)
static uint64_t milliseconds(void){struct timespec value;if(clock_gettime(CLOCK_MONOTONIC,&value))return 0;return (uint64_t)value.tv_sec*1000+(unsigned)value.tv_nsec/1000000;}
static int packet(int fd,void *data,size_t size,int writing,uint64_t end){
    for(;;){uint64_t now=milliseconds();if(!now||now>=end)return -1;
        struct pollfd ready={fd,writing?POLLOUT:POLLIN,0};int n=poll(&ready,1,(int)(end-now));
        if(n<0&&errno==EINTR)continue;if(n!=1)return -1;
        ssize_t used=writing?write(fd,data,size):read(fd,data,size);
        if(used<0&&(errno==EINTR||errno==EAGAIN||errno==EWOULDBLOCK))continue;
        return used<0?-1:(int)used;
    }
}
static int close_except(const int *keep,unsigned count){
    DIR *list=opendir("/proc/self/fd");if(!list)return -1;int own=dirfd(list),bad=0;struct dirent *entry;
    while((entry=readdir(list))){char *end;long fd=strtol(entry->d_name,&end,10);if(*end||fd<0||fd==own)continue;
        unsigned retained=0;for(unsigned i=0;i<count;++i)retained|=fd==keep[i];if(!retained&&close((int)fd)&&errno!=EBADF)bad=1;
    }if(closedir(list))bad=1;return bad?-1:0;
}
static int isolate(const char *root,const char *image){
    if(unshare(CLONE_NEWNS)||mount(NULL,"/",NULL,MS_REC|MS_PRIVATE,NULL)||mount("tmpfs",root,"tmpfs",MS_NOSUID|MS_NODEV,"size=1m,mode=755"))return -1;
    const char *dirs[]={"/lib","/usr","/usr/lib","/opt","/opt/lisa","/dev"};
    for(unsigned i=0;i<sizeof(dirs)/sizeof(dirs[0]);++i)if(diagnostics_directory(root,dirs[i]))return -1;
    if(diagnostics_bind(root,"/lib","/lib",0,0)||diagnostics_bind(root,"/usr/lib","/usr/lib",0,0)||
        diagnostics_text(root,"/master-read.marker","MASTER_READ_V1\n")||diagnostics_text(root,"/opt/lisa/actor","")||
        platform_storage_bind_file(root,image,"/opt/lisa/actor",1)||diagnostics_bind(root,"/dev/null","/dev/null",1,1)||
        mount(NULL,root,NULL,MS_REMOUNT|MS_RDONLY|MS_NOSUID|MS_NODEV,NULL)||chroot(root)||chdir("/"))return -1;
    return 0;
}
static int identity(void){
    if(setgroups(0,NULL)||setgid(MASTER_GROUP))return -1;
    for(unsigned cap=0;cap<64;++cap){int present=prctl(PR_CAPBSET_READ,cap,0,0,0);
        if(present<0){if(errno==EINVAL)break;return -1;}if(present&&prctl(PR_CAPBSET_DROP,cap,0,0,0))return -1;}
    struct __user_cap_header_struct header={_LINUX_CAPABILITY_VERSION_3,0};struct __user_cap_data_struct caps[2]={{0}};
    return syscall(SYS_capset,&header,caps)||prctl(PR_SET_NO_NEW_PRIVS,1,0,0,0)?-1:0;
}
static int epoch_decode(const char *text,unsigned char epoch[MASTER_EPOCH_BYTES]){
    if(strlen(text)!=2*MASTER_EPOCH_BYTES)return -1;
    for(unsigned i=0;i<MASTER_EPOCH_BYTES;++i){unsigned value=0;
        for(unsigned j=0;j<2;++j){char byte=text[2*i+j];unsigned part=byte>='0'&&byte<='9'?(unsigned)(byte-'0'):byte>='a'&&byte<='f'?(unsigned)(byte-'a'+10):16;
            if(part>15)return -1;value=value*16+part;}epoch[i]=(unsigned char)value;
    }return master_epoch_valid(epoch)?0:-1;
}
static int hardware_read(int fd,unsigned *control_id,unsigned *level,unsigned *calls){
    struct stat info;int flags=fcntl(fd,F_GETFL);
    if(fstat(fd,&info)||!S_ISCHR(info.st_mode)||major(info.st_rdev)!=116||minor(info.st_rdev)||flags<0||(flags&O_ACCMODE)!=O_RDONLY){errno=EPERM;return -1;}
    struct snd_ctl_elem_info before={0},after={0};hardvolume_mixer_id(&before.id);
    if(ioctl(fd,SNDRV_CTL_IOCTL_ELEM_INFO,&before))return -1;++*calls;
    if(!before.id.numid||(*control_id&&before.id.numid!=*control_id)||!hardvolume_mixer_compatible(&before)){errno=EPROTO;return -1;}
    struct snd_ctl_elem_value value={0};value.id=before.id;if(ioctl(fd,SNDRV_CTL_IOCTL_ELEM_READ,&value))return -1;++*calls;
    after.id=before.id;if(ioctl(fd,SNDRV_CTL_IOCTL_ELEM_INFO,&after))return -1;++*calls;
    if(!hardvolume_mixer_compatible(&after)||after.id.numid!=before.id.numid||value.value.integer.value[0]<0||value.value.integer.value[0]>255){errno=EPROTO;return -1;}
    *control_id=before.id.numid;*level=(unsigned)value.value.integer.value[0];return 0;
}
struct actor_report {uint32_t magic;unsigned phase,role,checks,failures,reads,ioctls,rejected,closed;unsigned values[2];};
static int report(struct actor_report *value,unsigned phase){value->magic=0x4d525031u;value->phase=phase;value->checks=checks;value->failures=failures;return write(2,value,sizeof(*value))==(ssize_t)sizeof(*value)?0:-1;}
static int caps_zero(void){
    struct __user_cap_header_struct header={_LINUX_CAPABILITY_VERSION_3,0};struct __user_cap_data_struct caps[2];
    if(syscall(SYS_capget,&header,caps))return 0;
    for(unsigned i=0;i<2;++i)if(caps[i].effective||caps[i].permitted||caps[i].inheritable)return 0;
    for(unsigned i=0;i<64;++i){int present=prctl(PR_CAPBSET_READ,i,0,0,0);if(present<0)return errno==EINVAL;
        if(present||prctl(PR_CAP_AMBIENT,PR_CAP_AMBIENT_IS_SET,i,0,0))return 0;}
    return 0;
}
static int actor(int peer,int control,pid_t parent,unsigned role,unsigned mode,const unsigned char *epoch,unsigned control_id){
    checks=failures=0;struct actor_report result={.role=role};struct statvfs fs;int death=0;
    check(getppid()==parent&&getgid()==MASTER_GROUP&&!getuid()&&!geteuid()&&getgroups(0,NULL)==0);
    check(prctl(PR_GET_NO_NEW_PRIVS,0,0,0,0)==1&&prctl(PR_GET_SECCOMP,0,0,0,0)==2);
    check(caps_zero());
    check(!prctl(PR_GET_PDEATHSIG,&death,0,0,0)&&death==SIGKILL&&master_peer_valid(peer,parent));
    check(!statvfs("/",&fs)&&(fs.f_flag&ST_RDONLY));
    struct stat hidden;errno=0;check(lstat("/dev/snd",&hidden)<0&&errno==ENOENT);
    DENIED(socket(AF_INET,SOCK_STREAM,0));DENIED(socket(AF_UNIX,SOCK_STREAM,0));DENIED(syscall(SYS_fork));
    DENIED(prctl(PR_SET_PDEATHSIG,0,0,0,0));
    DENIED(syscall(SYS_ioctl,control,(unsigned long)SNDRV_CTL_IOCTL_ELEM_WRITE,NULL));
    DENIED(syscall(SYS_ioctl,control,(unsigned long)SNDRV_CTL_IOCTL_ELEM_REMOVE,NULL));
    DENIED(syscall(SYS_ioctl,control,(unsigned long)SNDRV_CTL_IOCTL_ELEM_ADD,NULL));
    DENIED(syscall(SYS_ioctl,peer,(unsigned long)SNDRV_CTL_IOCTL_ELEM_READ,NULL));
    struct msghdr message={0};DENIED(sendmsg(peer,&message,0));DENIED(recvmsg(peer,&message,0));
    if(failures||report(&result,1))return 9;
    uint64_t end=milliseconds()+3000;int good=1;
    if(!role){struct master_read_session session;if(master_session_init(&session,epoch))return 9;
        while(!session.closed){unsigned char request[MASTER_REQUEST_BYTES+1];int got=packet(peer,request,sizeof(request),0,end);
            if(!got){master_session_fault(&session);break;}
            if(got<0){good=0;master_session_fault(&session);break;}
            if(master_session_accept(&session,request,(size_t)got)){result.rejected=1;master_session_fault(&session);break;}
            unsigned value=0,error=0;if(hardware_read(control,&control_id,&value,&result.ioctls)){error=(unsigned)errno;if(!error||error>4095)error=EIO;good=0;}
            if(result.reads<2)result.values[result.reads]=value;++result.reads;
            unsigned char reply[MASTER_REPLY_BYTES];
            if(master_reply_encode(epoch,session.completed+1,error,value,reply,sizeof(reply))||packet(peer,reply,sizeof(reply),1,end)!=(int)sizeof(reply)||master_session_complete(&session)){good=0;master_session_fault(&session);break;}
            if(mode==7&&result.reads==1&&report(&result,2)){good=0;master_session_fault(&session);break;}
            if(error)master_session_fault(&session);
        }
    }else{
        unsigned count=mode==7?1:2;
        for(unsigned sequence=1;sequence<=count;++sequence){unsigned char request[MASTER_REQUEST_BYTES],reply[MASTER_REPLY_BYTES+1];struct master_read_value value;
            if(master_request_encode(epoch,sequence,request,sizeof(request))||packet(peer,request,sizeof(request),1,end)!=(int)sizeof(request)||
                packet(peer,reply,sizeof(reply),0,end)!=MASTER_REPLY_BYTES||master_reply_decode(reply,MASTER_REPLY_BYTES,epoch,sequence,&value)||value.error){good=0;break;}
            result.values[result.reads++]=value.value;
        }
        if(good&&mode==7){if(report(&result,2))good=0;else{unsigned char reply[MASTER_REPLY_BYTES+1];if(packet(peer,reply,sizeof(reply),0,end)!=0)good=0;}}
        else if(good&&mode){unsigned char invalid[MASTER_REQUEST_BYTES+1];master_request_encode(epoch,mode==1?1:3,invalid,MASTER_REQUEST_BYTES);size_t size=MASTER_REQUEST_BYTES;
            if(mode==2)invalid[8]^=1;else if(mode==3)master_put32(invalid+28,2);else if(mode==4){invalid[size++]=0;}else if(mode==5)--size;else if(mode==6)invalid[32]=1;
            unsigned char reply[MASTER_REPLY_BYTES+1];if(packet(peer,invalid,size,1,end)!=(int)size||packet(peer,reply,sizeof(reply),0,end)!=0)good=0;else result.rejected=1;
        }
    }
    if(close(peer))good=0;else{errno=0;if(fcntl(peer,F_GETFD)>=0||errno!=EBADF)good=0;else result.closed=1;}
    if(control>=3&&close(control))good=0;
    check(good);if(report(&result,3))return 9;return failures?9:0;
}
struct actor_handle {pid_t pid;int report;unsigned role;char root[PATH_MAX];struct stat peer,control,pipe,image;int peer_fd,control_fd;};
static int private_view(const struct actor_handle *actor,int executed){
    char path[PATH_MAX],line[256];struct stat actual,own;struct statvfs fs;
    snprintf(path,sizeof(path),"/proc/%ld/ns/mnt",(long)actor->pid);if(stat(path,&actual)||stat("/proc/self/ns/mnt",&own)||actual.st_ino==own.st_ino)return 0;
    snprintf(path,sizeof(path),"/proc/%ld/root",(long)actor->pid);if(statvfs(path,&fs)||!(fs.f_flag&ST_RDONLY)||!(fs.f_flag&ST_NOSUID)||!(fs.f_flag&ST_NODEV)||(uint64_t)fs.f_blocks*fs.f_frsize>1024u*1024)return 0;
    const char *hidden[]={"/proc","/sys","/data","/bkupgrade","/tmp","/dev/snd","/dev/shm","/var/run/dbus"};
    for(unsigned i=0;i<sizeof(hidden)/sizeof(hidden[0]);++i){snprintf(path,sizeof(path),"/proc/%ld/root%s",(long)actor->pid,hidden[i]);if(!lstat(path,&actual)||errno!=ENOENT)return 0;}
    snprintf(path,sizeof(path),"/proc/%ld/exe",(long)actor->pid);if(stat(path,&actual)||actual.st_dev!=actor->image.st_dev||actual.st_ino!=actor->image.st_ino)return 0;
    snprintf(path,sizeof(path),"/proc/%ld/fd",(long)actor->pid);DIR *list=opendir(path);if(!list)return 0;struct dirent *entry;unsigned count=0;int good=1;
    while((entry=readdir(list))){char *end;long fd=strtol(entry->d_name,&end,10);if(*end||fd<0)continue;++count;
        snprintf(path,sizeof(path),"/proc/%ld/fd/%ld",(long)actor->pid,fd);if(stat(path,&actual)){good=0;break;}
        const struct stat *expected=fd==2?&actor->pipe:fd==actor->peer_fd?&actor->peer:fd==actor->control_fd?&actor->control:NULL;
        if(fd<2){if(!S_ISCHR(actual.st_mode)||major(actual.st_rdev)!=1||minor(actual.st_rdev)!=3){good=0;break;}}
        else if(!expected||actual.st_dev!=expected->st_dev||actual.st_ino!=expected->st_ino){good=0;break;}
        if(fd==actor->control_fd){snprintf(path,sizeof(path),"/proc/%ld/fdinfo/%ld",(long)actor->pid,fd);FILE *info=fopen(path,"r");unsigned flags=UINT_MAX;
            if(!info){good=0;break;}while(fgets(line,sizeof(line),info))if(sscanf(line,"flags:\t%o",&flags)==1)break;fclose(info);
            if(flags==UINT_MAX||(flags&O_ACCMODE)!=O_RDONLY){good=0;break;}}
    }closedir(list);if(!good||count!=(actor->role?4u:5u))return 0;
    snprintf(path,sizeof(path),"/proc/%ld/status",(long)actor->pid);FILE *status=fopen(path,"r");if(!status)return 0;
    unsigned caps=0,uid=0,gid=0,groups=0,seccomp=0;
    while(fgets(line,sizeof(line),status)){unsigned long long value;unsigned a,b,c,d;
        if(sscanf(line,"CapInh: %llx",&value)==1||sscanf(line,"CapPrm: %llx",&value)==1||sscanf(line,"CapEff: %llx",&value)==1||sscanf(line,"CapBnd: %llx",&value)==1||sscanf(line,"CapAmb: %llx",&value)==1){++caps;if(value)good=0;}
        if(sscanf(line,"Gid: %u %u %u %u",&a,&b,&c,&d)==4)gid=a==MASTER_GROUP&&a==b&&a==c&&a==d;
        if(sscanf(line,"Uid: %u %u %u %u",&a,&b,&c,&d)==4)uid=!a&&!b&&!c&&!d;
        if(!strncmp(line,"Groups:",7)){char *p=line+7;while(*p==' '||*p=='\t')++p;groups=*p=='\n';}
        if(sscanf(line,"Seccomp: %u",&a)==1)seccomp=a;
    }if(ferror(status))good=0;fclose(status);return good&&caps==5&&uid&&gid&&groups&&(!executed||seccomp==2);
}
static int receive_report(struct actor_handle *actor,struct actor_report *result,unsigned phase){
    size_t used=0;uint64_t end=milliseconds()+4000;
    while(used<sizeof(*result)){int n=packet(actor->report,(char *)result+used,sizeof(*result)-used,0,end);if(n<=0)return -1;used+=(size_t)n;}
    return result->magic==0x4d525031u&&result->role==actor->role&&result->phase==phase&&result->checks>=15&&!result->failures?0:-1;
}
static int start_actor(const char *base,const char *image,unsigned index,int peer,int control,unsigned role,unsigned mode,const char *epoch,unsigned control_id,struct actor_handle *handle){
    *handle=(struct actor_handle){.pid=-1,.report=-1,.role=role,.peer_fd=peer,.control_fd=control};
    if(snprintf(handle->root,sizeof(handle->root),"%s/root%u",base,index)>=(int)sizeof(handle->root)||mkdir(handle->root,0700)||
        fstat(peer,&handle->peer)||(control>=3&&fstat(control,&handle->control))||stat(image,&handle->image))return -1;
    int reports[2];if(pipe2(reports,O_CLOEXEC)||fstat(reports[0],&handle->pipe))return -1;pid_t parent=getpid(),child=fork();if(child<0)return -1;
    if(!child){
        if(prctl(PR_SET_PDEATHSIG,SIGKILL)||getppid()!=parent)_exit(80);
        char path[PATH_MAX],temporary[PATH_MAX],text[96];struct process_stamp stamp;
        if(process_stamp(getpid(),&stamp)||snprintf(path,sizeof(path),"%s.child",handle->root)>=(int)sizeof(path)||snprintf(temporary,sizeof(temporary),"%s.child.new",handle->root)>=(int)sizeof(temporary))_exit(80);
        int output=open(temporary,O_WRONLY|O_CREAT|O_EXCL|O_NOFOLLOW|O_CLOEXEC,0600);int n=snprintf(text,sizeof(text),"%ld %" PRIu64 "\n",(long)getpid(),stamp.ticks);
        if(output<0||store_write_all(output,text,(size_t)n)||fsync(output)||close(output)||rename(temporary,path))_exit(80);
        int zero=open("/dev/null",O_RDWR|O_CLOEXEC);if(zero<0||dup2(zero,0)<0||dup2(zero,1)<0||dup2(reports[1],2)<0)_exit(81);
        int keep[]={0,1,2,peer,control};unsigned count=control>=3?5:4;
        if(close_except(keep,count)||isolate(handle->root,image)||clearenv()||identity()||prctl(PR_SET_PDEATHSIG,SIGKILL)||getppid()!=parent)_exit(82);
        struct rlimit cpu={2,3},data={32u*1024*1024,32u*1024*1024},files={64,64},core={0,0};
        if(setrlimit(RLIMIT_CPU,&cpu)||setrlimit(RLIMIT_AS,&data)||setrlimit(RLIMIT_NOFILE,&files)||setrlimit(RLIMIT_CORE,&core))_exit(83);
        for(unsigned i=0;i<count;++i)if(fcntl(keep[i],F_SETFD,0))_exit(83);
        if(ptrace(PTRACE_TRACEME,0,NULL,NULL)||raise(SIGSTOP))_exit(84);
        if(master_read_guard(peer,parent,control))_exit(85);
        char a[24],b[24],c[24],d[8],e[8],f[16];snprintf(a,sizeof(a),"%d",peer);snprintf(b,sizeof(b),"%d",control);snprintf(c,sizeof(c),"%ld",(long)parent);snprintf(d,sizeof(d),"%u",role);snprintf(e,sizeof(e),"%u",mode);snprintf(f,sizeof(f),"%u",control_id);
        execl("/opt/lisa/actor","master-read-actor","--actor",a,b,c,d,e,epoch,f,(char *)NULL);_exit(86);
    }
    close(reports[1]);handle->pid=child;handle->report=reports[0];int status=0;pid_t done;
    do{done=waitpid(child,&status,0);}while(done<0&&errno==EINTR);
    if(done!=child||!WIFSTOPPED(status)||WSTOPSIG(status)!=SIGSTOP||!private_view(handle,0))return -1;
    if(ptrace(PTRACE_SETOPTIONS,child,NULL,(void *)(PTRACE_O_EXITKILL|PTRACE_O_TRACEEXEC))||ptrace(PTRACE_CONT,child,NULL,NULL))return -1;
    do{done=waitpid(child,&status,0);}while(done<0&&errno==EINTR);
    return done==child&&WIFSTOPPED(status)&&WSTOPSIG(status)==SIGTRAP&&(unsigned)status>>16==PTRACE_EVENT_EXEC&&private_view(handle,1)?0:-1;
}
static int finish_actor(struct actor_handle *handle,int killed,struct actor_report *result){
    int good=killed||!receive_report(handle,result,3);int status=0;pid_t done;
    do{done=waitpid(handle->pid,&status,0);}while(done<0&&errno==EINTR);
    if(done==handle->pid&&WIFSTOPPED(status)){kill(handle->pid,SIGKILL);ptrace(PTRACE_CONT,handle->pid,NULL,(void *)(intptr_t)SIGKILL);waitpid(handle->pid,&status,0);good=0;}
    if(done!=handle->pid||(killed?(!WIFSIGNALED(status)||WTERMSIG(status)!=SIGKILL):(!WIFEXITED(status)||WEXITSTATUS(status))))good=0;
    char byte;int n=packet(handle->report,&byte,1,0,milliseconds()+1000);if(n||close(handle->report)||rmdir(handle->root))good=0;
    handle->pid=-1;handle->report=-1;return good?0:-1;
}
static int same_image(pid_t pid,const char *source);
static int scope_absent(const char *source);
static int run(const char *base,const char *image){
    int total_good=1;unsigned before_checks=checks,inspection_checks=0;
#define INSPECT(c) do{++inspection_checks;if(!(c))return -1;}while(0)
    INSPECT(same_image(getpid(),image)==0);INSPECT(same_image(getppid(),image)==1);INSPECT(scope_absent(image)==0);
    for(unsigned mode=0;mode<8;++mode){unsigned char epoch[MASTER_EPOCH_BYTES];int random=open("/dev/urandom",O_RDONLY|O_CLOEXEC);if(random<0)return -1;
        ssize_t n=read(random,epoch,sizeof(epoch));int closed=close(random);if(n!=(ssize_t)sizeof(epoch)||closed||!master_epoch_valid(epoch))return -1;
        char token[2*MASTER_EPOCH_BYTES+1];for(unsigned i=0;i<MASTER_EPOCH_BYTES;++i)snprintf(token+2*i,3,"%02x",epoch[i]);
        int peer[2],control=open("/dev/snd/controlC0",O_RDONLY|O_NOFOLLOW|O_CLOEXEC);struct stat identity;
        if(control<3||fstat(control,&identity)||!S_ISCHR(identity.st_mode)||identity.st_uid||major(identity.st_rdev)!=116||minor(identity.st_rdev)||socketpair(AF_UNIX,SOCK_SEQPACKET|SOCK_CLOEXEC,0,peer))return -1;
        unsigned control_id=0,level=0,control_calls=0;if(hardware_read(control,&control_id,&level,&control_calls)||control_calls!=3)return -1;
        struct actor_handle server,client;struct actor_report a={0},b={0};
        int good=!start_actor(base,image,2*mode,peer[0],control,0,mode,token,control_id,&server);
        if(good){INSPECT(same_image(server.pid,image)==0);INSPECT(scope_absent(image)==1);}
        if(good&&(ptrace(PTRACE_CONT,server.pid,NULL,NULL)||receive_report(&server,&a,1)))good=0;
        if(good&&start_actor(base,image,2*mode+1,peer[1],-1,1,mode,token,0,&client))good=0;
        if(good)INSPECT(same_image(client.pid,image)==0);
        int sources_closed=!close(peer[0]);if(close(peer[1]))sources_closed=0;if(close(control))sources_closed=0;
        for(unsigned i=0;i<3;++i){int fd=i==2?control:peer[i];errno=0;if(fcntl(fd,F_GETFD)>=0||errno!=EBADF)sources_closed=0;}
        if(!sources_closed)return -1;
        if(!good)return -1;
        if(ptrace(PTRACE_CONT,client.pid,NULL,NULL)||receive_report(&client,&b,1))return -1;
        if(mode==7){if(receive_report(&client,&b,2)||receive_report(&server,&a,2)||b.reads!=1||a.reads!=1||a.ioctls!=3||a.values[0]!=b.values[0]||kill(server.pid,SIGKILL))return -1;}
        int client_done=finish_actor(&client,0,&b),server_done=finish_actor(&server,mode==7,&a);if(client_done||server_done)return -1;
        if(mode==7)good=b.reads==1&&a.reads==1&&a.ioctls==3&&a.values[0]==b.values[0]&&b.closed;
        else good=a.reads==2&&a.ioctls==6&&b.reads==2&&a.closed&&b.closed&&a.values[0]==b.values[0]&&a.values[1]==b.values[1]&&a.rejected==(mode!=0)&&b.rejected==(mode!=0);
        check(good);if(!good)total_good=0;
        printf("{\"event\":\"master-read-epoch\",\"case\":%u,\"ok\":%s,\"backend_checks\":%u,\"client_checks\":%u,\"reads\":%u,\"ioctl_reads\":%u,\"malformed_rejected\":%s,\"backend_killed\":%s,\"client_closed\":%s,\"backend_admitted\":true,\"client_admitted\":true,\"sources_closed\":true,\"values_agree\":%s,\"views_released\":true,\"pcm_opened\":false}\n",
            mode,good?"true":"false",a.checks,b.checks,b.reads,a.ioctls,mode&&mode!=7?"true":"false",mode==7?"true":"false",b.closed?"true":"false",good?"true":"false");fflush(stdout);
    }
    INSPECT(scope_absent(image)==0);
#undef INSPECT
    int network=socket(AF_INET,SOCK_STREAM|SOCK_CLOEXEC,0);check(network>=0);if(network>=0)close(network);
    printf("{\"selftest\":\"master-read-broker\",\"checks\":%u,\"inspection_checks\":%u,\"failures\":%u,\"ok\":%s,\"own_client_only\":true,\"unrelated_socket_creation\":%s,\"audio_opened\":false,\"production_changed\":false}\n",checks-before_checks,inspection_checks,failures,total_good&&!failures?"true":"false",network>=0?"true":"false");fflush(stdout);
    return total_good&&!failures?0:-1;
}
/* Read-only cleanup inspection: no hardware, signals, state deletion or actor
 * admission. The shell combines same-image with the committed PID/start tick.
 * Compare inodes because an exec through a bind mount has a different path. */
static int inspection_source(const char *path,struct stat *info){
    const char prefix[]="/bkupgrade/data/opt/lisa-controller-lab/master-read-probe-";
    if(getuid()||geteuid()||strncmp(path,prefix,sizeof(prefix)-1)||strlen(path)!=sizeof(prefix)-1+16)return -1;
    for(size_t i=sizeof(prefix)-1;path[i];++i)if(!((path[i]>='0'&&path[i]<='9')||(path[i]>='a'&&path[i]<='f')))return -1;
    int fd=open(path,O_RDONLY|O_NOFOLLOW|O_CLOEXEC);if(fd<0)return -1;
    int good=!fstat(fd,info)&&S_ISREG(info->st_mode)&&!info->st_uid&&info->st_nlink==1&&(info->st_mode&07777)==0700&&info->st_size>0;
    if(close(fd))good=0;return good?0:-1;
}
static int scope_absent(const char *source){
    struct stat expected,actual;if(inspection_source(source,&expected))return 2;
    DIR *list=opendir("/proc");if(!list)return 2;int result=0;struct dirent *entry;
    for(;;){errno=0;entry=readdir(list);if(!entry){if(errno)result=2;break;}
        char *end;long pid=strtol(entry->d_name,&end,10);if(*end||pid<=1||pid==getpid()||pid>INT_MAX)continue;
        char path[80];snprintf(path,sizeof(path),"/proc/%ld/exe",pid);
        if(!stat(path,&actual)){if(actual.st_dev==expected.st_dev&&actual.st_ino==expected.st_ino){result=1;break;}}
        else if(errno!=ENOENT&&errno!=ESRCH){result=2;break;}
    }if(closedir(list))result=2;return result;
}
static int same_image(pid_t pid,const char *source_path){
    struct stat source,actual;if(pid<=1||inspection_source(source_path,&source))return 2;
    char path[80];snprintf(path,sizeof(path),"/proc/%ld/exe",(long)pid);
    if(stat(path,&actual))return errno==ENOENT||errno==ESRCH?1:2;
    return source.st_dev==actual.st_dev&&source.st_ino==actual.st_ino?0:1;
}
int main(int argc,char **argv){
    if(argc==3&&!strcmp(argv[1],"--scope-absent"))return scope_absent(argv[2]);
    if(argc==4&&!strcmp(argv[1],"--same-image")){char *end;errno=0;long pid=strtol(argv[2],&end,10);
        if(*end||errno||pid<=1||pid>INT_MAX)return 2;return same_image((pid_t)pid,argv[3]);
    }
    if(argc==9&&!strcmp(argv[1],"--actor")){long values[5];for(unsigned i=0;i<5;++i){char *end;errno=0;values[i]=strtol(argv[i+2],&end,10);if(*end||errno||values[i]>INT_MAX)return 2;}
        char *end;errno=0;unsigned long control_id=strtoul(argv[8],&end,10);if(*end||errno||control_id>UINT_MAX)return 2;
        unsigned char epoch[MASTER_EPOCH_BYTES];if(values[0]<3||(values[1]!=-1&&values[1]<3)||values[2]<=1||values[3]<0||values[3]>1||values[4]<0||values[4]>7||
            (values[3]?(values[1]!=-1||control_id):(values[1]<3||!control_id))||epoch_decode(argv[7],epoch))return 2;
        return actor((int)values[0],(int)values[1],(pid_t)values[2],(unsigned)values[3],(unsigned)values[4],epoch,(unsigned)control_id);
    }
    if(argc!=3||strcmp(argv[1],"--run")||getuid()||geteuid()||getgid()||getegid())return 2;
    const char *base=argv[2],prefix[]="/bkupgrade/data/opt/lisa-controller-lab/master-read.";size_t length=strlen(base);
    if(strncmp(base,prefix,sizeof(prefix)-1)||length<sizeof(prefix)+5||length>sizeof(prefix)+15)return 2;
    for(size_t i=sizeof(prefix)-1;i<length;++i)if(!((base[i]>='0'&&base[i]<='9')||(base[i]>='A'&&base[i]<='Z')||(base[i]>='a'&&base[i]<='z')))return 2;
    struct stat info;if(lstat(base,&info)||!S_ISDIR(info.st_mode)||info.st_uid||(info.st_mode&07777)!=0700)return 2;
    const char *production[]={"/bkupgrade/data/opt/lisa-station/state","/run/lisa-station"};for(unsigned i=0;i<2;++i)if(!lstat(production[i],&info)||errno!=ENOENT)return 2;
    pid_t parent=getppid();if(parent<=1||prctl(PR_SET_PDEATHSIG,SIGKILL)||getppid()!=parent)return 2;alarm(40);signal(SIGPIPE,SIG_IGN);
    char image[PATH_MAX];ssize_t n=readlink("/proc/self/exe",image,sizeof(image)-1);if(n<=0||n>=(ssize_t)sizeof(image)-1)return 2;image[n]=0;
    char stamp_path[PATH_MAX],temporary[PATH_MAX],text[96];struct process_stamp stamp;
    if(process_stamp(getpid(),&stamp)||snprintf(stamp_path,sizeof(stamp_path),"%s/native.driver",base)>=(int)sizeof(stamp_path)||
        snprintf(temporary,sizeof(temporary),"%s/native.driver.new",base)>=(int)sizeof(temporary))return 2;
    int output=open(temporary,O_WRONLY|O_CREAT|O_EXCL|O_NOFOLLOW|O_CLOEXEC,0600);int used=snprintf(text,sizeof(text),"%ld %" PRIu64 "\n",(long)getpid(),stamp.ticks);
    if(output<0||store_write_all(output,text,(size_t)used)||fsync(output)||close(output)||rename(temporary,stamp_path))return 2;
    return run(base,image)?2:0;
}
