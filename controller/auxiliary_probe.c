/* Own actors only. No hardware, microphone, vendor or network configuration. */
#define _GNU_SOURCE
#include "hardvolume_guard.h"
#include "hardvolume_mixer.h"
static unsigned checks;
#define CHECK(x) do{++checks;if(!(x)){fprintf(stderr,"check %u line %d: %s\n",checks,__LINE__,#x);return 1;}}while(0)
static int fixture_prepare(void){return prctl(PR_SET_NO_NEW_PRIVS,1,0,0,0)||prctl(PR_GET_NO_NEW_PRIVS,0,0,0,0)!=1||hardvolume_filter();}
static int fixture_absent(const struct guardian_record *r){return r->child<2||!process_live(r->child,r->child_ticks);}
static int fixture_observe(pid_t pid){
    char path[64],line[256];snprintf(path,sizeof(path),"/proc/%ld/status",(long)pid);
    FILE *file=fopen(path,"r");if(!file)return -1;int nnp=1,seccomp=0;
    while(fgets(line,sizeof(line),file)){unsigned value;if(sscanf(line,"NoNewPrivs: %u",&value)==1)nnp=value==1;
        if(sscanf(line,"Seccomp: %u",&value)==1)seccomp=value==2;}
    fclose(file);return nnp&&seccomp?0:-1;
}
static int filter_checks(void){
    if(fixture_prepare())return 1;
    const int families[]={AF_INET,AF_INET6,AF_UNIX,AF_NETLINK,AF_PACKET};
    for(unsigned i=0;i<sizeof(families)/sizeof(families[0]);++i){errno=0;if(socket(families[i],SOCK_DGRAM,0)!=-1||errno!=EPERM)return 2;}
    errno=0;if(syscall(SYS_fork)!=-1||errno!=EPERM)return 3;
    errno=0;if(setgid(getgid())!=-1||errno!=EPERM)return 4;
    errno=0;if(syscall(SYS_clock_settime,CLOCK_REALTIME,NULL)!=-1||errno!=EPERM)return 5;
    errno=0;if(syscall(SYS_ptrace,0,0,NULL,NULL)!=-1||errno!=EPERM)return 6;
    errno=0;if(kill(getpid(),0)!=-1||errno!=EPERM)return 7;
    errno=0;if(syscall(SYS_process_vm_readv,getpid(),NULL,0,NULL,0,0)!=-1||errno!=EPERM)return 8;
    return 0;
}
static int reap(pid_t pid){int status;return waitpid(pid,&status,0)==pid&&WIFEXITED(status)&&!WEXITSTATUS(status);}
int main(int argc,char **argv){
    if(argc==2&&!strcmp(argv[1],"--fixture")){for(;;)pause();}
    if(argc!=1)return 2;
    struct snd_ctl_elem_info mixer={0};hardvolume_mixer_id(&mixer.id);
    mixer.type=SNDRV_CTL_ELEM_TYPE_INTEGER;mixer.count=1;mixer.owner=-1;
    mixer.access=SNDRV_CTL_ELEM_ACCESS_USER|SNDRV_CTL_ELEM_ACCESS_READWRITE;mixer.value.integer.max=255;
    CHECK(hardvolume_mixer_compatible(&mixer));
    struct snd_ctl_elem_info bad=mixer;bad.access&=~SNDRV_CTL_ELEM_ACCESS_USER;CHECK(!hardvolume_mixer_compatible(&bad));
    bad=mixer;bad.access|=SNDRV_CTL_ELEM_ACCESS_LOCK;CHECK(!hardvolume_mixer_compatible(&bad));
    bad=mixer;bad.owner=1234;CHECK(!hardvolume_mixer_compatible(&bad));
    bad=mixer;bad.count=2;CHECK(!hardvolume_mixer_compatible(&bad));
    bad=mixer;bad.type=SNDRV_CTL_ELEM_TYPE_ENUMERATED;CHECK(!hardvolume_mixer_compatible(&bad));
    bad=mixer;bad.value.integer.max=100;CHECK(!hardvolume_mixer_compatible(&bad));
    bad=mixer;bad.value.integer.min=1;CHECK(!hardvolume_mixer_compatible(&bad));
    bad=mixer;bad.value.integer.step=1;CHECK(!hardvolume_mixer_compatible(&bad));
    bad=mixer;strcpy((char*)bad.id.name,"SY6045S Master Playback Volume");CHECK(!hardvolume_mixer_compatible(&bad));
    bad=mixer;bad.id.device=1;CHECK(!hardvolume_mixer_compatible(&bad));
    bad=mixer;bad.id.subdevice=1;CHECK(!hardvolume_mixer_compatible(&bad));
    bad=mixer;bad.id.index=1;CHECK(!hardvolume_mixer_compatible(&bad));
    bad=mixer;bad.id.iface=SNDRV_CTL_ELEM_IFACE_CARD;CHECK(!hardvolume_mixer_compatible(&bad));
    pid_t own=fork();CHECK(own>=0);if(!own)_exit(filter_checks());CHECK(reap(own));
    char self[PATH_MAX];ssize_t size=readlink("/proc/self/exe",self,sizeof(self)-1);
    CHECK(size>0&&size<(ssize_t)sizeof(self)-1);self[size]=0;
    char root[]="/tmp/lisa-auxiliary.XXXXXX";CHECK(mkdtemp(root)!=NULL);
    int runtime=open(root,O_RDONLY|O_DIRECTORY|O_CLOEXEC);CHECK(runtime>=0);
    const char boot[]="11111111-2222-4333-8444-555555555555";uid_t owner=geteuid();
    char *const args[]={self,"--fixture",NULL};
    struct guardian_spec spec={.role="hardware",.executable=self,.argv=args,.prepare=fixture_prepare,
        .observe=fixture_observe,.actors_absent=fixture_absent,.maximum_seconds=8};
    struct guardian_started first,repeat;struct guardian_record observed;
    CHECK(auxiliary_status(runtime,owner,boot,&spec,&observed)==GUARD_RECOVERY);
    CHECK(auxiliary_start(runtime,owner,boot,&spec,&first)==GUARD_OK);
    CHECK(first.result==GUARD_OK);
    CHECK(auxiliary_status(runtime,owner,boot,&spec,&observed)==GUARD_OK);
    CHECK(observed.child==first.record.child&&observed.child_ticks==first.record.child_ticks);
    CHECK(auxiliary_start(runtime,owner,boot,&spec,&repeat)==GUARD_OK);
    CHECK(repeat.result==GUARD_OK&&repeat.record.guardian==first.record.guardian&&repeat.record.child==first.record.child);
    CHECK(auxiliary_status(runtime,owner,"21111111-2222-4333-8444-555555555555",&spec,&observed)==GUARD_RECOVERY);
    CHECK(process_live(first.record.child,first.record.child_ticks));
    CHECK(guardian_stop(runtime,owner,boot,&spec)==GUARD_OK);
    CHECK(reap(first.record.guardian));
    CHECK(!process_live(first.record.child,first.record.child_ticks));
    CHECK(auxiliary_status(runtime,owner,boot,&spec,&observed)==GUARD_RECOVERY);
    CHECK(auxiliary_start(runtime,owner,boot,&spec,&repeat)==GUARD_OK);
    CHECK(repeat.record.child!=first.record.child);
    /* Kill only this probe's own unreaped guardian; its child must die too. */
    siginfo_t pending={0};CHECK(!waitid(P_PID,repeat.record.guardian,&pending,WEXITED|WNOHANG|WNOWAIT)&&!pending.si_pid);
    CHECK(!kill(repeat.record.guardian,SIGKILL));int status;CHECK(waitpid(repeat.record.guardian,&status,0)==repeat.record.guardian);
    for(unsigned i=0;i<100&&process_live(repeat.record.child,repeat.record.child_ticks);++i){struct timespec delay={0,10000000};nanosleep(&delay,NULL);}
    CHECK(!process_live(repeat.record.child,repeat.record.child_ticks));
    CHECK(auxiliary_start(runtime,owner,boot,&spec,&first)==GUARD_OK);
    CHECK(guardian_stop(runtime,owner,boot,&spec)==GUARD_OK);CHECK(reap(first.record.guardian));
    int fd=openat(runtime,"hardware.child",O_WRONLY|O_TRUNC|O_CLOEXEC);CHECK(fd>=0);
    CHECK(!store_write_all(fd,"bad\n",4));CHECK(!close(fd));
    CHECK(auxiliary_start(runtime,owner,boot,&spec,&first)==GUARD_RECOVERY);
    CHECK(!unlinkat(runtime,"hardware.child",0));
    signal(SIGCHLD,SIG_IGN);CHECK(auxiliary_start(runtime,owner,boot,&spec,&first)==GUARD_DENIED);signal(SIGCHLD,SIG_DFL);
    CHECK(!unlinkat(runtime,"hardware.start-lock",0));CHECK(!close(runtime));CHECK(!rmdir(root));
    printf("{\"selftest\":\"auxiliary-supervisor\",\"checks\":%u,\"ok\":true,\"hardware_changed\":false,\"audio_opened\":false}\n",checks);
    return 0;
}
