/* Real shell, private mount namespace/chroot, synthetic init scripts only.
 * No actual init script, network service, hardware or audio device is invoked. */
#define _GNU_SOURCE
#include <linux/capability.h>
#include <linux/audit.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <stddef.h>
#include <sys/syscall.h>
#include "boot_runner.h"
#include "boot_dispatch.h"
#include "diagnostics_guard.h"

static unsigned checks;
#define CHECK(condition) do { ++checks; if(!(condition)) { fprintf(stderr,"boot-dispatch-check:%u\n",checks); return 4; } } while(0)
static int fixture_stage(const char *flag) {
    const char *allowed[]={"--bootstrap","--hardware-start","--diagnostics-stage","--time-start","--dns-start","--vendor-start"};
    unsigned i=0; while(i<6&&strcmp(flag,allowed[i])) ++i;
    if(i==6) return 90;
    int fd=open("/run/trace",O_WRONLY|O_CREAT|O_APPEND|O_CLOEXEC,0600);
    if(fd<0) return 91;
    int failed=store_write_all(fd,flag,strlen(flag))||store_write_all(fd,"\n",1)||close(fd);
    if(failed) return 91;
    if(i==0&&access("/run/hang-bootstrap",F_OK)==0) { for(;;) pause(); }
    if(i==0&&access("/run/fail-bootstrap",F_OK)==0) return 1;
    if(i!=0&&access("/run/fail-gates",F_OK)==0) return 1;
    return 0;
}
static int fixture_runner(const char *flag) {
    char *const args[]={"boot-dispatch-fixture","--fixture-stage",(char*)flag,NULL};
    return boot_run("/bkupgrade/data/opt/lisa-station/bin/station-boot",args,150)==BOOT_RUN_OK?0:1;
}
static int fixture_case(const char *root,const char *self,unsigned mode) {
    if(unshare(CLONE_NEWNS)||mount(NULL,"/",NULL,MS_REC|MS_PRIVATE,NULL)||
        mount("tmpfs",root,"tmpfs",MS_NOSUID|MS_NODEV,"size=8m,mode=700")) return 10;
    const char *dirs[]={"/lib","/usr","/usr/lib","/bin","/dev","/proc","/etc","/etc/init.d","/run",
        "/bkupgrade","/bkupgrade/data","/bkupgrade/data/opt","/bkupgrade/data/opt/lisa-station","/bkupgrade/data/opt/lisa-station/bin"};
    for(unsigned i=0;i<sizeof(dirs)/sizeof(dirs[0]);++i) if(diagnostics_directory(root,dirs[i])) return 11;
    if(diagnostics_bind(root,"/lib","/lib",0,0)||diagnostics_bind(root,"/usr/lib","/usr/lib",0,0)||
        diagnostics_bind(root,"/dev/null","/dev/null",1,1)||
        diagnostics_bind(root,"/proc","/proc",0,0)||
        diagnostics_bind(root,self,"/bkupgrade/data/opt/lisa-station/bin/station-boot",1,0)) return 12;
    if(mode!=2&&diagnostics_bind(root,self,"/bkupgrade/data/opt/lisa-station/bin/station-init",1,0)) return 12;
    /* The firmware BusyBox has a set-ID bit. Use a private plain executable
     * copy for this fixture; never relax the production helper's set-ID check. */
    char shell[PATH_MAX]; snprintf(shell,sizeof(shell),"%s/bin/sh",root);
    int input=open("/bin/sh",O_RDONLY|O_CLOEXEC),output=open(shell,O_WRONLY|O_CREAT|O_EXCL|O_CLOEXEC,0700);
    if(input<0||output<0) return 12;
    char buffer[8192]; ssize_t count;
    while((count=read(input,buffer,sizeof(buffer)))>0) if(store_write_all(output,buffer,(size_t)count)) return 12;
    if(count<0||close(input)||close(output)) return 12;
    const char *gated[]={"/etc/init.d/S46hardvold","/etc/init.d/S47alsa-audio-monitor","/etc/init.d/S49chrony","/etc/init.d/S70unbound","/etc/init.d/S99quasar"};
    for(unsigned i=0;i<5;++i)
        if(diagnostics_text(root,gated[i],"#!/bin/sh\necho ORIGINAL_VENDOR_RAN >> /run/trace\n")) return 13;
    if(diagnostics_text(root,"/etc/init.d/S00fixture.sh","echo SYSTEM:$1 >> /run/trace\nlisa_fixture_leak=1\n")||
        diagnostics_text(root,"/etc/init.d/S01fixture.sh","[ -z \"$lisa_fixture_leak\" ] && echo SOURCE_ISOLATED >> /run/trace\n")||
        diagnostics_text(root,"/etc/init.d/S99zdropbear","#!/bin/sh\necho RECOVERY:$1 >> /run/trace\n")||
        diagnostics_text(root,"/etc/init.d/rcS",lisa_boot_dispatch)) return 13;
    char path[PATH_MAX];
    for(unsigned i=0;i<5;++i) {
        snprintf(path,sizeof(path),"%s%s",root,gated[i]); if(chmod(path,0700)) return 14;
    }
    snprintf(path,sizeof(path),"%s/etc/init.d/S99zdropbear",root); if(chmod(path,0700)) return 14;
    if(mode==1&&diagnostics_text(root,"/run/fail-bootstrap","")) return 15;
    if(mode==3&&diagnostics_text(root,"/run/fail-gates","")) return 15;
    if(mode==4&&diagnostics_text(root,"/run/hang-bootstrap","")) return 15;
    if(chroot(root)||chdir("/")) return 16;
    char *const args[]={"sh","/etc/init.d/rcS",NULL};
    enum boot_run_result shell_result=boot_run("/bin/sh",args,4000);
    if(shell_result!=BOOT_RUN_OK) { fprintf(stderr,"fixture-shell-result:%d\n",shell_result); return 17; }
    char actual[2048]; int fd=open("/run/trace",O_RDONLY|O_CLOEXEC);
    if(fd<0) return 18;
    ssize_t bytes=read(fd,actual,sizeof(actual)-1); close(fd);
    if(bytes<0||bytes==(ssize_t)sizeof(actual)-1) return 18;
    actual[bytes]=0;
    const char *normal="--bootstrap\nSYSTEM:start\nSOURCE_ISOLATED\nRECOVERY:start\n--hardware-start\n--diagnostics-stage\n--time-start\n--dns-start\n--vendor-start\nRECOVERY:start\n";
    const char *closed="--bootstrap\nSYSTEM:start\nSOURCE_ISOLATED\nRECOVERY:start\nRECOVERY:start\n";
    const char *missing="SYSTEM:start\nSOURCE_ISOLATED\nRECOVERY:start\nRECOVERY:start\n";
    return strcmp(actual,mode==2?missing:(mode==1||mode==4)?closed:normal)?19:0;
}
int main(int argc,char **argv) {
    if(argc==3&&!strcmp(argv[1],"--fixture-stage")) return fixture_stage(argv[2]);
    if(argc==2&&!strncmp(argv[1],"--",2)) return fixture_runner(argv[1]);
    if(argc!=1||geteuid()) return 2;
    alarm(20);
    char self[PATH_MAX],root[]="/data/opt/lisa-controller-lab/boot-dispatch.XXXXXX";
    ssize_t size=readlink("/proc/self/exe",self,sizeof(self)-1); CHECK(size>0&&size<(ssize_t)sizeof(self)-1); self[size]=0;
    CHECK(mkdtemp(root)!=NULL);
    for(unsigned mode=0;mode<5;++mode) {
        pid_t child=fork(); CHECK(child>=0);
        if(!child) _exit(fixture_case(root,self,mode));
        int status; CHECK(waitpid(child,&status,0)==child);
        if(!WIFEXITED(status)||WEXITSTATUS(status)) fprintf(stderr,"case:%u:status:%d\n",mode,WIFEXITED(status)?WEXITSTATUS(status):-1);
        if(!WIFEXITED(status)||WEXITSTATUS(status)) (void)rmdir(root);
        CHECK(WIFEXITED(status)&&WEXITSTATUS(status)==0);
    }
    CHECK(!rmdir(root));
    printf("{\"selftest\":\"boot-dispatch\",\"checks\":%u,\"cases\":5,\"ok\":true,\"real_init_changed\":false,\"audio_opened\":false}\n",checks);
    return 0;
}
