/* Fixed own-executable test. No vendor service, microphone, real log contents,
 * firewall or interface configuration is changed. Synthetic log bytes only. */
#define _GNU_SOURCE
#include <grp.h>
#include <pwd.h>
#include <dlfcn.h>
#include <linux/audit.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <stddef.h>
#include <sys/syscall.h>
#include <sys/sysmacros.h>
#include "startup_guardian.h"
#include "vendor_identity.h"
#include "diagnostics_guard.h"

struct result { unsigned checks,failed; uint64_t failure_mask; unsigned bus_error; };
static void observe(struct result *r,int ok) {
    if(!ok&&r->checks<64) r->failure_mask|=1ull<<r->checks;
    ++r->checks; r->failed+=!ok;
}
static int bus_smoke(struct result *r) {
    void *library=dlopen("libdbus-1.so.3",RTLD_NOW|RTLD_LOCAL);
    if(!library) { r->bus_error=1; return 0; }
    void (*init)(void*)=dlsym(library,"dbus_error_init");
    void (*free_error)(void*)=dlsym(library,"dbus_error_free");
    int (*has_name)(const void*,const char*)=dlsym(library,"dbus_error_has_name");
    void *(*get)(int,void*)=dlsym(library,"dbus_bus_get_private");
    void (*close_bus)(void*)=dlsym(library,"dbus_connection_close");
    void (*unref)(void*)=dlsym(library,"dbus_connection_unref");
    if(!init||!free_error||!has_name||!get||!close_bus||!unref) { r->bus_error=2; return 0; }
    /* Reserved aligned storage for the published DBusError ABI. Inspect only
     * standard error names through the API; never export error message text. */
    union { max_align_t alignment; unsigned char bytes[128]; } error={0};
    init(error.bytes); void *connection=get(1,error.bytes);
    if(connection) { close_bus(connection); unref(connection); }
    else {
        const char *names[]={"FileNotFound","AccessDenied","AuthFailed","NoServer","BadAddress","Failed","NoMemory","NotSupported","Disconnected","IOError"};
        r->bus_error=99;
        for(unsigned i=0;i<sizeof(names)/sizeof(names[0]);++i) {
            char name[96]; snprintf(name,sizeof(name),"org.freedesktop.DBus.Error.%s",names[i]);
            if(has_name(error.bytes,name)) r->bus_error=10+i;
        }
    }
    free_error(error.bytes); return connection!=NULL;
}
static int actor(int report,int control) {
    struct result r={0}; struct stat info; struct statvfs filesystem;
    /* Refuse the synthetic writer unless already inside the narrow jail. */
    if(lstat("/proc/self",&info)!=-1||errno!=ENOENT||stat("/dev/kmsg",&info)||!S_ISREG(info.st_mode)) return 3;
    observe(&r,!statvfs("/",&filesystem)&&(filesystem.f_flag&ST_RDONLY));
    observe(&r,getuid()==0&&geteuid()==0&&getgid()==57343&&getegid()==57343);
    struct passwd *user=getpwuid(0); struct group *group=getgrgid(57343);
    observe(&r,user&&!strcmp(user->pw_name,"root")&&user->pw_gid==57343);
    observe(&r,group&&!strcmp(group->gr_name,"lisa-diagnostics"));
    observe(&r,prctl(PR_GET_NO_NEW_PRIVS,0,0,0,0)==1);
    struct __user_cap_header_struct header={_LINUX_CAPABILITY_VERSION_3,0}; struct __user_cap_data_struct caps[2];
    int valid=!syscall(SYS_capget,&header,caps);
    uint64_t mask=diagnostics_forbidden_caps();
    observe(&r,valid&&!(((uint64_t)(caps[0].effective|caps[0].permitted|caps[0].inheritable)|
        ((uint64_t)(caps[1].effective|caps[1].permitted|caps[1].inheritable)<<32))&mask));
    const int forbidden[]={CAP_SYS_ADMIN,CAP_SYS_CHROOT,CAP_SYSLOG,CAP_MKNOD,CAP_NET_ADMIN,CAP_NET_RAW,CAP_SYS_PTRACE};
    for(unsigned i=0;i<sizeof(forbidden)/sizeof(forbidden[0]);++i)
        observe(&r,prctl(PR_CAPBSET_READ,forbidden[i],0,0,0)==0);
    const int families[]={AF_INET,AF_INET6,AF_NETLINK,AF_PACKET};
    for(unsigned i=0;i<sizeof(families)/sizeof(families[0]);++i) {
        errno=0; int fd=socket(families[i],SOCK_DGRAM|SOCK_CLOEXEC,0);
        observe(&r,fd==-1&&errno==EPERM); if(fd>=0) close(fd);
    }
    errno=0; int route=socket(AF_NETLINK,SOCK_RAW|SOCK_CLOEXEC,NETLINK_ROUTE);
    observe(&r,route==-1&&errno==EPERM); if(route>=0) close(route);
    int generic=socket(AF_NETLINK,SOCK_RAW|SOCK_CLOEXEC,NETLINK_GENERIC);
    observe(&r,generic==-1&&errno==EPERM); if(generic>=0) close(generic);
    int bus=socket(AF_UNIX,SOCK_STREAM|SOCK_CLOEXEC,0);
    observe(&r,bus>=0); if(bus>=0) close(bus);
    int pair[2];
    int paired=socketpair(AF_UNIX,SOCK_STREAM|SOCK_CLOEXEC,0,pair);
    observe(&r,!paired); if(!paired) { close(pair[0]); close(pair[1]); }
    errno=0; paired=socketpair(AF_INET,SOCK_STREAM|SOCK_CLOEXEC,0,pair);
    observe(&r,paired==-1&&errno==EPERM); if(!paired) { close(pair[0]); close(pair[1]); }
    errno=0; observe(&r,syscall(SYS_syslog,10,NULL,0)==-1&&errno==EPERM);
    errno=0; observe(&r,chroot(".")==-1&&errno==EPERM);
    errno=0; observe(&r,unshare(CLONE_NEWNS)==-1&&errno==EPERM);
    errno=0; observe(&r,mount(NULL,"/",NULL,MS_REMOUNT,NULL)==-1&&errno==EPERM);
    errno=0; observe(&r,mknod("/escape-kmsg",S_IFCHR|0600,makedev(1,11))==-1&&errno==EPERM);
    errno=0; observe(&r,syscall(SYS_open_by_handle_at,-1,NULL,0)==-1&&errno==EPERM);
    const char *hidden[]={"/sys","/tmp/messages","/data/quasar/data","/system/vendor/quasar/quasar.cfg","/dev/snd",
        "/proc/self/root","/proc/kmsg"};
    for(unsigned i=0;i<sizeof(hidden)/sizeof(hidden[0]);++i)
        observe(&r,lstat(hidden[i],&info)==-1&&errno==ENOENT);
    errno=0; int executable=open("/usr/bin/alsa-audio-monitord",O_WRONLY|O_CLOEXEC);
    /* An executing ELF can be rejected before the readonly-filesystem check.
     * Verify both actual refusal and the target mount's readonly property. */
    observe(&r,executable==-1&&!statvfs("/usr/bin/alsa-audio-monitord",&filesystem)&&(filesystem.f_flag&ST_RDONLY));
    if(executable>=0) close(executable);
    const char text[]="lisa-synthetic-log\n";
    int file=open("/dev/kmsg",O_WRONLY|O_APPEND|O_CLOEXEC);
    observe(&r,file>=0&&!store_write_all(file,text,sizeof(text)-1)); if(file>=0) close(file);
    file=open("/data/quasar/daemons_logs/probe.log",O_WRONLY|O_CREAT|O_EXCL|O_CLOEXEC,0600);
    observe(&r,file>=0&&!store_write_all(file,text,sizeof(text)-1)); if(file>=0) close(file);
    observe(&r,bus_smoke(&r));
    /* Metadata only: never read, initialize or resize the real RMS object. */
    observe(&r,!lstat(DIAGNOSTICS_SHARED,&info)&&diagnostics_shared_valid(&info));
    observe(&r,!statvfs(DIAGNOSTICS_SHARED,&filesystem)&&!(filesystem.f_flag&ST_RDONLY)&&
        (filesystem.f_flag&ST_NOSUID)&&(filesystem.f_flag&ST_NODEV)&&(filesystem.f_flag&ST_NOEXEC));
    struct stat sample=info;
    sample.st_size++; observe(&r,!diagnostics_shared_valid(&sample)); sample=info;
    sample.st_mode=S_IFLNK|0640; observe(&r,!diagnostics_shared_valid(&sample)); sample=info;
    sample.st_mode|=0002; observe(&r,!diagnostics_shared_valid(&sample)); sample=info;
    sample.st_uid=1; observe(&r,!diagnostics_shared_valid(&sample)); sample=info;
    sample.st_nlink=2; observe(&r,!diagnostics_shared_valid(&sample));
    if(write(report,&r,sizeof(r))!=sizeof(r)) return 4;
    struct pollfd ready={control,POLLIN,0}; char command;
    return poll(&ready,1,4000)==1&&read(control,&command,1)==1&&command=='X'&&!r.failed?0:4;
}
int main(int argc,char **argv) {
    if(geteuid()) return 2;
    if(argc==4&&!strcmp(argv[1],"--guard-actor")) {
        char *end; long report=strtol(argv[2],&end,10); if(*end||report<3||report>1024) return 2;
        long control=strtol(argv[3],&end,10); if(*end||control<3||control>1024||report==control) return 2;
        return actor((int)report,(int)control);
    }
    if(argc!=2||strcmp(argv[1],"--selftest")) return 2;
    umask(077); alarm(20); signal(SIGPIPE,SIG_IGN);
    char root[]="/data/opt/lisa-controller-lab/diagnostics-guard.XXXXXX",executable[PATH_MAX];
    ssize_t size=readlink("/proc/self/exe",executable,sizeof(executable)-1);
    if(size<=0||size>=(ssize_t)sizeof(executable)-1||!mkdtemp(root)) return 3;
    executable[size]=0;
    int channel[2],commands[2]; if(pipe2(channel,O_CLOEXEC)||pipe2(commands,O_CLOEXEC)) return 3;
    pid_t parent=getpid(),child=fork();
    if(!child) {
        alarm(15);
        if(prctl(PR_SET_PDEATHSIG,SIGKILL)||getppid()!=parent) _exit(79);
        close(channel[0]); close(commands[1]);
        int keep[]={channel[1],commands[0]};
        if(guardian_close_except(keep,2)) _exit(80);
        int null=open("/dev/null",O_RDWR|O_CLOEXEC);
        if(null<0) _exit(81);
        for(int fd=0;fd<3;++fd) if(dup2(null,fd)<0) _exit(81);
        if(null>2) close(null);
        if(clearenv()||setenv("DBUS_SYSTEM_BUS_ADDRESS","unix:path=/var/run/dbus/system_bus_socket",1)||
            diagnostics_isolate(root,executable)||vendor_identity_prepare(57343)||diagnostics_extra_guard()||
            prctl(PR_SET_PDEATHSIG,SIGKILL)||getppid()!=parent||fcntl(channel[1],F_SETFD,0)||fcntl(commands[0],F_SETFD,0)) _exit(82);
        char report[16],control[16]; snprintf(report,sizeof(report),"%d",channel[1]); snprintf(control,sizeof(control),"%d",commands[0]);
        char *const args[]={"diagnostics-guard-actor","--guard-actor",report,control,NULL};
        execv("/usr/bin/alsa-audio-monitord",args); _exit(83);
    }
    close(channel[1]); close(commands[0]);
    if(child<2) return 3;
    struct result r={0};
    if(!guardian_readable(channel[0],8000)||read(channel[0],&r,sizeof(r))!=sizeof(r)) { r.failed=1; }
    else {
        char child_path[PATH_MAX],self_namespace[128],child_namespace[128];
        snprintf(child_path,sizeof(child_path),"/proc/%ld/ns/mnt",(long)child);
        ssize_t a=readlink("/proc/self/ns/mnt",self_namespace,sizeof(self_namespace)),b=readlink(child_path,child_namespace,sizeof(child_namespace));
        observe(&r,a>0&&b>0&&(a!=b||memcmp(self_namespace,child_namespace,(size_t)a)));
        struct stat private_kmsg,real_kmsg,private_binary,real_binary;
        snprintf(child_path,sizeof(child_path),"/proc/%ld/root/dev/kmsg",(long)child);
        observe(&r,!stat(child_path,&private_kmsg)&&S_ISREG(private_kmsg.st_mode)&&!stat("/dev/kmsg",&real_kmsg)&&S_ISCHR(real_kmsg.st_mode));
        snprintf(child_path,sizeof(child_path),"/proc/%ld/root/usr/bin/alsa-audio-monitord",(long)child);
        observe(&r,!stat(child_path,&private_binary)&&!stat(executable,&real_binary)&&
            private_binary.st_dev==real_binary.st_dev&&private_binary.st_ino==real_binary.st_ino);
        snprintf(child_path,sizeof(child_path),"/proc/%ld/root%s",(long)child,DIAGNOSTICS_SHARED);
        struct stat shared,host_shared;
        observe(&r,!lstat(child_path,&shared)&&!lstat(DIAGNOSTICS_SHARED,&host_shared)&&
            shared.st_dev==host_shared.st_dev&&shared.st_ino==host_shared.st_ino);
    }
    if(write(commands[1],"X",1)!=1) r.failed=1;
    close(commands[1]); close(channel[0]); int status;
    observe(&r,waitpid(child,&status,0)==child&&WIFEXITED(status)&&WEXITSTATUS(status)==0);
    observe(&r,!rmdir(root));
    printf("{\"selftest\":\"diagnostics-guard\",\"checks\":%u,\"ok\":%s,\"failure_mask\":\"%016" PRIx64 "\",\"audio_opened\":false,"
        "\"vendor_processes_changed\":false,\"synthetic_logs_only\":true,\"bus_error_class\":%u}\n",r.checks,r.failed?"false":"true",r.failure_mask,r.bus_error);
    return r.failed?4:0;
}
