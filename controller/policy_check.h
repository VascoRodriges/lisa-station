/* Read-only verification of a dedicated owner-only OUTPUT policy. This helper
 * never edits unrelated rules. Installation/ownership is the caller's job. */
#ifndef LISA_POLICY_CHECK_H
#define LISA_POLICY_CHECK_H
#include "startup_guardian.h"
#include "loopback_socket.h"

/* Own ephemeral sockets under the unrelated administrative identity. No
 * dependence on a firmware ping6 executable and no external endpoint. */
static inline int policy_control_socket(int family) {
    struct pair control={-1,-1};
    int ok=!make_pair(family,0,&control) && exchange(&control);
    if(control.client>=0) close(control.client);
    if(control.peer>=0) close(control.peer);
    return ok;
}

static inline int policy_capture(const char *program,char *const *argv,char *output,size_t capacity) {
    int channel[2];
    if(pipe2(channel,O_CLOEXEC)) return -1;
    pid_t parent=getpid(),child=fork();
    if(!child) {
        close(channel[0]);
        int null=open("/dev/null",O_RDWR|O_CLOEXEC);
        if(null<0 || setpgid(0,0) || prctl(PR_SET_PDEATHSIG,SIGKILL) || getppid()!=parent ||
            dup2(null,0)<0 || dup2(null,2)<0 || dup2(channel[1],1)<0 ||
            guardian_close_except(NULL,0) || clearenv()) _exit(80);
        execv(program,argv); _exit(81);
    }
    close(channel[1]);
    if(child<0) { close(channel[0]); return -1; }
    uint64_t deadline=guardian_milliseconds()+2500;
    size_t used=0; int eof=0,status=0,reaped=0;
    while(guardian_milliseconds()<deadline && used<capacity-1) {
        if(!guardian_readable(channel[0],100)) continue;
        ssize_t count=read(channel[0],output+used,capacity-1-used);
        if(count<0 && errno==EINTR) continue;
        if(count<0) break;
        if(!count) { eof=1; break; }
        used+=(size_t)count;
    }
    close(channel[0]); output[used]=0;
    while(guardian_milliseconds()<deadline) {
        pid_t waited=waitpid(child,&status,WNOHANG);
        if(waited==child) { reaped=1; break; }
        if(waited<0 && errno!=EINTR) return -1;
        struct timespec delay={0,10000000}; nanosleep(&delay,NULL);
    }
    if(!reaped) {
        /* Own unreaped verifier child; no PID from external metadata. */
        siginfo_t owned={0};
        if(waitid(P_PID,child,&owned,WEXITED|WNOHANG|WNOWAIT)) return -1;
        kill(child,SIGKILL);
        do { reaped=waitpid(child,&status,0)==child; } while(!reaped && errno==EINTR);
    }
    return eof && reaped && WIFEXITED(status) && !WEXITSTATUS(status)?0:-1;
}

static inline int policy_chain_read(int runtime,uid_t owner,char *chain,size_t capacity) {
    if(!store_directory_valid(runtime,owner) || capacity<32) return -1;
    int fd=openat(runtime,"policy.chain",O_RDONLY|O_NOFOLLOW|O_NONBLOCK|O_CLOEXEC);
    if(fd<0) return -1;
    if(!store_file_valid(fd,owner)) { close(fd); return -1; }
    ssize_t size=read(fd,chain,capacity-1); close(fd);
    const char prefix[]="LISACQ_";
    if(size<=(ssize_t)strlen(prefix)+1 || size>28 || memchr(chain,0,(size_t)size) || chain[size-1]!='\n') return -1;
    chain[size-1]=0;
    if(strncmp(chain,prefix,strlen(prefix))) return -1;
    for(char *at=chain+strlen(prefix);*at;++at)
        if(!((*at>='A'&&*at<='Z')||(*at>='0'&&*at<='9')||*at=='_')) return -1;
    return 0;
}

static inline int policy_group_denied(const char *chain,unsigned group) {
    const char *programs[]={"/usr/sbin/iptables","/usr/sbin/ip6tables"};
    for(unsigned i=0;i<2;++i) {
        char rules[8192],expected[512];
        char *name=i?"ip6tables":"iptables";
        /* Legacy xtables rejects -n with -S; rule specifications already
         * serialize --gid-owner as the numeric group on this firmware. */
        char *const own_args[]={name,"-S",(char*)chain,NULL};
        if(policy_capture(programs[i],own_args,rules,sizeof(rules))) return 0;
        snprintf(expected,sizeof(expected),"-N %s\n-A %s -m owner --gid-owner %u -j DROP\n",chain,chain,group);
        if(strcmp(rules,expected)) return 0;
        char *const output_args[]={name,"-S","OUTPUT",NULL};
        if(policy_capture(programs[i],output_args,rules,sizeof(rules)) || strncmp(rules,"-P OUTPUT ",10)) return 0;
        const char *first=strchr(rules,'\n');
        snprintf(expected,sizeof(expected),"-A OUTPUT -j %s\n",chain);
        if(!first || strncmp(first+1,expected,strlen(expected))) return 0;
    }
    return 1;
}
#endif
