/* Kernel guard and SEQPACKET fixtures only: /dev/null is NOT ALSA hardware. */
#define _GNU_SOURCE
#include <dirent.h>
#include <fcntl.h>
#include <grp.h>
#include <limits.h>
#include <poll.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/statvfs.h>
#include <sys/uio.h>
#include <sys/wait.h>
#include "master_read_guard.h"
#include <sys/ioctl.h>
static unsigned checks,failures;
static void check(int good){++checks;if(!good){++failures;fprintf(stderr,"Master guard check %u errno %d\n",checks,errno);}}
#define DENIED(c) do{errno=0;long result=(c);check(result==-1&&errno==EPERM);}while(0)
int main(int argc,char **argv){
    if(argc!=2||strcmp(argv[1],"--selftest"))return 2;
    int zero=open("/dev/null",O_RDONLY|O_CLOEXEC);if(zero<3)return 2;
    for(unsigned mode=0;mode<2;++mode){int pair[2];if(socketpair(AF_UNIX,SOCK_SEQPACKET|SOCK_CLOEXEC,0,pair))return 2;
        pid_t parent=getpid(),child=fork();if(child<0)return 2;
        if(!child){checks=failures=0;close(pair[1]);check(master_peer_valid(pair[0],parent));
            int stream[2];check(!socketpair(AF_UNIX,SOCK_STREAM|SOCK_CLOEXEC,0,stream));
            check(!master_peer_valid(stream[0],parent));close(stream[0]);close(stream[1]);
            check(!master_read_guard(pair[0],parent,mode?zero:-1));if(failures)_exit(9);
            DENIED(socket(AF_INET,SOCK_STREAM,0));DENIED(socket(AF_UNIX,SOCK_STREAM,0));DENIED(socketpair(AF_UNIX,SOCK_STREAM,0,stream));
            DENIED(syscall(SYS_fork));DENIED(prctl(PR_SET_PDEATHSIG,0,0,0,0));
            DENIED(syscall(SYS_ioctl,zero,(unsigned long)SNDRV_CTL_IOCTL_ELEM_WRITE,NULL));
            DENIED(syscall(SYS_ioctl,zero,(unsigned long)SNDRV_CTL_IOCTL_ELEM_REMOVE,NULL));
            DENIED(syscall(SYS_ioctl,zero,(unsigned long)SNDRV_CTL_IOCTL_ELEM_ADD,NULL));
            DENIED(syscall(SYS_ioctl,pair[0],(unsigned long)SNDRV_CTL_IOCTL_ELEM_READ,NULL));
            for(unsigned i=0;i<2;++i){unsigned long command=i?SNDRV_CTL_IOCTL_ELEM_READ:SNDRV_CTL_IOCTL_ELEM_INFO;errno=0;
                int result=ioctl(zero,command,NULL);check(result==-1&&(mode?errno==ENOTTY:errno==EPERM));}
#ifdef __x86_64__
            DENIED(syscall(SYS_ioctl,zero,0x100000000ULL|(unsigned long)SNDRV_CTL_IOCTL_ELEM_READ,NULL));
#endif
            struct msghdr message={0};DENIED(sendmsg(pair[0],&message,0));DENIED(recvmsg(pair[0],&message,0));
            unsigned char packet[]={1,2,3};check(write(pair[0],packet,sizeof(packet))==(ssize_t)sizeof(packet));
            printf("{\"kind\":\"master-read-guard\",\"mode\":%u,\"checks\":%u,\"failures\":%u}\n",mode,checks,failures);fflush(stdout);_exit(failures?9:0);
        }
        close(pair[0]);int status=0;check(waitpid(child,&status,0)==child&&WIFEXITED(status)&&!WEXITSTATUS(status));
        unsigned char packet[4];check(read(pair[1],packet,sizeof(packet))==3&&packet[0]==1&&packet[1]==2&&packet[2]==3);
        close(pair[1]);
    }
    close(zero);return failures?1:0;
}
