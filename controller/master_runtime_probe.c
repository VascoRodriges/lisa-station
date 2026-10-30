/* Own dynamic-loader fixture with an explicitly synthetic packet provider.
 * Same separate ALSA translation unit as the hardware lab, no hardware/SDK. */
#define _GNU_SOURCE
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>
#include "master_plugin_actor.h"
#include "master_read_protocol.h"
static const unsigned char tag[MASTER_EPOCH_BYTES]={1};
int main(int argc,char **argv){
    if(argc!=2)return 2;
    alarm(20);signal(SIGPIPE,SIG_IGN);
    for(unsigned mode=0;mode<3;++mode){int peer[2];if(socketpair(AF_UNIX,SOCK_SEQPACKET,0,peer))return 2;
        pid_t child=fork();if(child<0)return 2;
        if(!child){alarm(5);signal(SIGPIPE,SIG_DFL);close(peer[0]);struct master_plugin_actor actor={0};
            if(master_actor_begin(&actor,argv[1],peer[1],tag))_exit(3);
            unsigned value=999;int result=master_actor_get(&actor,&value);
            if(mode==0?(result||value!=173):(result!=(mode==1?-EIO:-EPIPE)||value))_exit(4);
            if(master_actor_end(&actor))_exit(5);
            _exit(0);
        }
        close(peer[1]);unsigned char request[MASTER_REQUEST_BYTES+1],reply[MASTER_REPLY_BYTES];
        if(mode<2){ssize_t n=read(peer[0],request,sizeof(request));if(n!=MASTER_REQUEST_BYTES||master_request_decode(request,(size_t)n,tag,1))return 6;
            if(master_reply_encode(tag,1,mode==1?EIO:0,mode==1?0:173,reply,sizeof(reply))||write(peer[0],reply,sizeof(reply))!=(ssize_t)sizeof(reply))return 7;
        }
        close(peer[0]);int status;pid_t done;do{done=waitpid(child,&status,0);}while(done<0&&errno==EINTR);
        if(done!=child||!WIFEXITED(status)||WEXITSTATUS(status))return 8;
    }
    puts("{\"selftest\":\"master-runtime-loader\",\"cases\":3,\"ok\":true,\"synthetic_provider\":true,\"hardware_opened\":false,\"sdk_executed\":false}");return 0;
}
