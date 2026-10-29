/* Own ephemeral loopback sockets only. The driver installs an unused group
 * label before socket creation, then tests conntrack-mark denial after closure.
 * No vendor sockets, external addresses or microphone stream are accepted. */
#define _GNU_SOURCE
#include <grp.h>
#include "startup_guardian.h"
#include "socket_diag.h"
#include "loopback_socket.h"

#define LABEL_GID 57340
static unsigned checks,failed;
static const char *family_name,*transport;
static int check(const char *name,int ok) {
    ++checks; failed+=!ok;
    printf("{\"event\":\"label-check\",\"family\":\"%s\",\"protocol\":\"%s\",\"check\":\"%s\",\"ok\":%s}\n",
        family_name,transport,name,ok?"true":"false"); fflush(stdout); return ok;
}
static void event(const char *name) {
    printf("{\"event\":\"%s\",\"family\":\"%s\",\"protocol\":\"%s\"}\n",name,family_name,transport); fflush(stdout);
}
static int command(char expected) {
    struct pollfd ready={0,POLLIN,0}; char byte;
    return poll(&ready,1,7000)==1&&read(0,&byte,1)==1&&byte==expected;
}
static int readable(int fd,int timeout) {
    struct pollfd ready={fd,POLLIN,0}; return poll(&ready,1,timeout)==1&&!!(ready.revents&POLLIN);
}
static int quiet(int fd,int timeout) {
    struct pollfd ready={fd,POLLIN|POLLERR,0}; return poll(&ready,1,timeout)==0;
}
static unsigned port(int fd) {
    struct sockaddr_storage address; socklen_t length=sizeof(address);
    if(getsockname(fd,(struct sockaddr*)&address,&length)) return 0;
    return ntohs(address.ss_family==AF_INET?((struct sockaddr_in*)&address)->sin_port:((struct sockaddr_in6*)&address)->sin6_port);
}
static int make_target(int family,int type,int mapped,struct pair *target,int marked) {
    struct sockaddr_storage address={0}; socklen_t length;
    if(family==AF_INET) {
        struct sockaddr_in *a=(struct sockaddr_in*)&address;
        a->sin_family=AF_INET; a->sin_addr.s_addr=htonl(INADDR_LOOPBACK); length=sizeof(*a);
    } else {
        struct sockaddr_in6 *a=(struct sockaddr_in6*)&address;
        a->sin6_family=AF_INET6; length=sizeof(*a);
        if(inet_pton(AF_INET6,mapped?"::ffff:127.0.0.1":"::1",&a->sin6_addr)!=1) return -1;
    }
    int server=socket(family,type|SOCK_CLOEXEC,0);
    if(server<0) return -1;
    if(bind(server,(struct sockaddr*)&address,length)||getsockname(server,(struct sockaddr*)&address,&length)||
        (type==SOCK_STREAM&&listen(server,1))||(marked&&setegid(LABEL_GID))) { close(server); return -1; }
    int client=socket(family,type|SOCK_CLOEXEC,0),restored=!marked||!setegid(0);
    if(client<0||!restored) { if(client>=0) close(client); close(server); return -1; }
    if(type==SOCK_STREAM) {
        if(connect(client,(struct sockaddr*)&address,length)) { close(client); close(server); return -1; }
        int peer=accept4(server,NULL,NULL,SOCK_CLOEXEC); close(server);
        if(peer<0) { close(client); return -1; }
        *target=(struct pair){client,peer};
    } else {
        /* Leave the marked sender unconnected; the ordinary root peer is
         * connected only to observe ICMP errors after the sender closes. */
        struct sockaddr_storage local=address;
        if(family==AF_INET) ((struct sockaddr_in*)&local)->sin_port=0;
        else ((struct sockaddr_in6*)&local)->sin6_port=0;
        if(bind(client,(struct sockaddr*)&local,length)||getsockname(client,(struct sockaddr*)&local,&length)||
            connect(server,(struct sockaddr*)&local,length)) { close(client); close(server); return -1; }
        *target=(struct pair){client,server};
    }
    return 0;
}
static int udp_exchange(struct pair *p) {
    struct sockaddr_storage destination,source; socklen_t length=sizeof(destination),from=sizeof(source);
    char byte=0;
    if(getsockname(p->peer,(struct sockaddr*)&destination,&length)||sendto(p->client,"L",1,MSG_NOSIGNAL,(struct sockaddr*)&destination,length)!=1||
        !readable(p->peer,500)||recvfrom(p->peer,&byte,1,0,(struct sockaddr*)&source,&from)!=1||byte!='L'||
        sendto(p->peer,"R",1,MSG_NOSIGNAL,(struct sockaddr*)&source,from)!=1||!readable(p->client,500)||
        recv(p->client,&byte,1,0)!=1||byte!='R') return 0;
    return 1;
}
static int run(int family,int type,int mapped) {
    struct pair target={-1,-1},control={-1,-1}; int result=4;
    if(!check("baseline",!make_target(family,type,mapped,&target,1)&&!make_target(family,type,mapped,&control,0))) goto done;
    if(!check("open_exchange",(type==SOCK_STREAM?exchange(&target):udp_exchange(&target))&&
        (type==SOCK_STREAM?exchange(&control):udp_exchange(&control)))) goto done;
    unsigned source=port(target.client),destination=port(target.peer);
    printf("{\"event\":\"label-ready\",\"family\":\"%s\",\"protocol\":\"%s\",\"source_port\":%u,\"destination_port\":%u}\n",
        family_name,transport,source,destination); fflush(stdout);
    if(!source||!destination||source==destination||!command('b')) goto done;
    if(type==SOCK_STREAM) {
        struct inet_diag_sockid id; struct inet_diag_msg found;
        if(!check("own_socket_lookup",!socket_id(target.client,family,&id)&&!diag_exchange(family,&id,0,&found))) goto done;
        if(!check("own_socket_destroy",!diag_exchange(family,&found.id,1,NULL))) goto done;
        if(!check("reset_denied",quiet(target.peer,250))) goto done;
    } else {
        struct sockaddr_storage address; socklen_t length=sizeof(address);
        if(getsockname(target.peer,(struct sockaddr*)&address,&length)) goto done;
        errno=0; ssize_t sent=sendto(target.client,"B",1,MSG_NOSIGNAL,(struct sockaddr*)&address,length);
        if(!check("unconnected_send_denied",(sent==1||(sent<0&&(errno==EPERM||errno==EACCES)))&&quiet(target.peer,250))) goto done;
    }
    if(!check("unrelated_control_closed",type==SOCK_STREAM?exchange(&control):udp_exchange(&control))) goto done;
    event("label-closed");
    if(!command('o')) goto done;
    close(target.client); target.client=-1;
    if(!check("stray_to_closed_endpoint",send(target.peer,"O",1,MSG_NOSIGNAL)==1)) goto done;
    if(!check("kernel_reply_denied",quiet(target.peer,300))) goto done;
    if(!check("unrelated_control_orphan",type==SOCK_STREAM?exchange(&control):udp_exchange(&control))) goto done;
    event("label-orphan");
    if(!command('r')) goto done;
    int restored=0; char byte; errno=0;
    ssize_t sent=send(target.peer,"R",1,MSG_NOSIGNAL);
    if(sent<0&&(errno==ECONNRESET||errno==ECONNREFUSED)) restored=1;
    struct pollfd ready={target.peer,POLLIN|POLLERR,0};
    if(poll(&ready,1,1500)==1) {
        errno=0; ssize_t received=recv(target.peer,&byte,1,MSG_DONTWAIT);
        restored|=received<0&&(errno==ECONNRESET||errno==ECONNREFUSED);
    }
    if(!check("kernel_reply_after_lab_restore",restored)) goto done;
    if(!check("unrelated_control_restored",type==SOCK_STREAM?exchange(&control):udp_exchange(&control))) goto done;
    result=0;
done:
    if(target.client>=0) close(target.client);
    if(target.peer>=0) close(target.peer);
    if(control.client>=0) close(control.client);
    if(control.peer>=0) close(control.peer);
    return result;
}
int main(int argc,char **argv) {
    if(argc!=4||strcmp(argv[1],"--own-connmark")||geteuid()||getgid()||getegid()) return 2;
    int mapped=!strcmp(argv[2],"mapped"),family=!strcmp(argv[2],"4")?AF_INET:AF_INET6;
    if((family==AF_INET6&&!mapped&&strcmp(argv[2],"6"))||(strcmp(argv[3],"tcp")&&strcmp(argv[3],"udp"))) return 2;
    alarm(30); family_name=mapped?"ipv4-mapped-ipv6":family==AF_INET?"ipv4":"ipv6"; transport=argv[3];
    int result=run(family,!strcmp(transport,"tcp")?SOCK_STREAM:SOCK_DGRAM,mapped);
    printf("{\"event\":\"label-summary\",\"family\":\"%s\",\"protocol\":\"%s\",\"checks\":%u,\"failures\":%u,"
        "\"audio_opened\":false,\"vendor_processes_changed\":false}\n",family_name,transport,checks,failed);
    return result||failed;
}
