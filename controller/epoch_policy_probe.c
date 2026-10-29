/* Own ephemeral loopback traffic only. A driver changes its owned epoch policy
 * at checkpoints; no vendor PID, external destination or audio is accepted. */
#define _GNU_SOURCE
#include <grp.h>
#include "epoch_policy.h"

static unsigned checks,failures,old_epoch,new_epoch;
static const char *family_name,*protocol;
static int check(const char *name,int ok){
    ++checks;failures+=!ok;
    printf("{\"event\":\"epoch-check\",\"family\":\"%s\",\"protocol\":\"%s\",\"old_epoch\":%u,\"new_epoch\":%u,\"check\":\"%s\",\"ok\":%s}\n",
        family_name,protocol,old_epoch,new_epoch,name,ok?"true":"false");fflush(stdout);return ok;
}
static int readable(int fd,int milliseconds){struct pollfd ready={fd,POLLIN,0};return poll(&ready,1,milliseconds)==1&&!!(ready.revents&POLLIN);}
static int quiet(int fd){struct pollfd ready={fd,POLLIN|POLLERR,0};return poll(&ready,1,250)==0;}
static int command(char expected){char byte;return readable(0,7000)&&read(0,&byte,1)==1&&byte==expected;}
static unsigned port(int fd){
    struct sockaddr_storage address;socklen_t size=sizeof(address);
    if(getsockname(fd,(struct sockaddr*)&address,&size))return 0;
    return ntohs(address.ss_family==AF_INET?((struct sockaddr_in*)&address)->sin_port:((struct sockaddr_in6*)&address)->sin6_port);
}
static int pair_create(int family,int type,int mapped,int marked,struct pair *pair){
    struct sockaddr_storage address={0};socklen_t size;
    if(family==AF_INET){struct sockaddr_in *a=(void*)&address;a->sin_family=AF_INET;a->sin_addr.s_addr=htonl(INADDR_LOOPBACK);size=sizeof(*a);}
    else{struct sockaddr_in6 *a=(void*)&address;a->sin6_family=AF_INET6;size=sizeof(*a);
        if(inet_pton(AF_INET6,mapped?"::ffff:127.0.0.1":"::1",&a->sin6_addr)!=1)return -1;}
    int server=socket(family,type|SOCK_CLOEXEC,0);if(server<0)return -1;
    if(bind(server,(struct sockaddr*)&address,size)||getsockname(server,(struct sockaddr*)&address,&size)||
        (type==SOCK_STREAM&&listen(server,1))||(marked&&setegid(57342))){close(server);return -1;}
    int client=socket(family,type|SOCK_CLOEXEC,0),restored=!marked||!setegid(0);
    if(client<0||!restored){if(client>=0)close(client);close(server);return -1;}
    if(type==SOCK_STREAM){
        if(connect(client,(struct sockaddr*)&address,size)){close(client);close(server);return -1;}
        int peer=accept4(server,NULL,NULL,SOCK_CLOEXEC);close(server);
        if(peer<0){close(client);return -1;}*pair=(struct pair){client,peer};
    }else{
        struct sockaddr_storage local=address;
        if(family==AF_INET)((struct sockaddr_in*)&local)->sin_port=0;else((struct sockaddr_in6*)&local)->sin6_port=0;
        if(bind(client,(struct sockaddr*)&local,size)||getsockname(client,(struct sockaddr*)&local,&size)||
            connect(server,(struct sockaddr*)&local,size)){close(client);close(server);return -1;}
        *pair=(struct pair){client,server};
    }
    return 0;
}
static int udp_send(struct pair *pair,char byte){
    struct sockaddr_storage address;socklen_t size=sizeof(address);
    if(getsockname(pair->peer,(struct sockaddr*)&address,&size))return 0;
    ssize_t sent=sendto(pair->client,&byte,1,MSG_NOSIGNAL,(struct sockaddr*)&address,size);
    return sent==1||(sent<0&&(errno==EPERM||errno==EACCES));
}
static int transfer(struct pair *pair,int type){
    if(type==SOCK_STREAM)return exchange(pair);
    char byte;return udp_send(pair,'L')&&readable(pair->peer,500)&&recv(pair->peer,&byte,1,0)==1&&byte=='L'&&
        send(pair->peer,"R",1,MSG_NOSIGNAL)==1&&readable(pair->client,500)&&recv(pair->client,&byte,1,0)==1&&byte=='R';
}
static int blocked(struct pair *pair,int type){
    errno=0;int sent;
    if(type==SOCK_DGRAM)sent=udp_send(pair,'B');
    else{ssize_t count=send(pair->client,"B",1,MSG_NOSIGNAL);sent=count==1||(count<0&&(errno==EPERM||errno==EACCES));}
    return sent&&quiet(pair->peer);
}
static void ready(const char *phase,const struct pair *pair){
    printf("{\"event\":\"epoch-ready\",\"family\":\"%s\",\"protocol\":\"%s\",\"old_epoch\":%u,\"new_epoch\":%u,\"phase\":\"%s\",\"source_port\":%u,\"destination_port\":%u}\n",
        family_name,protocol,old_epoch,new_epoch,phase,pair?port(pair->client):0,pair?port(pair->peer):0);fflush(stdout);
}
static int run(int family,int type,int mapped){
    struct pair old={-1,-1},fresh={-1,-1},control={-1,-1};int result=4;
    if(!check("baseline",!pair_create(family,type,mapped,1,&old)&&!pair_create(family,type,mapped,0,&control)))goto done;
    if(!check("old_open_exchange",transfer(&old,type)&&transfer(&control,type)))goto done;
    ready("old",&old);
    if(!command('c'))goto done;
    if(!check("old_closed",blocked(&old,type))||!check("unrelated_closed",transfer(&control,type)))goto done;
    ready("closed",NULL);
    if(!command('n'))goto done;
    if(!check("new_socket",!pair_create(family,type,mapped,1,&fresh))||!check("new_open_exchange",transfer(&fresh,type))||
        !check("old_still_denied",blocked(&old,type))||!check("unrelated_reopened",transfer(&control,type)))goto done;
    ready("new",&fresh);
    if(!command('r'))goto done;
    if(!check("new_closed",blocked(&fresh,type))||!check("old_remains_closed",blocked(&old,type))||
        !check("unrelated_final",transfer(&control,type)))goto done;
    result=0;
done: ;
    struct pair *pairs[]={&old,&fresh,&control};
    for(unsigned i=0;i<3;++i){if(pairs[i]->client>=0)close(pairs[i]->client);if(pairs[i]->peer>=0)close(pairs[i]->peer);}
    return result;
}
static unsigned number(const char *text){
    char *end;errno=0;unsigned long value=strtoul(text,&end,10);
    return !errno&&*text&&!*end&&epoch_valid((unsigned)value)&&value<=255?(unsigned)value:0;
}
static int selftest(void){
#define ASSERT(x) do{if(!(x)){fprintf(stderr,"epoch-policy-selftest line %d\n",__LINE__);return 4;}}while(0)
    struct label_policy_names names;ASSERT(!label_policy_names("LISACQ_EPOCH",&names));
    char text[2048];unsigned char used[256]={0};
    for(unsigned epoch=1;epoch<256;++epoch){
        ASSERT(epoch_valid(epoch));
        for(unsigned kind=0;kind<3;++kind)for(int closed=0;closed<2;++closed){
            ASSERT(epoch_policy_expected(&names,kind,epoch,closed,text,sizeof(text))>0);
            ASSERT(epoch_policy_expected(&names,kind,epoch,closed,text,1)<0);
        }
    }
    ASSERT(epoch_policy_expected(&names,1,0,1,text,sizeof(text))<0);
    ASSERT(epoch_policy_expected(&names,1,256,1,text,sizeof(text))<0);
    ASSERT(epoch_policy_expected(&names,3,1,1,text,sizeof(text))<0);
    ASSERT(epoch_policy_expected(&names,0,1,2,text,sizeof(text))<0);
    ASSERT(epoch_policy_expected(&names,0,1,0,text,sizeof(text))>0&&!strcmp(text,"-N LISACQ_EPOCH\n"));
    ASSERT(epoch_policy_expected(&names,1,2,0,text,sizeof(text))>0&&strstr(text,"--mark 0x0/0xff000000")&&
        strstr(text,"--set-xmark 0x2000000/0xff000000"));
    ASSERT(epoch_policy_expected(&names,2,2,0,text,sizeof(text))>0&&!strcmp(text,
        "-N LISACL_EPOCH\n-A LISACL_EPOCH -m connmark --mark 0x0/0xff000000 -j RETURN\n"
        "-A LISACL_EPOCH -m connmark --mark 0x2000000/0xff000000 -j RETURN\n-A LISACL_EPOCH -j DROP\n"));
    ASSERT(epoch_next_unused(used,0)==1);used[1]=1;ASSERT(epoch_next_unused(used,0)==2);
    ASSERT(epoch_next_unused(used,255)==2);ASSERT(epoch_next_unused(used,2)==3);
    memset(used,1,sizeof(used));ASSERT(epoch_next_unused(used,0)==0);
    used[2]=0;ASSERT(epoch_next_unused(used,2)==0);ASSERT(epoch_next_unused(used,1)==2);
    char good[]="ipv4 2 udp 17 99 src=127.0.0.1 mark=16777216 use=1\nipv6 10 tcp 6 99 mark=33554439 use=1\nipv4 2 tcp 6 9 mark=42 use=1\n";
    FILE *file=fmemopen(good,strlen(good),"r");ASSERT(file&&!epoch_conntrack_used(file,used));fclose(file);
    ASSERT(used[1]&&used[2]&&!used[0]&&!used[3]);
    const char *bad[]={"missing mark\n","x mark=4294967296\n","x mark=-0\n","x mark=1junk\n","x mark=1 mark=2\n","x mark=1"};
    for(unsigned i=0;i<sizeof(bad)/sizeof(bad[0]);++i){file=fmemopen((void*)bad[i],strlen(bad[i]),"r");
        ASSERT(file&&epoch_conntrack_used(file,used)<0);fclose(file);}
    puts("{\"selftest\":\"epoch-policy\",\"epochs_checked\":255,\"ok\":true,\"firewall_changed\":false,\"audio_opened\":false}");return 0;
#undef ASSERT
}
int main(int argc,char **argv){
    if(argc==2&&!strcmp(argv[1],"--selftest"))return selftest();
    if(getuid()||geteuid()||getgid()||getegid())return 2;
    if(argc==5&&!strcmp(argv[1],"--verify-policy")){
        unsigned epoch=number(argv[3]);int closed=!strcmp(argv[4],"closed");
        if(!epoch||(!closed&&strcmp(argv[4],"open")))return 2;
        alarm(8);int ok=epoch_policy_verified(argv[2],epoch,closed);
        printf("{\"event\":\"epoch-policy\",\"epoch\":%u,\"closed\":%s,\"ok\":%s}\n",epoch,closed?"true":"false",ok?"true":"false");return ok?0:4;
    }
    if(argc!=6||strcmp(argv[1],"--own-epochs"))return 2;
    old_epoch=number(argv[4]);new_epoch=number(argv[5]);if(!old_epoch||!new_epoch||old_epoch==new_epoch)return 2;
    int mapped=!strcmp(argv[2],"mapped"),family=!strcmp(argv[2],"4")?AF_INET:AF_INET6;
    if((family==AF_INET6&&!mapped&&strcmp(argv[2],"6"))||(strcmp(argv[3],"tcp")&&strcmp(argv[3],"udp")))return 2;
    alarm(30);family_name=mapped?"ipv4-mapped-ipv6":family==AF_INET?"ipv4":"ipv6";protocol=argv[3];
    int result=run(family,!strcmp(protocol,"tcp")?SOCK_STREAM:SOCK_DGRAM,mapped);
    printf("{\"event\":\"epoch-summary\",\"family\":\"%s\",\"protocol\":\"%s\",\"old_epoch\":%u,\"new_epoch\":%u,\"checks\":%u,\"failures\":%u,\"audio_opened\":false,\"vendor_processes_changed\":false}\n",
        family_name,protocol,old_epoch,new_epoch,checks,failures);return result||failures;
}
