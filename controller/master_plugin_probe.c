/* Host ABI fixture against the REAL public ALSA library. The packet provider
 * here is explicitly synthetic, never a hardware/SDK qualification. */
#define _GNU_SOURCE
#include <alloca.h>
#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include "master_alsa.h"
#include "master_read_client.h"
static unsigned checks,failures;
static void check(int good){++checks;if(!good)++failures;}
typedef int (*plugin_entry)(snd_ctl_t **,const char *,snd_config_t *,snd_config_t *,int);
static const unsigned char epoch[MASTER_EPOCH_BYTES]={1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16};
struct concurrent {snd_ctl_t *ctl;unsigned values[8];int good;};
static int get(snd_ctl_t *ctl,unsigned *level){
    snd_ctl_elem_value_t *value;snd_ctl_elem_value_alloca(&value);snd_ctl_elem_value_clear(value);
    snd_ctl_elem_value_set_numid(value,1);snd_ctl_elem_value_set_integer(value,0,999);
    int result=snd_ctl_elem_read(ctl,value);*level=(unsigned)snd_ctl_elem_value_get_integer(value,0);return result;
}
static void *concurrent_read(void *argument){struct concurrent *job=argument;job->good=1;for(unsigned i=0;i<8;++i)if(get(job->ctl,&job->values[i]))job->good=0;return NULL;}
static int own_client(const char *path,int fd,unsigned mode,int start){
    checks=failures=0;signal(SIGPIPE,mode==10?SIG_IGN:SIG_DFL);
    check(!strcmp(snd_asoundlib_version(),"1.2.1.2"));
    if(mode==12){sigset_t mask;sigemptyset(&mask);sigaddset(&mask,SIGPIPE);check(!pthread_sigmask(SIG_BLOCK,&mask,NULL));check(!raise(SIGPIPE));}
    void *module=dlopen(path,RTLD_NOW|RTLD_LOCAL);check(module!=NULL);if(!module)return 9;
    plugin_entry entry=(plugin_entry)dlsym(module,"_snd_ctl_lisa_master_open");check(entry!=NULL);
    check(dlsym(module,"__snd_ctl_lisa_master_open_dlsym_control_001")!=NULL);if(!entry)return 9;
    char number[24],token[2*MASTER_EPOCH_BYTES+1];snprintf(number,sizeof(number),"%d",fd);
    for(unsigned i=0;i<MASTER_EPOCH_BYTES;++i)snprintf(token+2*i,3,"%02x",epoch[i]);
    check(!setenv("LISA_MASTER_FD",number,1)&&!setenv("LISA_MASTER_EPOCH",token,1));
    snd_config_t *root=NULL,*conf=NULL,*type=NULL;check(!snd_config_top(&root));check(!snd_config_make_compound(&conf,"own",0));
    check(!snd_config_imake_string(&type,"type","lisa_master")&&!snd_config_add(conf,type));
    snd_ctl_t *ctl=NULL;
    const char *bad_numbers[]={"", "03", "-1", "1024", "2147483648", "3x"};
    for(unsigned i=0;i<sizeof(bad_numbers)/sizeof(bad_numbers[0]);++i){check(!setenv("LISA_MASTER_FD",bad_numbers[i],1));check(entry(&ctl,"own",root,conf,0)==-EINVAL&&!ctl);}
    check(!setenv("LISA_MASTER_FD",number,1));check(!setenv("LISA_MASTER_EPOCH","00000000000000000000000000000000",1));check(entry(&ctl,"own",root,conf,0)==-EINVAL&&!ctl);
    check(!setenv("LISA_MASTER_EPOCH",token,1));snd_config_t *unknown=NULL;
    check(!snd_config_imake_string(&unknown,"device","hw:0")&&!snd_config_add(conf,unknown));check(entry(&ctl,"own",root,conf,0)==-EINVAL&&!ctl);check(!snd_config_delete(unknown));
    check(!entry(&ctl,"own",root,conf,0)&&ctl!=NULL);if(!ctl)return 9;
    snd_ctl_t *other=NULL;check(entry(&other,"own",root,conf,0)==-EBUSY&&!other);
    snd_ctl_card_info_t *card;snd_ctl_card_info_alloca(&card);check(!snd_ctl_card_info(ctl,card)&&!strcmp(snd_ctl_card_info_get_id(card),"LisaMaster"));
    check(snd_ctl_poll_descriptors_count(ctl)==0);
    snd_ctl_elem_list_t *list;snd_ctl_elem_list_alloca(&list);check(!snd_ctl_elem_list_alloc_space(list,1));
    check(!snd_ctl_elem_list(ctl,list)&&snd_ctl_elem_list_get_count(list)==1&&snd_ctl_elem_list_get_used(list)==1);
    check(snd_ctl_elem_list_get_numid(list,0)==1&&!strcmp(snd_ctl_elem_list_get_name(list,0),"Master Playback Volume"));snd_ctl_elem_list_free_space(list);
    snd_ctl_elem_info_t *info;snd_ctl_elem_info_alloca(&info);snd_ctl_elem_info_clear(info);snd_ctl_elem_info_set_numid(info,1);
    check(!snd_ctl_elem_info(ctl,info)&&snd_ctl_elem_info_get_type(info)==SND_CTL_ELEM_TYPE_INTEGER&&snd_ctl_elem_info_get_count(info)==1&&
        snd_ctl_elem_info_is_readable(info)&&!snd_ctl_elem_info_is_writable(info)&&snd_ctl_elem_info_is_volatile(info)&&
        snd_ctl_elem_info_get_min(info)==0&&snd_ctl_elem_info_get_max(info)==255&&snd_ctl_elem_info_get_step(info)==0);
    snd_ctl_elem_info_clear(info);snd_ctl_elem_info_set_numid(info,2);check(snd_ctl_elem_info(ctl,info)==-ENOENT);
    snd_ctl_elem_info_clear(info);snd_ctl_elem_info_set_interface(info,SND_CTL_ELEM_IFACE_MIXER);snd_ctl_elem_info_set_name(info,"Capture Volume");check(snd_ctl_elem_info(ctl,info)==-ENOENT);
    snd_ctl_elem_value_t *value;snd_ctl_elem_value_alloca(&value);snd_ctl_elem_value_clear(value);snd_ctl_elem_value_set_numid(value,1);
    check(snd_ctl_elem_write(ctl,value)==-EACCES);
    snd_ctl_elem_id_t *id;snd_ctl_elem_id_alloca(&id);snd_ctl_elem_id_clear(id);snd_ctl_elem_id_set_numid(id,1);unsigned tlv[8];check(snd_ctl_elem_tlv_read(ctl,id,tlv,sizeof(tlv))<0);
    char ready;check(read(start,&ready,1)==1&&ready=='1');check(!close(start));
    if(mode==0){struct concurrent jobs[4]={{.ctl=ctl},{.ctl=ctl},{.ctl=ctl},{.ctl=ctl}};pthread_t threads[4];unsigned created=0;uint32_t seen=0;
        for(unsigned i=0;i<4;++i){int result=pthread_create(&threads[i],NULL,concurrent_read,&jobs[i]);check(!result);if(result)break;++created;}
        for(unsigned i=0;i<created;++i){check(!pthread_join(threads[i],NULL)&&jobs[i].good);for(unsigned j=0;j<8;++j){unsigned level=jobs[i].values[j];check(level<32&&!(seen&(1u<<(level&31))));if(level<32)seen|=1u<<level;}}
        check(seen==UINT32_MAX);unsigned level=999;check(get(ctl,&level)==-ENOTCONN&&!level);
    }else{unsigned level=999;int result=get(ctl,&level);check(result==(mode==1?-EIO:mode==9?-ETIMEDOUT:mode>=10?-EPIPE:mode==8?-EPIPE:-EPROTO)&&!level);
        level=999;check(get(ctl,&level)==-ENOTCONN&&!level);}
    if(mode==12){sigset_t pending;check(!sigpending(&pending)&&sigismember(&pending,SIGPIPE));}
    struct sigaction action;check(!sigaction(SIGPIPE,NULL,&action)&&action.sa_handler==(mode==10?SIG_IGN:SIG_DFL));
    check(!snd_ctl_close(ctl));errno=0;check(fcntl(fd,F_GETFD)<0&&errno==EBADF);
    check(entry(&other,"own",root,conf,0)<0&&!other);check(!snd_config_delete(conf)&&!snd_config_delete(root));check(!dlclose(module));
    return failures?9:0;
}
static int provider(int fd,unsigned mode){
    unsigned count=mode?1:MASTER_READ_LIMIT;
    for(unsigned sequence=1;sequence<=count;++sequence){struct pollfd ready={fd,POLLIN,0};if(poll(&ready,1,2000)!=1)return -1;
        unsigned char request[MASTER_REQUEST_BYTES+1],reply[MASTER_REPLY_BYTES+1];ssize_t got=read(fd,request,sizeof(request));
        if(got!=MASTER_REQUEST_BYTES||master_request_decode(request,(size_t)got,epoch,sequence))return -1;
        if(mode==8)return 0;
        if(mode==9){struct timespec t={0,300000000};nanosleep(&t,NULL);return 0;}
        if(master_reply_encode(epoch,sequence,mode==1?EIO:0,mode==1?0:sequence-1,reply,MASTER_REPLY_BYTES))return -1;
        size_t size=MASTER_REPLY_BYTES;
        if(mode==2)--size;else if(mode==3)reply[size++]=0;else if(mode==4)reply[8]^=1;else if(mode==5)master_put32(reply+24,sequence+1);
        else if(mode==6)reply[36]=1;else if(mode==7)master_put32(reply+32,256);
        if(write(fd,reply,size)!=(ssize_t)size)return -1;
    }
    return 0;
}
int main(int argc,char **argv){
    if(argc!=2)return 2;
    signal(SIGPIPE,SIG_IGN);alarm(30);unsigned total=0,bad=0;
    for(unsigned mode=0;mode<13;++mode){int peer[2],start[2];if(socketpair(AF_UNIX,SOCK_SEQPACKET|SOCK_CLOEXEC,0,peer)||pipe(start))return 2;
        pid_t child=fork();if(child<0)return 2;if(!child){alarm(5);close(peer[0]);close(start[1]);_exit(own_client(argv[1],peer[1],mode,start[0]));}
        close(peer[1]);close(start[0]);int provided=0;if(mode>=10)close(peer[0]);
        if(write(start[1],"1",1)!=1)return 2;
        close(start[1]);
        if(mode<10){provided=provider(peer[0],mode);close(peer[0]);}
        int status;pid_t done;do{done=waitpid(child,&status,0);}while(done<0&&errno==EINTR);
        int good=done==child&&WIFEXITED(status)&&!WEXITSTATUS(status)&&!provided;++total;if(!good)++bad;
        printf("{\"fixture\":\"master-plugin-abi\",\"synthetic_provider\":true,\"case\":%u,\"ok\":%s,\"child_status\":%d,\"provider_result\":%d}\n",mode,good?"true":"false",status,provided);fflush(stdout);
    }
    printf("{\"selftest\":\"master-plugin-abi\",\"cases\":%u,\"failures\":%u,\"ok\":%s,\"hardware_opened\":false,\"sdk_executed\":false}\n",total,bad,bad?"false":"true");return bad?1:0;
}
