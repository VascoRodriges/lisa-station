/* Experimental READ-ONLY external control plugin. Parent must separately
 * admit the sole packet FD and epoch. Environment/peer credentials are not
 * authorization. No SDK integration, raw sound FD, events or write capability. */
#define _GNU_SOURCE
#include <stdatomic.h>
#include <stdlib.h>
#include <string.h>
#include "master_alsa.h"
#include "master_read_client.h"
static atomic_uint claimed;
struct master_ctl {snd_ctl_ext_t ext;pthread_mutex_t mutex;struct master_read_client client;};
static struct master_ctl *state(snd_ctl_ext_t *ext){return ext->private_data;}
static int element_count(snd_ctl_ext_t *ext){(void)ext;return 1;}
static int element_list(snd_ctl_ext_t *ext,unsigned offset,snd_ctl_elem_id_t *id){
    (void)ext;if(offset)return -EINVAL;snd_ctl_elem_id_clear(id);
    snd_ctl_elem_id_set_interface(id,SND_CTL_ELEM_IFACE_MIXER);snd_ctl_elem_id_set_name(id,"Master Playback Volume");return 0;
}
static snd_ctl_ext_key_t find_element(snd_ctl_ext_t *ext,const snd_ctl_elem_id_t *id){
    (void)ext;return snd_ctl_elem_id_get_numid(id)<=1&&snd_ctl_elem_id_get_interface(id)==SND_CTL_ELEM_IFACE_MIXER&&
        !snd_ctl_elem_id_get_device(id)&&!snd_ctl_elem_id_get_subdevice(id)&&!snd_ctl_elem_id_get_index(id)&&
        !strcmp(snd_ctl_elem_id_get_name(id),"Master Playback Volume")?0:SND_CTL_EXT_KEY_NOT_FOUND;
}
static int attributes(snd_ctl_ext_t *ext,snd_ctl_ext_key_t key,int *type,unsigned *access,unsigned *count){
    (void)ext;if(key)return -ENOENT;*type=SND_CTL_ELEM_TYPE_INTEGER;*access=SND_CTL_EXT_ACCESS_READ|SND_CTL_EXT_ACCESS_VOLATILE;*count=1;return 0;
}
static int integer_info(snd_ctl_ext_t *ext,snd_ctl_ext_key_t key,long *low,long *high,long *step){
    (void)ext;if(key)return -ENOENT;*low=0;*high=255;*step=0;return 0;
}
static int read_integer(snd_ctl_ext_t *ext,snd_ctl_ext_key_t key,long *value){
    if(key)return -ENOENT;
    *value=0;struct master_ctl *ctl=state(ext);unsigned level=0;int error=pthread_mutex_lock(&ctl->mutex);if(error)return -error;
    int result=master_client_get(&ctl->client,&level);if(!result)*value=(long)level;
    error=pthread_mutex_unlock(&ctl->mutex);if(error){*value=0;return -error;}return result;
}
static int write_integer(snd_ctl_ext_t *ext,snd_ctl_ext_key_t key,long *value){(void)ext;(void)value;return key?-ENOENT:-EACCES;}
static int read_event(snd_ctl_ext_t *ext,snd_ctl_elem_id_t *id,unsigned *mask){(void)ext;(void)id;(void)mask;return -ENOSYS;}
static void close_control(snd_ctl_ext_t *ext){
    struct master_ctl *ctl=state(ext);master_client_close(&ctl->client);pthread_mutex_destroy(&ctl->mutex);free(ctl);
}
static const snd_ctl_ext_callback_t callbacks={.close=close_control,.elem_count=element_count,.elem_list=element_list,.find_elem=find_element,
    .get_attribute=attributes,.get_integer_info=integer_info,.read_integer=read_integer,.write_integer=write_integer,.read_event=read_event};
static int environment(int *fd,unsigned char epoch[MASTER_EPOCH_BYTES]){
    const char *number=getenv("LISA_MASTER_FD"),*token=getenv("LISA_MASTER_EPOCH");
    if(!number||!*number||number[0]=='0'||!token||strlen(token)!=2*MASTER_EPOCH_BYTES)return -EINVAL;
    unsigned n=0;for(const char *p=number;*p;++p){if(*p<'0'||*p>'9'||n>102||(n==102&&*p>'3'))return -EINVAL;n=n*10+(unsigned)(*p-'0');}
    if(n<3)return -EINVAL;
    for(unsigned i=0;i<MASTER_EPOCH_BYTES;++i){unsigned value=0;for(unsigned j=0;j<2;++j){char c=token[2*i+j];unsigned digit=c>='0'&&c<='9'?(unsigned)(c-'0'):c>='a'&&c<='f'?(unsigned)(c-'a'+10):16;
        if(digit>15)return -EINVAL;
        value=value*16+digit;}epoch[i]=(unsigned char)value;}
    if(!master_epoch_valid(epoch))return -EINVAL;
    *fd=(int)n;return 0;
}
SND_CTL_PLUGIN_DEFINE_FUNC(lisa_master){
    (void)root;if(!handlep||!name||!conf||snd_config_get_type(conf)!=SND_CONFIG_TYPE_COMPOUND)return -EINVAL;*handlep=NULL;
    snd_config_iterator_t iterator,next;unsigned types=0;
    snd_config_for_each(iterator,next,conf){snd_config_t *entry=snd_config_iterator_entry(iterator);const char *id,*type;
        if(snd_config_get_id(entry,&id)||strcmp(id,"type")||snd_config_get_string(entry,&type)||strcmp(type,"lisa_master"))return -EINVAL;
        ++types;}
    if(types!=1)return -EINVAL;
    unsigned char epoch[MASTER_EPOCH_BYTES];int fd,error=environment(&fd,epoch);if(error)return error;
    struct ucred peer;socklen_t bytes=sizeof(peer);if(getppid()<=1||getsockopt(fd,SOL_SOCKET,SO_PEERCRED,&peer,&bytes)||bytes!=sizeof(peer)||peer.pid!=getppid()||peer.uid!=geteuid())return -EPERM;
    struct master_ctl *ctl=calloc(1,sizeof(*ctl));if(!ctl)return -ENOMEM;ctl->client.fd=-1;
    error=pthread_mutex_init(&ctl->mutex,NULL);if(error){free(ctl);return -error;}
    unsigned expected=0;if(!atomic_compare_exchange_strong(&claimed,&expected,1)){pthread_mutex_destroy(&ctl->mutex);free(ctl);return -EBUSY;}
    error=master_client_init(&ctl->client,fd,epoch);if(error){pthread_mutex_destroy(&ctl->mutex);free(ctl);return error;}
    ctl->ext.version=SND_CTL_EXT_VERSION;ctl->ext.card_idx=0;ctl->ext.poll_fd=-1;
    strcpy(ctl->ext.id,"LisaMaster");strcpy(ctl->ext.driver,"lisa_master");strcpy(ctl->ext.name,"Lisa Master");
    strcpy(ctl->ext.longname,"Lisa bounded Master read capability");strcpy(ctl->ext.mixername,"Lisa Master");
    ctl->ext.callback=&callbacks;ctl->ext.private_data=ctl;
    error=snd_ctl_ext_create(&ctl->ext,name,mode);if(error<0){close_control(&ctl->ext);return error;}
    *handlep=ctl->ext.handle;return 0;
}
SND_CTL_PLUGIN_SYMBOL(lisa_master)
