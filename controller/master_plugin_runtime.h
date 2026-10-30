/* Own-client firmware-ALSA composition. Caller must already admit a
 * pinned module in a private view and the sole epoch packet descriptor.
 * This performs no admission, hardware open, SDK launch or PCM operation. */
#ifndef LISA_MASTER_PLUGIN_RUNTIME_H
#define LISA_MASTER_PLUGIN_RUNTIME_H
#include <dlfcn.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "master_alsa.h"
#include "master_read_protocol.h"
#define MASTER_RUNTIME_API(X) \
    X(snd_asoundlib_version) X(snd_config_top) X(snd_config_make_compound) X(snd_config_imake_string) X(snd_config_add) X(snd_config_delete) \
    X(snd_ctl_elem_value_malloc) X(snd_ctl_elem_value_free) X(snd_ctl_elem_value_clear) X(snd_ctl_elem_value_set_numid) X(snd_ctl_elem_value_get_integer) \
    X(snd_ctl_elem_info_malloc) X(snd_ctl_elem_info_free) X(snd_ctl_elem_info_clear) X(snd_ctl_elem_info_set_numid) X(snd_ctl_elem_info_get_type) \
    X(snd_ctl_elem_info_get_count) X(snd_ctl_elem_info_get_min) X(snd_ctl_elem_info_get_max) X(snd_ctl_elem_info_get_step) \
    X(snd_ctl_elem_info_is_readable) X(snd_ctl_elem_info_is_writable) X(snd_ctl_elem_info_is_volatile) X(snd_ctl_elem_info) \
    X(snd_ctl_elem_read) X(snd_ctl_close) X(snd_ctl_poll_descriptors_count)
struct master_plugin_runtime {
    void *alsa,*module;snd_ctl_t *ctl;snd_config_t *root,*conf;snd_ctl_elem_value_t *value;
#define MASTER_RUNTIME_FIELD(name) __typeof__(&name) name;
    MASTER_RUNTIME_API(MASTER_RUNTIME_FIELD)
#undef MASTER_RUNTIME_FIELD
};
static inline int master_runtime_end(struct master_plugin_runtime *runtime){
    int bad=0;
    if(runtime->value)runtime->snd_ctl_elem_value_free(runtime->value);
    if(runtime->ctl&&runtime->snd_ctl_close(runtime->ctl))bad=1;
    if(runtime->conf&&runtime->snd_config_delete(runtime->conf))bad=1;
    if(runtime->root&&runtime->snd_config_delete(runtime->root))bad=1;
    if(runtime->module&&dlclose(runtime->module))bad=1;
    if(runtime->alsa&&dlclose(runtime->alsa))bad=1;
    memset(runtime,0,sizeof(*runtime));return bad?-1:0;
}
static inline int master_runtime_begin(struct master_plugin_runtime *runtime,const char *module,int fd,const unsigned char *epoch){
    if(!runtime||!module||fd<3||!master_epoch_valid(epoch))return -1;
    *runtime=(struct master_plugin_runtime){0};runtime->alsa=dlopen("libasound.so.2",RTLD_NOW|RTLD_GLOBAL);
    if(!runtime->alsa)return -1;
#define MASTER_RUNTIME_RESOLVE(name) runtime->name=(__typeof__(runtime->name))dlsym(runtime->alsa,#name);if(!runtime->name)goto failed;
    MASTER_RUNTIME_API(MASTER_RUNTIME_RESOLVE)
#undef MASTER_RUNTIME_RESOLVE
    if(strcmp(runtime->snd_asoundlib_version(),"1.2.1.2"))goto failed;
    runtime->module=dlopen(module,RTLD_NOW|RTLD_LOCAL);if(!runtime->module||!dlsym(runtime->module,"__snd_ctl_lisa_master_open_dlsym_control_001"))goto failed;
    int (*entry)(snd_ctl_t **,const char *,snd_config_t *,snd_config_t *,int)=
        (int (*)(snd_ctl_t **,const char *,snd_config_t *,snd_config_t *,int))dlsym(runtime->module,"_snd_ctl_lisa_master_open");
    if(!entry)goto failed;
    char number[24],token[2*MASTER_EPOCH_BYTES+1];snprintf(number,sizeof(number),"%d",fd);
    for(unsigned i=0;i<MASTER_EPOCH_BYTES;++i)snprintf(token+2*i,3,"%02x",epoch[i]);
    if(setenv("LISA_MASTER_FD",number,1)||setenv("LISA_MASTER_EPOCH",token,1)||runtime->snd_config_top(&runtime->root)||
        runtime->snd_config_make_compound(&runtime->conf,"own",0))goto failed;
    snd_config_t *type=NULL;
    if(runtime->snd_config_imake_string(&type,"type","lisa_master"))goto failed;
    if(runtime->snd_config_add(runtime->conf,type)){runtime->snd_config_delete(type);goto failed;}
    if(entry(&runtime->ctl,"own",runtime->root,runtime->conf,0)<0||!runtime->ctl||runtime->snd_ctl_poll_descriptors_count(runtime->ctl)!=0)goto failed;
    snd_ctl_elem_info_t *info=NULL;if(runtime->snd_ctl_elem_info_malloc(&info))goto failed;
    runtime->snd_ctl_elem_info_clear(info);runtime->snd_ctl_elem_info_set_numid(info,1);
    int compatible=!runtime->snd_ctl_elem_info(runtime->ctl,info)&&runtime->snd_ctl_elem_info_get_type(info)==SND_CTL_ELEM_TYPE_INTEGER&&
        runtime->snd_ctl_elem_info_get_count(info)==1&&runtime->snd_ctl_elem_info_get_min(info)==0&&runtime->snd_ctl_elem_info_get_max(info)==255&&
        !runtime->snd_ctl_elem_info_get_step(info)&&runtime->snd_ctl_elem_info_is_readable(info)&&!runtime->snd_ctl_elem_info_is_writable(info)&&runtime->snd_ctl_elem_info_is_volatile(info);
    runtime->snd_ctl_elem_info_free(info);
    if(!compatible||runtime->snd_ctl_elem_value_malloc(&runtime->value))goto failed;
    return 0;
failed:
    master_runtime_end(runtime);return -1;
}
static inline int master_runtime_get(struct master_plugin_runtime *runtime,unsigned *value){
    if(!value)return -EINVAL;
    *value=0;if(!runtime||!runtime->ctl||!runtime->value)return -ENOTCONN;
    runtime->snd_ctl_elem_value_clear(runtime->value);runtime->snd_ctl_elem_value_set_numid(runtime->value,1);
    int result=runtime->snd_ctl_elem_read(runtime->ctl,runtime->value);if(result<0)return result;
    long level=runtime->snd_ctl_elem_value_get_integer(runtime->value,0);if(level<0||level>255)return -EPROTO;
    *value=(unsigned)level;return 0;
}
#undef MASTER_RUNTIME_API
#endif
