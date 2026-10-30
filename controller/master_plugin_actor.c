#define _GNU_SOURCE
#include "master_plugin_runtime.h"
#include "master_plugin_actor.h"
int master_actor_begin(struct master_plugin_actor *actor,const char *module,int fd,const unsigned char *epoch){
    if(!actor||actor->state)return -EINVAL;
    struct master_plugin_runtime *runtime=calloc(1,sizeof(*runtime));if(!runtime)return -ENOMEM;
    if(master_runtime_begin(runtime,module,fd,epoch)){free(runtime);return -EIO;}
    actor->state=runtime;return 0;
}
int master_actor_get(struct master_plugin_actor *actor,unsigned *value){
    return master_runtime_get(actor?actor->state:NULL,value);
}
int master_actor_end(struct master_plugin_actor *actor){
    if(!actor)return -EINVAL;
    if(!actor->state)return 0;
    int result=master_runtime_end(actor->state);free(actor->state);actor->state=NULL;return result;
}
