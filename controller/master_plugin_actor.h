/* Keep public libasound declarations in a separate translation unit from the
 * kernel ALSA ioctl ABI. The native parent passes only its packet capability. */
#ifndef LISA_MASTER_PLUGIN_ACTOR_H
#define LISA_MASTER_PLUGIN_ACTOR_H
struct master_plugin_actor {void *state;};
int master_actor_begin(struct master_plugin_actor *actor,const char *module,int fd,const unsigned char *epoch);
int master_actor_get(struct master_plugin_actor *actor,unsigned *value);
int master_actor_end(struct master_plugin_actor *actor);
#endif
