/* Opt-in SDK API parameter audit. No PCM, authentication or audio buffers.
 * The actual ALSA function executes unchanged; this never fakes attachment. */
#ifndef LISA_MIXER_ATTACH_HOOK_H
#define LISA_MIXER_ATTACH_HOOK_H
#include <dlfcn.h>
#include <errno.h>
#include <pthread.h>
#include <stdatomic.h>
#include <unistd.h>
#include "mixer_attach_record.h"
struct _snd_mixer;
static int (*mixer_real_attach)(struct _snd_mixer *,const char *);
static pthread_once_t mixer_resolve_once=PTHREAD_ONCE_INIT;
static _Atomic unsigned mixer_audit_calls;
static void mixer_resolve(void){mixer_real_attach=dlsym(RTLD_NEXT,"snd_mixer_attach");if(!mixer_real_attach)_exit(126);}
int snd_mixer_attach(struct _snd_mixer *mixer,const char *label){
    int entry_errno=errno;if(pthread_once(&mixer_resolve_once,mixer_resolve))_exit(126);errno=entry_errno;
    int result=mixer_real_attach(mixer,label),saved=errno;unsigned char record[MIXER_RECORD_WIRE];
    if(atomic_fetch_add(&mixer_audit_calls,1)>=MIXER_RECORD_LIMIT||mixer_record_encode(label,result,record,sizeof(record)))_exit(126);
    ssize_t written;do{written=write(2,record,sizeof(record));}while(written<0&&errno==EINTR);
    memset(record,0,sizeof(record));if(written!=(ssize_t)sizeof(record))_exit(126);
    errno=saved;return result;
}
#endif
