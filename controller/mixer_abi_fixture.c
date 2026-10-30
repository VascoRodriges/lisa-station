/* Synthetic original ABI for host forwarding tests ONLY. No ALSA substitute
 * is linked into the SDK diagnostic or shipped as a device artifact. */
#include <errno.h>
#include <stdatomic.h>
struct _snd_mixer;
static _Atomic unsigned calls;
int snd_mixer_attach(struct _snd_mixer *mixer,const char *label){
    (void)mixer;(void)label;atomic_fetch_add(&calls,1);errno=EACCES;return -37;
}
unsigned mixer_fixture_calls(void){return atomic_load(&calls);}
