/* Host hook/real-function ABI forwarding fixture; synthetic callee, no ALSA. */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <sys/wait.h>
#include "mixer_attach_hook.h"
extern unsigned mixer_fixture_calls(void);
static unsigned checks,failures;
static void check(int good){++checks;if(!good){++failures;fprintf(stdout,"Mixer hook check %u\n",checks);}}
int main(int argc,char **argv){
    if(argc!=2||strcmp(argv[1],"--selftest"))return 2;
    FILE *file=tmpfile();int original=dup(2);if(!file||original<0||dup2(fileno(file),2)<0)return 2;
    check(!mixer_fixture_calls());
    for(unsigned i=0;i<4;++i){errno=ERANGE;int result=snd_mixer_attach(NULL,MIXER_MISSING_CONTROL);
        check(result==-37&&errno==EACCES&&mixer_fixture_calls()==i+1);}
    pid_t child=fork();check(child>=0);
    if(!child){snd_mixer_attach(NULL,MIXER_MISSING_CONTROL);_exit(9);}
    if(child>0){int status=0;check(waitpid(child,&status,0)==child&&WIFEXITED(status)&&WEXITSTATUS(status)==126);}
    check(lseek(fileno(file),0,SEEK_END)==(off_t)(4*MIXER_RECORD_WIRE)&&lseek(fileno(file),0,SEEK_SET)==0);
    for(unsigned i=0;i<4;++i){unsigned char bytes[MIXER_RECORD_WIRE];struct mixer_attach_record record;
        check(read(fileno(file),bytes,sizeof(bytes))==(ssize_t)sizeof(bytes)&&!mixer_record_decode(bytes,sizeof(bytes),&record)&&
            record.result==-37&&!strcmp(record.label,MIXER_MISSING_CONTROL));}
    check(dup2(original,2)>=0&&!close(original)&&!fclose(file));
    printf("{\"kind\":\"mixer-hook-forwarding\",\"checks\":%u,\"failures\":%u}\n",checks,failures);return failures?1:0;
}
