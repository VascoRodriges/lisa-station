/* Lab-only libc return observer. Never records a time value, peer or speech.
 * The actual call and errno are preserved; failed logging cannot change it. */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/timex.h>
#include <unistd.h>
#ifndef LISA_CLOCK_PROOF_DIRECTORY
#define LISA_CLOCK_PROOF_DIRECTORY "/run/lisa-clock-proof"
#endif
static void clock_proof(const char *api,unsigned modes,int result,int error) {
    if(!modes&&result>=0)return;
    int saved=errno;
    int fd=open(LISA_CLOCK_PROOF_DIRECTORY "/clock-calls.jsonl",O_WRONLY|O_CREAT|O_APPEND|O_NOFOLLOW|O_CLOEXEC,0600);
    struct stat info;
    if(fd>=0){
        if(!fstat(fd,&info)&&S_ISREG(info.st_mode)&&info.st_uid==geteuid()&&info.st_nlink==1&&(info.st_mode&07777)==0600){
            char line[192];int size=snprintf(line,sizeof(line),"{\"event\":\"clock-call\",\"api\":\"%s\",\"modes\":%u,\"result\":%d,\"errno\":%d}\n",api,modes,result,error);
            if(size>0&&size<(int)sizeof(line)){ssize_t ignored=write(fd,line,(size_t)size);(void)ignored;}
        }
        close(fd);
    }
    errno=saved;
}
int adjtimex(struct timex *value) {
    int (*next)(struct timex*)=(int(*)(struct timex*))dlsym(RTLD_NEXT,"adjtimex");
    if(!next){errno=ENOSYS;return -1;}
    int result=next(value),saved=errno;
    /* Successful libc/kernel copy-back establishes a readable pointer. */
    unsigned modes=result>=0?value->modes:0;
    clock_proof("adjtimex",modes,result,result<0?saved:0);errno=saved;return result;
}
int settimeofday(const struct timeval *value,const struct timezone *zone) {
    int (*next)(const struct timeval*,const struct timezone*)=(int(*)(const struct timeval*,const struct timezone*))dlsym(RTLD_NEXT,"settimeofday");
    if(!next){errno=ENOSYS;return -1;}
    int result=next(value,zone),saved=errno;
    clock_proof("settimeofday",value?1u:0u,result,result<0?saved:0);errno=saved;return result;
}
