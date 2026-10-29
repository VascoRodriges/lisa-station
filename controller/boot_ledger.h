/* Immutable per-boot namespace ownership and completed closed-policy record.
 * Records are not a substitute for inspecting the actual kernel policy. */
#ifndef LISA_BOOT_LEDGER_H
#define LISA_BOOT_LEDGER_H
#include "boot_policy.h"
static inline const char *boot_ledger_name(unsigned kind) { return kind==0?"boot.policy":kind==1?"boot.ready":NULL; }
static inline int boot_ledger_format(unsigned kind,const char *boot,const char *chain,char *text,size_t capacity) {
    struct label_policy_names names;
    if(!boot_ledger_name(kind)||!gate_boot_valid(boot)||label_policy_names(chain,&names)) return -1;
    int size=snprintf(text,capacity,"LISA_BOOT_%s_V1 %s %s\n",kind?"READY":"POLICY",boot,chain);
    return size<0||(size_t)size>=capacity?-1:size;
}
static inline int boot_ledger_file(int fd,uid_t owner) {
    struct stat info;
    return store_file_valid(fd,owner)&&!fstat(fd,&info)&&(info.st_mode&07777)==0600;
}
/* 1 absent, 0 exact and private, -1 stale/malformed/insecure. */
static inline int boot_ledger_read(int runtime,uid_t owner,unsigned kind,const char *boot,const char *chain) {
    char expected[256],actual[256]; int length=boot_ledger_format(kind,boot,chain,expected,sizeof(expected));
    if(length<0||!store_directory_valid(runtime,owner)) return -1;
    int fd=openat(runtime,boot_ledger_name(kind),O_RDONLY|O_NOFOLLOW|O_NONBLOCK|O_CLOEXEC);
    if(fd<0) return errno==ENOENT?1:-1;
    if(!boot_ledger_file(fd,owner)) { close(fd); return -1; }
    size_t used=0; int failed=0;
    while(used<sizeof(actual)) {
        ssize_t bytes=read(fd,actual+used,sizeof(actual)-used);
        if(bytes<0&&errno==EINTR) continue;
        if(bytes<0) { failed=1; break; }
        if(!bytes) break;
        used+=(size_t)bytes;
    }
    if(close(fd)) failed=1;
    return failed||used!=(size_t)length||memcmp(expected,actual,used)?-1:0;
}
static inline int boot_ledger_nonce(uint64_t *nonce) {
    ssize_t count=getrandom(nonce,sizeof(*nonce),GRND_NONBLOCK);
    if(count==(ssize_t)sizeof(*nonce)) return 0;
    if(count<0&&errno!=EAGAIN&&errno!=ENOSYS) return -1;
    /* A temporary filename in a private directory is not an authentication
     * secret. O_EXCL protects it; cold boot must not wait for entropy seeding. */
    static uint64_t serial;
    struct timespec now;
    if(clock_gettime(CLOCK_MONOTONIC,&now)) return -1;
    *nonce=((uint64_t)now.tv_sec<<32)^(uint64_t)now.tv_nsec^((uint64_t)(unsigned)getpid()<<16)^++serial;
    return 0;
}
static inline int boot_ledger_publish(int runtime,uid_t owner,unsigned kind,const char *boot,const char *chain) {
    char text[256]; int size=boot_ledger_format(kind,boot,chain,text,sizeof(text));
    if(size<0||!store_directory_valid(runtime,owner)) return -1;
    int present=boot_ledger_read(runtime,owner,kind,boot,chain);
    if(present<0) return -1;
    if(!present) {
        int fd=openat(runtime,boot_ledger_name(kind),O_RDONLY|O_NOFOLLOW|O_NONBLOCK|O_CLOEXEC);
        if(fd<0) return -1;
        int failed=!boot_ledger_file(fd,owner)||fsync(fd);
        if(close(fd)) failed=1;
        return failed||fsync(runtime)?-1:0;
    }
    uint64_t nonce; char temporary[64];
    if(boot_ledger_nonce(&nonce)) return -1;
    snprintf(temporary,sizeof(temporary),".boot-%" PRIx64 ".tmp",nonce);
    int fd=openat(runtime,temporary,O_WRONLY|O_CREAT|O_EXCL|O_NOFOLLOW|O_CLOEXEC,0600);
    if(fd<0) return -1;
    int failed=store_write_all(fd,text,(size_t)size)||fsync(fd);
    if(close(fd)) failed=1;
    if(!failed&&linkat(runtime,temporary,runtime,boot_ledger_name(kind),0)) failed=1;
    if(unlinkat(runtime,temporary,0)) failed=1;
    if(!failed&&fsync(runtime)) failed=1;
    return failed?-1:0;
}
#endif
