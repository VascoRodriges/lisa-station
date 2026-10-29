/* Immutable per-boot/revision marking admission. Caller holds mode.lock while
 * verifying an empty actor scope and the actual marking policy, then publishes
 * before any admitted socket can be created. This is not boot installation. */
#ifndef LISA_LABEL_ADMISSION_H
#define LISA_LABEL_ADMISSION_H
#include "label_policy.h"
static inline int label_arm_format(char *text,size_t capacity,uint64_t revision,const char *boot,const char *chain) {
    struct label_policy_names names;
    if(!revision||!gate_boot_valid(boot)||label_policy_names(chain,&names)) return -1;
    int size=snprintf(text,capacity,"LISA_LABEL_ARM_V1 %" PRIu64 " %s %s\n",revision,boot,chain);
    return size<0||(size_t)size>=capacity?-1:size;
}
/* Missing returns 1; malformed/stale/insecure evidence returns -1. */
static inline int label_arm_read(int runtime,uid_t owner,uint64_t revision,const char *boot,const char *chain) {
    char expected[256],actual[256]; int length=label_arm_format(expected,sizeof(expected),revision,boot,chain);
    if(length<0||!store_directory_valid(runtime,owner)) return -1;
    int fd=openat(runtime,"label.arm",O_RDONLY|O_NOFOLLOW|O_NONBLOCK|O_CLOEXEC);
    if(fd<0) return errno==ENOENT?1:-1;
    if(!store_file_valid(fd,owner)) { close(fd); return -1; }
    size_t used=0; int failed=0;
    while(used<sizeof(actual)) {
        ssize_t bytes=read(fd,actual+used,sizeof(actual)-used);
        if(bytes<0&&errno==EINTR) continue;
        if(bytes<0) { failed=1; break; }
        if(!bytes) break;
        used+=(size_t)bytes;
    }
    if(close(fd)) failed=1;
    return failed||used!=(size_t)length||memcmp(actual,expected,used)?-1:0;
}
static inline int label_arm_publish(int runtime,uid_t owner,uint64_t revision,const char *boot,const char *chain) {
    char text[256]; int size=label_arm_format(text,sizeof(text),revision,boot,chain);
    if(size<0||!store_directory_valid(runtime,owner)) return -1;
    int existing=label_arm_read(runtime,owner,revision,boot,chain);
    if(existing<0) return -1;
    if(!existing) {
        int fd=openat(runtime,"label.arm",O_RDONLY|O_NOFOLLOW|O_NONBLOCK|O_CLOEXEC);
        if(fd<0) return -1;
        int failed=!store_file_valid(fd,owner)||fsync(fd);
        if(close(fd)) failed=1;
        return failed||fsync(runtime)?-1:0;
    }
    char temporary[64]; uint64_t nonce;
    if(getrandom(&nonce,sizeof(nonce),0)!=(ssize_t)sizeof(nonce)) return -1;
    snprintf(temporary,sizeof(temporary),".label-%" PRIx64 ".tmp",nonce);
    int fd=openat(runtime,temporary,O_WRONLY|O_CREAT|O_EXCL|O_NOFOLLOW|O_CLOEXEC,0600);
    if(fd<0) return -1;
    int failed=store_write_all(fd,text,(size_t)size)||fsync(fd);
    if(close(fd)) failed=1;
    if(!failed&&linkat(runtime,temporary,runtime,"label.arm",0)) failed=1;
    if(unlinkat(runtime,temporary,0)) failed=1;
    if(!failed&&fsync(runtime)) failed=1;
    return failed?-1:0;
}
static inline int label_arm_present(int runtime) {
    struct stat info;
    if(!fstatat(runtime,"label.arm",&info,AT_SYMLINK_NOFOLLOW)) return 1;
    return errno==ENOENT?0:-1;
}
#endif
