/* Copy only fixed, pre-approved identity seed names from a private staging
 * directory. Never traverse or bind the shared vendor DATA tree. This validates
 * file objects and bounds, not the semantic contents of a credential database.
 */
#ifndef LISA_PLATFORM_SEED_H
#define LISA_PLATFORM_SEED_H
#include "mode_store.h"

#define PLATFORM_SEED_COUNT 5u
static inline const char *platform_seed_name(unsigned index){
    const char *names[]={"account_storage.dat","gsdkTokens.json","initialized","registered","first_greeting_done"};
    return index<PLATFORM_SEED_COUNT?names[index]:NULL;
}
static inline int platform_seed_directory(int fd,uid_t owner){
    struct stat info;
    return !fstat(fd,&info)&&S_ISDIR(info.st_mode)&&info.st_uid==owner&&(info.st_mode&07777)==0700;
}
static inline int platform_seed_valid(const struct stat *info,uid_t owner,unsigned index){
    return platform_seed_name(index)&&S_ISREG(info->st_mode)&&info->st_uid==owner&&info->st_nlink==1&&
        (info->st_mode&07777)==0600&&info->st_size>=0&&(index<2?info->st_size>0&&info->st_size<=65536:info->st_size==0);
}
static inline int platform_seed_same(const struct stat *a,const struct stat *b){
    return a->st_dev==b->st_dev&&a->st_ino==b->st_ino&&a->st_size==b->st_size&&a->st_uid==b->st_uid&&
        a->st_gid==b->st_gid&&a->st_mode==b->st_mode&&a->st_nlink==b->st_nlink&&
        a->st_mtim.tv_sec==b->st_mtim.tv_sec&&a->st_mtim.tv_nsec==b->st_mtim.tv_nsec&&
        a->st_ctim.tv_sec==b->st_ctim.tv_sec&&a->st_ctim.tv_nsec==b->st_ctim.tv_nsec;
}
static inline int platform_seed_open(int directory,uid_t owner,unsigned index,struct stat *info){
    if(!info||!platform_seed_directory(directory,owner)||!platform_seed_name(index))return -1;
    int fd=openat(directory,platform_seed_name(index),O_RDONLY|O_NOFOLLOW|O_NONBLOCK|O_CLOEXEC);if(fd<0)return -1;
    if(fstat(fd,info)||!platform_seed_valid(info,owner,index)){close(fd);return -1;}return fd;
}
static inline int platform_seed_copy(int source,int destination,uid_t owner,unsigned index){
    if(!platform_seed_directory(destination,owner))return -1;
    struct stat before,after,path;int input=platform_seed_open(source,owner,index,&before);if(input<0)return -1;
    const char *name=platform_seed_name(index);
    int output=openat(destination,name,O_WRONLY|O_CREAT|O_EXCL|O_NOFOLLOW|O_CLOEXEC,0600);
    if(output<0){close(input);return -1;}
    char buffer[4096];off_t copied=0;int failed=fchmod(output,0600)!=0;
    while(!failed&&copied<before.st_size){
        size_t wanted=(size_t)(before.st_size-copied);if(wanted>sizeof(buffer))wanted=sizeof(buffer);
        ssize_t count=read(input,buffer,wanted);
        if(count<0&&errno==EINTR)continue;
        if(count<=0||store_write_all(output,buffer,(size_t)count)){failed=1;break;}copied+=count;
    }
    char extra;ssize_t tail;
    do{tail=read(input,&extra,1);}while(tail<0&&errno==EINTR);
    if(tail!=0||fstat(input,&after)||!platform_seed_same(&before,&after)||
        fstatat(source,name,&path,AT_SYMLINK_NOFOLLOW)||!platform_seed_same(&before,&path)||fsync(output))failed=1;
    struct stat written,named;
    if(fstat(output,&written)||!platform_seed_valid(&written,owner,index)||written.st_size!=before.st_size||
        fstatat(destination,name,&named,AT_SYMLINK_NOFOLLOW)||!platform_seed_same(&written,&named))failed=1;
    if(close(input))failed=1;
    if(close(output))failed=1;
    if(!failed&&fsync(destination))failed=1;
    if(failed)(void)unlinkat(destination,name,0);
    return failed?-1:0;
}
#endif
