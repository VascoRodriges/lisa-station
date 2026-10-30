/* Reviewed ARM syscall metadata tracer. No read/write/audio/auth buffer
 * inspection. The caller owns ONLY these new workers, installs kernel guards,
 * verifies the private view and retains/releases its DATA reference explicitly. */
#ifndef LISA_SDK_METADATA_TRACE_H
#define LISA_SDK_METADATA_TRACE_H
#include <elf.h>
#include <sys/ptrace.h>
#include <sys/uio.h>
#ifndef __arm__
#error This diagnostic tracer requires the reviewed ARM register ABI
#endif
struct task{pid_t tid;unsigned pending,first,second;uint32_t pc,link;int active,entering;char path[256];};
struct observed{unsigned entries,errors,denied,sockets,opens,clones,threads,lost_registers;int status,execs,verified,bounded,drained,path_control,binding_seen;};
static uint64_t now_ms(void){struct timespec ts;if(clock_gettime(CLOCK_MONOTONIC,&ts))return 0;return (uint64_t)ts.tv_sec*1000+(uint64_t)ts.tv_nsec/1000000;}
static int reg_state(pid_t tid,unsigned *number,int32_t *result,uint32_t *first,uint32_t *second,uint32_t *pc,uint32_t *link){
    uint32_t registers[18];struct iovec buffer={registers,sizeof(registers)};
    if(ptrace(PTRACE_GETREGSET,tid,(void *)(uintptr_t)NT_PRSTATUS,&buffer)||buffer.iov_len!=sizeof(registers))return -1;
    *number=registers[7];*result=(int32_t)registers[0];*first=registers[0];*second=registers[1];*pc=registers[15];*link=registers[14];return 0;
}
/* Map the two sampled code-register values to file offsets, never code bytes
 * or stack contents. This is diagnostic provenance, not an admission decision. */
static int sdk_trace_origin(pid_t tid,int output,unsigned *bytes,uint32_t pc,uint32_t link){
    char path[80],line[PATH_MAX+256];snprintf(path,sizeof(path),"/proc/%ld/maps",(long)tid);
    FILE *maps=fopen(path,"r");if(!maps)return errno==ENOENT||errno==ESRCH?0:-1;
    unsigned count=0;int failed=0;
    while(fgets(line,sizeof(line),maps)){
        if(++count>8192||!strchr(line,'\n')){failed=1;break;}
        unsigned long long low,high,offset,inode;unsigned major,minor;char access[5];int position=0;
        if(sscanf(line,"%llx-%llx %4s %llx %x:%x %llu %n",&low,&high,access,&offset,&major,&minor,&inode,&position)!=7)continue;
        uint32_t addresses[]={pc,link};
        for(unsigned i=0;i<2&&*bytes<32768;++i){uint64_t address=addresses[i]&~UINT32_C(1);
            if(address<low||address>=high)continue;
            char *object=line+position;size_t length=strlen(object);if(length&&object[length-1]=='\n')object[length-1]=0;
            char row[PATH_MAX+256];int size=snprintf(row,sizeof(row),"network-origin register=%s value=%x offset=%llx device=%x:%x inode=%llu access=%s object=%s\n",
                i?"lr":"pc",addresses[i],offset+address-low,major,minor,inode,access,object);
            if(size<=0||size>=(int)sizeof(row)||store_write_all(output,row,(size_t)size)){failed=1;break;}*bytes+=(unsigned)size;
        }if(failed)break;
    }if(ferror(maps))failed=1;fclose(maps);return failed?-1:0;
}
static int tgid_is(pid_t tid,pid_t leader){
    char path[80],line[256];snprintf(path,sizeof(path),"/proc/%ld/status",(long)tid);FILE *file=fopen(path,"r");if(!file)return errno==ENOENT||errno==ESRCH?-1:0;
    int good=0;while(fgets(line,sizeof(line),file)){long value;if(sscanf(line,"Tgid: %ld",&value)==1){good=value==leader;break;}}
    fclose(file);return good;
}
/* Read only a pathname argument for these fixed filesystem syscall ABIs.
 * Never inspect buffers supplied to read/write, socket payloads or SDK objects. */
static void syscall_path(pid_t tid,unsigned number,uint32_t first,uint32_t second,char path[256]){
    uintptr_t address=0;path[0]=0;
    if(number==SYS_open||number==SYS_access||number==SYS_stat64||number==SYS_lstat64||number==SYS_readlink||number==SYS_mkdir)address=first;
    if(number==SYS_openat||number==SYS_faccessat||number==SYS_fstatat64||number==SYS_readlinkat||number==SYS_mkdirat)address=second;
    if(!address)return;
    for(unsigned offset=0;offset<252;offset+=sizeof(long)){
        errno=0;long word=ptrace(PTRACE_PEEKDATA,tid,(void *)(address+offset),NULL);
        if(word==-1&&errno){path[0]=0;return;}
        const unsigned char *bytes=(const unsigned char *)&word;
        for(unsigned i=0;i<sizeof(long);++i){unsigned position=offset+i;unsigned char value=bytes[i];
            if(!value){path[position]=0;return;}
            path[position]=value>=32&&value<=126?(char)value:'?';}
    }
    path[252]=0;
}
/* In a common coordinator, unrelated bus/relay children must not be reaped
 * or treated as traced SDK threads. Clone event enrollment supplies the exact
 * task family before those TIDs are polled. Default old diagnostic behavior is
 * retained when family_only is zero. */
static pid_t sdk_trace_wait(struct task *tasks,unsigned count,int *status,int family_only){
    if(!family_only)return waitpid(-1,status,__WALL|WNOHANG);
    unsigned active=0,missing=0;
    for(unsigned i=0;i<count;++i)if(tasks[i].active){
        ++active;pid_t result=waitpid(tasks[i].tid,status,__WALL|WNOHANG);
        if(result>0)return result;
        if(result<0){if(errno==EINTR)return -1;if(errno!=ECHILD)return -1;++missing;}
    }
    if(!active||missing==active){errno=ECHILD;return -1;}
    return 0;
}
static int sdk_trace_worker(pid_t child,const char *expected,int *retained,struct observed *result,int paths,
    int (*view)(pid_t,struct stat *,void *),void *context,int family_only,int (*binding)(pid_t,void *),
    int (*received)(pid_t,unsigned,int32_t,void *),int (*idle)(pid_t,void *)){
    unsigned path_bytes=0;struct task tasks[80]={{.tid=child,.active=1,.entering=1}};unsigned count=1,live=1,stops=0;
    uint64_t deadline=now_ms()+6000;int killing=0,failed=0,leader_owned=1;
    #define TRACE_FAIL() do{if(!failed)fprintf(stderr,"sdk trace stage %d errno %d\n",__LINE__,errno);failed=1;}while(0)
    while(live){
        if((now_ms()>deadline||stops>20000)&&!killing){result->bounded=1;if(leader_owned)kill(child,SIGKILL);killing=1;deadline=now_ms()+3000;}
        if(killing&&now_ms()>deadline){TRACE_FAIL();break;}
        /* Optional OWN provider pump. Never consumes a wait status or SDK buffer. */
        if(!killing&&!failed&&result->verified&&idle&&idle(child,context)<0){
            TRACE_FAIL();if(leader_owned)kill(child,SIGKILL);killing=1;deadline=now_ms()+3000;
        }
        int status=0;pid_t tid=sdk_trace_wait(tasks,count,&status,family_only);
        if(tid==0){struct timespec pause={0,100000};nanosleep(&pause,NULL);continue;}
        if(tid<0){if(errno==EINTR)continue;if(errno==ECHILD&&killing){live=0;break;}TRACE_FAIL();break;}
        unsigned slot=0;while(slot<count&&tasks[slot].tid!=tid)++slot;
        if(slot==count){
            if(count>=80||tgid_is(tid,child)==0){TRACE_FAIL();if(leader_owned)kill(child,SIGKILL);killing=1;deadline=now_ms()+3000;continue;}
            tasks[count++]=(struct task){.tid=tid,.active=1,.entering=1};++live;
        }
        if(WIFEXITED(status)||WIFSIGNALED(status)){
            if(tid==child){result->status=status;leader_owned=0;}
            if(tasks[slot].active){tasks[slot].active=0;--live;}
            continue;
        }
        if(!WIFSTOPPED(status)){TRACE_FAIL();break;}
        /* An exited proc entry may disappear before its queued ptrace event.
         * These TIDs come only from this guard-filtered child's clone events
         * or this tracer's wait queue; no unrelated process is attached. */
        if(killing){ptrace(PTRACE_CONT,tid,NULL,(void *)(intptr_t)SIGKILL);continue;}
        ++stops;int signal=WSTOPSIG(status),deliver=0;unsigned event=(unsigned)status>>16;
        if(event==PTRACE_EVENT_EXEC){
            struct stat data,actual,target;char path[PATH_MAX];++result->execs;
            snprintf(path,sizeof(path),"/proc/%ld/exe",(long)child);
            if(result->execs!=1||tid!=child||stat(path,&actual)||stat(expected,&target)||actual.st_dev!=target.st_dev||actual.st_ino!=target.st_ino||!view(child,&data,context))TRACE_FAIL();
            else{result->verified=1;snprintf(path,sizeof(path),"/proc/%ld/root/data/quasar",(long)child);
                *retained=open(path,O_RDONLY|O_DIRECTORY|O_CLOEXEC);if(*retained<0)TRACE_FAIL();}
        }else if(event==PTRACE_EVENT_CLONE){
            ++result->threads;unsigned long created=0;
            if(ptrace(PTRACE_GETEVENTMSG,tid,NULL,&created)||created<2||created>INT_MAX)TRACE_FAIL();
            else{unsigned next=0;while(next<count&&tasks[next].tid!=(pid_t)created)++next;
                if(next==count){if(count>=80||tgid_is((pid_t)created,child)==0)TRACE_FAIL();
                    else{tasks[count++]=(struct task){.tid=(pid_t)created,.active=1,.entering=1};++live;}}}
        }else if(signal==(SIGTRAP|0x80)){
            if(result->verified&&!result->binding_seen&&binding){
                int mapped=binding(child,context);if(mapped<0)TRACE_FAIL();else if(mapped)result->binding_seen=1;
            }
            unsigned number;int32_t returned;uint32_t first,second,pc,link;if(reg_state(tid,&number,&returned,&first,&second,&pc,&link)){
                if(errno==ESRCH){++result->lost_registers;continue;}
                TRACE_FAIL();
            }
            else if(tasks[slot].entering){tasks[slot].pending=number;tasks[slot].first=first;tasks[slot].second=second;tasks[slot].pc=pc;tasks[slot].link=link;
                syscall_path(tid,number,first,second,tasks[slot].path);
                if(result->verified){++result->entries;if(number==SYS_socket||number==SYS_socketpair||number==SYS_connect)++result->sockets;
                    if(number==SYS_open||number==SYS_openat)++result->opens;
                    if(number==SYS_clone||number==SYS_fork||number==SYS_vfork)++result->clones;}
            }else if(result->verified&&returned<0&&returned>=-4095){
                ++result->errors;if(returned==-EPERM)++result->denied;
                /* Numeric kernel ABI metadata only. Never dereference socket
                 * addresses, ancillary data or authentication buffers. */
                if(binding&&path_bytes<32768&&(returned==-EPERM||tasks[slot].pending==SYS_socket||tasks[slot].pending==SYS_socketpair||tasks[slot].pending==SYS_connect)){
                    char row[128];int used;
                    if(tasks[slot].pending==SYS_connect)used=snprintf(row,sizeof(row),"network syscall=%u fd=%u error=%d\n",tasks[slot].pending,tasks[slot].first,-returned);
                    else if(tasks[slot].pending==SYS_socket||tasks[slot].pending==SYS_socketpair)used=snprintf(row,sizeof(row),"network syscall=%u domain=%u type=%u error=%d\n",tasks[slot].pending,tasks[slot].first,tasks[slot].second,-returned);
                    else used=snprintf(row,sizeof(row),"denied syscall=%u error=%d\n",tasks[slot].pending,-returned);
                    if(used<=0||used>=(int)sizeof(row)||store_write_all(paths,row,(size_t)used))TRACE_FAIL();else path_bytes+=(unsigned)used;
                    if(sdk_trace_origin(tid,paths,&path_bytes,tasks[slot].pc,tasks[slot].link))TRACE_FAIL();
                }
                if(returned==-ENOENT&&!strcmp(tasks[slot].path,"/lisa-sdk-missing-metadata"))result->path_control=1;
                if(tasks[slot].path[0]&&path_bytes<32768){char row[320];
                    int used=snprintf(row,sizeof(row),"%u %d %s\n",tasks[slot].pending,-returned,tasks[slot].path);
                    if(used<=0||used>=(int)sizeof(row)||store_write_all(paths,row,(size_t)used))TRACE_FAIL();
                    else path_bytes+=(unsigned)used;}
            }
            /* Scalar FD/result metadata only. The optional observer may query
             * its private bus API; it never sees the SDK's I/O buffers. */
            if(!failed&&result->verified&&!tasks[slot].entering&&returned>0&&tasks[slot].pending==SYS_readv&&received&&
                received(child,tasks[slot].first,returned,context)<0)TRACE_FAIL();
            tasks[slot].entering=!tasks[slot].entering;
        }else if(signal!=SIGSTOP){deliver=signal;}
        if(failed&&!killing){if(leader_owned)kill(child,SIGKILL);killing=1;deadline=now_ms()+3000;}
        if(ptrace(PTRACE_SYSCALL,tid,NULL,(void *)(intptr_t)(killing?SIGKILL:deliver))&&errno!=ESRCH){TRACE_FAIL();break;}
    }
    if(failed){if(leader_owned)kill(child,SIGKILL);
        for(unsigned i=0;i<count;++i)if(tasks[i].active)ptrace(PTRACE_CONT,tasks[i].tid,NULL,(void *)(intptr_t)SIGKILL);
        uint64_t end=now_ms()+3000;
        while(now_ms()<end){int status;pid_t done=sdk_trace_wait(tasks,count,&status,family_only);
            if(done<0&&errno==ECHILD){live=0;break;}
            if(done>0&&WIFSTOPPED(status))ptrace(PTRACE_CONT,done,NULL,(void *)(intptr_t)SIGKILL);
            if(!done){struct timespec pause={0,1000000};nanosleep(&pause,NULL);}}
    }
    #undef TRACE_FAIL
    result->drained=!live;
    return failed||live?-1:0;
}
#endif
