/* Independent local services. No vendor permit, mode revision, network policy
 * mutation or fallback. The caller supplies fixed executable/specification only.
 * Children must stay foreground and must not create independent processes. */
#ifndef LISA_AUXILIARY_SUPERVISOR_H
#define LISA_AUXILIARY_SUPERVISOR_H
#include "boot_ledger.h"

static inline int auxiliary_save(int runtime,uid_t owner,const char *name,struct guardian_record *record) {
    struct guardian_record previous; int existing=guardian_read(runtime,owner,name,&previous);
    if(existing<0||record->revision!=1||
        (existing==1&&record->phase!=G_RESERVING)||
        (existing==0&&(previous.guardian!=record->guardian||previous.guardian_ticks!=record->guardian_ticks)&&
         (record->phase!=G_RESERVING||process_live(previous.guardian,previous.guardian_ticks)||
          process_live(previous.child,previous.child_ticks)))) return -1;
    char text[256],temporary[64]; uint64_t nonce;
    int size=guardian_format(text,sizeof(text),record);
    if(size<0||size>=(int)sizeof(text)||boot_ledger_nonce(&nonce)) return -1;
    snprintf(temporary,sizeof(temporary),".aux-%" PRIx64 ".tmp",nonce);
    int fd=openat(runtime,temporary,O_WRONLY|O_CREAT|O_EXCL|O_NOFOLLOW|O_CLOEXEC,0600);
    if(fd<0) return -1;
    int failed=store_write_all(fd,text,(size_t)size)||fsync(fd);
    if(close(fd)) failed=1;
    if(!failed&&renameat(runtime,temporary,runtime,name)) failed=1;
    if(!failed&&fsync(runtime)) failed=1;
    if(failed) unlinkat(runtime,temporary,0);
    return failed?-1:0;
}

static inline enum guardian_result auxiliary_status(int runtime,uid_t owner,const char *boot,
    const struct guardian_spec *spec,struct guardian_record *record) {
    char name[32],lock[32],control[32]; struct stat expected; struct sockaddr_un address;
    if(!store_directory_valid(runtime,owner)||guardian_names(spec,name,lock,control)||
        guardian_target(spec,&expected)||expected.st_nlink!=1||guardian_read(runtime,owner,name,record)||
        record->revision!=1||strcmp(record->boot,boot)||record->phase!=G_RUNNING||
        !guardian_exec_observed(record->child,record->child_ticks,&expected,spec)||
        !process_live(record->guardian,record->guardian_ticks)||guardian_address(runtime,control,&address)) return GUARD_RECOVERY;
    int fd=socket(AF_UNIX,SOCK_SEQPACKET|SOCK_CLOEXEC|SOCK_NONBLOCK,0);
    if(fd<0) return GUARD_FAILED;
    struct ucred peer; socklen_t size=sizeof(peer); char response;
    int valid=!connect(fd,(struct sockaddr*)&address,sizeof(address))&&
        !getsockopt(fd,SOL_SOCKET,SO_PEERCRED,&peer,&size)&&peer.uid==owner&&peer.pid==record->guardian&&
        process_live(peer.pid,record->guardian_ticks)&&send(fd,"Q",1,MSG_NOSIGNAL)==1&&
        guardian_readable(fd,500)&&recv(fd,&response,1,0)==1&&response=='R'&&
        guardian_exec_observed(record->child,record->child_ticks,&expected,spec);
    close(fd); return valid?GUARD_OK:GUARD_RECOVERY;
}

static inline void auxiliary_run(int runtime,uid_t owner,const char *boot,const struct guardian_spec *spec,
    int notify,int role_lock,const char *record_name,const char *socket_name) {
    guardian_termination=0; umask(077);
    signal(SIGPIPE,SIG_IGN); signal(SIGCHLD,SIG_DFL); signal(SIGTERM,guardian_signal);
    signal(SIGINT,guardian_signal); signal(SIGHUP,guardian_signal); signal(SIGALRM,guardian_signal);
    alarm(5);
    struct guardian_started response={.result=GUARD_FAILED}; struct guardian_record *record=&response.record;
    int setup[2]={-1,-1},go[2]={-1,-1},control=-1,stop_client=-1,announced=0,bound=0;
    pid_t child=-1; struct process_stamp self; struct stat expected;
    const int keep[]={runtime,notify,role_lock};
    if(guardian_close_except(keep,3)||setsid()<0||prctl(PR_SET_CHILD_SUBREAPER,1)||
        process_stamp(getpid(),&self)||guardian_target(spec,&expected)||expected.st_nlink!=1||chdir("/")||clearenv()) goto finish;
    struct rlimit core={0,0};
    if(setrlimit(RLIMIT_CORE,&core)||setenv("PATH","/usr/sbin:/usr/bin:/sbin:/bin",1)||setenv("LC_ALL","C",1)) goto finish;
    int null=open("/dev/null",O_RDWR|O_CLOEXEC);
    if(null<0) goto finish;
    for(int fd=0;fd<3;++fd) if(dup2(null,fd)<0) { close(null); goto finish; }
    if(null>2) close(null);
    *record=(struct guardian_record){.revision=1,.guardian=getpid(),.guardian_ticks=self.ticks,.phase=G_RESERVING};
    memcpy(record->boot,boot,37);
    if(auxiliary_save(runtime,owner,record_name,record)) goto finish;
    struct sockaddr_un address;
    control=socket(AF_UNIX,SOCK_SEQPACKET|SOCK_CLOEXEC|SOCK_NONBLOCK,0);
    if(control<0||guardian_address(runtime,socket_name,&address)||
        bind(control,(struct sockaddr*)&address,sizeof(address))) goto finish;
    bound=1;
    if(listen(control,2)||pipe2(setup,O_CLOEXEC)||pipe2(go,O_CLOEXEC)||guardian_termination) goto finish;
    pid_t parent=getpid(); child=fork();
    if(!child) { close(setup[0]); close(go[1]); guardian_child(spec,parent,setup[1],go[0]); _exit(75); }
    if(child<0) goto finish;
    close(setup[1]);setup[1]=-1;close(go[0]);go[0]=-1;
    char token;struct process_stamp stamp;
    if(process_stamp(child,&stamp)) goto finish;
    record->child=child;record->child_ticks=stamp.ticks;record->phase=G_FORKED;
    if(auxiliary_save(runtime,owner,record_name,record)||!guardian_readable(setup[0],1500)||
        read(setup[0],&token,1)!=1||token!='P'||guardian_termination) goto finish;
    record->phase=G_PREPARED;
    if(auxiliary_save(runtime,owner,record_name,record)||write(go[1],"G",1)!=1) goto finish;
    close(go[1]);go[1]=-1;
    if(!guardian_readable(setup[0],1500)||read(setup[0],&token,1)!=0) goto finish;
    uint64_t until=guardian_milliseconds()+1500;
    while(!guardian_exec_observed(child,stamp.ticks,&expected,spec)) {
        if(guardian_termination||!process_live(child,stamp.ticks)||guardian_milliseconds()>=until) goto finish;
        struct timespec delay={0,20000000};nanosleep(&delay,NULL);
    }
    record->phase=G_RUNNING;
    if(auxiliary_save(runtime,owner,record_name,record)||guardian_termination) goto finish;
    response.result=GUARD_OK;
    if(write(notify,&response,sizeof(response))!=sizeof(response)) goto finish;
    announced=1;alarm(0);close(notify);notify=-1;
    uint64_t deadline=spec->maximum_seconds?guardian_milliseconds()+spec->maximum_seconds*1000u:0;
    while(!guardian_termination&&(!deadline||guardian_milliseconds()<deadline)) {
        siginfo_t status={0};
        if(waitid(P_PID,child,&status,WEXITED|WNOHANG|WNOWAIT)||status.si_pid) break;
        if(guardian_readable(control,100)) {
            int peer=accept4(control,NULL,NULL,SOCK_CLOEXEC|SOCK_NONBLOCK);
            if(peer<0) continue;
            struct ucred credentials;socklen_t size=sizeof(credentials);char command[2];
            if(!getsockopt(peer,SOL_SOCKET,SO_PEERCRED,&credentials,&size)&&credentials.uid==owner&&
                guardian_readable(peer,100)&&recv(peer,command,sizeof(command),MSG_TRUNC)==1) {
                if(command[0]=='S') {stop_client=peer;break;}
                if(command[0]=='Q') {
                    char answer=guardian_exec_observed(child,stamp.ticks,&expected,spec)?'R':'F';
                    if(send(peer,&answer,1,MSG_NOSIGNAL)!=1) {close(peer);continue;}
                }
            }
            close(peer);
        }
    }
finish: ;
    int teardown=child>1?guardian_teardown(child):0;
    int absent=spec->actors_absent&&spec->actors_absent(record);
    record->phase=announced&&absent&&!teardown?G_STOPPED:G_FAILED;
    int saved=record->guardian>1&&!auxiliary_save(runtime,owner,record_name,record);
    if(control>=0)close(control);
    if(bound)unlinkat(runtime,socket_name,0);
    if(stop_client>=0) {if(send(stop_client,saved&&absent&&!teardown?"S":"F",1,MSG_NOSIGNAL)!=1)saved=0;close(stop_client);}
    for(unsigned i=0;i<2;++i){if(setup[i]>=0)close(setup[i]);if(go[i]>=0)close(go[i]);}
    if(!announced&&notify>=0){response.result=GUARD_FAILED;if(write(notify,&response,sizeof(response))!=sizeof(response))saved=0;close(notify);}
    close(role_lock);_exit(saved?0:76);
}

static inline enum guardian_result auxiliary_start(int runtime,uid_t owner,const char *boot,
    const struct guardian_spec *spec,struct guardian_started *started) {
    memset(started,0,sizeof(*started));started->result=GUARD_DENIED;
    struct sigaction action;char name[32],lock_name[32],control[32];
    if(!store_directory_valid(runtime,owner)||!gate_boot_valid(boot)||!spec->actors_absent||
        guardian_names(spec,name,lock_name,control)||sigaction(SIGCHLD,NULL,&action)||
        action.sa_handler!=SIG_DFL||(action.sa_flags&SA_NOCLDWAIT)) return GUARD_DENIED;
    int lock=guardian_role_lock(runtime,owner,lock_name);
    if(lock<0) {
        started->result=auxiliary_status(runtime,owner,boot,spec,&started->record)==GUARD_OK?GUARD_OK:GUARD_BUSY;
        return started->result;
    }
    struct guardian_record previous;int existing=guardian_read(runtime,owner,name,&previous);
    if(existing<0||(existing==0&&(strcmp(previous.boot,boot)||process_live(previous.guardian,previous.guardian_ticks)||
        process_live(previous.child,previous.child_ticks)||!spec->actors_absent(&previous)))) {close(lock);return GUARD_RECOVERY;}
    struct stat info;
    if(!fstatat(runtime,control,&info,AT_SYMLINK_NOFOLLOW)) {
        if(!S_ISSOCK(info.st_mode)||info.st_uid!=owner||unlinkat(runtime,control,0)||fsync(runtime)) {close(lock);return GUARD_RECOVERY;}
    }else if(errno!=ENOENT){close(lock);return GUARD_RECOVERY;}
    int result[2];if(pipe2(result,O_CLOEXEC)){close(lock);return GUARD_FAILED;}
    pid_t child=fork();
    if(!child){close(result[0]);auxiliary_run(runtime,owner,boot,spec,result[1],lock,name,control);}
    close(result[1]);close(lock);enum guardian_result answer=GUARD_FAILED;
    if(child>1&&guardian_readable(result[0],5500)&&read(result[0],started,sizeof(*started))==sizeof(*started))answer=started->result;
    close(result[0]);
    if(child>1&&answer!=GUARD_OK)guardian_teardown(child);
    return answer;
}
#endif
