/* Bounded root qualification on own pre-existing loopback sockets only. The
 * administrative driver owns empty chains and an independent cleanup watchdog. */
#define _GNU_SOURCE
#include "flow_policy.h"
#include "closed_transition.h"

static unsigned checks,failures;
static int check(const char *name,unsigned index,int ok) {
    ++checks; failures+=!ok;
    printf("{\"event\":\"closed-flow-check\",\"check\":\"%s\",\"case\":%u,\"ok\":%s}\n",name,index,ok?"true":"false");
    fflush(stdout); return ok;
}
static int wait_readable(int fd,int milliseconds) {
    struct pollfd ready={fd,POLLIN,0}; return poll(&ready,1,milliseconds);
}
static ssize_t datagram(int source,int destination) {
    struct sockaddr_storage address; socklen_t size=sizeof(address);
    if(getsockname(destination,(struct sockaddr*)&address,&size)) return -2;
    return sendto(source,"lisa-exact-flow",16,MSG_NOSIGNAL,(struct sockaddr*)&address,size);
}
static int udp_pair(int family,int mapped,struct pair *pair) {
    struct sockaddr_storage address={0}; socklen_t length;
    if(family==AF_INET) {
        struct sockaddr_in *a=(void*)&address; a->sin_family=AF_INET;
        a->sin_addr.s_addr=htonl(INADDR_LOOPBACK); length=sizeof(*a);
    } else {
        struct sockaddr_in6 *a=(void*)&address; a->sin6_family=AF_INET6; length=sizeof(*a);
        if(inet_pton(AF_INET6,mapped?"::ffff:127.0.0.1":"::1",&a->sin6_addr)!=1) return -1;
    }
    pair->client=socket(family,SOCK_DGRAM|SOCK_CLOEXEC,0);
    pair->peer=socket(family,SOCK_DGRAM|SOCK_CLOEXEC,0);
    return pair->client<0 || pair->peer<0 || bind(pair->client,(struct sockaddr*)&address,length) ||
        bind(pair->peer,(struct sockaddr*)&address,length)?-1:0;
}
static int udp_exchange(struct pair *pair) {
    char bytes[32];
    return datagram(pair->client,pair->peer)==16 && wait_readable(pair->peer,500)==1 &&
        recv(pair->peer,bytes,sizeof(bytes),MSG_DONTWAIT)==16 && !memcmp(bytes,"lisa-exact-flow",16);
}
static int udp_blocked(int source,int destination) {
    errno=0; ssize_t sent=datagram(source,destination);
    return (sent==16 || (sent<0 && (errno==EPERM || errno==EACCES))) && wait_readable(destination,200)==0;
}
static int snapshot(struct pair *pair,int family,int protocol,struct saved_flow *flow) {
    struct stat info; struct inet_diag_sockid id={0};
    if(fstat(pair->client,&info) || !S_ISSOCK(info.st_mode)) return -1;
    if(protocol==IPPROTO_TCP) {
        struct inet_diag_msg found;
        if(socket_id(pair->client,family,&id) || diag_exchange(family,&id,0,&found) || found.idiag_inode!=info.st_ino) return -1;
        id=found.id;
    } else {
        struct sockaddr_storage local={0},peer={0}; socklen_t length=sizeof(local);
        if(getsockname(pair->client,(struct sockaddr*)&local,&length)) return -1;
        length=sizeof(peer);
        if(getsockname(pair->peer,(struct sockaddr*)&peer,&length)) return -1;
        if(family==AF_INET) {
            struct sockaddr_in *a=(void*)&local,*b=(void*)&peer;
            id.idiag_sport=a->sin_port; id.idiag_dport=b->sin_port;
            memcpy(id.idiag_src,&a->sin_addr,4); memcpy(id.idiag_dst,&b->sin_addr,4);
        } else {
            struct sockaddr_in6 *a=(void*)&local,*b=(void*)&peer;
            id.idiag_sport=a->sin6_port; id.idiag_dport=b->sin6_port;
            memcpy(id.idiag_src,&a->sin6_addr,16); memcpy(id.idiag_dst,&b->sin6_addr,16);
        }
        id.idiag_cookie[0]=id.idiag_cookie[1]=INET_DIAG_NOCOOKIE;
    }
    *flow=(struct saved_flow){family,protocol,info.st_ino,id};
    return flow_valid(flow)?0:-1;
}
struct context {
    int state,runtime,pause_after_deny,pause_after_stop,first_denial;
    char boot[37]; struct flow_plan plan;
    struct pair targets[6],controls[6];
};
static int load(struct context *c,struct flow_plan *plan) { return flow_plan_read(c->state,0,1,c->boot,plan); }
static int udp_inodes_absent(const struct flow_plan *plan) {
    const char *tables[]={"/proc/net/udp","/proc/net/udp6"};
    for(unsigned table=0;table<2;++table) {
        FILE *file=fopen(tables[table],"r"); char line[512]; int absent=1;
        if(!file) return 0;
        if(!fgets(line,sizeof(line),file)) absent=0;
        while(absent && fgets(line,sizeof(line),file)) {
            if(!strchr(line,'\n')) { absent=0; break; }
            char *save,*token=strtok_r(line," \t\r\n",&save);
            for(unsigned column=0;token && column<9;++column) token=strtok_r(NULL," \t\r\n",&save);
            if(!token) { absent=0; break; }
            char *end; errno=0; unsigned long long inode=strtoull(token,&end,10);
            if(errno || *end) { absent=0; break; }
            for(unsigned i=0;i<plan->count;++i)
                if(plan->flows[i].protocol==IPPROTO_UDP && plan->flows[i].inode==inode) absent=0;
        }
        if(ferror(file)) absent=0;
        fclose(file); if(!absent) return 0;
    }
    return 1;
}
static int deny(void *pointer) {
    struct context *c=pointer; struct flow_plan saved;
    if(load(c,&saved) || flow_policy_apply(&saved)) return -1;
    if(!c->first_denial) {
        c->first_denial=1;
        for(unsigned i=1;i<6;i+=2) {
            if(!check("udp_output_denied",i,udp_blocked(c->targets[i].client,c->targets[i].peer)) ||
                !check("udp_input_denied",i,udp_blocked(c->targets[i].peer,c->targets[i].client))) return -1;
        }
    }
    return 0;
}
static int stop(void *pointer) {
    struct context *c=pointer; struct flow_plan saved;
    if(load(c,&saved) || flow_policy_verify(&saved)) return -1;
    for(unsigned i=0;i<6;++i) {
        if(c->targets[i].client<0) continue;
        if(saved.flows[i].protocol==IPPROTO_TCP) {
            struct inet_diag_msg found; char byte;
            if(diag_exchange(saved.flows[i].family,&saved.flows[i].id,0,&found) ||
                found.idiag_inode!=saved.flows[i].inode || memcmp(found.id.idiag_cookie,saved.flows[i].id.idiag_cookie,8)) return -1;
            if(!check("cookie_tcp_destroyed",i,!diag_exchange(saved.flows[i].family,&saved.flows[i].id,1,NULL))) return -1;
            errno=0;
            ssize_t size=recv(c->targets[i].client,&byte,1,MSG_DONTWAIT);
            if(size>=0 || errno!=ECONNABORTED || !check("tcp_reset_quarantined",i,wait_readable(c->targets[i].peer,200)==0)) return -1;
        }
        close(c->targets[i].client); c->targets[i].client=-1;
    }
    return 0;
}
static int verify(void *pointer) {
    struct context *c=pointer; struct flow_plan saved;
    if(load(c,&saved) || flow_policy_verify(&saved) || !udp_inodes_absent(&saved)) return -1;
    for(unsigned i=0;i<6;++i) {
        if(c->targets[i].client>=0 || wait_readable(c->targets[i].peer,0)!=0) return -1;
        if(saved.flows[i].protocol==IPPROTO_TCP) {
            struct inet_diag_msg found;
            int reply=diag_exchange(saved.flows[i].family,&saved.flows[i].id,0,&found);
            if(reply!=-ENOENT && reply!=-ESTALE) return -1;
        }
    }
    return 0;
}
static void checkpoint(void *pointer,enum close_phase phase) {
    struct context *c=pointer;
    if(phase==CLOSE_DENIED && c->pause_after_deny) {
        puts("{\"event\":\"closed-flow-denied-ready\",\"persistent_fence\":true}"); fflush(stdout);
        for(;;) pause();
    }
    if(phase==CLOSE_STOPPED && c->pause_after_stop) {
        puts("{\"event\":\"closed-flow-stopped-ready\",\"persistent_fence\":true}"); fflush(stdout);
        for(;;) pause();
    }
}
static int controls(struct context *c,const char *name) {
    for(unsigned i=0;i<6;++i)
        if(!check(name,i,i%2?udp_exchange(&c->controls[i]):exchange(&c->controls[i]))) return -1;
    return 0;
}
static int fixture_rule(struct flow_plan *plan,int remove,int accept) {
    char chain[32],output[64];
    if(flow_chain_name(plan,0,chain,sizeof(chain))) return -1;
    char *const remove_first[]={"iptables","-D",chain,"1",NULL};
    char *const add_accept[]={"iptables","-A",chain,"-j","ACCEPT",NULL};
    char *const remove_accept[]={"iptables","-D",chain,"-j","ACCEPT",NULL};
    return flow_tool(AF_INET,accept?(remove?remove_accept:add_accept):remove_first,output,sizeof(output));
}
#define REQUIRE(condition,name,index) do { if(!check(name,index,(condition))) goto cleanup; } while(0)
static int resume_fixture(int directory) {
    struct context c={.state=-1,.runtime=-1,.first_denial=1}; int ok=0;
    for(unsigned i=0;i<6;++i) c.targets[i]=c.controls[i]=(struct pair){-1,-1};
    c.state=openat(directory,"state",O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC);
    c.runtime=openat(directory,"run",O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC);
    REQUIRE(store_directory_valid(c.state,0)&&store_directory_valid(c.runtime,0),"resume_private_dirs",6);
    char boot[38]; int file=open("/proc/sys/kernel/random/boot_id",O_RDONLY|O_CLOEXEC);
    ssize_t size=file>=0?read(file,boot,sizeof(boot)):-1; if(file>=0) close(file);
    REQUIRE(size==37&&boot[36]=='\n',"resume_boot",6); boot[36]=0; strcpy(c.boot,boot);
    REQUIRE(!load(&c,&c.plan)&&c.plan.count==6,"resume_saved_plan",6);
    struct close_record pending; struct mode_record intent;
    REQUIRE(!close_read(c.state,0,&pending)&&pending.base_revision==1&&pending.target==LISA_MODE_PAUSED&&
        pending.phase==CLOSE_STOPPED,"resume_stopped_fence",6);
    /* These are the private fixture's sockets, created only by the dead probe.
     * A new coordinator has no inherited target descriptors to rely on. */
    REQUIRE(udp_inodes_absent(&c.plan),"resume_old_inodes_absent",6);
    struct close_ops ops={deny,stop,verify,NULL,&c};
    REQUIRE(close_execute(c.state,c.runtime,0,1,LISA_MODE_PAUSED,&ops)==CLOSE_OK,"resume_transaction_complete",6);
    REQUIRE(mode_store_read(c.state,0,&intent)==STORE_OK&&intent.revision==2&&
        mode_store_boot_choice(c.state,0)==LISA_MODE_PAUSED,"resume_revision_unchanged",6);
    REQUIRE(!flow_policy_verify(&c.plan),"resume_policy_verified",6);
    ok=1;
cleanup:
    if(c.state>=0) close(c.state);
    if(c.runtime>=0) close(c.runtime);
    printf("{\"event\":\"closed-flow-resume-summary\",\"checks\":%u,\"failures\":%u,\"ok\":%s,"
        "\"audio_captured\":false,\"vendor_processes_changed\":false,\"isolation_verified\":false}\n",
        checks,failures,ok&&!failures?"true":"false");
    return ok&&!failures?0:4;
}
int main(int argc,char **argv) {
    int resume=argc==3&&!strcmp(argv[1],"--resume-own-loopback-transition");
    if(geteuid() || (argc!=3&&argc!=4) || (!resume&&strcmp(argv[1],"--own-loopback-transition")) ||
        (argc==4&&strcmp(argv[3],"--pause-after-deny")&&strcmp(argv[3],"--pause-after-stop"))) return 2;
    const char prefix[]="/bkupgrade/data/opt/lisa-controller-lab/closed-flow.";
    if(strncmp(argv[2],prefix,strlen(prefix)) || strlen(argv[2])!=strlen(prefix)+6) return 2;
    for(const char *at=argv[2]+strlen(prefix);*at;++at)
        if(!((*at>='a'&&*at<='z')||(*at>='A'&&*at<='Z')||(*at>='0'&&*at<='9'))) return 2;
    pid_t parent=getppid();
    if(prctl(PR_SET_PDEATHSIG,SIGKILL) || getppid()!=parent) return 3;
    alarm(60); umask(077);
    struct context c={.state=-1,.runtime=-1,
        .pause_after_deny=argc==4&&!strcmp(argv[3],"--pause-after-deny"),
        .pause_after_stop=argc==4&&!strcmp(argv[3],"--pause-after-stop")};
    for(unsigned i=0;i<6;++i) c.targets[i]=c.controls[i]=(struct pair){-1,-1};
    int directory=open(argv[2],O_RDONLY|O_DIRECTORY|O_CLOEXEC|O_NOFOLLOW),ok=0;
    if(resume) {
        if(directory<0 || !store_directory_valid(directory,0)) return 3;
        int result=resume_fixture(directory); close(directory); return result;
    }
    REQUIRE(directory>=0 && store_directory_valid(directory,0),"private_fixture",6);
    REQUIRE(!mkdirat(directory,"state",0700) && !mkdirat(directory,"run",0700),"private_state_runtime",6);
    c.state=openat(directory,"state",O_RDONLY|O_DIRECTORY|O_CLOEXEC);
    c.runtime=openat(directory,"run",O_RDONLY|O_DIRECTORY|O_CLOEXEC);
    REQUIRE(c.state>=0&&c.runtime>=0,"open_state_runtime",6);
    int file=open("/proc/sys/kernel/random/boot_id",O_RDONLY|O_CLOEXEC); char boot[38];
    ssize_t size=file>=0?read(file,boot,sizeof(boot)):-1; if(file>=0) close(file);
    REQUIRE(size==37&&boot[36]=='\n',"current_boot_read",6); boot[36]=0;
    strcpy(c.boot,boot); strcpy(c.plan.boot,boot); c.plan.revision=1; c.plan.count=6;
    file=openat(directory,"chain",O_RDONLY|O_NOFOLLOW|O_CLOEXEC);
    size=file>=0?read(file,c.plan.chain,sizeof(c.plan.chain)-1):-1; if(file>=0) close(file);
    REQUIRE(size>0 && c.plan.chain[size-1]=='\n',"owned_chain_binding",6); c.plan.chain[size-1]=0;
    struct mode_record intent;
    REQUIRE(mode_store_request(c.state,0,0,LISA_MODE_ALICE,&intent)==STORE_OK,"fixture_alice_intent",6);
    char permit[160]; int length=snprintf(permit,sizeof(permit),"LISA_VENDOR_PERMIT_V1 1 %s\n",boot);
    file=openat(c.runtime,"vendor.permit",O_WRONLY|O_CREAT|O_EXCL|O_CLOEXEC,0600);
    REQUIRE(file>=0 && !store_write_all(file,permit,(size_t)length) && !close(file),"fixture_permit",6);
    for(unsigned i=0;i<6;++i) {
        int family=i<2?AF_INET:AF_INET6,mapped=i>=4,udp=i%2;
        REQUIRE(udp?(!udp_pair(family,mapped,&c.targets[i])&&!udp_pair(family,mapped,&c.controls[i])&&
            udp_exchange(&c.targets[i])&&udp_exchange(&c.controls[i])):
            (!make_pair(family,mapped,&c.targets[i])&&!make_pair(family,mapped,&c.controls[i])&&
            exchange(&c.targets[i])&&exchange(&c.controls[i])),"baseline",i);
        REQUIRE(!snapshot(&c.targets[i],family,udp?IPPROTO_UDP:IPPROTO_TCP,&c.plan.flows[i]),"owned_snapshot",i);
    }
    REQUIRE(!flow_plan_publish(c.state,0,&c.plan),"evidence_persisted_before_close",6);
    struct close_ops ops={deny,stop,verify,checkpoint,&c};
    REQUIRE(close_execute(c.state,c.runtime,0,1,LISA_MODE_PAUSED,&ops)==CLOSE_OK,"transaction_complete",6);
    struct close_record closed;
    REQUIRE(!close_read(c.state,0,&closed)&&closed.phase==CLOSE_COMPLETE&&
        mode_store_boot_choice(c.state,0)==LISA_MODE_PAUSED&&!gate_permit_valid(c.runtime,0,1,boot),"closed_fence_retained",6);
    REQUIRE(!controls(&c,"control_after_close"),"controls_survive_close",6);
    REQUIRE(close_execute(c.state,c.runtime,0,1,LISA_MODE_PAUSED,&ops)==CLOSE_OK,"repeat_reverifies_plan",6);
    REQUIRE(mode_store_read(c.state,0,&intent)==STORE_OK&&intent.revision==2,"revision_not_incremented_twice",6);
    REQUIRE(!fixture_rule(&c.plan,1,0)&&flow_policy_verify(&c.plan)<0,"missing_rule_detected",6);
    REQUIRE(close_execute(c.state,c.runtime,0,1,LISA_MODE_PAUSED,&ops)==CLOSE_OK,"resume_repairs_missing_drop",6);
    REQUIRE(!fixture_rule(&c.plan,0,1)&&close_execute(c.state,c.runtime,0,1,LISA_MODE_PAUSED,&ops)==CLOSE_POLICY,
        "unknown_rule_refuses_completion",6);
    REQUIRE(mode_store_boot_choice(c.state,0)==LISA_MODE_PAUSED&&!gate_permit_valid(c.runtime,0,1,boot),"failure_keeps_closed",6);
    REQUIRE(!fixture_rule(&c.plan,1,1)&&close_execute(c.state,c.runtime,0,1,LISA_MODE_PAUSED,&ops)==CLOSE_OK,
        "explicit_fixture_repair_resumes",6);
    REQUIRE(!controls(&c,"control_after_repair"),"controls_survive_repair",6);
    struct flow_plan reloaded;
    REQUIRE(!load(&c,&reloaded)&&reloaded.count==6,"evidence_survives_socket_destruction",6);
    ok=1;
cleanup:
    for(unsigned i=0;i<6;++i) {
        if(c.targets[i].client>=0) close(c.targets[i].client);
        if(c.targets[i].peer>=0) close(c.targets[i].peer);
        if(c.controls[i].client>=0) close(c.controls[i].client);
        if(c.controls[i].peer>=0) close(c.controls[i].peer);
    }
    if(c.state>=0) close(c.state);
    if(c.runtime>=0) close(c.runtime);
    if(directory>=0) close(directory);
    printf("{\"event\":\"closed-flow-summary\",\"checks\":%u,\"failures\":%u,\"ok\":%s,\"audio_captured\":false,"
        "\"vendor_processes_changed\":false,\"isolation_verified\":false}\n",checks,failures,ok&&!failures?"true":"false");
    return ok&&!failures?0:4;
}
