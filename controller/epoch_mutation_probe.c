#define _GNU_SOURCE
#include <sys/statvfs.h>
#include <stdlib.h>
#include "epoch_mutation.h"
#include "pending_recovery.h"
#include "emergency_policy.h"
#define CHECK(x) do{++checks;if(!(x)){fprintf(stderr,"epoch-store draft check line %d\n",__LINE__);return 2;}}while(0)
static int selftest(const char *base){
 unsigned checks=0;umask(077);char path[256];snprintf(path,sizeof(path),"%s/lisa-epoch-store.XXXXXX",base);CHECK(mkdtemp(path));
 int runtime=open(path,O_RDONLY|O_DIRECTORY|O_CLOEXEC);CHECK(runtime>=0);
 uid_t owner=geteuid();struct epoch_lease a={.descriptor=-1},b={.descriptor=-1};
 struct epoch_owner identity={.boot="11111111-2222-4333-8444-555555555555",.chain="LISACQ_STORE",.initial_revision=1},actual;
 struct epoch_record state={.revision=1,.epoch=1,.previous=0,.phase=EPOCH_RESERVED},readback;
 CHECK(epoch_owner_read(runtime,owner,&actual)==1);CHECK(!epoch_store_lock(runtime,owner,&a));
 CHECK(epoch_store_lock(runtime,owner,&b)<0);CHECK(!epoch_owner_publish(&a,&identity));
 CHECK(!epoch_owner_publish(&a,&identity));CHECK(!epoch_owner_read(runtime,owner,&actual));
 CHECK(epoch_record_read(runtime,owner,&identity,&readback)==1);
 state.phase=EPOCH_CLOSED;CHECK(epoch_record_publish(&a,&identity,&state)<0);
 state.phase=EPOCH_RESERVED;CHECK(!epoch_record_publish(&a,&identity,&state));
 state.phase=EPOCH_CLOSED;CHECK(!epoch_record_publish(&a,&identity,&state));
 state.phase=EPOCH_ARMED;CHECK(epoch_record_publish(&a,&identity,&state)<0);
 state=(struct epoch_record){3,1,1,EPOCH_ARMING};CHECK(epoch_record_publish(&a,&identity,&state)<0);
 state=(struct epoch_record){3,2,1,EPOCH_ARMING};CHECK(!epoch_record_publish(&a,&identity,&state));
 state.phase=EPOCH_ARMED;CHECK(!epoch_record_publish(&a,&identity,&state));
 state.phase=EPOCH_OPEN;CHECK(epoch_record_publish(&a,&identity,&state)<0);
 state.phase=EPOCH_OPENING;CHECK(!epoch_record_publish(&a,&identity,&state));
 state.phase=EPOCH_OPEN;CHECK(!epoch_record_publish(&a,&identity,&state));
 state.phase=EPOCH_CLOSED;CHECK(epoch_record_publish(&a,&identity,&state)<0);
 state.phase=EPOCH_DENYING;CHECK(!epoch_record_publish(&a,&identity,&state));
 state.phase=EPOCH_CLOSED;CHECK(!epoch_record_publish(&a,&identity,&state));
 state=(struct epoch_record){5,3,2,EPOCH_ARMING};CHECK(!epoch_record_publish(&a,&identity,&state));
 struct epoch_owner wrong=identity;wrong.boot[0]='2';
 CHECK(epoch_owner_publish(&a,&wrong)<0);CHECK(epoch_record_read(runtime,owner,&wrong,&readback)<0);
 CHECK(!linkat(runtime,"epoch.owner",runtime,"alias",0));CHECK(epoch_owner_read(runtime,owner,&actual)<0);
 CHECK(!unlinkat(runtime,"alias",0));CHECK(!fchmodat(runtime,"epoch.owner",0666,0));CHECK(epoch_owner_read(runtime,owner,&actual)<0);
 CHECK(!fchmodat(runtime,"epoch.owner",0600,0));CHECK(!epoch_record_read(runtime,owner,&identity,&readback));
 CHECK(readback.revision==5&&readback.epoch==3&&readback.previous==2&&readback.phase==EPOCH_ARMING);
 CHECK(epoch_store_write(&a,"../other","bad\n",0)<0);CHECK(epoch_store_write(&a,"epoch.owner","bad\n",0)<0);
 CHECK(!renameat(runtime,"epoch.lock",runtime,"old.lock"));
 int fd=openat(runtime,"epoch.lock",O_WRONLY|O_CREAT|O_EXCL|O_CLOEXEC,0600);CHECK(fd>=0&&!close(fd));
 CHECK(!epoch_store_lease_valid(&a));CHECK(epoch_record_publish(&a,&identity,&state)<0);
 epoch_store_unlock(&a);CHECK(!unlinkat(runtime,"old.lock",0));CHECK(!epoch_store_lock(runtime,owner,&a));
 const char *bad[]={"LISA_EPOCH_STATE_V1 05 3 2 arming\n","LISA_EPOCH_STATE_V1 5 -3 2 arming\n",
  "LISA_EPOCH_STATE_V1 5 3 3 arming\n","LISA_EPOCH_STATE_V1 5 0 2 arming\n","LISA_EPOCH_STATE_V1 5 3 2 unknown\n",
  "LISA_EPOCH_STATE_V1 5 3 2 arming\n\n","LISA_EPOCH_STATE_V1 5 3 2 arming"};
 for(unsigned i=0;i<sizeof(bad)/sizeof(bad[0]);++i){
  fd=openat(runtime,"epoch.state",O_WRONLY|O_TRUNC|O_CLOEXEC);CHECK(fd>=0);
  CHECK(!store_write_all(fd,bad[i],strlen(bad[i]))&&!close(fd));
  CHECK(epoch_record_read(runtime,owner,&identity,&readback)<0);
  CHECK(epoch_record_publish(&a,&identity,&state)<0);
 }
 epoch_store_unlock(&a);
 CHECK(!unlinkat(runtime,"epoch.owner",0));CHECK(!epoch_store_lock(runtime,owner,&a));
 CHECK(epoch_owner_publish(&a,&identity)<0);
 epoch_store_unlock(&a);
 CHECK(!unlinkat(runtime,"epoch.state",0));CHECK(!unlinkat(runtime,"epoch.lock",0));
 CHECK(!close(runtime));CHECK(!rmdir(path));
 printf("{\"selftest\":\"epoch-mutation-store\",\"checks\":%u,\"ok\":true,\"firewall_changed\":false,\"audio_opened\":false}\n",checks);
 return 0;
}
#undef CHECK

#define CHECK(x) do{++checks;if(!(x)){fprintf(stderr,"recovery draft line %d\n",__LINE__);return 2;}}while(0)
static int put(int dir,const char *name,const char *text){
 int fd=openat(dir,name,O_WRONLY|O_CREAT|O_TRUNC|O_CLOEXEC,0600);if(fd<0)return -1;
 int failed=store_write_all(fd,text,strlen(text));if(close(fd))failed=1;return failed;
}
static int recovery_selftest(const char *base){
 umask(077);unsigned checks=0;char path[256];snprintf(path,sizeof(path),"%s/lisa-recovery.XXXXXX",base);CHECK(mkdtemp(path));
 int state=open(path,O_RDONLY|O_DIRECTORY|O_CLOEXEC);CHECK(state>=0);uid_t owner=geteuid();
 struct recovery_lease lease={.descriptor=-1},other={.descriptor=-1};struct recovery_plan plan;
 CHECK(recovery_lock(state,owner,&lease)==RECOVERY_CLEAR);
 CHECK(recovery_lock(state,owner,&other)==RECOVERY_BUSY);
 CHECK(recovery_attempt(state,state,owner,NULL,&plan)==RECOVERY_FAULT);
 struct close_ops incomplete_ops={0};CHECK(recovery_attempt(state,state,owner,&incomplete_ops,&plan)==RECOVERY_FAULT);
 CHECK(!put(state,"mode.state","LISA_MODE_V1 2 paused\n"));
 CHECK(!put(state,"closed.request","LISA_CLOSE_V1 1 paused complete\n"));
 CHECK(recovery_inspect(&lease,&plan)==RECOVERY_CLEAR);
 CHECK(!put(state,"opening.request","LISA_OPEN_V1 2 11111111-2222-4333-8444-555555555555 prepared\n"));
 CHECK(recovery_inspect(&lease,&plan)==RECOVERY_CANCEL_OPEN&&plan.base_revision==2&&plan.target==LISA_MODE_PAUSED);
 CHECK(!put(state,"mode.state","LISA_MODE_V1 3 paused\n"));
 CHECK(!put(state,"closed.request","LISA_CLOSE_V1 2 paused complete\n"));
 CHECK(recovery_inspect(&lease,&plan)==RECOVERY_CLEAR);
 CHECK(!put(state,"mode.state","LISA_MODE_V1 3 alice\n")&&!unlinkat(state,"closed.request",0));
 CHECK(recovery_inspect(&lease,&plan)==RECOVERY_CANCEL_OPEN&&plan.base_revision==3&&plan.target==LISA_MODE_PAUSED);
 CHECK(!put(state,"closed.request","LISA_CLOSE_V1 3 lisa requested\n"));
 CHECK(recovery_inspect(&lease,&plan)==RECOVERY_FINISH_CLOSE&&plan.base_revision==3&&plan.target==LISA_MODE_LISA);
 CHECK(!put(state,"opening.request","broken\n"));
 CHECK(recovery_inspect(&lease,&plan)==RECOVERY_FINISH_CLOSE);
 CHECK(!put(state,"mode.state","LISA_MODE_V1 4 lisa\n"));
 CHECK(!put(state,"closed.request","LISA_CLOSE_V1 3 lisa complete\n"));
 CHECK(recovery_inspect(&lease,&plan)==RECOVERY_INVALID);
 CHECK(!unlinkat(state,"opening.request",0));
 CHECK(recovery_inspect(&lease,&plan)==RECOVERY_CLEAR);
 CHECK(!put(state,"mode.state","LISA_MODE_V1 5 alice\n"));
 CHECK(recovery_inspect(&lease,&plan)==RECOVERY_INVALID);
 CHECK(!unlinkat(state,"closed.request",0));
 CHECK(recovery_inspect(&lease,&plan)==RECOVERY_CLEAR);
 CHECK(!put(state,"closed.request","corrupt\n"));
 CHECK(recovery_inspect(&lease,&plan)==RECOVERY_INVALID);
 recovery_unlock(&lease);
 CHECK(!unlinkat(state,"transition.lock",0)&&!unlinkat(state,"mode.state",0)&&!unlinkat(state,"closed.request",0));
 CHECK(!close(state)&&!rmdir(path));
 printf("{\"selftest\":\"pending-recovery\",\"checks\":%u,\"ok\":true,\"policy_changed\":false,\"audio_opened\":false}\n",checks);return 0;
}
#undef CHECK
#define CHECK(x) do{++checks;if(!(x)){fprintf(stderr,"emergency fixture line %d\n",__LINE__);return 2;}}while(0)
static int emergency_selftest(const char *base){
 umask(077);unsigned checks=0;char path[256];snprintf(path,sizeof(path),"%s/lisa-emergency.XXXXXX",base);CHECK(mkdtemp(path));
 int state=open(path,O_RDONLY|O_DIRECTORY|O_CLOEXEC);CHECK(state>=0);uid_t owner=geteuid();
 struct epoch_owner scope={.boot="11111111-2222-4333-8444-555555555555",.chain="LISACQ_EMERGENCY",.initial_revision=1};
 struct emergency_names names;CHECK(!emergency_names(&scope,&names)&&!strcmp(names.group,"LISACE_EMERGENCY")&&!strcmp(names.label,"LISACF_EMERGENCY"));
 CHECK(emergency_read(state,owner,0,&scope)==1&&!emergency_publish(state,owner,0,&scope));
 CHECK(!emergency_read(state,owner,0,&scope)&&!emergency_publish(state,owner,0,&scope));
 struct epoch_owner wrong=scope;wrong.initial_revision=2;CHECK(emergency_publish(state,owner,0,&wrong)<0);
 wrong=scope;wrong.boot[0]='2';CHECK(emergency_read(state,owner,0,&wrong)<0);
 CHECK(!put(state,"mode.state","LISA_MODE_V1 2 alice\n")&&mode_store_boot_choice(state,owner)==LISA_MODE_ALICE);
 CHECK(!emergency_publish(state,owner,1,&scope)&&mode_store_fault_pending(state,owner)&&mode_store_boot_choice(state,owner)==LISA_MODE_PAUSED);
 struct mode_record mode;CHECK(mode_store_request(state,owner,2,LISA_MODE_ALICE,&mode)==STORE_INVALID);
 CHECK(mode_store_request(state,owner,2,LISA_MODE_PAUSED,&mode)==STORE_OK&&mode.revision==3);
 CHECK(!emergency_publish(state,owner,1,&scope)&&!emergency_read(state,owner,1,&scope));
 CHECK(!put(state,"fault.request","corrupt\n")&&emergency_publish(state,owner,1,&scope)<0&&mode_store_fault_pending(state,owner));
 CHECK(!unlinkat(state,"fault.request",0)&&!symlinkat("missing",state,"fault.request")&&mode_store_fault_pending(state,owner)&&emergency_publish(state,owner,1,&scope)<0);
 CHECK(!unlinkat(state,"fault.request",0)&&!mkdirat(state,"fault.request",0700)&&mode_store_fault_pending(state,owner));
 CHECK(!unlinkat(state,"fault.request",AT_REMOVEDIR));
 CHECK(!linkat(state,"emergency.owner",state,"alias",0)&&emergency_read(state,owner,0,&scope)<0);
 CHECK(!unlinkat(state,"alias",0)&&!fchmodat(state,"emergency.owner",0644,0)&&emergency_read(state,owner,0,&scope)<0);
 CHECK(!fchmodat(state,"emergency.owner",0600,0)&&!emergency_read(state,owner,0,&scope));
 struct epoch_owner recovered={0};
 CHECK(!emergency_scope_read(state,owner,scope.boot,scope.chain,&recovered)&&recovered.initial_revision==1);
 CHECK(emergency_scope_read(state,owner,"21111111-2222-4333-8444-555555555555",scope.chain,&recovered)<0);
 CHECK(emergency_scope_read(state,owner,scope.boot,"LISACQ_OTHER",&recovered)<0);
 CHECK(!put(state,"epoch.owner","damaged primary\n")&&!put(state,"epoch.state","damaged state\n")&&
  !emergency_scope_read(state,owner,scope.boot,scope.chain,&recovered));
 const char *bad_scopes[]={
  "LISA_EMERGENCY_V2 11111111-2222-4333-8444-555555555555 LISACQ_EMERGENCY 1 0xff000000\n",
  "LISA_EMERGENCY_V1 11111111-2222-4333-8444-555555555555 LISACQ_EMERGENCY 01 0xff000000\n",
  "LISA_EMERGENCY_V1 11111111-2222-4333-8444-555555555555 LISACQ_EMERGENCY 0 0xff000000\n",
  "LISA_EMERGENCY_V1 11111111-2222-4333-8444-555555555555 LISACQ_EMERGENCY 18446744073709551615 0xff000000\n",
  "LISA_EMERGENCY_V1 11111111-2222-4333-8444-555555555555 LISACQ_EMERGENCY 1 0x00ffffff\n",
  "LISA_EMERGENCY_V1 11111111-2222-4333-8444-555555555555 LISACQ_EMERGENCY 1 0xff000000",
  "LISA_EMERGENCY_V1 11111111-2222-4333-8444-555555555555 LISACQ_EMERGENCY 1 0xff000000\n\n"};
 for(unsigned i=0;i<sizeof(bad_scopes)/sizeof(bad_scopes[0]);++i){
  recovered.initial_revision=99;
  CHECK(!put(state,"emergency.owner",bad_scopes[i])&&emergency_scope_read(state,owner,scope.boot,scope.chain,&recovered)<0&&recovered.initial_revision==99);
 }
 CHECK(!unlinkat(state,"emergency.owner",0)&&!symlinkat("epoch.owner",state,"emergency.owner")&&
  emergency_scope_read(state,owner,scope.boot,scope.chain,&recovered)<0);
 CHECK(!unlinkat(state,"emergency.owner",0)&&!emergency_publish(state,owner,0,&scope));
 CHECK(!unlinkat(state,"epoch.owner",0)&&!unlinkat(state,"epoch.state",0));
 char expected[1024];CHECK(emergency_expected(&names,0,expected,sizeof(expected))>0&&strstr(expected,"57342")&&strstr(expected,"57345"));
 CHECK(emergency_expected(&names,1,expected,sizeof(expected))>0&&strstr(expected,"! --mark 0x0/0xff000000 -j DROP"));
 CHECK(!unlinkat(state,"emergency.owner",0)&&!unlinkat(state,"mode.state",0)&&!unlinkat(state,"mode.lock",0)&&!close(state)&&!rmdir(path));
 printf("{\"selftest\":\"emergency-policy\",\"checks\":%u,\"ok\":true,\"policy_changed\":false,\"audio_opened\":false}\n",checks);return 0;
}
#undef CHECK

static int parser_selftest(void){
#define VERIFY(x) do{if(!(x)){fprintf(stderr,"epoch mutation parser line %d\n",__LINE__);return 4;}}while(0)
 struct label_policy_names names;VERIFY(!label_policy_names("LISACQ_MUTATION",&names));
 struct epoch_record record={3,2,1,EPOCH_ARMING};
 char old[2048],fresh[2048],body[2048],*ol[5],*nl[5];
 VERIFY(epoch_policy_expected(&names,1,1,1,old,sizeof(old))>0);
 VERIFY(epoch_policy_expected(&names,1,2,1,fresh,sizeof(fresh))>0);
 VERIFY(boot_policy_lines(old,ol,5)==5&&boot_policy_lines(fresh,nl,5)==5);
 for(unsigned mask=0;mask<16;++mask)for(unsigned next=0;next<16;++next){
  int size=snprintf(body,sizeof(body),"%s\n",nl[0]);
  for(unsigned i=0;i<4;++i)if(mask&(1u<<i))size+=snprintf(body+size,sizeof(body)-(size_t)size,"%s\n",(next&(1u<<i))?nl[i+1]:ol[i+1]);
  struct epoch_chain_shape shape={0};VERIFY(!epoch_mark_subset(body,&names,&record,&shape));
  for(unsigned i=0;i<4;++i)VERIFY(shape.present[i]==!!(mask&(1u<<i))&&shape.newer[i]==!!((mask&next)&(1u<<i)));
 }
 snprintf(body,sizeof(body),"%s\n%s\n%s\n",nl[0],nl[2],nl[1]);struct epoch_chain_shape shape={0};
 VERIFY(epoch_mark_subset(body,&names,&record,&shape)<0);
 snprintf(body,sizeof(body),"%s\n%s\n%s\n",nl[0],nl[1],nl[1]);memset(&shape,0,sizeof(shape));VERIFY(epoch_mark_subset(body,&names,&record,&shape)<0);
 snprintf(body,sizeof(body),"%s\n-A LISACM_MUTATION -j RETURN\n",nl[0]);VERIFY(epoch_mark_subset(body,&names,&record,&shape)<0);
 char closed[2048],opened[2048],*cl[2],*op[4];
 VERIFY(epoch_policy_expected(&names,2,2,1,closed,sizeof(closed))>0&&boot_policy_lines(closed,cl,2)==2);
 VERIFY(epoch_policy_expected(&names,2,2,0,opened,sizeof(opened))>0&&boot_policy_lines(opened,op,4)==4);
 for(unsigned head=0;head<2;++head)for(unsigned mask=0;mask<8;++mask){
  int size=snprintf(body,sizeof(body),"%s\n",cl[0]);
  if(head)size+=snprintf(body+size,sizeof(body)-(size_t)size,"%s\n",cl[1]);
  unsigned tails=0;
  for(unsigned i=0;i<3;++i)if(mask&(1u<<i)){size+=snprintf(body+size,sizeof(body)-(size_t)size,"%s\n",op[i+1]);++tails;}
  memset(&shape,0,sizeof(shape));int valid=head||mask==0||mask==7;
  VERIFY((epoch_deny_subset(body,&names,2,&shape)==0)==valid);
  if(valid)VERIFY(shape.head==(int)head&&shape.tails==tails);
 }
 snprintf(body,sizeof(body),"%s\n%s\n%s\n",cl[0],cl[1],cl[1]);memset(&shape,0,sizeof(shape));VERIFY(epoch_deny_subset(body,&names,2,&shape)<0);
 snprintf(body,sizeof(body),"%s\n%s\n%s\n",cl[0],op[2],op[1]);VERIFY(epoch_deny_subset(body,&names,2,&shape)<0);
 snprintf(body,sizeof(body),"%s\n%s\n-A LISACL_MUTATION -j RETURN\n",cl[0],cl[1]);VERIFY(epoch_deny_subset(body,&names,2,&shape)<0);
 puts("{\"selftest\":\"epoch-mutation-parser\",\"mark_subsets\":256,\"deny_subsets\":16,\"ok\":true,\"firewall_changed\":false}");
 return 0;
#undef VERIFY
}
static int lab_directory(const char *path){
 if(!path||path[0]!='/'||strlen(path)>=PATH_MAX)return -1;
 char copy[PATH_MAX];strcpy(copy,path);int parent=open("/",O_RDONLY|O_DIRECTORY|O_CLOEXEC);if(parent<0)return -1;
 char *save=NULL;
 for(char *part=strtok_r(copy,"/",&save);part;part=strtok_r(NULL,"/",&save)){
  if(!strcmp(part,".")||!strcmp(part,"..")){close(parent);return -1;}
  int next=openat(parent,part,O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC);close(parent);parent=next;
  struct stat info;
  if(parent<0||fstat(parent,&info)||info.st_uid||(info.st_mode&0022)){if(parent>=0)close(parent);return -1;}
 }
 if(!store_directory_valid(parent,0)){close(parent);return -1;}return parent;
}
static int lab_model_boot(char boot[37]){
 char compatible[512];int fd=open("/proc/device-tree/compatible",O_RDONLY|O_CLOEXEC);
 ssize_t size=fd<0?-1:read(fd,compatible,sizeof(compatible));if(fd>=0)close(fd);
 const char model[]="yandex,station-midi";int supported=0;
 for(ssize_t i=0;i+(ssize_t)sizeof(model)<=size;++i)if((!i||!compatible[i-1])&&!memcmp(compatible+i,model,sizeof(model)))supported=1;
 char text[38];fd=open("/proc/sys/kernel/random/boot_id",O_RDONLY|O_CLOEXEC);size=fd<0?-1:read(fd,text,sizeof(text));if(fd>=0)close(fd);
 if(!supported||size!=37||text[36]!='\n')return -1;
 text[36]=0;if(!gate_boot_valid(text))return -1;memcpy(boot,text,37);return 0;
}
/* The lab's pre-existing unlabelled stock processes are outside this scope.
 * Own fixture sockets deliberately survive under an untagged root holder.
 * This is NOT the production vendor/FD absence inventory. */
static int lab_scope_absent(void *pointer){
 (void)pointer;DIR *directory=opendir("/proc");if(!directory)return 0;struct dirent *entry;int absent=1;
 for(;;){
  errno=0;entry=readdir(directory);if(!entry){if(errno)absent=0;break;}
  char *end;long pid=strtol(entry->d_name,&end,10);if(*end||pid<2||pid>INT_MAX)continue;
  struct process_stamp stamp;if(process_stamp((pid_t)pid,&stamp)||stamp.state=='Z'||stamp.state=='X')continue;
  char path[64],line[512];snprintf(path,sizeof(path),"/proc/%ld/status",pid);FILE *file=fopen(path,"r");
  if(!file){if(process_live((pid_t)pid,stamp.ticks))absent=0;continue;}
  unsigned fields=0;
  while(fgets(line,sizeof(line),file)){
   if(strncmp(line,"Gid:",4)&&strncmp(line,"Groups:",7))continue;
   ++fields;char *at=strchr(line,':')+1,*parsed;
   while(*at){unsigned long gid=strtoul(at,&parsed,10);if(parsed==at)break;if(gid>=57342&&gid<=57345)absent=0;at=parsed;}
  }
  if(ferror(file)||fields!=2)absent=0;
  fclose(file);
 }
 closedir(directory);return absent;
}
struct lab_context{struct epoch_mutation mutation;struct emergency_cache emergency;int state,emergency_enabled,emergency_closed;unsigned emergency_fault;unsigned fault,hold;};
static int lab_flag(int runtime,const char *name,const char *expected){
 int fd=openat(runtime,name,O_RDONLY|O_NOFOLLOW|O_NONBLOCK|O_CLOEXEC);if(fd<0)return errno==ENOENT?0:-1;
 char text[96];ssize_t used=read(fd,text,sizeof(text));int valid=store_file_valid(fd,0);close(fd);
 return valid&&used==(ssize_t)strlen(expected)&&!memcmp(text,expected,(size_t)used)?1:-1;
}
static int lab_note(int runtime,const char *name,const char *text){
 int fd=openat(runtime,name,O_WRONLY|O_CREAT|O_EXCL|O_NOFOLLOW|O_CLOEXEC,0600);if(fd<0)return -1;
 int failed=store_write_all(fd,text,strlen(text))||fsync(fd);if(close(fd))failed=1;
 return failed||fsync(runtime)?-1:0;
}
static void lab_checkpoint(void *pointer,unsigned step){
 struct lab_context *context=pointer;
 if(context->fault&&context->fault==step){
  printf("{\"event\":\"mutation-fault\",\"step\":%u}\n",step);fflush(stdout);kill(getpid(),SIGKILL);_exit(99);
 }
 if(context->hold&&context->hold==step){
  if(lab_note(context->mutation.lease->runtime,"hold.ready","LISA_HOLD_READY_V1\n"))_exit(98);
  uint64_t deadline=guardian_milliseconds()+15000;
  for(;;){
   int flag=lab_flag(context->mutation.lease->runtime,"hold.release","LISA_HOLD_RELEASE_V1\n");
   if(flag==1)break;
   if(flag<0||guardian_milliseconds()>=deadline)_exit(98);
   struct timespec delay={0,50000000};nanosleep(&delay,NULL);
  }
 }
}
static int lab_deny(void *pointer){
 struct lab_context *context=pointer;struct epoch_lease *lease=context->mutation.lease;
 if(lease->descriptor<0&&epoch_store_lock(lease->runtime,lease->owner,lease))return -1;
 return epoch_mutation_deny(&context->mutation);
}
static int lab_stop(void *pointer){return lab_scope_absent(pointer)?0:-1;}
static int lab_prepare(void *pointer,uint64_t revision,const char *boot){
 struct lab_context *context=pointer;
 return strcmp(boot,context->mutation.owner.boot)?-1:epoch_mutation_prepare(&context->mutation,revision,lab_scope_absent,context);
}
static int lab_release(void *pointer){struct lab_context *context=pointer;return epoch_mutation_release(&context->mutation,context->state);}
static int lab_verify_open(void *pointer){
 struct lab_context *context=pointer;
 return epoch_mutation_load(&context->mutation)||context->mutation.record.phase!=EPOCH_OPEN||
  !epoch_mutation_verified(&context->mutation,0)?-1:0;
}
static int lab_verify_closed(void *pointer){
 struct lab_context *context=pointer;
 return epoch_mutation_load(&context->mutation)||context->mutation.record.phase!=EPOCH_CLOSED||
  !epoch_mutation_verified(&context->mutation,1)?-1:0;
}

/* Crash only this bounded laboratory coordinator at a fixed emergency phase.
 * Administrative probes use fresh unrelated sockets and never open audio. */
static void lab_emergency_checkpoint(void *pointer,unsigned step){
 struct lab_context *context=pointer;if(!context->emergency_fault||context->emergency_fault!=step)return;
 int runtime=context->mutation.lease->runtime;struct stat info;
 int absent=fstatat(runtime,"vendor.permit",&info,AT_SYMLINK_NOFOLLOW)<0&&errno==ENOENT;
 printf("{\"event\":\"emergency-checkpoint\",\"step\":%u,\"fault_present\":%s,\"permit_absent\":%s,\"policy_closed\":%s,\"control_ipv4\":%s,\"control_ipv6\":%s}\n",
  step,mode_store_fault_pending(context->state,0)?"true":"false",absent?"true":"false",
  emergency_armed(&context->emergency,1)?"true":"false",policy_control_socket(AF_INET)?"true":"false",policy_control_socket(AF_INET6)?"true":"false");
 fflush(stdout);kill(getpid(),SIGKILL);_exit(99);
}
static int lab_emergency_resume(struct lab_context *context,const char *boot,const char *chain){
 struct epoch_lease *epoch=context->mutation.lease;struct recovery_lease lease={.descriptor=-1};
 enum recovery_action lock=recovery_lock(context->state,0,&lease);int reconstructed=0,closed=0;
 if(lock==RECOVERY_CLEAR){
  reconstructed=emergency_cache_reconstruct(epoch->runtime,0,boot,chain,&context->emergency)==0;
  if(reconstructed)closed=emergency_activate_observed(&context->emergency,context->state,epoch->runtime,lab_emergency_checkpoint,context)==0;
 }
 int valid=reconstructed&&emergency_read(context->state,0,1,&context->emergency.scope)==0;
 int barrier=reconstructed&&emergency_armed(&context->emergency,1);struct stat info;
 int absent=fstatat(epoch->runtime,"vendor.permit",&info,AT_SYMLINK_NOFOLLOW)<0&&errno==ENOENT;
 printf("{\"event\":\"emergency-resume\",\"result\":\"%s\",\"cache_reconstructed\":%s,\"fault_valid\":%s,\"policy_closed\":%s,\"permit_absent\":%s,\"control_ipv4\":%s,\"control_ipv6\":%s,\"automatic_open\":false,\"audio_opened\":false,\"isolation_verified\":false}\n",
  closed?"ok":lock==RECOVERY_BUSY?"busy":"denied",reconstructed?"true":"false",valid?"true":"false",reconstructed?(barrier?"true":"false"):"null",absent?"true":"false",policy_control_socket(AF_INET)?"true":"false",policy_control_socket(AF_INET6)?"true":"false");
 recovery_unlock(&lease);return closed&&valid&&barrier&&absent?0:4;
}
/* Called only by the optional emergency fixture, never interpreted as a
 * production actor/FD census. 1 healthy, 0 valid contention, -1 fault. */
static int lab_health(struct lab_context *context){
 struct epoch_lease *epoch=context->mutation.lease;struct recovery_lease transition={.descriptor=-1};
 enum recovery_action action=recovery_lock(context->state,epoch->owner,&transition);
 if(action==RECOVERY_BUSY)return 0;
 if(action!=RECOVERY_CLEAR){context->emergency_closed=emergency_activate_observed(&context->emergency,context->state,epoch->runtime,lab_emergency_checkpoint,context)==0;return -1;}
 errno=0;
 if(epoch_store_lock(epoch->runtime,epoch->owner,epoch)){
  int busy=errno==EWOULDBLOCK;
  if(!busy)context->emergency_closed=emergency_activate_observed(&context->emergency,context->state,epoch->runtime,lab_emergency_checkpoint,context)==0;
  recovery_unlock(&transition);return busy?0:-1;
 }
 struct mode_record mode;struct stat info;
 int healthy=!epoch_mutation_load(&context->mutation)&&mode_store_read(context->state,epoch->owner,&mode)==STORE_OK;
 if(healthy&&mode.requested==LISA_MODE_ALICE)healthy=context->mutation.record.phase==EPOCH_OPEN&&
  mode.revision==context->mutation.record.revision&&epoch_mutation_verified(&context->mutation,0)&&
  gate_permit_valid(epoch->runtime,epoch->owner,mode.revision,context->mutation.owner.boot)&&!mode_store_fault_pending(context->state,epoch->owner);
 else if(healthy)healthy=context->mutation.record.phase==EPOCH_CLOSED&&epoch_mutation_verified(&context->mutation,1)&&
  fstatat(epoch->runtime,"vendor.permit",&info,AT_SYMLINK_NOFOLLOW)<0&&errno==ENOENT;
 if(!healthy)context->emergency_closed=emergency_activate_observed(&context->emergency,context->state,epoch->runtime,lab_emergency_checkpoint,context)==0;
 recovery_unlock(&transition);return healthy?1:-1;
}
static int lab_watch(struct lab_context *context,unsigned lifetime){
 struct epoch_lease *lease=context->mutation.lease;int runtime=lease->runtime;uid_t owner=lease->owner;
 if(epoch_store_lock(runtime,owner,lease)||epoch_mutation_load(&context->mutation))return -1;
 struct epoch_snapshot snapshot;if(epoch_mutation_snapshot(&context->mutation,&snapshot))return -1;
 if(context->emergency_enabled&&emergency_reserve(&context->mutation,&context->emergency))return -1;
 epoch_store_unlock(lease);lease->runtime=runtime;lease->owner=owner;
 struct process_stamp stamp;if(process_stamp(getpid(),&stamp))return -1;
 char ready[160];snprintf(ready,sizeof(ready),"LISA_RECOVERY_READY_V1 %s %ld %" PRIu64 "\n",context->mutation.owner.boot,(long)getpid(),stamp.ticks);
 if(lab_note(runtime,"watch.ready",ready))return -1;
 printf("{\"event\":\"recovery-watch\",\"state\":\"ready\",\"deadline_seconds\":%u}\n",lifetime);fflush(stdout);
 struct close_ops ops={lab_deny,lab_stop,lab_verify_closed,NULL,context};
 uint64_t deadline=guardian_milliseconds()+(uint64_t)lifetime*1000;unsigned busy=0,recovered=0,idle=0,faults=0;int stopped=0;
 while(guardian_milliseconds()<deadline){
  context->mutation.steps=0;
  int flag=lab_flag(runtime,"watch.stop","LISA_RECOVERY_STOP_V1\n");
  if(flag<0){++faults;break;}
  if(flag==1){
   struct mode_record mode;
   if(mode_store_read(context->state,owner,&mode)==STORE_OK&&mode.requested!=LISA_MODE_ALICE&&
      epoch_store_lock(runtime,owner,lease)==0&&lab_verify_closed(context)==0){stopped=1;break;}
   if(lease->descriptor>=0){epoch_store_unlock(lease);lease->runtime=runtime;lease->owner=owner;}
  }
  struct recovery_plan plan={0};
  enum recovery_result result=recovery_attempt(context->state,runtime,owner,&ops,&plan);
  if(result==RECOVERY_RETRY){
   ++busy;if(busy==1){puts("{\"event\":\"recovery-watch\",\"state\":\"busy\"}");fflush(stdout);}
  }else if(result==RECOVERY_DONE){
   ++recovered;struct mode_record mode;
   if(mode_store_read(context->state,owner,&mode)!=STORE_OK||lab_verify_closed(context)||
      gate_permit_valid(runtime,owner,mode.revision,context->mutation.owner.boot)){++faults;break;}
   printf("{\"event\":\"recovery-watch\",\"state\":\"recovered\",\"reason\":\"%s\",\"base_revision\":%" PRIu64 ",\"mode_revision\":%" PRIu64
    ",\"target\":\"%s\",\"policy_closed\":true,\"permit_revoked\":true}\n",
    plan.action==RECOVERY_CANCEL_OPEN?"cancel_open":"finish_close",plan.base_revision,mode.revision,mode_name(mode.requested));fflush(stdout);
  }else if(result==RECOVERY_FAULT){++faults;break;}else {
   ++idle;
   if(context->emergency_enabled){
    int health=lab_health(context);
    if(health<0){
     int closed=context->emergency_closed;
     printf("{\"event\":\"emergency-fault\",\"latched\":%s,\"policy_closed\":%s,\"primary_preserved\":true,\"automatic_open\":false}\n",
      mode_store_fault_pending(context->state,owner)?"true":"false",closed?"true":"false");fflush(stdout);++faults;break;
    }
   }
  }
  if(lease->descriptor>=0){epoch_store_unlock(lease);lease->runtime=runtime;lease->owner=owner;}
  struct timespec delay={0,100000000};nanosleep(&delay,NULL);
 }
 if(lease->descriptor>=0){epoch_store_unlock(lease);lease->runtime=runtime;lease->owner=owner;}
 context->mutation.steps=0;
 printf("{\"event\":\"recovery-watch-summary\",\"busy_polls\":%u,\"recovered\":%u,\"idle_polls\":%u,\"faults\":%u,"
  "\"stopped\":%s,\"automatic_open\":false,\"audio_opened\":false}\n",busy,recovered,idle,faults,stopped?"true":"false");fflush(stdout);
 return stopped&&!faults?0:-1;
}

static uint64_t lab_number(const char *text){
 if(!text||*text<'0'||*text>'9')return 0;
 errno=0;char *end;unsigned long long value=strtoull(text,&end,10);return errno||*end?0:value;
}
int main(int argc,char **argv){
 if(argc==2&&(!strcmp(argv[1],"--selftest")||!strcmp(argv[1],"--station-selftest"))){
  int station=!strcmp(argv[1],"--station-selftest");if(station&&(getuid()||geteuid()||getgid()||getegid()))return 2;
  alarm(30);const char *base=station?"/data/opt/lisa-controller-lab":"/tmp";
  return parser_selftest()||selftest(base)||recovery_selftest(base)||emergency_selftest(base);
 }
 if(getuid()||geteuid()||getgid()||getegid()||argc<3||argc>5)return 2;
 pid_t parent=getppid();if(prctl(PR_SET_PDEATHSIG,SIGKILL)||getppid()!=parent)return 2;
 int reserve=!strcmp(argv[1],"--lab-reserve"),status=!strcmp(argv[1],"--lab-status"),deny=!strcmp(argv[1],"--lab-deny");
 int crashing=!strcmp(argv[1],"--lab-watch-emergency-crash"),resuming=!strcmp(argv[1],"--lab-emergency-resume");
 int holding=!strcmp(argv[1],"--lab-open-hold"),emergency=!strcmp(argv[1],"--lab-watch-emergency")||crashing;
 int watching=!strcmp(argv[1],"--lab-watch")||emergency;
 int opening=!strcmp(argv[1],"--lab-open")||holding,closing=!strcmp(argv[1],"--lab-close")||!strcmp(argv[1],"--lab-close-lisa");
 if(!reserve&&!status&&!deny&&!opening&&!closing&&!watching&&!resuming)return 2;
 if((watching&&argc!=(crashing?5:4))||(holding&&argc!=5)||(resuming&&argc>4))return 2;
 if((opening||closing)?argc<4:((!crashing&&argc>4)||(status&&argc!=3)))return 2;
 uint64_t base=opening||closing?lab_number(argv[3]):0;
 uint64_t fault=argc==(opening||closing?5:4)?lab_number(argv[argc-1]):0;if(fault>1000)return 2;
 unsigned lifetime=watching?(unsigned)lab_number(argv[3]):0;if(watching&&(!lifetime||lifetime>120))return 2;
 unsigned emergency_fault=crashing?(unsigned)lab_number(argv[4]):resuming?(unsigned)fault:0;
 if(emergency_fault>9||(crashing&&!emergency_fault)||(resuming&&argc==4&&!fault&&strcmp(argv[3],"0")))return 2;
 const char prefix[]="/bkupgrade/data/opt/lisa-controller-lab/epoch-mutation.";
 if(strncmp(argv[2],prefix,sizeof(prefix)-1))return 2;
 const char *suffix=argv[2]+sizeof(prefix)-1;size_t length=strlen(suffix);if(length<6||length>16)return 2;
 for(size_t i=0;i<length;++i)if(!((suffix[i]>='a'&&suffix[i]<='z')||(suffix[i]>='A'&&suffix[i]<='Z')||(suffix[i]>='0'&&suffix[i]<='9')))return 2;
 struct stat info;struct statvfs rootfs;
 if(!lstat("/bkupgrade/data/opt/lisa-station/state",&info)||errno!=ENOENT||!lstat("/run/lisa-station",&info)||errno!=ENOENT||
  statvfs("/",&rootfs)||!(rootfs.f_flag&ST_RDONLY))return 3;
 char boot[37],mutex[PATH_MAX];if(lab_model_boot(boot)||!realpath("/data/opt/lisa-lab/trial.lock",mutex))return 3;
 int directory=lab_directory(mutex);if(directory<0)return 3;close(directory);
 directory=lab_directory(argv[2]);if(directory<0)return 3;
 char path[PATH_MAX];snprintf(path,sizeof(path),"%s/run",argv[2]);int runtime=lab_directory(path);
 snprintf(path,sizeof(path),"%s/state",argv[2]);int state=lab_directory(path);close(directory);
 if(runtime<0||state<0){if(runtime>=0)close(runtime);if(state>=0)close(state);return 3;}
 alarm(watching?lifetime+5:45);struct epoch_lease lease={.descriptor=-1,.runtime=runtime,.owner=0};int result=-1;
 struct lab_context context={.state=state,.emergency_enabled=emergency,.emergency_fault=emergency_fault,.fault=holding||watching?0:(unsigned)fault,.hold=holding?(unsigned)fault:0};
 context.mutation.lease=&lease;context.mutation.checkpoint=lab_checkpoint;context.mutation.context=&context;
 struct mode_record mode={0};char chain[32];
 if(policy_chain_read(runtime,0,chain,sizeof(chain)))goto done;
 if(resuming){int resumed=lab_emergency_resume(&context,boot,chain);close(runtime);close(state);return resumed;}
 if((reserve||status||deny)&&epoch_store_lock(runtime,0,&lease))goto done;
 int found=epoch_owner_read(runtime,0,&context.mutation.owner);
 if(found<0)goto done;
 if(found==0){if(strcmp(boot,context.mutation.owner.boot)||strcmp(chain,context.mutation.owner.chain))goto done;}
 else{
  if(!reserve||mode_store_read(state,0,&mode)!=STORE_OK||mode.requested==LISA_MODE_ALICE||mode_store_open_pending(state,0))goto done;
  memcpy(context.mutation.owner.boot,boot,37);strcpy(context.mutation.owner.chain,chain);context.mutation.owner.initial_revision=mode.revision;
 }
 if(watching)result=lab_watch(&context,lifetime);
 else if(reserve)result=epoch_mutation_reserve(&context.mutation,lab_scope_absent,&context);
 else if(status)result=epoch_mutation_load(&context.mutation);
 else if(deny)result=epoch_mutation_deny(&context.mutation)||close_revoke(runtime)?-1:0;
 else if(opening){
  struct open_ops ops={lab_deny,lab_stop,lab_prepare,lab_release,lab_verify_open,NULL,&context};
  enum open_result opened=OPEN_BUSY;
  for(unsigned attempt=0;attempt<100&&opened==OPEN_BUSY;++attempt){
   opened=open_execute(state,runtime,0,base,boot,&ops);
   if(opened==OPEN_BUSY){struct timespec delay={0,50000000};nanosleep(&delay,NULL);}
  }
  result=opened==OPEN_OK?0:-1;
 }else if(closing){
  struct close_ops ops={lab_deny,lab_stop,lab_verify_closed,NULL,&context};
  result=close_execute(state,runtime,0,base,!strcmp(argv[1],"--lab-close-lisa")?LISA_MODE_LISA:LISA_MODE_PAUSED,&ops)==CLOSE_OK?0:-1;
 }
done: ;
 if(lease.descriptor<0){lease.runtime=runtime;lease.owner=0;(void)epoch_store_lock(runtime,0,&lease);}
 int observed=!epoch_mutation_load(&context.mutation);
 const char *closed="null",*opened="null";
 if(observed){
  closed=epoch_mutation_verified(&context.mutation,1)?"true":"false";
  opened=epoch_mutation_verified(&context.mutation,0)?"true":"false";
 }
 const char *requested=mode_store_read(state,0,&mode)==STORE_OK?mode_name(mode.requested):"unknown";
 int control4=policy_control_socket(AF_INET),control6=policy_control_socket(AF_INET6);
 printf("{\"event\":\"epoch-mutation\",\"operation\":\"%s\",\"result\":\"%s\",\"phase\":\"%s\",\"revision\":%" PRIu64
  ",\"epoch\":%u,\"mode_revision\":%" PRIu64 ",\"requested_mode\":\"%s\",\"boot_choice\":\"%s\",\"opening_pending\":%s,"
  "\"permit_valid\":%s,\"policy_closed\":%s,\"policy_open\":%s,\"mutation_steps\":%u,\"control_ipv4\":%s,\"control_ipv6\":%s,"
  "\"vendor_started\":false,\"stock_fallback\":false,\"audio_opened\":false,\"isolation_verified\":false}\n",
  argv[1]+6,result?"denied":"ok",observed?epoch_phase_name(context.mutation.record.phase):"unknown",
  observed?context.mutation.record.revision:0,observed?context.mutation.record.epoch:0,mode.revision,requested,mode_name(mode_store_boot_choice(state,0)),
  mode_store_open_pending(state,0)?"true":"false",gate_permit_valid(runtime,0,mode.revision,boot)?"true":"false",closed,opened,context.mutation.steps,
  control4?"true":"false",control6?"true":"false");
 epoch_store_unlock(&lease);close(runtime);close(state);return result?4:0;
}
