#define _GNU_SOURCE
#include <sys/statvfs.h>
#include <stdlib.h>
#include "epoch_mutation.h"
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
struct lab_context{struct epoch_mutation mutation;int state;unsigned fault;};
static void lab_checkpoint(void *pointer,unsigned step){
 struct lab_context *context=pointer;
 if(context->fault&&context->fault==step){
  printf("{\"event\":\"mutation-fault\",\"step\":%u}\n",step);fflush(stdout);kill(getpid(),SIGKILL);_exit(99);
 }
}
static int lab_deny(void *pointer){return epoch_mutation_deny(&((struct lab_context*)pointer)->mutation);}
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
static uint64_t lab_number(const char *text){
 if(!text||*text<'0'||*text>'9')return 0;
 errno=0;char *end;unsigned long long value=strtoull(text,&end,10);return errno||*end?0:value;
}
int main(int argc,char **argv){
 if(argc==2&&(!strcmp(argv[1],"--selftest")||!strcmp(argv[1],"--station-selftest"))){
  int station=!strcmp(argv[1],"--station-selftest");if(station&&(getuid()||geteuid()||getgid()||getegid()))return 2;
  alarm(30);return parser_selftest()||selftest(station?"/data/opt/lisa-controller-lab":"/tmp");
 }
 if(getuid()||geteuid()||getgid()||getegid()||argc<3||argc>5)return 2;
 pid_t parent=getppid();if(prctl(PR_SET_PDEATHSIG,SIGKILL)||getppid()!=parent)return 2;
 int reserve=!strcmp(argv[1],"--lab-reserve"),status=!strcmp(argv[1],"--lab-status"),deny=!strcmp(argv[1],"--lab-deny");
 int opening=!strcmp(argv[1],"--lab-open"),closing=!strcmp(argv[1],"--lab-close");
 if(!reserve&&!status&&!deny&&!opening&&!closing)return 2;
 if((opening||closing)?argc<4:(argc>4||(status&&argc!=3)))return 2;
 uint64_t base=opening||closing?lab_number(argv[3]):0;
 uint64_t fault=argc==(opening||closing?5:4)?lab_number(argv[argc-1]):0;if(fault>1000)return 2;
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
 alarm(45);struct epoch_lease lease={.descriptor=-1};int result=-1;
 struct lab_context context={.state=state,.fault=(unsigned)fault};
 context.mutation.lease=&lease;context.mutation.checkpoint=lab_checkpoint;context.mutation.context=&context;
 struct mode_record mode={0};char chain[32];
 if(epoch_store_lock(runtime,0,&lease)||policy_chain_read(runtime,0,chain,sizeof(chain)))goto done;
 int found=epoch_owner_read(runtime,0,&context.mutation.owner);
 if(found<0)goto done;
 if(found==0){if(strcmp(boot,context.mutation.owner.boot)||strcmp(chain,context.mutation.owner.chain))goto done;}
 else{
  if(!reserve||mode_store_read(state,0,&mode)!=STORE_OK||mode.requested==LISA_MODE_ALICE||mode_store_open_pending(state,0))goto done;
  memcpy(context.mutation.owner.boot,boot,37);strcpy(context.mutation.owner.chain,chain);context.mutation.owner.initial_revision=mode.revision;
 }
 if(reserve)result=epoch_mutation_reserve(&context.mutation,lab_scope_absent,&context);
 else if(status)result=epoch_mutation_load(&context.mutation);
 else if(deny)result=epoch_mutation_deny(&context.mutation)||close_revoke(runtime)?-1:0;
 else if(opening){
  struct open_ops ops={lab_deny,lab_stop,lab_prepare,lab_release,lab_verify_open,NULL,&context};
  result=open_execute(state,runtime,0,base,boot,&ops)==OPEN_OK?0:-1;
 }else if(closing){
  struct close_ops ops={lab_deny,lab_stop,lab_verify_closed,NULL,&context};
  result=close_execute(state,runtime,0,base,LISA_MODE_PAUSED,&ops)==CLOSE_OK?0:-1;
 }
done: ;
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
