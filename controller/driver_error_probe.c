/* Synthetic real-libdbus call/return and private record controls; no live bus. */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <sys/wait.h>
#include "driver_error_hook.h"
extern struct DBusMessage *dbus_message_new_method_call(const char *,const char *,const char *,const char *);
extern int dbus_message_set_sender(struct DBusMessage *,const char *);
extern void dbus_message_set_serial(struct DBusMessage *,unsigned);
extern void dbus_message_unref(struct DBusMessage *);
extern const char *dbus_message_get_error_name(struct DBusMessage *);
extern unsigned dbus_message_get_reply_serial(struct DBusMessage *);
extern int dbus_message_get_args(struct DBusMessage *,void *,int,...);
static unsigned checks,failures;
static void check(int good){++checks;if(!good){++failures;fprintf(stderr,"Driver error check %u\n",checks);}}
static void operation(const char *destination,const char *interface,const char *member,const char *error){
    struct DBusMessage *request=dbus_message_new_method_call(destination,"/org/freedesktop/DBus",interface,member);
    check(request&&dbus_message_set_sender(request,":1.2"));if(!request)exit(1);dbus_message_set_serial(request,111);
    const char *text="Private denial for org.example.LisaDenied";
    struct DBusMessage *reply=dbus_message_new_error(request,error,text);const char *actual=NULL;
    check(reply&&driver_type(reply)==3&&!strcmp(dbus_message_get_error_name(reply),error)&&dbus_message_get_reply_serial(reply)==111&&
        dbus_message_get_args(reply,NULL,'s',&actual,0)&&actual&&!strcmp(actual,text));
    if(reply)dbus_message_unref(reply);
    dbus_message_unref(request);
}
static void invalid_record(const unsigned char *bytes,size_t size){
    struct driver_denial_record result,zero={0};memset(&result,0xa5,sizeof(result));
    check(driver_denial_decode(bytes,size,&result)<0&&!memcmp(&result,&zero,sizeof(result)));
}
int main(int argc,char **argv){
    if(argc!=2||strcmp(argv[1],"--selftest"))return 2;
    int original=dup(1);FILE *file=tmpfile();if(original<0||!file||dup2(fileno(file),1)<0)return 2;
    check(!driver_error_prepare(1));if(!driver_real_error)return 2;
    const char *driver="org.freedesktop.DBus",*denied="org.freedesktop.DBus.Error.AccessDenied";
    operation(driver,driver,"RequestName",denied);check(driver_audit_count==1);
    operation(driver,driver,"Hello",denied);operation("org.example.LisaOther",driver,"RequestName",denied);
    operation(driver,"org.example.LisaOther","RequestName",denied);
    operation(driver,driver,"RequestName","org.freedesktop.DBus.Error.LimitsExceeded");check(driver_audit_count==1);
    driver_audit_enabled=0;operation(driver,driver,"RequestName",denied);check(driver_audit_count==1);driver_audit_enabled=1;
    for(unsigned i=0;i<3;++i)operation(driver,driver,"RequestName",denied);
    check(driver_audit_count==4);
    pid_t child=fork();check(child>=0);
    if(!child){operation(driver,driver,"RequestName",denied);_exit(9);}
    if(child>0){int status=0;check(waitpid(child,&status,0)==child&&WIFEXITED(status)&&WEXITSTATUS(status)==126);}
    check(lseek(fileno(file),0,SEEK_END)==(off_t)(DRIVER_DENIAL_LIMIT*DRIVER_DENIAL_WIRE)&&lseek(fileno(file),0,SEEK_SET)==0);
    unsigned char bytes[DRIVER_DENIAL_WIRE],valid[DRIVER_DENIAL_WIRE];
    for(unsigned i=0;i<4;++i){struct driver_denial_record record;
        check(read(fileno(file),bytes,sizeof(bytes))==(ssize_t)sizeof(bytes)&&!driver_denial_decode(bytes,sizeof(bytes),&record)&&record.serial==111&&
            !strcmp(record.sender,":1.2")&&!strcmp(record.body.text,"Private denial for org.example.LisaDenied"));
    }
    memcpy(valid,bytes,sizeof(valid));
    for(size_t i=0;i<sizeof(bytes);++i)invalid_record(valid,i);
    invalid_record(NULL,sizeof(bytes));invalid_record(valid,SIZE_MAX);check(driver_denial_decode(valid,sizeof(valid),NULL)<0);
    const unsigned offsets[]={0,7,12,16,22,80,DRIVER_DENIAL_WIRE-1};
    for(unsigned i=0;i<sizeof(offsets)/sizeof(offsets[0]);++i){memcpy(bytes,valid,sizeof(bytes));bytes[offsets[i]]=0xff;invalid_record(bytes,sizeof(bytes));}
    memcpy(bytes,valid,sizeof(bytes));memset(bytes+8,0,4);invalid_record(bytes,sizeof(bytes));
    const char *const bad_names[]={NULL,"","org.example.LisaOther",":bad",":1..2",":.1"};
    for(unsigned i=0;i<sizeof(bad_names)/sizeof(bad_names[0]);++i)check(driver_denial_encode(bad_names[i],1,"denied",bytes,sizeof(bytes))<0);
    check(driver_denial_encode(":1.2",0,"denied",bytes,sizeof(bytes))<0);
    check(driver_denial_encode(":1.2",1,"",bytes,sizeof(bytes))<0);
    check(driver_denial_encode(":1.2",1,NULL,bytes,sizeof(bytes))<0);
    check(driver_denial_encode(":1.2",1,"denied",NULL,sizeof(bytes))<0);
    check(driver_denial_encode(":1.2",1,"denied",bytes,sizeof(bytes)-1)<0);
    char maximum[PRIVATE_ERROR_TEXT_MAX+2];memset(maximum,'x',sizeof(maximum));maximum[sizeof(maximum)-1]=0;
    check(driver_denial_encode(":1.2",1,maximum,bytes,sizeof(bytes))<0);maximum[PRIVATE_ERROR_TEXT_MAX]=0;
    struct driver_denial_record record;
    check(!driver_denial_encode(":1.2",0xffffffffu,maximum,bytes,sizeof(bytes))&&!driver_denial_decode(bytes,sizeof(bytes),&record)&&
        record.serial==0xffffffffu&&record.body.size==PRIVATE_ERROR_TEXT_MAX);
    check(dup2(original,1)>=0&&!close(original)&&!fclose(file));
    printf("{\"kind\":\"driver-error-hook\",\"checks\":%u,\"failures\":%u}\n",checks,failures);return failures?1:0;
}
