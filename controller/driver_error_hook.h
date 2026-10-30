/* Explicit PRIVATE daemon diagnostic. No SDK memory or bus policy changes.
 * Call the real libdbus operation unchanged; audit only a denied RequestName
 * error constructed by this preadmitted daemon. FD 1 is a bounded owned pipe. */
#ifndef LISA_DRIVER_ERROR_HOOK_H
#define LISA_DRIVER_ERROR_HOOK_H
#include <dlfcn.h>
#include <errno.h>
#include <unistd.h>
#include "driver_denial_record.h"
struct DBusMessage;
static struct DBusMessage *(*driver_real_error)(struct DBusMessage *,const char *,const char *);
static const char *(*driver_sender)(struct DBusMessage *),*(*driver_destination)(struct DBusMessage *);
static const char *(*driver_interface)(struct DBusMessage *),*(*driver_member)(struct DBusMessage *);
static unsigned (*driver_serial)(struct DBusMessage *);
static int (*driver_type)(struct DBusMessage *);
static unsigned driver_audit_enabled,driver_audit_count;
static int driver_error_prepare(unsigned enabled){
    if(enabled>1)return -1;
    driver_real_error=dlsym(RTLD_NEXT,"dbus_message_new_error");driver_sender=dlsym(RTLD_NEXT,"dbus_message_get_sender");
    driver_destination=dlsym(RTLD_NEXT,"dbus_message_get_destination");driver_interface=dlsym(RTLD_NEXT,"dbus_message_get_interface");
    driver_member=dlsym(RTLD_NEXT,"dbus_message_get_member");driver_serial=dlsym(RTLD_NEXT,"dbus_message_get_serial");driver_type=dlsym(RTLD_NEXT,"dbus_message_get_type");
    if(!driver_real_error||!driver_sender||!driver_destination||!driver_interface||!driver_member||!driver_serial||!driver_type)return -1;
    driver_audit_enabled=enabled;return 0;
}
struct DBusMessage *dbus_message_new_error(struct DBusMessage *request,const char *name,const char *text){
    if(!driver_real_error)_exit(126);
    struct DBusMessage *reply=driver_real_error(request,name,text);int saved=errno;
    if(driver_audit_enabled&&reply&&request&&name&&!strcmp(name,"org.freedesktop.DBus.Error.AccessDenied")&&driver_type(request)==1){
        const char *destination=driver_destination(request),*interface=driver_interface(request),*member=driver_member(request);
        if(destination&&!strcmp(destination,"org.freedesktop.DBus")&&interface&&!strcmp(interface,"org.freedesktop.DBus")&&member&&!strcmp(member,"RequestName")){
            unsigned char record[DRIVER_DENIAL_WIRE];
            if(driver_audit_count==DRIVER_DENIAL_LIMIT||driver_denial_encode(driver_sender(request),driver_serial(request),text,record,sizeof(record)))_exit(126);
            ssize_t written;do{written=write(1,record,sizeof(record));}while(written<0&&errno==EINTR);
            memset(record,0,sizeof(record));if(written!=(ssize_t)sizeof(record))_exit(126);++driver_audit_count;
        }
    }
    errno=saved;return reply;
}
#endif
