/* Fixed boot entry points only. Not a production coordinator: station-boot
 * must implement verified mode/service operations before this is installed. */
#define _GNU_SOURCE
#include "boot_runner.h"
#include "boot_dispatch.h"

int main(int argc,char **argv) {
    if(argc!=2) return 2;
    if(!strcmp(argv[1],"--print-rcs")) {
        return fwrite(lisa_boot_dispatch,1,sizeof(lisa_boot_dispatch)-1,stdout)==sizeof(lisa_boot_dispatch)-1?0:3;
    }
    if(geteuid()) return 2;
    const char *operations[]={"--bootstrap","--hardware-start","--diagnostics-stage","--time-start","--dns-start","--vendor-start"};
    const unsigned deadlines[]={4000,4000,4000,8000,8000,45000};
    unsigned operation=0;
    while(operation<sizeof(operations)/sizeof(operations[0])&&strcmp(argv[1],operations[operation])) ++operation;
    if(operation==sizeof(operations)/sizeof(operations[0])) return 2;
    char compatible[512]; int fd=open("/proc/device-tree/compatible",O_RDONLY|O_CLOEXEC);
    ssize_t size=fd<0?-1:read(fd,compatible,sizeof(compatible)); if(fd>=0) close(fd);
    const char model[]="yandex,station-midi"; int supported=0;
    for(ssize_t i=0;i+(ssize_t)sizeof(model)<=size;++i)
        if((!i||!compatible[i-1])&&!memcmp(compatible+i,model,sizeof(model))) supported=1;
    if(!supported) return 3;
    char *const arguments[]={"station-boot",(char*)operations[operation],NULL};
    enum boot_run_result result=boot_run("/bkupgrade/data/opt/lisa-station/bin/station-boot",arguments,deadlines[operation]);
    const char *names[]={"ok","invalid","failed","timeout"};
    printf("{\"event\":\"station-init\",\"operation\":\"%s\",\"result\":\"%s\",\"stock_fallback\":false,\"isolation_verified\":false}\n",operations[operation],names[result]);
    return result==BOOT_RUN_OK?0:4;
}
