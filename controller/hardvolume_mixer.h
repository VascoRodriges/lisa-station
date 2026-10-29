/* Fixed synthetic Master control only. ALSA user controls outlive their daemon;
 * after verified daemon absence, remove a compatible unlocked stale control so
 * the fixed daemon can recreate it. Never remove a hardware/vendor control. */
#ifndef LISA_HARDVOLUME_MIXER_H
#define LISA_HARDVOLUME_MIXER_H
#include <sound/asound.h>
#include <sys/ioctl.h>
static inline void hardvolume_mixer_id(struct snd_ctl_elem_id *id) {
    memset(id,0,sizeof(*id));id->iface=SNDRV_CTL_ELEM_IFACE_MIXER;
    strcpy((char*)id->name,"Master Playback Volume");
}
static inline int hardvolume_mixer_compatible(const struct snd_ctl_elem_info *info) {
    return info->id.iface==SNDRV_CTL_ELEM_IFACE_MIXER&&!info->id.device&&!info->id.subdevice&&!info->id.index&&
        !memcmp(info->id.name,"Master Playback Volume",sizeof("Master Playback Volume"))&&info->type==SNDRV_CTL_ELEM_TYPE_INTEGER&&
        info->count==1&&(info->access&SNDRV_CTL_ELEM_ACCESS_USER)&&
        (info->access&SNDRV_CTL_ELEM_ACCESS_READWRITE)==SNDRV_CTL_ELEM_ACCESS_READWRITE&&
        !(info->access&SNDRV_CTL_ELEM_ACCESS_LOCK)&&info->owner==-1&&
        info->value.integer.min==0&&info->value.integer.max==255&&info->value.integer.step==0;
}
static inline int hardvolume_mixer_open(void) {
    int fd=open("/dev/snd/controlC0",O_RDWR|O_NOFOLLOW|O_CLOEXEC);struct stat info;
    if(fd<0)return -1;
    if(fstat(fd,&info)||!S_ISCHR(info.st_mode)||info.st_uid){close(fd);return -1;}
    return fd;
}
/* 1 absent, 0 compatible snapshot (and optional removal), -1 refused. Caller
 * must hold its coordinator lock and independently prove no mixer daemon. */
static inline int hardvolume_mixer_snapshot(int remove,long *level) {
    int fd=hardvolume_mixer_open();if(fd<0)return -1;
    struct snd_ctl_elem_info info={0};hardvolume_mixer_id(&info.id);
    if(ioctl(fd,SNDRV_CTL_IOCTL_ELEM_INFO,&info)) {int absent=errno==ENOENT;close(fd);return absent?1:-1;}
    struct snd_ctl_elem_value value={0};value.id=info.id;
    int failed=!hardvolume_mixer_compatible(&info)||ioctl(fd,SNDRV_CTL_IOCTL_ELEM_READ,&value)||
        value.value.integer.value[0]<0||value.value.integer.value[0]>255;
    if(!failed){*level=value.value.integer.value[0];if(remove&&ioctl(fd,SNDRV_CTL_IOCTL_ELEM_REMOVE,&info.id))failed=1;}
    if(close(fd))failed=1;
    return failed?-1:0;
}
static inline int hardvolume_mixer_restore(long level) {
    if(level<0||level>255)return -1;
    int fd=hardvolume_mixer_open();if(fd<0)return -1;
    struct snd_ctl_elem_info info={0};hardvolume_mixer_id(&info.id);
    struct snd_ctl_elem_value value={0};hardvolume_mixer_id(&value.id);value.value.integer.value[0]=level;
    int failed=ioctl(fd,SNDRV_CTL_IOCTL_ELEM_INFO,&info)||!hardvolume_mixer_compatible(&info)||
        ioctl(fd,SNDRV_CTL_IOCTL_ELEM_WRITE,&value);
    if(close(fd))failed=1;
    return failed?-1:0;
}
#endif
