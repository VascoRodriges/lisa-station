/* ONE synthetic offline Adapter1 for a lab dependency audit. No hardware,
 * real identity, paired devices, operations or host-bus forwarding. */
#ifndef LISA_PRIVATE_ADAPTER_OBJECTS_H
#define LISA_PRIVATE_ADAPTER_OBJECTS_H
#include "private_empty_objects.h"
#define ADAPTER_BODY 1024u
#define ADAPTER_REPLY (ADAPTER_BODY+EMPTY_OBJECTS_REPLY)
struct adapter_cursor {unsigned char bytes[ADAPTER_BODY];size_t position;int bad;};
static inline void adapter_pad(struct adapter_cursor *c,size_t alignment){
    size_t next=(c->position+alignment-1)&~(alignment-1);
    if(next>sizeof(c->bytes)){c->bad=1;return;}c->position=next;
}
static inline void adapter_u32(struct adapter_cursor *c,uint32_t value){
    adapter_pad(c,4);if(c->bad||sizeof(c->bytes)-c->position<4){c->bad=1;return;}
    empty_objects_put(c->bytes+c->position,value);c->position+=4;
}
static inline void adapter_string(struct adapter_cursor *c,const char *text){
    size_t size=strlen(text);adapter_u32(c,(uint32_t)size);
    if(c->bad||size>=sizeof(c->bytes)-c->position){c->bad=1;return;}
    memcpy(c->bytes+c->position,text,size+1);c->position+=size+1;
}
static inline void adapter_signature(struct adapter_cursor *c,const char *text){
    size_t size=strlen(text);
    if(c->bad||size>255||sizeof(c->bytes)-c->position<size+2){c->bad=1;return;}
    c->bytes[c->position++]=(unsigned char)size;memcpy(c->bytes+c->position,text,size+1);c->position+=size+1;
}
static inline size_t adapter_array(struct adapter_cursor *c,size_t alignment){
    adapter_u32(c,0);size_t offset=c->position;adapter_pad(c,alignment);return offset;
}
static inline void adapter_end(struct adapter_cursor *c,size_t offset,size_t alignment){
    size_t start=(offset+alignment-1)&~(alignment-1);
    if(c->bad||offset<4||start>c->position){c->bad=1;return;}
    empty_objects_put(c->bytes+offset-4,(uint32_t)(c->position-start));
}
/* Closed constant schema only; there are no caller-provided object/property values. */
static inline int private_adapter_body(void *output,size_t capacity,size_t *written){
    if(!written)return -1;
    *written=0;if(!output)return -1;
    struct adapter_cursor c={0};size_t objects=adapter_array(&c,8);
    adapter_string(&c,"/org/bluez/hci0");size_t interfaces=adapter_array(&c,8);
    adapter_string(&c,"org.bluez.Adapter1");size_t properties=adapter_array(&c,8);
    const struct {const char *name,*type,*text;} values[]={
        {"Address","s","02:00:00:00:00:01"},{"AddressType","s","public"},
        {"Name","s","Lisa synthetic"},{"Alias","s","Lisa synthetic"},
        {"Class","u",NULL},{"Powered","b",NULL},{"Discoverable","b",NULL},
        {"DiscoverableTimeout","u",NULL},{"Pairable","b",NULL},{"PairableTimeout","u",NULL},
        {"Discovering","b",NULL},{"UUIDs","as",NULL},{"Modalias","s","usb:v0000p0000d0000"},{"Roles","as",NULL},
    };
    for(unsigned i=0;i<sizeof(values)/sizeof(values[0]);++i){
        adapter_pad(&c,8);adapter_string(&c,values[i].name);adapter_signature(&c,values[i].type);
        if(values[i].text)adapter_string(&c,values[i].text);
        else if(!strcmp(values[i].type,"as")){size_t array=adapter_array(&c,4);adapter_end(&c,array,4);}
        else adapter_u32(&c,0);
    }
    adapter_end(&c,properties,8);adapter_end(&c,interfaces,8);adapter_end(&c,objects,8);
    if(c.bad||c.position>capacity)return -1;
    memcpy(output,c.bytes,c.position);*written=c.position;return 0;
}
static inline int private_adapter_reply(const struct private_empty_request *request,uint32_t serial,void *output,size_t capacity,size_t *written){
    if(!written)return -1;
    *written=0;if(!output)return -1;
    unsigned char bytes[ADAPTER_REPLY];size_t size=0,body=0;
    if(private_empty_reply(request,serial,bytes,EMPTY_OBJECTS_REPLY,&size)||size<8)return -1;
    size-=8;
    if(private_adapter_body(bytes+size,sizeof(bytes)-size,&body)||size+body>capacity)return -1;
    empty_objects_put(bytes+4,(uint32_t)body);memcpy(output,bytes,size+body);*written=size+body;return 0;
}
#endif
