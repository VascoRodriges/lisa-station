/* Fixed-schema lab ObjectManager exchange. No bus, SDK memory or hardware.
 * This codec does not authenticate a peer or authorize production service use.
 * Callers provide valid, distinct C objects and validate channel ownership. */
#ifndef LISA_PRIVATE_EMPTY_OBJECTS_H
#define LISA_PRIVATE_EMPTY_OBJECTS_H
#include "private_match_snapshot.h"
#define EMPTY_OBJECTS_FRAME 8192u
#define EMPTY_OBJECTS_REPLY 256u
struct private_empty_request {uint32_t serial;char sender[MATCH_NAME];};
static inline size_t empty_objects_name_size(const char *name){
    if(!name)return 0;
    size_t size=0;while(size<MATCH_NAME&&name[size])++size;
    return size<MATCH_NAME&&match_name(name)?size:0;
}
static inline int private_empty_request_decode(const void *message,size_t size,const char *sender,struct private_empty_request *output){
    if(!output)return -1;
    memset(output,0,sizeof(*output));
    size_t name_size=empty_objects_name_size(sender);
    if(!message||!name_size||size<16||size>EMPTY_OBJECTS_FRAME)return -1;
    const unsigned char *p=message;
    /* NO_AUTO_START may be present; NO_REPLY_EXPECTED and unknown flags may not. */
    if(p[0]!='l'||p[1]!=1||(p[2]&~2u)||p[3]!=1||match_u32(p+4)||!match_u32(p+8))return -1;
    size_t fields=match_u32(p+12);if(fields>4096||fields>size-16)return -1;
    size_t end=16+fields;struct private_match_cursor c={p,size,16};unsigned seen=0;
    while(c.position<end){
        if(match_align(&c,8,end)||end-c.position<4)return -1;
        unsigned code=p[c.position],type=p[c.position+2];
        if(!code||code>9||(seen&(1u<<code))||p[c.position+1]!=1||p[c.position+3])return -1;
        seen|=1u<<code;c.position+=4;
        if(code==9){if(type!='u'||end-c.position<4||match_u32(p+c.position))return -1;c.position+=4;continue;}
        if(code==8){if(type!='g'||end-c.position<2||p[c.position]||p[c.position+1])return -1;c.position+=2;continue;}
        const char *expected=NULL;
        switch(code){
            case 1:if(type!='o')return -1;expected="/";break;
            case 2:expected="org.freedesktop.DBus.ObjectManager";break;
            case 3:expected="GetManagedObjects";break;
            case 6:expected="org.bluez";break;
            case 7:expected=sender;break;
            default:return -1;
        }
        if(code!=1&&type!='s')return -1;
        char text[128];if(match_string(&c,end,text,sizeof(text))||strcmp(text,expected))return -1;
    }
    const unsigned required=(1u<<1)|(1u<<2)|(1u<<3)|(1u<<6)|(1u<<7);
    if((seen&required)!=required||c.position!=end||match_align(&c,8,size)||c.position!=size)return -1;
    output->serial=match_u32(p+8);memcpy(output->sender,sender,name_size+1);return 0;
}
static inline void empty_objects_put(unsigned char *p,uint32_t value){for(unsigned i=0;i<4;++i)p[i]=(unsigned char)(value>>(8*i));}
static inline size_t empty_objects_field(unsigned char *p,size_t position,unsigned code,char type,const char *text){
    position=(position+7)&~(size_t)7;p[position++]=(unsigned char)code;p[position++]=1;p[position++]=(unsigned char)type;p[position++]=0;
    size_t size=strlen(text);
    if(type=='g')p[position++]=(unsigned char)size;
    else{empty_objects_put(p+position,(uint32_t)size);position+=4;}
    memcpy(p+position,text,size+1);return position+size+1;
}
/* On failure written is zero and the caller's output bytes are unchanged. */
static inline int private_empty_reply(const struct private_empty_request *request,uint32_t serial,void *output,size_t capacity,size_t *written){
    if(!written)return -1;
    *written=0;
    if(!request||!serial||!request->serial||!empty_objects_name_size(request->sender)||!output)return -1;
    unsigned char bytes[EMPTY_OBJECTS_REPLY]={'l',2,0,1};
    empty_objects_put(bytes+4,8);empty_objects_put(bytes+8,serial);
    size_t position=16;bytes[position++]=5;bytes[position++]=1;bytes[position++]='u';bytes[position++]=0;
    empty_objects_put(bytes+position,request->serial);position+=4;
    position=empty_objects_field(bytes,position,6,'s',request->sender);
    position=empty_objects_field(bytes,position,8,'g',"a{oa{sa{sv}}}");
    empty_objects_put(bytes+12,(uint32_t)(position-16));position=(position+7)&~(size_t)7;
    /* Empty ARRAY length, followed by required 8-byte element alignment. */
    position+=8;
    if(position>sizeof(bytes)||position>capacity)return -1;
    memcpy(output,bytes,position);*written=position;return 0;
}
#endif
