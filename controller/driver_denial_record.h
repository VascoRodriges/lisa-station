/* Fixed PRIVATE lab record, not a general bus parser or authorization token.
 * Valid distinct objects; caller proves the pipe and private daemon identity. */
#ifndef LISA_DRIVER_DENIAL_RECORD_H
#define LISA_DRIVER_DENIAL_RECORD_H
#include "private_error_text.h"
#define DRIVER_DENIAL_WIRE (16u+MATCH_NAME+PRIVATE_ERROR_TEXT_MAX+5u)
#define DRIVER_DENIAL_LIMIT 4u
struct driver_denial_record {unsigned serial;char sender[MATCH_NAME];struct private_error_text body;};
static inline int driver_denial_decode(const void *input,size_t size,struct driver_denial_record *output){
    if(!output)return -1;
    memset(output,0,sizeof(*output));
    if(!input||size!=DRIVER_DENIAL_WIRE)return -1;
    const unsigned char *bytes=input;struct driver_denial_record next={0};
    if(memcmp(bytes,"LISADEN1",8)||!(next.serial=match_u32(bytes+8)))return -1;
    size_t length=match_u32(bytes+12);if(length<5||length>PRIVATE_ERROR_TEXT_MAX+5u)return -1;
    const unsigned char *end=memchr(bytes+16,0,MATCH_NAME);if(!end)return -1;
    size_t name_size=(size_t)(end-(bytes+16));memcpy(next.sender,bytes+16,name_size);
    if(!match_name(next.sender))return -1;
    for(size_t i=16+name_size;i<16+MATCH_NAME;++i)if(bytes[i])return -1;
    if(private_error_decode("s",bytes+16+MATCH_NAME,length,&next.body)||!next.body.size)return -1;
    for(size_t i=16+MATCH_NAME+length;i<size;++i)if(bytes[i])return -1;
    *output=next;return 0;
}
static inline void driver_denial_u32(unsigned char *bytes,uint32_t value){
    for(unsigned i=0;i<4;++i)bytes[i]=(unsigned char)(value>>(8*i));
}
static inline int driver_denial_encode(const char *sender,unsigned serial,const char *text,void *output,size_t capacity){
    if(!output||capacity<DRIVER_DENIAL_WIRE)return -1;
    memset(output,0,DRIVER_DENIAL_WIRE);
    if(!sender||!text||!serial)return -1;
    size_t name_size=strnlen(sender,MATCH_NAME),length=strnlen(text,PRIVATE_ERROR_TEXT_MAX+1u);
    if(!name_size||name_size==MATCH_NAME||!length||length>PRIVATE_ERROR_TEXT_MAX||!match_name(sender)||!match_utf8((const unsigned char *)text,length))return -1;
    unsigned char *bytes=output;memcpy(bytes,"LISADEN1",8);driver_denial_u32(bytes+8,serial);driver_denial_u32(bytes+12,(uint32_t)length+5);
    memcpy(bytes+16,sender,name_size);driver_denial_u32(bytes+16+MATCH_NAME,(uint32_t)length);memcpy(bytes+20+MATCH_NAME,text,length);return 0;
}
#endif
