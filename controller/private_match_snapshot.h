/* Bounded little-endian a{sas} from the admitted PRIVATE daemon's Stats API.
 * No SDK memory, authentication/audio buffers, general variants or recursion.
 * These limits match the current lab's four clients and one rule per client.
 * The caller supplies valid, distinct input and output buffers. */
#ifndef LISA_PRIVATE_MATCH_SNAPSHOT_H
#define LISA_PRIVATE_MATCH_SNAPSHOT_H
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#define MATCH_CLIENTS 4u
#define MATCH_NAME 64u
#define MATCH_RULE 1024u
#define MATCH_BODY 4096u
struct private_match_entry {char name[MATCH_NAME],rule[MATCH_RULE+1];unsigned rules;};
struct private_match_snapshot {unsigned clients,rules;struct private_match_entry entry[MATCH_CLIENTS];};
struct private_match_cursor {const unsigned char *bytes;size_t size,position;};
static inline uint32_t match_u32(const unsigned char *p){return (uint32_t)p[0]|(uint32_t)p[1]<<8|(uint32_t)p[2]<<16|(uint32_t)p[3]<<24;}
static inline int match_align(struct private_match_cursor *c,size_t alignment,size_t end){
    if(c->position>end||end>c->size||c->position>SIZE_MAX-(alignment-1))return -1;
    size_t next=(c->position+alignment-1)&~(alignment-1);if(next>end)return -1;
    for(;c->position<next;++c->position)if(c->bytes[c->position])return -1;
    return 0;
}
static inline int match_utf8(const unsigned char *text,size_t size){
    for(size_t i=0;i<size;){uint32_t value=text[i++];unsigned more;uint32_t minimum;
        if(value<128){if(!value)return 0;continue;}
        if(value>=0xc2&&value<=0xdf){value&=31;more=1;minimum=0x80;}
        else if(value>=0xe0&&value<=0xef){value&=15;more=2;minimum=0x800;}
        else if(value>=0xf0&&value<=0xf4){value&=7;more=3;minimum=0x10000;}
        else return 0;
        if(more>size-i)return 0;
        while(more--){unsigned byte=text[i++];if((byte&0xc0)!=0x80)return 0;value=(value<<6)|(byte&63);}
        if(value<minimum||value>0x10ffff||(value>=0xd800&&value<=0xdfff))return 0;
    }return 1;
}
static inline int match_string(struct private_match_cursor *c,size_t end,char *target,size_t capacity){
    if(match_align(c,4,end)||end-c->position<4)return -1;
    size_t size=match_u32(c->bytes+c->position);c->position+=4;
    if(size>=capacity||size>=end-c->position||c->bytes[c->position+size]||!match_utf8(c->bytes+c->position,size))return -1;
    memcpy(target,c->bytes+c->position,size+1);c->position+=size+1;return 0;
}
static inline int match_name(const char *name){
    if(name[0]!=':')return 0;
    unsigned dots=0,part=0;
    for(size_t i=1;name[i];++i){unsigned char value=(unsigned char)name[i];
        if(value=='.'){if(!part)return 0;++dots;part=0;}
        else{if(!((value>='a'&&value<='z')||(value>='A'&&value<='Z')||(value>='0'&&value<='9')||value=='_'||value=='-'))return 0;++part;}
    }return dots>0&&part>0;
}
static inline int private_match_decode(const void *body,size_t size,struct private_match_snapshot *output){
    if(!output)return -1;
    memset(output,0,sizeof(*output));
    if(!body||size<8||size>MATCH_BODY)return -1;
    struct private_match_cursor c={body,size,4};size_t bytes=match_u32(c.bytes);
    if(match_align(&c,8,size)||bytes!=size-c.position)return -1;
    struct private_match_snapshot next={0};
    while(c.position<size){
        if(next.clients==MATCH_CLIENTS||match_align(&c,8,size))return -1;
        struct private_match_entry *entry=&next.entry[next.clients];
        if(match_string(&c,size,entry->name,sizeof(entry->name))||!match_name(entry->name))return -1;
        for(unsigned i=0;i<next.clients;++i)if(!strcmp(next.entry[i].name,entry->name))return -1;
        if(match_align(&c,4,size)||size-c.position<4)return -1;
        bytes=match_u32(c.bytes+c.position);c.position+=4;
        if(bytes>size-c.position)return -1;
        size_t end=c.position+bytes;
        if(c.position<end){if(match_string(&c,end,entry->rule,sizeof(entry->rule)))return -1;entry->rules=1;++next.rules;}
        if(c.position!=end)return -1;
        ++next.clients;
    }
    *output=next;return 0;
}
static inline const struct private_match_entry *private_match_find(const struct private_match_snapshot *s,const char *name){
    if(!s||!name)return NULL;
    for(unsigned i=0;i<s->clients&&i<MATCH_CLIENTS;++i)if(!strcmp(s->entry[i].name,name))return &s->entry[i];
    return NULL;
}
#endif
