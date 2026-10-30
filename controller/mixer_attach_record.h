/* PRIVATE API metadata only, never a mixer implementation or authorization.
 * Fixed little-endian record; valid distinct objects and bounded C strings. */
#ifndef LISA_MIXER_ATTACH_RECORD_H
#define LISA_MIXER_ATTACH_RECORD_H
#include "private_match_snapshot.h"
#define MIXER_LABEL_MAX 128u
#define MIXER_RECORD_WIRE (16u+MIXER_LABEL_MAX+1u)
#define MIXER_RECORD_LIMIT 4u
#define MIXER_MISSING_CONTROL "org.example.LisaMissingCtl"
struct mixer_attach_record {int32_t result;char label[MIXER_LABEL_MAX+1];};
static inline int mixer_record_decode(const void *input,size_t size,struct mixer_attach_record *output){
    if(!output)return -1;
    memset(output,0,sizeof(*output));if(!input||size!=MIXER_RECORD_WIRE)return -1;
    const unsigned char *bytes=input;size_t length=match_u32(bytes+8);
    if(memcmp(bytes,"LISAMIX1",8)||!length||length>MIXER_LABEL_MAX||!match_utf8(bytes+16,length))return -1;
    for(size_t i=16+length;i<size;++i)if(bytes[i])return -1;
    uint32_t value=match_u32(bytes+12);output->result=(int32_t)(value<=INT32_MAX?(int64_t)value:(int64_t)value-4294967296LL);
    memcpy(output->label,bytes+16,length);return 0;
}
static inline int mixer_record_encode(const char *label,int32_t result,void *output,size_t capacity){
    if(!output||capacity<MIXER_RECORD_WIRE)return -1;
    memset(output,0,MIXER_RECORD_WIRE);if(!label)return -1;
    size_t length=strnlen(label,MIXER_LABEL_MAX+1u);
    if(!length||length>MIXER_LABEL_MAX||!match_utf8((const unsigned char *)label,length))return -1;
    unsigned char *bytes=output;memcpy(bytes,"LISAMIX1",8);uint32_t values[]={(uint32_t)length,(uint32_t)result};
    for(unsigned i=0;i<2;++i)for(unsigned j=0;j<4;++j)bytes[8+4*i+j]=(unsigned char)(values[i]>>(8*j));
    memcpy(bytes+16,label,length);return 0;
}
struct mixer_attach_audit {unsigned used,count,failed;unsigned char pending[MIXER_RECORD_WIRE];struct mixer_attach_record record[MIXER_RECORD_LIMIT];};
/* Noise is discarded. Candidate records can span chunks; failures are sticky.
 * Retained earlier records are diagnostics only and unusable after failure. */
static inline int mixer_audit_feed(struct mixer_attach_audit *audit,const void *input,size_t size){
    if(!audit||audit->failed)return -1;
    if((!input&&size)||audit->used>=MIXER_RECORD_WIRE||audit->count>MIXER_RECORD_LIMIT){audit->failed=1;return -1;}
    const unsigned char *bytes=input;const unsigned char magic[]="LISAMIX1";
    for(size_t i=0;i<size;++i){unsigned char value=bytes[i];
        if(audit->used<8){
            if(value==magic[audit->used])audit->pending[audit->used++]=value;
            else if(audit->used==7){audit->failed=1;return -1;}
            else{audit->used=value==magic[0];if(audit->used)audit->pending[0]=value;}
        }else audit->pending[audit->used++]=value;
        if(audit->used==MIXER_RECORD_WIRE){
            if(audit->count==MIXER_RECORD_LIMIT||mixer_record_decode(audit->pending,sizeof(audit->pending),&audit->record[audit->count])){audit->failed=1;return -1;}
            ++audit->count;audit->used=0;memset(audit->pending,0,sizeof(audit->pending));
        }
    }return 0;
}
static inline int mixer_audit_finish(const struct mixer_attach_audit *audit){return audit&&!audit->failed&&!audit->used&&audit->count&&audit->count<=MIXER_RECORD_LIMIT?0:-1;}
#endif
