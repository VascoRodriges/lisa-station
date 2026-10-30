/* GET-only logical Master capability. No names, indices, ioctls or pointers
 * are supplied by a client. Valid distinct C objects. This codec/state helper
 * grants no descriptor or hardware access; admission and freshness are external. */
#ifndef LISA_MASTER_READ_PROTOCOL_H
#define LISA_MASTER_READ_PROTOCOL_H
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#define MASTER_EPOCH_BYTES 16u
#define MASTER_REQUEST_BYTES 40u
#define MASTER_REPLY_BYTES 48u
#define MASTER_READ_LIMIT 32u
struct master_read_value {unsigned error,value;};
struct master_read_session {unsigned char epoch[MASTER_EPOCH_BYTES];unsigned completed,pending,closed;};
static inline uint32_t master_u32(const unsigned char *bytes){return (uint32_t)bytes[0]|(uint32_t)bytes[1]<<8|(uint32_t)bytes[2]<<16|(uint32_t)bytes[3]<<24;}
static inline void master_put32(unsigned char *bytes,uint32_t value){for(unsigned i=0;i<4;++i)bytes[i]=(unsigned char)(value>>(8*i));}
static inline int master_epoch_valid(const unsigned char *epoch){
    if(!epoch)return 0;
    unsigned any=0;for(unsigned i=0;i<MASTER_EPOCH_BYTES;++i)any|=epoch[i];return any!=0;
}
static inline int master_sequence_valid(unsigned sequence){return sequence>=1&&sequence<=MASTER_READ_LIMIT;}
static inline int master_request_encode(const unsigned char *epoch,unsigned sequence,void *output,size_t size){
    if(!output||size!=MASTER_REQUEST_BYTES)return -1;
    memset(output,0,size);if(!master_epoch_valid(epoch)||!master_sequence_valid(sequence))return -1;
    unsigned char *bytes=output;memcpy(bytes,"LMGET001",8);memcpy(bytes+8,epoch,MASTER_EPOCH_BYTES);
    master_put32(bytes+24,sequence);master_put32(bytes+28,1);return 0;
}
static inline int master_request_decode(const void *input,size_t size,const unsigned char *epoch,unsigned sequence){
    if(!input||size!=MASTER_REQUEST_BYTES||!master_epoch_valid(epoch)||!master_sequence_valid(sequence))return -1;
    const unsigned char *bytes=input;
    if(memcmp(bytes,"LMGET001",8)||memcmp(bytes+8,epoch,MASTER_EPOCH_BYTES)||master_u32(bytes+24)!=sequence||master_u32(bytes+28)!=1)return -1;
    for(size_t i=32;i<size;++i)if(bytes[i])return -1;
    return 0;
}
static inline int master_value_valid(unsigned error,unsigned value){return error?error<=4095&&!value:value<=255;}
static inline int master_reply_encode(const unsigned char *epoch,unsigned sequence,unsigned error,unsigned value,void *output,size_t size){
    if(!output||size!=MASTER_REPLY_BYTES)return -1;
    memset(output,0,size);if(!master_epoch_valid(epoch)||!master_sequence_valid(sequence)||!master_value_valid(error,value))return -1;
    unsigned char *bytes=output;memcpy(bytes,"LMVAL001",8);memcpy(bytes+8,epoch,MASTER_EPOCH_BYTES);
    master_put32(bytes+24,sequence);master_put32(bytes+28,error);master_put32(bytes+32,value);return 0;
}
static inline int master_reply_decode(const void *input,size_t size,const unsigned char *epoch,unsigned sequence,struct master_read_value *output){
    if(!output)return -1;
    memset(output,0,sizeof(*output));if(!input||size!=MASTER_REPLY_BYTES||!master_epoch_valid(epoch)||!master_sequence_valid(sequence))return -1;
    const unsigned char *bytes=input;unsigned error=master_u32(bytes+28),value=master_u32(bytes+32);
    if(memcmp(bytes,"LMVAL001",8)||memcmp(bytes+8,epoch,MASTER_EPOCH_BYTES)||master_u32(bytes+24)!=sequence||!master_value_valid(error,value))return -1;
    for(size_t i=36;i<size;++i)if(bytes[i])return -1;
    output->error=error;output->value=value;return 0;
}
static inline int master_session_valid(const struct master_read_session *session){
    return session&&master_epoch_valid(session->epoch)&&session->completed<=MASTER_READ_LIMIT&&session->pending<=1&&session->closed<=1&&
        !(session->closed&&session->pending)&&!(session->pending&&session->completed==MASTER_READ_LIMIT)&&
        (session->completed<MASTER_READ_LIMIT||session->closed);
}
static inline int master_session_init(struct master_read_session *session,const unsigned char *epoch){
    if(!session)return -1;
    memset(session,0,sizeof(*session));if(!master_epoch_valid(epoch))return -1;
    memcpy(session->epoch,epoch,MASTER_EPOCH_BYTES);return 0;
}
/* Failure preserves prior state for inspection. Caller MUST fault/close epoch
 * after any rejected packet; preserved state is not permission to retry. */
static inline int master_session_accept(struct master_read_session *session,const void *input,size_t size){
    if(!master_session_valid(session)||session->closed||session->pending||
        master_request_decode(input,size,session->epoch,session->completed+1))return -1;
    session->pending=1;return 0;
}
/* Complete only after a real result is sent; never accept a pipelined request. */
static inline int master_session_complete(struct master_read_session *session){
    if(!master_session_valid(session)||session->closed||!session->pending)return -1;
    session->pending=0;if(++session->completed==MASTER_READ_LIMIT)session->closed=1;return 0;
}
static inline int master_session_fault(struct master_read_session *session){
    if(!master_session_valid(session))return -1;
    session->pending=0;session->closed=1;return 0;
}
#endif
