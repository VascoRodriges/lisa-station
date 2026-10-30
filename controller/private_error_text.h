/* Pure little-endian D-Bus body decoder: exactly ONE STRING, no headers.
 * Caller supplies valid, distinct C objects and an already bounded signature.
 * Decoded text is private diagnostic data, NEVER an authorization decision. */
#ifndef LISA_PRIVATE_ERROR_TEXT_H
#define LISA_PRIVATE_ERROR_TEXT_H
#include "private_match_snapshot.h"
#define PRIVATE_ERROR_TEXT_MAX 1024u
struct private_error_text {size_t size;char text[PRIVATE_ERROR_TEXT_MAX+1];};
static inline int private_error_decode(const char *signature,const void *body,size_t size,struct private_error_text *output){
    if(!output)return -1;
    memset(output,0,sizeof(*output));
    if(!signature||strcmp(signature,"s")||!body||size<5||size>PRIVATE_ERROR_TEXT_MAX+5u)return -1;
    const unsigned char *bytes=body;size_t length=match_u32(bytes);
    if(length!=size-5||bytes[4+length]||!match_utf8(bytes+4,length))return -1;
    memcpy(output->text,bytes+4,length+1);output->size=length;return 0;
}
#endif
