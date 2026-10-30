/* Synthetic wire fixtures only. No bus, SDK, identities, audio or permissions. */
#include <stdio.h>
#include "private_error_text.h"
static unsigned checks,failures;
static void check(int good){++checks;if(!good){++failures;fprintf(stderr,"Error text check %u\n",checks);}}
static size_t body(unsigned char *bytes,const unsigned char *text,size_t size){
    for(unsigned i=0;i<4;++i)bytes[i]=(unsigned char)(size>>(8*i));
    memcpy(bytes+4,text,size);bytes[4+size]=0;return size+5;
}
static void reject(const char *signature,const void *bytes,size_t size){
    struct private_error_text result,zero={0};memset(&result,0xa5,sizeof(result));
    check(private_error_decode(signature,bytes,size,&result)<0&&!memcmp(&result,&zero,sizeof(result)));
}
static void accept(const unsigned char *text,size_t size){
    unsigned char bytes[PRIVATE_ERROR_TEXT_MAX+5];struct private_error_text result;
    size_t length=body(bytes,text,size);memset(&result,0xa5,sizeof(result));
    check(!private_error_decode("s",bytes,length,&result)&&result.size==size&&!memcmp(result.text,text,size)&&!result.text[size]);
    for(size_t i=size+1;i<sizeof(result.text);++i)if(result.text[i]){check(0);return;}
}
int main(int argc,char **argv){
    if(argc!=2||strcmp(argv[1],"--selftest"))return 2;
    accept((const unsigned char *)"",0);
    const unsigned char example[]="Permission denied for org.example.LisaDenied";
    accept(example,sizeof(example)-1);
    const unsigned char valid[][4]={{0x7f},{0xc2,0x80},{0xdf,0xbf},{0xe0,0xa0,0x80},{0xed,0x9f,0xbf},
        {0xee,0x80,0x80},{0xef,0xbf,0xbf},{0xf0,0x90,0x80,0x80},{0xf4,0x8f,0xbf,0xbf}};
    const size_t lengths[]={1,2,2,3,3,3,3,4,4};
    for(unsigned i=0;i<sizeof(lengths)/sizeof(lengths[0]);++i)accept(valid[i],lengths[i]);
    unsigned char bytes[PRIVATE_ERROR_TEXT_MAX+6],text[PRIVATE_ERROR_TEXT_MAX+1];memset(text,'x',sizeof(text));
    accept(text,1);accept(text,PRIVATE_ERROR_TEXT_MAX-1);accept(text,PRIVATE_ERROR_TEXT_MAX);
    size_t length=body(bytes,text,PRIVATE_ERROR_TEXT_MAX);
    /* Every incomplete prefix, including a missing final terminator. */
    for(size_t i=0;i<length;++i)reject("s",bytes,i);
    bytes[length]=0;reject("s",bytes,length+1);
    reject("s",bytes,SIZE_MAX);reject("s",NULL,length);reject(NULL,bytes,length);
    const char *const signatures[]={"","ss","as","v","o","g","(s)","S"};
    for(unsigned i=0;i<sizeof(signatures)/sizeof(signatures[0]);++i)reject(signatures[i],bytes,length);
    check(private_error_decode("s",bytes,length,NULL)<0);
    /* Wrong declared sizes, including opposite endian and integer wrap values. */
    const uint32_t declared[]={0,1,1023,1025,0x00040000,0x7fffffff,0xffffffff};
    for(unsigned j=0;j<sizeof(declared)/sizeof(declared[0]);++j){
        body(bytes,text,PRIVATE_ERROR_TEXT_MAX);
        for(unsigned i=0;i<4;++i)bytes[i]=(unsigned char)(declared[j]>>(8*i));
        reject("s",bytes,length);
    }
    body(bytes,text,PRIVATE_ERROR_TEXT_MAX);bytes[length-1]=1;reject("s",bytes,length);
    /* Every payload position rejects embedded NUL; each mutation has a valid baseline. */
    for(size_t i=0;i<PRIVATE_ERROR_TEXT_MAX;++i){body(bytes,text,PRIVATE_ERROR_TEXT_MAX);bytes[4+i]=0;reject("s",bytes,length);}
    const unsigned char invalid[][4]={{0},{0x80},{0xbf},{0xc0,0x80},{0xc1,0xbf},{0xc2},{0xc2,0x7f},
        {0xe0,0x9f,0xbf},{0xed,0xa0,0x80},{0xe1,0x80},{0xe1,0x80,0x7f},{0xf0,0x8f,0xbf,0xbf},
        {0xf4,0x90,0x80,0x80},{0xf5,0x80,0x80,0x80},{0xf1,0x80,0x80},{0xf1,0x80,0x80,0x7f},{0xff}};
    const size_t bad_lengths[]={1,1,1,2,2,1,2,3,3,2,3,4,4,4,3,4,1};
    for(unsigned i=0;i<sizeof(bad_lengths)/sizeof(bad_lengths[0]);++i){size_t n=body(bytes,invalid[i],bad_lengths[i]);reject("s",bytes,n);}
    /* One more byte than the fixed maximum, even when otherwise well-formed. */
    length=body(bytes,text,sizeof(text));reject("s",bytes,length);
    printf("{\"kind\":\"private-error-text\",\"checks\":%u,\"failures\":%u}\n",checks,failures);
    return failures?1:0;
}
