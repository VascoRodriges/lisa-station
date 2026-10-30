/* Synthetic body/capacity fixtures; no bus, SDK, device or external input. */
#include <stdio.h>
#include "private_adapter_objects.h"
static unsigned checks,failures;
static void check(int good){++checks;if(!good){++failures;fprintf(stderr,"adapter objects check %u\n",checks);}}
static int filled(const unsigned char *bytes,size_t size){for(size_t i=0;i<size;++i)if(bytes[i]!=0xa5)return 0;return 1;}
int main(int argc,char **argv){
    if(argc!=2||(strcmp(argv[1],"--selftest")&&strcmp(argv[1],"--wire")))return 2;
    struct private_empty_request request={.serial=7,.sender=":1.2"};
    unsigned char body[ADAPTER_BODY],reply[ADAPTER_REPLY],copy[ADAPTER_REPLY];size_t body_size=0,size=0;
    check(!private_adapter_body(body,sizeof(body),&body_size)&&body_size>8&&body_size<=ADAPTER_BODY);
    check(!private_adapter_reply(&request,11,reply,sizeof(reply),&size)&&size<=ADAPTER_REPLY);
    check(match_u32(reply+4)==body_size&&size==64+body_size&&!memcmp(reply+64,body,body_size));
    if(!strcmp(argv[1],"--wire")){if(failures)return 2;printf("{\"reply\":\"");for(size_t i=0;i<size;++i)printf("%02x",reply[i]);puts("\"}");return 0;}
    for(size_t cap=0;cap<body_size;++cap){memset(copy,0xa5,sizeof(copy));size_t count=1;
        check(private_adapter_body(copy,cap,&count)<0&&!count&&filled(copy,sizeof(copy)));}
    for(size_t cap=0;cap<size;++cap){memset(copy,0xa5,sizeof(copy));size_t count=1;
        check(private_adapter_reply(&request,11,copy,cap,&count)<0&&!count&&filled(copy,sizeof(copy)));}
    size_t count=1;check(private_adapter_body(NULL,sizeof(body),&count)<0&&!count);
    check(private_adapter_body(body,sizeof(body),NULL)<0);
    count=1;check(private_adapter_reply(NULL,11,reply,sizeof(reply),&count)<0&&!count);
    count=1;check(private_adapter_reply(&request,0,reply,sizeof(reply),&count)<0&&!count);
    count=1;check(private_adapter_reply(&request,11,NULL,sizeof(reply),&count)<0&&!count);
    check(private_adapter_reply(&request,11,reply,sizeof(reply),NULL)<0);
    request.serial=0;count=1;check(private_adapter_reply(&request,11,reply,sizeof(reply),&count)<0&&!count);request.serial=UINT32_MAX;
    memset(request.sender,'x',sizeof(request.sender));count=1;check(private_adapter_reply(&request,11,reply,sizeof(reply),&count)<0&&!count);
    request.sender[0]=':';request.sender[1]='1';request.sender[2]='.';request.sender[MATCH_NAME-1]=0;
    check(!private_adapter_reply(&request,UINT32_MAX,reply,sizeof(reply),&count)&&count<=ADAPTER_REPLY);
    check(!private_adapter_body(copy,sizeof(copy),&count)&&count==body_size&&!memcmp(copy,body,body_size));
    printf("{\"selftest\":\"private-adapter-objects\",\"checks\":%u,\"failures\":%u,\"ok\":%s,\"synthetic_only\":true}\n",checks,failures,failures?"false":"true");return failures?2:0;
}
