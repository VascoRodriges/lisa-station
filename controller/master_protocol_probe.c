/* Synthetic wire/state controls only; no hardware, descriptors or SDK. */
#include <stdio.h>
#include "master_read_protocol.h"
static unsigned checks,failures;
static void check(int good){++checks;if(!good){++failures;fprintf(stderr,"Master protocol check %u\n",checks);}}
static void bad_reply(const void *wire,size_t size,const unsigned char *epoch,unsigned sequence){
    struct master_read_value value,zero={0};memset(&value,0xa5,sizeof(value));
    check(master_reply_decode(wire,size,epoch,sequence,&value)<0&&!memcmp(&value,&zero,sizeof(value)));
}
int main(int argc,char **argv){
    if(argc!=2||strcmp(argv[1],"--selftest"))return 2;
    unsigned char epoch[MASTER_EPOCH_BYTES],other[MASTER_EPOCH_BYTES],zero[MASTER_EPOCH_BYTES]={0};
    for(unsigned i=0;i<MASTER_EPOCH_BYTES;++i){epoch[i]=(unsigned char)(i+1);other[i]=(unsigned char)(i+2);}
    unsigned char request[MASTER_REQUEST_BYTES+1],reply[MASTER_REPLY_BYTES+1];struct master_read_value value;
    check(!master_request_encode(epoch,1,request,MASTER_REQUEST_BYTES)&&!master_request_decode(request,MASTER_REQUEST_BYTES,epoch,1));
    for(size_t i=0;i<MASTER_REQUEST_BYTES;++i){unsigned char bad[MASTER_REQUEST_BYTES];memcpy(bad,request,sizeof(bad));bad[i]^=1;
        check(master_request_decode(bad,sizeof(bad),epoch,1)<0);}
    for(size_t i=0;i<MASTER_REQUEST_BYTES;++i)check(master_request_decode(request,i,epoch,1)<0);
    check(master_request_decode(request,sizeof(request),epoch,1)<0&&master_request_decode(request,SIZE_MAX,epoch,1)<0);
    check(master_request_decode(NULL,MASTER_REQUEST_BYTES,epoch,1)<0&&master_request_decode(request,MASTER_REQUEST_BYTES,NULL,1)<0);
    check(master_request_decode(request,MASTER_REQUEST_BYTES,other,1)<0&&master_request_decode(request,MASTER_REQUEST_BYTES,zero,1)<0);
    const unsigned invalid_sequences[]={0,MASTER_READ_LIMIT+1,UINT32_MAX};
    for(unsigned i=0;i<sizeof(invalid_sequences)/sizeof(invalid_sequences[0]);++i){unsigned sequence=invalid_sequences[i];
        check(master_request_encode(epoch,sequence,request,MASTER_REQUEST_BYTES)<0);
        check(master_reply_encode(epoch,sequence,0,0,reply,MASTER_REPLY_BYTES)<0);
    }
    for(unsigned level=0;level<=255;++level)
        check(!master_reply_encode(epoch,32,0,level,reply,MASTER_REPLY_BYTES)&&!master_reply_decode(reply,MASTER_REPLY_BYTES,epoch,32,&value)&&!value.error&&value.value==level);
    const unsigned errors[]={1,5,4095};
    for(unsigned i=0;i<sizeof(errors)/sizeof(errors[0]);++i)
        check(!master_reply_encode(epoch,1,errors[i],0,reply,MASTER_REPLY_BYTES)&&!master_reply_decode(reply,MASTER_REPLY_BYTES,epoch,1,&value)&&value.error==errors[i]&&!value.value);
    check(master_reply_encode(epoch,1,4096,0,reply,MASTER_REPLY_BYTES)<0&&master_reply_encode(epoch,1,UINT32_MAX,0,reply,MASTER_REPLY_BYTES)<0);
    check(master_reply_encode(epoch,1,5,1,reply,MASTER_REPLY_BYTES)<0&&master_reply_encode(epoch,1,0,256,reply,MASTER_REPLY_BYTES)<0);
    check(!master_reply_encode(epoch,1,0,127,reply,MASTER_REPLY_BYTES));
    for(size_t i=0;i<MASTER_REPLY_BYTES;++i){if(i==32)continue;unsigned char bad[MASTER_REPLY_BYTES];memcpy(bad,reply,sizeof(bad));bad[i]^=1;bad_reply(bad,sizeof(bad),epoch,1);}
    for(size_t i=0;i<MASTER_REPLY_BYTES;++i)bad_reply(reply,i,epoch,1);
    bad_reply(reply,sizeof(reply),epoch,1);bad_reply(reply,SIZE_MAX,epoch,1);bad_reply(NULL,MASTER_REPLY_BYTES,epoch,1);
    bad_reply(reply,MASTER_REPLY_BYTES,NULL,1);bad_reply(reply,MASTER_REPLY_BYTES,zero,1);bad_reply(reply,MASTER_REPLY_BYTES,other,1);
    bad_reply(reply,MASTER_REPLY_BYTES,epoch,2);check(master_reply_decode(reply,MASTER_REPLY_BYTES,epoch,1,NULL)<0);
    check(master_request_encode(epoch,1,NULL,MASTER_REQUEST_BYTES)<0&&master_request_encode(epoch,1,request,MASTER_REQUEST_BYTES-1)<0);
    check(master_reply_encode(epoch,1,0,0,NULL,MASTER_REPLY_BYTES)<0&&master_reply_encode(epoch,1,0,0,reply,MASTER_REPLY_BYTES-1)<0);
    struct master_read_session session;check(!master_session_init(&session,epoch)&&master_session_valid(&session));
    for(unsigned sequence=1;sequence<=MASTER_READ_LIMIT;++sequence){
        struct master_read_session before=session,invalid=session;
        check(master_session_complete(&invalid)<0&&!memcmp(&invalid,&before,sizeof(invalid)));
        check(!master_request_encode(epoch,sequence,request,MASTER_REQUEST_BYTES)&&!master_session_accept(&session,request,MASTER_REQUEST_BYTES)&&session.pending);
        invalid=session;before=session;check(master_session_accept(&invalid,request,MASTER_REQUEST_BYTES)<0&&!memcmp(&invalid,&before,sizeof(invalid)));
        check(!master_session_complete(&session)&&session.completed==sequence&&!session.pending&&session.closed==(sequence==MASTER_READ_LIMIT));
        if(sequence<MASTER_READ_LIMIT){invalid=session;before=session;
            check(master_session_accept(&invalid,request,MASTER_REQUEST_BYTES)<0&&!memcmp(&invalid,&before,sizeof(invalid)));
            check(!master_session_fault(&invalid)&&invalid.closed&&!invalid.pending);
        }
    }
    struct master_read_session before=session;
    check(master_session_accept(&session,request,MASTER_REQUEST_BYTES)<0&&!memcmp(&session,&before,sizeof(session)));
    check(!master_session_fault(&session)&&!memcmp(&session,&before,sizeof(session)));
    check(!master_session_init(&session,other));before=session;
    check(master_session_accept(&session,request,MASTER_REQUEST_BYTES)<0&&!memcmp(&session,&before,sizeof(session)));
    check(!master_session_fault(&session)&&session.closed);
    check(master_session_init(&session,zero)<0&&!master_session_valid(&session));
    check(master_session_init(NULL,epoch)<0&&master_session_accept(NULL,request,MASTER_REQUEST_BYTES)<0&&master_session_complete(NULL)<0&&master_session_fault(NULL)<0);
    for(unsigned i=0;i<5;++i){check(!master_session_init(&session,epoch));
        if(i==0)session.completed=33;else if(i==1)session.pending=2;else if(i==2)session.closed=2;else if(i==3){session.closed=1;session.pending=1;}else session.completed=32;
        before=session;check(!master_session_valid(&session)&&master_session_accept(&session,request,MASTER_REQUEST_BYTES)<0&&master_session_complete(&session)<0&&master_session_fault(&session)<0&&!memcmp(&session,&before,sizeof(session)));
    }
    printf("{\"kind\":\"master-read-protocol\",\"checks\":%u,\"failures\":%u}\n",checks,failures);return failures?1:0;
}
