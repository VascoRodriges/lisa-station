/* Synthetic API metadata and chunk-boundary fixtures, no ALSA or devices. */
#include <stdio.h>
#include "mixer_attach_record.h"
static unsigned checks,failures;
static void check(int good){++checks;if(!good){++failures;fprintf(stderr,"Mixer record check %u\n",checks);}}
static void reject(const void *bytes,size_t size){
    struct mixer_attach_record result,zero={0};memset(&result,0xa5,sizeof(result));
    check(mixer_record_decode(bytes,size,&result)<0&&!memcmp(&result,&zero,sizeof(result)));
}
int main(int argc,char **argv){
    if(argc!=2||strcmp(argv[1],"--selftest"))return 2;
    unsigned char wire[MIXER_RECORD_WIRE],other[MIXER_RECORD_WIRE];struct mixer_attach_record record;
    const int32_t results[]={INT32_MIN,-2,-1,0,1,INT32_MAX};
    for(unsigned i=0;i<sizeof(results)/sizeof(results[0]);++i)
        check(!mixer_record_encode(MIXER_MISSING_CONTROL,results[i],wire,sizeof(wire))&&!mixer_record_decode(wire,sizeof(wire),&record)&&
            record.result==results[i]&&!strcmp(record.label,MIXER_MISSING_CONTROL));
    check(!mixer_record_encode(MIXER_MISSING_CONTROL,-2,wire,sizeof(wire)));
    check(!mixer_record_encode("ctl.\xc2\xa3",-1,other,sizeof(other)));
    const char noise[]="plain noise LILIS plain\n",tail[]="tail\n";
    unsigned char stream[sizeof(noise)-1+2*MIXER_RECORD_WIRE+sizeof(tail)-1];size_t n=sizeof(noise)-1;
    memcpy(stream,noise,n);memcpy(stream+n,wire,sizeof(wire));n+=sizeof(wire);memcpy(stream+n,other,sizeof(other));n+=sizeof(other);memcpy(stream+n,tail,sizeof(tail)-1);
    for(size_t cut=0;cut<=sizeof(stream);++cut){struct mixer_attach_audit audit={0};
        check(!mixer_audit_feed(&audit,stream,cut)&&!mixer_audit_feed(&audit,stream+cut,sizeof(stream)-cut)&&!mixer_audit_finish(&audit)&&
            audit.count==2&&audit.record[0].result==-2&&!strcmp(audit.record[0].label,MIXER_MISSING_CONTROL)&&audit.record[1].result==-1&&!strcmp(audit.record[1].label,"ctl.\xc2\xa3"));
    }
    for(size_t chunk=1;chunk<=32;++chunk){struct mixer_attach_audit audit={0};int good=1;
        for(size_t offset=0;offset<sizeof(stream);offset+=chunk){size_t size=sizeof(stream)-offset;if(size>chunk)size=chunk;if(mixer_audit_feed(&audit,stream+offset,size))good=0;}
        check(good&&!mixer_audit_finish(&audit)&&audit.count==2);
    }
    for(size_t i=0;i<sizeof(wire);++i){reject(wire,i);struct mixer_attach_audit audit={0};
        check(!mixer_audit_feed(&audit,wire,i)&&mixer_audit_finish(&audit)<0);
    }
    reject(NULL,sizeof(wire));reject(wire,SIZE_MAX);check(mixer_record_decode(wire,sizeof(wire),NULL)<0);
    const unsigned offsets[]={0,7,8,16,16+sizeof(MIXER_MISSING_CONTROL),MIXER_RECORD_WIRE-1};
    for(unsigned i=0;i<sizeof(offsets)/sizeof(offsets[0]);++i){unsigned char bad[MIXER_RECORD_WIRE];memcpy(bad,wire,sizeof(bad));bad[offsets[i]]=0xff;reject(bad,sizeof(bad));}
    char label[MIXER_LABEL_MAX+2];memset(label,'x',sizeof(label));label[sizeof(label)-1]=0;
    check(mixer_record_encode(label,0,other,sizeof(other))<0);label[MIXER_LABEL_MAX]=0;
    check(!mixer_record_encode(label,0,other,sizeof(other))&&!mixer_record_decode(other,sizeof(other),&record)&&strlen(record.label)==MIXER_LABEL_MAX);
    const char *const invalid[]={NULL,"","\xc0\x80","\xed\xa0\x80","\xf4\x90\x80\x80"};
    for(unsigned i=0;i<sizeof(invalid)/sizeof(invalid[0]);++i)check(mixer_record_encode(invalid[i],0,other,sizeof(other))<0);
    check(mixer_record_encode("ctl",0,NULL,sizeof(other))<0&&mixer_record_encode("ctl",0,other,sizeof(other)-1)<0);
    struct mixer_attach_audit audit={0};
    check(!mixer_audit_feed(&audit,NULL,0)&&mixer_audit_finish(&audit)<0);
    for(unsigned i=0;i<4;++i)check(!mixer_audit_feed(&audit,wire,sizeof(wire)));
    check(!mixer_audit_finish(&audit)&&audit.count==4);
    check(mixer_audit_feed(&audit,wire,sizeof(wire))<0&&audit.failed&&mixer_audit_finish(&audit)<0);
    check(mixer_audit_feed(&audit,NULL,0)<0);
    memset(&audit,0,sizeof(audit));memcpy(other,wire,sizeof(other));other[7]='2';
    check(mixer_audit_feed(&audit,other,sizeof(other))<0&&audit.failed);
    memset(&audit,0,sizeof(audit));check(mixer_audit_feed(&audit,NULL,1)<0&&audit.failed);
    check(mixer_audit_feed(NULL,wire,sizeof(wire))<0&&mixer_audit_finish(NULL)<0);
    printf("{\"kind\":\"mixer-attach-record\",\"checks\":%u,\"failures\":%u}\n",checks,failures);return failures?1:0;
}
