/* Synthetic codec fixtures only; this executable opens no bus or devices. */
#include <stdio.h>
#include "private_empty_objects.h"
static unsigned checks,failures;
static void check(int good){++checks;if(!good){++failures;fprintf(stderr,"empty objects check %u\n",checks);}}
static int zero(const struct private_empty_request *request){struct private_empty_request empty={0};return !memcmp(request,&empty,sizeof(empty));}
static void bad(const void *bytes,size_t size,const char *sender){struct private_empty_request request;memset(&request,0xa5,sizeof(request));check(private_empty_request_decode(bytes,size,sender,&request)<0&&zero(&request));}
static size_t fixture(unsigned char *p,const char *path,const char *interface,const char *member,const char *destination,const char *sender,unsigned optional,unsigned flags){
    memset(p,0,EMPTY_OBJECTS_FRAME);p[0]='l';p[1]=1;p[2]=(unsigned char)flags;p[3]=1;empty_objects_put(p+8,7);
    size_t n=16;n=empty_objects_field(p,n,1,'o',path);n=empty_objects_field(p,n,2,'s',interface);
    n=empty_objects_field(p,n,3,'s',member);n=empty_objects_field(p,n,6,'s',destination);n=empty_objects_field(p,n,7,'s',sender);
    if(optional&1)n=empty_objects_field(p,n,8,'g',"");
    if(optional&2){n=(n+7)&~(size_t)7;p[n++]=9;p[n++]=1;p[n++]='u';p[n++]=0;n+=4;}
    empty_objects_put(p+12,(uint32_t)(n-16));return (n+7)&~(size_t)7;
}
static size_t good_fixture(unsigned char *p,unsigned optional,unsigned flags){return fixture(p,"/","org.freedesktop.DBus.ObjectManager","GetManagedObjects","org.bluez",":1.2",optional,flags);}
static const char golden_hex[]=
    /* Independent libdbus-1 message marshal, with destination before interface. */
    "6c01000100000000070000008500000001016f00010000002f0000000000000006017300090000006f72672e626c75657a0000000000000002017300220000006f72672e667265656465736b746f702e444275732e4f626a6563744d616e6167657200000000000003017300110000004765744d616e616765644f626a656374730000000000000007017300040000003a312e3200000000";
static size_t golden(unsigned char *bytes){size_t size=strlen(golden_hex)/2;for(size_t i=0;i<size;++i){unsigned value=0;sscanf(golden_hex+2*i,"%2x",&value);bytes[i]=(unsigned char)value;}return size;}
static void hex(const unsigned char *bytes,size_t size){for(size_t i=0;i<size;++i)printf("%02x",bytes[i]);}
int main(int argc,char **argv){
    if(argc!=2||(strcmp(argv[1],"--selftest")&&strcmp(argv[1],"--wire")))return 2;
    unsigned char bytes[EMPTY_OBJECTS_FRAME],altered[EMPTY_OBJECTS_FRAME],reply[EMPTY_OBJECTS_REPLY];struct private_empty_request request;
    size_t size=golden(bytes),written=0;
    check(size==152&&!private_empty_request_decode(bytes,size,":1.2",&request)&&request.serial==7&&!strcmp(request.sender,":1.2"));
    check(!private_empty_reply(&request,11,reply,sizeof(reply),&written));
    if(!strcmp(argv[1],"--wire")){if(failures)return 2;printf("{\"request\":\"");hex(bytes,size);printf("\",\"reply\":\"");hex(reply,written);puts("\"}");return 0;}
    for(size_t cut=0;cut<size;++cut)bad(bytes,cut,":1.2");
    bad(bytes,size,":1.3");bad(bytes,size,NULL);bad(NULL,size,":1.2");bad(bytes,EMPTY_OBJECTS_FRAME+1,":1.2");
    check(private_empty_request_decode(bytes,size,":1.2",NULL)<0);
    const char *invalid_names[]={"",":one",":.1",":1.",":1..2","org.example.Name",":1. bad"};
    for(unsigned i=0;i<sizeof(invalid_names)/sizeof(invalid_names[0]);++i)bad(bytes,size,invalid_names[i]);
    for(unsigned option=0;option<4;++option)for(unsigned flag=0;flag<=2;flag+=2){size=good_fixture(bytes,option,flag);
        check(!private_empty_request_decode(bytes,size,":1.2",&request));
        for(size_t cut=0;cut<size;++cut)bad(bytes,cut,":1.2");
    }
    for(unsigned flag=0;flag<256;++flag)if(flag!=0&&flag!=2){size=good_fixture(bytes,0,flag);bad(bytes,size,":1.2");}
    for(unsigned field=0;field<5;++field){const char *values[]={"/","org.freedesktop.DBus.ObjectManager","GetManagedObjects","org.bluez",":1.2"};
        values[field]="wrong";size=fixture(bytes,values[0],values[1],values[2],values[3],values[4],0,0);bad(bytes,size,":1.2");}
    size=good_fixture(bytes,0,0);empty_objects_put(bytes+4,1);bad(bytes,size,":1.2");
    size=good_fixture(bytes,0,0);empty_objects_put(bytes+8,0);bad(bytes,size,":1.2");
    size=good_fixture(bytes,0,0);empty_objects_put(bytes+12,UINT32_MAX);bad(bytes,size,":1.2");
    size=good_fixture(bytes,0,0);bytes[1]=2;bad(bytes,size,":1.2");
    size=good_fixture(bytes,0,0);bytes[0]='B';bad(bytes,size,":1.2");
    size=good_fixture(bytes,0,0);bytes[3]=2;bad(bytes,size,":1.2");
    /* Missing/duplicate/unknown fields and each wrong variant type. */
    for(unsigned field=0;field<5;++field){size=good_fixture(bytes,0,0);size_t cursor=16;
        for(unsigned i=0;i<field;++i){cursor=(cursor+7)&~(size_t)7;cursor+=8+strlen((const char *)bytes+cursor+8)+1;}
        cursor=(cursor+7)&~(size_t)7;
        memcpy(altered,bytes,size);altered[cursor]=10;bad(altered,size,":1.2");
        memcpy(altered,bytes,size);altered[cursor]=field?1:4;bad(altered,size,":1.2");
        memcpy(altered,bytes,size);altered[cursor+2]=field?'o':'s';bad(altered,size,":1.2");
        memcpy(altered,bytes,size);altered[cursor+1]=2;bad(altered,size,":1.2");
        memcpy(altered,bytes,size);empty_objects_put(altered+cursor+4,UINT32_MAX);bad(altered,size,":1.2");
        /* Terminate the header before this required field. */
        memcpy(altered,bytes,size);empty_objects_put(altered+12,(uint32_t)(cursor-16));bad(altered,cursor,":1.2");
    }
    size=good_fixture(bytes,3,0);size_t end=16+match_u32(bytes+12);bytes[end-1]=1;bad(bytes,size,":1.2");
    size=good_fixture(bytes,1,0);end=16+match_u32(bytes+12);bytes[end-2]=1;bad(bytes,size,":1.2");
    size=good_fixture(bytes,0,0);end=16+match_u32(bytes+12);bytes[end]=1;bad(bytes,size,":1.2");
    size=good_fixture(bytes,0,0);bytes[size]=0;bad(bytes,size+1,":1.2");
    size=golden(bytes);
    for(size_t where=0;where<size;++where){memcpy(altered,bytes,size);altered[where]^=0xff;
        int result=private_empty_request_decode(altered,size,":1.2",&request);check(result?zero(&request):request.serial&&!strcmp(request.sender,":1.2"));}
    /* Longest valid unique name and unterminated/oversize names. */
    char name[MATCH_NAME+1];memset(name,'x',sizeof(name));name[0]=':';name[1]='1';name[2]='.';name[MATCH_NAME-1]=0;
    size=fixture(bytes,"/","org.freedesktop.DBus.ObjectManager","GetManagedObjects","org.bluez",name,0,0);
    check(!private_empty_request_decode(bytes,size,name,&request));
    check(!private_empty_reply(&request,UINT32_MAX,reply,sizeof(reply),&written)&&written<=EMPTY_OBJECTS_REPLY);
    name[MATCH_NAME-1]='x';name[MATCH_NAME]=0;bad(bytes,size,name);
    memset(request.sender,'x',sizeof(request.sender));written=1;
    check(private_empty_reply(&request,11,reply,sizeof(reply),&written)<0&&!written);
    size=golden(bytes);check(!private_empty_request_decode(bytes,size,":1.2",&request));
    check(!private_empty_reply(&request,11,reply,sizeof(reply),&written)&&written==72&&reply[0]=='l'&&reply[1]==2&&match_u32(reply+4)==8&&match_u32(reply+8)==11);
    for(size_t capacity=0;capacity<written;++capacity){memset(altered,0xa5,sizeof(altered));size_t count=1;
        check(private_empty_reply(&request,11,altered,capacity,&count)<0&&!count);
        int unchanged=1;for(size_t i=0;i<sizeof(altered);++i)if(altered[i]!=0xa5)unchanged=0;check(unchanged);
    }
    written=1;check(private_empty_reply(NULL,11,reply,sizeof(reply),&written)<0&&!written);
    written=1;check(private_empty_reply(&request,0,reply,sizeof(reply),&written)<0&&!written);
    written=1;check(private_empty_reply(&request,11,NULL,sizeof(reply),&written)<0&&!written);
    check(private_empty_reply(&request,11,reply,sizeof(reply),NULL)<0);
    request.serial=0;written=1;check(private_empty_reply(&request,11,reply,sizeof(reply),&written)<0&&!written);
    printf("{\"selftest\":\"private-empty-objects\",\"checks\":%u,\"failures\":%u,\"ok\":%s,\"synthetic_only\":true}\n",checks,failures,failures?"false":"true");return failures?2:0;
}
