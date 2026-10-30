/* Synthetic private Stats replies only. No bus, SDK, account or audio. */
#include <stdio.h>
#include "private_match_snapshot.h"
static unsigned checks,failures;
static void check(int good){++checks;if(!good){++failures;fprintf(stderr,"match snapshot check %u\n",checks);}}
static void put(unsigned char *p,uint32_t n){for(unsigned i=0;i<4;++i)p[i]=(unsigned char)(n>>(8*i));}
static size_t align(size_t n,unsigned a){return (n+a-1)&~(size_t)(a-1);}
static size_t string(unsigned char *p,size_t n,const char *text){n=align(n,4);size_t length=strlen(text);put(p+n,(uint32_t)length);n+=4;memcpy(p+n,text,length+1);return n+length+1;}
static size_t entry(unsigned char *p,size_t n,const char *name,const char *rule){
    n=align(n,8);n=string(p,n,name);n=align(n,4);size_t length=n;n+=4;size_t start=n;
    if(rule)n=string(p,n,rule);
    put(p+length,(uint32_t)(n-start));return n;
}
static int zero(const struct private_match_snapshot *s){struct private_match_snapshot empty={0};return !memcmp(s,&empty,sizeof(empty));}
static void bad(const unsigned char *p,size_t size){struct private_match_snapshot out;memset(&out,0xa5,sizeof(out));check(private_match_decode(p,size,&out)<0&&zero(&out));}
int main(int argc,char **argv){
    if(argc!=2||strcmp(argv[1],"--selftest"))return 2;
    unsigned char bytes[MATCH_BODY+128]={0};struct private_match_snapshot out;
    /* Independent fixed wire image: one :1.0 key, one type='signal' rule. */
    const unsigned char golden[]={34,0,0,0,0,0,0,0,4,0,0,0,':','1','.','0',0,0,0,0,18,0,0,0,13,0,0,0,'t','y','p','e','=','\'','s','i','g','n','a','l','\'',0};
    check(!private_match_decode(golden,sizeof(golden),&out)&&out.clients==1&&out.rules==1);
    const struct private_match_entry *found=private_match_find(&out,":1.0");check(found&&found->rules==1&&!strcmp(found->rule,"type='signal'"));
    check(!private_match_find(&out,":1.1")&&!private_match_find(NULL,":1.0")&&!private_match_find(&out,NULL));
    check(!private_match_decode(bytes,8,&out)&&!out.clients&&!out.rules);
    for(unsigned count=1;count<=4;++count){memset(bytes,0,sizeof(bytes));size_t n=8;
        for(unsigned i=0;i<count;++i){char name[16];snprintf(name,sizeof(name),":1.%u",i);n=entry(bytes,n,name,i%2?NULL:"type='signal',arg0='Привет'");}
        put(bytes,(uint32_t)(n-8));check(!private_match_decode(bytes,n,&out)&&out.clients==count&&out.rules==(count+1)/2);
        for(size_t cut=0;cut<n;++cut)bad(bytes,cut);
    }
    memset(bytes,0,sizeof(bytes));size_t n=8;for(unsigned i=0;i<5;++i){char name[16];snprintf(name,sizeof(name),":1.%u",i);n=entry(bytes,n,name,NULL);}put(bytes,(uint32_t)(n-8));bad(bytes,n);
    memset(bytes,0,sizeof(bytes));n=entry(bytes,8,":1.0",NULL);n=entry(bytes,n,":1.0",NULL);put(bytes,(uint32_t)(n-8));bad(bytes,n);
    const char *names[]={"",":one",":.one",":one.",":one..two","org.example.Name",":1. bad"};
    for(unsigned i=0;i<sizeof(names)/sizeof(names[0]);++i){memset(bytes,0,sizeof(bytes));n=entry(bytes,8,names[i],NULL);put(bytes,(uint32_t)(n-8));bad(bytes,n);}
    const unsigned char invalid[][5]={{0xc0,0x80,0},{0xed,0xa0,0x80,0},{0xf4,0x90,0x80,0x80,0},{0xe2,0x82,0},{0xff,0},{0x80,0}};
    for(unsigned i=0;i<sizeof(invalid)/sizeof(invalid[0]);++i){memset(bytes,0,sizeof(bytes));n=entry(bytes,8,":1.0",(const char *)invalid[i]);put(bytes,(uint32_t)(n-8));bad(bytes,n);}
    char long_rule[MATCH_RULE+2];memset(long_rule,'x',sizeof(long_rule));long_rule[sizeof(long_rule)-1]=0;
    memset(bytes,0,sizeof(bytes));n=entry(bytes,8,":1.0",long_rule);put(bytes,(uint32_t)(n-8));bad(bytes,n);
    long_rule[MATCH_RULE]=0;memset(bytes,0,sizeof(bytes));n=entry(bytes,8,":1.0",long_rule);put(bytes,(uint32_t)(n-8));check(!private_match_decode(bytes,n,&out)&&strlen(out.entry[0].rule)==MATCH_RULE);
    memset(bytes,0,sizeof(bytes));n=entry(bytes,8,":1.0","");put(bytes,(uint32_t)(n-8));check(!private_match_decode(bytes,n,&out)&&out.rules==1&&!out.entry[0].rule[0]);
    memset(bytes,0,sizeof(bytes));n=entry(bytes,8,":1.0","one");size_t start=24;n=string(bytes,n,"two");put(bytes+20,(uint32_t)(n-start));put(bytes,(uint32_t)(n-8));bad(bytes,n);
    for(unsigned where=0;where<sizeof(golden);++where){
        memcpy(bytes,golden,sizeof(golden));bytes[where]^=0xff;
        int result=private_match_decode(bytes,sizeof(golden),&out);
        check(result?zero(&out):(out.clients<=4&&out.rules<=4&&out.entry[0].rules<=1));
    }
    memcpy(bytes,golden,sizeof(golden));bytes[4]=1;bad(bytes,sizeof(golden));
    memcpy(bytes,golden,sizeof(golden));bytes[17]=1;bad(bytes,sizeof(golden));
    memcpy(bytes,golden,sizeof(golden));bytes[sizeof(golden)]=0;put(bytes,35);bad(bytes,sizeof(golden)+1);
    memcpy(bytes,golden,sizeof(golden));put(bytes,UINT32_MAX);bad(bytes,sizeof(golden));
    memcpy(bytes,golden,sizeof(golden));put(bytes+8,UINT32_MAX);bad(bytes,sizeof(golden));
    memcpy(bytes,golden,sizeof(golden));put(bytes+20,UINT32_MAX);bad(bytes,sizeof(golden));
    memcpy(bytes,golden,sizeof(golden));bytes[30]=0;bad(bytes,sizeof(golden));
    bad(NULL,8);bad(bytes,MATCH_BODY+1);check(private_match_decode(bytes,8,NULL)<0);
    printf("{\"selftest\":\"private-match-snapshot\",\"checks\":%u,\"failures\":%u,\"ok\":%s,\"synthetic_only\":true}\n",checks,failures,failures?"false":"true");return failures?2:0;
}
