/* Synthetic bytes only. No sockets, actual bus, SDK, account or audio. */
#include <stdio.h>
#include "bus_auth_gate.h"
static unsigned checks,failures;
static void check(int good){++checks;if(!good){++failures;fprintf(stderr,"auth check %u\n",checks);}}
static const char hello[]="\0AUTH EXTERNAL 30\r\nNEGOTIATE_UNIX_FD\r\nBEGIN\r\n\1\0\2\xff";
static const char reply[]="OK 0123456789abcdef0123456789abcdef\r\n";
static const char denied[]="ERROR Unix FD passing disabled\r\n";
static int zeroed(const struct bus_auth_gate *gate){
    struct bus_auth_gate expected;memset(&expected,0,sizeof(expected));expected.phase=BUS_FAILED;return !memcmp(gate,&expected,sizeof(expected));
}
static void pipeline(size_t client_split,size_t server_split){
    struct bus_auth_gate gate;check(bus_auth_init(&gate,100)==BUS_OK);
    check(bus_auth_feed(&gate,BUS_CLIENT,hello,client_split,101)==BUS_OK);
    check(bus_auth_feed(&gate,BUS_CLIENT,hello+client_split,sizeof(hello)-1-client_split,102)==BUS_OK);
    static const char auth[]="\0AUTH EXTERNAL 30\r\n";
    check(gate.phase==BUS_WAIT_AUTH&&gate.outgoing[BUS_BACKEND]==sizeof(auth)-1&&!memcmp(gate.output[BUS_BACKEND],auth,sizeof(auth)-1));
    check(bus_auth_consume(&gate,BUS_BACKEND,1)==BUS_OK);
    check(bus_auth_consume(&gate,BUS_BACKEND,sizeof(auth)-2)==BUS_OK);
    check(bus_auth_feed(&gate,BUS_BACKEND,reply,server_split,103)==BUS_OK);
    check(bus_auth_feed(&gate,BUS_BACKEND,reply+server_split,sizeof(reply)-1-server_split,104)==BUS_OK);
    static const char binary[]="BEGIN\r\n\1\0\2\xff";
    check(gate.phase==BUS_BINARY&&gate.negotiated==1&&gate.outgoing[BUS_BACKEND]==sizeof(binary)-1&&!memcmp(gate.output[BUS_BACKEND],binary,sizeof(binary)-1));
    check(gate.outgoing[BUS_CLIENT]==sizeof(reply)+sizeof(denied)-2&&!memcmp(gate.output[BUS_CLIENT],reply,sizeof(reply)-1)&&
        !memcmp(gate.output[BUS_CLIENT]+sizeof(reply)-1,denied,sizeof(denied)-1));
    check(bus_auth_tick(&gate,99999)==BUS_OK);
    check(bus_auth_consume(&gate,BUS_CLIENT,gate.outgoing[BUS_CLIENT])==BUS_OK);
    const char payload[]={0,1,2,(char)255};check(bus_auth_feed(&gate,BUS_BACKEND,payload,sizeof(payload),100000)==BUS_OK&&
        gate.outgoing[BUS_CLIENT]==sizeof(payload)&&!memcmp(gate.output[BUS_CLIENT],payload,sizeof(payload)));
    check(bus_auth_close(&gate)==BUS_BAD&&zeroed(&gate));
}
static void negative(void){
    const char *requests[]={"X","\0AUTH ANONYMOUS\r\n","\0AUTH EXTERNAL 31\r\n","\0AUTH EXTERNAL 3030\r\n", "\0BEGIN\r\n", "\0DATA 30\r\n", "\0AUTH\n", "\0AUTH\rX"};
    const size_t sizes[]={1,17,19,21,8,10,6,7};
    for(unsigned i=0;i<sizeof(sizes)/sizeof(sizes[0]);++i){struct bus_auth_gate gate;bus_auth_init(&gate,10);
        check(bus_auth_feed(&gate,BUS_CLIENT,requests[i],sizes[i],11)==BUS_BAD&&zeroed(&gate));}
    const char *responses[]={"AGREE_UNIX_FD\r\n","OK 0\r\n","OK 0123456789abcdef0123456789abcdeg\r\n","REJECTED ANONYMOUS\r\n", "DATA 31\r\n", "OK 0123456789abcdef0123456789abcdef\r\nX"};
    for(unsigned i=0;i<sizeof(responses)/sizeof(responses[0]);++i){struct bus_auth_gate gate;bus_auth_init(&gate,10);
        check(bus_auth_feed(&gate,BUS_CLIENT,hello,sizeof(hello)-1,11)==BUS_OK);
        check(bus_auth_feed(&gate,BUS_BACKEND,responses[i],strlen(responses[i]),12)==BUS_BAD&&zeroed(&gate));}
    struct bus_auth_gate gate;bus_auth_init(&gate,10);
    check(bus_auth_feed(&gate,BUS_BACKEND,reply,sizeof(reply)-1,11)==BUS_BAD&&zeroed(&gate));
    bus_auth_init(&gate,10);check(bus_auth_feed(&gate,BUS_CLIENT,"\0AUTH\r\n",7,11)==BUS_OK);
    check(bus_auth_feed(&gate,BUS_BACKEND,"REJECTED EXTERNAL\r\n",19,12)==BUS_OK);
    check(bus_auth_feed(&gate,BUS_CLIENT,"AUTH\r\n",6,13)==BUS_BAD&&zeroed(&gate));
    bus_auth_init(&gate,10);check(bus_auth_feed(&gate,BUS_CLIENT,"\0AUTH EXTERNAL\r\n",16,11)==BUS_OK);
    check(bus_auth_feed(&gate,BUS_BACKEND,"DATA\r\n",6,12)==BUS_OK);
    check(bus_auth_feed(&gate,BUS_CLIENT,"DATA 31\r\n",9,13)==BUS_BAD&&zeroed(&gate));
    bus_auth_init(&gate,10);check(bus_auth_feed(&gate,BUS_CLIENT,"\0AUTH EXTERNAL 30\r\n",19,11)==BUS_OK);
    check(bus_auth_feed(&gate,BUS_BACKEND,reply,sizeof(reply)-1,12)==BUS_OK);
    static const char repeated[]="NEGOTIATE_UNIX_FD\r\nNEGOTIATE_UNIX_FD\r\n";
    check(bus_auth_feed(&gate,BUS_CLIENT,repeated,sizeof(repeated)-1,13)==BUS_BAD&&zeroed(&gate));
}
static void limits(void){
    struct bus_auth_gate gate;check(bus_auth_init(&gate,0)==BUS_BAD&&zeroed(&gate));
    check(bus_auth_init(&gate,UINT64_MAX)==BUS_BAD&&zeroed(&gate));
    bus_auth_init(&gate,100);check(bus_auth_tick(&gate,99)==BUS_BAD&&zeroed(&gate));
    bus_auth_init(&gate,100);check(bus_auth_tick(&gate,3099)==BUS_OK);check(bus_auth_tick(&gate,3100)==BUS_BAD&&zeroed(&gate));
    bus_auth_init(&gate,100);check(bus_auth_feed(&gate,2,"X",1,101)==BUS_BAD&&zeroed(&gate));
    bus_auth_init(&gate,100);check(bus_auth_feed(&gate,BUS_CLIENT,NULL,1,101)==BUS_BAD&&zeroed(&gate));
    bus_auth_init(&gate,100);check(bus_auth_consume(&gate,BUS_CLIENT,1)==BUS_BAD&&zeroed(&gate));
    bus_auth_init(&gate,100);check(bus_auth_consume(&gate,2,0)==BUS_BAD&&zeroed(&gate));
    bus_auth_init(&gate,100);char long_line[130];memset(long_line,'A',sizeof(long_line));long_line[0]=0;
    check(bus_auth_feed(&gate,BUS_CLIENT,long_line,sizeof(long_line),101)==BUS_BAD&&zeroed(&gate));
    bus_auth_init(&gate,100);gate.phase=BUS_BINARY;unsigned char bytes[BUS_AUTH_OUTPUT];memset(bytes,0xa5,sizeof(bytes));
    check(bus_auth_feed(&gate,BUS_CLIENT,bytes,sizeof(bytes),101)==BUS_OK);
    struct bus_auth_gate previous;memcpy(&previous,&gate,sizeof(gate));
    check(bus_auth_feed(&gate,BUS_CLIENT,"X",1,102)==BUS_BLOCKED&&!memcmp(&gate,&previous,sizeof(gate)));
    check(bus_auth_consume(&gate,BUS_BACKEND,3)==BUS_OK);
    check(bus_auth_feed(&gate,BUS_CLIENT,"XYZ",3,103)==BUS_OK&&gate.outgoing[BUS_BACKEND]==BUS_AUTH_OUTPUT&&
        !memcmp(gate.output[BUS_BACKEND]+BUS_AUTH_OUTPUT-3,"XYZ",3));
    check(bus_auth_feed(&gate,BUS_BACKEND,NULL,0,104)==BUS_OK);
    check(bus_auth_close(&gate)==BUS_BAD&&zeroed(&gate));
    bus_auth_init(&gate,100);bus_auth_feed(&gate,BUS_CLIENT,hello,sizeof(hello)-1,101);memcpy(&previous,&gate,sizeof(gate));
    check(bus_auth_feed(&gate,BUS_CLIENT,bytes,BUS_AUTH_INPUT+1,102)==BUS_BLOCKED&&!memcmp(&gate,&previous,sizeof(gate)));
    check(bus_auth_tick(&gate,3100)==BUS_BAD&&zeroed(&gate));
    bus_auth_init(&gate,100);gate.total=BUS_AUTH_INPUT;check(bus_auth_feed(&gate,BUS_CLIENT,"\0",1,101)==BUS_BAD&&zeroed(&gate));
}
static void challenge(void){
    struct bus_auth_gate gate;bus_auth_init(&gate,1);
    check(bus_auth_feed(&gate,BUS_CLIENT,"\0AUTH\r\n",7,2)==BUS_OK);
    check(bus_auth_feed(&gate,BUS_BACKEND,"REJECTED EXTERNAL\r\n",19,3)==BUS_OK);
    check(bus_auth_feed(&gate,BUS_CLIENT,"AUTH EXTERNAL\r\n",15,4)==BUS_OK);
    check(bus_auth_feed(&gate,BUS_BACKEND,"DATA\r\n",6,5)==BUS_OK);
    check(bus_auth_feed(&gate,BUS_CLIENT,"DATA 30\r\n",9,6)==BUS_OK);
    check(bus_auth_feed(&gate,BUS_BACKEND,reply,sizeof(reply)-1,7)==BUS_OK);
    check(bus_auth_feed(&gate,BUS_CLIENT,"BEGIN\r\n",7,8)==BUS_OK&&gate.phase==BUS_BINARY&&!gate.negotiated);
    check(bus_auth_close(&gate)==BUS_BAD&&zeroed(&gate));
}
int main(int argc,char **argv){
    if(argc!=2||strcmp(argv[1],"--selftest"))return 2;
    for(size_t i=0;i<sizeof(hello);++i)for(size_t j=0;j<sizeof(reply);++j)pipeline(i,j);
    negative();limits();challenge();
    printf("{\"selftest\":\"bus-auth-gate\",\"checks\":%u,\"failures\":%u,\"ok\":%s,\"synthetic_only\":true}\n",checks,failures,failures?"false":"true");
    return failures?2:0;
}
