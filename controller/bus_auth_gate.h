/* Bounded EXTERNAL/UID0 authentication compatibility, then opaque bytes.
 * No sockets, credentials, D-Bus binary parsing or endpoint authorization here.
 * The owner closes BOTH streams on failure/EOF and maintains kernel FD denial.
 * Valid C buffers, serialized calls and an external monotonic timer are required. */
#ifndef LISA_BUS_AUTH_GATE_H
#define LISA_BUS_AUTH_GATE_H
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#define BUS_AUTH_INPUT 2048u
#define BUS_AUTH_OUTPUT 8192u
#define BUS_AUTH_LINE 128u
enum bus_auth_direction { BUS_CLIENT, BUS_BACKEND };
enum bus_auth_phase { BUS_NUL, BUS_AUTH, BUS_DISCOVERY, BUS_WAIT_AUTH, BUS_DATA, BUS_WAIT_DATA, BUS_BEGIN, BUS_BINARY, BUS_FAILED };
enum bus_auth_result { BUS_OK, BUS_BLOCKED, BUS_BAD };
struct bus_auth_gate {
    enum bus_auth_phase phase;
    uint64_t deadline,last;
    unsigned discovery,attempt,negotiated,challenge,total;
    size_t incoming[2],outgoing[2];
    unsigned char input[2][BUS_AUTH_INPUT],output[2][BUS_AUTH_OUTPUT];
};
static inline enum bus_auth_result bus_auth_close(struct bus_auth_gate *gate){
    if(gate){memset(gate,0,sizeof(*gate));gate->phase=BUS_FAILED;}
    return BUS_BAD;
}
static inline enum bus_auth_result bus_auth_init(struct bus_auth_gate *gate,uint64_t now){
    if(!gate)return BUS_BAD;
    memset(gate,0,sizeof(*gate));
    if(!now||now>UINT64_MAX-3000)return bus_auth_close(gate);
    gate->deadline=now+3000;gate->last=now;return BUS_OK;
}
static inline enum bus_auth_result bus_auth_tick(struct bus_auth_gate *gate,uint64_t now){
    if(!gate||gate->phase==BUS_FAILED)return BUS_BAD;
    if(!now||now<gate->last||(gate->phase!=BUS_BINARY&&now>=gate->deadline))return bus_auth_close(gate);
    gate->last=now;return BUS_OK;
}
static inline void bus_auth_shift(unsigned char *buffer,size_t *size,size_t amount){
    memmove(buffer,buffer+amount,*size-amount);memset(buffer+*size-amount,0,amount);*size-=amount;
}
/* The caller sends only this prefix, then consumes exactly the bytes actually
 * written. BLOCKED feed is transactional: no input or state was consumed. */
static inline enum bus_auth_result bus_auth_consume(struct bus_auth_gate *gate,unsigned direction,size_t amount){
    if(!gate||gate->phase==BUS_FAILED)return BUS_BAD;
    if(direction>1||amount>gate->outgoing[direction])return bus_auth_close(gate);
    bus_auth_shift(gate->output[direction],&gate->outgoing[direction],amount);return BUS_OK;
}
static inline enum bus_auth_result bus_auth_emit(struct bus_auth_gate *gate,unsigned direction,const void *data,size_t size){
    if(size>BUS_AUTH_OUTPUT-gate->outgoing[direction])return BUS_BLOCKED;
    if(size)memcpy(gate->output[direction]+gate->outgoing[direction],data,size);
    gate->outgoing[direction]+=size;return BUS_OK;
}
/* 1 complete line, 0 partial, -1 invalid. Check only the current auth line;
 * bytes after its CRLF can be a pipelined command or a binary tail. */
static inline int bus_auth_line(struct bus_auth_gate *gate,unsigned direction,char text[BUS_AUTH_LINE+1],size_t *wire){
    size_t size=gate->incoming[direction];const unsigned char *data=gate->input[direction];
    for(size_t i=0;i<size;++i){
        if(i>BUS_AUTH_LINE)return -1;
        if(data[i]=='\r'){
            if(i==size-1)return 0;
            if(data[i+1]!='\n')return -1;
            memcpy(text,data,i);text[i]=0;*wire=i+2;return 1;
        }
        if(data[i]<32||data[i]>126||i==BUS_AUTH_LINE)return -1;
    }
    return 0;
}
static inline enum bus_auth_result bus_auth_count(struct bus_auth_gate *gate,size_t wire){
    if(wire>BUS_AUTH_INPUT-gate->total)return BUS_BAD;
    gate->total+=(unsigned)wire;return BUS_OK;
}
static inline int bus_auth_ok_line(const char *text){
    if(strlen(text)!=35||memcmp(text,"OK ",3))return 0;
    for(unsigned i=3;i<35;++i)if(!((text[i]>='0'&&text[i]<='9')||(text[i]>='a'&&text[i]<='f')))return 0;
    return 1;
}
static inline enum bus_auth_result bus_auth_pump(struct bus_auth_gate *gate){
    for(;;){
        if(gate->phase==BUS_BINARY){
            for(unsigned i=0;i<2;++i){
                if(bus_auth_emit(gate,1-i,gate->input[i],gate->incoming[i])!=BUS_OK)return BUS_BLOCKED;
                bus_auth_shift(gate->input[i],&gate->incoming[i],gate->incoming[i]);
            }
            return BUS_OK;
        }
        int waiting=gate->phase==BUS_DISCOVERY||gate->phase==BUS_WAIT_AUTH||gate->phase==BUS_WAIT_DATA;
        unsigned direction=waiting?BUS_BACKEND:BUS_CLIENT;
        if(!waiting&&gate->incoming[BUS_BACKEND])return BUS_BAD;
        if(gate->phase==BUS_NUL){
            if(!gate->incoming[BUS_CLIENT])return BUS_OK;
            if(gate->input[BUS_CLIENT][0]||bus_auth_count(gate,1)!=BUS_OK)return BUS_BAD;
            if(bus_auth_emit(gate,BUS_BACKEND,"",1)!=BUS_OK)return BUS_BLOCKED;
            bus_auth_shift(gate->input[BUS_CLIENT],&gate->incoming[BUS_CLIENT],1);gate->phase=BUS_AUTH;continue;
        }
        char text[BUS_AUTH_LINE+1];size_t wire=0;int complete=bus_auth_line(gate,direction,text,&wire);
        if(complete<0)return BUS_BAD;
        if(!complete)return BUS_OK;
        if(bus_auth_count(gate,wire)!=BUS_OK)return BUS_BAD;
        if(waiting){
            if(gate->phase==BUS_DISCOVERY){
                if(strcmp(text,"REJECTED EXTERNAL"))return BUS_BAD;
                gate->phase=BUS_AUTH;
            }else if(bus_auth_ok_line(text)){
                /* The daemon cannot legitimately send binary data before we
                 * have forwarded BEGIN. Reject unsolicited coalesced bytes. */
                if(gate->incoming[BUS_BACKEND]!=wire)return BUS_BAD;
                gate->phase=BUS_BEGIN;
            }else if(gate->phase==BUS_WAIT_AUTH&&!gate->challenge&&(!strcmp(text,"DATA")||!strcmp(text,"DATA "))){
                gate->challenge=1;gate->phase=BUS_DATA;
            }else return BUS_BAD;
            if(bus_auth_emit(gate,BUS_CLIENT,gate->input[direction],wire)!=BUS_OK)return BUS_BLOCKED;
        }else if(gate->phase==BUS_AUTH){
            if(!strcmp(text,"AUTH")&&!gate->discovery&&!gate->attempt){gate->discovery=1;gate->phase=BUS_DISCOVERY;}
            else if((!strcmp(text,"AUTH EXTERNAL 30")||!strcmp(text,"AUTH EXTERNAL"))&&!gate->attempt){gate->attempt=1;gate->phase=BUS_WAIT_AUTH;}
            else return BUS_BAD;
            if(bus_auth_emit(gate,BUS_BACKEND,gate->input[direction],wire)!=BUS_OK)return BUS_BLOCKED;
        }else if(gate->phase==BUS_DATA){
            if(strcmp(text,"DATA 30"))return BUS_BAD;
            gate->phase=BUS_WAIT_DATA;
            if(bus_auth_emit(gate,BUS_BACKEND,gate->input[direction],wire)!=BUS_OK)return BUS_BLOCKED;
        }else if(gate->phase==BUS_BEGIN){
            if(!strcmp(text,"NEGOTIATE_UNIX_FD")&&!gate->negotiated){
                static const char denied[]="ERROR Unix FD passing disabled\r\n";gate->negotiated=1;
                if(bus_auth_emit(gate,BUS_CLIENT,denied,sizeof(denied)-1)!=BUS_OK)return BUS_BLOCKED;
            }else if(!strcmp(text,"BEGIN")){
                if(bus_auth_emit(gate,BUS_BACKEND,gate->input[direction],wire)!=BUS_OK)return BUS_BLOCKED;
                gate->phase=BUS_BINARY;
            }else return BUS_BAD;
        }else return BUS_BAD;
        bus_auth_shift(gate->input[direction],&gate->incoming[direction],wire);
    }
}
static inline enum bus_auth_result bus_auth_feed(struct bus_auth_gate *gate,unsigned direction,const void *data,size_t size,uint64_t now){
    if(!gate||gate->phase==BUS_FAILED)return BUS_BAD;
    if(direction>1||(!data&&size))return bus_auth_close(gate);
    struct bus_auth_gate next=*gate;
    if(bus_auth_tick(&next,now)!=BUS_OK)return bus_auth_close(gate);
    if(next.phase==BUS_BINARY){
        enum bus_auth_result result=bus_auth_emit(&next,1-direction,data,size);
        if(result==BUS_OK)*gate=next;
        return result;
    }
    if(size>BUS_AUTH_INPUT-next.incoming[direction])return BUS_BLOCKED;
    if(size)memcpy(next.input[direction]+next.incoming[direction],data,size);
    next.incoming[direction]+=size;
    enum bus_auth_result result=bus_auth_pump(&next);
    if(result==BUS_BAD)return bus_auth_close(gate);
    if(result==BUS_OK)*gate=next;
    return result;
}
#endif
