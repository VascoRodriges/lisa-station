/* Selective closed policy installation. Caller must durably reserve the owned
 * namespace before mutation and serialize operations. Never flush/adopt unknown
 * rules, change default policy or drop unrelated root traffic. */
#ifndef LISA_BOOT_POLICY_H
#define LISA_BOOT_POLICY_H
#include "label_policy.h"

static inline int boot_policy_lines(char *text,char **lines,unsigned maximum) {
    size_t length=strlen(text);
    if(!length||text[0]=='\n'||text[length-1]!='\n'||strstr(text,"\n\n")) return -1;
    unsigned count=0; char *save=NULL;
    for(char *line=strtok_r(text,"\n",&save);line;line=strtok_r(NULL,"\n",&save)) {
        if(count==maximum) return -1;
        lines[count++]=line;
    }
    return (int)count;
}
/* An ordered subset is recoverable. Duplicates, reordered or unknown rules are
 * not ownership evidence and are never removed to make a comparison pass. */
static inline int boot_policy_subset(const char *actual,const char *expected,unsigned present[4]) {
    char a[2048],e[2048],*al[5],*el[5];
    if(!actual||!expected||strlen(actual)>=sizeof(a)||strlen(expected)>=sizeof(e)) return -1;
    strcpy(a,actual); strcpy(e,expected); memset(present,0,4*sizeof(*present));
    int ac=boot_policy_lines(a,al,5),ec=boot_policy_lines(e,el,5);
    if(ac<1||ec<2||strcmp(al[0],el[0])) return -1;
    unsigned cursor=1;
    for(int i=1;i<ac;++i) {
        while(cursor<(unsigned)ec&&strcmp(al[i],el[cursor])) ++cursor;
        if(cursor==(unsigned)ec) return -1;
        present[cursor-1]=1; ++cursor;
    }
    return ec-1;
}
static inline int boot_policy_expected(const struct label_policy_names *names,unsigned kind,char *text,size_t capacity) {
    if(kind==0) return policy_expected_groups(names->group,composite_groups,COMPOSITE_ROLE_COUNT,text,capacity);
    if(kind==1||kind==2) return label_policy_expected(names,kind==1,text,capacity);
    return -1;
}
static inline int boot_policy_command(unsigned family,char *const *argv) {
    char ignored[1024];
    return policy_capture(family?"/usr/sbin/ip6tables":"/usr/sbin/iptables",argv,ignored,sizeof(ignored));
}
static inline int boot_policy_chain(unsigned family,const struct label_policy_names *names,unsigned kind) {
    char *program=family?"ip6tables":"iptables",*table=kind==1?"mangle":"filter";
    char *chain=(char*)(kind==0?names->group:kind==1?names->mark:names->deny);
    char actual[8192],expected[2048]; unsigned present[4];
    if(boot_policy_expected(names,kind,expected,sizeof(expected))<0) return -1;
    char *const read[]={program,"-t",table,"-S",chain,NULL};
    if(policy_capture(family?"/usr/sbin/ip6tables":"/usr/sbin/iptables",read,actual,sizeof(actual))) {
        char *const create[]={program,"-t",table,"-N",chain,NULL};
        if(boot_policy_command(family,create)||policy_capture(family?"/usr/sbin/ip6tables":"/usr/sbin/iptables",read,actual,sizeof(actual))) return -1;
    }
    int count=boot_policy_subset(actual,expected,present);
    if(count<1) return -1;
    for(int i=0;i<count;++i) {
        if(present[i]) continue;
        char position[12],group[16]; snprintf(position,sizeof(position),"%u",(unsigned)i+1);
        if(kind==2) {
            char *const rule[]={program,"-t",table,"-I",chain,position,"-m","connmark","--mark",ROLE_LABEL_MARK,"-j","DROP",NULL};
            if(boot_policy_command(family,rule)) return -1;
        } else {
            snprintf(group,sizeof(group),"%u",composite_groups[i]);
            char *const drop[]={program,"-t",table,"-I",chain,position,"-m","owner","--gid-owner",group,"-j","DROP",NULL};
            char *const mark[]={program,"-t",table,"-I",chain,position,"-m","owner","--gid-owner",group,"-j","CONNMARK","--set-xmark",ROLE_LABEL_MARK,NULL};
            if(boot_policy_command(family,kind==1?mark:drop)) return -1;
        }
    }
    return policy_capture(family?"/usr/sbin/ip6tables":"/usr/sbin/iptables",read,actual,sizeof(actual))||strcmp(actual,expected)?-1:0;
}
/* Owned hooks must form an ordered prefix, possibly incomplete after a crash.
 * Never move/delete a hook across an unrelated rule to hide policy drift. */
static inline int boot_policy_hook_subset(const char *rules,const char *hook,const char *const targets[],unsigned count,unsigned present[2]) {
    if(!rules||!hook||!targets||!count||count>2||!strlen(rules)||strlen(rules)>=8192||
        rules[strlen(rules)-1]!='\n'||strstr(rules,"\n\n")) return -1;
    char copy[8192],prefix[64]; strcpy(copy,rules); snprintf(prefix,sizeof(prefix),"-P %s ",hook);
    char *save=NULL,*line=strtok_r(copy,"\n",&save);
    if(!line||strncmp(line,prefix,strlen(prefix))) return -1;
    memset(present,0,2*sizeof(*present)); int unrelated=0,last=-1;
    while((line=strtok_r(NULL,"\n",&save))) {
        int match=-1;
        for(unsigned i=0;i<count;++i) {
            char expected[128]; snprintf(expected,sizeof(expected),"-A %s -j %s",hook,targets[i]);
            if(!strcmp(line,expected)) match=(int)i;
            else if(strstr(line,targets[i])) return -1;
        }
        if(match<0) { unrelated=1; continue; }
        if(unrelated||match<=last||present[match]) return -1;
        present[match]=1; last=match;
    }
    return 0;
}
static inline int boot_policy_hook(unsigned family,const struct label_policy_names *names,unsigned kind) {
    char *program=family?"ip6tables":"iptables",*table=kind==0?"mangle":"filter",*hook=kind==2?"INPUT":"OUTPUT";
    const char *targets[2]={kind==0?names->mark:kind==1?names->group:names->deny,names->deny};
    unsigned count=kind==1?2:1,present[2]; char actual[8192];
    char *const read[]={program,"-t",table,"-S",hook,NULL};
    if(policy_capture(family?"/usr/sbin/ip6tables":"/usr/sbin/iptables",read,actual,sizeof(actual))||
        boot_policy_hook_subset(actual,hook,targets,count,present)) return -1;
    for(unsigned i=0;i<count;++i) if(!present[i]) {
        char position[8]; snprintf(position,sizeof(position),"%u",i+1);
        char *const insert[]={program,"-t",table,"-I",hook,position,"-j",(char*)targets[i],NULL};
        if(boot_policy_command(family,insert)) return -1;
    }
    return 0;
}
static inline int boot_policy_foreign_writers(const struct label_policy_names *names,int fresh) {
    for(unsigned family=0;family<2;++family) {
        char output[65536],expected[2048];
        char *const args[]={family?"ip6tables-save":"iptables-save",NULL};
        if(policy_capture(family?"/usr/sbin/ip6tables-save":"/usr/sbin/iptables-save",args,output,sizeof(output))||
            label_policy_expected(names,1,expected,sizeof(expected))<0) return -1;
        char *save=NULL; int mangle=0;
        for(char *line=strtok_r(output,"\n",&save);line;line=strtok_r(NULL,"\n",&save)) {
            if(line[0]=='*') mangle=!strcmp(line,"*mangle");
            if(fresh&&(strstr(line,names->group)||strstr(line,names->mark)||strstr(line,names->deny))) return -1;
            if(!strstr(line,"CONNMARK")) continue;
            if(fresh||!mangle) return -1;
            char candidate[2048]; int size=snprintf(candidate,sizeof(candidate),"%s\n",line);
            if(size<0||(size_t)size>=sizeof(candidate)||!strstr(expected,candidate)) return -1;
        }
    }
    return 0;
}
static inline int boot_policy_unused_label(void) {
    FILE *file=fopen("/proc/net/nf_conntrack","r"); char line[4096]; unsigned rows=0; int ok=1;
    if(!file) return 0;
    while(fgets(line,sizeof(line),file)) {
        if(++rows>65536||!strchr(line,'\n')) { ok=0; break; }
        char *mark=strstr(line," mark="),*end;
        if(!mark) { ok=0; break; }
        errno=0; unsigned long long value=strtoull(mark+6,&end,10);
        if(errno||end==mark+6||(*end!=' '&&*end!='\n')||value>UINT32_MAX||(value&0x40000000u)) { ok=0; break; }
    }
    if(ferror(file)) ok=0;
    fclose(file); return ok;
}
static inline int boot_policy_install(const char *chain) {
    struct label_policy_names names;
    if(label_policy_names(chain,&names)||boot_policy_foreign_writers(&names,0)) return -1;
    for(unsigned family=0;family<2;++family) {
        for(unsigned kind=0;kind<3;++kind) if(boot_policy_chain(family,&names,kind)) return -1;
        for(unsigned kind=0;kind<3;++kind) if(boot_policy_hook(family,&names,kind)) return -1;
    }
    return label_policy_verified(chain)&&!boot_policy_foreign_writers(&names,0)?0:-1;
}
#endif
