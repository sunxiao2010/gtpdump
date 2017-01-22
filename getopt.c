/*
 *   BSD LICENSE
 *
 *   Copyright(c) Unisk. All rights reserved.
 *   Copyright(c) Chinaunicom. All rights reserved.
 *
 *   Redistribution and use in source and binary forms, with or without
 *   modification, are permitted provided that the following conditions
 *   are met:
 *
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in
 *       the documentation and/or other materials provided with the
 *       distribution.
 *     * Neither the name of Intel Corporation nor the names of its
 *       contributors may be used to endorse or promote products derived
 *       from this software without specific prior written permission.
 *
 *   THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 *   "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 *   LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 *   A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 *   OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 *   SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 *   LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 *   DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 *   THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 *   (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 *   OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */


#include <string.h>
#include <stdio.h>
#include <memory.h>
#include <stdlib.h>
#include "conf.h"
#include "gtp.h"
#include "gtp_session.h"

#include "opt.h"

#define tolower(c)  ((char)((c >= 'A' && c <= 'Z') ? (c | 0x20) : c))
#define toupper(c)  ((char)((c >= 'a' && c <= 'z') ? (c & ~0x20) : c))
#define SKIP_BLANK(x) do{ \
    while(*x==' ') x++; \
}while(0)
#define UNTIL_BLANK(x) do{ \
    while(*x!=' '&&*x!=0) x++; \
}while(0)

int string_to_hex(unsigned char* name,unsigned char* start /*memory*/,int* outlen)
{
    unsigned char ch,cl;
    int count = 0;
    while (ch=*(name++), ch!=' '&&ch!=0 )
    {
        if(ch>0x7a) goto end;
        cl=*(name++);
        if(cl==0x7a) goto end;
        if(ch<0x40)
        {
            ch=ch-'0';
            goto next;
        }
        if(ch>0x39)
        {
            ch=tolower(ch)-0x61+0xa;
        }
next:
        if(cl<0x40)
        {
            cl=cl-'0';
            goto next1;
        }
        if(cl>0x39)
        {
            cl=tolower(cl)-0x61+0xa;
        }
next1:
        *start=(ch<<4) + cl;
        start ++;
        count ++;
    }
end:
    *outlen=count;
    return 0;
}

void to_real_hex(unsigned char* src, int slen, unsigned char* dst, int *dlen){
    int l=0;
    for(;l<slen;l++){
        dst[l]=(src[2*l]<<4)+src[2*l+1];
    }
    *dlen=l;
    dst[l]=0;
}
void revert_hex(unsigned char* v, int len){
    while(--len>=0){
        v[len]=(v[len]>>4) |(v[len]<<4);
    }
}
void print_hex(unsigned char *v, int len){
    int i=0;
    _PP(" -->");
    while(i<len){
        _PP("%.2x",v[i]);
        i++;
    }
    _P("\n");
}

void segment_assign(char* dest, char* source){
    strncpy(dest,source,strlen(source)>32?32:strlen(source));
}

void capture_enable_all(char planned[]){
    planned[GTP_CREATE_REQUEST]=1;
    planned[GTP_CREATE_RESPONSE]=1;
    planned[GTP_UPDATE_REQUEST]=1;
    planned[GTP_UPDATE_RESPONSE]=1;
    planned[GTP_DELETE_REQUEST]=1;
    planned[GTP_DELETE_RESPONSE]=1;
    planned[GTP_V2_CREATE_REQ]=1;
    planned[GTP_V2_CREATE_RES]=1;
    planned[GTP_V2_MODIFY_REQ]=1;
    planned[GTP_V2_MODIFY_RES]=1;
    planned[GTP_V2_DELETE_REQ]=1;
    planned[GTP_V2_DELETE_RES]=1;
}

static unsigned int _seq,_teid,_ip,_msisdn;
static unsigned long long _imei,_imsi;
static unsigned char _v=1,_port=port_c;
unsigned char _dev[32];
static unsigned char tmp[32];

int read_options(int args,char **argv,conf_node_t **mc) {
    if(args<1) {return NOT_CORRECT_ARG;}
    conf_node_t *conf;

    if(!*mc) {*mc=conf=(conf_node_t*)malloc(sizeof(conf_node_t)*64);}
    else {conf=*mc;}

    int index=0,outlen=0;
    char* p,*q, *str;
    char s=s_command;
    p = *(++argv);

    while(p){
        SKIP_BLANK(p);
        if(!*p) { p = *(++argv); continue; }
        if(s!=s_command) { goto VAL; }

        switch(*p) {
        case '-':
            p++;
            if(*p=='i'){
                p++;
                SKIP_BLANK(p);
                s=s_device;
            }
            else {return NOT_SUPPORTED;}
            break;
        case 't':
            if(!strncmp(p,"teid",4)){
                p+=4;
                SKIP_BLANK(p);
                conf[index].cmd=s_teid;
                s=s_hex;
            }
            break;
        case 's':
            if(!strncmp(p,"seq",3)){
                p+=3;
                SKIP_BLANK(p);
                conf[index].cmd=s_seq;
                s=s_hex;
            }
            break;
        case 'i':
            if(!strncasecmp(p,"imei",4)){
                p+=4;
                conf[index].cmd=s_imei;
                s=s_hexstring;
                break;
            }
            else if(!strncmp(p,"imsi",4)){
                p+=4;
                conf[index].cmd=s_imsi;
                s=s_hexstring;
                break;
            }
            else if(!strncmp(p,"ip",2)){
                p+=2;
                conf[index].cmd=s_ip;
                s=s_dotteddecimal;
                break;
            }
            else {return NOT_SUPPORTED;}
            break;
        case 'c': case 'C': case 'u': case 'U':
            tmp[0]=tolower(*p);
            if(tmp[0]=='c') {_port=port_c;}
            else if(tmp[0]=='u') {_port=port_u;}
            p+=1;
            SKIP_BLANK(p);
            break;
        case 'm':
            if(!strncmp(p,"msisdn",6)){
                p+=6;
                s=s_hexstring;
                conf[index].cmd=s_msisdn;
            }
            break;
        case 'v':
            _v=p[1];
            if(_v!='1'&&_v!='2') {return NOT_SUPPORTED;}
            _v-='1';
            p+=2;
            SKIP_BLANK(p);
            break;
        case 0: default:
            p=*(argv++);
            break;
        } //switch(*p)
        continue;
VAL:
        switch(s) { 
        case s_device:
            q=p;
            UNTIL_BLANK(q);
            memcpy(_dev,p,q-p);
            p=q;
            s=s_command;
            break;
        case s_long:
            conf[index++].val.ll=atol(p);
            UNTIL_BLANK(p);
            s=s_command;
            break;
        case s_longlong:
            conf[index++].val.ll=atoll(p);
            UNTIL_BLANK(p);
            s=s_command;
            break;
        case s_dotteddecimal:
            conf[index++].val.l=inet_addr(p);
            UNTIL_BLANK(p);
            s=s_command;
            break;
        case s_hex:
            q=p;
            UNTIL_BLANK(q);
            memcpy(&tmp,p,(size_t)(q-p));
            str=(char*)malloc(DEFALUT_STR_LEN);
            conf[index].val.ptr=(void*)str;
            string_to_hex(tmp, str+1, &outlen);
            _PP("read command type [%d], val ptr [%p]",conf[index].cmd,conf[index].val.ptr);
            print_hex(str+1, outlen);
            str[0]=outlen;

            p=q;
            s=s_command;
            index++;
            break;
        case s_hexstring:
            q=p;
            UNTIL_BLANK(q);

            memcpy(&tmp,p,(size_t)(q-p));
            if((q-p)%2==0){
                tmp[q-p]=0;
            }else {
                tmp[q-p]='f'; tmp[q-p+1]=0;
            }

            str=(char*)malloc(DEFALUT_STR_LEN);
            conf[index].val.ptr=(void*)str;
            string_to_hex(tmp, str+1, &outlen);
            revert_hex(str+1, outlen);
            _PP("read command type [%d], val ptr [%p]",conf[index].cmd,conf[index].val.ptr);
            print_hex(str+1, outlen);
            str[0]=outlen;
            
            p=q;
            s=s_command;
            index++;
            break;
        //case s_longstring:
        default:
            return NOT_SUPPORTED;
        }
    } //while
}

int gtpfilter_init(gtpdump_cared_t *c, conf_node_t *conf){

    memset(c,0,sizeof(gtpdump_cared_t));
    char *p,*q;
    int len;

    //default
    if(_v==1) { c->v2=1;}
    else if(_v==0) { c->v1=0;}

    c->port=_port;
    
    int i=0, j;
    for(;conf[i].cmd;i++) {
        p=conf[i].val.ptr;
        //printf("type [%d], val [%lld]\n",conf[i].cmd,conf[i].val.ll);
        switch(conf[i].cmd) {
        case 0:
            break;
        case s_teid:
            c->teid_flag=1;
            c->teid=p;
            capture_enable_all(c->planned);
            break;
        case s_seq:
            c->seq_flag=1;
            c->seq=p;
            capture_enable_all(c->planned);
            break;
        case s_ip:
            break;
        case s_imsi:
            c->iev1[GTP_TYPE_IMSI]=p;
            c->iev2[GTP_V2_TYPE_IMSI]=p;

            c->filters[GTP_CREATE_REQUEST]+=1;
            c->filters[GTP_V2_CREATE_REQ]+=1;

            c->planned[GTP_CREATE_REQUEST]=1;
            c->planned[GTP_CREATE_RESPONSE]=1;
            c->planned[GTP_V2_CREATE_REQ]=1;
            c->planned[GTP_V2_CREATE_RES]=1;

            break;
        case s_imei:
            c->iev1[GTP_TYPE_IMEI]=p;
            c->iev2[GTP_V2_TYPE_MEI]=p;

            c->filters[GTP_CREATE_REQUEST]+=1;
            c->filters[GTP_V2_CREATE_REQ]+=1;
            
            c->planned[GTP_CREATE_REQUEST]=1;
            c->planned[GTP_CREATE_RESPONSE]=1;
            c->planned[GTP_V2_CREATE_REQ]=1;
            c->planned[GTP_V2_CREATE_RES]=1;
            
            break;
        case s_msisdn:

            c->iev1[GTP_TYPE_MSISDN]=p;
            c->iev2[GTP_V2_TYPE_MSISDN]=p;
            
            c->filters[GTP_CREATE_REQUEST]+=1;
            c->filters[GTP_V2_CREATE_REQ]+=1;
            
            c->planned[GTP_CREATE_REQUEST]=1;
            c->planned[GTP_CREATE_RESPONSE]=1;
            c->planned[GTP_V2_CREATE_REQ]=1;
            c->planned[GTP_V2_CREATE_RES]=1;
            break;
        }
    }

    _P("inited");
}

