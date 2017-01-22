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

#include "gtp.h"
#include "conf.h"
#include "gtp_session.h"
#include <stdio.h>
#include <stdlib.h>
#include <memory.h>
#include <netinet/in.h>

#define USER_ONLINE     1
#define USER_OFFLINE    2
#define USER_UPDATE     3
#define USER_ONLINE_REQ          4
#define USER_GTPV2_ONLINE      0x11
#define USER_GTPV2_OFFLINE     0x12
#define USER_GTPV2_REQ           0x1a
#define USER_GTPV2_RES           0x1b
#define USER_GTPV2_UPD           0x13
#define USER_GTPV2_UPD_REQ   0x1c
#define USER_GTPV2_UPD_RES   0x1d

#define PUT_GTPV2_CI(ui, eci)  do {\
    ((gtp_user_info_t*)(ui))->ci = eci & 0xffff; \
    ((gtp_user_info_t*)(ui))->ecih = (eci>>16) & 0xffff; \
}while(0);

gtpdump_cared_t _C;

#ifdef GTPDUMP_DEBUG
int compare(char* a,char* b,int c){
    return memcmp(a,b,c);
}
#endif

int gtpv2_body_filter(unsigned char *hdr,int to_match)
{
    unsigned char type;
    short belen,len,gtp_len;
    int cmp;
    if(to_match==0) return 1; //no problem
    
    gtpv2hdr_t* h=(gtpv2hdr_t*)hdr;
    unsigned char *ie_start=hdr+sizeof(gtpv2hdr_t);
    unsigned char *p=ie_start;

    gtp_len = htons(h->length);
    while( p - ie_start < gtp_len - 8 ){
        type = *p;
        p += 1; //type offset
        memcpy(&belen, p, sizeof(belen));
        len = ntohs(belen);
        p += (sizeof(belen) + 1);

        if(_C.iev2[type]){
#ifdef GTPDUMP_DEBUG
            cmp = compare(p,_C.iev2[type]+1,_C.iev2[type][0]);
#else
            cmp = memcmp(p,_C.iev2[type]+1,_C.iev2[type][0]);
#endif
            if(cmp==0 
               // && len==_C.iev2[type][0]
                ) {
                if(--to_match==0) return 2; //all match
            }
            else return 0; //not match
        }
        p += len;
    }

    return 0; //not match
}

