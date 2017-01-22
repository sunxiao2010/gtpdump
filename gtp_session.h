/*
 *   BSD LICENSE
 *
 *   Copyright(c) sunxiao. All rights reserved.
 *   sunx17@chinaunicom.cn
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

#ifndef  GTP_SESSION_H
#define  GTP_SESSION_H

#include <pcap.h>
#include <stdio.h>
#include "opt.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct gtpdump_cared {
    char  port;
    char  v1,v2,seq_flag,teid_flag;
    char *seq,*teid;
    char  planned[256];
    char  disabled[256];
    char  filters[256];
    char* iev1[256];
    char* iev2[256];
} gtpdump_cared_t;

/*packet available and packet filter */
#define PA(pcared,ptype) (((gtpdump_cared_t*)pcared)->planned[ptype]>0)
#define PF(pcared,ptype) (((gtpdump_cared_t*)pcared)->filters[ptype]>0)

void gtp_packet_process(unsigned char *str, const struct pcap_pkthdr *p_pkthdr, const unsigned char *p_packet);
#ifdef __cplusplus
}
#endif

#endif
