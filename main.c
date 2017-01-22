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


#include <stdio.h>
#include <stdlib.h>
#include <memory.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <linux/if_ether.h>
#include <pcap.h>
#include "conf.h"
#include "opt.h"
#include "gtp.h"
#include "gtp_session.h"

char* filter[2]={"port 2123","port 2152"};
char* default_dev    = "lo";
const int max_cap_len = 1514;

int count;
int m_socket;
struct sockaddr addr_to;

pcap_dumper_t* dump_handler;
extern unsigned char  _dev[];
extern gtpdump_cared_t _C;

pcap_t* pcap_init(gtpdump_cared_t *c)
{
    char errbuf[512];
    pcap_t *handle;
    bpf_u_int32 network, netmask;
    struct bpf_program fcode;

    if (_dev == NULL) {
        return NULL;
    }

    if ((handle = pcap_open_live(_dev, 1514, 1, 0, errbuf)) == NULL){
        return NULL;
    }

    if ( pcap_setdirection( handle, PCAP_D_IN|PCAP_D_OUT ) == -1){
        return NULL;
    }

    if ( pcap_compile(handle, &fcode, filter[c->port], 1 /* optimize */, netmask) < 0) {
        return NULL;
    }

    if ( pcap_setfilter(handle, &fcode) == -1) {
        return NULL;
    }

    dump_handler = (pcap_dumper_t*)pcap_dump_open(handle,"./dump.pcap");

    return handle;
}

int main(int argc, char** argv)
{
    int file;
    int ret;
    
    short int on = 1;
    //pseudohdr_t psdhdr;
    char pspacket[2048];
    if( (m_socket = socket(AF_INET, SOCK_PACKET, ETH_P_IP)) < 0 )
    {
        return -1;
    }
    memset(&addr_to, 0, sizeof addr_to);
    //strcpy(addr_to.sa_data,fwd_dev);
    addr_to.sa_family = AF_PACKET;

    _P("started");

    conf_node_t *conf=NULL;
    read_options(argc,argv,&conf);

    gtpfilter_init(&_C,conf);

    pcap_t* pcap_i=pcap_init(&_C);

    if(!pcap_i){ _P("pcap init failed"); exit(0);}

    ret = pcap_loop(pcap_i, -1, gtp_packet_process, NULL);
}
