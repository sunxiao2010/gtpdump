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

extern "C" {
#include "gtp.h"
#include <stdio.h>
}
#include "gtp_session.h"
#include "conf.h"
#include <pcap.h>
#include <stdio.h>
#define __FAVOR_BSD
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <stddef.h>
#include <cstring>
#include <hash_map>
#include <string>
#include <ext/hash_map>
using namespace __gnu_cxx;

//gtpv1 create pdp holder
hash_map<uint16_t, gtp_user_info_t>  sn_hash;
//gtpv2 create session holder
hash_map<uint32_t, gtp_user_info_t>  sn_hash32;
//gtpv2 update & modify holder
hash_map<uint32_t, gtp_user_info_t>  sn_hash_update;

hash_map<uint32_t, gtp_packet_t>  gtpv2_transaction_hash;
gtp_packet_t request_packet;


hash_map<uint16_t, gtp_packet_t>::iterator element;
hash_map<uint32_t, gtp_packet_t>::iterator element32;

extern gtpdump_cared_t _C;
extern "C" pcap_dumper_t* dump_handler;


void gtp_packet_process(u_char *str, const struct pcap_pkthdr *p_pkthdr, const u_char *p_packet)
{
    unsigned char *p = const_cast<unsigned char*>(p_packet);
    uint32_t packet_len = p_pkthdr->len;
    int ret = 0,cmp=0;

    //L2 offset
    p += 14;
    //cut off L3-L4 header
    struct iphdr *p_iphdr = (struct iphdr *)(p);
    uint32_t ip_len = p_iphdr->ihl * 4;
    uint32_t total_len = ntohs(p_iphdr->tot_len);

    if (total_len > packet_len) {
        _P("total_len: %u > packet_len: %u", total_len, packet_len);
        return;
    }

    if (p_iphdr->protocol != IPPROTO_UDP) {
        _P("protocol is not UDP!");
        return;
    }

    struct udphdr *p_udphdr = (struct udphdr *)(p + ip_len);
    uint32_t udp_len = ntohs(p_udphdr->uh_ulen);
    p += ip_len;

    if (total_len != ip_len + udp_len) {
        _P("The packet is wrong packet format, %u != %u + %u",
            total_len, ip_len, udp_len);
        return;
    }

    //cut off gtp header
    gtphdr_t *p_gtphdr = (gtphdr_t *)(p + sizeof(struct udphdr));
    gtpchdr_t *p_gtpchdr = (gtpchdr_t *)(p + sizeof(struct udphdr));
    uint32_t gtp_len = ntohs(p_gtphdr->length);

    uint16_t sn = 0;
    uint32_t sn32 = 0;

    size_t ret_size;

    if (gtp_len!= udp_len - sizeof(struct udphdr)  - offsetof(gtpchdr_t,teid)) {return;}

    if(!PA(&_C,p_gtpchdr->msg_type)) return;

    if(_C.seq_flag) {
        ret = memcmp(&p_gtpchdr->seq,_C.seq+1,_C.seq[0]);
        if(ret!=0) { return; }
    }

    if(_C.v2 && p_gtpchdr->flags == GTP_VERSION_2)
    {
        //_P("gtpc - gtpv2 process");

        if(PF(&_C,p_gtpchdr->msg_type)) {

            ret = gtpv2_body_filter((unsigned char*)p_gtpchdr,_C.planned[p_gtpchdr->msg_type]);

            if(!ret){
                //gtpv2_transaction_hash.erase(sn32);
                return ;
            }
        }

        sn32 = p_gtpchdr->seq;

        switch (p_gtpchdr->msg_type){
        case GTP_V2_CREATE_REQ:

            gettimeofday(&request_packet.tv,NULL);
            request_packet.user = str;
            memcpy(&request_packet.h,p_pkthdr,sizeof(request_packet.h));
            request_packet.packet = p_packet;
            request_packet.teid = p_gtpchdr->teid;

            gtpv2_transaction_hash.erase(sn32);
            gtpv2_transaction_hash.insert(std::pair<uint32_t, gtp_packet_t>(sn32, request_packet));

            break;

        case GTP_V2_CREATE_RES:

            element32 = gtpv2_transaction_hash.find(sn32);
            if (element32 != gtpv2_transaction_hash.end())
            {
                request_packet = element32->second;
                gtpv2_transaction_hash.erase(sn32);

                if(_C.teid_flag) {
                    ret = memcmp(&p_gtpchdr->teid,_C.teid+1,_C.teid[0]);
                    cmp = memcmp(&request_packet.teid,_C.teid+1,_C.teid[0]);
                    if(ret!=0 && cmp!=0) { return; }
                }

                _P(" found v2 request");
                //record_packets
                pcap_dump((unsigned char*)dump_handler,&request_packet.h,request_packet.packet);
                pcap_dump((unsigned char*)dump_handler,p_pkthdr,p_packet);
                pcap_dump_flush(dump_handler);
            }
            else {
#ifdef GTPDUMP_DEBUG
                _P("not found in v2 request");
#endif
            }
            break;

        default:
            break;
        }
    }

    return ;
}

