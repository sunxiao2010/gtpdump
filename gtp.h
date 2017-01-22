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

#ifndef GTP_H
#define GTP_H

#include <stdint.h>
#include <sys/time.h>
#include <pcap.h>

#define GTP_IMSI_ARRAY_SIZE            8
#define GTP_PHONE_ARRAY_SIZE           7
#define IP_MAX_LEN        (32)
#define APN_MAX_LEN     (24)
#define IMSI_MAX_LEN     (32)
#define IMEI_MAX_LEN     (32)
#define NAME_MAX_LEN    (40)
#define TEID_MAX_LEN    (8+1)

//v2 header interface /  2015-11-16
#define GTP_VERSION_1                  0x32
#define GTP_VERSION_2                  0x48

//gtp v1
#define GTP_ECHO_REQUEST            0x01
#define GTP_ECHO_RESPONSE           0x02
#define GTP_CREATE_REQUEST          0x10
#define GTP_CREATE_RESPONSE         0x11
#define GTP_UPDATE_REQUEST          0x12
#define GTP_UPDATE_RESPONSE         0x13
#define GTP_DELETE_REQUEST          0x14
#define GTP_DELETE_RESPONSE         0x15

#define GTP_V2_CREATE_REQ           0x20
#define GTP_V2_CREATE_RES           0x21
#define GTP_V2_MODIFY_REQ           0x22
#define GTP_V2_MODIFY_RES           0x23
#define GTP_V2_DELETE_REQ           0x25
#define GTP_V2_DELETE_RES           0x25

//v2 req options
#define GTP_OPTION_EXPAND_FLAG                  0x01
#define GTP_OPTION_SEQUENCE_NUMBER_FLAG         0x02
#define GTP_OPTION_PNSE_FLAG                    0x07

#define GTP_CAUSE_ACCEPTED          0x80
#define GTP_RESPONSE_OFFSET         10
#define GTP_RESPONSE_IP_OFFSET      5
#define GTP_RESPONSE_IP_LEN         4

#define GTP_ROUTING_AREA_IDENTITY_OFFSET    7
#define GTP_RECOVERY_OFFSET                 2
#define GTP_SELECTION_MODE_OFFSET           2 
#define GTP_TEID_DATA_OFFSET                5
#define GTP_NSAPI_OFFSET                    2
#define GTP_CHARGING_OFFSET                 3

#define GTP_TYPE_CAUSE                  0x01
#define GTP_TYPE_IMSI                   0x02
#define GTP_TYPE_ROUTING_AREA_IDENTITY  0x03
#define GTP_TYPE_RECOVERY               0x0e
#define GTP_TYPE_SELECTION_MODE         0x0f
#define GTP_TYPE_TEID_DATA              0x10
#define GTP_TYPE_TEID_CONTROL           0x11
#define GTP_TYPE_CHARGING               0x1a
#define GTP_TYPE_END_USER_ADDR          0x80
#define GTP_TYPE_APN                    0x83
#define GTP_TYPE_PROTOCOL_CONFIG        0x84
#define GTP_TYPE_GSN                    0x85
#define GTP_TYPE_MSISDN                 0x86
#define GTP_TYPE_QOS                    0x87
#define GTP_TYPE_COMMON_FLAGS           0x94
#define GTP_TYPE_RAT_TYPE               0x97
#define GTP_TYPE_USER_LOCATION          0x98
#define GTP_TYPE_MS_TIME_ZONE           0x99
#define GTP_TYPE_IMEI                   0x9a
#define GTP_TYPE_DIRECT_TUNNEL_FLAGS    0xb6

#define GTP_UL_TYPE_SIZE                8
#define GTP_UL_TYPE_GEO_LOC_TYPE_SIZE   1
#define GTP_UL_TYPE_MMC_SIZE            2
#define GTP_UL_TYPE_MNC_SIZE            1
#define GTP_UL_TYPE_CELL_LAC_SIZE       2
#define GTP_UL_TYPE_CELL_CI_SIZE        2

#define GTP_FLAG_EXT		0x04
#define GTP_FLAG_SEQ_NUM	0x02
#define GTP_FLAG_NPDU_NUM	0x01

#define GTP_V2_TYPE_IMSI                0x01
#define GTP_V2_TYPE_MSISDN           0x4c
#define GTP_V2_TYPE_MEI                 0x4b
#define GTP_V2_TYPE_ULI                 0x56
#define GTP_V2_TYPE_FTEID              0x57
#define GTP_V2_TYPE_BEARER          0x5d
#define GTP_V2_TYPE_APN                0x47
#define GTP_V2_TYPE_PDNTYPE         0x63
#define GTP_V2_TYPE_PAA                0x4f
#define GTP_V2_TYPE_IP                   0x4a

//v2 res options
#define GTP_V2_TYPE_CAUSE            0x02
#define GTP_V2_CAUSE_ACCEPTED     0x10
//v2 interface flag
#define GTP_V2_INTERFACE_C    0xa
#define GTP_V2_INTERFACE_7    0x7
#define GTP_V2_INTERFACE_10  0xa
#define GTP_V2_INTERFACE_11  0xb
#define GTP_V2_INTERFACE_S5U  0x4
#define GTP_V2_INTERFACE_S1U  0x1
#define GTP_V2_INTERFACE_TYPE(x) ((x) & 0x3f)

#define GTP_V2_IE_FLAG_OFFSET  1
#define GTP_V2_TEID_FLAG_OFFSET  1

typedef struct gtphdr_s
{
    uint8_t  flags;
    uint8_t  msg_type;
    uint16_t length;
    uint32_t teid;
} gtphdr_t;

typedef struct gtpv2hdr_s
{
    uint8_t  flags;
    uint8_t  msg_type;
    uint16_t length;
    uint32_t teid;
    uint32_t seq;
} gtpv2hdr_t;

typedef struct gtpchdr_s
{
    uint8_t  flags;
    uint8_t  msg_type;
    uint16_t length;
    uint32_t teid;
    uint32_t seq;
} gtpchdr_t;

typedef struct gtphdr_option_s
{
    uint16_t sn;
    uint8_t  n_pdu_number;
    uint8_t  next_extension_header_type;
} gtphdr_option_t;

typedef struct gtpv2_ie_uli_s
{
    uint8_t  flags;
    uint8_t  c1; //country_code
    uint8_t  c1_2;
    uint8_t  sp;   //service_provider
    uint16_t  ac; //area_code
    uint16_t  c2;
    uint8_t  sp2;
    uint8_t  eci[];//E-UTRAN cell identifier
} gtpv2_ie_uli_t;

typedef struct gtp_user_info_s
{
    uint32_t ip;
    uint8_t parsed:8;
    uint8_t gv:8;
    uint16_t lac;
    uint16_t ci;
    uint16_t ecih;
    uint32_t teid;
    uint64_t phone;    //imsi
    char     imei[IMEI_MAX_LEN];
    char     apn[APN_MAX_LEN];
    char     imsi[IMSI_MAX_LEN];
    char     name[NAME_MAX_LEN]; //adsl name, or phone
    char     static_end[0];
    uint32_t teid_d;
    uint8_t flag;
    unsigned char* data;
    unsigned char buffer[1024];
} gtp_user_info_t, *gtp_user_info_p;

typedef struct gtp_packet
{
    struct timeval tv;
    int pktlen;
    int teid;
    unsigned char *user;
    struct pcap_pkthdr h;
    const unsigned char *packet;
} gtp_packet_t;

int gtpv2_body_filter(unsigned char *hdr,int to_match);

#endif
