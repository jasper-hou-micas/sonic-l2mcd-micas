/*
 * Copyright 2019 Broadcom.  The term “Broadcom�?refers to Broadcom Inc. and/or
 * its subsidiaries.

 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef _MLD_STRUCT_
#define _MLD_STRUCT_

#include "l2mcd_data_struct.h"
// #include "l2mcd_portdb.h"
// #include "l2mcd_mld_port.h"
// #include "l2mcd.h"
// #include "l2mcd_mcast_co.h"

// IPv6 Header (Fixed 40 Bytes)
typedef struct IPV6_HEADER
{
    // Version (4), Traffic Class (8), Flow Label (20) -> Total 32 bits
    // Using a union/struct combo to handle bitfields across byte boundaries is common,
    // but strictly following your style:
#if __BYTE_ORDER != __BIG_ENDIAN
    UINT32          flow_label : 20;
    UINT32          traffic_class : 8;
    UINT32          version : 4;
#else
    UINT32          version : 4;
    UINT32          traffic_class : 8;
    UINT32          flow_label : 20;
#endif

    UINT16          payload_length;
    UINT8           next_header;       // Protocol (e.g., 0 for Hop-by-Hop, 58 for ICMPv6)
    UINT8           hop_limit;
    IPV6_ADDRESS    source_ip_address;
    IPV6_ADDRESS    destination_ip_address;
} IPV6_HEADER;

// IPv6 Hop-by-Hop Options Header
// MLD packets usually carry this immediately after the IPv6 Header
typedef struct IPV6_HBH_HEADER
{
    UINT8       next_header;    // Usually 58 (ICMPv6) if MLD follows immediately
    UINT8       hdr_ext_len;    // Length of this header in 8-octet units, not including the first 8 octets
} IPV6_HBH_HEADER;

// Router Alert Option (RFC 2711)
// Format: Type(8) | Len(8) | Value(16)
// It must be 8-byte aligned inside the HBH header, so PadN options might be needed usually.
// This struct represents the specific Option payload.
typedef struct IPV6_ROUTER_ALERT_OPTION
{
    UINT8       type;           // 0x05 for Router Alert
    UINT8       length;         // 2
    UINT16      value;          // 0 for MLD
} IPV6_ROUTER_ALERT_OPTION;

// A typical IPv6 HBH Header containing ONLY Router Alert and necessary Padding (PadN)
// to align to 8 bytes.
// Total HBH length = 2 (header) + 4 (Router Alert) + 2 (PadN) = 8 bytes
typedef struct IPV6_HBH_ROUTER_ALERT_COMPLETE
{
    IPV6_HBH_HEADER hbh_header;
    IPV6_ROUTER_ALERT_OPTION rtr_alert;

    // PadN Option (to align to 8 bytes)
    UINT8       pad_type;       // 1 (PadN)
    UINT8       pad_len;        // 0 (Data length)
} IPV6_HBH_ROUTER_ALERT_COMPLETE;

// MLDv1 Query / Report / Done Message
// RFC 2710
typedef struct MLD_MESSAGE
{
    UINT8           type;
    UINT8           code;
    UINT16          checksum;
    UINT16          maximum_response_delay; // Note: 16 bits in MLD, vs 8 bits in IGMP
    UINT16          reserved;
    IPV6_ADDRESS    group_address;          // IPv6 Multicast Address
} MLD_MESSAGE;

// MLDv2 Query Message
// RFC 3810
typedef struct MLDV2_MESSAGE
{
    UINT8       type;                   // 130 for Query
    UINT8       code;                   // 0 for send
    UINT16      checksum;
    UINT16      maximum_response_code;
    UINT16      reserved;
    IPV6_ADDRESS    group_address;

    // MLDv2 specific fields
    // Byte layout: | Resv(4) | S(1) | QRV(3) |
#if __BYTE_ORDER != __BIG_ENDIAN
    UINT8       querier_robustness_var : 3;
    UINT8       suppress_router_process : 1;
    UINT8       reserved_flags : 4;
#else
    UINT8       reserved_flags : 4;
    UINT8       suppress_router_process : 1;
    UINT8       querier_robustness_var : 3;
#endif

    UINT8       query_interval_code;
    UINT16      num_srcs;
    IPV6_ADDRESS    source_ary[1];          // Variable length: num_srcs
} MLDV2_MESSAGE;

// MLDv2 Group Record
typedef struct MLDV2_GROUP_RECORD
{
    UINT8       type;
    UINT8       aux_data_len;
    UINT16      num_srcs;
    IPV6_ADDRESS    group_address;
    IPV6_ADDRESS    source_address_ary[1];  // Variable length: num_srcs
} MLDV2_GROUP_RECORD;

// MLDv2 Report Message
typedef struct MLDV2_REPORT
{
    UINT8               type;           // 143 for Report
    UINT8               code;           // 0 for send
    UINT16              checksum;
    UINT16              reserved;
    UINT16              num_grps;
    MLDV2_GROUP_RECORD  group_record[1]; // Variable length: num_grps
} MLDV2_REPORT_MESSAGE;

// MLDv1 Packet (Query + Report + Leave)
typedef struct MLD_PACKET
{
    IPV6_HEADER                     ip_header;
    IPV6_HBH_ROUTER_ALERT_COMPLETE  hbh_options; // MLD requires Router Alert
    MLD_MESSAGE                     mld_message;
} MLD_PACKET;

// MLDv2 Query Packet
typedef struct MLDV2_PACKET
{
    IPV6_HEADER                     ip_header;
    IPV6_HBH_ROUTER_ALERT_COMPLETE  hbh_options;
    MLDV2_MESSAGE                   mld_message;
} MLDV2_PACKET;

// MLDv2 Report Packet (Group Packet)
typedef struct MLDV2_GROUP_PACKET
{
    IPV6_HEADER                     ip_header;
    IPV6_HBH_ROUTER_ALERT_COMPLETE  hbh_options;
    MLDV2_REPORT_MESSAGE            mld_report;
} MLDV2_GROUP_PACKET;


 #if 0
typedef struct MLD_MESSGAGE{
    UINT8   type;
    UINT8   max_resp_time;
    UINT16  checksum;
    MADDR_ST  group_address;
}MLD_MESSAGE;

typedef struct MLD_PAKCET {
    // IPv6 ͷ
    struct ipv6_hdr_fixed {
        uint32_t ver_tc_fl;
        uint16_t payload_len;
        uint8_t  next_header;
        uint8_t  hop_limit;
        uint8_t  src[16];
        uint8_t  dst[16];
    } ip6;

    // Hop-by-Hop Header(��ѡ)�����ȸ��� hbh_len ����
    uint8_t *hbh_start;
    uint16_t hbh_len;

    // ICMPv6 ����ͷ������ MLDv1/v2 ���У�
    struct {
        uint8_t  type;      // 130/131/132/143
        uint8_t  code;      // always 0
        uint16_t checksum;
    } icmp6;
    
    MLD_MESSAGE mld_msg;
} MLD_PAKCET;

struct MLDV1_QUERY {
	UINT8	type;
	UINT8	max_resp_time;
	UINT16	checksum;
	MADDR_ST group_address;
} __attribute__((packed));

struct MLDV1_REPORT_DONE {
    uint16_t max_delay;  // always 0
    uint16_t reserved;
    MADDR_ST group_address;
} __attribute__((packed));

struct MLDV2_REPORT_HDR {
    uint16_t reserved;
    uint16_t num_records;
    MADDR_ST group_address;
    MADDR_ST records[];     // variable
} __attribute__((packed));

// MLD Query Message
typedef struct MLD_QRY_MESSAGE
{
	UINT8	type;
	UINT8	max_resp_time;
	UINT16	checksum;
	MADDR_ST group_address;

	UINT8	reserved                : 4;
	UINT8	suppress_router_process : 1;
	UINT8	robustness_var          : 3;       // querier's robustness variable

	UINT8	query_interval_code;               // querier's interval code
	UINT16	num_srcs;
	UINT32	source_ary[1];         // num_srcs number

} MLD_QRY_MESSAGE;

typedef struct MLDV2_GROUP_RECORD
{
    UINT8   type;             // Record Type: 1~6
    UINT8   aux_data_len;     // in 32bit words
    UINT16  num_srcs;         // number of source addresses
    MADDR_ST  group_address;     // IPv6 multicast address
    MADDR_ST  source_address_ary[1];  // placeholder for num_srcs*16 bytes
                                     // (each source is 16 bytes IPv6 addr)
} MLDV2_GROUP_RECORD;

typedef struct MLDV2_REPORT
{
    UINT8   type;            // 143
    UINT8   reserved_uint8;  // 0
    UINT16  checksum;
    UINT16  reserved_uint16; // 0
    UINT16  num_grps;        // number of group records

    MLDV2_GROUP_RECORD group_record[1]; // num_grps records (variable)
} MLDV2_REPORT;
#endif 




void mld_enable (VRF_INDEX  vrf_index, UINT8      protocol);
BOOLEAN mcgrp_initialize_port_db_array(UINT32 afi);
#endif /*MLD_STRUCT*/