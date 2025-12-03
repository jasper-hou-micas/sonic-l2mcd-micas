#ifndef _MLD_STRUCT_
#define _MLD_STRUCT_

#include "l2mcd_data_struct.h"

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

typedef struct ICMP6_PSEUDO_HDR
{
    UINT8   type;
    UINT8   code;       // 0 for send
    UINT16  checksum;
} ICMP6_PSEUDO_HDR_MESSAGE;

void mld_enable(VRF_INDEX vrf_index, UINT8 protocol);
BOOLEAN mcgrp_initialize_port_db_array(UINT32 afi);
#endif /*MLD_STRUCT*/