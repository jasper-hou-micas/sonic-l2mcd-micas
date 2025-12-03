/*
 * Copyright 2019 Broadcom.  The term “Broadcom” refers to Broadcom Inc. and/or
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
#include "l2mcd_portdb.h"
#include "mld_vlan_db.h"
#include "l2mcd.h"
#include <linux/if_packet.h>
#include <linux/if_ether.h>
#include <sys/socket.h>
#include <errno.h>


extern int l3_get_port_from_ifindex(int ifindex);
extern L2MCD_AVL_TREE *ve_mld_portdb_tree;
extern uint32_t hsl_sock_fd[MCAST_AFI_MAX];
#define HSL_ETHER_TYPE_IP                  0x0800
#define HSL_ETHER_TYPE_IPV6                0x86DD
#define AF_IGMP_SNOOP 51
#define AF_MLD_SNOOP 59

#define VLAN_HDR_LEN 4
#define ETH_ADDR_LEN 6

extern L2MCD_AVL_TREE *mld_portdb_tree;

int mld_ok_to_send_over_edge_port(ifindex_t source, ifindex_t destination)
{
	if(source == destination)
		return FALSE;
    else 
		return TRUE;
}

/* 	This function will prepare a IGMP report and send it over mrouter port. This is needed because
	we want to send the static IGMP report over mrouter ports.
	Parameters:
		grp_addr 	: Static group Ip address
		mld 		: instance class
		mld_vport	: Vlan Instance in IGMP
		rx_phy_port	: Port-Id of the port where static group is configured
		joinflag	: Boolean flag, TRUE: Join, FALSE: Leave
	Note: Currently, this function supports only IPV4.
*/
void mld_tx_static_report_leave_on_mrtr_port(MCGRP_CLASS  *mld, MADDR_ST *grp_addr, MCGRP_L3IF *mld_vport, 
											 uint32_t rx_phy_port, uint8_t joinflag)
{
	uint8_t 			afi 						= (IS_IGMP_CLASS(mld) ? MCAST_IPV4_AFI : MCAST_IPV6_AFI);
	ifindex_t 			source;
	uint32_t 			gvid 						= 0;
	uint32_t			src_addr 					= 0;
	IPV6_ADDRESS		src_addr6                   = IP6_ADDRESS_UNSPECIFIED_INIT;
	int 				port_id 					= 0;
	mld_vlan_node_t 	*vlan_node 					= NULL;

	if (mld_vport == NULL) {
		L2MCD_LOG_INFO("%s(%d) mld_vport is NULL. ", FN, LN);	
		return;
	}

	/*
	 * Note : Here tx_port_number is based out of vlan_id ifindex.
	 * If vlan has a Ve associated then, retrieve the Ve_port_id and
	 * see whether there is any IP address associated with this ve_port_id
	 * in mld_portdb_tree/ve_mld_portdb_tree.
	 * This is needed when Vlan and VE ID are different.
	 * When Vlan and VE are same id then, tx_port_number will be same.
	 */
	gvid = mld_get_vlan_id(mld_vport->vir_port_id);
	vlan_node = mld_vdb_vlan_get(gvid, mld_vport->type);
	if (vlan_node && vlan_node->ve_ifindex) 
	{
		if (afi == MCAST_IPV4_AFI)
		{
			port_link_list_t *sptr_addr_entry = NULL;
			if (l2mcd_ifindex_is_svi(vlan_node->ve_ifindex))
			{
				port_id = l3_get_port_from_ifindex(vlan_node->ve_ifindex);
				sptr_addr_entry = (port_link_list_t *)(portdb_get_port_lowest_ipv4_addr_from_list(ve_mld_portdb_tree, port_id));
				MLD_LOG(MLD_LOGLEVEL7, MLD_IP_IPV4_AFI, "%s(%d) rx_phy_port:0x%x ifindex:0x%x ve_ifindex:0x%x ",
						FN, LN, rx_phy_port, vlan_node->ifindex, vlan_node->ve_ifindex);
			}
			else
			{
				// Router Port IP address
				port_id = mld_vport->vir_port_id;
				sptr_addr_entry = (port_link_list_t *)(portdb_get_port_lowest_ipv4_addr_from_list(mld_portdb_tree, port_id));
				MLD_LOG(MLD_LOGLEVEL7, MLD_IP_IPV4_AFI, "%s(%d) rx_phy_port:0x%x Router ifindex:0x%x ",
						FN, LN, rx_phy_port, vlan_node->ifindex);
			}
			if (sptr_addr_entry)
			{
				uint32_t lowest_ip = sptr_addr_entry->value.ipaddress;

				for (port_link_list_t *addr_entry = sptr_addr_entry->next; addr_entry; addr_entry = addr_entry->next)
				{
					if (addr_entry->value.ipaddress < lowest_ip)
					{
						lowest_ip = addr_entry->value.ipaddress;
					}
				}
				src_addr = lowest_ip;
			}
		}
		else
		{
			PORTDB_IP6_ADDRESS_ENTRY *sptr_addr6_entry = NULL;
			if (l2mcd_ifindex_is_svi(vlan_node->ve_ifindex))
			{
				port_id = l3_get_port_from_ifindex(vlan_node->ve_ifindex);
				sptr_addr6_entry = (PORTDB_IP6_ADDRESS_ENTRY *)(portdb_get_port_lowest_ipv6_addr_from_list(ve_mld_portdb_tree, port_id));
				MLD_LOG(MLD_LOGLEVEL7, MLD_IP_IPV6_AFI, "%s(%d) rx_phy_port:0x%x ifindex:0x%x ve_ifindex:0x%x ",
						FN, LN, rx_phy_port, vlan_node->ifindex, vlan_node->ve_ifindex);
			}
			else
			{
				// Router Port IP address
				port_id = mld_vport->vir_port_id;
				sptr_addr6_entry = (PORTDB_IP6_ADDRESS_ENTRY *)(portdb_get_port_lowest_ipv6_addr_from_list(mld_portdb_tree, port_id));
				MLD_LOG(MLD_LOGLEVEL7, MLD_IP_IPV6_AFI, "%s(%d) rx_phy_port:0x%x Router ifindex:0x%x ",
						FN, LN, rx_phy_port, vlan_node->ifindex);
			}
			if (sptr_addr6_entry)
			{
				src_addr6 = sptr_addr6_entry->ipaddress;
			}
		}
	}


	source = rx_phy_port;
	if(MCAST_IPV4_AFI == afi && is_mld_snooping_enabled(mld_vport, afi)) 
	{
		/* This function should take care of sending to all mrouter ports
		 */
		igmp_send_igmp_message(mld, mld_vport->vir_port_id,
					source, //mcgrp_rport->phy_port_id,
					joinflag ? IGMP_V2_MEMBERSHIP_REPORT_TYPE : IGMP_V2_LEAVE_GROUP_TYPE,
					(UINT8) mld_vport->oper_version,
					grp_addr->ip.v4addr,   // Group Address
					src_addr, // Source Address of the packet 
					0, // 0 means use default response time
					NULL, FALSE,       // no srcs
					FALSE); // not retx
	}

	if(MCAST_IPV6_AFI == afi && is_mld_snooping_enabled(mld_vport, afi)) 
	{
		/* This function should take care of sending to all mrouter ports
		 */
		mld_send_mld_message(mld, mld_vport->vir_port_id,
					source, //mcgrp_rport->phy_port_id,
					joinflag ? MLD_V1_MEMBERSHIP_REPORT_TYPE : MLD_V1_LEAVE_GROUP_TYPE,
					(UINT8) mld_vport->oper_version,
					grp_addr->ip.v6addr,   // Group Address
					src_addr6, // Source Address of the packet 
					0, // 0 means use default response time
					NULL, FALSE,       // no srcs
					FALSE); // not retx
	}
}

void mld_tx_reports_leave_rcvd_on_edge_port(void *req, MADDR_ST *grp_addr, MCGRP_CLASS  *mld, MCGRP_L3IF *mld_vport)
{
	MCGRP_ROUTER_ENTRY* mcgrp_rport = NULL;
	MADDR_ST dest_addr;
	uint8_t afi;
	MCGRP_GLOBAL_CLASS *mcgrp_glb = (IS_IGMP_CLASS(mld) ? &gIgmp : &gMld);
	ifindex_t source,destination;
	uint32_t rx_phy_port;
	MCGRP_PORT_ENTRY* mcgrp_pport;


	if (mld_vport == NULL) 
	{
		L2MCD_LOG_INFO("%s(%d) mld_vport is NULL. ", FN, LN);	
		return;
    }

	if(!IS_IGMP_CLASS(mld)) {
	    afi = MCAST_IPV6_AFI;
	    mcast_set_ipv6_addr(&dest_addr, &grp_addr->ip.v6addr);
		rx_phy_port = ((IP6_RX_PKT_MSG *)req)->ip_param.rx_physical_port_number;
		
	}
    else {
	    afi = MCAST_IPV4_AFI;
	    mcast_set_ipv4_addr(&dest_addr, grp_addr->ip.v4addr);
		//For Non-bcast case use source as rx_phy_port_numder, 
		//vaddr.port contains ifindex for bcast case
		rx_phy_port = ((IP_RX_PKT_MSG *)req)->ip_param.rx_phy_port_number;
	}
	source = rx_phy_port;

	if (is_mld_snooping_enabled(mld_vport, afi)) {
		mcgrp_rport = mld_vport->rtr_port_list;
		
		while (mcgrp_rport) {
			L2MCD_VLAN_LOG_DEBUG(mld_vport->vir_port_id, "%s:%d:[vlan:%d] port_ifindex:0x%x", 
				__FUNCTION__, __LINE__, mld_vport->vir_port_id, mcgrp_rport->phy_port_id);

			/* This is for stopping looping the joins, received on vlag , sending them to again on the
 			** the same vlag */ 
			//destination = mld_get_port_ifindex(mcgrp_rport->phy_port_id);
			destination = mcgrp_rport->phy_port_id;
			L2MCD_LOG_INFO("%s(%d) src_port:0x%x (%s) dst_port:0x%x", FN, LN, 
				source, mld_get_if_name_from_ifindex(rx_phy_port), destination);
			if (mld_ok_to_send_over_edge_port(source, destination)) {
				L2MCD_VLAN_LOG_DEBUG(mld_vport->vir_port_id,"%s:%d:[vlan:%d] %s:mcgrp_rport %s vlan_id %s %s",
							FN, LN, mld_vport->vir_port_id, afi == MLD_IP_IPV4_AFI ? "IGMP":"MLD", 
							mld_get_if_name_from_ifindex(mcgrp_rport->phy_port_id), 
							mld_get_if_name_from_port(mld_vport->vir_port_id), mcast_print_addr(grp_addr));
				l2mcd_send_pkt(req, mcgrp_rport->phy_port_id, mld_vport->vir_port_id, &dest_addr, mld, mcgrp_glb, TRUE, FALSE);

			}
			mcgrp_rport = mcgrp_rport->next;
		}
		/* Now scan through the edge ports and whichever matches tunnel, forward it.
		   We will exclude mrouter ports since we already forwarded over mrouter ports. */	
		mcgrp_pport = mld_vport->phy_port_list;
		while (mcgrp_pport)
		{ 	
			destination = mcgrp_pport->phy_port_id;
			if(l2mcd_ifindex_is_tunnel(destination)
				  && mld_ok_to_send_over_edge_port(source, destination)
				  && !mcgrp_find_rtr_port_entry(mld, mld_vport, mcgrp_pport->phy_port_id))	
			{
				L2MCD_VLAN_LOG_DEBUG(mld_vport->vir_port_id, "%s:%d:[vlan:%d] mcgrp_pport %s vlan_id %s %s",
					  __FUNCTION__, LN,mld_vport->vir_port_id, mld_get_if_name_from_ifindex(mcgrp_pport->phy_port_id), 
					  mld_get_if_name_from_port(mld_vport->vir_port_id), mcast_print_addr(grp_addr));
				l2mcd_send_pkt(req, mcgrp_pport->phy_port_id, mld_vport->vir_port_id, &dest_addr, mld, mcgrp_glb, FALSE, FALSE);
			}
			mcgrp_pport = mcgrp_pport->next;
		}
	}
}

void mld_tx_query_rcvd_on_edge_port(void *req, MADDR_ST *grp_addr, MCGRP_CLASS *mld, MCGRP_L3IF *mld_vport)
{
    if (mld == NULL || mld_vport == NULL)
    {
        L2MCD_LOG_INFO("%s(%d) mld: %p, mld_vport: %p. ", FN, LN, mld, mld_vport);
        return;
    }

    MADDR_ST dest_addr;
    MCGRP_GLOBAL_CLASS *mcgrp_glb = (IS_IGMP_CLASS(mld) ? &gIgmp : &gMld);
    ifindex_t source, destination;
    MCGRP_PORT_ENTRY *mcgrp_pport;
    BOOL is_general_query = FALSE;

    if (!IS_IGMP_CLASS(mld))
    {
        mcast_init_addr(&dest_addr, IP_IPV6_AFI, MADDR_GET_FULL_PLEN(IP_IPV6_AFI));
        mcast_set_ipv6_addr(&dest_addr, &grp_addr->ip.v6addr);
        source = ((IP6_RX_PKT_MSG *)req)->ip_param.rx_physical_port_number;
    }
    else
    {
        mcast_init_addr(&dest_addr, IP_IPV4_AFI, MADDR_GET_FULL_PLEN(IP_IPV4_AFI));
        mcast_set_ipv4_addr(&dest_addr, grp_addr->ip.v4addr);
        source = ((IP_RX_PKT_MSG *)req)->ip_param.rx_phy_port_number;
    }
    is_general_query = mcast_addr_any(grp_addr);
    L2MCD_VLAN_LOG_INFO(mld_vport->vir_port_id, "MLD: Fwd Query Type: %s", is_general_query ? "General" : "Specific");

    /* Now scan through the edge ports and whichever matches tunnel, forward it.
       We will exclude mrouter ports since we already forwarded over mrouter ports. */
    mcgrp_pport = mld_vport->phy_port_list;
    while (mcgrp_pport)
    {
        destination = mcgrp_pport->phy_port_id;
        L2MCD_VLAN_LOG_INFO(mld_vport->vir_port_id, "MLD:%s()%d Inspecting mcgrp_pport phy_port_id=%u", FN, LN, destination);
        if (!mld_ok_to_send_over_edge_port(source, destination))
        {
            mcgrp_pport = mcgrp_pport->next;
            continue;
        }
        if (is_general_query)
        {
            L2MCD_LOG_DEBUG("MLD:%s()%d General Query Packet sent over edge port %s",
                            FN, LN, mld_get_if_name_from_ifindex(destination));
            l2mcd_fwd_pkt(req, destination, mld_vport->vir_port_id, mld, mcgrp_glb, TRUE);
        }
        else
        {
            MCGRP_MBRSHP *mld_mbrshp = mcgrp_find_mbrshp_entry_for_grpaddr(mld, &dest_addr, mld_vport->vir_port_id, destination);
            MCGRP_ROUTER_ENTRY *mld_rtr = mcgrp_find_rtr_port_entry(mld, mld_vport, destination);
            if (mld_mbrshp || mld_rtr)
            {
                L2MCD_LOG_DEBUG("%s: GSQ Query Packet sent over edge port %s", FN,
                                mld_get_if_name_from_ifindex(destination));
                l2mcd_fwd_pkt(req, destination, mld_vport->vir_port_id, mld, mcgrp_glb, TRUE);
            }
        }
        mcgrp_pport = mcgrp_pport->next;
    }
}

void mld_tx_reports_and_leave_rcvd_on_edge_port(void *req, MADDR_ST *grp_addr, MCGRP_CLASS *mld, MCGRP_L3IF *mld_vport)
{
    if (mld == NULL || mld_vport == NULL)
    {
        L2MCD_LOG_INFO("%s(%d) mld: %p, mld_vport: %p. ", FN, LN, mld, mld_vport);
        return;
    }

    MCGRP_GLOBAL_CLASS *mcgrp_glb = (IS_IGMP_CLASS(mld) ? &gIgmp : &gMld);
    ifindex_t source, destination;
    MCGRP_PORT_ENTRY *mcgrp_pport;

    if (!IS_IGMP_CLASS(mld))
    {
        source = ((IP6_RX_PKT_MSG *)req)->ip_param.rx_physical_port_number;
    }
    else
    {
        source = ((IP_RX_PKT_MSG *)req)->ip_param.rx_phy_port_number;
    }

    /* Now scan through the edge ports and whichever matches tunnel, forward it.
       We will exclude mrouter ports since we already forwarded over mrouter ports. */
    mcgrp_pport = mld_vport->phy_port_list;
    while (mcgrp_pport)
    {
        destination = mcgrp_pport->phy_port_id;
        if (!mld_ok_to_send_over_edge_port(source, destination))
        {
            mcgrp_pport = mcgrp_pport->next;
            continue;
        }
        L2MCD_LOG_DEBUG("%s(%d) src_port:0x%x (%s) dst_port:0x%x", FN, LN, source, mld_get_if_name_from_ifindex(source), destination);
        if (l2mcd_ifindex_is_tunnel(destination) || mcgrp_find_rtr_port_entry(mld, mld_vport, destination))
        {
            L2MCD_VLAN_LOG_DEBUG(mld_vport->vir_port_id, "%s:%d:[vlan:%d] mcgrp_pport %s vlan_id %s %s",
                                 __FUNCTION__, LN, mld_vport->vir_port_id, mld_get_if_name_from_ifindex(destination),
                                 mld_get_if_name_from_port(mld_vport->vir_port_id), mcast_print_addr(grp_addr));
            l2mcd_fwd_pkt(req, destination, mld_vport->vir_port_id, mld, mcgrp_glb, TRUE);
        }
        mcgrp_pport = mcgrp_pport->next;
    }
}

int l2mcd_send_pkt(void *msg, ifindex_t phy_port_id, uint16_t ivid,
                   MADDR_ST *grp_addr,
                   MCGRP_CLASS *mld,
                   MCGRP_GLOBAL_CLASS *mcgrp_glb,
                   bool_t is_forwarded, bool_t is_bcast)
{
    int ret = 0;
    int send_sock_handle = -1;

    uint8_t *payload_data = NULL;
    int payload_len = 0;
    uint8_t *send_pkt = NULL;
    int send_pkt_size = 0;
    int l2_hdr_len = 0;
    uint16_t ether_type = 0;

    struct sockaddr_ll sa = {0};
    char ifname[L2MCD_IFNAME_SIZE] = {0};
    l2mcd_if_tree_t *l2mcd_if_tree = NULL;

    if (!IS_IGMP_CLASS(mld))
    {
        /* IPv6 / MLD */
        IP6_RX_PKT_MSG *mld_msg = (IP6_RX_PKT_MSG *)msg;
        payload_data = mld_msg->pkt_data;
        payload_len = mld_msg->pkt_size;
        ether_type = HSL_ETHER_TYPE_IPV6;
        send_sock_handle = g_l2mcd_mld_tx_handle;
        sa.sll_protocol = htons(ETH_P_IPV6); 
    }
    else
    {
        /* IPv4 / IGMP */
        IP_RX_PKT_MSG *igmp_msg = (IP_RX_PKT_MSG *)msg;
        payload_data = igmp_msg->ip_param.data;
        payload_len = igmp_msg->ip_param.total_length;
        ether_type = HSL_ETHER_TYPE_IP;
        send_sock_handle = g_l2mcd_igmp_tx_handle;
        sa.sll_protocol = htons(ETH_P_IP); 
    }
    if (!payload_data || payload_len <= 0)
    {
        L2MCD_LOG_ERR("Invalid payload: ptr=%p, len=%d", payload_data, payload_len);
        return -1;
    }

    if (is_forwarded)
    {
        l2_hdr_len = sizeof(struct vlan_ethhdr);
    }
    else
    {
        l2_hdr_len = sizeof(struct ethhdr);
    }

    send_pkt_size = l2_hdr_len + payload_len;
    send_pkt = calloc(1, send_pkt_size);
    if (!send_pkt)
    {
        L2MCD_LOG_ERR("calloc failed, len=%d", send_pkt_size);
        return -1;
    }

    if (is_forwarded)
    {
        struct vlan_ethhdr *vhdr = (struct vlan_ethhdr *)send_pkt;
        /* SMAC */
        memcpy(vhdr->h_source, mcgrp_glb->mac, ETH_ALEN);
        if (grp_addr->afi == IP_IPV6_AFI)
        {
            MLD_CONVERT_IPV6MCADDR_TO_MAC((char *)&grp_addr->ip.v6addr, vhdr->h_dest);
        }
        else
        {
            MLD_CONVERT_IPV4MCADDR_TO_MAC((char *)&grp_addr->ip.v4addr, vhdr->h_dest);
        }

        /* VLAN Tag Construction */
        vhdr->h_vlan_proto = htons(ETH_P_8021Q);
        /* Prio=7, CFI=0, VID=ivid */
        uint16_t tci = (7 << 13) | (ivid & 0x0FFF);
        vhdr->h_vlan_TCI = htons(tci);
        /* Inner Ethertype */
        vhdr->h_vlan_encapsulated_proto = htons(ether_type);
    }
    else
    {
        struct ethhdr *ehdr = (struct ethhdr *)send_pkt;
        memcpy(ehdr->h_source, mcgrp_glb->mac, ETH_ALEN);
        if (grp_addr->afi == IP_IPV6_AFI)
        {
            MLD_CONVERT_IPV6MCADDR_TO_MAC((char *)&grp_addr->ip.v6addr, ehdr->h_dest);
        }
        else
        {
            MLD_CONVERT_IPV4MCADDR_TO_MAC((char *)&grp_addr->ip.v4addr, ehdr->h_dest);
        }
        ehdr->h_proto = htons(ether_type);
    }

    memcpy(send_pkt + l2_hdr_len, payload_data, payload_len);

    sa.sll_family = AF_PACKET;
    sa.sll_halen = ETH_ALEN;
    if (is_forwarded)
    {
        memcpy(sa.sll_addr, ((struct vlan_ethhdr *)send_pkt)->h_dest, ETH_ALEN);
    }
    else
    {
        memcpy(sa.sll_addr, ((struct ethhdr *)send_pkt)->h_dest, ETH_ALEN);
    }

    if (is_bcast)
    {
        snprintf(ifname, L2MCD_IFNAME_SIZE, "Vlan%d", ivid);
        sa.sll_ifindex = if_nametoindex(ifname);
    }
    else
    {
        if (mld_get_vlan_type(ivid) != MLD_VLAN)
        {
            L2MCD_LOG_INFO("Invalid VLAN type for vlan:%d phy:%d", ivid, phy_port_id);
            free(send_pkt);
            return -1;
        }
        l2mcd_if_tree = M_AVLL_FIND(g_l2mcd_if_to_kif_tree, &phy_port_id);
        if (l2mcd_if_tree)
        {
            sa.sll_ifindex = l2mcd_if_tree->kif;
        }
        else
        {
            L2MCD_LOG_ERR("Interface not found for phy:%d", phy_port_id);
            free(send_pkt);
            return -1;
        }
    }

    L2MCD_LOG_DEBUG("Tx Pkt: Port:%d Vlan:%d Type:%s Len:%d",
                    phy_port_id, ivid,
                    (grp_addr->afi == IP_IPV6_AFI) ? "MLD" : "IGMP",
                    send_pkt_size);

    if (sendto(send_sock_handle, send_pkt, send_pkt_size, 0, (struct sockaddr *)&sa, sizeof(sa)) == -1)
    {
        L2MCD_PKT_PRINT(ivid, "%s_TX Err is_bcast:%d port:%d ret:%s\n",
                        (grp_addr->afi == IP_IPV6_AFI) ? "MLD" : "IGMP", is_bcast, phy_port_id, strerror(errno));

        L2MCD_LOG_NOTICE("Tx Fail: handle:%d vlan:%d port:%d err:%s",
                         send_sock_handle, ivid, phy_port_id, strerror(errno));
        ret = -1;
    }

    free(send_pkt);
    return ret;
}

int l2mcd_fwd_pkt(void *msg, ifindex_t phy_port_id, uint16_t vlan_id, MCGRP_CLASS *mld, MCGRP_GLOBAL_CLASS *mcgrp_glb, bool_t is_forwarded)
{
    int ret = 0;
    int send_sock_handle = -1;
    uint16_t ether_type = 0;

    uint8_t *payload_data = NULL;
    int payload_len = 0;
    uint8_t *src_mac = NULL;
    uint8_t *dest_mac = NULL;

    uint8_t *send_pkt = NULL;
    int send_pkt_size = 0;
    int l2_hdr_len = 0;

    struct sockaddr_ll sa = {0};
    l2mcd_if_tree_t *l2mcd_if_tree = NULL;
    char ifname[L2MCD_IFNAME_SIZE] = {0};

    if (IS_IGMP_CLASS(mld))
    {
        IP_RX_PKT_MSG *igmps = (IP_RX_PKT_MSG *)msg;
        payload_data = igmps->ip_param.data;
        payload_len = igmps->ip_param.total_length;
        src_mac = igmps->ip_param.smac;
        dest_mac = igmps->ip_param.dmac;
        ether_type = HSL_ETHER_TYPE_IP; // IPv4
        send_sock_handle = g_l2mcd_igmp_tx_handle;
    }
    else
    {
        IP6_RX_PKT_MSG *mlds = (IP6_RX_PKT_MSG *)msg;
        payload_data = mlds->pkt_data;
        payload_len = mlds->pkt_size;
        src_mac = mlds->ip_param.smac;
        dest_mac = mlds->ip_param.dmac;
        ether_type = HSL_ETHER_TYPE_IPV6; // IPv6
        send_sock_handle = g_l2mcd_mld_tx_handle;
    }

    if (!payload_data || payload_len <= 0 || payload_len > 2000)
    {
        L2MCD_LOG_ERR("Invalid payload: ptr=%p, len=%d", payload_data, payload_len);
        return -1;
    }

    if (mld_get_vlan_type(vlan_id) != MLD_VLAN)
    {
        L2MCD_LOG_INFO("Invalid vlan type for vlan:%d phy:%d", vlan_id, phy_port_id);
        return -1;
    }
    l2mcd_if_tree = M_AVLL_FIND(g_l2mcd_if_to_kif_tree, &phy_port_id);
    if (!l2mcd_if_tree)
    {
        L2MCD_LOG_ERR("Interface not found for phy_port:%d", phy_port_id);
        return -1;
    }
    sa.sll_ifindex = l2mcd_if_tree->kif;
    memcpy(ifname, l2mcd_if_tree->iname, L2MCD_IFNAME_SIZE);

    if (is_forwarded)
    {
        l2_hdr_len = sizeof(struct vlan_ethhdr);
    }
    else
    {
        l2_hdr_len = sizeof(struct ethhdr);
    }

    send_pkt_size = l2_hdr_len + payload_len;
    send_pkt = calloc(1, send_pkt_size);
    if (!send_pkt)
    {
        L2MCD_LOG_ERR("calloc failed for size %d", send_pkt_size);
        return -1;
    }

    if (is_forwarded)
    {
        struct vlan_ethhdr *vhdr = (struct vlan_ethhdr *)send_pkt;
        uint16_t tci = (7 << 13) | (vlan_id & 0x0FFF);

        memcpy(vhdr->h_dest, dest_mac, ETH_ALEN);
        memcpy(vhdr->h_source, src_mac, ETH_ALEN);

        /* 0x8100 */
        vhdr->h_vlan_proto = htons(ETH_P_8021Q);
        vhdr->h_vlan_TCI = htons(tci);
        vhdr->h_vlan_encapsulated_proto = htons(ether_type);
    }
    else
    {
        struct ethhdr *ehdr = (struct ethhdr *)send_pkt;

        memcpy(ehdr->h_dest, dest_mac, ETH_ALEN);
        memcpy(ehdr->h_source, src_mac, ETH_ALEN);
        ehdr->h_proto = htons(ether_type);
    }
    memcpy(send_pkt + l2_hdr_len, payload_data, payload_len);

    sa.sll_family = AF_PACKET;
    sa.sll_halen = ETH_ALEN;
    memcpy(sa.sll_addr, dest_mac, ETH_ALEN);
    if (sendto(send_sock_handle, send_pkt, send_pkt_size, 0, (struct sockaddr *)&sa, sizeof(sa)) == -1)
    {
        L2MCD_LOG_NOTICE("Tx Err: vlan:%d port:%d sock:%d len:%d err:%s",
                         vlan_id, phy_port_id, send_sock_handle, send_pkt_size, strerror(errno));
        ret = -1;
    }

    free(send_pkt);
    return ret;
}