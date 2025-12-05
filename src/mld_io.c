#include<string.h>
#include "l2mcd_portdb.h"
#include "l2mcd_mld_port.h"
#include "l2mcd_mld_utils.h"
#include "l2mcd_dbsync.h"
#include "mld_struct.h"
#include "l2mcd.h"
#include "l2mcd_mcast_co.h"

#include <linux/ipv6.h>

extern L2MCD_AVL_TREE *mld_portdb_tree;
extern IP6_IPV6_ADDRESS ip6_unspecified_address;
extern L2MCD_AVL_TREE *ve_mld_portdb_tree;

BOOLEAN mld_check_if_checksum_is_valid(IPV6_ADDRESS *source_address, IPV6_ADDRESS *dest_address,
                                       ICMP6_PSEUDO_HDR_MESSAGE *icmp6h, USHORT message_size)
{
    UINT16 calculated_checksum;
    /* calculate checksum for the whole MLD message */
    if (icmp6h->checksum != 0x0000)
    {
        calculated_checksum = calculate_ip6_checksum(source_address, dest_address, icmp6h, message_size, IP6_ICMPV6);
        if (calculated_checksum != 0x0000)
        {
            return FALSE;
        }
    }
    return TRUE;
}

BOOLEAN mld_update_ssm_parameters(MCGRP_CLASS         *mcgrp,
        MADDR_ST             *group_addr,
        UINT8                *version,
        PORT_ID               vir_port_id,
        UINT32                phy_port_id,
        UINT8                *mld_action,
        UINT16               *num_srcs,
        UINT32               **src_list)
{
    MCGRP_L3IF          *mcgrp_vport;
    mcgrp_vport = IS_IGMP_CLASS(mcgrp) ? gIgmp.port_list[vir_port_id] : gMld.port_list[vir_port_id];
    if (mcgrp_vport == NULL || (! mcgrp_vport->is_up) )
    {
        L2MCD_VLAN_LOG_INFO(vir_port_id, "%s:%d:[vlan:%d] Got a static group entry on a NULL vir port or vir port down", FN,LN,vir_port_id);
        if (mcgrp_vport)
        {
            L2MCD_VLAN_LOG_INFO(vir_port_id, "%s:%d:[vlan:%d] vport->is_up :%d", FN,LN,vir_port_id,mcgrp_vport->is_up);
        }
        return FALSE;

    }
    
    *src_list = NULL;
    *num_srcs = 0;
    L2MCD_VLAN_LOG_INFO(vir_port_id, "%s:%d:[vlan:%d] NON SSM group %s.  num_srcs would be 0. \n",FN,LN, vir_port_id, mcast_print_addr(group_addr));
    return TRUE;
}

IPV6_ADDRESS ip_get_lowest_ipv6_address_on_port(UINT16 port_number, uint8_t type)
{
    uint32_t gvid = 0;
    mld_vlan_node_t *vlan_node = NULL;
    IPV6_ADDRESS lowest_ip6_address = {
        .address.address32 = {0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF}};
    IPV6_ADDRESS ip6_address = {0};
    UINT16 port_id = 0;
    gvid = mld_get_vlan_id(port_number);
    vlan_node = mld_vdb_vlan_get(gvid, type);
    if (vlan_node && vlan_node->ve_ifindex) {
        if (l2mcd_ifindex_is_svi(vlan_node->ve_ifindex)) {
            port_id = l3_get_port_from_ifindex(vlan_node->ve_ifindex);
            ip6_address = ve_mld_portdb_get_port_lowest_ipv6_addr_from_list(port_id);
        }
        else
        {
            //insert_linklocal_ipv6_into_portdb(port_number);
            ip6_address = mld_portdb_get_port_lowest_ipv6_addr_from_list(port_number);
        }
    }
    if (memcmp(&ip6_address, &lowest_ip6_address, 16))
        lowest_ip6_address = ip6_address;
    return lowest_ip6_address;
}


void l2mcd_mld_process_query(IP6_RX_PKT_MSG* mld_pkt_msg)
{
    UINT16              vir_port_id;
    UINT32              phy_port_id;
    IP6_IPV6_ADDRESS    clnt_src_ip;
    
    MCGRP_L3IF          *mld_vport = NULL;
    MCGRP_PORT_ENTRY    *mld_pport = NULL;
    MCGRP_MBRSHP        *mld_mbrshp;
    MCGRP_CLASS         *mld = MLD_GET_INSTANCE_FROM_VRFINDEX(L2MCD_DEFAULT_VRF_IDX);
    UINT8               rx_max_resp_time = 0;
    UINT8               mldver;
    MADDR_ST            group_addr;
    uint32_t            max_resp_time;
    BOOLEAN             is_general_query;

    MLDV2_MESSAGE*      mldv2_qry_msg = NULL;
    MLD_MESSAGE*        mld_qry_msg = NULL;

    L2MCD_LOG_NOTICE("[MLD] Query received");
    if (NULL == mld_pkt_msg)
    {
        L2MCD_LOG_ERR("invalid input!");
        return;
    }

    clnt_src_ip = mld_pkt_msg->ip_param.source_address;
    vir_port_id = mld_pkt_msg->ip_param.rx_port_number;
    phy_port_id = mld_pkt_msg->ip_param.rx_physical_port_number;

    mld_vport = gMld.port_list[vir_port_id];
    mld_pport  = mcgrp_find_phy_port_entry(mld, mld_vport, phy_port_id);
    if (mld_vport == NULL || mld_pport == NULL)
    {
        L2MCD_VLAN_LOG_ERR(vir_port_id, "MLD:%s()%d MLD.VRF%d.ERR: process_query received pkt on a NULL Port %s,%s\n",FN,LN,
                mld->vrf_index, mld_get_if_name_from_ifindex(phy_port_id), mld_get_if_name_from_port(vir_port_id));
        return;
    }

    if (mld_pkt_msg->pkt_size == sizeof(MLD_PACKET))
    {
        mldver = MLD_VERSION_1;
        mld_qry_msg = &((MLD_PACKET *)mld_pkt_msg->pkt_data)->mld_message;
        mld_vport->v1_rtr_present = TRUE;
    }
    else if (mld_pkt_msg->pkt_size >= (sizeof(MLDV2_PACKET) - sizeof(IPV6_ADDRESS)))
    {
        mldver = MLD_VERSION_2;
        mldv2_qry_msg = &((MLDV2_PACKET *)mld_pkt_msg->pkt_data)->mld_message;
    }
    else
    {
        mldver = MLD_VERSION_NONE;
        L2MCD_VLAN_LOG_ERR(vir_port_id, "MLD:%s()%d packet size maybe wrong",FN,LN);
        return;
    }

    if (mldver == MLD_VERSION_1)
    {
        max_resp_time = mld_qry_msg->maximum_response_delay;
        max_resp_time = MCGRP_CODE_2_VAL((UINT8)max_resp_time);
        mcast_init_addr(&group_addr, IP_IPV6_AFI, MADDR_GET_FULL_PLEN(IP_IPV6_AFI));
        mcast_set_ipv6_addr(&group_addr, &mld_qry_msg->group_address);
    }
    else if (mldver == MLD_VERSION_2)
    {
        max_resp_time = mldv2_qry_msg->maximum_response_code;
        max_resp_time = MLDV2_CODE16_2_VAL((UINT16)max_resp_time);
        mcast_init_addr(&group_addr, IP_IPV6_AFI, MADDR_GET_FULL_PLEN(IP_IPV6_AFI));
        mcast_set_ipv6_addr(&group_addr, &mldv2_qry_msg->group_address);
    }

    if (mld_vport->oper_version < mldver)
    {
        L2MCD_VLAN_LOG_ERR(vir_port_id, "MLD:%s()%d query version mismatch %d, %d", FN, LN, mld_vport->oper_version, mldver);
        return;
    }
    mld->mld_stats[vir_port_id].recv_packets++;
    // Update stats
    if (IP6_IS_ADDRESS_NOT_NULL(group_addr.ip.v6addr.address))
        mld->mld_stats[vir_port_id].mld_recv_gen_query_msg[mldver - 1]++;
    else if (mldver == MLD_VERSION_1 || (mldver == MLD_VERSION_2 && mldv2_qry_msg->num_srcs == 0))
        mld->mld_stats[vir_port_id].mld_recv_grp_query_msg++;
    else
        mld->mld_stats[vir_port_id].mld_recv_grp_src_query_msg++;

    if ((is_mld_l3_configured(mld_vport) || is_mld_snooping_querier_enabled(mld_vport)) &&
        IP6_IS_ADDRESS_NOT_NULL(clnt_src_ip.address) &&
        (IP6_IS_ADDRESS_NOT_NULL(ip_get_lowest_ipv6_address_on_port(vir_port_id, mld_vport->type).address) ||
         (IP6_IS_ADDRESS_LESS(clnt_src_ip.address, ip_get_lowest_ipv6_address_on_port(vir_port_id, mld_vport->type).address))))
    {
        L2MCD_LOG_NOTICE("[MLD RX] Update Query Timer");
        if ((mld_vport->querier) &&
                (memcmp(&clnt_src_ip, &mld_vport->querier_router.ip.v6addr, sizeof(IP6_IPV6_ADDRESS))!= 0))
        {
            /*Since this is new querier note down the absolute time when the querier was started*/
            mld_vport->querier_uptime = read_tb_sec();
        }
        mld_vport->querier = FALSE;
        mcast_init_addr(&mld_vport->querier_router, IP_IPV6_AFI, MADDR_GET_FULL_PLEN(IP_IPV6_AFI));
        mcast_set_ipv6_addr(&mld_vport->querier_router, &clnt_src_ip);
        mld_vport->querier_router.afi = IP_IPV6_AFI;
        L2MCD_VLAN_LOG_DEBUG(vir_port_id,"%s:%d:[vlan:%d] Querier_ip:%s ",
                FN, LN, vir_port_id,mcast_print_addr(&mld_vport->querier_router));

        if (WheelTimerSuccess == WheelTimer_IsElementEnqueued(&mld_vport->vport_tmr.mcgrp_wte))
        {
            WheelTimer_ReTimeElement(mld->mcgrp_wtid,
                    &mld_vport->vport_tmr.mcgrp_wte,
                    (UINT32)OTHER_QUERIER_PRESENT_INTERVAL(mld_vport));
        }
        else
        {
            // Add to the wheel timer.
            mld_vport->vport_tmr.timer_type            = MCGRP_WTE_QUERIER;
            mld_vport->vport_tmr.mcgrp                 = mld;
            mld_vport->vport_tmr.wte.vport.mcgrp_vport = mld_vport;
            mld_vport->vport_tmr.mcgrp_wte.data        = &mld_vport->vport_tmr;
            WheelTimer_AddElement(mld->mcgrp_wtid,
                    &mld_vport->vport_tmr.mcgrp_wte,
                    (UINT32)OTHER_QUERIER_PRESENT_INTERVAL(mld_vport));
        }
    }

    L2MCD_VLAN_LOG_INFO(vir_port_id,"%s:%d:[vlan:%d] MLD. Querier Enable %d, addr %p",FN,LN, vir_port_id, mld_vport->querier);
    if (mld_vport->querier == FALSE)
    {
        if (IP6_IS_ADDRESS_NOT_NULL(group_addr.ip.v6addr.address))
        {
            if (mldver == MLD_VERSION_1 ||
                (mldver == MLD_VERSION_2 && mldv2_qry_msg->suppress_router_process == 0 && mldv2_qry_msg->num_srcs == 0 /* i.e. this is a GS and not SS Qry */))
            {
                /* Find and update lifetime and state of the group address */
                mld_mbrshp = mcgrp_find_mbrshp_entry_for_grpaddr(mld, &group_addr, vir_port_id, phy_port_id);
                if (mld_mbrshp)
                {
                    if (rx_max_resp_time < MCGRP_TIMER_GET_REMAINING_TIME(mld->mcgrp_wtid, &mld_mbrshp->mbrshp_tmr.mcgrp_wte))
                    {
                        L2MCD_VLAN_LOG_INFO(vir_port_id, "%s:%d:[vlan:%d] .ALERT:Modifying grp timer in query processing to %d", FN, LN,
                                            vir_port_id, rx_max_resp_time);
                        mld_mbrshp->group_timer = read_tb_sec() + rx_max_resp_time;
                        WheelTimer_ReTimeElement(mld->mcgrp_wtid,
                                                 &mld_mbrshp->mbrshp_tmr.mcgrp_wte,
                                                 rx_max_resp_time);
                    }
                }
            }
            else if (mldver == MLD_VERSION_2 && mldv2_qry_msg->suppress_router_process == 0)
            {
                // This is a V2 source-specific query and the suppress bit is not set,
                // so update the source's age
                UINT16 s, num_srcs = mldv2_qry_msg->num_srcs;
                IPV6_ADDRESS *p_srcaddr = mldv2_qry_msg->source_ary;
                
                mld_mbrshp = mcgrp_find_mbrshp_entry_for_grpaddr(mld, &group_addr, vir_port_id, phy_port_id);
                if (mld_mbrshp)
                {
                    for (s = 0; s < num_srcs; s++, p_srcaddr++)
                    {
                        MCGRP_SOURCE *mldv2_src;
                        MADDR_ST srd_addr;
                        mcast_init_addr(&srd_addr, IP_IPV6_AFI, MADDR_GET_FULL_PLEN(IP_IPV6_AFI));
                        mcast_set_ipv6_addr(&srd_addr, p_srcaddr);
                        mldv2_src = mcgrp_find_source(mld_mbrshp, &srd_addr, FILT_INCL);
                        if (mldv2_src)
                        {
                            mldv2_src->src_timer = read_tb_sec() + rx_max_resp_time;
                            if (rx_max_resp_time < MCGRP_TIMER_GET_REMAINING_TIME(mld->mcgrp_wtid, &mld_mbrshp->mbrshp_tmr.mcgrp_wte))
                            {
                                WheelTimer_ReTimeElement(mld->mcgrp_wtid, &mld_mbrshp->mbrshp_tmr.mcgrp_wte, rx_max_resp_time);
                            }
                        }
                    }
                }
            }
        }

        if (mldver == MLD_VERSION_2)
        {
            // Update the query interval time
            if (mldv2_qry_msg->query_interval_code != 0)
            {
                mld->query_interval_time = MCGRP_CODE_2_VAL(mldv2_qry_msg->query_interval_code);
            }

            // Update the robustness variable
            if (mldv2_qry_msg->querier_robustness_var != 0)
            {
                mld->robustness_var = mldv2_qry_msg->querier_robustness_var;

                if (mld->robustness_var < IGMP_DEFAULT_ROBUSTNESS_VARIABLE)
                {
                    L2MCD_VLAN_LOG_ERR(vir_port_id,"MLD:%s()%d MLD.VRF%d.ERR: [ Port %s,%s. Grp %s ] Rx invalid non-zero robustness variable %d\n",FN,LN,
                            mld->vrf_index, mld_get_if_name_from_ifindex(phy_port_id), mld_get_if_name_from_port(vir_port_id), mcast_print_addr(&group_addr), 
                            mldv2_qry_msg->querier_robustness_var);
                    mld->robustness_var = mld->cfg_robustness_var;
                }
            }
            else
            {
                mld->robustness_var = mld->cfg_robustness_var;
            }
        }
    }
    else
    {
        /* I am the querier */
        if (IP6_IS_ADDRESS_NOT_NULL(group_addr.ip.v6addr.address))
        {
            MADDR_ST src_addr;
            mcast_set_ipv6_addr(&src_addr, &clnt_src_ip);
            L2MCD_VLAN_LOG_ERR(vir_port_id,"IGMP:%s()%d IGMP.VRF%d.ERR: Strange... saw GS-query from %s for %s on port %s when we are querier\n",FN,LN,
                    mld->vrf_index, mcast_print_addr(&src_addr), mcast_print_addr(&group_addr), mld_get_if_name_from_ifindex(phy_port_id));
        }
    }

    if (is_mld_snooping_enabled(mld_vport, MCAST_IPV6_AFI) && mld_vport->phy_port_id != phy_port_id) 
    {
        mcgrp_add_router_port(mld, mld_vport, phy_port_id, 0, MLD_PROTO_MROUTER, DEFAULT_MROUTER_AGING_TIME, FALSE);
    }

    L2MCD_VLAN_LOG_INFO(vir_port_id,"%s:%d:[vlan:%d] MLD.QRY From %s,%s. Grp %s Ver:%d",FN,LN,vir_port_id,
            portdb_get_ifname_from_portindex(phy_port_id), portdb_get_ifname_from_portindex(vir_port_id), mcast_print_addr(&group_addr), mldver);

    // General Query & Group/Source Specific Query
    if (is_mld_snooping_enabled(mld_vport, MCAST_IPV6_AFI) )
    {
        mld_tx_query_rcvd_on_edge_port(mld_pkt_msg, &group_addr, mld, mld_vport);
    }
}

void l2mcd_mld_process_v1_report(IP6_RX_PKT_MSG* mld_msg)
{
    L2MCD_LOG_NOTICE("[MLD_V1] Enter function: l2mcd_mld_process_v1_report()");

    if (!mld_msg)
    {
        L2MCD_LOG_ERR("[MLD_V1] ERROR: NULL parameter! mld_msg=%p", mld_msg);
        return;
    }

    if (mld_msg->pkt_data == NULL)
    {
        L2MCD_LOG_ERR("mld_msg->pkt_data is NULL (vlan: %u)", (uint16_t)mld_msg->ip_param.vlan_id);
        return;
    }
    if (mld_msg->pkt_size == 0)
    {
        L2MCD_LOG_ERR("mld_msg->pkt_size is 0 (vlan: %u)", (uint16_t)mld_msg->ip_param.vlan_id);
        return;
    }

    L2MCD_LOG_NOTICE("[MLD_V1] VLAN=%u rx_port=%hu rx_phy_port=%u SRC=%s",
            mld_msg->ip_param.vlan_id,
            mld_msg->ip_param.rx_port_number,
            mld_msg->ip_param.rx_physical_port_number,
            mcast_print_addr(&mld_msg->ip_param.source_address));

    mld_msg->ip_param.version = MLD_VER_1;
    MLD_PACKET *mld_packet = (MLD_PACKET*)mld_msg->pkt_data;
    MLD_MESSAGE *mld_v1_report = &mld_packet->mld_message;
    
    
    MADDR_ST group_addr,source_addr;
    mcast_set_ipv6_addr(&group_addr, &mld_v1_report->group_address); 
    mcast_set_ipv6_addr(&source_addr,&mld_msg->ip_param.source_address); 

    L2MCD_LOG_NOTICE("[MLD_V1] Parsed MLDv1 Report: group=%s",
                     mcast_print_addr(&group_addr));

    MCGRP_CLASS *mld = MLD_GET_INSTANCE_FROM_VRFINDEX(L2MCD_DEFAULT_VRF_IDX);
    if (!mld)
    {
        L2MCD_LOG_ERR("[MLD_V1] ERROR: mld instance is NULL!");
        return;
    }

    MCGRP_L3IF *mld_vport = gMld.port_list[mld_msg->ip_param.rx_port_number];
    if (!mld_vport)
    {
        L2MCD_LOG_ERR("[MLD_V1] Port down or not found: port=%s phys=%s vlan=%d",
                mld_get_if_name_from_ifindex(mld_msg->ip_param.rx_port_number),
                mld_get_if_name_from_port(mld_msg->ip_param.rx_physical_port_number),
                mld_msg->ip_param.vlan_id);

        mld->rx_bad_if++;
        return;
    }

    L2MCD_LOG_NOTICE("[MLD_V1] Valid MLD port found: logical=%s physical=%s",
            portdb_get_ifname_from_portindex(mld_msg->ip_param.rx_port_number),
            portdb_get_ifname_from_portindex(mld_msg->ip_param.rx_physical_port_number));

    // Group Address Check
    if (!mld_check_valid_range(&mld_v1_report->group_address))
    {
        L2MCD_LOG_ERR("[MLD_V1] Group address out of range: %s",
                       mcast_print_addr(&source_addr));

        mld->mld_stats[mld_msg->ip_param.rx_port_number].recv_size_or_range_error++;
        return;
    }
    mld->mld_stats[mld_msg->ip_param.rx_port_number].recv_packets++;

    L2MCD_LOG_NOTICE("[MLD_V1] Group address valid: %s",
                     mcast_print_addr(&group_addr));

    if (!l2mcd_is_peerlink(
            portdb_get_ifname_from_portindex(mld_msg->ip_param.rx_physical_port_number)))
    {
        UINT8 action = IS_EXCL;
        UINT16 num_srcs = 0;
        UINT32 *src_list = NULL;

        L2MCD_LOG_NOTICE("[MLD_V1] Updating membership: action=%d src_count=%d vlan=%d",
                         action, num_srcs, mld_msg->ip_param.vlan_id);

        L2MCD_LOG_NOTICE("[MLD_V1] Call mcgrp_update_group_address_table(): port=%d phy=%d grp=%s src=%s",
                mld_msg->ip_param.rx_port_number,
                mld_msg->ip_param.rx_physical_port_number,
                mcast_print_addr(&group_addr),
                mcast_print_addr(&source_addr));

        MCGRP_MBRSHP* mld_mbrshp = mcgrp_update_group_address_table(
                mld,
                mld_msg->ip_param.rx_port_number,
                mld_msg->ip_param.rx_physical_port_number,
                &group_addr,
                &source_addr,
                action,
                mld_msg->ip_param.version,
                num_srcs,
                (void*)src_list);

        if (!mld_mbrshp)
        {
            L2MCD_LOG_ERR("[MLD_V1] ERROR: mld_mbrshp NULL after update! port=%d group=%s",
                mld_msg->ip_param.rx_physical_port_number,
                mcast_print_addr(&group_addr));
        }
        else
        {
            L2MCD_LOG_NOTICE("[MLD_V1] Membership updated OK.");
        }
    }
    else
    {
        L2MCD_LOG_NOTICE("[MLD_V1] Peerlink port—skip membership update");
    }

    // Snooping
    L2MCD_LOG_NOTICE("[MLD_V1] Checking if snooping enabled…");

    if (is_mld_snooping_enabled(mld_vport, MCAST_IPV6_AFI))
    {
        L2MCD_LOG_NOTICE("[MLD_V1] Snooping enabled. Forwarding report to router ports.");
        mld_tx_reports_and_leave_rcvd_on_edge_port(mld_msg, &group_addr, mld, mld_vport);
    }
    else
    {
        L2MCD_LOG_NOTICE("[MLD_V1] Snooping disabled — not forwarding.");
    }

    L2MCD_LOG_NOTICE("[MLD_V1] Exit l2mcd_mld_process_v1_report()");
}

void l2mcd_mld_process_done(IP6_RX_PKT_MSG* mld_msg)
{
    L2MCD_LOG_NOTICE("[MLD] V1 Done received");
    
    MCGRP_MBRSHP* mld_mbrshp = NULL;
    MCGRP_CLASS *mld = MLD_GET_INSTANCE_FROM_VRFINDEX(L2MCD_DEFAULT_VRF_IDX);
    MCGRP_L3IF    *mld_vport = NULL;
    MADDR_ST group_addr,source_addr;

    if (NULL == mld_msg)
    {
        L2MCD_LOG_ERR("invalid input!");
        return;
    }
    
    mld_msg->ip_param.version = MLD_VER_1;
    
    MLD_MESSAGE* mld_v1_report = NULL;
    MLD_PACKET* mld_v1_packet = NULL;
    mld_v1_packet = (MLD_PACKET *)mld_msg->pkt_data;//parse v1 done
    mld_v1_report = &mld_v1_packet->mld_message;

    mcast_set_ipv6_addr(&group_addr, &mld_v1_report->group_address); 
    mcast_set_ipv6_addr(&source_addr,&mld_msg->ip_param.source_address); 

    if ((mld_vport = gMld.port_list[mld_msg->ip_param.rx_port_number]) == NULL )
    {
        L2MCD_VLAN_LOG_ERR(mld_msg->ip_param.vlan_id, "%s:%d:[vlan:%d]  [ Port %s,%s ] ignored received pkt as Port %s is down \n",FN,LN,
                mld_msg->ip_param.vlan_id, mld_get_if_name_from_ifindex(mld_msg->ip_param.rx_port_number), mld_get_if_name_from_port(mld_msg->ip_param.rx_physical_port_number),
                (mld_vport == NULL ? mld_get_if_name_from_port(mld_msg->ip_param.rx_port_number) : mld_get_if_name_from_ifindex(mld_msg->ip_param.rx_physical_port_number)));
        mld->rx_bad_if++;
        return;
    }

    L2MCD_VLAN_LOG_INFO(mld_msg->ip_param.vlan_id,"%s:%d:[vlan:%d] Report, Port:%s,%s  Grp:%s",FN,LN,mld_msg->ip_param.vlan_id,
             portdb_get_ifname_from_portindex(mld_msg->ip_param.rx_port_number), portdb_get_ifname_from_portindex(mld_msg->ip_param.rx_physical_port_number), mcast_print_addr(&group_addr));


    if (mld_check_valid_range(&mld_v1_report->group_address))
    {
        mld->mld_stats[mld_msg->ip_param.rx_port_number].recv_packets++;
        if (!l2mcd_is_peerlink(portdb_get_ifname_from_portindex(mld_msg->ip_param.rx_physical_port_number)))
        {
            UINT8 mld_action = TO_INCL;
            UINT16 num_srcs = 0;
            UINT32 *src_list = NULL;
            mld_mbrshp = mcgrp_update_group_address_table(mld,
                    mld_msg->ip_param.rx_port_number, 
                    mld_msg->ip_param.rx_physical_port_number,
                    &group_addr,
                    &source_addr,
                    mld_action,
                    mld_msg->ip_param.version,
                    num_srcs,
                    (void *)src_list);
            if(mld_mbrshp == NULL)
                L2MCD_VLAN_LOG_ERR(mld_msg->ip_param.vlan_id ,"%s(%d) mld_mbrshp is NULL. port:%d GA:%s ", FN, LN,mld_msg->ip_param.rx_physical_port_number,mcast_print_addr(&group_addr));
        }
    }
    else
    {

        L2MCD_VLAN_LOG_ERR(mld_msg->ip_param.vlan_id,"MLD:%s()%d MLD.VRF%d.ERR: Pkt ignored as group address %s out of range\n",FN,LN, 
                0, mcast_print_addr(&group_addr));
        mld->mld_stats[mld_msg->ip_param.rx_port_number].recv_size_or_range_error++;

    }

    if(is_mld_snooping_enabled(mld_vport, MCAST_IPV6_AFI)) 
    {
        /*
            * Send leave only if fast-leave is configured.
            * Else send leave post processing GSQ
            */
        if (is_mld_fast_leave_configured(mld_vport)) {
            MLD_LOG(MLD_LOGLEVEL7,MLD_IP_IPV6_AFI,"%s(%d) Send v2 Fast Leave for grp:%s to rtr ports", FN, LN, mcast_print_addr(&group_addr));
            mld_tx_reports_and_leave_rcvd_on_edge_port(mld_msg, &group_addr, mld, mld_vport);
        }
    }
}

void l2mcd_mld_process_v2_report(IP6_RX_PKT_MSG* mld_pkt_msg)
{
    MCGRP_MBRSHP    *mld_mbrshp = NULL;
    MCGRP_CLASS     *mld = MLD_GET_INSTANCE_FROM_VRFINDEX(L2MCD_DEFAULT_VRF_IDX);
    MCGRP_L3IF      *mld_vport = NULL;
    MADDR_ST        group_addr, src_addr;

    //group 
    MLDV2_GROUP_PACKET* mldv2_group_packet = (MLDV2_GROUP_PACKET*)(mld_pkt_msg->pkt_data);
    MLDV2_REPORT_MESSAGE *mld_v2_report = &(mldv2_group_packet->mld_report);
    USHORT rx_port_number = mld_pkt_msg->ip_param.rx_port_number;
    UINT32 rx_phy_port_number = mld_pkt_msg->ip_param.rx_physical_port_number;
    IPV6_ADDRESS* dest_ip = &mldv2_group_packet->ip_header.destination_ip_address;

    L2MCD_LOG_NOTICE("[MLD] v2 report received");
    if (NULL == mld_pkt_msg)
    {
        L2MCD_LOG_ERR("invalid input!");
        return;
    }

    UINT8 mldver = MLD_VER_2;
    mld_pkt_msg->ip_param.version = mldver;
    mld_vport = gMld.port_list[rx_port_number];

    if (!mld_vport)
    {
        L2MCD_VLAN_LOG_ERR(mld_pkt_msg->ip_param.vlan_id, "%s:%d:[vlan:%d]  [ Port %s,%s ] ignored received pkt as Port %s is down \n", FN, LN,
                           mld_pkt_msg->ip_param.vlan_id, mld_get_if_name_from_ifindex(rx_port_number), mld_get_if_name_from_port(rx_phy_port_number),
                           (mld_vport == NULL ? mld_get_if_name_from_port(rx_port_number) : mld_get_if_name_from_ifindex(rx_phy_port_number)));
        mld->rx_bad_if++;
        return;
    }
    mld->mld_stats[rx_port_number].mld_recv_membership_ary[mldver - 1]++;

    if (is_mld_snooping_enabled(mld_vport, MCAST_IPV6_AFI))
    {
        L2MCD_VLAN_LOG_INFO(rx_port_number, "%s:%d:[vlan:%d] send MLD V2 Report to Rtr ports", __FUNCTION__, __LINE__, rx_port_number);
        mld_tx_reports_and_leave_rcvd_on_edge_port(&mld_pkt_msg->ip_param, dest_ip, mld, mld_vport);
    }

    if (l2mcd_is_peerlink(portdb_get_ifname_from_portindex(rx_phy_port_number)))
    {
        return;
    }
    mld->mld_stats[rx_port_number].recv_packets++;

    UINT16 num_grps = ntohs(mld_v2_report->num_grps);
    MLDV2_GROUP_RECORD *mldv2_group_rec = &mld_v2_report->group_record;
    UINT32 offset = 0;
    for (int g=0; g < num_grps; g++)
    {
        IPV6_ADDRESS *src_list = mldv2_group_rec->source_address_ary; // No sources
        IPV6_ADDRESS group_address = mldv2_group_rec->group_address;
        UINT8 mld_action = mldv2_group_rec->type;
        int num_srcs = ntohs(mldv2_group_rec->num_srcs);
        offset = offset + sizeof(MLDV2_GROUP_RECORD) + (num_srcs - 1) * sizeof(IPV6_ADDRESS);

        mcast_init_addr(&group_addr, IP_IPV6_AFI, MADDR_GET_FULL_PLEN(IP_IPV6_AFI));
        mcast_set_ipv6_addr(&group_addr, &group_address);

        L2MCD_LOG_NOTICE("[vlan:%d] Grp=%s RecordType=%d SrcCnt=%d",
            mld_pkt_msg->ip_param.vlan_id,
            mcast_print_addr(&group_addr),
            mldv2_group_rec->type,
            ntohs(mldv2_group_rec->num_srcs));

        L2MCD_VLAN_LOG_INFO(mld_pkt_msg->ip_param.vlan_id, "%s:%d:[vlan:%d] Report, Port:%s,%s  Grp:%s", FN, LN, mld_pkt_msg->ip_param.vlan_id,
                            portdb_get_ifname_from_portindex(mld_pkt_msg->ip_param.rx_port_number), portdb_get_ifname_from_portindex(mld_pkt_msg->ip_param.rx_physical_port_number), mcast_print_addr(&group_addr));
        

        if (!mld_check_valid_range(&mldv2_group_rec->group_address))
        {
            L2MCD_VLAN_LOG_INFO(mld_pkt_msg->ip_param.vlan_id,
                                "%s:%d:[vlan:%d] Group out-of-range: %s", FN, LN, mld_pkt_msg->ip_param.vlan_id,
                                mcast_print_addr(&group_addr));
            continue;
        }
        
        if (num_srcs > 0)
        {
            int eff_num_srcs = (int)num_srcs;

            for (int i = 0; i < num_srcs; i++)
            {
                mcast_init_addr(&src_addr, IP_IPV6_AFI, MADDR_GET_FULL_PLEN(IP_IPV6_AFI));
                mcast_set_ipv6_addr(&src_addr, &src_list[i]);
                L2MCD_LOG_INFO("[MLD_V2] Src[%d]=%s", i, mcast_print_addr(&src_addr));
            }

        }
         if (num_srcs > 0 && ((mldv2_group_rec->type == IS_EXCL) || (mldv2_group_rec->type == TO_EXCL)))
        {
            L2MCD_LOG_INFO(" MLD:%s()%d MLD.VRF%d: Grp:%s with EXCL list is ignored. action %d\n", 
                           FN, LN, mld->vrf_index, mcast_print_addr(&group_addr), 
                           mldv2_group_rec->type);
            continue;
        }

        if (((mld_action == ALLOW_NEW) || (mld_action == IS_INCL)) && (num_srcs == 0))
        {
            mld_action = IS_EXCL;
            mldver = MLD_VERSION_1;
            L2MCD_LOG_INFO("MLD:%s()%d Converting MLDv2 action %d to MLDv1 IS_EXCL for group %s",
                           FN, LN, mldv2_group_rec->type, mcast_print_addr(&group_addr));
        }
        else if ((mld_action == BLOCK_OLD) && (num_srcs == 0))
        {
            mld_action = TO_INCL;
            mldver = MLD_VERSION_1;
            L2MCD_LOG_INFO("MLD:%s()%d Converting MLDv2 action %d to MLDv1 TO_INCL for group %s",
                           FN, LN, mldv2_group_rec->type, mcast_print_addr(&group_addr));
        }

        MCGRP_MBRSHP *mld_mbrshp = mcgrp_update_group_address_table(
            mld,
            rx_port_number,
            rx_phy_port_number,
            &group_addr,
            &src_addr,
            mld_action,
            mldver,
            num_srcs,
            (void *)src_list);

        if (!mld_mbrshp)
        {
            L2MCD_VLAN_LOG_ERR(mld_pkt_msg->ip_param.vlan_id,
                               "%s(%d) mld_mbrshp is NULL. port:%d GA:%s ",
                               FN, LN, rx_phy_port_number,
                               mcast_print_addr(&group_addr));
        }

        mldv2_group_rec = (MLDV2_GROUP_RECORD *)((UINT8 *)mldv2_group_rec + offset);
    }
}

BOOLEAN mld_send_mld_message(MCGRP_CLASS *mld,
                             UINT16 tx_port_number,
                             UINT32 physical_port, // if valid send to this port only, else send to tx_port_number
                             UINT8 type,
                             UINT8 version,
                             IPV6_ADDRESS group_address, // 0 => general query
                             IPV6_ADDRESS source_address,
                             UINT16 response_time, // 0 means use default
                             MCGRP_SOURCE *src_list,
                             BOOLEAN all_srcs,
                             BOOLEAN is_retx)
{
    IP6_RX_PKT_MSG rx_pkt_msg;
    IPV6_HEADER *ip6h = NULL;
    IPV6_HBH_ROUTER_ALERT_COMPLETE *hbh_opts = NULL;
    union mld_in6_cmsg *cmsg;

    // Routing/Interface lookups
    MCGRP_L3IF *mld_vport = gMld.port_list[tx_port_number];
    MCGRP_GLOBAL_CLASS *mcgrp_glb = (IS_IGMP_CLASS(mld) ? &gIgmp : &gMld);
    uint32_t ifindex = 0;
    uint16_t vlan_id = 0;
    int ret = 0;

    // Pointers for Message construction
    MLD_MESSAGE *sptr_mld_message = NULL;
    MLDV2_MESSAGE *sptr_mldv2_message = NULL;
    MLDV2_REPORT_MESSAGE *sptr_mldv2_group_message = NULL;

    MLD_PACKET *sptr_mld_packet = NULL;
    MLDV2_PACKET *sptr_mldv2_packet = NULL;
    MLDV2_GROUP_PACKET *sptr_mldv2_group_packet = NULL;

    UINT32 packet_total_size = 0;
    UINT32 mld_message_size = 0;
    int num_srcs = 0;

    MADDR_ST group_addr;
    MADDR_ST source_addr;
    mcast_init_addr(&source_addr, IP_IPV6_AFI, MADDR_GET_FULL_PLEN(IP_IPV6_AFI));
    mcast_init_addr(&group_addr, IP_IPV6_AFI, MADDR_GET_FULL_PLEN(IP_IPV6_AFI));
    mcast_set_ipv6_addr(&group_addr, &group_address);
    mcast_set_ipv6_addr(&source_addr, &source_address);

    L2MCD_VLAN_LOG_DEBUG(tx_port_number, "%s:%d:[vlan:%d] type:%d ver:%d G:%s,S:%s port:0x%x tx_port:0x%x type:%d",
                         __FUNCTION__, __LINE__, tx_port_number, type, version, mcast_print_addr(&group_addr),
                         mcast_print_addr(&source_addr), physical_port, tx_port_number, type);
    // Prepare TX Message Wrapper
    memset(&rx_pkt_msg, 0, sizeof(rx_pkt_msg));

    if (version == MLD_NONE)
    {
        L2MCD_VLAN_LOG_ERR(tx_port_number, "MLD:%s()%d MLD. ERR: [ Port %s,%s, Grp %s ] BUG !!! Request to send a Version None pkt\n", FN, LN,
                           mld_get_if_name_from_ifindex(physical_port), mld_get_if_name_from_port(tx_port_number), mcast_print_addr(&group_addr));
        version = MLD_VER_1;
    }

    // ---------------------------------------------------------
    // 1. Memory Allocation
    // ---------------------------------------------------------
    if (version == MLD_VER_1)
    {
        packet_total_size = sizeof(MLD_PACKET);
        sptr_mld_packet = (MLD_PACKET *)calloc(1, packet_total_size);

        if (sptr_mld_packet == NULL)
        {

            L2MCD_VLAN_LOG_ERR(tx_port_number, "MLD:%s()%d MLD.VRF%d.ERR: Failed to allocate an IP pkt. Transmit failed\n", FN, LN, mld->vrf_index);
            return FALSE;
        }
        ip6h = &sptr_mld_packet->ip_header;
        hbh_opts = &sptr_mld_packet->hbh_options;
        sptr_mld_message = &sptr_mld_packet->mld_message;
        mld_message_size = sizeof(MLD_MESSAGE);
    }
    else if (version == MLD_VER_2)
    {
        if (src_list)
        {
            MCGRP_SOURCE *p_src = src_list;
            for (; p_src; p_src = p_src->next)
            {
                if (is_retx || p_src->retx_cnt == 0)
                {
                    num_srcs++;
                    // Limit packet size if necessary (MTU checks usually happen here)
                    if (num_srcs >= 80)
                        break;
                }
            }
        }
        else
        {
            num_srcs = 0;
        }

        // Packet size = Base Structure + (N-1) IPv6 addresses (since struct has array[1])
        int variable_part = (num_srcs - 1) * sizeof(IPV6_ADDRESS);
        packet_total_size = sizeof(MLDV2_PACKET) + variable_part;

        sptr_mldv2_packet = (MLDV2_PACKET *)calloc(1, packet_total_size);

        if (sptr_mldv2_packet == NULL)
        {
            L2MCD_VLAN_LOG_ERR(tx_port_number, "MLD:%s()%d MLD.VRF%d.ERR: Failed to allocate an IP pkt. Transmit failed\n", FN, LN, mld->vrf_index);
            return FALSE;
        }

        ip6h = &sptr_mldv2_packet->ip_header;
        hbh_opts = &sptr_mldv2_packet->hbh_options;
        sptr_mldv2_message = &sptr_mldv2_packet->mld_message; // Base pointer

        mld_message_size = sizeof(MLDV2_MESSAGE) + variable_part;

        // Reset num_srcs for encoding loop
        num_srcs = 0;
    }
    // ---------------------------------------------------------
    // 2. MLD Payload Construction
    // ---------------------------------------------------------
    // For leave packets the response_time should be 0
    int resp_time32 = response_time;
    if ((response_time == 0) && (type == MLD_MEMBERSHIP_QUERY_TYPE))
    {
        response_time = mld->max_response_time * 10;
    }
    resp_time32 = response_time * 100;

    switch (version)
    {
    case MLD_VER_1:
    {
        sptr_mld_message->type = type;
        sptr_mld_message->code = 0;
        // MLDv1 Max Response Delay is in milliseconds (16 bits).
        sptr_mld_message->maximum_response_delay = htons((UINT16)resp_time32);
        sptr_mld_message->reserved = 0;

        // Copy Group Address
        memcpy(&sptr_mld_message->group_address, &group_address, sizeof(IPV6_ADDRESS));
        break;
    }
    case MLD_VER_2:
    {
        sptr_mldv2_message->type = type;
        sptr_mldv2_message->code = 0;
        // MLDv2 Max Response Code (float encoding similar to IGMPv3)
        sptr_mldv2_message->maximum_response_code = htons(MCGRP_VAL_2_CODE16(resp_time32)); // Ensure helper supports v2
        sptr_mldv2_message->reserved = 0;
        memcpy(&sptr_mldv2_message->group_address, &group_address, sizeof(IPV6_ADDRESS));

        // Encode Source List
        if (src_list)
        {
            num_srcs = mldv2_encode_src_list(sptr_mldv2_message, src_list, all_srcs, is_retx);
        }
        else
        {
            num_srcs = 0;
        }

        // Group-Source Query Logic Check
        if (!IN6_IS_ADDR_UNSPECIFIED(&group_address) && src_list && num_srcs == 0)
        {
            free(sptr_mldv2_packet);
            sptr_mldv2_packet = NULL;
            L2MCD_VLAN_LOG_DEBUG(tx_port_number, "%s:%d:[vlan:%d] [ Port %s,%s. Grp %s ] Skipped Grp-Src-Qry as num_srcs is 0. List %d",
                                 FN, LN, tx_port_number,
                                 mld_get_if_name_from_ifindex(physical_port), mld_get_if_name_from_port(tx_port_number),
                                 mcast_print_addr(&group_addr),
                                 (src_list != NULL));
            return TRUE;
        }

        // Fill MLDv2 specific fields
        // Note: Bitfield handling macros or direct assignment depending on endianness
        // Simplified assignment here assuming struct handles bitfields:
        sptr_mldv2_message->reserved_flags = 0;
        sptr_mldv2_message->suppress_router_process = (response_time > mld->LMQ_interval);
        sptr_mldv2_message->querier_robustness_var = mld->cfg_robustness_var;

        sptr_mldv2_message->query_interval_code = MCGRP_VAL_2_CODE(mld->cfg_query_interval_time);
        sptr_mldv2_message->num_srcs = htons((UINT16)num_srcs);

        L2MCD_VLAN_LOG_DEBUG(tx_port_number, "%s:%d:[vlan:%d] MLDv2 num_srcs:%d mld_packet_size:%d alloc_buff_size:%d mld_type:%d",
                             __FUNCTION__, __LINE__, tx_port_number, num_srcs, packet_total_size, mld_message_size, type);
        break;
    }
    } /* switch (version) */

    // ---------------------------------------------------------
    // 3. IPv6 Header & HBH Construction
    // ---------------------------------------------------------

    // Setup HBH Options (Router Alert is mandatory for MLD)
    hbh_opts->hbh_header.next_header = IP6_ICMPV6; // Next is ICMPv6
    hbh_opts->hbh_header.hdr_ext_len = 0;          // (0 + 1) * 8 = 8 bytes

    hbh_opts->rtr_alert.type = IP6_OPT_RTALERT;      // Router Alert Option Type
    hbh_opts->rtr_alert.length = 2;                  // Length
    hbh_opts->rtr_alert.value = IP6_OPT_RTALERT_MLD; // MLD

    hbh_opts->pad_type = 1; // PadN
    hbh_opts->pad_len = 0;  // 0 Data bytes (total 2 bytes overhead fills alignment)

    // Setup IPv6 Header
    // Note: IPV6_HEADER struct usage depends on bitfield definition order
    UINT32 vtf = (6 << 28) | (0xc0 << 20) | 0;
    vtf = htonl(vtf);
    memcpy(ip6h, &vtf, sizeof(UINT32));

    ip6h->payload_length = htons(sizeof(IPV6_HBH_ROUTER_ALERT_COMPLETE) + mld_message_size);
    ip6h->next_header = IP6_HOP_BY_HOP_EH; // Next is Hop-by-Hop Options
    ip6h->hop_limit = 1;                   // MLD MUST have Hop Limit 1

    memcpy(&ip6h->source_ip_address, &source_address, sizeof(IPV6_ADDRESS));

    // Group-Specific Query || MLD_V1_MEMBERSHIP_REPORT_TYPE
    memcpy(&ip6h->destination_ip_address, &group_address, sizeof(IPV6_ADDRESS));
    if (type == MLD_MEMBERSHIP_QUERY_TYPE)
    {
        if (IN6_IS_ADDR_UNSPECIFIED(&group_address))
        {
            // General Query
            inet_pton(AF_INET6, "FF02::1", &ip6h->destination_ip_address);
        }
    }
    else if (type == MLD_V2_MEMBERSHIP_REPORT_TYPE)
    {
        inet_pton(AF_INET6, "FF02::16", &ip6h->destination_ip_address);
    }
    else if (type == MLD_V1_LEAVE_GROUP_TYPE)
    {
        inet_pton(AF_INET6, "FF02::2", &ip6h->destination_ip_address);
    }
    // ---------------------------------------------------------
    // 4. Checksum Calculation (ICMPv6 includes Pseudo-Header)
    // ---------------------------------------------------------

    UINT8 *msg_ptr = (version == MLD_VER_2) ? (UINT8 *)sptr_mldv2_message : (UINT8 *)sptr_mld_message;
    if (version == MLD_VER_2)
    {
        sptr_mldv2_message->checksum = 0;
        // calculate_icmpv6_checksum must handle IPv6 Pseudo Header + Payload
        sptr_mldv2_message->checksum = htons(calculate_ip6_checksum(
            &ip6h->source_ip_address,
            &ip6h->destination_ip_address,
            msg_ptr,
            mld_message_size,
            IP6_ICMPV6));
    }
    else
    {
        sptr_mld_message->checksum = 0;
        sptr_mld_message->checksum = htons(calculate_ip6_checksum(
            &ip6h->source_ip_address,
            &ip6h->destination_ip_address,
            msg_ptr,
            mld_message_size,
            IP6_ICMPV6));
    }

    // ---------------------------------------------------------
    // 5. Send Packet
    // ---------------------------------------------------------

    // Get VLAN Info
    cmsg = calloc(1, sizeof(union mld_in6_cmsg));
    if (!cmsg)
    {
        L2MCD_VLAN_LOG_ERR(tx_port_number, "MLD:%s()%d MLD.VRF%d.ERR: Failed to allocate cmsg.\n", FN, LN, mld->vrf_index);
        return FALSE;
    }

    ifindex = portdb_get_port_ifindex(mld_portdb_tree, tx_port_number);
    if (l2mcd_ifindex_is_physical(ifindex))
    {
        cmsg->vaddr.vlanid = mld_portdb_get_ivid_from_gvid(ifindex, MLD_ROUTE_PORT);
    }
    else
    {
        cmsg->vaddr.vlanid = mld_get_ivid_vport(tx_port_number, MCAST_IPV6_AFI);
    }
    cmsg->vaddr.port = physical_port;
    vlan_id = cmsg->vaddr.vlanid;

    if ((type == MLD_MEMBERSHIP_QUERY_TYPE))
    {
        memcpy(cmsg->vaddr.src_mac, mcgrp_glb->mac, ETHER_ADDR_LEN);
    }

    // Copy addresses for the TX internal structure (using custom structs/unions per your system)
    memcpy(&rx_pkt_msg.ip_param.source_address, &source_address, sizeof(IPV6_ADDRESS));
    memcpy(&rx_pkt_msg.ip_param.destination_address, &ip6h->destination_ip_address, sizeof(IPV6_ADDRESS));

    // rx_pkt_msg.ip_param.smac = ;
    // rx_pkt_msg.ip_param.dmac = ;
    // rx_pkt_msg.ip_param.source_address = ;
    // rx_pkt_msg.ip_param.destination_address = ;

    rx_pkt_msg.ip_param.rx_port_number = tx_port_number;
    rx_pkt_msg.ip_param.rx_physical_port_number = physical_port;
    rx_pkt_msg.ip_param.vrf_index = L2MCD_DEFAULT_VRF_IDX;
    rx_pkt_msg.ip_param.vlan_id = vlan_id;
    rx_pkt_msg.pkt_data = (version == MLD_VER_2) ? (void *)sptr_mldv2_packet : (void *)sptr_mld_packet;
    rx_pkt_msg.pkt_size = packet_total_size;

    MADDR_ST dest_addr_st;
    mcast_init_addr(&dest_addr_st, IP_IPV6_AFI, MADDR_GET_FULL_PLEN(IP_IPV6_AFI));
    mcast_set_ipv6_addr(&dest_addr_st, &ip6h->destination_ip_address);

    if ((type == MLD_V1_LEAVE_GROUP_TYPE) || (type == MLD_V1_MEMBERSHIP_REPORT_TYPE))
    {
        mld_tx_reports_leave_rcvd_on_edge_port(&rx_pkt_msg, &dest_addr_st, mld, mld_vport);
    }
    else
    {
        L2MCD_VLAN_LOG_DEBUG(tx_port_number, "[Before Send] pkt: %p, phy_port: %d, vlan: %d, dest ip: %s, mld(%p) mcgrp_glb(%p) fwd: %d bocast: %d",
                             &rx_pkt_msg, physical_port, vlan_id, mcast_print_addr(&dest_addr_st), mld, mcgrp_glb, (physical_port != PORT_INDEX_INVALID), (physical_port == PORT_INDEX_INVALID));
        if (physical_port != PORT_INDEX_INVALID)
        {
            MCGRP_PORT_ENTRY *mcgrp_pport = mld_vport->phy_port_list;
            while (mcgrp_pport)
            {
                if (mcgrp_pport->phy_port_id != physical_port)
                {
                    mcgrp_pport = mcgrp_pport->next;
                    continue;
                }
                ret = l2mcd_send_pkt(&rx_pkt_msg, physical_port, vlan_id, &dest_addr_st, mld, mcgrp_glb,
                                     mcgrp_pport->tagged, FALSE);
                break;
            }
            mld->mld_stats[tx_port_number].xmt_packets++;

            if (ret == -1)
                mld->mld_stats[tx_port_number].xmt_error++;
        }
        else
        {
            MCGRP_PORT_ENTRY *mcgrp_pport = mld_vport->phy_port_list;
            while (mcgrp_pport)
            {
                ret = l2mcd_send_pkt(&rx_pkt_msg, mcgrp_pport->phy_port_id, vlan_id, &dest_addr_st, mld, mcgrp_glb,
                                     mcgrp_pport->tagged, FALSE);
                mld->mld_stats[tx_port_number].xmt_packets++;
                if (ret == -1)
                    mld->mld_stats[tx_port_number].xmt_error++;
                mcgrp_pport = mcgrp_pport->next;
            }
        }
    }

    L2MCD_VLAN_LOG_DEBUG(tx_port_number, "%s:%d:[vlan:%d] MLD.type:%d: [ Port %s(%d),  %s(%d) Grp %s ] Sent version %d. size %d. Src %s vlan:%d", FN, LN,
                         tx_port_number, type, portdb_get_ifname_from_portindex(physical_port), physical_port, portdb_get_ifname_from_portindex(tx_port_number), tx_port_number,
                         mcast_print_addr(&group_addr), version, mld_message_size, mcast_print_addr(&source_addr), vlan_id);
    L2MCD_VLAN_LOG_DEBUG(tx_port_number, "dest ip: %s", mcast_print_addr(&dest_addr_st));

    // Cleanup
    if (version == MLD_VER_2)
        free(sptr_mldv2_packet);
    else
        free(sptr_mld_packet);
    free(cmsg);

    return TRUE;
}

typedef struct s_MLD_CLNT_LV_PARAM
{
    MCGRP_L3IF *mld_vport;
    MCGRP_MBRSHP *mld_mbrshp;
    IPV6_ADDRESS group_addr6;
    SORTED_LINKLIST **src_list;
    BOOLEAN was_excl;
    IPV6_ADDRESS clnt_ip_addr;

} MLD_CLNT_LV_PARAM;

UINT32 mld_track_v2_clnt_leave(MCGRP_CLASS *mld, 
        MLD_CLNT_LV_PARAM* p_param)
{
    MCGRP_SOURCE *p_src = NULL, *p_next;
    IPV6_ADDRESS group_address  = p_param->group_addr6;
    MCGRP_MBRSHP* mld_mbrshp = p_param->mld_mbrshp;
    MCGRP_L3IF * mld_vport  = p_param->mld_vport;
    BOOLEAN exclude_all = p_param->was_excl;
    BOOLEAN grp_delete = FALSE;
    MADDR_ST addr, src_addr;

    mcast_init_addr(&src_addr, IP_IPV6_AFI, MADDR_GET_FULL_PLEN(IP_IPV6_AFI));      
    mcast_init_addr(&addr, IP_IPV6_AFI, MADDR_GET_FULL_PLEN(IP_IPV6_AFI));          
    mcast_set_ipv6_addr(&addr, &group_address);


    // We do not correctly maintain the client-list when we are in the EXCL mode
    // So, if we were in the EXCLUDE mode then do not attempt Fast-Leave
    if (exclude_all)
    {
        return grp_delete;
    }

    p_src = (MCGRP_SOURCE*) *p_param->src_list;

    mldv2_destroy_client(mld, &mld_mbrshp->clnt_tree, p_param->clnt_ip_addr);
    if (p_src == NULL)
    {
        L2MCD_LOG_DEBUG("MLD:%s()%d MLD.VRF%d: [ Port %s,%s. Grp %s ] Fast-deleting grp on last client Leave %I\n",FN,LN, 
                mld->vrf_index, mld_get_if_name_from_ifindex(mld_mbrshp->phy_port_id), mld_get_if_name_from_port(mld_vport->vir_port_id),
                mcast_print_addr(&addr),
                p_param->clnt_ip_addr);
        //if it was exclude {} and new state is include {} then grp_delete
        return TRUE;
    }
    if (M_AVLL_FIRST(p_src->clnt_tree) == NULL)
    {

        L2MCD_LOG_DEBUG("MLD:%s()%d MLD.VRF%d: [ Port %s,%s. Grp %s ] Common client list empty; srclist not empty \n",FN,LN,
                mld->vrf_index, mld_get_if_name_from_ifindex(mld_mbrshp->phy_port_id), mld_get_if_name_from_port(mld_vport->vir_port_id), mcast_print_addr(&addr));
    }

    for (; p_src; p_src = p_next)
    {
        // Members of src_list may be deleted during the loop iteration.
        // So save the next pointer to enable us to correctly traverse the list.
        p_next = p_src->next;

        if (! p_src->include_in_query)
            continue;

        (void) mldv2_destroy_client(mld, &p_src->clnt_tree, p_param->clnt_ip_addr);

        if (M_AVLL_FIRST(p_src->clnt_tree) == NULL)
        {
            MCGRP_SOURCE* p_del;

            L2MCD_LOG_DEBUG("MLD:%s()%d MLD.VRF%d: [ Port %s,%s. Grp %s ] Fast-deleting src %s on last client Leave %I\n",FN,LN, 
                    mld->vrf_index, mld_get_if_name_from_ifindex(mld_mbrshp->phy_port_id), mld_get_if_name_from_port(mld_vport->vir_port_id),
                    mcast_print_addr(&addr),
                    mcast_print_addr(&p_src->src_addr),
                    p_param->clnt_ip_addr);         

            p_del = mcgrp_delist_source(mld_mbrshp, &p_src->src_addr, FILT_INCL);

            if (mld_mbrshp->filter_mode == FILT_INCL)
            {
                if (mld_mbrshp->src_list[FILT_INCL] == NULL)
                    grp_delete = TRUE;
            }
            else if (mld_mbrshp->filter_mode == FILT_EXCL)
            {
                sorted_linklist_add_one_item(gMld.src_specific_pool, 
                        &mldv2_src_keyinfo,
                        (SORTED_LINKLIST**)&mld_mbrshp->src_list[FILT_EXCL], 
                        &p_src->src_addr);

                mcgrp_notify_source_list_add_blocked(mld, 
                        &addr, 
                        mld_vport, 
                        mld_mbrshp, 
                        p_src, TRUE);

                mcast_init_addr(&src_addr, IP_IPV6_AFI, MADDR_GET_FULL_PLEN(IP_IPV6_AFI));
                mcast_set_ipv6_addr(&src_addr, &(p_param->clnt_ip_addr));

                L2MCD_LOG_DEBUG("MLD:%s()%d MLD.VRF%d: [ Port %s,%s. Grp %s ] Added blocked source %s on last INCL-clnt Leave %x\n",FN,LN, 
                        mld->vrf_index, mld_get_if_name_from_ifindex(mld_mbrshp->phy_port_id), mld_get_if_name_from_port(mld_vport->vir_port_id),
                        mcast_print_addr(&addr),
                        mcast_print_addr(&p_src->src_addr),
                        p_param->clnt_ip_addr);         


            }

            // Mark source so that we do not send a query for it
            p_src->include_in_query = FALSE;


            // Notify mcast routing protocols et al
            mcgrp_notify_source_del_allowed(mld, &addr, 
                    mld_vport, mld_mbrshp,
                    &p_src->src_addr, TRUE);

            mcgrp_free_source(mld, p_del);
        }
    }

    return grp_delete;
}

BOOLEAN mldv2_send_group_source_query(MCGRP_CLASS *mld,
                                      MCGRP_MBRSHP *mld_mbrshp,
                                      UINT16 vir_port_id,
                                      UINT32 phy_port_id,
                                      IPV6_ADDRESS group_address,
                                      SORTED_LINKLIST **p_src_list,
                                      BOOLEAN was_excl,
                                      IPV6_ADDRESS clnt_ip_addr,
                                      BOOLEAN is_retx)
{
    BOOLEAN grp_deleted = FALSE;
    MCGRP_L3IF *mld_vport = NULL;
    MCGRP_PORT_ENTRY *mld_pport = NULL;
    MADDR_ST addr;

    /* If source list pointer is NULL or empty, don't send group-source query */
    if (p_src_list == NULL || *p_src_list == NULL)
        return grp_deleted;

    /* initialize IPv6 multicast address structure */
    mcast_init_addr(&addr, IP_IPV6_AFI, MADDR_GET_FULL_PLEN(IP_IPV6_AFI));
    mcast_set_ipv6_addr(&addr, &group_address);

    /* Find virtual vport and physical port entry (parallel to IGMP code) */
    mld_vport = gMld.port_list[vir_port_id];
    mld_pport = mcgrp_find_phy_port_entry(mld, mld_vport, phy_port_id);

    if (mld_vport == NULL)
    {
        return grp_deleted;
    }

    if (mld_pport == NULL)
    {
        L2MCD_VLAN_LOG_ERR(vir_port_id, "MLD:%s()%d  [ Port %d,%d.] mld_pport is NULL. ", FN, LN, phy_port_id, vir_port_id);
        return grp_deleted;
    }

    /* If tracking is enabled and this is an MLDv2-capable port and client IPv6 address provided,
       consult tracking to possibly skip sending the Query and remove the source(s) if they are
       only referenced by this client. */
    if (mld_vport->tracking_enabled &&
        mld_pport->oper_version == MLD_VERSION_2 /*&& clnt_ip_addr*/)
    {
        MLD_CLNT_LV_PARAM clnt_param;

        clnt_param.mld_vport = mld_vport;
        clnt_param.mld_mbrshp = mld_mbrshp;
        clnt_param.group_addr6 = group_address;
        clnt_param.src_list = p_src_list;
        clnt_param.was_excl = was_excl;

        /* Check if these sources are referenced only by this client; if so, delete and skip sending */
        grp_deleted = mld_track_v2_clnt_leave(mld, &clnt_param);
    }

    if (*p_src_list)
    {
        /* Send an MLDv2 Group-and-Source-specific Query. The helper mld_send_mld_message
           is expected to form the correct ICMPv6 MLDv2 Query with the given source list. */
        if (mld_send_mld_message(mld,
                                 vir_port_id,
                                 phy_port_id,
                                 MLD_MEMBERSHIP_QUERY_TYPE,
                                 MLD_VERSION_2,
                                 group_address,
                                 ip_get_lowest_ipv6_address_on_port(vir_port_id, mld_vport->type),
                                 (mld_vport->LMQ_interval * 10), /* LMQI msec -> RFC response field conversion */
                                 (MCGRP_SOURCE *)*p_src_list, FALSE /* all_srcs */,
                                 is_retx))
        {
            L2MCD_VLAN_LOG_INFO(vir_port_id, "%s:%d:[vlan:%d][ Port %d. Grp 0x%x ] Sent MLDv2 Grp-Src-Qry Ver %d. ReTx %d",
                                FN, LN, vir_port_id, phy_port_id, group_address, MLD_VERSION_2, is_retx);
            /* Update stats */
            mld->mld_stats[vir_port_id].mld_xmt_grp_src_query_msg++;
        }
        else
        {
            L2MCD_VLAN_LOG_INFO(vir_port_id, "%s:%d:[vlan:%d][ Port %d. Grp %s ] Skipped MLDv2 Grp-Src-Qry",
                                FN, LN, vir_port_id, phy_port_id, "<ipv6>");
        }
    }

    return grp_deleted;
}

BOOLEAN mld_staticGroup_exists_on_port (IPV6_ADDRESS*  group_addr, 
        PORT_ID     port_id, 
        //PORT_ID phy_port)
        UINT32 phy_port)
{
    VRF_INDEX vrf_index = IP6_PORT_VRF_INDEX(port_id);
    MCGRP_CLASS *mld = MCGRP_GET_INSTANCE_FROM_VRFINDEX(IP_IPV6_AFI, vrf_index);
    MCGRP_STATIC_ENTRY *mld_entry = NULL;
    MADDR_ST grp_addr;
    MCGRP_L3IF          *mcgrp_vport = NULL;

    mcast_init_addr(&grp_addr, IP_IPV6_AFI, MADDR_GET_FULL_PLEN(IP_IPV6_AFI));
    mcast_set_ipv6_addr(&grp_addr, group_addr);

    if (!mld )
        return FALSE;

    mcgrp_vport = IS_IGMP_CLASS(mld) ? gIgmp.port_list[port_id] : gMld.port_list[port_id];
    mld_entry = mcgrp_vport->static_mcgrp_list_head;

    while (mld_entry)
    {
        if (mld_entry->port_num == port_id &&
                (IP6_IS_ADDRESS_UNSPECIFIED(group_addr->address)) ||
            (mcast_cmp_addr(&grp_addr, &mld_entry->group_address) == 0))
        {
            if (mld_is_member_tree(&(mld_entry->port_tree), phy_port))
            {
                return TRUE;
            }
        }

        mld_entry = mld_entry->next;
    }

    return FALSE;
}

void mld_send_general_query(
        MCGRP_CLASS *mld,
        UINT16       tx_port_number,
        UINT32       physical_port,
        UINT8        version,
        IPV6_ADDRESS *use_src,
        UINT16       response_time)
{
    uint32_t gvid = 0;
    int port_id = 0;

    mld_vlan_node_t *vlan_node = NULL;
    MCGRP_L3IF *mld_vport = NULL;

    IPV6_ADDRESS src_addr;
    IPV6_ADDRESS src_address;

    mld_vport = gMld.port_list[tx_port_number];
    if (mld_vport == NULL)
    {
        L2MCD_VLAN_LOG_ERR(tx_port_number, "%s mld_vport not found for %d", __FUNCTION__, tx_port_number);
        return;
    }

    gvid = mld_get_vlan_id(tx_port_number);
    vlan_node = mld_vdb_vlan_get(gvid, mld_vport->type);

    if (vlan_node && vlan_node->ve_ifindex)
    {
        if (l2mcd_ifindex_is_svi(vlan_node->ve_ifindex))
        {
            port_id = mld_l3_get_port_from_ifindex(
                        vlan_node->ve_ifindex, vlan_node->type);
            portdb_get_port_ipv6_addr_list(ve_mld_portdb_tree, port_id);
            src_address = ve_mld_portdb_get_port_lowest_ipv6_addr_from_list(port_id);

            L2MCD_VLAN_LOG_DEBUG(tx_port_number,
                "%s:%d:[vlan:%d] VE ipv6 lookup ifindex=0x%x port=0x%x",
                __FUNCTION__, __LINE__, tx_port_number,
                vlan_node->ve_ifindex, port_id);
        }
        else
        {
            /* Router port */
            port_id = tx_port_number;
            portdb_get_port_ipv6_addr_list(mld_portdb_tree, port_id);
            src_address = ve_mld_portdb_get_port_lowest_ipv6_addr_from_list(port_id);
            L2MCD_VLAN_LOG_DEBUG(tx_port_number,
                "%s:%d:[vlan:%d] Router ipv6 lookup",
                __FUNCTION__, __LINE__, tx_port_number);
        }
    }

    L2MCD_VLAN_LOG_DEBUG(tx_port_number,
        "%s:%d:[vlan:%d] phy_port:0x%x version:%d",
        __FUNCTION__, __LINE__,
        tx_port_number, physical_port, version);

  
    if (use_src == NULL)
        memcpy(&src_addr, &src_address, sizeof(IPV6_ADDRESS));
    else
        memcpy(&src_addr, use_src, sizeof(IPV6_ADDRESS));

    L2MCD_VLAN_LOG_DEBUG(tx_port_number,
        "%s:%d:[vlan:%d] Outgoing MLD Query src=%pI6 version=%d",
        __FUNCTION__, __LINE__, tx_port_number,
        &src_addr, version);

    if (mld_send_mld_message(
            mld, tx_port_number,
            physical_port,
            MLD_MEMBERSHIP_QUERY_TYPE,
            version,
            ip6_unspecified_address,              /* general query */
            src_addr,
            response_time,
            NULL, 
            FALSE, 
            FALSE))
    {
        L2MCD_VLAN_LOG_DEBUG(tx_port_number,
            "%s:%d:[vlan:%d] Sent MLD General Query src=%pI6",
            __FUNCTION__, __LINE__,
            tx_port_number, &src_addr);

        mld->mld_stats[tx_port_number].mld_xmt_gen_query_msg[version-1]++;
    }
    
}

BOOLEAN mld_send_group_query(MCGRP_CLASS     *mld, 
        MCGRP_MBRSHP*    mld_mbrshp,
        UINT16           tx_port_number,
        UINT32           physical_port,
        UINT8            version,
        IPV6_ADDRESS     group_address,
        IPV6_ADDRESS     src_ip,
        IPV6_ADDRESS     clnt_ip_addr,
        BOOLEAN          is_retx)
{

    BOOLEAN grp_deleted = FALSE;
    MADDR_ST group_addr, src_addr;
    MCGRP_L3IF        *mld_vport = NULL;
    MCGRP_PORT_ENTRY  *mld_pport = NULL;
    UINT32  response_time = 0;

    mld_vport  = gMld.port_list[tx_port_number];
    if(mld_vport == NULL)
    {
        return grp_deleted;
    }

    mld_pport  = mcgrp_find_phy_port_entry(mld, mld_vport, physical_port);
    if(mld_pport == NULL)
    {
        MLD_LOG(MLD_LOGLEVEL7,MLD_IP_IPV4_AFI,
                "IGMP:%s()%d  [ Port %d ] igmp_pport is NULL. ",FN,LN,
                physical_port);
        return grp_deleted;
    }

    if (mld_vport->LMQ_100ms_enabled == TRUE)
    {
        // LMQI is msec. convert as per RFC response time in pkt
        response_time = (mld_vport->LMQ_interval * 10)/1000;
    }
    else
    {   
        // convert as per RFC response time in pkt
        response_time = (mld_vport->LMQ_interval * 10);
    }

    if(mld_pport == NULL)
    {
        MLD_LOG(MLD_LOGLEVEL7,MLD_IP_IPV6_AFI,
                "MLD:%s()%d  [ Port %d ] mld_pport is NULL. ",FN,LN, 
                physical_port);
        return grp_deleted; 
    }

    if (mld_vport->tracking_enabled &&
            mld_pport->oper_version == MLD_VERSION_2 && IP6_IS_ADDRESS_NOT_NULL(clnt_ip_addr.address))
    {
        MLD_CLNT_LV_PARAM clnt_param;

        clnt_param.mld_vport   = mld_vport;
        clnt_param.mld_mbrshp  = mld_mbrshp;
        clnt_param.group_addr6   = group_address;
        clnt_param.src_list     = NULL;
        clnt_param.was_excl     = TRUE;
        clnt_param.clnt_ip_addr = clnt_ip_addr;

        grp_deleted = mld_track_v2_clnt_leave(mld, &clnt_param);
    }

    mcast_init_addr(&group_addr, IP_IPV6_AFI, MADDR_GET_FULL_PLEN(IP_IPV6_AFI));        
    mcast_init_addr(&src_addr, IP_IPV6_AFI, MADDR_GET_FULL_PLEN(IP_IPV6_AFI));      
    mcast_set_ipv6_addr(&group_addr, &group_address);
    mcast_set_ipv6_addr(&src_addr, &src_ip);

    // Send the Query if there is not one already queued or if this is a retransmit
    if (mld_mbrshp->retx_cnt == 0 || is_retx)
    {
        if (IP6_IS_ADDRESS_UNSPECIFIED(src_ip.address))
            src_ip = ip_get_lowest_ipv6_address_on_port(tx_port_number, mld_vport->type);

        if (mld_send_mld_message(mld, tx_port_number,
                    physical_port,
                    IGMP_MEMBERSHIP_QUERY_TYPE, 
                    version,
                    group_address,
                    src_ip,
                    response_time,  
                    NULL, FALSE,       // no srcs
                    is_retx))
        {
            L2MCD_VLAN_LOG_INFO(tx_port_number,"%s:%d:[vlan:%d] [ Port %s,%s. Grp %s ] Sent Grp-Qry Ver %d. ReTx %d(Cnt %d)",FN,LN,
                    tx_port_number, mld_get_if_name_from_port(physical_port), mld_get_if_name_from_port(tx_port_number), 
                    mcast_print_addr(&group_addr),
                    version,
                    is_retx,
                    mld_mbrshp->retx_cnt);         

            // Update stats
            mld->mld_stats[tx_port_number].mld_xmt_grp_query_msg++;
        }
        else
        {
            L2MCD_VLAN_LOG_DEBUG(tx_port_number,"%s:%d:[vlan:%d] [ Port %s,%s. Grp %s ] Skipped Grp-Qry Ver %d. ReTx %d(Cnt %d)",FN,LN,
                    tx_port_number, mld_get_if_name_from_port(physical_port), mld_get_if_name_from_port(tx_port_number), 
                    mcast_print_addr(&group_addr),
                    version,
                    is_retx,
                    mld_mbrshp->retx_cnt);         
        }
    }
    else
    {
        L2MCD_VLAN_LOG_DEBUG(tx_port_number,"%s:%d:[vlan:%d] [ Port %s,%s. Grp %s ] Skipped Grp-Qry Ver %d. ReTx %d(Cnt %d)",FN,LN,
                tx_port_number, mld_get_if_name_from_port(physical_port), mld_get_if_name_from_port(tx_port_number), 
                mcast_print_addr(&group_addr), version, is_retx, mld_mbrshp->retx_cnt);            
    }
    return grp_deleted;
}

int receive_mld_packet(IP6_RX_PKT_MSG *mld_pkt_msg)
{
    MADDR_ST                    group_addr;
    MCGRP_L3IF                  *mld_vport  = NULL;
    ICMP6_PSEUDO_HDR_MESSAGE    *icmp6h     = NULL;

    VRF_INDEX vrf_index = mld_pkt_msg->ip_param.vrf_index;
    USHORT rx_vir_port = mld_pkt_msg->ip_param.rx_port_number;
    UINT32 rx_phy_port = mld_pkt_msg->ip_param.rx_physical_port_number;
    UINT16 mld_packet_size = mld_pkt_msg->pkt_size;
    IPV6_HEADER *ip6h = (IPV6_HEADER *)mld_pkt_msg->pkt_data;
    MCGRP_CLASS *mld = MLD_GET_INSTANCE_FROM_VRFINDEX(vrf_index);
    UINT8 mldver = MLD_VERSION_NONE;
    UINT8 nexthdr = ip6h->next_header;
    UINT16 hbh_len;

    char *ifname = portdb_get_ifname_from_portindex(rx_phy_port);
    int vid = mld_l3_get_port_from_ifindex(rx_vir_port, MLD_VLAN);
    if (nexthdr == IPPROTO_HOPOPTS)
    {
        struct ipv6_hopopt_hdr *hbh = (struct ipv6_hopopt_hdr *)(mld_pkt_msg->pkt_data + sizeof(IPV6_HEADER));
        hbh_len = (hbh->hdrlen + 1) * 8;
        icmp6h = (ICMP6_PSEUDO_HDR_MESSAGE *)(mld_pkt_msg->pkt_data + sizeof(IPV6_HEADER) + hbh_len);
    }
    else if (nexthdr == IPPROTO_ICMPV6)
    {
        icmp6h = (ICMP6_PSEUDO_HDR_MESSAGE *)(mld_pkt_msg->pkt_data + sizeof(IPV6_HEADER));
    }

    if (!MCGRP_IS_VALID_INTF(rx_vir_port))
    {
        L2MCD_VLAN_LOG_ERR(vid, "%s:%d:[vlan:%d] : Invalid Rx Port %s. Dropping packet",FN,LN, 
                vid, mld_get_if_name_from_port(rx_vir_port));
    }

    mld_vport = gMld.port_list[rx_vir_port];
    if (!mld_vport)
    {
        L2MCD_VLAN_LOG_ERR(vid, "%s:%d:[vlan:%d]  [ Port %s,%s ] ignored received pkt as Port %s is down \n", FN, LN,
                           vid, ifname, mld_get_if_name_from_port(rx_vir_port),
                           (mld_vport == NULL ? mld_get_if_name_from_port(rx_vir_port) : mld_get_if_name_from_ifindex(rx_phy_port)));
        mld->rx_bad_if++;
    }
    mld->mld_stats[rx_vir_port].recv_packets++;
    // checksum
    if (!mld_check_if_checksum_is_valid(
            &mld_pkt_msg->ip_param.destination_address, &mld_pkt_msg->ip_param.source_address,
            icmp6h, mld_pkt_msg->ip_param.payload_length - hbh_len))
    {
        L2MCD_VLAN_LOG_ERR(vid, "%s:%d:[vlan:%d] ERR Rx packet has invalid checksum. Dropping packet", FN, LN, vid);
        mld->mld_stats[rx_vir_port].recv_checksum_error++;
    }

    // len + dest ip + proto + version check
    if (!mcast_validate_mld_packet(mld_pkt_msg))
    {
        L2MCD_VLAN_LOG_ERR(vid, "%s:%d:[vlan:%d] ERR Rx packet is invalid. Dropping packet", FN, LN, vid);
    }
    mld_pkt_msg->ip_param.hopbyhop_length = hbh_len;

    switch (icmp6h->type)
    {
    case MLD_MEMBERSHIP_QUERY_TYPE: // MLDv1v2 Query
        l2mcd_mld_process_query(mld_pkt_msg);
        break;
    case MLD_V1_MEMBERSHIP_REPORT_TYPE: // MLDv1 Report
        l2mcd_mld_process_v1_report(mld_pkt_msg);
        break;
    case MLD_V2_MEMBERSHIP_REPORT_TYPE: // MLDv2 Report
        l2mcd_mld_process_v2_report(mld_pkt_msg);
        break;
    case MLD_V1_MEMBERSHIP_DONE_TYPE: // MLDv1 Done
        l2mcd_mld_process_done(mld_pkt_msg);
        break;
    }
}