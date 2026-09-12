#include "l2mcd_mcast_co.h"
#include <stdio.h>
#include <netinet/in.h>
#include "l2mcd_mld_utils.h"
#include "l2mcd_mld_port.h"
#include "mld_struct.h"
#include "l2mcd_mcast_co.h"

void mld_enable (VRF_INDEX  vrf_index,  UINT8   protocol)
{
    MCGRP_CLASS  *mld=NULL;
    mld = MLD_GET_INSTANCE_FROM_VRFINDEX(vrf_index);
    if (mld == NULL)
    {
        mld = mcgrp_vrf_alloc(IP_IPV6_AFI, vrf_index);
        if (mld == NULL)
        {
            L2MCD_LOG_NOTICE("%s:%d vrf allocate fail vrf %d ", __FUNCTION__, __LINE__, vrf_index);
            return;
        }
    }

    // If IGMP needs to be initialized, do so.
    if (mld->first_time_init == FALSE)
    {
        // If initialization fails retain the first_time flag so that we can attempt again
        if (mcgrp_initialize(IP_IPV6_AFI, mld))
            mld->first_time_init = TRUE;
    }
    mld->enabled |= TRUE;

    static int group_address_offset = M_AVLL_OFFSETOF(GROUP_ENTRY, group_address.ip.v6addr);
    mld->group_tree= L2MCD_AVL_CREATE(l2mcd_avl_compare_addr6, (void *) &group_address_offset, NULL);
    L2MCD_LOG_NOTICE("%s Completed vrf:%d protocol:%d mld:%p group_tree:%p", __FUNCTION__,vrf_index, protocol, mld, mld->group_tree);
    return;
}

void in6_addr_to_ip6_union(
        const struct in6_addr *addr,
        IP6_UNION_IPV6_ADDRESS *out)
{
    memcpy(out->address8, addr->s6_addr, 16);
}

void mld_update_ve_member_ports (MCGRP_CLASS *mld,
        MCGRP_L3IF  *mld_vport,
        UINT8        version,
        BOOL         force)
{
    MCGRP_PORT_ENTRY *mld_pport;

    mld_pport = mld_vport->phy_port_list;

    // Update oper_version for all member ports that do not have an explicit configuration
    for (; mld_pport; mld_pport = mld_pport->next)
    { 
        if (mld_pport->cfg_version == MLD_VERSION_NONE)
        {
            mld_pport->oper_version = version;
        }
        else if (force)
        {
            mld_pport->oper_version = version;
            mld_pport->cfg_version  = mld_vport->cfg_version;
        }
    }
    (mld->mld_stats[mld_vport->vir_port_id]).mld_wrong_ver_query = 0;
}

void mld_set_global_version(VRF_INDEX vrf_index,
        UINT32    version,
        BOOL      force)
{
    MCGRP_CLASS       *mld= MLD_GET_INSTANCE_FROM_VRFINDEX(vrf_index);
    IP_PORT_DB_ENTRY  *portP;
    MCGRP_L3IF        *mld_vport;

    // When we reset the IGMP global version, the change needs to trickle
    // down to all ports that do not have an explicitly configured version.

    if (!force && mld->cfg_version == version)
        return;

    mld->cfg_version = (UINT8) version;
    if (mld->cfg_version == MLD_VERSION_NONE)
        mld->oper_version = MLD_VERSION_DEFAULT;
    else
        mld->oper_version = mld->cfg_version;

    if (! mld->enabled)
        return;

    // Walk thru all ports updating the port version for non-configured ports
    for (portP = IP_PORT_DB_HEAD; portP != NULL; IP_PORT_DB_NEXT(portP))
    {
        mld_vport = gMld.port_list[portP->port_number];

        // If the port does not exist or is part of a virtual port
        // or has a version explicitly configured, skip it.
        // The reason why we skip virtual port members is that they are taken care of later
        if (mld_vport == NULL ||
                (!force && (mld_vport->cfg_version != MLD_VERSION_NONE)) )
        {
            continue;
        }

        // Update this port's 
        mld_vport->oper_version = mld->oper_version;
        if (force)
            mld_vport->cfg_version = mld->cfg_version;

        // and if this is a virtual port, update its member ports too.
        if (MCGRP_IS_PORT_VIRTUAL(mld_vport))
        {
            mld_update_ve_member_ports(mld, mld_vport, (UINT8)mld_vport->oper_version, 
                    force);
        }
        else
        {
            if (mld_vport->phy_port_list)
            { 
                mld_vport->phy_port_list->oper_version = mld_vport->oper_version;
                (mld->mld_stats[mld_vport->vir_port_id]).mld_wrong_ver_query = 0;
            }
        }
    }
} 

void mld_reset_default_values(MCGRP_CLASS *mld)
{
    mld->cfg_query_interval_time = CU_DFLT_IGMP_QUERY_INTERVAL;
    mld->query_interval_time     = CU_DFLT_IGMP_QUERY_INTERVAL;
    mld->max_response_time       = CU_DFLT_IGMP_RESPONSE_TIME;
    mld->group_membership_time   = CU_DFLT_IGMP_GROUP_MEMBERSHIP_TIME;
    mld->older_host_present_time = CU_DFLT_IGMP_OLDER_HOST_PRESENT_TIME;
    mld->robustness_var          = IGMP_DEFAULT_ROBUSTNESS_VARIABLE;
    mld->cfg_robustness_var      = IGMP_DFLT_ROBUSTNESS;
    mld->max_groups              = CU_DFLT_IGMP_MAX_GROUP_ADDRESS;
    mld->pim_prune_wait_interval = 3;
    mld->LMQ_interval            = 1;      /* seconds */
    mld->LMQ_count               = mld->robustness_var;
    mld->router_alert_check_disable = FALSE;

    mld_set_global_version(mld->vrf_index, IGMP_VERSION_NONE, TRUE);
}

// This function is invoked to process a change in an interface's (VE or otherwise) version
int mld_set_if_mld_version (VRF_INDEX  vrf_index, 
        UINT16     vport, 
        UINT8      version)
{
    MCGRP_CLASS  *mld = MLD_GET_INSTANCE_FROM_VRFINDEX(vrf_index);
    MCGRP_L3IF   *mld_vport;

    if (!MCGRP_IS_VALID_INTF(vport))
    {
        return -1;
    }

    mld_vport = gMld.port_list[vport];
    if (mld_vport == NULL)
    {
        mld_vport = mcgrp_alloc_init_l3if_entry(mld, vport);
        if (!mld_vport)
            return -1;
        mld_vport->is_up = FALSE;
    }
    else
    {
        if (mld_vport->cfg_version == version)
            return 0;
    }

    L2MCD_LOG_DEBUG("%s(%d) vport:%d version:%d Prev vport->cfg_version:%d ", __FUNCTION__, __LINE__,
            vport, version, mld_vport->cfg_version);
    mld_vport->cfg_version  = version;
    mld_vport->oper_version = (mld_vport->cfg_version == MLD_VERSION_NONE) ?
        mld->oper_version : mld_vport->cfg_version;

    // Update the version for this VE's member ports if this is a virtual port
    if (MCGRP_IS_PORT_VIRTUAL(mld_vport))
    {
        mld_update_ve_member_ports(mld, mld_vport, (UINT8) mld_vport->oper_version,
                FALSE /* do not force */);
    }
    else
    { 
        if (mld_vport->phy_port_list)
        {
            mld_vport->phy_port_list->oper_version = mld_vport->oper_version;
            (mld->mld_stats[mld_vport->vir_port_id]).mld_wrong_ver_query = 0;
            L2MCD_LOG_DEBUG("%s(%d) phy_port:%d oper_version:%d ", __FUNCTION__, __LINE__, 
                    mld_vport->phy_port_list->phy_port_id, mld_vport->phy_port_list->oper_version);
        }
    }
    mcgrp_handle_intf_ver_change(mld, mld_vport);
    return 0;
}

enum BOOLEAN mld_check_valid_range(IPV6_ADDRESS *group_address)
{
    if (group_address->address.address8[0] != 0xFF)
        return FALSE;

    IPV6_ADDRESS allnodes = IP6_ADDRESS_LINKLOCAL_ALLNODES_INIT;
    IPV6_ADDRESS allrouters = IP6_ADDRESS_LINKLOCAL_ALLROUTERS_INIT;
    IPV6_ADDRESS mldv2 = IP6_ADDRESS_MLDV2_ALLROUTERS_INIT;

    if (memcmp(group_address, &allnodes, sizeof(IPV6_ADDRESS)) == 0 ||
        memcmp(group_address, &allrouters, sizeof(IPV6_ADDRESS)) == 0 ||
        memcmp(group_address, &mldv2, sizeof(IPV6_ADDRESS)) == 0)
    {
        return FALSE;
    }

    if (IP6_IS_ADDRESS_MC_SOLICITEDNODE(group_address->address))
    {
        return FALSE;
    }

    UINT8 scope = group_address->address.address8[1] & 0x0F;
    // Link-Local(2) Admin-Local(4) Site-Local(5)
    // Organization-Local(8) Global(E) Reserve(0,3,F)
    if (scope == 0x0 || scope == 0x2 || scope == 0x3 || scope == 0x4 || scope == 0x5 || scope == 0x8 || scope == 0xE || scope == 0xF)
        return TRUE;

    return FALSE;
}
