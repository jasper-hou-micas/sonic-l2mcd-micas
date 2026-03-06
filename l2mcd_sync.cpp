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

#include <string.h>
#include <errno.h>
#include <system_error>
#include <sys/socket.h>
#include <chrono>
#include <string>
#include "dbconnector.h"
#include "producerstatetable.h"
#include "l2mcd.h"
#include "l2mcd_sync.h"
#include <algorithm> 
#include "notificationproducer.h"
#include "tokenize.h"

#define L2MC_APPL_NOTIFICATIONS             "L2MC_NOTIFICATIONS"
#define L2MC_APPL_MROUTE_NOTIFICATIONS      "L2MC_MROUTER_NOTIFICATIONS"
#define L2MC_APPL_CONFIG_NOTIFICATIONS      "L2MC_CONFIG_PARA_DONE"
#define L2MC_APPL_WARMREBOOT_NOTIFICATIONS  "L2MC_WARMREBOOT_NOTIFICATIONS"

using namespace std;
using namespace swss;

void l2mcd_debugCLI(std::string s, KeyOpFieldsValuesTuple t);
string g_L2McdCompstring = "l2mcd_debug";

L2mcSync::L2mcSync(DBConnector *db, DBConnector *cfgDb, DBConnector *stateDb) :
    m_appVlanProducerTable(db, APP_L2MC_VLAN_TABLE_NAME),
    m_appEntryProducerTable(db,  APP_L2MC_MEMBER_TABLE_NAME),
    m_appMrouterProducerTable(db, APP_L2MC_MROUTER_TABLE_NAME),
    m_appSuppressProducerTable(db, APP_L2MC_SUPPRESS_TABLE_NAME),
    m_statel2mcdLocalMemberTable(stateDb, STATE_L2MC_MEMBER_TABLE_NAME),
    m_statel2mcdLocalMrouterTable(stateDb, STATE_L2MC_MROUTER_TABLE_NAME),
    m_featureTable(cfgDb, CFG_FEATURE_TABLE_NAME),
    m_appVlanTable(db, APP_L2MC_VLAN_TABLE_NAME),
    m_appEntryTable(db, APP_L2MC_MEMBER_TABLE_NAME),
    m_appMrouteTable(db, APP_L2MC_MROUTER_TABLE_NAME),
    m_appSuppressTable(db, APP_L2MC_SUPPRESS_TABLE_NAME)
{
    SWSS_LOG_NOTICE("L2MCD: sync object");
    l2mc_entry_notifications = new swss::NotificationProducer(db, L2MC_APPL_NOTIFICATIONS);
    l2mc_mrouter_notifications = new swss::NotificationProducer(db, L2MC_APPL_MROUTE_NOTIFICATIONS);
    l2mc_cfg_done_notifications = new swss::NotificationProducer(db, L2MC_APPL_CONFIG_NOTIFICATIONS);
    l2mc_warm_reboot_notifications = new swss::NotificationProducer(db, L2MC_APPL_WARMREBOOT_NOTIFICATIONS);

    m_mclagTable = std::unique_ptr<Table>(new Table(cfgDb, CFG_MCLAG_TABLE_NAME));
}

L2mcSync::~L2mcSync()
{
    if (l2mc_entry_notifications)
    {
        delete l2mc_entry_notifications;
    }
    if (l2mc_mrouter_notifications)
    {
        delete l2mc_mrouter_notifications;
    }
    if (l2mc_cfg_done_notifications)
    {
        delete l2mc_cfg_done_notifications;
    }
    if (l2mc_warm_reboot_notifications)
    {
        delete l2mc_warm_reboot_notifications;
    }
}

DBConnector db(APPL_DB, DBConnector::DEFAULT_UNIXSOCKET, 0);
DBConnector cfgDb(CONFIG_DB, DBConnector::DEFAULT_UNIXSOCKET, 0);
DBConnector stateDb(STATE_DB, DBConnector::DEFAULT_UNIXSOCKET, 0);
L2mcSync l2mcsync(&db, &cfgDb, &stateDb);
extern "C" void l2mcd_dump_vdb_brief(int id);
extern "C" void l2mcd_dump_vdb_stats(int id);
extern "C" void l2mcd_dump_portdb(void);
extern "C" void l2mcd_dump_groups(int id, int flag);
extern "C" void l2mcd_print_vars(void);
extern "C" void l2mcd_set_loglevel_w(int level);
extern "C" void l2mcd_dump_vdb_ports(int vid);
extern "C" void l2mcd_dump_ve_portdb_tree(void);
extern "C" void l2mcd_dump_port_vlan_bm(void);
extern "C" int l2mcd_is_peerlink(char *portname);
extern "C" void l2mcd_clr_snooping(int vid);
extern "C" void l2mcd_clr_snooping_stats(int vid);
extern "C" {

    void l2mcsync_add_vlan_entry(uint16_t vlan_id)
    {
        l2mcsync.addL2mcVlanEntry(vlan_id);
    }
    int l2mcdsync_get_l2mcmgr_debug_prio()
    {
        return l2mcsync.getL2mcMgrDebugPrio();
    }  
    void l2mcsync_del_vlan_entry(uint16_t vlan_id)
    {
        l2mcsync.delL2mcVlanEntry(vlan_id);
    }
    void l2mcsync_add_l2mc_entry(L2MCD_APP_TABLE_ENTRY *msg)
    {
        l2mcsync.addL2mcTableEntry(msg);
    }
    void l2mcsync_del_l2mc_entry(L2MCD_APP_TABLE_ENTRY *msg)
    {
        l2mcsync.delL2mcTableEntry(msg);
    }
    void l2mcsync_process_mrouterentry(L2MCD_APP_TABLE_ENTRY *msg)
    {
        l2mcsync.processL2mcMrouterTableEntry(msg);
    }
    void l2mcsync_debug_print(const char *fmt, ...)
    {
        char dump_str[200];
        va_list args;
        va_start(args,fmt);
        vsnprintf(dump_str, 200, fmt, args);
        va_end(args);
        SWSS_LOG_DEBUG("%s", dump_str);
    }
    int l2mcd_is_peerlink(char *portname)
    {
        return l2mcsync.isPortPeerLink(portname);
    }
    void l2mcsync_notify_config_done(char *option, char *paraname)
    {
        l2mcsync.notify_config_done(option, paraname);
    }
    void l2mcsync_notify_warm_reboot_done(char *option, char *paraname)
    {
        l2mcsync.notify_warm_reboot_done(option, paraname);
    }
    void l2mcsync_clear_l2mc_entry()
    {
        l2mcsync.clearL2mcVlanEntry();
    }
    int l2mcsync_get_l2mc_info_count(uint16_t vlan_id, uint16_t afi)
    {
        return l2mcsync.getL2mcVlanEntryCount(vlan_id, afi);
    }
    void l2mcsync_dump_l2mc_info(DUMP_L2MCD_APP_TABLE_ENTRY *msg)
    {
        l2mcsync.dumpL2mcVlanEntry(msg);
    }
}

int L2mcSync::getL2mcMgrDebugPrio(void)
{
    return (swss::Logger::getInstance().getMinPrio());
}

void L2mcSync::notify_config_done(std::string option, std::string paraname)
{
    std::vector<swss::FieldValueTuple> value;
    FieldValueTuple s("state", "done");
    value.push_back(s);
    l2mc_cfg_done_notifications->send(option, paraname, value);
}

void L2mcSync::notify_warm_reboot_done(std::string option, std::string paraname)
{
    std::vector<swss::FieldValueTuple> value;
    FieldValueTuple s("state", "done");
    value.push_back(s);
    l2mc_warm_reboot_notifications->send(option, paraname, value);
}

void L2mcSync::clearL2mcVlanEntry(void)
{
    SWSS_LOG_NOTICE("clear All L2mc Entry");
    bool l2mcd_state = false;

    std::vector<string> feature_keys;
    m_featureTable.getKeys(feature_keys);
    for (auto i: feature_keys)
    {
        if (i != "l2mcd")
            continue;
        std::vector<swss::FieldValueTuple> feature_fvs;
        m_featureTable.get(i, feature_fvs);
        for (auto f: feature_fvs)
        {
            if (fvField(f) == "state")
            {
                l2mcd_state = fvValue(f) == "enabled";
                SWSS_LOG_NOTICE("l2mcd state: %s, %d", fvValue(f).c_str(), l2mcd_state);
                break;
            }
        }
    }
    // feature enabled and maybe warm-restart
    if (l2mcd_state)
    {
        SWSS_LOG_NOTICE("l2mcd state is still Enabled, there is no need to clear the l2mc entry");
        return;
    }
    // feature disable and clear l2mcd entry
    std::vector<string> l2mcd_keys;
    m_statel2mcdLocalMemberTable.getKeys(l2mcd_keys);
    for (auto i: l2mcd_keys)
    {
        m_statel2mcdLocalMemberTable.del(i);
    }
    m_statel2mcdLocalMrouterTable.getKeys(l2mcd_keys);
    for (auto i: l2mcd_keys)
    {
        m_statel2mcdLocalMrouterTable.del(i);
    }

    m_appSuppressTable.getKeys(l2mcd_keys);
    for (auto i: l2mcd_keys)
    {
        m_appSuppressProducerTable.del(i);
    }
    m_appEntryTable.getKeys(l2mcd_keys);
    for (auto i: l2mcd_keys)
    {
        m_appEntryProducerTable.del(i);
    }
    m_appMrouteTable.getKeys(l2mcd_keys);
    for (auto i: l2mcd_keys)
    {
        m_appMrouterProducerTable.del(i);
    }
    m_appVlanTable.getKeys(l2mcd_keys);
    for (auto i: l2mcd_keys)
    {
        m_appVlanProducerTable.del(i);
    }
}

void L2mcSync::addL2mcVlanEntry(uint16_t vlan_id)
{
    std::vector<FieldValueTuple> fvVector;
    string vlan;

    vlan = VLAN_PREFIX + to_string(vlan_id);
    FieldValueTuple s("id", to_string(vlan_id));
    fvVector.push_back(s);
    m_appVlanProducerTable.set(vlan, fvVector);
    SWSS_LOG_NOTICE("APP_L2MC_VLAN_TABLE Add %s to L2MC ", vlan.c_str());
}

void L2mcSync::delL2mcVlanEntry(uint16_t vlan_id)
{
    string vlan;

    vlan = VLAN_PREFIX + to_string(vlan_id);
    m_appVlanProducerTable.del(vlan);

    SWSS_LOG_NOTICE("APP_L2MC_VLAN_TABLE Delete %s from L2MC ", vlan.c_str());
}

void L2mcSync::addL2mcTableEntry(L2MCD_APP_TABLE_ENTRY *msg)
{
    string key;
    string stateKey;
    string type = "dynamic";
    std::vector<FieldValueTuple> fvVector;
    std::vector<FieldValueTuple> fvVector1;
    std::vector<swss::FieldValueTuple> entry;

    key = VLAN_PREFIX + to_string(msg->vlan_id)+L2MCD_DEFAULT_KEY_SEPARATOR;
    key.append(msg->saddr);
    key.append(L2MCD_DEFAULT_KEY_SEPARATOR);
    key.append(msg->gaddr);
    key.append(L2MCD_DEFAULT_KEY_SEPARATOR);
    key.append(msg->port.pnames);
    stateKey = VLAN_PREFIX + to_string(msg->vlan_id)+L2MCD_STATE_KEY_SEPARATOR;
    stateKey.append(msg->saddr);
    stateKey.append(L2MCD_STATE_KEY_SEPARATOR);
    stateKey.append(msg->gaddr);
    stateKey.append(L2MCD_STATE_KEY_SEPARATOR);
    stateKey.append(msg->port.pnames);

    if(msg->is_static) type.assign("static");
    if(msg->is_remote) type.assign("remote");
    FieldValueTuple s("type", type.c_str());
    fvVector.push_back(s);
    if (!msg->op_code)
    {
        SWSS_LOG_NOTICE("APP_L2MC_ENTRY_TABLE Group-DEL key:%s vid:%d G:%s sa:%s port %s static:%d is_remote:%d ", key.c_str(), msg->vlan_id, msg->gaddr, msg->saddr, msg->port.pnames, msg->is_static,msg->is_remote);
        m_appEntryProducerTable.del(key);
        if (!m_statel2mcdLocalMemberTable.get(stateKey, fvVector1))
        {
            SWSS_LOG_NOTICE("STATE_L2MC_ENTRY_TABLE Group-DEL key:%s vid:%d G:%s sa:%s port %s static:%d Not Exists ", key.c_str(), msg->vlan_id, msg->gaddr, msg->saddr, msg->port.pnames, msg->is_static);
            return;
        }
        m_statel2mcdLocalMemberTable.del(stateKey);

        stateKey.append(L2MCD_STATE_KEY_SEPARATOR);
        if (msg->is_static)
            stateKey.append("static");
        else
            stateKey.append("dynamic");
        stateKey.append(L2MCD_STATE_KEY_SEPARATOR);
        if (msg->port_oper)
            stateKey.append("LEAVE");
        l2mc_entry_notifications->send("DEL", stateKey, entry);
    }
    else
    {
        SWSS_LOG_NOTICE("APP_L2MC_ENTRY_TABLE Group-ADD key:%s vid:%d G:%s sa:%s port %s static:%d,is_remote:%d  ", key.c_str(), msg->vlan_id, msg->gaddr, msg->saddr, msg->port.pnames, msg->is_static, msg->is_remote);
        m_appEntryProducerTable.set(key,fvVector);
        if (m_statel2mcdLocalMemberTable.get(stateKey, fvVector1))
        {
            SWSS_LOG_NOTICE("STATE_L2MC_ENTRY_TABLE Group-ADD key:%s vid:%d G:%s sa:%s port %s static:%d Exists ", key.c_str(), msg->vlan_id, msg->gaddr, msg->saddr, msg->port.pnames, msg->is_static);
            return;
        }
        m_statel2mcdLocalMemberTable.set(stateKey, fvVector);

        stateKey.append(L2MCD_STATE_KEY_SEPARATOR);
        if (msg->is_static)
            stateKey.append("static");
        else
            stateKey.append("dynamic");
        l2mc_entry_notifications->send("SET", stateKey, entry);
    }

}

void L2mcSync::delL2mcTableEntry(L2MCD_APP_TABLE_ENTRY *msg)
{
    string key;
    key = VLAN_PREFIX + to_string(msg->vlan_id) +  L2MCD_DEFAULT_KEY_SEPARATOR + "*"+L2MCD_DEFAULT_KEY_SEPARATOR;
    key +=msg->gaddr;
    SWSS_LOG_NOTICE("APP_L2MC_ENTRY_TABLE Group delete vid:%d G:%s ", msg->vlan_id, msg->gaddr);
    m_appEntryProducerTable.del(key);

}

void L2mcSync::processL2mcMrouterTableEntry(L2MCD_APP_TABLE_ENTRY *msg)
{
    string key;
    string stateKey;
    string type = "dynamic";
    std::vector<FieldValueTuple> fvVector;
    std::vector<FieldValueTuple> fvVector1;
    std::vector<swss::FieldValueTuple> entry;

    key = VLAN_PREFIX + to_string(msg->vlan_id) + L2MCD_DEFAULT_KEY_SEPARATOR;
    key.append(msg->port.pnames);
    stateKey = VLAN_PREFIX + to_string(msg->vlan_id) + L2MCD_STATE_KEY_SEPARATOR;
    stateKey.append(msg->port.pnames);
    if (msg->is_igmp)
    {
        key = key + ":V4";
        stateKey = stateKey + "|V4";
    }
    else
    {
        key = key + ":V6";
        stateKey = stateKey + "|V6";
    }

    if(msg->is_static) type.assign("static");
    FieldValueTuple s("type", type.c_str());
    fvVector.push_back(s);

    if (msg->op_code)
    {
        SWSS_LOG_NOTICE("APP_L2MC_MROUTER_TABLE:Key:%s stateKey:%s Vlan%d:%s mrouter add",key.c_str(), stateKey.c_str(),
                msg->vlan_id, msg->port.pnames);
        m_appMrouterProducerTable.set(key,fvVector);
        if (m_statel2mcdLocalMrouterTable.get(stateKey, fvVector1))
        {
            SWSS_LOG_NOTICE("STATE_L2MC_MROUTER_TABLE Mroute port Add key:%s vid:%d port %s static:%d Exists ", stateKey.c_str(), 
                    msg->vlan_id, msg->port.pnames, msg->is_static);
            return;
        }
        m_statel2mcdLocalMrouterTable.set(stateKey, fvVector);
        
        stateKey.append(L2MCD_STATE_KEY_SEPARATOR);
        if (msg->is_static)
            stateKey.append("static");
        else
            stateKey.append("dynamic");
        l2mc_mrouter_notifications->send("SET", stateKey, entry);
    }
    else
    {
        m_appMrouterProducerTable.del(key);
        SWSS_LOG_NOTICE("APP_L2MC_MROUTER_TABLE:Key:%s stateKey:%s Vlan%d:%s mrouter entry deleted", key.c_str(),
                stateKey.c_str(), msg->vlan_id, msg->port.pnames);

        if (!m_statel2mcdLocalMrouterTable.get(stateKey, fvVector1))
        {
            SWSS_LOG_NOTICE("STATE_L2MC_MROUTER_TABLE Mroute port DEL key:%s vid:%d port %s static:%d Not Exists ", stateKey.c_str(), 
                    msg->vlan_id, msg->port.pnames, msg->is_static);
            return;
        }
        m_statel2mcdLocalMrouterTable.del(stateKey);

        stateKey.append(L2MCD_STATE_KEY_SEPARATOR);
        if (msg->is_static)
            stateKey.append("static");
        else
            stateKey.append("dynamic");
        
        stateKey.append(L2MCD_STATE_KEY_SEPARATOR);
        if (msg->port_oper)
            stateKey.append("LEAVE");
        l2mc_mrouter_notifications->send("DEL", stateKey, entry);
    }
}

void l2mcd_debugCLI(std::string s, KeyOpFieldsValuesTuple t)
{
    string group = "dumpall";
    string keywd = kfvKey(t);
    string vid;
    string levelString;
    int vlan_id=0,level=0;
    int i=0;
    SWSS_LOG_NOTICE("L2MCD: Debug CLI key-%s",keywd.c_str());

    if (keywd != g_L2McdCompstring)
    {
        SWSS_LOG_NOTICE("Keywd wrong %s", keywd.c_str());
        return;
    }
    g_l2mcd_fwk_dbg_mode = 1;

    for (auto i : kfvFieldsValues(t))
    {
        if (fvField(i) == "group")
        {
            group = fvValue(i);
        }
        else if (fvField(i) == "vid")
        {
            vid = fvValue(i);
            vlan_id = stoi(vid.c_str());
        }
        else if (fvField(i) == "level")
        {
            levelString = fvValue(i);
            level = stoi(levelString.c_str());
        }
        else
        {
            string field = fvField(i);
            string value = fvValue(i);
            SWSS_LOG_DEBUG("L2MCD: Rcvd field %s, Value %s", field.c_str(), value.c_str());
        }
    }

    if (group =="vdb")
    {
        l2mcd_dump_vdb_brief(vlan_id);
    }
    else if (group =="vdb_stats")
    {
        l2mcd_dump_vdb_stats(vlan_id);
    }
    else if (group =="igmp_groups")
    {
        l2mcd_dump_groups(vlan_id, 0);
    }
    else if (group =="clear_groups")
    {
    l2mcd_clr_snooping(vlan_id);
    }
    else if (group =="clear_stats")
    {
    l2mcd_clr_snooping_stats(vlan_id);
    }
    else if (group == "ports")
    {
        l2mcd_dump_portdb();
    }
    else if (group == "global")
    {
        l2mcd_print_vars();
    }
    else if (group == "dumpall")
    {
        l2mcd_print_vars();
        l2mcd_dump_portdb();
        l2mcd_dump_vdb_brief(0);
        l2mcd_dump_vdb_stats(0);
        l2mcd_dump_groups(0,1);
        l2mcd_dump_vdb_ports(0);
        l2mcd_dump_ve_portdb_tree();
        l2mcd_dump_port_vlan_bm();
    }
    else if (group == "vlanLog")
    {
        g_l2mcd_vlan_dbg_to_sys_log = TRUE;
        if (level)
        {
            g_l2mcd_vlan_log_mask = level;
        }
        if (!vlan_id)
        {
            memset(&g_l2mcd_pkt_log[0], 0, L2MCD_VLAN_MAX);
            g_l2mcd_vlan_dbg_to_sys_log = FALSE;
            L2MCD_CLI_PRINT("Disable Vlan sys logging for all tags global_level_mask:%x", g_l2mcd_vlan_log_mask);
        }
        else if (vlan_id == L2MCD_VLAN_MAX)
        {
            memset(&g_l2mcd_pkt_log[0], 1, L2MCD_VLAN_MAX);
            L2MCD_CLI_PRINT("Enable Vlan sys logging for all tags global_level_maskk:%x", g_l2mcd_vlan_log_mask);
            g_l2mcd_dbg_vlan_log_all = TRUE;
        }
        else
        {
            g_l2mcd_pkt_log[vlan_id & 0xFFF] = level ? 1 : 0;
            L2MCD_CLI_PRINT("vlan logging %s for vid:%d global_level_mask:0x%x", level ? "Enabled" : "Disabled", vlan_id, g_l2mcd_vlan_log_mask);
        }
        g_l2mcd_dbg_vlan_log_all = TRUE;
        for (i = 0; i < L2MCD_VLAN_MAX; i++)
            g_l2mcd_dbg_vlan_log_all &= g_l2mcd_pkt_log[i];
    }
    else if (group == "dbgLevel")
    {
        l2mcd_set_loglevel_w(level);
    }
    SWSS_LOG_NOTICE(" l2mcd debug command:  group:%s vid %s(%d) global_level_mask:%d, g_l2mcd_dbg_vlan_log_all:%d", group.c_str(), vid.c_str(), vlan_id,g_l2mcd_vlan_log_mask,g_l2mcd_dbg_vlan_log_all);
    g_l2mcd_fwk_dbg_mode=0;
}

bool L2mcSync::isPortPeerLink(std::string portname)
{
    std::vector<std::string> keys;
    std::string peerlink;

    m_mclagTable->getKeys(keys);    
    if (keys.empty()) {
        return 0;
    }
    for (auto &k : keys) {
        m_mclagTable->hget(k, "peer_link", peerlink);
        if (portname == peerlink)
            return 1;
    }
    return 0;
}
int L2mcSync::getL2mcVlanEntryCount(uint16_t vlan_id, uint16_t afi)
{
    int count = 0;
    int vlanid = 0;
    std::vector<string> l2mcd_keys;
    m_appEntryTable.getKeys(l2mcd_keys);
    for (auto key: l2mcd_keys)
    {
        vector<string> keys = tokenize(key, ':');

        if (keys.size() < 4)
        {
            SWSS_LOG_ERROR("Invalid key size, skipping %s", key.c_str());
            continue;
        }
        
        /* Ensure the key starts with "Vlan" otherwise ignore */
        if (strncmp(keys[0].c_str(), VLAN_PREFIX, 4))
        {
            SWSS_LOG_ERROR("Invalid key format. No 'Vlan' prefix: %s", keys[0].c_str());
            continue;
        }

        int  vlanid;

        vlanid = stoi(keys[0].substr(4));
        if (vlanid != vlan_id)
            continue;

        string source_addr, group_addr;
        
        if (keys.size() == 4)
        {
            /*IPv4 addresses*/
            source_addr = keys[1];
            group_addr = keys[2];
        }
        else
        {
            /*IPv6 addresses*/
            vector<string> address_parts(keys.begin() + 1, keys.end() - 1);

            SWSS_LOG_NOTICE(" address_parts size %lu", address_parts.size());
            
            if (address_parts.size() == 16)
            {
                size_t mid_point = 8;
                
                source_addr = address_parts[0];
                for (size_t i = 1; i < mid_point; i++)
                {
                    source_addr += ":" + address_parts[i];
                }
                
                group_addr = address_parts[mid_point];
                for (size_t i = mid_point + 1; i < address_parts.size(); i++)
                {
                    group_addr += ":" + address_parts[i];
                }
            }
            else
            {
                SWSS_LOG_ERROR("Invalid IPv6 address format in key %s", key.c_str());
                continue;
            }
        }

        bool is_v6 = (group_addr.find(':') != string::npos);
        if ((is_v6 && afi == 2) || (!is_v6 && afi == 1))
        {
            count++;
            SWSS_LOG_INFO(" l2mc group count %d", count);
        }
    }
    l2mcd_keys.clear();
    m_appMrouteTable.getKeys(l2mcd_keys);
    for (auto key: l2mcd_keys)
    {
        vector<string> keys = tokenize(key, ':');
        if (keys.size() != 3)
        {
            SWSS_LOG_ERROR("Invalid key size, skipping %s", key.c_str());
            continue;
        }
        if (strncmp(keys[0].c_str(), VLAN_PREFIX, 4))
        {
            SWSS_LOG_ERROR("Invalid key format. No 'Vlan' prefix: %s", keys[0].c_str());
            continue;
        }
        std::string protocol;

        vlanid = stoi(keys[0].substr(4));
        if (vlanid != vlan_id)
            continue;
        protocol = keys[2];

        if ((protocol == "V4" && afi == 1) || (protocol == "V6" && afi == 2))
        {
            count++;
            SWSS_LOG_INFO(" mrouter count %d", count);
        }
    }
    return count ;
}

void L2mcSync::dumpL2mcVlanEntry(DUMP_L2MCD_APP_TABLE_ENTRY *msg)
{
    int vlan_id, afi;
    uint32_t idx = 0;
    
    vlan_id = msg->vlan_id;
    afi = msg->afi;

    std::vector<string> l2mcd_keys;

    m_appEntryTable.getKeys(l2mcd_keys);
    for (auto key: l2mcd_keys)
    {
        msg->count = idx;
        if (idx >= msg->max_count)
            return;
        vector<string> keys = tokenize(key, ':');
        /* Key: <VLAN_name>:<source_address>:<group_address>:<member_port> */

        /* Ensure the key has at least 4 fields otherwise ignore */

        if (keys.size() < 4)
        {
            SWSS_LOG_ERROR("Invalid key size, skipping %s", key.c_str());
            continue;
        }
        
        /* Ensure the key starts with "Vlan" otherwise ignore */
        if (strncmp(keys[0].c_str(), VLAN_PREFIX, 4))
        {
            SWSS_LOG_ERROR("Invalid key format. No 'Vlan' prefix: %s", keys[0].c_str());
            continue;
        }

        int vlanid;
        std::string port_alias;

        vlanid = stoi(keys[0].substr(4));
        if (vlanid != vlan_id)
            continue;
        
        port_alias = keys[keys.size() - 1];

        string source_addr, group_addr;
        
        if (keys.size() == 4)
        {
            /*IPv4 addresses*/
            source_addr = keys[1];
            group_addr = keys[2];
        }
        else
        {
            /*IPv6 addresses*/
            vector<string> address_parts(keys.begin() + 1, keys.end() - 1);

            SWSS_LOG_NOTICE(" address_parts size %lu", address_parts.size());
            
            if (address_parts.size() == 16)
            {
                size_t mid_point = 8;
                
                source_addr = address_parts[0];
                for (size_t i = 1; i < mid_point; i++)
                {
                    source_addr += ":" + address_parts[i];
                }
                
                group_addr = address_parts[mid_point];
                for (size_t i = mid_point + 1; i < address_parts.size(); i++)
                {
                    group_addr += ":" + address_parts[i];
                }
            }
            else
            {
                SWSS_LOG_ERROR("Invalid IPv6 address format in key %s", key.c_str());
                continue;
            }
        }

        bool is_v6 = (group_addr.find(':') != string::npos);
        if ((is_v6 && afi != 2) || (!is_v6 && afi != 1))
            continue;

        L2MCD_APP_TABLE_ENTRY &entry = msg->data[idx];
        memset(&entry, 0, sizeof(entry));

        entry.op_code   = 1;
        std::vector<swss::FieldValueTuple> value;
        if (m_appEntryTable.get(key, value))
        {
            auto it_en = std::find_if(
                value.begin(), value.end(),
                [](auto &t){ return t.first == "type"; });

            if (it_en != value.end() && fvValue(*it_en) == "dynamic")
                entry.is_static = 0;
            else 
                entry.is_static = 1;
        }
        entry.vlan_id   = vlanid;
        entry.is_igmp = (afi == 1) ? TRUE : FALSE;
        memcpy(entry.port.pnames, port_alias.c_str() , L2MCD_IFNAME_SIZE);
        memcpy(entry.gaddr,group_addr.c_str(), L2MCD_IP_ADDR_STR_SIZE);
        memcpy(entry.saddr,source_addr.c_str(), L2MCD_IP_ADDR_STR_SIZE);

        idx++;

    }
    l2mcd_keys.clear();
    m_appMrouteTable.getKeys(l2mcd_keys);
    for (auto key: l2mcd_keys)
    {
        msg->count = idx;
        if (idx >= msg->max_count)
            return;
        vector<string> keys = tokenize(key, ':');
        
        /* Key: <VLAN_name>:<mrouter_port> */

        /* Ensure the key size is 1 otherwise ignore */
        if (keys.size() != 3)
        {
            SWSS_LOG_ERROR("Invalid key size, skipping %s", key.c_str());
            continue;
        }

        /* Ensure the key starts with "Vlan" otherwise ignore */
        if (strncmp(keys[0].c_str(), VLAN_PREFIX, 4))
        {
            SWSS_LOG_ERROR("Invalid key format. No 'Vlan' prefix: %s", keys[0].c_str());
            continue;
        }
        int vlanid ;
        vlanid = stoi(keys[0].substr(4));
        if (vlanid != vlan_id)
            continue;

        std::string port_alias, protocol;
        port_alias = keys[1];
        protocol = keys[2];

        if ((protocol == "V4" && afi != 1) || (protocol == "V6" && afi != 2))
            continue;
        
        L2MCD_APP_TABLE_ENTRY &entry = msg->data[idx];
        memset(&entry, 0, sizeof(entry));

        entry.op_code   = 1;
        std::vector<swss::FieldValueTuple> value;
        if (m_appMrouteTable.get(key, value))
        {
            auto it_en = std::find_if(
                value.begin(), value.end(),
                [](auto &t){ return t.first == "type"; });

            if (it_en != value.end() && fvValue(*it_en) == "dynamic")
                entry.is_static = 0;
            else 
                entry.is_static = 1;
        }
        entry.vlan_id   = vlanid;
        entry.is_igmp = (afi == 1) ? TRUE : FALSE;
        memcpy(entry.port.pnames, port_alias.c_str() , L2MCD_IFNAME_SIZE);
        
        idx++;
        
    }

}