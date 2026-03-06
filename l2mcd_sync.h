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

#ifndef __L2MCD_SYNC__
#define __L2MCD_SYNC__

#include <string>
#include "dbconnector.h"
#include "producerstatetable.h"
#include "l2mcd.h"
#include "l2mcd_dbsync.h"
#include "notificationproducer.h"

namespace swss {

    class L2mcSync {
        public:
            L2mcSync(DBConnector *db, DBConnector *cfgDb, DBConnector *stateDb);
            ~L2mcSync();
            void addL2mcVlanEntry(uint16_t vlan_id);
            void delL2mcVlanEntry(uint16_t vlan_id);
            void addL2mcTableEntry(L2MCD_APP_TABLE_ENTRY *msg);
            void delL2mcTableEntry(L2MCD_APP_TABLE_ENTRY *msg);
            void processL2mcMrouterTableEntry(L2MCD_APP_TABLE_ENTRY *msg);
            int getL2mcMgrDebugPrio(void);
            bool isPortPeerLink(std::string portname);
            void notify_config_done(std::string option, std::string paraname);
            void notify_warm_reboot_done(std::string option, std::string paraname);
            void clearL2mcVlanEntry(void);
            int getL2mcVlanEntryCount(uint16_t vlan_id, uint16_t afi);
            void dumpL2mcVlanEntry(DUMP_L2MCD_APP_TABLE_ENTRY *msg);

        protected:
        private:
            ProducerStateTable m_appVlanProducerTable;
            ProducerStateTable m_appEntryProducerTable;
            ProducerStateTable m_appMrouterProducerTable;
            ProducerStateTable m_appSuppressProducerTable;

            NotificationProducer *l2mc_entry_notifications;
            NotificationProducer *l2mc_mrouter_notifications;
            NotificationProducer *l2mc_cfg_done_notifications;
            NotificationProducer *l2mc_warm_reboot_notifications;
            std::unique_ptr<Table> m_mclagTable;

            Table m_statel2mcdLocalMemberTable, m_statel2mcdLocalMrouterTable;
            Table m_featureTable, m_appVlanTable, m_appEntryTable, m_appMrouteTable, m_appSuppressTable;
    };

}
#endif
