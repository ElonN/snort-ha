//--------------------------------------------------------------------------
// Copyright (C) 2014-2015 Cisco and/or its affiliates. All rights reserved.
// Copyright (C) 2006-2013 Sourcefire, Inc.
//
// This program is free software; you can redistribute it and/or modify it
// under the terms of the GNU General Public License Version 2 as published
// by the Free Software Foundation.  You may not use, modify or distribute
// this program under any other version of the GNU General Public License.
//
// This program is distributed in the hope that it will be useful, but
// WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
// General Public License for more details.
//
// You should have received a copy of the GNU General Public License along
// with this program; if not, write to the Free Software Foundation, Inc.,
// 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
//--------------------------------------------------------------------------

/*
 * Author: Steven Sturges
 * sftarget_reader.c
 */

#include "sftarget_reader.h"

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <assert.h>
#include <stdio.h>
#include <signal.h>
#include <sys/types.h>
#include <stdlib.h>
#include <errno.h>
#include <unistd.h>
#include <time.h>

#include "snort_protocols.h"
#include "sftarget_hostentry.h"
#include "sftarget_data.h"

#include "main/snort_config.h"
#include "main/snort_debug.h"
#include "parser/parser.h"
#include "hash/sfxhash.h"
#include "perf_monitor/perf.h"
#include "utils/util.h"
#include "utils/util_net.h"
#include "utils/stats.h"
#include "sfip/sf_ip.h"
#include "sfrt/sfrt.h"

#define ATTRIBUTE_MAP_MAX_ROWS 1024

struct tTargetBasedConfig
{
    table_t* lookupTable;

    tTargetBasedConfig();
    ~tTargetBasedConfig();
};

void SFAT_CleanupCallback(void* host_attr_ent)
{
    HostAttributeEntry* host_entry = (HostAttributeEntry*)host_attr_ent;
    FreeHostEntry(host_entry);
}

tTargetBasedConfig::tTargetBasedConfig()
{
    /* Add 1 to max for table purposes
    * We use max_hosts to limit memcap, assume 16k per entry costs*/
    // FIXIT-M 16k per host is no longer true
    // FIXIT-M init before snort_conf; move to filename and load separately
    // this is a hack to get it going
    uint32_t max = snort_conf ?
        SnortConfig::get_max_attribute_hosts() : DEFAULT_MAX_ATTRIBUTE_HOSTS;
    lookupTable = sfrt_new(DIR_8x16, IPv6, max + 1, (max>>6) + 1);
}

tTargetBasedConfig::~tTargetBasedConfig()
{
    sfrt_cleanup(lookupTable, SFAT_CleanupCallback);
    sfrt_free(lookupTable);
}

static THREAD_LOCAL tTargetBasedConfig* curr_cfg = NULL;
static tTargetBasedConfig* next_cfg = NULL;

static bool sfat_grammar_error_printed = false;
static bool sfat_insufficient_space_logged = false;

/*****TODO: cleanup to use config directive *******/
uint32_t SFAT_NumberOfHosts(void)
{
    if ( curr_cfg && curr_cfg->lookupTable )
    {
        return sfrt_num_entries(curr_cfg->lookupTable);
    }

    return 0;
}

void FreeApplicationEntry(ApplicationEntry* app)
{
    DebugFormat(DEBUG_ATTRIBUTE, "Freeing ApplicationEntry: 0x%x\n", app);
    free(app);
}

ApplicationEntry* SFAT_CreateApplicationEntry(void)
{
    return (ApplicationEntry*)SnortAlloc(sizeof(ApplicationEntry));
}

HostAttributeEntry* SFAT_CreateHostEntry(void)
{
    return (HostAttributeEntry*)SnortAlloc(sizeof(HostAttributeEntry));
}

void FreeHostEntry(HostAttributeEntry* host)
{
    ApplicationEntry* app = NULL, * tmp_app;

    if (!host)
        return;

    DebugFormat(DEBUG_ATTRIBUTE, "Freeing HostEntry: 0x%x\n", host);

    /* Free the service list */
    if (host->services)
    {
        do
        {
            tmp_app = host->services;
            app = tmp_app->next;
            FreeApplicationEntry(tmp_app);
            host->services = app;
        }
        while (app);
    }

    /* Free the client list */
    if (host->clients)
    {
        do
        {
            tmp_app = host->clients;
            app = tmp_app->next;
            FreeApplicationEntry(tmp_app);
            host->clients = app;
        }
        while (app);
    }

    free(host);
}

static void AppendApplicationData(ApplicationList** list, ApplicationEntry* app)
{
    if (!list)
        return;

    if (*list)
    {
        app->next = *list;
    }
    *list = app;
}

int SFAT_AddService(HostAttributeEntry* host, ApplicationEntry* app)
{
    AppendApplicationData(&host->services, app);
    return SFAT_OK;
}

int SFAT_AddApplicationData(HostAttributeEntry* host, ApplicationEntry* app)
{
    uint8_t required_fields =
        (APPLICATION_ENTRY_PORT |
        APPLICATION_ENTRY_IPPROTO |
        APPLICATION_ENTRY_PROTO);

    if ((app->fields & required_fields) != required_fields)
    {
        ParseError("Missing required field in Service attribute table for host %s",
            inet_ntoa(&host->ipAddr));
    }
    AppendApplicationData(&host->services, app);

    return SFAT_OK;
}

#ifdef DEBUG_MSGS
void PrintHostAttributeEntry(HostAttributeEntry* host)
{
    ApplicationEntry* app;
    int i = 0;

    if (!host)
        return;

    DebugFormat(DEBUG_ATTRIBUTE, "Host IP: %s/%d\n",
        inet_ntoa(&host->ipAddr),
        host->ipAddr.bits);

    DebugFormat(DEBUG_ATTRIBUTE,
        "\tPolicy Information: frag:%s (%u) stream: %s (%u)\n",
        "look-me-up", host->hostInfo.fragPolicy,
        "look-me-up", host->hostInfo.streamPolicy);

    DebugMessage(DEBUG_ATTRIBUTE, "\tServices:\n");

    for (i=0, app = host->services; app; app = app->next,i++)
    {
        DebugFormat(DEBUG_ATTRIBUTE, "\tService #%d:\n", i);
        DebugFormat(DEBUG_ATTRIBUTE, "\t\tIPProtocol: %s\tPort: %s\tProtocol %s\n",
            app->ipproto, app->port, app->protocol);
    }
    if (i==0)
        DebugMessage(DEBUG_ATTRIBUTE, "\t\tNone\n");

    DebugMessage(DEBUG_ATTRIBUTE, "\tClients:\n");
    for (i=0, app = host->clients; app; app = app->next,i++)
    {
        DebugFormat(DEBUG_ATTRIBUTE, "\tClient #%d:\n", i);
        DebugFormat(DEBUG_ATTRIBUTE, "\t\tIPProtocol: %s\tProtocol %s\n",
            app->ipproto, app->protocol);

        if (app->fields & APPLICATION_ENTRY_PORT)
        {
            DebugFormat(DEBUG_ATTRIBUTE, "\t\tPort: %s\n", app->port);
        }
    }
    if (i==0)
    {
        DebugMessage(DEBUG_ATTRIBUTE, "\t\tNone\n");
    }
}

#endif

int SFAT_AddHost(HostAttributeEntry* host)
{
    return SFAT_AddHostEntryToMap(host);
}

int SFAT_AddHostEntryToMap(HostAttributeEntry* host)
{
    int ret;
    sfip_t* ipAddr;

    DEBUG_WRAP(PrintHostAttributeEntry(host); );

    ipAddr = &host->ipAddr;
    assert(ipAddr);

    ret = sfrt_insert(ipAddr, (unsigned char)ipAddr->bits, host,
        RT_FAVOR_SPECIFIC, next_cfg->lookupTable);

    if (ret != RT_SUCCESS)
    {
        if (ret == RT_POLICY_TABLE_EXCEEDED)
        {
            if ( !sfat_insufficient_space_logged )
            {
                ParseWarning(WARN_HOSTS,
                    "AttributeTable insertion failed: %d Insufficient "
                    "space in attribute table, only configured to store %d hosts\n",
                    ret, SnortConfig::get_max_attribute_hosts());
                sfat_insufficient_space_logged = true;
            }
            /* Reset return value and continue w/ only snort_conf->max_attribute_hosts */
            ret = RT_SUCCESS;
        }
        else if ( !sfat_grammar_error_printed )
        {
            ParseWarning(WARN_HOSTS,
                "AttributeTable insertion failed: %d '%s'\n",
                ret, rt_error_messages[ret]);
            sfat_grammar_error_printed = true;
        }

        FreeHostEntry(host);
    }

    return ret == RT_SUCCESS ? SFAT_OK : SFAT_ERROR;
}

HostAttributeEntry* SFAT_LookupHostEntryByIP(const sfip_t* ipAddr)
{
    if ( !curr_cfg )
        return NULL;

    return (HostAttributeEntry*)sfrt_lookup((sfip_t*)ipAddr, curr_cfg->lookupTable);
}

HostAttributeEntry* SFAT_LookupHostEntryBySrc(Packet* p)
{
    if (!p || !p->ptrs.ip_api.is_ip())
        return NULL;

    return SFAT_LookupHostEntryByIP(p->ptrs.ip_api.get_src());
}

HostAttributeEntry* SFAT_LookupHostEntryByDst(Packet* p)
{
    if (!p || !p->ptrs.ip_api.is_ip())
        return NULL;

    return SFAT_LookupHostEntryByIP(p->ptrs.ip_api.get_dst());
}

void SFAT_Cleanup(void)
{
    delete curr_cfg;
    delete next_cfg;

    FreeProtoocolReferenceTable();
}

void SFAT_SetConfig(tTargetBasedConfig* p)
{
    curr_cfg = p;
}

tTargetBasedConfig* SFAT_GetConfig()
{
    return curr_cfg;
}

void SFAT_Free(tTargetBasedConfig* p)
{
    delete p;
}

void SFAT_Init()
{
    curr_cfg = nullptr;
    next_cfg = new tTargetBasedConfig;
    InitializeProtocolReferenceTable();
}

void SFAT_Start()
{
    curr_cfg = next_cfg;
    next_cfg = new tTargetBasedConfig;
}

tTargetBasedConfig* SFAT_Swap()
{
    curr_cfg = next_cfg;
    next_cfg = new tTargetBasedConfig;

    sfBase.iAttributeHosts = SFAT_NumberOfHosts();
    sfBase.iAttributeReloads++;
    proc_stats.attribute_table_reloads++;

    LogMessage(STDu64 " hosts loaded\n", sfBase.iAttributeHosts);
    return curr_cfg;
}

void SFAT_UpdateApplicationProtocol(sfip_t* ipAddr, uint16_t port, uint16_t protocol, uint16_t id)
{
    HostAttributeEntry* host_entry;
    ApplicationEntry* service;
    unsigned service_count = 0;
    int rval;

    host_entry = (HostAttributeEntry*)sfrt_lookup(ipAddr, curr_cfg->lookupTable);

    if (!host_entry)
    {
        if (sfrt_num_entries(curr_cfg->lookupTable) >= SnortConfig::get_max_attribute_hosts())
            return;

        host_entry = (HostAttributeEntry*)SnortAlloc(sizeof(*host_entry));
        sfip_set_ip(&host_entry->ipAddr, ipAddr);

        if ((rval = sfrt_insert(ipAddr, (unsigned char)ipAddr->bits, host_entry,
                RT_FAVOR_SPECIFIC, curr_cfg->lookupTable)) != RT_SUCCESS)
        {
            FreeHostEntry(host_entry);
            return;
        }
        service = NULL;
    }
    else
    {
        for (service = host_entry->services; service; service = service->next)
        {
            if (service->ipproto == protocol && (uint16_t)service->port == port)
            {
                break;
            }
            service_count++;
        }
    }
    if (!service)
    {
        if ( service_count >= SnortConfig::get_max_services_per_host() )
            return;

        service = (ApplicationEntry*)SnortAlloc(sizeof(*service));
        service->port = port;
        service->ipproto = protocol;
        service->next = host_entry->services;
        host_entry->services = service;
        service->protocol = id;
    }
    else if (service->protocol != id)
    {
        service->protocol = id;
    }
}

