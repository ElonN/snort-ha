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

// sftarget_data.c author Steven Sturges

#ifndef SFTARGET_DATA_H
#define SFTARGET_DATA_H

#include "sfip/sfip_t.h"

#define SFAT_OK 0
#define SFAT_ERROR -1
#define SFAT_BUFSZ 1024

typedef enum
{
    ATTRIBUTE_SERVICE,
    ATTRIBUTE_CLIENT
} ServiceClient;

#define APPLICATION_ENTRY_PORT 0x01
#define APPLICATION_ENTRY_IPPROTO 0x02
#define APPLICATION_ENTRY_PROTO 0x04
#define APPLICATION_ENTRY_APPLICATION 0x08
#define APPLICATION_ENTRY_VERSION 0x10

typedef struct _ApplicationEntry
{
    struct _ApplicationEntry* next;

    uint16_t port;
    uint16_t ipproto;
    uint16_t protocol;

    uint8_t fields;
} ApplicationEntry;

typedef ApplicationEntry ApplicationList;

#define HOST_INFO_OS 1
#define HOST_INFO_VENDOR 2
#define HOST_INFO_VERSION 3
#define HOST_INFO_FRAG_POLICY 4
#define HOST_INFO_STREAM_POLICY 5

struct HostInfo
{
    uint8_t streamPolicy;
    uint8_t fragPolicy;
};

#define SFAT_SERVICE 1
#define SFAT_CLIENT 2

struct HostAttributeEntry
{
    sfip_t ipAddr;
    HostInfo hostInfo;
    ApplicationList* services;
    ApplicationList* clients;
};

int SFAT_AddHost(HostAttributeEntry*);
int SFAT_AddService(HostAttributeEntry*, ApplicationEntry*);
int SFAT_AddHostEntryToMap(HostAttributeEntry*);

HostAttributeEntry* SFAT_CreateHostEntry(void);
ApplicationEntry* SFAT_CreateApplicationEntry(void);

#endif /* SFTARGET_DATA_H */

