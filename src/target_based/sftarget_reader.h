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

// sftarget_reader.h author Steven Sturges

#ifndef SFTARGET_READER_H
#define SFTARGET_READER_H

// Provides attribute table initialization, lookup, swap, and releasing.

#include "target_based/sftarget_data.h"

#define DEFAULT_MAX_ATTRIBUTE_HOSTS   10000
#define DEFAULT_MAX_ATTRIBUTE_SERVICES_PER_HOST 100
#define DEFAULT_MAX_METADATA_SERVICES     8

#define MAX_MAX_ATTRIBUTE_HOSTS   (512 * 1024)
#define MIN_MAX_ATTRIBUTE_HOSTS    32
#define MAX_MAX_ATTRIBUTE_SERVICES_PER_HOST   65535
#define MIN_MAX_ATTRIBUTE_SERVICES_PER_HOST       1
#define MAX_MAX_METADATA_SERVICES 256
#define MIN_MAX_METADATA_SERVICES 1

struct Packet;

/* main Functions, called by Snort shutdown */
void SFAT_Init();
void SFAT_Start();
void SFAT_Cleanup(void);
void FreeHostEntry(HostAttributeEntry* host);

/* status functions */
uint32_t SFAT_NumberOfHosts(void);

/* API Lookup functions, to be called by Stream & Frag */
HostAttributeEntry* SFAT_LookupHostEntryByIP(const sfip_t* ipAddr);
HostAttributeEntry* SFAT_LookupHostEntryBySrc(Packet* p);
HostAttributeEntry* SFAT_LookupHostEntryByDst(Packet* p);
void SFAT_UpdateApplicationProtocol(
    sfip_t* ipAddr, uint16_t port, uint16_t protocol, uint16_t id);

// reload functions
struct tTargetBasedConfig;
tTargetBasedConfig* SFAT_Swap();
tTargetBasedConfig* SFAT_GetConfig();
void SFAT_SetConfig(tTargetBasedConfig*);
void SFAT_Free(tTargetBasedConfig*);

#endif

