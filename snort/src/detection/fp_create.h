//--------------------------------------------------------------------------
// Copyright (C) 2014-2015 Cisco and/or its affiliates. All rights reserved.
// Copyright (C) 2002-2013 Sourcefire, Inc.
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

// fp_create.h is derived from fpcreate.h by:
//
// Dan Roelker <droelker@sourcefire.com>
// Marc Norton <mnorton@sourcefire.com>

#ifndef FPCREATE_H
#define FPCREATE_H

// this is where rule groups are compiled and MPSE are instantiated

#include "detection/pcrm.h"
#include "target_based/snort_protocols.h"

struct SnortConfig;

struct PMX
{
    void* RuleNode;
    void* PatternMatchData;
};

/* Used for negative content list */
struct NCListNode
{
    PMX* pmx;
    NCListNode* next;
};

/*
**  This is the main routine to create a FastPacket inspection
**  engine.  It reads in the snort list of RTNs and OTNs and
**  assigns them to PORT_MAPS.
*/
int fpCreateFastPacketDetection(SnortConfig*);
void fpDeleteFastPacketDetection(SnortConfig*);

void fpShowEventStats(SnortConfig*);

typedef int (* OtnWalkFcn)(int, struct RuleTreeNode*, struct OptTreeNode*);
void fpWalkOtns(int, OtnWalkFcn);

void fpDeletePortGroup(void*);

bool set_fp_content(struct OptTreeNode*);

#endif

