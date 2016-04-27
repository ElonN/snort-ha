//--------------------------------------------------------------------------
// Copyright (C) 2014-2015 Cisco and/or its affiliates. All rights reserved.
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

#ifndef ACTIONS_H
#define ACTIONS_H

// Define action types and provide hooks to apply a given action to a packet

#include <stdint.h>

#define ACTION_LOG      "log"
#define ACTION_PASS     "pass"
#define ACTION_ALERT    "alert"
#define ACTION_DROP     "drop"
#define ACTION_BLOCK    "block"
#define ACTION_RESET    "reset"

struct Packet;
struct OptTreeNode;

// FIXIT-L: Convert to a scoped enum
enum RuleType
{
    RULE_TYPE__NONE = 0,
    RULE_TYPE__LOG,
    RULE_TYPE__PASS,
    RULE_TYPE__ALERT,
    RULE_TYPE__DROP,
    RULE_TYPE__BLOCK,
    RULE_TYPE__RESET,
    RULE_TYPE__MAX
};

// FIXIT-L: Could be static methods of class enclosing RuleType enum
const char* get_action_string(RuleType);
RuleType get_action_type(const char*);

void action_execute(RuleType, struct Packet*, const struct OptTreeNode*,
    uint16_t event_id);

void action_apply(RuleType, struct Packet*);

static inline bool pass_action(RuleType a)
{ return ( a == RULE_TYPE__PASS ); }

#endif

