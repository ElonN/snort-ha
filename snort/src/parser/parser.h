//--------------------------------------------------------------------------
// Copyright (C) 2014-2015 Cisco and/or its affiliates. All rights reserved.
// Copyright (C) 2013-2013 Sourcefire, Inc.
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

#ifndef PARSER_H
#define PARSER_H

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <stdio.h>

#include "detection/rules.h"
#include "detection/sfrim.h"
#include "detection/treenodes.h"
#include "main/policy.h"

void parser_init();
void parser_term();

unsigned get_parse_errors();
unsigned get_parse_warnings();

const char* get_parse_file();
void get_parse_location(const char*& name, unsigned& line);
void push_parse_location(const char* name, unsigned line = 0);

void pop_parse_location();
void inc_parse_position();

/* rule setup funcs */
SnortConfig* ParseSnortConf(const SnortConfig*);
void ParseRules(SnortConfig*);

void OrderRuleLists(SnortConfig*, const char*);
void PrintRuleOrder(RuleListNode*);

const char* VarGet(SnortConfig*, const char*);
char* ProcessFileOption(SnortConfig*, const char*);
void SetRuleStates(SnortConfig*);

void FreeRuleLists(SnortConfig*);
void VarTablesFree(SnortConfig*);
void PortTablesFree(struct RulePortTables*);

void parser_append_rules(const char*);

void ConfigureSideChannelModules(SnortConfig*);

SO_PUBLIC NORETURN void ParseAbort(const char*, ...);
SO_PUBLIC void ParseError(const char*, ...);
SO_PUBLIC void ParseMessage(const char*, ...);

enum WarningGroup
{
    WARN_DAQ, WARN_CONF, WARN_VARS, WARN_SYMBOLS, WARN_SCRIPTS,
    WARN_HOSTS, WARN_RULES, WARN_FLOWBITS, WARN_PLUGINS,
#ifdef PIGLET
    WARN_PIGLET,
#endif
    WARN_MAX
};

SO_PUBLIC void ParseWarning(WarningGroup, const char*, ...);

int ParseBool(const char* arg);

int addRtnToOtn(struct OptTreeNode*, RuleTreeNode*);
int addRtnToOtn(struct OptTreeNode*, RuleTreeNode*, PolicyId);

RuleTreeNode* deleteRtnFromOtn(struct OptTreeNode*);
RuleTreeNode* deleteRtnFromOtn(struct OptTreeNode*, PolicyId);

static inline RuleTreeNode* getRtnFromOtn(
    const struct OptTreeNode* otn, PolicyId policyId)
{
    if (otn && otn->proto_nodes && (otn->proto_node_num > (unsigned)policyId))
    {
        return otn->proto_nodes[policyId];
    }

    return NULL;
}

static inline RuleTreeNode* getRtnFromOtn(
    const struct OptTreeNode* otn)
{
    return getRtnFromOtn(otn, get_ips_policy()->policy_id);
}

static inline RuleTreeNode* getRuntimeRtnFromOtn(
    const struct OptTreeNode* otn)
{
    return getRtnFromOtn(otn);
}

ListHead* CreateRuleType(SnortConfig* sc, const char* name, RuleType);

void FreeRuleTreeNode(RuleTreeNode*);
void DestroyRuleTreeNode(RuleTreeNode*);

int parser_get_rule_index(unsigned gid, unsigned sid);
void parser_get_rule_ids(int index, unsigned& gid, unsigned& sid);
void rule_index_map_print_index(int index, char* buf, int);

#endif

