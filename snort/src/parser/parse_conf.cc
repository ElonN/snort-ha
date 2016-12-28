//--------------------------------------------------------------------------
// Copyright (C) 2014-2015 Cisco and/or its affiliates. All rights reserved.
// Copyright (C) 2002-2013 Sourcefire, Inc.
// Copyright (C) 1998-2002 Martin Roesch <roesch@sourcefire.com>
// Copyright (C) 2000,2001 Andrew R. Baker <andrewb@uab.edu>
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

#include "parse_conf.h"

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <sys/types.h>
#include <sys/stat.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <errno.h>
#include <ctype.h>
#include <unistd.h>
#include <stdarg.h>
#include <pcap.h>
#include <grp.h>
#include <pwd.h>
#include <fnmatch.h>

#include <stack>
#include <string>
#include <fstream>
#include <sstream>

#include "parser.h"
#include "parse_stream.h"
#include "cmd_line.h"
#include "parse_rule.h"
#include "config_file.h"
#include "vars.h"

#include "actions/actions.h"
#include "detection/rules.h"
#include "detection/treenodes.h"
#include "detection/signature.h"
#include "main/snort_debug.h"
#include "main/snort_config.h"
#include "utils/util.h"
#include "utils/snort_bounds.h"
#include "hash/sfghash.h"
#include "sfip/sf_ip.h"
#include "sfip/sf_vartable.h"
#include "packet_io/active.h"
#include "file_api/libs/file_config.h"
#include "framework/ips_option.h"
#include "managers/action_manager.h"
#include "actions/actions.h"
#include "target_based/snort_protocols.h"

struct Location
{
    std::string file;
    unsigned line;

    Location(const char* s, unsigned u)
    { file = s; line = u; }
};

static std::stack<Location> files;

const char* get_parse_file()
{
    if ( files.empty() )
        return nullptr;

    Location& loc = files.top();
    return loc.file.c_str();
}

void get_parse_location(const char*& file, unsigned& line)
{
    if ( files.empty() )
    {
        file = nullptr;
        line = 0;
        return;
    }
    Location& loc = files.top();
    file = loc.file.c_str();
    line = loc.line;
}

void push_parse_location(const char* file, unsigned line)
{
    if ( !file )
        return;

    Location loc(file, line);
    files.push(loc);
    LogMessage("Loading %s:\n", file);
}

void pop_parse_location()
{
    if ( !files.empty() )
    {
        Location& loc = files.top();
        LogMessage("Finished %s.\n", loc.file.c_str());
        files.pop();
    }
}

void inc_parse_position()
{
    Location& loc = files.top();
    ++loc.line;
}

void parse_include(SnortConfig* sc, const char* arg)
{
    struct stat file_stat;  /* for include path testing */
    char* fname = SnortStrdup(arg);

    /* Stat the file.  If that fails, make it relative to the directory
     * that the top level snort configuration file was in */
    if ( stat(fname, &file_stat) == -1 && fname[0] != '/' )
    {
        const char* snort_conf_dir = get_snort_conf_dir();

        int path_len = strlen(snort_conf_dir) + strlen(arg) + 1;
        free(fname);

        fname = (char*)SnortAlloc(path_len);
        snprintf(fname, path_len, "%s%s", snort_conf_dir, arg);
    }

    push_parse_location(fname, 0);
    ParseConfigFile(sc, fname);
    pop_parse_location();
    free((char*)fname);
}

void ParseIpVar(SnortConfig* sc, const char* var, const char* val)
{
    int ret;
    IpsPolicy* p = get_ips_policy(); // FIXIT-M double check, see below
    DisallowCrossTableDuplicateVars(sc, var, VAR_TYPE__IPVAR);

    if ((ret = sfvt_define(p->ip_vartable, var, val)) != SFIP_SUCCESS)
    {
        switch (ret)
        {
        case SFIP_ARG_ERR:
            ParseError("the following is not allowed: %s.", val);
            return;

        case SFIP_DUPLICATE:
            ParseWarning(WARN_VARS, "Var '%s' redefined.", var);
            break;

        case SFIP_CONFLICT:
            ParseError("negated IP ranges that are more general than "
                "non-negated ranges are not allowed. Consider "
                "inverting the logic in %s.", var);
            return;

        case SFIP_NOT_ANY:
            ParseError("!any is not allowed in %s.", var);
            return;

        default:
            ParseError("failed to parse the IP address: %s.", val);
            return;
        }
    }
}

void add_service_to_otn(
    SnortConfig* sc, OptTreeNode* otn, const char* svc_name)
{
    if (otn->sigInfo.num_services >= sc->max_metadata_services)
    {
        ParseError("too many service's specified for rule, can't add %s", svc_name);
        return;
    }
    int16_t svc_id = AddProtocolReference(svc_name);

    for ( unsigned i = 0; i < otn->sigInfo.num_services; ++i )
        if ( otn->sigInfo.services[i].service_ordinal == svc_id )
            return;  // already added

    if ( !otn->sigInfo.services )
        otn->sigInfo.services =
            (ServiceInfo*)SnortAlloc(sizeof(ServiceInfo) * sc->max_metadata_services);

    int idx = otn->sigInfo.num_services++;

    otn->sigInfo.services[idx].service = SnortStrdup(svc_name);
    otn->sigInfo.services[idx].service_ordinal = svc_id;
}

// only keep drop rules ...
// if we are inline (and can actually drop),
// or we are going to just alert instead of drop,
// or we are going to ignore session data instead of drop.
// the alert case is tested for separately with SnortConfig::treat_drop_as_alert().
static inline int ScKeepDropRules(void)
{
    return ( SnortConfig::inline_mode() || SnortConfig::adaptor_inline_mode() || SnortConfig::treat_drop_as_ignore() );
}

static inline int ScLoadAsDropRules(void)
{
    return ( SnortConfig::inline_test_mode() || SnortConfig::adaptor_inline_test_mode() );
}

RuleType get_rule_type(const char* s)
{
    RuleType rt = get_action_type(s);

    if ( rt == RULE_TYPE__NONE )
        rt = ActionManager::get_action_type(s);

    switch ( rt )
    {
    case RULE_TYPE__DROP:
    case RULE_TYPE__BLOCK:
    case RULE_TYPE__RESET:
        if ( SnortConfig::treat_drop_as_alert() )
            return RULE_TYPE__ALERT;

        if ( ScKeepDropRules() || ScLoadAsDropRules() )
            return rt;

        return RULE_TYPE__NONE;

    case RULE_TYPE__NONE:
        ParseError("unknown rule type '%s'", s);
        break;

    default:
        break;
    }
    return rt;
}

ListHead* get_rule_list(SnortConfig* sc, const char* s)
{
    const RuleListNode* p = sc->rule_lists;

    while ( p && strcmp(p->name, s) )
        p = p->next;

    return p ? p->RuleList : nullptr;
}

// FIXIT-L move to snort config
void AddRuleState(SnortConfig* sc, const RuleState& rs)
{
    if (sc == NULL)
        return;

    RuleState* state = (RuleState*)SnortAlloc(sizeof(RuleState));
    *state = rs;

    if ( !sc->rule_state_list )
    {
        sc->rule_state_list = state;
    }
    else
    {
        state->next = sc->rule_state_list;
        sc->rule_state_list = state;
    }
}

void ParseConfigFile(SnortConfig* sc, const char* fname)
{
    if ( !fname )
        return;

    std::ifstream fs(fname, std::ios_base::binary);

    if ( !fs )
    {
        ParseError("unable to open rules file '%s': %s",
            fname, get_error(errno));
        return;
    }
    parse_stream(fs, sc);
}

void ParseConfigString(SnortConfig* sc, const char* s)
{
    std::string rules = s;
    std::stringstream ss(rules);
    parse_stream(ss, sc);
}

