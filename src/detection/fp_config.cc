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

// fp_config.cc is derived from fpcreate.cc by:
/*
**  Dan Roelker <droelker@sourcefire.com>
**  Marc Norton <mnorton@sourcefire.com>
*/

#include "fp_config.h"

#include <assert.h>
#include <stdlib.h>
#include <string.h>

#include "fp_config.h"
#include "framework/mpse.h"
#include "managers/mpse_manager.h"
#include "parser/parser.h"

FastPatternConfig::FastPatternConfig()
{
    memset(this, 0, sizeof(*this));

    inspect_stream_insert = false;
    max_queue_events = 5;
    bleedover_port_limit = 1024;

    search_api = MpseManager::get_search_api("ac_bnfa_q");
    assert(search_api);
    trim = MpseManager::search_engine_trim(search_api);
}

FastPatternConfig::~FastPatternConfig()
{ }

int FastPatternConfig::set_detect_search_method(const char* method)
{
    search_api = MpseManager::get_search_api(method);

    if ( !search_api )
    {
        ParseError("invalid search-method '%s'", method);
        return -1;
    }

    trim = MpseManager::search_engine_trim(search_api);
    return 0;
}

void FastPatternConfig::set_max_pattern_len(unsigned int max_len)
{
    if (max_pattern_len != 0)
        ParseWarning(WARN_CONF, "maximum pattern length redefined from %d to %d.\n",
            max_pattern_len, max_len);

    max_pattern_len = max_len;
}

int FastPatternConfig::set_max(int bytes)
{
    if ( max_pattern_len and (bytes > max_pattern_len) )
    {
        bytes = max_pattern_len;
        num_patterns_truncated++;
    }
    return bytes;
}

