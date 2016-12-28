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
// mpse_manager.h author Russ Combs <rucombs@cisco.com>

#ifndef MPSE_MANAGER_H
#define MPSE_MANAGER_H

// Factory for Mpse.  The same Mpse type is used for rule matching as well
// as searching by inspectors with a SearchTool.  Runtime use of the Mpse
// is by the fast pattern detection module.

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include "main/snort_types.h"
#include "framework/base_api.h"

#ifdef PIGLET
#include "framework/mpse.h"
#include "piglet/piglet_api.h"
#endif

struct MpseApi;
class Mpse;
struct SnortConfig;

//-------------------------------------------------------------------------

#ifdef PIGLET
struct MpseWrapper
{
    MpseWrapper(const MpseApi* a, Mpse* p) :
        api { a }, instance { p } { }

    ~MpseWrapper()
    {
        if ( api && instance && api->dtor )
            api->dtor(instance);
    }

    const MpseApi* api;
    Mpse* instance;
};
#endif

class MpseManager
{
public:
    static void add_plugin(const MpseApi*);
    static void release_plugins();
    static void dump_plugins();

    static void instantiate(const MpseApi*, Module*, SnortConfig*);
    static const MpseApi* get_search_api(const char* type);
    static void delete_search_engine(Mpse*);

    static Mpse* get_search_engine(const char*);
    static Mpse* get_search_engine(
        SnortConfig* sc,const MpseApi* api,
        bool use_gc,
        void (* user_ree)(void*),
        void (* tree_free)(void**),
        void (* list_free)(void**));

    static void activate_search_engine(const MpseApi*, SnortConfig*);
    static void setup_search_engine(const MpseApi*, SnortConfig*);
    static void start_search_engine(const MpseApi*);
    static void stop_search_engine(const MpseApi*);
    static bool search_engine_trim(const MpseApi*);
    static void print_mpse_summary(const MpseApi*);
    static void print_search_engine_stats();

#ifdef PIGLET
    static MpseWrapper* instantiate(const char*, Module*, SnortConfig*);
#endif
};

#endif

