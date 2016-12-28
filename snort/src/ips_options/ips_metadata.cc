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
// ips_metadata.cc author Russ Combs <rucombs@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <string>
#include <vector>
using namespace std;

#include "main/snort_types.h"
#include "main/snort_debug.h"
#include "main/snort_config.h"
#include "detection/detection_defines.h"
#include "framework/ips_option.h"
#include "framework/parameter.h"
#include "framework/module.h"
#include "parser/parse_conf.h"
#include "parser/parser.h"

#define s_name "metadata"

//-------------------------------------------------------------------------
// module
//-------------------------------------------------------------------------

static const Parameter s_params[] =
{
    { "service", Parameter::PT_STRING, nullptr, nullptr,
      "service name" },

    { "*", Parameter::PT_STRING, nullptr, nullptr,
      "additional parameters not used by snort" },

    { nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr }
};

#define s_help \
    "rule option for conveying arbitrary name, value data within the rule text"

class MetadataModule : public Module
{
public:
    MetadataModule() : Module(s_name, s_help, s_params)
    { snort_config = nullptr; }

    bool set(const char*, Value&, SnortConfig*) override;
    bool begin(const char*, int, SnortConfig*) override;

    struct SnortConfig* snort_config;
    vector<string> services;
};

bool MetadataModule::begin(const char*, int, SnortConfig* sc)
{
    snort_config = sc;
    services.clear();
    return true;
}

bool MetadataModule::set(const char*, Value& v, SnortConfig*)
{
    if ( v.is("service") )
    {
        const char* s = v.get_string();

        for ( auto p : services )
        {
            if ( p == s )
            {
                ParseWarning(WARN_RULES, "repeated metadata service '%s'", s);
                return true;
            }
        }
        services.push_back(s);
    }
    else if ( !v.is("*") )  // ignore other metadata
        return false;

    return true;
}

//-------------------------------------------------------------------------
// api methods
//-------------------------------------------------------------------------

static Module* mod_ctor()
{
    return new MetadataModule;
}

static void mod_dtor(Module* m)
{
    delete m;
}

static IpsOption* metadata_ctor(Module* p, OptTreeNode* otn)
{
    MetadataModule* m = (MetadataModule*)p;

    for ( auto p : m->services )
        add_service_to_otn(m->snort_config, otn, p.c_str());

    return nullptr;
}

static const IpsApi metadata_api =
{
    {
        PT_IPS_OPTION,
        sizeof(IpsApi),
        IPSAPI_VERSION,
        0,
        API_RESERVED,
        API_OPTIONS,
        s_name,
        s_help,
        mod_ctor,
        mod_dtor
    },
    OPT_TYPE_META,
    0, PROTO_BIT__NONE,
    nullptr,
    nullptr,
    nullptr,
    nullptr,
    metadata_ctor,
    nullptr,
    nullptr
};

const BaseApi* ips_metadata = &metadata_api.base;

