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
// ips_fragoffset.cc author Russ Combs <rucombs@cisco.com>

#include <sys/types.h>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdlib.h>
#include <ctype.h>

#include "main/snort_types.h"
#include "main/snort_debug.h"
#include "protocols/packet.h"
#include "time/profiler.h"
#include "hash/sfhashfcn.h"
#include "detection/detection_defines.h"
#include "framework/ips_option.h"
#include "framework/parameter.h"
#include "framework/module.h"
#include "framework/range.h"

#define s_name "fragoffset"

static THREAD_LOCAL ProfileStats fragOffsetPerfStats;

class FragOffsetOption : public IpsOption
{
public:
    FragOffsetOption(const RangeCheck& c) :
        IpsOption(s_name)
    { config = c; }

    uint32_t hash() const override;
    bool operator==(const IpsOption&) const override;

    int eval(Cursor&, Packet*) override;

private:
    RangeCheck config;
};

//-------------------------------------------------------------------------
// class methods
//-------------------------------------------------------------------------

uint32_t FragOffsetOption::hash() const
{
    uint32_t a,b,c;

    a = config.op;
    b = (uint32_t)config.min;
    c = (uint32_t)config.max;

    mix_str(a,b,c,get_name());
    final(a,b,c);

    return c;
}

bool FragOffsetOption::operator==(const IpsOption& ips) const
{
    if ( strcmp(get_name(), ips.get_name()) )
        return false;

    FragOffsetOption& rhs = (FragOffsetOption&)ips;
    return config == rhs.config;

    return false;
}

int FragOffsetOption::eval(Cursor&, Packet* p)
{
    int p_offset = p->ptrs.ip_api.off();
    int rval = DETECTION_OPTION_NO_MATCH;
    PROFILE_VARS;

    if (!p->has_ip())
    {
        return rval;
    }

    MODULE_PROFILE_START(fragOffsetPerfStats);

    if ( config.eval(p_offset) )
        rval = DETECTION_OPTION_MATCH;

    MODULE_PROFILE_END(fragOffsetPerfStats);
    return rval;
}

//-------------------------------------------------------------------------
// module
//-------------------------------------------------------------------------

static const Parameter s_params[] =
{
    { "~range", Parameter::PT_STRING, nullptr, nullptr,
      "check if packet payload size is 'size | min<>max | <max | >min'" },

    { nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr }
};

#define s_help \
    "rule option to test IP frag offset"

class FragOffsetModule : public Module
{
public:
    FragOffsetModule() : Module(s_name, s_help, s_params) { }

    bool begin(const char*, int, SnortConfig*) override;
    bool set(const char*, Value&, SnortConfig*) override;

    ProfileStats* get_profile() const override
    { return &fragOffsetPerfStats; }

    RangeCheck data;
};

bool FragOffsetModule::begin(const char*, int, SnortConfig*)
{
    data.init();
    return true;
}

bool FragOffsetModule::set(const char*, Value& v, SnortConfig*)
{
    if ( !v.is("~range") )
        return false;

    return data.parse(v.get_string());
}

//-------------------------------------------------------------------------
// api methods
//-------------------------------------------------------------------------

static Module* mod_ctor()
{
    return new FragOffsetModule;
}

static void mod_dtor(Module* m)
{
    delete m;
}

static IpsOption* fragoffset_ctor(Module* p, OptTreeNode*)
{
    FragOffsetModule* m = (FragOffsetModule*)p;
    return new FragOffsetOption(m->data);
}

static void fragoffset_dtor(IpsOption* p)
{
    delete p;
}

static const IpsApi fragoffset_api =
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
    OPT_TYPE_DETECTION,
    1, 0,
    nullptr,
    nullptr,
    nullptr,
    nullptr,
    fragoffset_ctor,
    fragoffset_dtor,
    nullptr
};

#ifdef BUILDING_SO
SO_PUBLIC const BaseApi* snort_plugins[] =
{
    &fragoffset_api.base,
    nullptr
};
#else
const BaseApi* ips_fragoffset = &fragoffset_api.base;
#endif

