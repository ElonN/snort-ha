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
// ips_dsize.cc author Russ Combs <rucombs@cisco.com>

#include <ctype.h>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include <stdlib.h>
#include <string.h>

#include "main/snort_types.h"
#include "main/snort_debug.h"
#include "protocols/packet.h"
#include "parser/parser.h"
#include "utils/util.h"
#include "hash/sfhashfcn.h"
#include "time/profiler.h"
#include "detection/treenodes.h"
#include "detection/detection_defines.h"
#include "framework/ips_option.h"
#include "framework/parameter.h"
#include "framework/module.h"
#include "framework/range.h"

#define s_name "dsize"

static THREAD_LOCAL ProfileStats dsizePerfStats;

class DsizeOption : public IpsOption
{
public:
    DsizeOption(const RangeCheck& c) :
        IpsOption(s_name)
    { config = c; }

    ~DsizeOption() { }

    uint32_t hash() const override;
    bool operator==(const IpsOption&) const override;

    int eval(Cursor&, Packet*) override;

private:
    RangeCheck config;
};

//-------------------------------------------------------------------------
// class methods
//-------------------------------------------------------------------------

uint32_t DsizeOption::hash() const
{
    uint32_t a,b,c;

    a = config.min;
    b = config.max;
    c = config.op;

    mix(a,b,c);
    mix_str(a,b,c,get_name());
    final(a,b,c);

    return c;
}

bool DsizeOption::operator==(const IpsOption& ips) const
{
    if ( strcmp(get_name(), ips.get_name()) )
        return false;

    DsizeOption& rhs = (DsizeOption&)ips;
    return config == rhs.config;
}

// Test the packet's payload size against the rule payload size value
int DsizeOption::eval(Cursor&, Packet* p)
{
    int rval = DETECTION_OPTION_NO_MATCH;
    PROFILE_VARS;

    MODULE_PROFILE_START(dsizePerfStats);

    /* fake packet dsizes are always wrong
       (unless they are PDUs) */
    if (
        (p->packet_flags & PKT_REBUILT_STREAM) &&
        !(p->packet_flags & PKT_PDU_HEAD) )
    {
        MODULE_PROFILE_END(dsizePerfStats);
        return rval;
    }

    if ( config.eval(p->dsize) )
        rval = DETECTION_OPTION_MATCH;

    MODULE_PROFILE_END(dsizePerfStats);
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
    "rule option to test payload size"

class DsizeModule : public Module
{
public:
    DsizeModule() : Module(s_name, s_help, s_params) { }

    bool begin(const char*, int, SnortConfig*) override;
    bool set(const char*, Value&, SnortConfig*) override;

    ProfileStats* get_profile() const override
    { return &dsizePerfStats; }

    RangeCheck data;
};

bool DsizeModule::begin(const char*, int, SnortConfig*)
{
    data.init();
    return true;
}

bool DsizeModule::set(const char*, Value& v, SnortConfig*)
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
    return new DsizeModule;
}

static void mod_dtor(Module* m)
{
    delete m;
}

static IpsOption* dsize_ctor(Module* p, OptTreeNode*)
{
    DsizeModule* m = (DsizeModule*)p;
    return new DsizeOption(m->data);
}

static void dsize_dtor(IpsOption* p)
{
    delete p;
}

static const IpsApi dsize_api =
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
    dsize_ctor,
    dsize_dtor,
    nullptr
};

#ifdef BUILDING_SO
SO_PUBLIC const BaseApi* snort_plugins[] =
{
    &dsize_api.base,
    nullptr
};
#else
const BaseApi* ips_dsize = &dsize_api.base;
#endif

