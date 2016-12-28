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
// ips_icode.cc author Russ Combs <rucombs@cisco.com>

#include <stdlib.h>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include <string.h>
#include <ctype.h>

#include "main/snort_types.h"
#include "main/snort_debug.h"
#include "protocols/packet.h"
#include "hash/sfhashfcn.h"
#include "time/profiler.h"
#include "detection/detection_defines.h"
#include "framework/ips_option.h"
#include "framework/parameter.h"
#include "framework/module.h"
#include "framework/range.h"
#include "protocols/icmp4.h"

#define s_name "icode"

static THREAD_LOCAL ProfileStats icmpCodePerfStats;

class IcodeOption : public IpsOption
{
public:
    IcodeOption(const RangeCheck& c) :
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

uint32_t IcodeOption::hash() const
{
    uint32_t a,b,c;

    a = config.op;
    b = config.min;
    c = config.max;

    mix_str(a,b,c,get_name());
    final(a,b,c);

    return c;
}

bool IcodeOption::operator==(const IpsOption& ips) const
{
    if ( strcmp(get_name(), ips.get_name()) )
        return false;

    IcodeOption& rhs = (IcodeOption&)ips;
    return ( config == rhs.config );
}

int IcodeOption::eval(Cursor&, Packet* p)
{
    int rval = DETECTION_OPTION_NO_MATCH;
    PROFILE_VARS;

    /* return 0  if we don't have an icmp header */
    if (!p->ptrs.icmph)
        return rval;

    MODULE_PROFILE_START(icmpCodePerfStats);

    if ( config.eval(p->ptrs.icmph->code) )
        rval = DETECTION_OPTION_MATCH;

    MODULE_PROFILE_END(icmpCodePerfStats);
    return rval;
}

//-------------------------------------------------------------------------
// module
//-------------------------------------------------------------------------

static const Parameter s_params[] =
{
    { "~range", Parameter::PT_STRING, nullptr, nullptr,
      "check if ICMP code is 'code | min<>max | <max | >min'" },

    { nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr }
};

#define s_help \
    "rule option to check ICMP code"

class IcodeModule : public Module
{
public:
    IcodeModule() : Module(s_name, s_help, s_params) { }

    bool begin(const char*, int, SnortConfig*) override;
    bool set(const char*, Value&, SnortConfig*) override;

    ProfileStats* get_profile() const override
    { return &icmpCodePerfStats; }

    RangeCheck data;
};

bool IcodeModule::begin(const char*, int, SnortConfig*)
{
    data.init();
    return true;
}

bool IcodeModule::set(const char*, Value& v, SnortConfig*)
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
    return new IcodeModule;
}

static void mod_dtor(Module* m)
{
    delete m;
}

static IpsOption* icode_ctor(Module* p, OptTreeNode*)
{
    IcodeModule* m = (IcodeModule*)p;
    return new IcodeOption(m->data);
}

static void icode_dtor(IpsOption* p)
{
    delete p;
}

static const IpsApi icode_api =
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
    1, PROTO_BIT__ICMP,
    nullptr,
    nullptr,
    nullptr,
    nullptr,
    icode_ctor,
    icode_dtor,
    nullptr
};

#ifdef BUILDING_SO
SO_PUBLIC const BaseApi* snort_plugins[] =
{
    &icode_api.base,
    nullptr
};
#else
const BaseApi* ips_icode = &icode_api.base;
#endif

