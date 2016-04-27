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
// ips_seq.cc author Russ Combs <rucombs@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "main/snort_types.h"
#include "main/snort_debug.h"
#include "time/profiler.h"
#include "hash/sfhashfcn.h"
#include "detection/detection_defines.h"
#include "framework/ips_option.h"
#include "framework/parameter.h"
#include "framework/module.h"
#include "framework/range.h"
#include "protocols/packet.h"
#include "protocols/tcp.h"

#define s_name "seq"

static THREAD_LOCAL ProfileStats tcpSeqPerfStats;

class TcpSeqOption : public IpsOption
{
public:
    TcpSeqOption(const RangeCheck& c) :
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

uint32_t TcpSeqOption::hash() const
{
    uint32_t a,b,c;

    a = config.op;
    b = config.min;
    c = config.max;

    mix_str(a,b,c,get_name());
    final(a,b,c);

    return c;
}

bool TcpSeqOption::operator==(const IpsOption& ips) const
{
    if ( strcmp(get_name(), ips.get_name()) )
        return false;

    TcpSeqOption& rhs = (TcpSeqOption&)ips;
    return ( config == rhs.config );
}

int TcpSeqOption::eval(Cursor&, Packet* p)
{
    int rval = DETECTION_OPTION_NO_MATCH;
    PROFILE_VARS;

    if (!p->ptrs.tcph)
        return rval;

    MODULE_PROFILE_START(tcpSeqPerfStats);

    if ( config.eval(p->ptrs.tcph->th_seq) )
        rval = DETECTION_OPTION_MATCH;

    MODULE_PROFILE_END(tcpSeqPerfStats);
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
    "rule option to check TCP sequence number"

class SeqModule : public Module
{
public:
    SeqModule() : Module(s_name, s_help, s_params) { }

    bool begin(const char*, int, SnortConfig*) override;
    bool set(const char*, Value&, SnortConfig*) override;

    ProfileStats* get_profile() const override
    { return &tcpSeqPerfStats; }

    RangeCheck data;
};

bool SeqModule::begin(const char*, int, SnortConfig*)
{
    data.init();
    return true;
}

bool SeqModule::set(const char*, Value& v, SnortConfig*)
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
    return new SeqModule;
}

static void mod_dtor(Module* m)
{
    delete m;
}

static IpsOption* seq_ctor(Module* p, OptTreeNode*)
{
    SeqModule* m = (SeqModule*)p;
    return new TcpSeqOption(m->data);
}

static void seq_dtor(IpsOption* p)
{
    delete p;
}

static const IpsApi seq_api =
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
    1, PROTO_BIT__TCP,
    nullptr,
    nullptr,
    nullptr,
    nullptr,
    seq_ctor,
    seq_dtor,
    nullptr
};

#ifdef BUILDING_SO
SO_PUBLIC const BaseApi* snort_plugins[] =
{
    &seq_api.base,
    nullptr
};
#else
const BaseApi* ips_seq = &seq_api.base;
#endif

