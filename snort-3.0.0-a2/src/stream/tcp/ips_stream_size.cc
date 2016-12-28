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
// ips_stream_size.cc author Russ Combs <rucombs@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "tcp_session.h"
#include "framework/ips_option.h"
#include "framework/module.h"
#include "framework/parameter.h"
#include "framework/range.h"
#include "detection/detect.h"
#include "detection/detection_defines.h"
#include "hash/sfhashfcn.h"
#include "time/profiler.h"
#include "sfip/sf_ip.h"

//-------------------------------------------------------------------------
// stream_size
//-------------------------------------------------------------------------

#define s_name "stream_size"
#define s_help \
    "detection option for stream size checking"

static THREAD_LOCAL ProfileStats streamSizePerfStats;

class SizeOption : public IpsOption
{
public:
    SizeOption(const RangeCheck& c, int dir) :
        IpsOption(s_name)
    { ssod = c; direction = dir; }

    uint32_t hash() const override;
    bool operator==(const IpsOption&) const override;

    int eval(Cursor&, Packet*) override;

private:
    RangeCheck ssod;
    int direction;
};

//-------------------------------------------------------------------------
// stream_size option
//-------------------------------------------------------------------------

uint32_t SizeOption::hash() const
{
    uint32_t a,b,c;

    a = ssod.op;
    b = ssod.min;
    c = ssod.max;

    mix(a,b,c);

    a = direction;

    mix_str(a,b,c,get_name());
    final(a,b,c);

    return c;
}

bool SizeOption::operator==(const IpsOption& ips) const
{
    if ( strcmp(get_name(), ips.get_name()) )
        return false;

    const SizeOption& rhs = (SizeOption&)ips;

    if ( (direction == rhs.direction) && (ssod == rhs.ssod) )
        return true;

    return false;
}

int SizeOption::eval(Cursor&, Packet* pkt)
{
    if (!pkt->flow || !pkt->ptrs.tcph)
        return DETECTION_OPTION_NO_MATCH;

    PROFILE_VARS;
    MODULE_PROFILE_START(streamSizePerfStats);

    Flow* lwssn = (Flow*)pkt->flow;
    TcpSession* tcpssn = (TcpSession*)lwssn->session;

    uint32_t client_size;
    uint32_t server_size;

    if (tcpssn->client.l_nxt_seq > tcpssn->client.isn)
    {
        /* the normal case... */
        client_size = tcpssn->client.l_nxt_seq - tcpssn->client.isn;
    }
    else
    {
        /* the seq num wrapping case... */
        client_size = tcpssn->client.isn - tcpssn->client.l_nxt_seq;
    }

    if (tcpssn->server.l_nxt_seq > tcpssn->server.isn)
    {
        /* the normal case... */
        server_size = tcpssn->server.l_nxt_seq - tcpssn->server.isn;
    }
    else
    {
        /* the seq num wrapping case... */
        server_size = tcpssn->server.isn - tcpssn->server.l_nxt_seq;
    }

    int result = DETECTION_OPTION_NO_MATCH;

    switch ( direction )
    {
    case SSN_DIR_FROM_CLIENT:
        if ( ssod.eval(client_size) )
            result = DETECTION_OPTION_MATCH;
        break;

    case SSN_DIR_FROM_SERVER:
        if ( ssod.eval(server_size) )
            result = DETECTION_OPTION_MATCH;
        break;

    case SSN_DIR_NONE: /* overloaded.  really, its an 'either' */
        if ( ssod.eval(client_size) || ssod.eval(server_size) )
            result = DETECTION_OPTION_MATCH;
        break;

    case SSN_DIR_BOTH:
        if ( ssod.eval(client_size) && ssod.eval(server_size) )
            result = DETECTION_OPTION_MATCH;
        break;

    default:
        break;
    }
    MODULE_PROFILE_END(streamSizePerfStats);
    return result;
}

//-------------------------------------------------------------------------
// stream_size module
//-------------------------------------------------------------------------

static const Parameter s_params[] =
{
    { "~range", Parameter::PT_STRING, nullptr, nullptr,
      "size for comparison" },

    { "~direction", Parameter::PT_ENUM, "either|to_server|to_client|both", nullptr,
      "compare applies to the given direction(s)" },

    { nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr }
};

class SizeModule : public Module
{
public:
    SizeModule() : Module(s_name, s_help, s_params) { }

    bool begin(const char*, int, SnortConfig*) override;
    bool set(const char*, Value&, SnortConfig*) override;

    ProfileStats* get_profile() const override
    { return &streamSizePerfStats; }

    RangeCheck ssod;
    int direction;
};

bool SizeModule::begin(const char*, int, SnortConfig*)
{
    ssod.init();
    direction = 0;
    return true;
}

bool SizeModule::set(const char*, Value& v, SnortConfig*)
{
    if ( v.is("~range") )
        ssod.parse(v.get_string());

    else if ( v.is("~direction") )
        direction = v.get_long();

    else
        return false;

    return true;
}

//-------------------------------------------------------------------------
// stream_size api methods
//-------------------------------------------------------------------------

static Module* size_mod_ctor()
{
    return new SizeModule;
}

static void mod_dtor(Module* m)
{
    delete m;
}

static IpsOption* size_ctor(Module* p, OptTreeNode*)
{
    SizeModule* m = (SizeModule*)p;
    return new SizeOption(m->ssod, m->direction);
}

static void opt_dtor(IpsOption* p)
{
    delete p;
}

static const IpsApi size_api =
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
        size_mod_ctor,
        mod_dtor
    },
    OPT_TYPE_DETECTION,
    1, PROTO_BIT__TCP,
    nullptr,
    nullptr,
    nullptr,
    nullptr,
    size_ctor,
    opt_dtor,
    nullptr
};

const BaseApi* ips_stream_size = &size_api.base;

