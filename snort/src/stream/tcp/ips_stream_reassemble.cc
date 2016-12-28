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
// ips_stream_reassemble.cc author Russ Combs <rucombs@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "tcp_session.h"
#include "stream/stream_splitter.h"
#include "framework/ips_option.h"
#include "framework/module.h"
#include "framework/parameter.h"
#include "detection/detect.h"
#include "detection/detection_defines.h"
#include "hash/sfhashfcn.h"
#include "time/profiler.h"

#ifdef UNIT_TEST
#include "test/catch.hpp"
#include "stream/libtcp/stream_tcp_unit_test.h"
#endif

//-------------------------------------------------------------------------
// stream_reassemble
//-------------------------------------------------------------------------

#define s_name "stream_reassemble"
#define s_help \
    "detection option for stream reassembly control"

static THREAD_LOCAL ProfileStats streamReassembleRuleOptionPerfStats;

struct StreamReassembleRuleOptionData
{
    char enable;
    char alert;
    char direction;
    char fastpath;
};

class ReassembleOption : public IpsOption
{
public:
    ReassembleOption(const StreamReassembleRuleOptionData& c) :
        IpsOption(s_name)
    { srod = c; }

    uint32_t hash() const override;
    bool operator==(const IpsOption&) const override;

    int eval(Cursor&, Packet*) override;

private:
    StreamReassembleRuleOptionData srod;
};

//-------------------------------------------------------------------------
// stream_reassemble option
//-------------------------------------------------------------------------

uint32_t ReassembleOption::hash() const
{
    uint32_t a,b,c;

    a = srod.enable;
    b = srod.direction;
    c = srod.alert;

    mix(a,b,c);

    a = srod.fastpath;

    mix_str(a,b,c,get_name());
    final(a,b,c);

    return c;
}

bool ReassembleOption::operator==(const IpsOption& ips) const
{
    if ( strcmp(get_name(), ips.get_name()) )
        return false;

    const ReassembleOption& rhs = (ReassembleOption&)ips;

    if ( (srod.enable == rhs.srod.enable) &&
        (srod.direction == rhs.srod.direction) &&
        (srod.alert == rhs.srod.alert) )
        return true;

    return false;
}

int ReassembleOption::eval(Cursor&, Packet* pkt)
{
    if (!pkt->flow || !pkt->ptrs.tcph)
        return 0;

    PROFILE_VARS;
    MODULE_PROFILE_START(streamReassembleRuleOptionPerfStats);

    Flow* lwssn = (Flow*)pkt->flow;
    TcpSession* tcpssn = (TcpSession*)lwssn->session;

    if ( !srod.enable ) /* Turn it off */
    {
        if ( srod.direction & SSN_DIR_FROM_SERVER )
        {
            tcpssn->server.flush_policy = STREAM_FLPOLICY_IGNORE;
            stream.set_splitter(lwssn, true);
        }

        if ( srod.direction & SSN_DIR_FROM_CLIENT )
        {
            tcpssn->client.flush_policy = STREAM_FLPOLICY_IGNORE;
            stream.set_splitter(lwssn, false);
        }
    }
    else
    {
        // FIXIT-M PAF need to instantiate service splitter?
        // FIXIT-M PAF need to check for ips / on-data
        if ( srod.direction & SSN_DIR_FROM_SERVER )
        {
            tcpssn->server.flush_policy = STREAM_FLPOLICY_ON_ACK;
            stream.set_splitter(lwssn, true, new AtomSplitter(true));
        }

        if ( srod.direction & SSN_DIR_FROM_CLIENT )
        {
            tcpssn->client.flush_policy = STREAM_FLPOLICY_ON_ACK;
            stream.set_splitter(lwssn, false, new AtomSplitter(false));
        }
    }

    if (srod.fastpath)
    {
        /* Turn off inspection */
        lwssn->ssn_state.ignore_direction |= srod.direction;
        DisableInspection(pkt);

        /* TBD: Set TF_FORCE_FLUSH ? */
    }

    MODULE_PROFILE_END(streamReassembleRuleOptionPerfStats);

    if (srod.alert)
        return DETECTION_OPTION_MATCH;

    return DETECTION_OPTION_NO_ALERT;
}

//-------------------------------------------------------------------------
// stream_reassemble module
//-------------------------------------------------------------------------

static const Parameter s_params[] =
{
    { "action", Parameter::PT_ENUM, "disable|enable", nullptr,
      "stop or start stream reassembly" },

    { "direction", Parameter::PT_ENUM, "client|server|both", nullptr,
      "action applies to the given direction(s)" },

    { "noalert", Parameter::PT_IMPLIED, nullptr, nullptr,
      "don't alert when rule matches" },

    { "fastpath", Parameter::PT_IMPLIED, nullptr, nullptr,
      "optionally whitelist the remainder of the session" },

    { nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr }
};

class ReassembleModule : public Module
{
public:
    ReassembleModule() : Module(s_name, s_help, s_params) { }

    bool begin(const char*, int, SnortConfig*) override;
    bool set(const char*, Value&, SnortConfig*) override;

    ProfileStats* get_profile() const override
    { return &streamReassembleRuleOptionPerfStats; }

    StreamReassembleRuleOptionData srod;
};

bool ReassembleModule::begin(const char*, int, SnortConfig*)
{
    srod.enable = 0;
    srod.direction = 0;
    srod.alert = 1;
    srod.fastpath = 0;
    return true;
}

bool ReassembleModule::set(const char*, Value& v, SnortConfig*)
{
    if ( v.is("action") )
        srod.enable = v.get_long();

    else if ( v.is("direction") )
        srod.direction = v.get_long() + 1;

    else if ( v.is("noalert") )
        srod.alert = 0;

    else if ( v.is("fastpath") )
        srod.fastpath = 1;

    else
        return false;

    return true;
}

//-------------------------------------------------------------------------
// stream_reassemble api methods
//-------------------------------------------------------------------------

static Module* reassemble_mod_ctor()
{
    return new ReassembleModule;
}

static void mod_dtor(Module* m)
{
    delete m;
}

static IpsOption* reassemble_ctor(Module* p, OptTreeNode*)
{
    ReassembleModule* m = (ReassembleModule*)p;
    return new ReassembleOption(m->srod);
}

static void opt_dtor(IpsOption* p)
{
    delete p;
}

static const IpsApi reassemble_api =
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
        reassemble_mod_ctor,
        mod_dtor
    },
    OPT_TYPE_DETECTION,
    1, PROTO_BIT__TCP,
    nullptr,
    nullptr,
    nullptr,
    nullptr,
    reassemble_ctor,
    opt_dtor,
    nullptr
};

const BaseApi* ips_stream_reassemble = &reassemble_api.base;

#ifdef UNIT_TEST

#include "framework/cursor.h"

TEST_CASE("IPS Stream Reassemble", "[ips_stream_reassemble][stream_tcp]")
{
    // initialization code here
    REQUIRE( ( ips_stream_reassemble->api_version == ((BASE_API_VERSION << 16) | 0) ) );
    REQUIRE( ( strcmp( ips_stream_reassemble->name, s_name ) == 0 ) );
    ReassembleModule* reassembler = ( ReassembleModule* ) ips_stream_reassemble->mod_ctor();
    REQUIRE( ( reassembler != nullptr ) );

    Flow* flow = new Flow;
    Packet* pkt = get_syn_packet( flow );
    pkt->flow->session = new TcpSession( flow );
    Cursor cursor( pkt );

    SECTION("reassembler initialization")
    {
        bool status = reassembler->begin( nullptr, 0, snort_conf );
        CHECK( status );
        CHECK( ( reassembler->srod.enable == 0 ) );
        CHECK( ( reassembler->srod.direction == 0 ) );
        CHECK( ( reassembler->srod.alert == 1 ) );
        CHECK( ( reassembler->srod.fastpath == 0 ) );
    }

#if 0
    SECTION("eval enable off")
    {
        reassembler->srod.direction = SSN_DIR_FROM_SERVER;
        IpsOption* ropt = reassemble_api.ctor( reassembler, nullptr );
        int rc = ropt->eval( cursor, pkt );
        CHECK( ( rc == DETECTION_OPTION_MATCH ) );
        StreamSplitter* ss = stream.get_splitter( flow, true );
        CHECK( ( ss != nullptr ) );
        CHECK( ( !ss->is_paf() ) );
        CHECK( ( ( ( TcpSession* ) pkt->flow->session)->server.flush_policy
                == STREAM_FLPOLICY_IGNORE ) );
    }
#endif

}


#endif
