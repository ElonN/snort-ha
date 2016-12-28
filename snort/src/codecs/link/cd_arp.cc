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
// cd_arp.cc author Josh Rosenbaum <jrosenba@cisco.com>

#include "framework/codec.h"
#include "codecs/codec_module.h"
#include "protocols/protocol_ids.h"
#include "protocols/arp.h"
#include "protocols/packet.h"
#include "log/text_log.h"

#define CD_ARP_NAME "arp"
#define CD_ARP_HELP "support for address resolution protocol"

namespace
{
static const RuleMap arp_rules[] =
{
    { DECODE_ARP_TRUNCATED, "truncated ARP" },
    { 0, nullptr }
};

class ArpModule : public CodecModule
{
public:
    ArpModule() : CodecModule(CD_ARP_NAME, CD_ARP_HELP) { }

    const RuleMap* get_rules() const override
    { return arp_rules; }
};

class ArpCodec : public Codec
{
public:
    ArpCodec() : Codec(CD_ARP_NAME) { }
    ~ArpCodec() { }

    void get_protocol_ids(std::vector<uint16_t>& v) override;
    bool decode(const RawData&, CodecData&, DecodeData&) override;
    void format(bool reverse, uint8_t* raw_pkt, DecodeData& snort) override;
};
} // anonymous namespace

void ArpCodec::get_protocol_ids(std::vector<uint16_t>& v)
{
    v.push_back(ETHERTYPE_ARP);
    v.push_back(ETHERTYPE_REVARP);
}

bool ArpCodec::decode(const RawData& raw, CodecData& codec, DecodeData& snort)
{
    if (raw.len < arp::ETHERARP_HDR_LEN)
    {
        codec_event(codec, DECODE_ARP_TRUNCATED);
        return false;
    }

    codec.proto_bits |= PROTO_BIT__ARP;
    codec.lyr_len = arp::ETHERARP_HDR_LEN;
    snort.set_pkt_type(PktType::ARP);

    return true;
}

void ArpCodec::format(bool /*reverse*/, uint8_t* /*raw_pkt*/, DecodeData& snort)
{
    snort.set_pkt_type(PktType::ARP);
}

//-------------------------------------------------------------------------
// api
//-------------------------------------------------------------------------

static Module* mod_ctor()
{ return new ArpModule; }

static void mod_dtor(Module* m)
{ delete m; }

static Codec* ctor(Module*)
{ return new ArpCodec(); }

static void dtor(Codec* cd)
{ delete cd; }

static const CodecApi arp_api =
{
    {
        PT_CODEC,
        sizeof(CodecApi),
        CDAPI_VERSION,
        0,
        API_RESERVED,
        API_OPTIONS,
        CD_ARP_NAME,
        CD_ARP_HELP,
        mod_ctor,
        mod_dtor,
    },
    nullptr, // pinit
    nullptr, // pterm
    nullptr, // tinit
    nullptr, // tterm
    ctor, // ctor
    dtor, // dtor
};

#ifdef BUILDING_SO
SO_PUBLIC const BaseApi* snort_plugins[] =
{
    &arp_api.base,
    nullptr
};
#else
const BaseApi* cd_arp = &arp_api.base;
#endif

