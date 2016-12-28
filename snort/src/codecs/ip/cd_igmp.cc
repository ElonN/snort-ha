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
// cd_igmp.cc author Josh Rosenbaum <jrosenba@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "framework/codec.h"
#include "codecs/codec_module.h"
#include "protocols/packet.h"
#include "protocols/ipv4_options.h"

#define CD_IGMP_NAME "igmp"
#define CD_IGMP_HELP "support for Internet group management protocol"

namespace
{
static const RuleMap igmp_rules[] =
{
    { DECODE_IGMP_OPTIONS_DOS, "DOS IGMP IP options validation attempt" },
    { 0, nullptr }
};

class IgmpModule : public CodecModule
{
public:
    IgmpModule() : CodecModule(CD_IGMP_NAME, CD_IGMP_HELP) { }

    const RuleMap* get_rules() const
    { return igmp_rules; }
};

class IgmpCodec : public Codec
{
public:
    IgmpCodec() : Codec(CD_IGMP_NAME) { }
    ~IgmpCodec() { }

    bool decode(const RawData&, CodecData&, DecodeData&) override;
    void get_protocol_ids(std::vector<uint16_t>&) override;
};
} // namespace

bool IgmpCodec::decode(const RawData& raw, CodecData& codec, DecodeData& snort)
{
    if (snort.ip_api.is_ip4() && raw.len >= 1 && raw.data[0] == 0x11)
    {
        const uint8_t* ip_opt_data = snort.ip_api.get_ip_opt_data();

        if (ip_opt_data != nullptr)
        {
            if (snort.ip_api.get_ip_opt_len() >= 2)
            {
                if (*(ip_opt_data) == 0 && *(ip_opt_data+1) == 0)
                {
                    codec_event(codec, DECODE_IGMP_OPTIONS_DOS);
                    return false;
                }
            }
        }

        if ((!(codec.codec_flags & CODEC_IPOPT_RTRALT_SEEN)) &&
            (codec.codec_flags & CODEC_IPOPT_LEN_THREE))
        {
            codec_event(codec, DECODE_IGMP_OPTIONS_DOS);
        }
    }
    return true;
}

void IgmpCodec::get_protocol_ids(std::vector<uint16_t>& v)
{
    v.push_back(IPPROTO_IGMP);
}

//-------------------------------------------------------------------------
// api
//-------------------------------------------------------------------------

static Module* mod_ctor()
{ return new IgmpModule; }

static void mod_dtor(Module* m)
{ delete m; }

static Codec* ctor(Module*)
{ return new IgmpCodec(); }

static void dtor(Codec* cd)
{ delete cd; }

static const CodecApi igmp_api =
{
    {
        PT_CODEC,
        sizeof(CodecApi),
        CDAPI_VERSION,
        0,
        API_RESERVED,
        API_OPTIONS,
        CD_IGMP_NAME,
        CD_IGMP_HELP,
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
    &igmp_api.base,
    nullptr
};
#else
const BaseApi* cd_igmp = &igmp_api.base;
#endif

