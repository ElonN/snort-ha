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
// cd_ppp_encap.cc author Josh Rosenbaum <jrosenba@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "framework/codec.h"
#include "protocols/protocol_ids.h"
#include "main/snort_config.h"
#include "main/snort_debug.h"

#define CD_PPPENCAP_NAME "ppp_encap"
#define CD_PPPENCAP_HELP "support for point-to-point encapsulation"

namespace
{
class PppEncap : public Codec
{
public:
    PppEncap() : Codec(CD_PPPENCAP_NAME) { }
    ~PppEncap() { }

    void get_protocol_ids(std::vector<uint16_t>& v) override;
    bool decode(const RawData&, CodecData&, DecodeData&) override;
};

const static uint16_t PPP_IP = 0x0021;       /* Internet Protocol */
const static uint16_t PPP_IPV6 = 0x0057;        /* Internet Protocol v6 */
const static uint16_t PPP_VJ_COMP = 0x002d;        /* VJ compressed TCP/IP */
const static uint16_t PPP_VJ_UCOMP = 0x002f;        /* VJ uncompressed TCP/IP */
const static uint16_t PPP_IPX = 0x002b;        /* Novell IPX Protocol */
} // namespace

void PppEncap::get_protocol_ids(std::vector<uint16_t>& v)
{ v.push_back(ETHERTYPE_PPP); }

bool PppEncap::decode(const RawData& raw, CodecData& codec, DecodeData&)
{
    uint16_t protocol;

    DebugMessage(DEBUG_DECODE, "PPP Packet!\n");

#ifdef WORDS_MUSTALIGN
    DebugMessage(DEBUG_DECODE, "Packet with PPP header.  "
        "PPP is only 1 or 2 bytes and will throw off "
        "alignment on this architecture when decoding IP, "
        "causing a bus error - stop decoding packet.\n");
    return true;

#endif  /* WORDS_MUSTALIGN */

    if (raw.len < 2)
        return false;

    if (raw.data[0] & 0x01)
    {
        /* Check for protocol compression rfc1661 section 5
         *
         */
        codec.lyr_len = 1;
        protocol = raw.data[0];
    }
    else
    {
        protocol = ntohs(*((uint16_t*)raw.data));
        codec.lyr_len = 2;
    }

    /*
     * We only handle uncompressed packets. Handling VJ compression would mean
     * to implement a PPP state machine.
     */
    switch (protocol)
    {
    case PPP_VJ_COMP:
        return false;

    case PPP_VJ_UCOMP:
        /* VJ compression modifies the protocol field. It must be set
         * to tcp (only TCP packets can be VJ compressed) */
        if (raw.len < (uint32_t)(codec.lyr_len + ip::IP4_HEADER_LEN))
        {
            // PPP VJ min packet length > captured len
            return false;
        }

        ((IP4Hdr*)(raw.data + codec.lyr_len))->set_proto(IPPROTO_TCP);
    /* fall through */

    case PPP_IP:
        codec.next_prot_id = ETHERTYPE_IPV4;
        break;

    case PPP_IPV6:
        codec.next_prot_id = ETHERTYPE_IPV6;
        break;

    case PPP_IPX:
        codec.next_prot_id = ETHERTYPE_IPX;
        break;

    default:
        break;
    }
    return true;
}

//-------------------------------------------------------------------------
// api
//-------------------------------------------------------------------------

static Codec* ctor(Module*)
{ return new PppEncap(); }

static void dtor(Codec* cd)
{ delete cd; }

static const CodecApi pppencap_api =
{
    {
        PT_CODEC,
        sizeof(CodecApi),
        CDAPI_VERSION,
        0,
        API_RESERVED,
        API_OPTIONS,
        CD_PPPENCAP_NAME,
        CD_PPPENCAP_HELP,
        nullptr,
        nullptr,
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
    &pppencap_api.base,
    nullptr
};
#else
const BaseApi* cd_pppencap = &pppencap_api.base;
#endif

