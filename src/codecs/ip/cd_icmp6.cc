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
// cd_icmp6.cc author Josh Rosenbaum <jrosenba@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "main/snort_config.h"
#include "framework/codec.h"
#include "protocols/icmp6.h"
#include "protocols/icmp4.h"
#include "codecs/codec_module.h"
#include "codecs/codec_module.h"
#include "codecs/ip/checksum.h"
#include "packet_io/active.h"
#include "log/text_log.h"
#include "main/snort_debug.h"

#define CD_ICMP6_NAME "icmp6"
#define CD_ICMP6_HELP "support for Internet control message protocol v6"

namespace
{
const PegInfo pegs[]
{
    { "bad checksum (ip4)", "nonzero ipcm4 checksums" },
    { "bad checksum (ip6)", "nonzero ipcm6 checksums" },
    { nullptr, nullptr }
};

struct Stats
{
    PegCount bad_ip4_cksum;
    PegCount bad_ip6_cksum;
};

static THREAD_LOCAL Stats stats;

static const RuleMap icmp6_rules[] =
{
    { DECODE_ICMP6_HDR_TRUNC, "truncated ICMP6 header" },
    { DECODE_ICMP6_TYPE_OTHER, "ICMP6 type not decoded" },
    { DECODE_ICMP6_DST_MULTICAST, "ICMP6 packet to multicast address" },
    { DECODE_ICMPV6_TOO_BIG_BAD_MTU,
      "ICMPv6 packet of type 2 (message too big) with MTU field < 1280" },
    { DECODE_ICMPV6_UNREACHABLE_NON_RFC_2463_CODE,
      "ICMPv6 packet of type 1 (destination unreachable) with non-RFC 2463 code" },
    { DECODE_ICMPV6_SOLICITATION_BAD_CODE,
      "ICMPv6 router solicitation packet with a code not equal to 0" },
    { DECODE_ICMPV6_ADVERT_BAD_CODE,
      "ICMPv6 router advertisement packet with a code not equal to 0" },
    { DECODE_ICMPV6_SOLICITATION_BAD_RESERVED,
      "ICMPv6 router solicitation packet with the reserved field not equal to 0" },
    { DECODE_ICMPV6_ADVERT_BAD_REACHABLE,
      "ICMPv6 router advertisement packet with the reachable time field set > 1 hour" },
    { DECODE_ICMPV6_UNREACHABLE_NON_RFC_4443_CODE,
      "ICMPv6 packet of type 1 (destination unreachable) with non-RFC 4443 code" },
    { DECODE_ICMPV6_NODE_INFO_BAD_CODE,
      "ICMPv6 node info query/response packet with a code greater than 2" },
    { 0, nullptr }
};

class Icmp6Module : public CodecModule
{
public:
    Icmp6Module() : CodecModule(CD_ICMP6_NAME, CD_ICMP6_HELP) { }

    const RuleMap* get_rules() const override
    { return icmp6_rules; }

    const PegInfo* get_pegs() const override
    { return pegs; }

    PegCount* get_counts() const override
    { return (PegCount*)&stats; }
};

class Icmp6Codec : public Codec
{
public:
    Icmp6Codec() : Codec(CD_ICMP6_NAME) { }
    ~Icmp6Codec() { }

    void get_protocol_ids(std::vector<uint16_t>& v) override;
    bool decode(const RawData&, CodecData&, DecodeData&) override;
    void update(const ip::IpApi&, const EncodeFlags, uint8_t* raw_pkt,
        uint16_t lyr_len, uint32_t& updated_len) override;
    void format(bool reverse, uint8_t* raw_pkt, DecodeData& snort) override;
    void log(TextLog* const, const uint8_t* pkt, const uint16_t len) override;
};
} // anonymous namespace

void Icmp6Codec::get_protocol_ids(std::vector<uint16_t>& v)
{ v.push_back(IPPROTO_ID_ICMPV6); }

bool Icmp6Codec::decode(const RawData& raw, CodecData& codec, DecodeData& snort)
{
    if (raw.len < icmp::ICMP6_HEADER_MIN_LEN)
    {
        codec_event(codec, DECODE_ICMP6_HDR_TRUNC);
        return false;
    }

    const icmp::Icmp6Hdr* const icmp6h = reinterpret_cast<const icmp::Icmp6Hdr*>(raw.data);

    /* Do checksums */
    if (SnortConfig::icmp_checksums())
    {
        uint16_t csum;
        PegCount* bad_cksum_cnt;

        if (snort.ip_api.is_ip4())
        {
            bad_cksum_cnt = &stats.bad_ip4_cksum;
            csum = checksum::cksum_add((uint16_t*)(icmp6h), raw.len);
        }
        /* IPv6 traffic */
        else
        {
            bad_cksum_cnt = &stats.bad_ip6_cksum;
            checksum::Pseudoheader6 ph6;
            COPY4(ph6.sip, snort.ip_api.get_src()->ip32);
            COPY4(ph6.dip, snort.ip_api.get_dst()->ip32);
            ph6.zero = 0;
            ph6.protocol = codec.ip6_csum_proto;
            ph6.len = htons((u_short)raw.len);

            csum = checksum::icmp_cksum((uint16_t*)(icmp6h), raw.len, &ph6);
        }
        if (csum && !codec.is_cooked())
        {
            (*bad_cksum_cnt)++;
            snort.decode_flags |= DECODE_ERR_CKSUM_ICMP;
            return false;
        }
    }

    const uint16_t dsize = raw.len - icmp::ICMP6_HEADER_MIN_LEN;
    uint16_t len;

    switch (icmp6h->type)
    {
    case icmp::Icmp6Types::ECHO_6:
    case icmp::Icmp6Types::REPLY_6:
        if (dsize >= sizeof(ICMPHdr::icmp_hun.idseq))
        {
            len = icmp::ICMP6_HEADER_NORMAL_LEN;

            if ( snort.ip_api.get_ip6h()->is_dst_multicast() )
                codec_event(codec, DECODE_ICMP6_DST_MULTICAST);
        }
        else
        {
            codec_event(codec, DECODE_ICMP_DGRAM_LT_ICMPHDR);
            return false;
        }
        break;

    case icmp::Icmp6Types::BIG:
        if (dsize >= sizeof(icmp::ICMP6TooBig))
        {
            icmp::ICMP6TooBig* too_big = (icmp::ICMP6TooBig*)raw.data;

            if (ntohl(too_big->mtu) < 1280)
                codec_event(codec, DECODE_ICMPV6_TOO_BIG_BAD_MTU);

            len = icmp::ICMP6_HEADER_NORMAL_LEN;
            codec.next_prot_id = PROTO_IP_EMBEDDED_IN_ICMP6;
        }
        else
        {
            codec_event(codec, DECODE_ICMP_DGRAM_LT_ICMPHDR);
            return false;
        }
        break;

    case icmp::Icmp6Types::TIME:
    case icmp::Icmp6Types::PARAMS:
    case icmp::Icmp6Types::UNREACH:
        if (dsize >= 4)
        {
            if (icmp6h->type == icmp::Icmp6Types::UNREACH)
            {
                if (icmp6h->code == icmp::Icmp6Code::UNREACH_INVALID)     // UNREACH_INVALID == 2
                    codec_event(codec, DECODE_ICMPV6_UNREACHABLE_NON_RFC_2463_CODE);

                else if (static_cast<uint8_t>(icmp6h->code) > 6)
                    codec_event(codec, DECODE_ICMPV6_UNREACHABLE_NON_RFC_4443_CODE);
            }
            len = icmp::ICMP6_HEADER_NORMAL_LEN;
            codec.next_prot_id = PROTO_IP_EMBEDDED_IN_ICMP6;
        }
        else
        {
            codec_event(codec, DECODE_ICMP_DGRAM_LT_ICMPHDR);
            return false;
        }
        break;

    case icmp::Icmp6Types::ADVERTISEMENT:
        if (dsize >= (sizeof(icmp::ICMP6RouterAdvertisement) - icmp::ICMP6_HEADER_MIN_LEN))
        {
            icmp::ICMP6RouterAdvertisement* ra = (icmp::ICMP6RouterAdvertisement*)raw.data;

            if (icmp6h->code != icmp::Icmp6Code::ADVERTISEMENT)
                codec_event(codec, DECODE_ICMPV6_ADVERT_BAD_CODE);

            if (ntohl(ra->reachable_time) > 3600000)
                codec_event(codec, DECODE_ICMPV6_ADVERT_BAD_REACHABLE);

            len = icmp::ICMP6_HEADER_MIN_LEN;
        }
        else
        {
            codec_event(codec, DECODE_ICMP_DGRAM_LT_ICMPHDR);
            return false;
        }
        break;

    case icmp::Icmp6Types::SOLICITATION:
        if (dsize >= (sizeof(icmp::ICMP6RouterSolicitation) - icmp::ICMP6_HEADER_MIN_LEN))
        {
            icmp::ICMP6RouterSolicitation* rs = (icmp::ICMP6RouterSolicitation*)raw.data;
            if (rs->code != 0)
                codec_event(codec, DECODE_ICMPV6_SOLICITATION_BAD_CODE);

            if (ntohl(rs->reserved) != 0)
                codec_event(codec, DECODE_ICMPV6_SOLICITATION_BAD_RESERVED);

            len = icmp::ICMP6_HEADER_MIN_LEN;
        }
        else
        {
            codec_event(codec, DECODE_ICMP_DGRAM_LT_ICMPHDR);
            return false;
        }
        break;

    case icmp::Icmp6Types::NODE_INFO_QUERY:
    case icmp::Icmp6Types::NODE_INFO_RESPONSE:
        if (dsize >= (sizeof(icmp::ICMP6NodeInfo) - icmp::ICMP6_HEADER_MIN_LEN))
        {
            icmp::ICMP6NodeInfo* ni = (icmp::ICMP6NodeInfo*)raw.data;
            if (ni->code > 2)
                codec_event(codec, DECODE_ICMPV6_NODE_INFO_BAD_CODE);

            /* FIXIT: Add alert for INFO Response, code == 1 || code == 2)
             * and there is data.
             */
            len = icmp::ICMP6_HEADER_MIN_LEN;
        }
        else
        {
            codec_event(codec, DECODE_ICMP_DGRAM_LT_ICMPHDR);
            return false;
        }
        break;

    default:
        codec_event(codec, DECODE_ICMP6_TYPE_OTHER);
        len = icmp::ICMP6_HEADER_MIN_LEN;
        break;
    }

    codec.lyr_len = len;
    codec.proto_bits |= PROTO_BIT__ICMP;
    snort.icmph = reinterpret_cast<const icmp::ICMPHdr*>(icmp6h);
    snort.set_pkt_type(PktType::ICMP);
    return true;
}

/******************************************************************
 *************************  L O G G E R   *************************
 ******************************************************************/

void Icmp6Codec::log(TextLog* const text_log, const uint8_t* raw_pkt,
    const uint16_t /*lyr_len*/)
{
    const icmp::Icmp6Hdr* const icmph = reinterpret_cast<const icmp::Icmp6Hdr*>(raw_pkt);
    TextLog_Print(text_log, "sType:%d  Code:%d  ", icmph->type, icmph->code);
}

/******************************************************************
 ************************* E N C O D E R  *************************
 ******************************************************************/

namespace
{
struct IcmpHdr
{
    uint8_t type;
    uint8_t code;
    uint16_t cksum;
    uint32_t unused;
};
} // namespace

void Icmp6Codec::update(const ip::IpApi& api, const EncodeFlags flags,
    uint8_t* raw_pkt, uint16_t /*lyr_len*/, uint32_t& updated_len)
{
    IcmpHdr* h = reinterpret_cast<IcmpHdr*>(raw_pkt);
    updated_len += sizeof(*h);

    if ( !(flags & UPD_COOKED) || (flags & UPD_REBUILT_FRAG) )
    {
        checksum::Pseudoheader6 ps6;
        h->cksum = 0;

        memcpy(ps6.sip, api.get_src()->ip32, sizeof(ps6.sip));
        memcpy(ps6.dip, api.get_dst()->ip32, sizeof(ps6.dip));
        ps6.zero = 0;
        ps6.protocol = IPPROTO_ICMPV6;
        ps6.len = htons((uint16_t)updated_len);
        h->cksum = checksum::icmp_cksum((uint16_t*)h, updated_len, &ps6);
    }
}

void Icmp6Codec::format(bool /*reverse*/, uint8_t* raw_pkt, DecodeData& snort)
{
    snort.icmph = reinterpret_cast<ICMPHdr*>(raw_pkt);
    snort.set_pkt_type(PktType::ICMP);
}

//-------------------------------------------------------------------------
// api
//-------------------------------------------------------------------------

static Module* mod_ctor()
{ return new Icmp6Module; }

static void mod_dtor(Module* m)
{ delete m; }

static Codec* ctor(Module*)
{ return new Icmp6Codec(); }

static void dtor(Codec* cd)
{ delete cd; }

static const CodecApi ipv6_api =
{
    {
        PT_CODEC,
        sizeof(CodecApi),
        CDAPI_VERSION,
        0,
        API_RESERVED,
        API_OPTIONS,
        CD_ICMP6_NAME,
        CD_ICMP6_HELP,
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
    &ipv6_api.base,
    nullptr
};
#else
const BaseApi* cd_icmp6 = &ipv6_api.base;
#endif

