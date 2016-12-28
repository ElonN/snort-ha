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
// codec.h author Josh Rosenbaum <jrosenba@cisco.com>

#include "framework/codec.h"
#include "events/event_queue.h"
#include "codecs/codec_module.h"
#include "protocols/ipv6.h"

EncState::EncState(const ip::IpApi& api, EncodeFlags f, uint8_t pr,
    uint8_t t, uint16_t data_size) :
    ip_api(api),
    flags(f),
    dsize(data_size),
    next_ethertype(0),
    next_proto(pr),
    ttl(t)
{ }

uint8_t EncState::get_ttl(uint8_t lyr_ttl) const
{
    if ( forward() )
    {
        if (flags & ENC_FLAG_TTL)
            return ttl;
        else
            return lyr_ttl;
    }
    else
    {
        uint8_t new_ttl;

        if (flags & ENC_FLAG_TTL)
            new_ttl = ttl;
        else
            new_ttl = MAX_TTL - lyr_ttl;

        if (new_ttl < MIN_TTL)
            new_ttl = MIN_TTL;

        return new_ttl;
    }
}

/* Logic behind 'buf + size + 1' -- we're encoding the
 * packet from the inside out.  So, whenever we add
 * data, 'allocating' N bytes means moving the pointer
 * N characters farther from the end. For this scheme
 * to work, an empty Buffer means the data pointer is
 * invalid and is actually one byte past the end of the
 * array
 */
Buffer::Buffer(uint8_t* buf, uint32_t size) :
    base(buf + size + 1),
    end(0),
    max_len(size),
    off(0)
{ }

void Codec::codec_event(const CodecData& codec, CodecSid sid)
{
    if ( codec.codec_flags & CODEC_STREAM_REBUILT )
        return;

    SnortEventqAdd(GID_DECODE, sid);
}

bool Codec::CheckIPV6HopOptions(const RawData& raw, const CodecData& codec)
{
    const ip::IP6Extension* const exthdr =
        reinterpret_cast<const ip::IP6Extension*>(raw.data);

    const uint8_t* pkt =
        reinterpret_cast<const uint8_t*>(raw.data);

    const uint32_t total_octets = (exthdr->ip6e_len * 8) + 8;
    const uint8_t* hdr_end = pkt + total_octets;
    uint8_t oplen;

    if (raw.len < total_octets)
        codec_event(codec, DECODE_IPV6_TRUNCATED_EXT);

    /* Skip to the options */
    pkt += 2;

    /* Iterate through the options, check for bad ones */
    while (pkt < hdr_end)
    {
        const ip::HopByHopOptions type = static_cast<ip::HopByHopOptions>(*pkt);
        switch (type)
        {
        case ip::HopByHopOptions::PAD1:
            pkt++;
            break;
        case ip::HopByHopOptions::PADN:
        case ip::HopByHopOptions::JUMBO:
        case ip::HopByHopOptions::RTALERT:
        case ip::HopByHopOptions::TUNNEL_ENCAP:
        case ip::HopByHopOptions::QUICK_START:
        case ip::HopByHopOptions::CALIPSO:
        case ip::HopByHopOptions::HOME_ADDRESS:
        case ip::HopByHopOptions::ENDPOINT_IDENT:
            oplen = *(++pkt);
            if ((pkt + oplen + 1) > hdr_end)
            {
                codec_event(codec, DECODE_IPV6_BAD_OPT_LEN);
                return false;
            }
            pkt += oplen + 1;
            break;
        default:
            codec_event(codec, DECODE_IPV6_BAD_OPT_TYPE);
            return false;
        }
    }

    return true;
}

void Codec::CheckIPv6ExtensionOrder(CodecData& codec, const uint8_t proto)
{
    const uint8_t current_order = ip::IPV6ExtensionOrder(proto);

    if (current_order <= codec.curr_ip6_extension)
    {
        const uint8_t next_order = ip::IPV6ExtensionOrder(codec.next_prot_id);

        /* A second "Destination Options" header is allowed iff:
           1) A routing header was already seen, and
           2) The second destination header is the last one before the upper layer.
        */
        if (!((codec.codec_flags & CODEC_ROUTING_SEEN) &&
            (proto == IPPROTO_ID_DSTOPTS) &&
            (next_order == ip::IPV6_ORDER_MAX)))
        {
            codec_event(codec, DECODE_IPV6_UNORDERED_EXTENSIONS);
        }
    }
    else
    {
        codec.curr_ip6_extension = current_order;
    }

    if (proto == IPPROTO_ID_ROUTING)
        codec.codec_flags |= CODEC_ROUTING_SEEN;
}

