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
// cd_ipv4.cc author Josh Rosenbaum <jrosenba@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <arpa/inet.h>
#include <array>

#include "utils/dnet_header.h"
#include "main/snort_config.h"

#include "protocols/tcp.h"
#include "protocols/ipv4.h"
#include "protocols/packet_manager.h"

#include "utils/stats.h"
#include "packet_io/active.h"
#include "codecs/ip/checksum.h"
#include "main/thread.h"
#include "stream/stream_api.h"
#include "codecs/codec_module.h"
#include "protocols/ip.h"
#include "protocols/ipv4_options.h"
#include "log/text_log.h"
#include "log/log_text.h"
#include "sfip/sf_ipvar.h"
#include "parser/parse_ip.h"

#define CD_IPV4_NAME "ipv4"
#define CD_IPV4_HELP "support for Internet protocol v4"

namespace
{
const PegInfo pegs[]
{
    { "bad checksum", "nonzero ip checksums" },
    { nullptr, nullptr }
};

struct Stats
{
    PegCount bad_cksum;
};

static THREAD_LOCAL Stats stats;
static sfip_var_t* MulticastReservedIp = nullptr;

static const RuleMap ipv4_rules[] =
{
    { DECODE_NOT_IPV4_DGRAM, "Not IPv4 datagram" },
    { DECODE_IPV4_INVALID_HEADER_LEN, "hlen < minimum" },
    { DECODE_IPV4_DGRAM_LT_IPHDR, "IP dgm len < IP Hdr len" },
    { DECODE_IPV4OPT_BADLEN, "Ipv4 Options found with bad lengths" },
    { DECODE_IPV4OPT_TRUNCATED, "Truncated Ipv4 Options" },
    { DECODE_IPV4_DGRAM_GT_CAPLEN, "IP dgm len > captured len" },
    { DECODE_ZERO_TTL, "IPV4 packet with zero TTL" },
    { DECODE_BAD_FRAGBITS, "IPV4 packet with bad frag bits (both MF and DF set)" },
    { DECODE_IP4_LEN_OFFSET, "IPV4 packet frag offset + length exceed maximum" },
    { DECODE_IP4_SRC_THIS_NET, "IPV4 packet from 'current net' source address" },
    { DECODE_IP4_DST_THIS_NET, "IPV4 packet to 'current net' dest address" },
    { DECODE_IP4_SRC_MULTICAST, "IPV4 packet from multicast source address" },
    { DECODE_IP4_SRC_RESERVED, "IPV4 packet from reserved source address" },
    { DECODE_IP4_DST_RESERVED, "IPV4 packet to reserved dest address" },
    { DECODE_IP4_SRC_BROADCAST, "IPV4 packet from broadcast source address" },
    { DECODE_IP4_DST_BROADCAST, "IPV4 packet to broadcast dest address" },
    { DECODE_IP4_MIN_TTL, "IPV4 packet below TTL limit" },
    { DECODE_IP4_DF_OFFSET, "IPV4 packet both DF and offset set" },
    { DECODE_IP_RESERVED_FRAG_BIT, "BAD-TRAFFIC IP reserved bit set" },
    { DECODE_IP_OPTION_SET, "MISC IP option set" },
    { DECODE_IP4_HDR_TRUNC, "truncated IP4 header" },
    { 0, nullptr }
};

class Ipv4Module : public CodecModule
{
public:
    Ipv4Module() : CodecModule(CD_IPV4_NAME, CD_IPV4_HELP) { }

    const RuleMap* get_rules() const override
    { return ipv4_rules; }

    const PegInfo* get_pegs() const override
    { return pegs; }

    PegCount* get_counts() const override
    { return (PegCount*)&stats; }
};

class Ipv4Codec : public Codec
{
public:
    Ipv4Codec() : Codec(CD_IPV4_NAME) { }
    ~Ipv4Codec() { }

    void get_protocol_ids(std::vector<uint16_t>& v) override;
    bool decode(const RawData&, CodecData&, DecodeData&) override;
    void log(TextLog* const, const uint8_t* pkt, const uint16_t len) override;
    bool encode(const uint8_t* const raw_in, const uint16_t raw_len,
        EncState&, Buffer&) override;
    void update(const ip::IpApi&, const EncodeFlags, uint8_t* raw_pkt,
        uint16_t lyr_len, uint32_t& updated_len) override;
    void format(bool reverse, uint8_t* raw_pkt, DecodeData& snort) override;

private:
    void IP4AddrTests(const IP4Hdr*, const CodecData&, DecodeData&);
    void IPMiscTests(const IP4Hdr* const ip4h, const CodecData& codec, uint16_t len);
    void DecodeIPOptions(const uint8_t* start, uint8_t& o_len, CodecData& data);
};

const uint16_t IP_ID_COUNT = 8192;
static THREAD_LOCAL rand_t* s_rand = 0;
static THREAD_LOCAL uint16_t s_id_index = 0;
static THREAD_LOCAL std::array<uint16_t, IP_ID_COUNT> s_id_pool {
    { 0 }
};
}  // namespace

void Ipv4Codec::get_protocol_ids(std::vector<uint16_t>& v)
{
    v.push_back(ETHERTYPE_IPV4);
    v.push_back(IPPROTO_ID_IPIP);
}

bool Ipv4Codec::decode(const RawData& raw, CodecData& codec, DecodeData& snort)
{
    uint32_t ip_len; /* length from the start of the ip hdr to the pkt end */
    uint16_t hlen;  /* ip header length */

    if (raw.len < ip::IP4_HEADER_LEN)
    {
        if ((codec.codec_flags & CODEC_UNSURE_ENCAP) == 0)
            codec_event(codec, DECODE_IP4_HDR_TRUNC);
        return false;
    }

    if ( snort_conf->hit_ip_maxlayers(codec.ip_layer_cnt) )
    {
        codec_event(codec, DECODE_IP_MULTIPLE_ENCAPSULATION);
        return false;
    }

    ++codec.ip_layer_cnt;
    /* lay the IP struct over the raw data */
    const IP4Hdr* const iph = reinterpret_cast<const IP4Hdr*>(raw.data);

    /*
     * with datalink DLT_RAW it's impossible to differ ARP datagrams from IP.
     * So we are just ignoring non IP datagrams
     */
    if (iph->ver() != 4)
    {
        if ((codec.codec_flags & CODEC_UNSURE_ENCAP) == 0)
            codec_event(codec, DECODE_NOT_IPV4_DGRAM);
        return false;
    }

    ip_len = iph->len();
    hlen = iph->hlen();

    if (hlen < ip::IP4_HEADER_LEN)
    {
        DebugFormat(DEBUG_DECODE,
            "Bogus IP header length of %i bytes\n", hlen);

        codec_event(codec, DECODE_IPV4_INVALID_HEADER_LEN);
        return false;
    }

    if (ip_len > raw.len)
    {
        DebugFormat(DEBUG_DECODE,
            "IP Len field is %d bytes bigger than captured length.\n"
            "    (ip.len: %lu, cap.len: %lu)\n",
            ip_len - raw.len, ip_len, raw.len);

        codec_event(codec, DECODE_IPV4_DGRAM_GT_CAPLEN);
        return false;
    }
#if 0
    else if (ip_len < len)
    {
        // There is no need to alert when (ip_len < len).
        // Libpcap will capture more bytes than are part of the IP payload.
        // These could be Ethernet trailers, ESP trailers, etc.
    }
#endif

    if (ip_len < hlen)
    {
        DebugFormat(DEBUG_DECODE,
            "IP dgm len (%d bytes) < IP hdr "
            "len (%d bytes), packet discarded\n", ip_len, hlen);

        codec_event(codec, DECODE_IPV4_DGRAM_LT_IPHDR);
        return false;
    }

    if ( snort.ip_api.is_ip6() )
    {
        /*  If Teredo or GRE seen, this is not an 4in6 tunnel */
        if ( codec.codec_flags & CODEC_NON_IP_TUNNEL )
            codec.codec_flags &= ~CODEC_NON_IP_TUNNEL;
        else if ( SnortConfig::tunnel_bypass_enabled(TUNNEL_4IN6) )
            Active::set_tunnel_bypass();
    }

    // set the api now since this layer has been verified as valid
    snort.ip_api.set(iph);

    /*
     * IP Header tests: Land attack, and Loop back test
     */
    IP4AddrTests(iph, codec, snort);

    if (SnortConfig::ip_checksums())
    {
        /* routers drop packets with bad IP checksums, we don't really
         * need to check them (should make this a command line/config
         * option
         */
        int16_t csum = checksum::ip_cksum((uint16_t*)iph, hlen);

        if (csum && !codec.is_cooked())
        {
            if ( !(codec.codec_flags & CODEC_UNSURE_ENCAP) )
            {
                stats.bad_cksum++;
                snort.decode_flags |= DECODE_ERR_CKSUM_IP;
            }
            return false;
        }
    }

    /* test for IP options */
    codec.codec_flags &= ~(CODEC_IPOPT_FLAGS);
    uint8_t ip_opt_len = (uint8_t)(hlen - ip::IP4_HEADER_LEN);

    if (ip_opt_len > 0)
        DecodeIPOptions((raw.data + ip::IP4_HEADER_LEN), ip_opt_len, codec);

    /* set the remaining packet length */
    const_cast<uint32_t&>(raw.len) = ip_len;
    ip_len -= hlen;

    /* check for fragmented packets */
    uint16_t frag_off = iph->off_w_flags();

    /*
     * get the values of the reserved, more
     * fragments and don't fragment flags
     */
    if (frag_off & 0x8000)
    {
        codec_event(codec, DECODE_IP_RESERVED_FRAG_BIT);
//        data.decode_flags |= DECODE_RF;  -- flag never needed
    }

    if (frag_off & 0x4000)
        codec.codec_flags |= CODEC_DF;

    if (frag_off & 0x2000)
        snort.decode_flags |= DECODE_MF;

    /* mask off the high bits in the fragment offset field */
    frag_off &= 0x1FFF;

    // to get the real frag_off, we need to multiply by 8. However, since
    // the actual frag_off is never used, we can comment this out
//    frag_off = frag_off << 3;

    if ( (codec.codec_flags & CODEC_DF) && frag_off )
        codec_event(codec, DECODE_IP4_DF_OFFSET);

    if ( frag_off + ip_len > IP_MAXPACKET )
        codec_event(codec, DECODE_IP4_LEN_OFFSET);

    if ( frag_off || (snort.decode_flags & DECODE_MF))
    {
        // FIXIT-L identical to DEFRAG_ANOMALY_ZERO
        if ( !ip_len)
            codec_event(codec, DECODE_ZERO_LENGTH_FRAG);

        snort.decode_flags |= DECODE_FRAG;
    }
    else
    {
        snort.decode_flags &= ~DECODE_FRAG;
    }

    if ( (snort.decode_flags & DECODE_MF) && (codec.codec_flags & CODEC_DF))
        codec_event(codec, DECODE_BAD_FRAGBITS);

    snort.set_pkt_type(PktType::IP);
    codec.proto_bits |= PROTO_BIT__IP;
    IPMiscTests(iph, codec, ip::IP4_HEADER_LEN + ip_opt_len);
    codec.lyr_len = hlen - codec.invalid_bytes;

    /* if this packet isn't a fragment
     * or if it is, its a UDP packet and offset is 0 */
    if (!(snort.decode_flags & DECODE_FRAG) /*||
        ((frag_off == 0) &&  // FIXIT-M this forces flow to udp instead of ip
         (iph->proto() == IPPROTO_UDP))*/)
    {
        if (iph->proto() >= MIN_UNASSIGNED_IP_PROTO)
            codec_event(codec, DECODE_IP_UNASSIGNED_PROTO);
        else
            codec.next_prot_id = iph->proto();
    }

    return true;
}

void Ipv4Codec::IP4AddrTests(
    const IP4Hdr* iph, const CodecData& codec, DecodeData& snort)
{
    uint8_t msb_src, msb_dst;

    // check all 32 bits ...
    if ( iph->ip_src == iph->ip_dst )
    {
        codec_event(codec, DECODE_BAD_TRAFFIC_SAME_SRCDST);
    }

    // check all 32 bits ...
    if (iph->is_src_broadcast())
        codec_event(codec, DECODE_IP4_SRC_BROADCAST);

    if (iph->is_dst_broadcast())
        codec_event(codec, DECODE_IP4_DST_BROADCAST);

    /* Loopback traffic  - don't use htonl for speed reasons -
     * s_addr is always in network order */
#ifdef WORDS_BIGENDIAN
    msb_src = (iph.ip_src >> 24);
    msb_dst = (iph.ip_dst >> 24);
#else
    msb_src = (uint8_t)(iph->ip_src & 0xff);
    msb_dst = (uint8_t)(iph->ip_dst & 0xff);
#endif
    // check the msb ...
    if ( (msb_src == ip::IP4_LOOPBACK) || (msb_dst == ip::IP4_LOOPBACK) )
    {
        codec_event(codec, DECODE_BAD_TRAFFIC_LOOPBACK);
    }
    // check the msb ...
    if ( msb_src == ip::IP4_THIS_NET )
        codec_event(codec, DECODE_IP4_SRC_THIS_NET);

    if ( msb_dst == ip::IP4_THIS_NET )
        codec_event(codec, DECODE_IP4_DST_THIS_NET);

    // check the 'msn' (most significant nibble) ...
    msb_src >>= 4;
    msb_dst >>= 4;

    if ( msb_src == ip::IP4_MULTICAST )
        codec_event(codec, DECODE_IP4_SRC_MULTICAST);

    if ( msb_src == ip::IP4_RESERVED || sfvar_ip_in(MulticastReservedIp, snort.ip_api.get_src()) )
        codec_event(codec, DECODE_IP4_SRC_RESERVED);

    if ( msb_dst == ip::IP4_RESERVED || sfvar_ip_in(MulticastReservedIp, snort.ip_api.get_dst()) )
        codec_event(codec, DECODE_IP4_DST_RESERVED);
}

/* IPv4-layer decoder rules */
void Ipv4Codec::IPMiscTests(const IP4Hdr* const ip4h, const CodecData& codec, uint16_t len)
{
    /* Yes, it's an ICMP-related vuln in IP options. */
    int cnt = 0;

    /* Alert on IP packets with either 0x07 (Record Route) or 0x44 (Timestamp)
       options that are specially crafted. */
    ip::IpOptionIterator iter(ip4h, (uint8_t)(len));
    for (const ip::IpOptions& opt : iter)
    {
        ++cnt;

        switch (opt.code)
        {
        case ip::IPOptionCodes::EOL:
            --cnt;
            break;

        case ip::IPOptionCodes::RR:
        {
            const uint8_t length = opt.len;
            if (length < 3)
                continue;

            uint8_t pointer = opt.data[0];

            /* If the pointer goes past the end of the data, then the data
               is full. That's okay. */
            if (pointer >= length)
                continue;
            /* If the remaining space in the option isn't a multiple of 4
               bytes, alert. */
            if (((length + 1) - pointer) % 4)
                codec_event(codec, DECODE_ICMP_DOS_ATTEMPT);

            break;
        }
        case ip::IPOptionCodes::TS:
        {
            const uint8_t length = opt.get_len();
            if (length < 2)
                continue;

            uint8_t pointer = opt.data[0];

            /* If the pointer goes past the end of the data, then the data
               is full. That's okay. */
            if (pointer >= length)
                continue;
            /* If the remaining space in the option isn't a multiple of 4
               bytes, alert. */
            if (((length + 1) - pointer) % 4)
                codec_event(codec, DECODE_ICMP_DOS_ATTEMPT);
            /* If there is a timestamp + address, we need a multiple of 8
               bytes instead. */
            if ((opt.data[1] & 0x01) && /* address flag */
                (((length + 1) - pointer) % 8))
                codec_event(codec, DECODE_ICMP_DOS_ATTEMPT);

            break;
        }
        default:
            break;
        }
    }

    if (cnt > 0)
        codec_event(codec, DECODE_IP_OPTION_SET);
}

void Ipv4Codec::DecodeIPOptions(const uint8_t* start, uint8_t& o_len, CodecData& codec)
{
    uint32_t tot_len = 0;
    int code = 0;  /* negative error codes are returned from bad options */

    const ip::IpOptions* option = reinterpret_cast<const ip::IpOptions*>(start);

    while (tot_len < o_len)
    {
        switch (option->code)
        {
        case ip::IPOptionCodes::EOL:
            /* if we hit an EOL, we're done */
            tot_len++;
            codec.invalid_bytes = o_len - tot_len;
            o_len = tot_len;
            return;
        // fall through

        case ip::IPOptionCodes::NOP:
            tot_len++;
            break;

        case ip::IPOptionCodes::RTRALT:
            codec.codec_flags |= CODEC_IPOPT_RTRALT_SEEN;
            goto default_case;

        case ip::IPOptionCodes::RR:
            codec.codec_flags |= CODEC_IPOPT_RR_SEEN;
            // fall through

default_case:
        default:

            if ((tot_len + 1) >= o_len)
                code = tcp::OPT_TRUNC;

            /* RFC sez that we MUST have atleast this much data */
            else if (option->len < 2)
                code = tcp::OPT_BADLEN;

            else if (tot_len + option->get_len() > o_len)
                /* not enough data to read in a perfect world */
                code = tcp::OPT_TRUNC;

            else if (option->len == 3)
                /* for IGMP alert */
                codec.codec_flags |= CODEC_IPOPT_LEN_THREE;

            if (code < 0)
            {
                /* Yes, we use TCP_OPT_* for the IP option decoder. */
                if (code == tcp::OPT_BADLEN)
                    codec_event(codec, DECODE_IPV4OPT_BADLEN);
                else if (code == tcp::OPT_TRUNC)
                    codec_event(codec, DECODE_IPV4OPT_TRUNCATED);

                codec.invalid_bytes = o_len - tot_len;
                o_len = tot_len;
                return;
            }

            tot_len += option->len;
        }

        option = &(option->next());
    }
}

/******************************************************************
 *********************  L O G G E R  ******************************
*******************************************************************/

struct ip4_addr
{
    union
    {
        uint32_t addr32;
        uint8_t addr8[4];
    };
};

void Ipv4Codec::log(TextLog* const text_log, const uint8_t* raw_pkt,
    const uint16_t lyr_len)
{
    const IP4Hdr* const ip4h = reinterpret_cast<const IP4Hdr*>(raw_pkt);

    // FIXIT-L  -->  This does NOT obfuscate correctly
    if (SnortConfig::obfuscate())
    {
        TextLog_Print(text_log, "xxx.xxx.xxx.xxx -> xxx.xxx.xxx.xxx");
    }
    else
    {
        ip4_addr src, dst;
        src.addr32 = ip4h->get_src();
        dst.addr32 = ip4h->get_dst();

        char src_buf[INET_ADDRSTRLEN];
        char dst_buf[INET_ADDRSTRLEN];

        inet_ntop(AF_INET, &src, src_buf, sizeof(src_buf));
        inet_ntop(AF_INET, &dst, dst_buf, sizeof(dst_buf));

        TextLog_Print(text_log, "%s -> %s", src_buf, dst_buf);
    }

    TextLog_NewLine(text_log);
    TextLog_Putc(text_log, '\t');

    const uint16_t hlen = ip4h->hlen();
    const uint16_t len = ip4h->len();
    const uint16_t frag_off = ip4h->off_w_flags();
    bool mf_set = false;

    TextLog_Print(text_log, "Next:0x%02X TTL:%u TOS:0x%X ID:%u IpLen:%u DgmLen:%u",
        ip4h->proto(), ip4h->ttl(), ip4h->tos(),
        ip4h->id(), hlen, len);

    /* print the reserved bit if it's set */
    if (frag_off & 0x8000)
        TextLog_Puts(text_log, " RB");

    /* printf more frags/don't frag bits */
    if (frag_off & 0x4000)
        TextLog_Puts(text_log, " DF");

    if (frag_off & 0x2000)
    {
        TextLog_Puts(text_log, " MF");
        mf_set = true;
    }

    /* print IP options */
    if (ip4h->has_options())
    {
        TextLog_Putc(text_log, '\t');
        TextLog_NewLine(text_log);
        LogIpOptions(text_log, ip4h, lyr_len);
    }

    if ( mf_set || (frag_off & 0x1FFF) )
    {
        TextLog_NewLine(text_log);
        TextLog_Putc(text_log, '\t');
        TextLog_Print(text_log, "Frag Offset: 0x%04X   Frag Size: 0x%04X\n",
            (frag_off & 0x1FFF) * 8, (len - hlen));
    }
}

/******************************************************************
 ******************** E N C O D E R  ******************************
*******************************************************************/

static inline uint16_t IpId_Next()
{
#if defined(REG_TEST) || defined(VALGRIND_TESTING)
    uint16_t id = htons(s_id_index + 1);
#else
    uint16_t id = s_id_pool[s_id_index];
#endif
    s_id_index = (s_id_index + 1) % IP_ID_COUNT;

#ifndef VALGRIND_TESTING
    if ( !s_id_index )
        rand_shuffle(s_rand, &s_id_pool[0], sizeof(s_id_pool), 1);
#endif
    return id;
}

/******************************************************************
 ******************** E N C O D E R  ******************************
 ******************************************************************/
bool Ipv4Codec::encode(const uint8_t* const raw_in, const uint16_t /*raw_len*/,
    EncState& enc, Buffer& buf)
{
    if (!buf.allocate(ip::IP4_HEADER_LEN))
        return false;

    const ip::IP4Hdr* const ip4h_in = reinterpret_cast<const IP4Hdr*>(raw_in);
    ip::IP4Hdr* const ip4h_out = reinterpret_cast<IP4Hdr*>(buf.data());

    /* IPv4 encoded header is hardcoded 20 bytes */
    ip4h_out->ip_verhl = 0x45;
    ip4h_out->ip_off = 0;
    ip4h_out->ip_id = IpId_Next();
    ip4h_out->ip_tos = ip4h_in->ip_tos;
    ip4h_out->ip_proto = ip4h_in->ip_proto;
    ip4h_out->ip_len = htons((uint16_t)buf.size());
    ip4h_out->ip_csum = 0;

    if ( enc.forward() )
    {
        ip4h_out->ip_src = ip4h_in->ip_src;
        ip4h_out->ip_dst = ip4h_in->ip_dst;
        ip4h_out->ip_ttl = enc.get_ttl(ip4h_in->ip_ttl);
    }
    else
    {
        ip4h_out->ip_src = ip4h_in->ip_dst;
        ip4h_out->ip_dst = ip4h_in->ip_src;
        ip4h_out->ip_ttl = enc.get_ttl(ip4h_in->ip_ttl);
    }

    if ( enc.next_proto_set() )
        ip4h_out->ip_proto = enc.next_proto;

    /* IPv4 encoded header is hardcoded 20 bytes, we save some
     * cycles and use the literal header size for checksum */
    ip4h_out->ip_csum = checksum::ip_cksum((uint16_t*)ip4h_out, ip::IP4_HEADER_LEN);

    enc.next_proto = IPPROTO_ID_IPIP;
    enc.next_ethertype = ETHERTYPE_IPV4;
    return true;
}

void Ipv4Codec::update(const ip::IpApi&, const EncodeFlags flags,
    uint8_t* raw_pkt, uint16_t /*lyr_len*/, uint32_t& updated_len)
{
    IP4Hdr* h = reinterpret_cast<IP4Hdr*>(raw_pkt);
    uint16_t hlen = h->hlen();

    updated_len += hlen;
    h->set_ip_len((uint16_t)updated_len);

    if ( !(flags & UPD_COOKED) || (flags & UPD_REBUILT_FRAG) )
    {
        h->ip_csum = 0;
        h->ip_csum = checksum::ip_cksum((uint16_t*)h, hlen);
    }
}

void Ipv4Codec::format(bool reverse, uint8_t* raw_pkt, DecodeData& snort)
{
    IP4Hdr* ip4h = reinterpret_cast<IP4Hdr*>(raw_pkt);

    if ( reverse )
    {
        uint32_t tmp_ip = ip4h->ip_src;
        ip4h->ip_src = ip4h->ip_dst;
        ip4h->ip_dst = tmp_ip;
    }

    snort.ip_api.set(ip4h);
    snort.set_pkt_type(PktType::IP);
}

//-------------------------------------------------------------------------
// api
//-------------------------------------------------------------------------

static Module* mod_ctor()
{ return new Ipv4Module; }

static void mod_dtor(Module* m)
{ delete m; }

//-------------------------------------------------------------------------
// ip id considerations:
//
// we use dnet's rand services to generate a vector of random 16-bit values and
// iterate over the vector as IDs are assigned.  when we wrap to the beginning,
// the vector is randomly reordered.
//-------------------------------------------------------------------------
static void ipv4_codec_ginit()
{
#ifndef VALGRIND_TESTING
    if ( s_rand )
        rand_close(s_rand);

    // rand_open() can yield valgrind errors because the
    // starting seed may come from "random stack contents"
    // (see man 3 dnet)
    s_rand = rand_open();

    if ( !s_rand )
        FatalError("rand_open() failed.\n");

    rand_get(s_rand, &s_id_pool[0], sizeof(s_id_pool));
#endif

    // Reserved addresses within multicast address space (See RFC 5771)
    MulticastReservedIp = sfip_var_from_string(
        "[224.1.0.0/16,224.5.0.0/16,224.6.0.0/15,224.8.0.0/13,224.16.0.0/12,"
        "224.32.0.0/11,224.64.0.0/10,224.128.0.0/9,225.0.0.0/8,226.0.0.0/7,"
        "228.0.0.0/6,234.0.0.0/7,236.0.0.0/7,238.0.0.0/8]");

    if ( MulticastReservedIp == nullptr )
        FatalError("Could not initialize IPv4 MulticastReservedIp\n");
}

static void ipv4_codec_gterm()
{
    if ( s_rand )
        rand_close(s_rand);

    if ( MulticastReservedIp )
        sfvar_free(MulticastReservedIp);

    s_rand = nullptr;
    MulticastReservedIp = nullptr;
}

static Codec* ctor(Module*)
{ return new Ipv4Codec; }

static void dtor(Codec* cd)
{ delete cd; }

static const CodecApi ipv4_api =
{
    {
        PT_CODEC,
        sizeof(CodecApi),
        CDAPI_VERSION,
        0,
        API_RESERVED,
        API_OPTIONS,
        CD_IPV4_NAME,
        CD_IPV4_HELP,
        mod_ctor,
        mod_dtor
    },
    ipv4_codec_ginit, // pinit
    ipv4_codec_gterm, // pterm
    nullptr, // tinit
    nullptr, // tterm
    ctor, // ctor
    dtor, // dtor
};

#if 0
#ifdef BUILDING_SO
SO_PUBLIC const BaseApi* snort_plugins[] =
{
    &ipv4_api.base,
    nullptr
};
#else
const BaseApi* cd_ipv4 = &ipv4_api.base;
#endif
#endif

// Currently needs to be static
const BaseApi* cd_ipv4 = &ipv4_api.base;

