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
// cd_eth.cc author Josh Rosenbaum <jrosenba@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <pcap.h>
#include "codecs/codec_module.h"
#include "framework/codec.h"
#include "protocols/packet.h"
#include "protocols/eth.h"
#include "protocols/packet_manager.h"
#include "log/text_log.h"

#define CD_ETH_NAME "eth"
#define CD_ETH_HELP_STR "support for ethernet protocol"
#define CD_ETH_HELP ADD_DLT(ADD_DLT(CD_ETH_HELP_STR, DLT_EN10MB), DLT_PPP_ETHER)

namespace
{
static const RuleMap eth_rules[] =
{
    { DECODE_ETH_HDR_TRUNC, "truncated eth header" },
    { 0, nullptr }
};

class EthModule : public CodecModule
{
public:
    EthModule() : CodecModule(CD_ETH_NAME, CD_ETH_HELP) { }

    const RuleMap* get_rules() const
    { return eth_rules; }
};

class EthCodec : public Codec
{
public:
    EthCodec() : Codec(CD_ETH_NAME) { }
    ~EthCodec() { }

    void get_protocol_ids(std::vector<uint16_t>&) override;
    void get_data_link_type(std::vector<int>&) override;
    void log(TextLog* const, const uint8_t* pkt, const uint16_t len) override;
    bool decode(const RawData&, CodecData&, DecodeData&) override;
    bool encode(const uint8_t* const raw_in, const uint16_t raw_len,
        EncState&, Buffer&) override;
    void format(bool reverse, uint8_t* raw_pkt, DecodeData& snort) override;
    void update(const ip::IpApi&, const EncodeFlags, uint8_t* raw_pkt,
        uint16_t lyr_len, uint32_t& updated_len) override;
};
} // namespace

#ifndef DLT_PPP_ETHER
// For PPP over Eth, the first layer is ethernet.
constexpr int DLT_PPP_ETHER = 51;
#endif

void EthCodec::get_data_link_type(std::vector<int>& v)
{
    v.push_back(DLT_PPP_ETHER);
    v.push_back(DLT_EN10MB);
}

void EthCodec::get_protocol_ids(std::vector<uint16_t>& v)
{
    v.push_back(PROTO_ETHERNET_802_3);
}

bool EthCodec::decode(const RawData& raw, CodecData& codec, DecodeData&)
{
    if (raw.len < eth::ETH_HEADER_LEN)
    {
        codec_event(codec, DECODE_ETH_HDR_TRUNC);
        return false;
    }

    /* lay the ethernet structure over the packet data */
    const eth::EtherHdr* eh = reinterpret_cast<const eth::EtherHdr*>(raw.data);

    uint16_t next_prot = eh->ethertype();
    if ( next_prot <= eth::MIN_ETHERTYPE )
    {
        codec.next_prot_id = PROTO_ETHERNET_LLC;
        codec.lyr_len = eth::ETH_HEADER_LEN;
    }
    else if ( next_prot == ETHERTYPE_FPATH )
    {
        /*  If this is FabricPath, the first 16 bytes are FabricPath data
         *  rather than Ethernet data.  So, set the length to zero and
         *  and decode this FabricPath data. Then, FabricPath will send the decoder
         *  right back to this Ethernet function.
         */
        codec.next_prot_id = next_prot;
        codec.lyr_len = 0;
    }
    else
    {
        codec.proto_bits |= PROTO_BIT__ETH;
        codec.lyr_len = eth::ETH_HEADER_LEN;
        codec.next_prot_id = next_prot;
    }

    return true;
}

void EthCodec::log(TextLog* const text_log, const uint8_t* raw_pkt,
    const uint16_t /*len*/)
{
    const eth::EtherHdr* eh = reinterpret_cast<const eth::EtherHdr*>(raw_pkt);

    /* src addr */
    TextLog_Print(text_log, "%02X:%02X:%02X:%02X:%02X:%02X -> ", eh->ether_src[0],
        eh->ether_src[1], eh->ether_src[2], eh->ether_src[3],
        eh->ether_src[4], eh->ether_src[5]);

    /* dest addr */
    TextLog_Print(text_log, "%02X:%02X:%02X:%02X:%02X:%02X", eh->ether_dst[0],
        eh->ether_dst[1], eh->ether_dst[2], eh->ether_dst[3],
        eh->ether_dst[4], eh->ether_dst[5]);

    const uint16_t prot = ntohs(eh->ether_type);

    if (prot <= eth::MIN_ETHERTYPE)
        TextLog_Print(text_log, "  len:0x%04X", prot);
    else
        TextLog_Print(text_log, "  type:0x%04X", prot);
}

//-------------------------------------------------------------------------
// ethernet
//-------------------------------------------------------------------------

bool EthCodec::encode(const uint8_t* const raw_in, const uint16_t /*raw_len*/,
    EncState& enc, Buffer& buf)
{
    const eth::EtherHdr* hi = reinterpret_cast<const eth::EtherHdr*>(raw_in);

    if (hi->ethertype() == ETHERTYPE_FPATH)
        return true;

    // not raw ip -> encode layer 2
    bool raw = ( enc.flags & ENC_FLAG_RAW );

    if ( !raw && (buf.size() == 0) )
    {
        // for alignment
        if (!buf.allocate(SPARC_TWIDDLE))
            return false;

        buf.off = SPARC_TWIDDLE;
    }

    if ( !raw || (buf.size() != 0) )
    {
        // we get here for outer-most layer when not raw ip
        // we also get here for any encapsulated ethernet layer.
        if ( !buf.allocate(eth::ETH_HEADER_LEN) )
            return false;

        eth::EtherHdr* ho = reinterpret_cast<eth::EtherHdr*>(buf.data());
        ho->ether_type = enc.ethertype_set() ? ntohs(enc.next_ethertype) : hi->ether_type;

        uint8_t* dst_mac = PacketManager::encode_get_dst_mac();

        if ( enc.forward() )
        {
            memcpy(ho->ether_src, hi->ether_src, sizeof(ho->ether_src));
            /*If user configured remote MAC address, use it*/
            if (nullptr != dst_mac)
                memcpy(ho->ether_dst, dst_mac, sizeof(ho->ether_dst));
            else
                memcpy(ho->ether_dst, hi->ether_dst, sizeof(ho->ether_dst));
        }
        else
        {
            memcpy(ho->ether_src, hi->ether_dst, sizeof(ho->ether_src));
            /*If user configured remote MAC address, use it*/
            if (nullptr != dst_mac)
                memcpy(ho->ether_dst, dst_mac, sizeof(ho->ether_dst));
            else
                memcpy(ho->ether_dst, hi->ether_src, sizeof(ho->ether_dst));
        }
    }

    enc.next_ethertype = 0;
    enc.next_proto = ENC_PROTO_UNSET;
    return true;
}

void EthCodec::format(bool reverse, uint8_t* raw_pkt, DecodeData&)
{
    eth::EtherHdr* ch = reinterpret_cast<eth::EtherHdr*>(raw_pkt);

    // If the ethertype is FabricPath, then this is not Ethernet Data.
    if ( reverse &&  (ch->ethertype() != ETHERTYPE_FPATH) )
    {
        uint8_t tmp_addr[6];

        memcpy(tmp_addr, ch->ether_dst, sizeof(ch->ether_dst));
        memcpy(ch->ether_dst, ch->ether_src, sizeof(ch->ether_src));
        memcpy(ch->ether_src, tmp_addr, sizeof(ch->ether_src));
    }
}

void EthCodec::update(const ip::IpApi&, const EncodeFlags, uint8_t* raw_pkt,
    uint16_t lyr_len, uint32_t& updated_len)
{
    const eth::EtherHdr* const eth = reinterpret_cast<eth::EtherHdr*>(raw_pkt);

    if ( eth->ethertype() != ETHERTYPE_FPATH )
        updated_len += lyr_len;
}

//-------------------------------------------------------------------------
// api
//-------------------------------------------------------------------------

static Module* mod_ctor()
{ return new EthModule; }

static void mod_dtor(Module* m)
{ delete m; }

static Codec* ctor(Module*)
{ return new EthCodec(); }

static void dtor(Codec* cd)
{ delete cd; }

static const CodecApi eth_api =
{
    {
        PT_CODEC,
        sizeof(CodecApi),
        CDAPI_VERSION,
        0,
        API_RESERVED,
        API_OPTIONS,
        CD_ETH_NAME,
        CD_ETH_HELP,
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
    &eth_api.base,
    nullptr
};
#else
const BaseApi* cd_eth = &eth_api.base;
#endif

