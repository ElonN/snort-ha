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
// packet.h author Josh Rosenbaum <jrosenba@cisco.com>

#ifndef PROTOCOLS_PACKET_H
#define PROTOCOLS_PACKET_H

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stddef.h>
#include <sys/types.h>

#ifndef WIN32

#include <sys/socket.h>
#include <netinet/in.h>
#include <net/if.h>

#else

#include <netinet/in_systm.h>
#ifndef IFNAMSIZ
#define IFNAMESIZ MAX_ADAPTER_NAME
#endif

#endif

extern "C" {
#include <daq.h>
#include <sfbpf_dlt.h>
}

#include "main/snort_types.h"
#include "framework/decode_data.h"
#include "flow/flow.h"
#include "protocols/layer.h"

/* packet status flags */
#define PKT_REBUILT_FRAG     0x00000001  /* is a rebuilt fragment */
#define PKT_REBUILT_STREAM   0x00000002  /* is a rebuilt stream */
#define PKT_STREAM_UNEST_UNI 0x00000004  /* is from an unestablished stream and
                                          * we've only seen traffic in one direction */
#define PKT_STREAM_EST       0x00000008  /* is from an established stream */

#define PKT_STREAM_INSERT    0x00000010  /* this packet has been queued for stream reassembly */
#define PKT_STREAM_TWH       0x00000020  /* packet completes the 3-way handshake */
#define PKT_FROM_SERVER      0x00000040  /* this packet came from the server
                                            side of a connection (TCP) */
#define PKT_FROM_CLIENT      0x00000080  /* this packet came from the client
                                            side of a connection (TCP) */

#define PKT_PDU_HEAD         0x00000100  /* start of PDU */
#define PKT_PDU_TAIL         0x00000200  /* end of PDU */
#define PKT_HTTP_DECODE      0x00000400  /* this packet has normalized http */

#define PKT_ALLOW_MULTIPLE_DETECT 0x00000800  /* packet has either pipelined mime attachements
                                                 or pipeline http requests */
#define PKT_PAYLOAD_OBFUSCATE     0x00001000

#define PKT_STATELESS        0x00002000  /* Packet has matched a stateless rule */
#define PKT_PASS_RULE        0x00004000  /* this packet has matched a pass rule */
#define PKT_IP_RULE          0x00008000  /* this packet is being evaluated against an IP rule */
#define PKT_IP_RULE_2ND      0x00010000  /* this packet is being evaluated against an IP rule */

#define PKT_PSEUDO           0x00020000  /* is a pseudo packet */
#define PKT_MODIFIED         0x00040000  /* packet had normalizations, etc. */
#define PKT_RESIZED          0x000c0000  /* packet has new size; must set modified too */

// neither of these flags will be set for (full) retransmissions or non-data segments
// a partial overlap results in out of sequence condition
// out of sequence condition is sticky
#define PKT_STREAM_ORDER_OK  0x00100000  /* this segment is in order, w/o gaps */
#define PKT_STREAM_ORDER_BAD 0x00200000  /* this stream had at least one gap */

#define PKT_FILE_EVENT_SET   0x00400000
#define PKT_IGNORE           0x00800000  /* this packet should be ignored, based on port */
#define PKT_UNUSED_FLAGS     0xfe000000

// 0x40000000 are available
#define PKT_PDU_FULL (PKT_PDU_HEAD | PKT_PDU_TAIL)

enum PseudoPacketType
{
    PSEUDO_PKT_IP,
    PSEUDO_PKT_TCP,
    PSEUDO_PKT_USER,
    PSEUDO_PKT_DCE_RPKT,
    PSEUDO_PKT_DCE_SEG,
    PSEUDO_PKT_DCE_FRAG,
    PSEUDO_PKT_SMB_SEG,
    PSEUDO_PKT_SMB_TRANS,
    PSEUDO_PKT_PS,
    PSEUDO_PKT_SDF,
    PSEUDO_PKT_MAX
};

/* We must twiddle to align the offset the ethernet header and align
 * the IP header on solaris -- maybe this will work on HPUX too.
 */
#if defined (SOLARIS) || defined (SUNOS) || defined (__sparc__) || defined(__sparc64__) || \
    defined (HPUX)
#define SPARC_TWIDDLE       2
#else
#define SPARC_TWIDDLE       0
#endif

/* default mpls flags */
#define DEFAULT_MPLS_PAYLOADTYPE      MPLS_PAYLOADTYPE_IPV4
#define DEFAULT_LABELCHAIN_LENGTH    -1

constexpr int32_t MAX_PORTS = 65536;
constexpr uint16_t NUM_IP_PROTOS = 256;
constexpr int16_t SFTARGET_UNKNOWN_PROTOCOL = -1;
constexpr uint8_t TCP_OPTLENMAX = 40; /* (((2^4) - 1) * 4  - TCP_HEADER_LEN) */
constexpr uint8_t DEFAULT_LAYERMAX = 40;

// Packet is an abstraction describing a unit of work.  it may define a
// wire packet or it may define a cooked packet.  the latter contains
// payload data only, no headers.
struct SO_PUBLIC Packet
{
    class Flow* flow;   /* for session tracking */

    uint32_t packet_flags;      /* special flags for the packet */
    uint32_t xtradata_mask;

    uint16_t proto_bits;        /* protocols contained within this packet */
    uint16_t alt_dsize;         /* the dsize of a packet before munging (used for log)*/

    uint8_t num_layers;         /* index into layers for next encap */
    uint8_t ip_proto_next;      /* the protocol ID after IP and all IP6 extension */

    // nothing after this point is zeroed ...

    // Everything beyond this point is set by PacketManager::decode()
    const DAQ_PktHdr_t* pkth;    // packet meta data
    const uint8_t* pkt;         // raw packet data

    // These are both set before PacketManager::decode() returns
    const uint8_t* data;        /* packet payload pointer */
    uint16_t dsize;             /* packet payload size */

    DecodeData ptrs; // convenience pointers used throughout Snort++
    Layer* layers;    /* decoded encapsulations */

    PseudoPacketType pseudo_type;    // valid only when PKT_PSEUDO is set
    uint32_t iplist_id;

    // for correlating configuration with event output
    uint16_t user_policy_id;

    uint8_t ps_proto;  // Used for portscan and unified2 logging

    // IP_MAXPACKET is the minimum allowable max_dsize
    // there is no requirement that all data fit into an IP datagram
    // but we do require that an IP datagram fit into Packet space
    // we can increase beyond this if needed
    static const uint32_t max_dsize = IP_MAXPACKET;

    /*  Boolean functions - general information about this packet */
    inline bool has_ip() const
    { return ptrs.ip_api.is_ip(); }

    inline bool is_ip4() const
    { return ptrs.ip_api.is_ip4(); }

    inline bool is_ip6() const
    { return ptrs.ip_api.is_ip6(); }

    inline bool is_ip() const
    { return ptrs.get_pkt_type() == PktType::IP; }

    inline bool is_tcp() const
    { return ptrs.get_pkt_type() == PktType::TCP; }

    inline bool is_udp() const
    { return ptrs.get_pkt_type() == PktType::UDP; }

    inline bool is_icmp() const
    { return ptrs.get_pkt_type() == PktType::ICMP; }

    inline bool is_data() const
    { return (ptrs.get_pkt_type() == PktType::PDU) or (ptrs.get_pkt_type() == PktType::FILE); }

    inline bool is_cooked() const
    { return packet_flags & PKT_PSEUDO; }

    inline bool is_fragment() const
    { return ptrs.decode_flags & DECODE_FRAG; }

    inline bool has_tcp_data() const
    { return (proto_bits & PROTO_BIT__TCP) and data and dsize; }

    /* Get general, non-boolean information */
    inline PktType type() const
    { return ptrs.get_pkt_type(); } // defined in codec.h

    const char* get_type() const;
    const char* get_pseudo_type() const;

    /* the ip_api return the protocol_ID of the protocol directly after the
     * innermost IP layer.  However, especially in IPv6, the next protocol
     * can frequently be an IP extension.  Therefore, this function
     * return the protocol ID of the first protocol after all the
     * IP layers.  For instance, if the stack is
     *     eth::ip4::udp::teredo::ip6::hop_opts::ipv6_routing::tcp
     * this function return 6 == IPPROTO_TCP == IPPROTO_ID_TCP
     */
    inline uint8_t get_ip_proto_next() const
    { return ip_proto_next; }

    /* Similar to above. However, this function
     * can be called in a loop to get all of the ip_proto's.
     * NOTE: Will only return protocols of validly decoded layers.
     *
     * PARAMS:
     *          lyr - zero based layer from which to start searching inward.
     *                  will always point to the layer after an IP header or
     *                  IPv6 extension.
     *          proto - the ip_proto (read above) for the next, outermost IP layer
     * EXAMPLE:
     *
     * uint8_t ip_proto;
     * int lyr = 0
     * while ( ip_proto_next(lyr, ip_proto))
     * {
     *    ....
     * }
     */
    bool get_ip_proto_next(uint8_t& lyr, uint8_t& proto) const;

    inline void reset()
    {
        memset(this, 0, offsetof(Packet, pkth));
        ptrs.reset();
    }
    bool from_client()
    { return (packet_flags & PKT_FROM_CLIENT) != 0; }

    bool from_server()
    { return (packet_flags & PKT_FROM_SERVER) != 0; }

    bool is_portscan()
    { return is_cooked() and (pseudo_type == PSEUDO_PKT_PS); }

    bool is_full_pdu()
    { return (packet_flags & PKT_PDU_FULL) == PKT_PDU_FULL; }

    bool is_pdu_start()
    { return (packet_flags & PKT_PDU_HEAD) != 0; }

    bool has_paf_payload()
    { return (packet_flags & PKT_REBUILT_STREAM) or is_full_pdu(); }

    bool is_rebuilt()
    { return (packet_flags & (PKT_REBUILT_STREAM|PKT_REBUILT_FRAG)) != 0; }

    int16_t get_application_protocol()
    { return flow ? flow->ssn_state.application_protocol : 0; }

    void set_application_protocol(int16_t ap)
    { if ( flow ) flow->ssn_state.application_protocol = ap; }
};

/* Macros to deal with sequence numbers - p810 TCP Illustrated vol 2 */
#define SEQ_LT(a,b)  ((int)((a) - (b)) <  0)
#define SEQ_LEQ(a,b) ((int)((a) - (b)) <= 0)
#define SEQ_GT(a,b)  ((int)((a) - (b)) >  0)
#define SEQ_GEQ(a,b) ((int)((a) - (b)) >= 0)
#define SEQ_EQ(a,b)  ((int)((a) - (b)) == 0)

#define BIT(i) (0x1 << (i-1))

static inline void SetExtraData(Packet* p, const uint32_t xid)
{ p->xtradata_mask |= BIT(xid); }

static inline uint16_t EXTRACT_16BITS(const uint8_t* const p)
{ return ntohs(*(uint16_t*)(p)); }

#ifdef WORDS_MUSTALIGN

#if defined(__GNUC__)
/* force word-aligned ntohl parameter */
static inline uint32_t EXTRACT_32BITS(const uint8_t* p)
{
    uint32_t tmp;
    memmove(&tmp, p, sizeof(uint32_t));
    return ntohl(tmp);
}
#endif

#else

/* allows unaligned ntohl parameter - dies w/SIGBUS on SPARCs */
static inline uint32_t EXTRACT_32BITS(const uint8_t* p)
{ return ntohl(*(uint32_t*)p); }

#endif

#endif

