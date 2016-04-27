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
// preprocessor_api.cc author Josh Rosenbaum <jrosenba@cisco.com>

#include "preprocessor_states/preprocessor_api.h"

namespace preprocessors
{
extern const ConvertMap* arpspoof_map;
extern const ConvertMap* arpspoof_host_map;
extern const ConvertMap* bo_map;
extern const ConvertMap* frag3_engine_map;
extern const ConvertMap* frag3_global_map;
extern const ConvertMap* ftptelnet_map;
extern const ConvertMap* ftptelnet_protocol_map;
extern const ConvertMap* gtp_map;
extern const ConvertMap* httpinspect_map;
extern const ConvertMap* httpinspect_server_map;
extern const ConvertMap* normalizer_icmp4_map;
extern const ConvertMap* normalizer_icmp6_map;
extern const ConvertMap* normalizer_ip4_map;
extern const ConvertMap* normalizer_ip6_map;
extern const ConvertMap* normalizer_tcp_map;
extern const ConvertMap* perfmonitor_map;
extern const ConvertMap* rpc_decode_map;
extern const ConvertMap* sip_map;
extern const ConvertMap* ssh_map;
extern const ConvertMap* ssl_map;
extern const ConvertMap* dns_map;
extern const ConvertMap* pop_map;
extern const ConvertMap* imap_map;
extern const ConvertMap* smtp_map;
extern const ConvertMap* sfportscan_map;
extern const ConvertMap* stream_ip_map;
extern const ConvertMap* stream_global_map;
extern const ConvertMap* stream_tcp_map;
extern const ConvertMap* stream_udp_map;

const std::vector<const ConvertMap*> preprocessor_api =
{
    arpspoof_map,
    arpspoof_host_map,
    bo_map,
    frag3_engine_map,
    frag3_global_map,
    ftptelnet_map,
    httpinspect_map,
    httpinspect_server_map,
    ftptelnet_protocol_map,
    gtp_map,
    normalizer_icmp4_map,
    normalizer_icmp6_map,
    normalizer_ip4_map,
    normalizer_ip6_map,
    normalizer_tcp_map,
    perfmonitor_map,
    rpc_decode_map,
    sip_map,
    ssh_map,
    ssl_map,
    dns_map,
    pop_map,
    imap_map,
    smtp_map,
    sfportscan_map,
    stream_ip_map,
    stream_global_map,
    stream_tcp_map,
    stream_udp_map,
//    nullptr,
};
} // namespace preprocessors

