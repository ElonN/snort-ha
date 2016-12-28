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

#include "flow/flow_control.h"

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <assert.h>
#include <arpa/inet.h>

#include "time/packet_time.h"
#include <sys/mman.h>
#include <sys/mman.h>
#include <fcntl.h>

#include "flow/flow_cache.h"
#include "flow/expect_cache.h"
#include "flow/session.h"
#include "packet_io/active.h"
#include "packet_io/sfdaq.h"
#include "utils/stats.h"
#include "protocols/layer.h"
#include "protocols/vlan.h"
#include "managers/inspector_manager.h"
#include "sfip/sf_ip.h"
#include "protocols/tcp.h"
#include "protocols/udp.h"
#include "protocols/icmp4.h"
#include "protocols/icmp6.h"
#include "detection/detect.h"

FlowControl::FlowControl()
{
    ip_cache = nullptr;
    icmp_cache = nullptr;
    tcp_cache = nullptr;
    udp_cache = nullptr;
    user_cache = nullptr;
    file_cache = nullptr;
    exp_cache = nullptr;

    ip_mem = icmp_mem = nullptr;
    tcp_mem = udp_mem = nullptr;
    user_mem = file_mem = nullptr;

    get_ip = get_icmp = nullptr;
    get_tcp = get_udp = nullptr;
    get_user = get_file = nullptr;
}

FlowControl::~FlowControl()
{
    delete ip_cache;
    delete icmp_cache;
    delete tcp_cache;
    delete udp_cache;
    delete user_cache;
    delete file_cache;
    delete exp_cache;

    free(ip_mem);
    free(icmp_mem);
    free(tcp_mem);
    free(udp_mem);
    free(user_mem);
    free(file_mem);
}

//-------------------------------------------------------------------------
// count foo
//-------------------------------------------------------------------------

static THREAD_LOCAL PegCount ip_count = 0;
static THREAD_LOCAL PegCount icmp_count = 0;
static THREAD_LOCAL PegCount tcp_count = 0;
static THREAD_LOCAL PegCount udp_count = 0;
static THREAD_LOCAL PegCount user_count = 0;
static THREAD_LOCAL PegCount file_count = 0;

static time_t update_interval = 1;


uint32_t FlowControl::max_flows(PktType proto)
{
    FlowCache* cache = get_cache(proto);

    if ( cache )
        return cache->get_max_flows();

    return 0;
}

PegCount FlowControl::get_prunes (PktType proto)
{
    FlowCache* cache = get_cache(proto);
    return cache ? cache->get_prunes() : 0;
}

PegCount FlowControl::get_flows(PktType proto)
{
    switch ( proto )
    {
    case PktType::IP:   return ip_count;
    case PktType::ICMP: return icmp_count;
    case PktType::TCP:  return tcp_count;
    case PktType::UDP:  return udp_count;
    case PktType::PDU: return user_count;
    case PktType::FILE: return file_count;
    default:            return 0;
    }
}

time_t* FlowControl::get_last_saved(PktType proto)
{
    switch ( proto )
    {
    case PktType::IP:   return &last_saved_ip;
    case PktType::ICMP: return &last_saved_icmp;
    case PktType::TCP:  return &last_saved_tcp;
    case PktType::UDP:  return &last_saved_udp;
    case PktType::PDU: return &last_saved_user;
    case PktType::FILE: return &last_saved_file;
    default:            return 0;
    }
}

void FlowControl::clear_counts()
{
    ip_count = icmp_count = 0;
    tcp_count = udp_count = 0;
    user_count = file_count = 0;

    FlowCache* cache;

    if ( (cache = get_cache(PktType::IP)) )
        cache->reset_prunes();

    if ( (cache = get_cache(PktType::ICMP)) )
        cache->reset_prunes();

    if ( (cache = get_cache(PktType::TCP)) )
        cache->reset_prunes();

    if ( (cache = get_cache(PktType::UDP)) )
        cache->reset_prunes();

    if ( (cache = get_cache(PktType::PDU)) )
        cache->reset_prunes();

    if ( (cache = get_cache(PktType::FILE)) )
        cache->reset_prunes();
}

Memcap& FlowControl::get_memcap (PktType proto)
{
    static Memcap dummy;
    FlowCache* cache = get_cache(proto);
    assert(cache);  // FIXIT-L dummy is a hack
    return cache ? cache->get_memcap() : dummy;
}

//-------------------------------------------------------------------------
// cache foo
//-------------------------------------------------------------------------
void FlowControl::save_cache(PktType proto) 
{
    const char* cache_key = get_cache_key(proto);
    size_t cache_size = get_cache_size(proto);
    redisReply *reply = 0;

    if(!context) {
        return;
    }

    time_t now = packet_time();

    if ( now > *get_last_saved(proto) + update_interval ) {
        
        reply = (redisReply*)redisCommand(context, "SET %b %b", cache_key, strlen(cache_key), (char*)get_mem(proto), cache_size);
        if (!reply) {
            return;
        }
        freeReplyObject(reply);
        *get_last_saved(proto) = now;
    }
}

void FlowControl::load_cache(PktType proto) 
{
	const char* cache_key = get_cache_key(proto);
    redisReply *reply = 0;

    if(!context) {
        return;
    }

    printf("load_cache: %s\n", cache_key);
	if (!cache_key)
	{
		return;
	}
	
    reply = (redisReply*)redisCommand(context, "GET %b", cache_key, strlen(cache_key));

    if ( !reply )
        return;
    if ( reply->type != REDIS_REPLY_STRING ) {
        printf("load_cache: ERROR: %s\n", reply->str);
    } else {
        printf("load_cache: adding %d entries\n", reply->len / sizeof(Flow));
        for ( unsigned i = 0; i < reply->len / sizeof(Flow); i++ )
        {
            Flow* cached_flow = ((Flow*)(reply->str)) + i;
            Flow::FlowState cached_fs = cached_flow->flow_state;
            if (cached_flow->key && (cached_fs == Flow::BLOCK || cached_fs == Flow::ALLOW))
            {
                printf("load_cache: adding interesting entry\n");
                Flow* current_flow = (get_cache(proto))->find(cached_flow->key);
                if (!current_flow)
                {
                    current_flow = (get_cache(proto))->get(cached_flow->key);
                    current_flow->new_from_cache = true;
                }
                current_flow->set_state(cached_fs);
                current_flow->last_data_seen = cached_flow->last_data_seen;
            }
        }
    }
    freeReplyObject(reply);

}

void FlowControl::load_caches() 
{
    load_cache(PktType::IP);
    load_cache(PktType::ICMP);
    load_cache(PktType::TCP);
    load_cache(PktType::UDP);
    load_cache(PktType::PDU);
    load_cache(PktType::FILE);

}

void FlowControl::load_if_interval() {
    time_t now = packet_time();

    if ( now > last_loaded + update_interval ) {

        if (context) {
            char active_state;
            int flag_fd;

            if ((flag_fd = open("/tmp/master", O_RDONLY)) == -1 ||
                 read(flag_fd, &active_state, sizeof(active_state)) != sizeof(active_state)) {
                active_state = '0';
            }
            close(flag_fd);
            if (active_state == '1') {
                if (last_active_state == '0') {
                    printf("load_if_interval: from PASSIVE to ACTIVE! loading db...%d\n", now);
                    load_caches();
                } 
            } else {
                printf("load_if_interval: PASSIVE! loading db...%d\n", now);
                load_caches();
            }
                
            last_active_state = active_state;
        }
        last_loaded = now;
    }
}

inline const char* FlowControl::get_cache_key (PktType proto)
{
    switch ( proto )
    {
    case PktType::IP:   return "ip_cache";
    case PktType::ICMP: return "icmp_cache";
    case PktType::TCP:  return "tcp_cache";
    case PktType::UDP:  return "udp_cache";
    case PktType::PDU: return "user_cache";
    case PktType::FILE: return "file_cache";
    default:            return nullptr;
    }
}

inline size_t FlowControl::get_cache_size (PktType proto)
{
    switch ( proto )
    {
    case PktType::IP:   return ip_mem_size;
    case PktType::ICMP: return icmp_mem_size;
    case PktType::TCP:  return tcp_mem_size;
    case PktType::UDP:  return udp_mem_size;
    case PktType::PDU: return user_mem_size;
    case PktType::FILE: return file_mem_size;
    default:            return 0;
    }
}


inline FlowCache* FlowControl::get_cache (PktType proto)
{
    switch ( proto )
    {
    case PktType::IP:   return ip_cache;
    case PktType::ICMP: return icmp_cache;
    case PktType::TCP:  return tcp_cache;
    case PktType::UDP:  return udp_cache;
    case PktType::PDU: return user_cache;
    case PktType::FILE: return file_cache;
    default:            return nullptr;
    }
}

inline char* FlowControl::get_mem (PktType proto)
{
    switch ( proto )
    {
    case PktType::IP:   return (char*)ip_mem;
    case PktType::ICMP: return (char*)icmp_mem;
    case PktType::TCP:  return (char*)tcp_mem;
    case PktType::UDP:  return (char*)udp_mem;
    case PktType::PDU: return (char*)user_mem;
    case PktType::FILE: return (char*)file_mem;
    default:            return nullptr;
    }
}

Flow* FlowControl::find_flow(const FlowKey* key)
{
    FlowCache* cache = get_cache((PktType)key->protocol);

    if ( cache )
        return cache->find(key);

    return NULL;
}

Flow* FlowControl::new_flow(const FlowKey* key)
{
    FlowCache* cache = get_cache((PktType)key->protocol);

    if ( !cache )
        return NULL;

    return cache->get(key);
}

// FIXIT-L cache* can be put in flow so that lookups by
// protocol are obviated for existing / initialized flows
void FlowControl::delete_flow(const FlowKey* key)
{
    FlowCache* cache = get_cache((PktType)key->protocol);

    if ( !cache )
        return;

    Flow* flow = cache->find(key);

    if ( flow )
        cache->release(flow, "ha sync");
}

void FlowControl::delete_flow(Flow* flow, const char* why)
{
    FlowCache* cache = get_cache(flow->protocol);

    if ( cache )
        cache->release(flow, why);
}

void FlowControl::purge_flows (PktType proto)
{
    FlowCache* cache = get_cache(proto);

    if ( cache )
        cache->purge();
}

void FlowControl::prune_flows (PktType proto, Packet* p)
{
    FlowCache* cache = get_cache(proto);

    if ( !cache )
        return;

    // smack the older timed out flows
    if (!cache->prune_stale(p->pkth->ts.tv_sec, (Flow*)p->flow))
    {
        // if no luck, try the memcap
        cache->prune_excess(true, (Flow*)p->flow);
    }
}

void FlowControl::timeout_flows(uint32_t flowCount, time_t cur_time)
{
    Active::suspend();

    if ( ip_cache )
        ip_cache->timeout(flowCount, cur_time);

    //if ( icmp_cache )
    //icmp_cache does not need cleaning

    if ( tcp_cache )
        tcp_cache->timeout(flowCount, cur_time);

    if ( udp_cache )
        udp_cache->timeout(flowCount, cur_time);

    if ( user_cache )
        user_cache->timeout(flowCount, cur_time);

    if ( file_cache )
        file_cache->timeout(flowCount, cur_time);

    Active::resume();
}

//-------------------------------------------------------------------------
// packet foo
//-------------------------------------------------------------------------

void FlowControl::set_key(FlowKey* key, Packet* p)
{
    const ip::IpApi& ip_api = p->ptrs.ip_api;
    uint32_t mplsId;
    uint16_t vlanId;
    uint16_t addressSpaceId;
    uint8_t type = (uint8_t)p->type();
    uint8_t proto = (uint8_t)p->get_ip_proto_next();

    if ( p->proto_bits & PROTO_BIT__VLAN )
        vlanId = layer::get_vlan_layer(p)->vid();
    else
        vlanId = 0;

    if ( p->proto_bits & PROTO_BIT__MPLS )
        mplsId = p->ptrs.mplsHdr.label;
    else
        mplsId = 0;

#ifdef HAVE_DAQ_ADDRESS_SPACE_ID
    addressSpaceId = DAQ_GetAddressSpaceID(p->pkth);
#else
    addressSpaceId = 0;
#endif

    if ( (p->ptrs.decode_flags & DECODE_FRAG) )
    {
        key->init(type, proto, ip_api.get_src(), ip_api.get_dst(), ip_api.id(),
            vlanId, mplsId, addressSpaceId);
    }
    else if ( type == (uint8_t)PktType::ICMP )
    {
        key->init(type, proto, ip_api.get_src(), p->ptrs.icmph->type, ip_api.get_dst(), 0,
            vlanId, mplsId, addressSpaceId);
    }
    else
    {
        key->init(type, proto, ip_api.get_src(), p->ptrs.sp, ip_api.get_dst(), p->ptrs.dp,
            vlanId, mplsId, addressSpaceId);
    }
}

static bool is_bidirectional(const Flow* flow)
{
    constexpr unsigned bidir = SSNFLAG_SEEN_CLIENT | SSNFLAG_SEEN_SERVER;
    return (flow->ssn_state.session_flags & bidir) == bidir;
}

// FIXIT-L init_roles* should take const Packet*
static void init_roles_ip(Packet* p, Flow* flow)
{
    flow->ssn_state.direction = FROM_CLIENT;
    sfip_copy(flow->client_ip, p->ptrs.ip_api.get_src());
    sfip_copy(flow->server_ip, p->ptrs.ip_api.get_dst());
}

static void init_roles_tcp(Packet* p, Flow* flow)
{
    if ( p->ptrs.tcph->is_syn_only() )
    {
        flow->ssn_state.direction = FROM_CLIENT;
        sfip_copy(flow->client_ip, p->ptrs.ip_api.get_src());
        flow->client_port = ntohs(p->ptrs.tcph->th_sport);
        sfip_copy(flow->server_ip, p->ptrs.ip_api.get_dst());
        flow->server_port = ntohs(p->ptrs.tcph->th_dport);
    }
    else if ( p->ptrs.tcph->is_syn_ack() )
    {
        flow->ssn_state.direction = FROM_SERVER;
        sfip_copy(flow->client_ip, p->ptrs.ip_api.get_dst());
        flow->client_port = ntohs(p->ptrs.tcph->th_dport);
        sfip_copy(flow->server_ip, p->ptrs.ip_api.get_src());
        flow->server_port = ntohs(p->ptrs.tcph->th_sport);
    }
    else if (p->ptrs.sp > p->ptrs.dp)
    {
        flow->ssn_state.direction = FROM_CLIENT;
        sfip_copy(flow->client_ip, p->ptrs.ip_api.get_src());
        flow->client_port = ntohs(p->ptrs.tcph->th_sport);
        sfip_copy(flow->server_ip, p->ptrs.ip_api.get_dst());
        flow->server_port = ntohs(p->ptrs.tcph->th_dport);
    }
    else
    {
        flow->ssn_state.direction = FROM_SERVER;
        sfip_copy(flow->client_ip, p->ptrs.ip_api.get_dst());
        flow->client_port = ntohs(p->ptrs.tcph->th_dport);
        sfip_copy(flow->server_ip, p->ptrs.ip_api.get_src());
        flow->server_port = ntohs(p->ptrs.tcph->th_sport);
    }
}

static void init_roles_udp(Packet* p, Flow* flow)
{
    flow->ssn_state.direction = FROM_CLIENT;
    sfip_copy(flow->client_ip, p->ptrs.ip_api.get_src());
    flow->client_port = ntohs(p->ptrs.udph->uh_sport);
    sfip_copy(flow->server_ip, p->ptrs.ip_api.get_dst());
    flow->server_port = ntohs(p->ptrs.udph->uh_dport);
}

static void init_roles_user(Packet* p, Flow* flow)
{
    if ( p->ptrs.decode_flags & DECODE_C2S )
    {
        flow->ssn_state.direction = FROM_CLIENT;
        sfip_copy(flow->client_ip, p->ptrs.ip_api.get_src());
        flow->client_port = p->ptrs.sp;
        sfip_copy(flow->server_ip, p->ptrs.ip_api.get_dst());
        flow->server_port = p->ptrs.dp;
    }
    else
    {
        flow->ssn_state.direction = FROM_SERVER;
        sfip_copy(flow->client_ip, p->ptrs.ip_api.get_dst());
        flow->client_port = p->ptrs.dp;
        sfip_copy(flow->server_ip, p->ptrs.ip_api.get_src());
        flow->server_port = p->ptrs.sp;
    }
}

static void init_roles(Packet* p, Flow* flow)
{
    switch ( flow->protocol )
    {
    case PktType::IP:
    case PktType::ICMP:
        init_roles_ip(p, flow);
        break;

    case PktType::TCP:
        init_roles_tcp(p, flow);
        break;

    case PktType::UDP:
        init_roles_udp(p, flow);
        break;

    case PktType::PDU:
    case PktType::FILE:
        init_roles_user(p, flow);
        break;

    default:
        break;
    }
}

unsigned FlowControl::process(Flow* flow, Packet* p)
{
    unsigned news = 0;

    load_if_interval();

    p->flow = flow;

    if ( flow->flow_state && !flow->new_from_cache)
        set_policies(snort_conf, flow->policy_id);

    else
    {
        init_roles(p, flow);
        Inspector* b = InspectorManager::get_binder();

        if ( b )
            b->eval(p);

        if ( !b || (flow->flow_state == Flow::INSPECT &&
            (!flow->ssn_client || !flow->session->setup(p))) )
            if (!flow->new_from_cache)
            	flow->set_state(Flow::ALLOW);
		flow->new_from_cache = false;
        ++news;
    }
    flow->set_direction(p);

    switch ( flow->flow_state )
    {
    case Flow::SETUP:
        flow->set_state(Flow::ALLOW);
        break;

    case Flow::INSPECT:
        assert(flow->ssn_client);
        assert(flow->ssn_server);
        flow->session->process(p);
        break;

    case Flow::ALLOW:
        if ( news )
            stream.stop_inspection(flow, p, SSN_DIR_BOTH, -1, 0);
        else
            DisableInspection(p);

        p->ptrs.decode_flags |= DECODE_PKT_TRUST;
        break;

    case Flow::BLOCK:
        if ( news )
            stream.drop_traffic(flow, SSN_DIR_BOTH);
        else
            Active::block_again();

        DisableInspection(p);
        break;

    case Flow::RESET:
        if ( news )
            stream.drop_traffic(flow, SSN_DIR_BOTH);
        else
            Active::reset_again();

        stream.blocked_session(flow, p);
        DisableInspection(p);
        break;
    }

    return news;
}

//-------------------------------------------------------------------------
// ip
//-------------------------------------------------------------------------

void FlowControl::init_ip(
    const FlowConfig& fc, InspectSsnFunc get_ssn)
{
    if ( !fc.max_sessions || !get_ssn )
        return;

    ip_cache = new FlowCache(fc, 5, 0);

    ip_mem = (Flow*)calloc(fc.max_sessions, sizeof(Flow));

	ip_mem_size = fc.max_sessions * sizeof(Flow);
	mlock(ip_mem, ip_mem_size);


    if ( !ip_mem )
        return;

    for ( unsigned i = 0; i < fc.max_sessions; ++i )
        ip_cache->push(ip_mem + i);

    get_ip = get_ssn;
}

void FlowControl::process_ip(Packet* p)
{
    if ( !ip_cache )
        return;

    FlowKey key;
    set_key(&key, p);
    Flow* flow = ip_cache->get(&key);

    if ( !flow )
        return;

    if ( !flow->session )
    {
        flow->init(PktType::IP);
        flow->session = get_ip(flow);
    }

    ip_count += process(flow, p);
	if (flow->fs_changed && ip_mem)
	{
		save_cache(PktType::IP);
		flow->fs_changed = false;
	}

    if ( flow->next && is_bidirectional(flow) )
        ip_cache->unlink_uni(flow);
}

//-------------------------------------------------------------------------
// icmp
//-------------------------------------------------------------------------

void FlowControl::init_icmp(
    const FlowConfig& fc, InspectSsnFunc get_ssn)
{
    if ( !fc.max_sessions || !get_ssn )
        return;

    icmp_cache = new FlowCache(fc, 5, 0);

    icmp_mem = (Flow*)calloc(fc.max_sessions, sizeof(Flow));

	icmp_mem_size = fc.max_sessions * sizeof(Flow);
	mlock(icmp_mem, icmp_mem_size);


    if ( !icmp_mem )
        return;

    for ( unsigned i = 0; i < fc.max_sessions; ++i )
        icmp_cache->push(icmp_mem + i);

    get_icmp = get_ssn;
}

void FlowControl::process_icmp(Packet* p)
{
    if ( !icmp_cache )
    {
        process_ip(p);
        return;
    }

    FlowKey key;
    set_key(&key, p);
    Flow* flow = icmp_cache->get(&key);

    if ( !flow )
        return;

    if ( !flow->session )
    {
        flow->init(PktType::ICMP);
        flow->session = get_icmp(flow);
    }

    icmp_count += process(flow, p);
	if (flow->fs_changed && icmp_mem)
	{
		save_cache(PktType::ICMP);
		flow->fs_changed = false;
	}

    if ( flow->next && is_bidirectional(flow) )
        icmp_cache->unlink_uni(flow);
}

//-------------------------------------------------------------------------
// tcp
//-------------------------------------------------------------------------

void FlowControl::init_tcp(
    const FlowConfig& fc, InspectSsnFunc get_ssn)
{
    if ( !fc.max_sessions || !get_ssn )
        return;

    tcp_cache = new FlowCache(fc, 5, 0);

    tcp_mem = (Flow*)calloc(fc.max_sessions, sizeof(Flow));

	tcp_mem_size = fc.max_sessions * sizeof(Flow);
    mlock(tcp_mem, tcp_mem_size);


    if ( !tcp_mem )
        return;

    for ( unsigned i = 0; i < fc.max_sessions; ++i )
        tcp_cache->push(tcp_mem + i);
	
    get_tcp = get_ssn;
}

void FlowControl::process_tcp(Packet* p)
{
    if ( !tcp_cache )
        return;

    FlowKey key;
    set_key(&key, p);
    Flow* flow = tcp_cache->get(&key);

    if ( !flow )
        return;

    if ( !flow->session )
    {
        flow->init(PktType::TCP);
        flow->session = get_tcp(flow);
    }

    tcp_count += process(flow, p);

	if (flow->fs_changed && tcp_mem)
	{
		save_cache(PktType::TCP);
		flow->fs_changed = false;
	}
    if ( flow->next && is_bidirectional(flow) )
        tcp_cache->unlink_uni(flow);
}

//-------------------------------------------------------------------------
// udp
//-------------------------------------------------------------------------

void FlowControl::init_udp(
    const FlowConfig& fc, InspectSsnFunc get_ssn)
{
    if ( !fc.max_sessions || !get_ssn )
        return;

    udp_cache = new FlowCache(fc, 5, 0);

    udp_mem = (Flow*)calloc(fc.max_sessions, sizeof(Flow));

	udp_mem_size = fc.max_sessions * sizeof(Flow);
    mlock(udp_mem, udp_mem_size);
	
    if ( !udp_mem )
        return;

    for ( unsigned i = 0; i < fc.max_sessions; ++i )
        udp_cache->push(udp_mem + i);

    get_udp = get_ssn;
}

void FlowControl::process_udp(Packet* p)
{
    if ( !udp_cache )
        return;

    FlowKey key;
    set_key(&key, p);
    Flow* flow = udp_cache->get(&key);

    if ( !flow )
        return;

    if ( !flow->session )
    {
        flow->init(PktType::UDP);
        flow->session = get_udp(flow);
    }

    udp_count += process(flow, p);
	if (flow->fs_changed && udp_mem)
	{
		save_cache(PktType::UDP);
		flow->fs_changed = false;
	}
    if ( flow->next && is_bidirectional(flow) )
        udp_cache->unlink_uni(flow);
}

//-------------------------------------------------------------------------
// user
//-------------------------------------------------------------------------

void FlowControl::init_user(
    const FlowConfig& fc, InspectSsnFunc get_ssn)
{
    if ( !fc.max_sessions || !get_ssn )
        return;

    user_cache = new FlowCache(fc, 5, 0);

    user_mem = (Flow*)calloc(fc.max_sessions, sizeof(Flow));

	user_mem_size = fc.max_sessions * sizeof(Flow);
	mlock(user_mem, user_mem_size);


    if ( !user_mem )
        return;

    for ( unsigned i = 0; i < fc.max_sessions; ++i )
        user_cache->push(user_mem + i);

    get_user = get_ssn;
}

void FlowControl::process_user(Packet* p)
{
    if ( !user_cache )
        return;

    FlowKey key;
    set_key(&key, p);
    Flow* flow = user_cache->get(&key);

    if ( !flow )
        return;

    if ( !flow->session )
    {
        flow->init(PktType::PDU);
        flow->session = get_user(flow);
    }

    user_count += process(flow, p);
	if (flow->fs_changed && user_mem)
	{
		save_cache(PktType::PDU);
		flow->fs_changed = false;
	}
    if ( flow->next && is_bidirectional(flow) )
        user_cache->unlink_uni(flow);
}

//-------------------------------------------------------------------------
// file
//-------------------------------------------------------------------------

void FlowControl::init_file(
    const FlowConfig& fc, InspectSsnFunc get_ssn)
{
    if ( !fc.max_sessions || !get_ssn )
        return;

    file_cache = new FlowCache(fc, 5, 0);

    file_mem = (Flow*)calloc(fc.max_sessions, sizeof(Flow));

	file_mem_size = fc.max_sessions * sizeof(Flow);
	mlock(file_mem, file_mem_size);


    if ( !file_mem )
        return;

    for ( unsigned i = 0; i < fc.max_sessions; ++i )
        file_cache->push(file_mem + i);

    get_file = get_ssn;
}

void FlowControl::process_file(Packet* p)
{
    if ( !file_cache )
        return;

    FlowKey key;
    set_key(&key, p);
    Flow* flow = file_cache->get(&key);

    if ( !flow )
        return;

    if ( !flow->session )
    {
        flow->init(PktType::FILE);
        flow->session = get_file(flow);
    }

    file_count += process(flow, p);
	if (flow->fs_changed && file_mem)
	{
		save_cache(PktType::FILE);
		flow->fs_changed = false;
	}
}

//-------------------------------------------------------------------------
// expected
//-------------------------------------------------------------------------

void FlowControl::init_exp(uint32_t max)
{
    max >>= 9;

    if ( !max )
        max = 2;

    exp_cache = new ExpectCache(max);
}

char FlowControl::expected_flow(Flow* flow, Packet* p)
{
    char ignore = exp_cache->check(p, flow);

    if ( ignore )
    {
        DebugFormat(DEBUG_STREAM_STATE,
            "Stream: Ignoring packet from %d. Marking flow marked as ignore.\n",
            p->packet_flags & PKT_FROM_CLIENT ? "sender" : "responder");

        flow->ssn_state.ignore_direction = ignore;
        DisableInspection(p);
    }

    return ignore;
}

int FlowControl::add_expected(
    const sfip_t *srcIP, uint16_t srcPort,
    const sfip_t *dstIP, uint16_t dstPort,
    PktType protocol, char direction,
    FlowData* fd)
{
    return exp_cache->add_flow(
        srcIP, srcPort, dstIP, dstPort, protocol, direction, fd);
}

int FlowControl::add_expected(
    const sfip_t *srcIP, uint16_t srcPort,
    const sfip_t *dstIP, uint16_t dstPort,
    PktType protocol, int16_t appId, FlowData* fd)
{
    return exp_cache->add_flow(
        srcIP, srcPort, dstIP, dstPort, protocol, SSN_DIR_BOTH, fd, appId);
}

bool FlowControl::is_expected(Packet* p)
{
    return exp_cache->is_expected(p);
}

