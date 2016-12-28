//--------------------------------------------------------------------------
// Copyright (C) 2015-2015 Cisco and/or its affiliates. All rights reserved.
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
// user_session.cc author Russ Combs <rucombs@cisco.com>

#include "user_session.h"

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "stream_user.h"
#include "user_module.h"

#include "stream/stream.h"
#include "stream/stream_splitter.h"
#include "stream/paf.h"
#include "perf_monitor/perf.h"
#include "flow/flow_control.h"
#include "sfip/sf_ip.h"
#include "time/profiler.h"
#include "main/snort.h"

THREAD_LOCAL ProfileStats user_perf_stats;

// we always get exactly one copy of user data in order
// maintain "seg"list of user data stream
// allocate bucket size to substantially improve performance
// run user data through paf

//-------------------------------------------------------------------------
// segment stuff
//-------------------------------------------------------------------------

#define OVERHEAD   32
#define PAGE_SZ    4096
#define BUCKET     (PAGE_SZ - OVERHEAD)

UserSegment* UserSegment::init(const uint8_t* p, unsigned n)
{
    unsigned bucket = (n > BUCKET) ? n : BUCKET;
    UserSegment* us = (UserSegment*)malloc(sizeof(*us)+bucket-1);

    if ( !us )
        return nullptr;

    us->len = 0;
    us->offset = 0;
    us->used = 0;
    us->copy(p, n);

    return us;
}

void UserSegment::term(UserSegment* us)
{
    free(us);
}

unsigned UserSegment::avail()
{
    unsigned size = offset + len;
    return (BUCKET > size) ? BUCKET - size : 0;
}

void UserSegment::copy(const uint8_t* p, unsigned n)
{
    memcpy(data+offset+len, p, n);
    len += n;
}

void UserSegment::shift(unsigned n)
{
    assert(len >= n);
    offset += n;
    len -= n;
}

unsigned UserSegment::get_len()
{ return len; }

uint8_t* UserSegment::get_data()
{ return data + offset; }

bool UserSegment::unused()
{ return used < offset + len; }

void UserSegment::use(unsigned n)
{
    used += n;
    if ( used > offset + len )
        used = offset + len;
}

void UserSegment::reset()
{ used = offset; }

unsigned UserSegment::get_unused_len()
{ return (offset + len > used) ? offset + len - used : 0; }

uint8_t* UserSegment::get_unused_data()
{ return data + used; }

//-------------------------------------------------------------------------
// tracker stuff
//-------------------------------------------------------------------------

UserTracker::UserTracker()
{ init(); }

UserTracker::~UserTracker()
{ term(); }

void UserTracker::init()
{
    paf_clear(&paf_state);
    splitter = nullptr;
    total = 0;
}

void UserTracker::term()
{
    delete splitter;
    splitter = nullptr;
}

void UserTracker::detect(const Packet* p, const StreamBuffer* sb, uint32_t flags)
{
    Packet up;
    up.reset();

    up.pkth = p->pkth;
    up.ptrs = p->ptrs;
    up.flow = p->flow;
    up.data = sb->data;
    up.dsize = sb->length;

    up.proto_bits = p->proto_bits;
    up.pseudo_type = PSEUDO_PKT_USER;

    up.packet_flags = flags | PKT_REBUILT_STREAM | PKT_PSEUDO;
    up.packet_flags |= (p->packet_flags & (PKT_FROM_CLIENT|PKT_FROM_SERVER));
    up.packet_flags |= (p->packet_flags & (PKT_STREAM_EST|PKT_STREAM_UNEST_UNI));

    //printf("user detect[%d] %*s\n", up.dsize, up.dsize, (char*)up.data);
    Snort::detect_rebuilt_packet(&up);
}

int UserTracker::scan(Packet* p, uint32_t& flags)
{
    if ( seg_list.empty() )
        return -1;

    std::list<UserSegment*>::iterator it;

    for ( it = seg_list.begin(); it != seg_list.end(); ++it)
    {
        UserSegment* us = *it;

        if ( !us->unused() )
            continue;

        flags = p->packet_flags & (PKT_FROM_CLIENT|PKT_FROM_SERVER);
        unsigned len = us->get_unused_len();
        //printf("user scan[%d] '%*s'\n", len, len, us->get_unused_data());

        int32_t flush_amt = paf_check(
            splitter, &paf_state, p->flow, us->get_unused_data(), len,
            total, paf_state.seq, &flags);

        if ( flush_amt >= 0 )
        {
            us->use(flush_amt);

            if ( !splitter->is_paf() && total > (unsigned)flush_amt )
            {
                paf_jump(&paf_state, total - flush_amt);
                return total;
            }
            return flush_amt;
        }
        us->use(len);
    }
    return -1;
}

void UserTracker::flush(Packet* p, unsigned flush_amt, uint32_t flags)
{
    unsigned bytes_flushed = 0;
    const StreamBuffer* sb = nullptr;
    //printf("user flush[%d]\n", flush_amt);
    uint32_t rflags = flags & ~PKT_PDU_TAIL;

    while ( !seg_list.empty() and flush_amt )
    {
        UserSegment* us = seg_list.front();
        const uint8_t* data = us->get_data();
        unsigned len = us->get_len();
        unsigned bytes_copied = 0;

        if ( len == flush_amt )
            rflags |= (flags & PKT_PDU_TAIL);

        //printf("user reassemble[%d]\n", len);
        sb = splitter->reassemble(
            p->flow, flush_amt, bytes_flushed, data, len, rflags, bytes_copied);

        bytes_flushed += bytes_copied;
        rflags &= ~PKT_PDU_HEAD;

        if ( sb )
            detect(p, sb, flags);

        if ( len == bytes_copied )
        {
            total -= len;
            flush_amt -= len;
            seg_list.pop_front();
            UserSegment::term(us);
        }
        else
        {
            total -= bytes_copied;
            us->shift(bytes_copied);
            flush_amt = 0;
        }
    }
}

void UserTracker::process(Packet* p)
{
    uint32_t flags = 0;
    int flush_amt = scan(p, flags);

    while ( flush_amt >= 0 )
    {
        unsigned amt = (unsigned)flush_amt;
        assert(total >= amt);

        flush(p, amt, flags);

        if ( total )
            flush_amt = scan(p, flags);
        else
            break;
    }
}

void UserTracker::add_data(Packet* p)
{
    //printf("user add[%d]\n", p->dsize);
   unsigned avail = 0;

    if ( !seg_list.empty() )
    {
        UserSegment* us = seg_list.back();
        avail = us->avail();

        if ( avail )
        {
            if ( avail > p->dsize )
                avail = p->dsize;
            us->copy(p->data, avail);
        }
    }

    if ( avail < p->dsize )
    {
        UserSegment* us = UserSegment::init(p->data+avail, p->dsize-avail);

        if ( !us )
            return;

        seg_list.push_back(us);
    }
    total += p->dsize;
    process(p);
}


//-------------------------------------------------------------------------
// private user session methods
// may need additional refactoring
//-------------------------------------------------------------------------

void UserSession::start(Packet* p, Flow* flow)
{
    Inspector* ins = flow->gadget;

    if ( !ins )
        ins = flow->clouseau;

    if ( ins )
    {
        set_splitter(true, ins->get_splitter(true));
        set_splitter(false, ins->get_splitter(false));
    }
    else
    {
        set_splitter(true, new AtomSplitter(true));
        set_splitter(false, new AtomSplitter(false));
    }

    {
        flow->protocol = p->type();

        if (flow->ssn_state.session_flags & SSNFLAG_RESET)
            flow->ssn_state.session_flags &= ~SSNFLAG_RESET;

        if ( (flow->ssn_state.session_flags & SSNFLAG_CLIENT_SWAP) &&
            !(flow->ssn_state.session_flags & SSNFLAG_CLIENT_SWAPPED) )
        {
            sfip_t ip = flow->client_ip;
            uint16_t port = flow->client_port;

            flow->client_ip = flow->server_ip;
            flow->server_ip = ip;

            flow->client_port = flow->server_port;
            flow->server_port = port;

            if ( !flow->two_way_traffic() )
            {
                if ( flow->ssn_state.session_flags & SSNFLAG_SEEN_CLIENT )
                {
                    flow->ssn_state.session_flags ^= SSNFLAG_SEEN_CLIENT;
                    flow->ssn_state.session_flags |= SSNFLAG_SEEN_SERVER;
                }
                else if ( flow->ssn_state.session_flags & SSNFLAG_SEEN_SERVER )
                {
                    flow->ssn_state.session_flags ^= SSNFLAG_SEEN_SERVER;
                    flow->ssn_state.session_flags |= SSNFLAG_SEEN_CLIENT;
                }
            }
            flow->ssn_state.session_flags |= SSNFLAG_CLIENT_SWAPPED;
        }
#if 0
        // FIXIT-L TBD
        //flow->set_expire(p, dstPolicy->session_timeout);

        // add user flavor to perf stats?
        AddStreamSession(
            &sfBase, flow->session_state & STREAM_STATE_MIDSTREAM ? SSNFLAG_MIDSTREAM : 0);

        StreamUpdatePerfBaseState(&sfBase, tmp->flow, TCP_STATE_SYN_SENT);

        EventInternal(INTERNAL_EVENT_SESSION_ADD);
#endif
    }
}

void UserSession::end(Packet*, Flow*)
{
    delete client.splitter;
    delete server.splitter;

    client.splitter = nullptr;
    server.splitter = nullptr;
}

void UserSession::update(Packet* p, Flow* flow)
{
    if ( p->ptrs.sp and p->ptrs.dp )
        p->packet_flags |= PKT_STREAM_EST;
    else
        p->packet_flags |= PKT_STREAM_UNEST_UNI;

    if ( !(flow->ssn_state.session_flags & SSNFLAG_ESTABLISHED) )
    {
        if ( p->packet_flags & PKT_FROM_CLIENT )
            flow->ssn_state.session_flags |= SSNFLAG_SEEN_CLIENT;
        else
            flow->ssn_state.session_flags |= SSNFLAG_SEEN_SERVER;

        if ( (flow->ssn_state.session_flags & SSNFLAG_SEEN_CLIENT) &&
             (flow->ssn_state.session_flags & SSNFLAG_SEEN_SERVER) )
        {
            flow->ssn_state.session_flags |= SSNFLAG_ESTABLISHED;

            flow->set_ttl(p, false);
        }
    }

    StreamUserConfig* pc = get_user_cfg(flow->ssn_server);
    flow->set_expire(p, pc->session_timeout);
}

void UserSession::restart(Packet* p)
{
    bool c2s = p->packet_flags & PKT_FROM_CLIENT;
    UserTracker& ut = c2s ? server : client;
    std::list<UserSegment*>::iterator it;
    ut.total = 0;

    for ( it = ut.seg_list.begin(); it != ut.seg_list.end(); ++it)
    {
        (*it)->reset();
        ut.total += (*it)->get_len();
    }

    paf_reset(&ut.paf_state);
    ut.process(p);
}

//-------------------------------------------------------------------------
// UserSession methods
//-------------------------------------------------------------------------

UserSession::UserSession(Flow* flow) : Session(flow) { }

UserSession::~UserSession() { }

bool UserSession::setup(Packet*)
{
    client.init();
    server.init();

#ifdef ENABLE_EXPECTED_USER
    if ( flow_con->expected_session(flow, p))
    {
        MODULE_PROFILE_END(user_perf_stats);
        return false;
    }
#endif
    return true;
}

void UserSession::clear()
{
    client.term();
    server.term();
    flow->restart();
}

void UserSession::set_splitter(bool c2s, StreamSplitter* ss)
{
    UserTracker& ut = c2s ? server : client;

    if ( ut.splitter )
        delete ut.splitter;

    ut.splitter = ss;

    if ( ss )
        paf_setup(&ut.paf_state);
}

StreamSplitter* UserSession::get_splitter(bool c2s)
{
    UserTracker& ut = c2s ? server : client;
    return ut.splitter;
}

int UserSession::process(Packet* p)
{
    PROFILE_VARS;
    MODULE_PROFILE_START(user_perf_stats);

    if ( stream.expired_session(flow, p) )
    {
        flow->restart();
        // FIXIT count user session timeouts here

#ifdef ENABLE_EXPECTED_USER
        if ( flow_con->expected_session(flow, p))
        {
            MODULE_PROFILE_END(user_perf_stats);
            return 0;
        }
#endif
    }

    flow->set_direction(p);

    if ( stream.blocked_session(flow, p) || stream.ignored_session(flow, p) )
    {
        MODULE_PROFILE_END(user_perf_stats);
        return 0;
    }

    update(p, flow);

    UserTracker& ut = p->from_client() ? server : client;

    if ( p->ptrs.decode_flags & DECODE_SOF or !ut.splitter )
        start(p, flow);

    if ( p->data && p->dsize )
        ut.add_data(p);

    if ( p->ptrs.decode_flags & DECODE_EOF )
        end(p, flow);

    MODULE_PROFILE_END(user_perf_stats);
    return 0;
}

//-------------------------------------------------------------------------
// UserSession methods
// FIXIT-L these are TBD after tcp is updated
// some will be deleted, some refactored, some implemented
//-------------------------------------------------------------------------

void UserSession::update_direction(char /*dir*/, const sfip_t*, uint16_t /*port*/) { }

bool UserSession::add_alert(Packet*, uint32_t /*gid*/, uint32_t /*sid*/) { return true; }
bool UserSession::check_alerted(Packet*, uint32_t /*gid*/, uint32_t /*sid*/) { return false; }

int UserSession::update_alert(
    Packet*, uint32_t /*gid*/, uint32_t /*sid*/,
    uint32_t /*event_id*/, uint32_t /*event_second*/)
{ return 0; }

void UserSession::flush_client(Packet*) { }
void UserSession::flush_server(Packet*) { }
void UserSession::flush_talker(Packet*) { }
void UserSession::flush_listener(Packet*) { }

void UserSession::set_extra_data(Packet*, uint32_t /*flag*/) { }
void UserSession::clear_extra_data(Packet*, uint32_t /*flag*/) { }

uint8_t UserSession::get_reassembly_direction()
{ return SSN_DIR_NONE; }

