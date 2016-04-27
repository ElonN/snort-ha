//--------------------------------------------------------------------------
// Copyright (C) 2014-2015 Cisco and/or its affiliates. All rights reserved.
// Copyright (C) 2013-2013 Sourcefire, Inc.
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

#ifndef SESSION_H
#define SESSION_H

// Session is an abstract base class for the various protocol subclasses.
// the subclasses do the actual work of tracking, reassembly, etc.

#include "sfip/sfip_t.h"
#include "stream/stream_api.h"

struct Packet;
class Flow;

class Session
{
public:
    virtual ~Session() { }

    virtual bool setup(Packet*) { return true; }
    virtual void update_direction(char /*dir*/, const sfip_t*, uint16_t /*port*/) { }
    virtual int process(Packet*) { return 0; }

    virtual void restart(Packet*) { }
    virtual void clear() = 0;
    virtual void cleanup() { clear(); }

    virtual bool add_alert(Packet*, uint32_t /*gid*/, uint32_t /*sid*/) { return false; }
    virtual bool check_alerted(Packet*, uint32_t /*gid*/, uint32_t /*sid*/) { return false; }

    virtual int update_alert(
        Packet*, uint32_t /*gid*/, uint32_t /*sid*/,
        uint32_t /*event_id*/, uint32_t /*event_second*/) { return 0; }

    virtual void flush_client(Packet*) { }
    virtual void flush_server(Packet*) { }
    virtual void flush_talker(Packet*) { }
    virtual void flush_listener(Packet*) { }

    virtual void set_splitter(bool /*c2s*/, StreamSplitter*) { }
    virtual StreamSplitter* get_splitter(bool /*c2s*/) { return nullptr; }

    virtual void set_extra_data(Packet*, uint32_t /*flag*/) { }
    virtual void clear_extra_data(Packet*, uint32_t /*flag*/) { }

    virtual bool is_sequenced(uint8_t /*dir*/) { return true; }
    virtual bool are_packets_missing(uint8_t /*dir*/) { return true; }

    virtual uint8_t get_reassembly_direction() { return SSN_DIR_NONE; }
    virtual uint8_t missing_in_reassembled(uint8_t /*dir*/) { return SSN_MISSING_NONE; }

protected:
    Session(Flow* f) { flow = f; }

public:
    Flow* flow;  // FIXIT-L use reference?
};

#endif

