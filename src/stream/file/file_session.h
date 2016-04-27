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
// file_session.h author Russ Combs <rucombs@cisco.com>

#ifndef USER_SESSION_H
#define USER_SESSION_H

#include <assert.h>
#include <list>

#include "flow/session.h"
#include "stream/paf.h"

class FileSession : public Session
{
public:
    FileSession(Flow*);
    ~FileSession();

    bool setup(Packet*) override;
    void clear() override;
    int process(Packet*) override;

    bool is_sequenced(uint8_t /*dir*/) override
    { return true; }

    bool are_packets_missing(uint8_t /*dir*/) override
    { return false; }

    uint8_t missing_in_reassembled(uint8_t /*dir*/) override
    { return SSN_MISSING_NONE; }

private:
    void start(Packet*, Flow*);
    void update(Packet*, Flow*);
    void end(Packet*, Flow*);
};

#endif

