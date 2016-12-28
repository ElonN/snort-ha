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
// nhttp_test_input.h author Tom Peters <thopeter@cisco.com>

#ifndef NHTTP_TEST_INPUT_H
#define NHTTP_TEST_INPUT_H

#include <stdio.h>

#include "nhttp_enum.h"
#include "nhttp_flow_data.h"

class NHttpTestInput
{
public:
    NHttpTestInput(const char* fileName);
    void scan(uint8_t*& data, uint32_t& length, NHttpEnums::SourceId source_id, uint64_t seq_num);
    void flush(uint32_t num_octets);
    void reassemble(uint8_t** buffer, unsigned& length, NHttpEnums::SourceId source_id,
        bool& tcp_close);

private:
    FILE* test_data_file;
    uint8_t msg_buf[2 * NHttpEnums::MAX_OCTETS];

    // break command has been read and we are waiting for a new flow to start
    bool need_break = false;

    // Sequence number of the flow we are currently piggybacking on
    uint64_t curr_seq_num = 0;

    // data has been flushed and must be sent by reassemble() before more data may be given to
    // scan()
    bool flushed = false;

    // current direction of traffic flow. Toggled by commands in file.
    NHttpEnums::SourceId last_source_id = NHttpEnums::SRC_CLIENT;

    // reassemble() just completed and all flushed octets forwarded, time to resume scan()
    bool just_flushed = true;

    // TCP connection directional close at end of current paragraph
    bool tcp_closed = false;

    // number of octets that have been flushed and must be sent by reassemble
    uint32_t flush_octets = 0;

    // number of characters in the buffer previously shown to PAF but not flushed yet
    uint32_t previous_offset = 0;

    // number of characters in the buffer
    uint32_t end_offset = 0;

    // Need to send close with next pass through reassemble()
    bool close_pending = false;

    // Close notification already provided
    bool close_notified = false;

    void reset();
};

#endif

