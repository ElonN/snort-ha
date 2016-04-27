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
// nhttp_msg_status.h author Tom Peters <thopeter@cisco.com>

#ifndef NHTTP_MSG_STATUS_H
#define NHTTP_MSG_STATUS_H

#include "nhttp_msg_start.h"
#include "nhttp_field.h"

//-------------------------------------------------------------------------
// NHttpMsgStatus class
//-------------------------------------------------------------------------

class NHttpMsgStatus : public NHttpMsgStart
{
public:
    NHttpMsgStatus(const uint8_t* buffer, const uint16_t buf_size, NHttpFlowData* session_data_,
        NHttpEnums::SourceId source_id_, bool buf_owner, Flow* flow_,
        const NHttpParaList* params_);
    void print_section(FILE* output) override;
    void gen_events() override;
    void update_flow() override;

    const Field& get_status_code() { return status_code; }
    const Field& get_reason_phrase() { return reason_phrase; }

private:
    void parse_start_line() override;
    void derive_status_code_num();

    Field status_code;
    Field reason_phrase;
};

#endif

