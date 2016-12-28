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

// author Hui Cao <huica@cisco.com>

#ifndef FILE_FLOWS_H
#define FILE_FLOWS_H

// This provides a wrapper to manage several file contexts

#include <sys/types.h>
#include "main/snort_types.h"
#include "libs/file_lib.h"

class FileContext;

class FileFlows:public FlowData
{
public:

    FileFlows() : FlowData(flow_id) {};
    ~FileFlows();
    static void init()
    { flow_id = FlowData::get_flow_id(); }

    // Factory method to get file flows
    static FileFlows* get_file_flows(Flow* flow);

    FileContext* get_current_file_context() {return current_context; };
    void set_current_file_context(FileContext* ctx);

    uint32_t get_new_file_instance();

    void set_file_name(const uint8_t* fname, uint32_t name_size);

    // This is used when there is only one file per session
    bool file_process(const uint8_t* file_data, int data_size,
        FilePosition position, bool upload);

    // This is used for each file context. Support multiple files per session
    bool file_process(FileContext* context, const uint8_t* file_data, int data_size,
        FilePosition position);

    //void handle_retransmit(Packet*) override;
    static unsigned flow_id;

private:
    void save_to_pending_context();
    FileContext* find_main_file_context(FilePosition position, FileDirection direction);
    FileContext* main_context = NULL;
    FileContext* pending_context = NULL;
    FileContext* current_context = NULL;
    uint32_t max_file_id = 0;
};
#endif

