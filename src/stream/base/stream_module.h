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

// stream_module.h author Russ Combs <rucombs@cisco.com>

#ifndef STREAM_MODULE_H
#define STREAM_MODULE_H

#include "main/snort_types.h"
#include "framework/module.h"
#include "flow/flow_control.h"

extern THREAD_LOCAL ProfileStats s5PerfStats;
struct SnortConfig;

//-------------------------------------------------------------------------
// stream module
//-------------------------------------------------------------------------

#define MOD_NAME "stream"
#define MOD_HELP "common flow tracking"

struct StreamModuleConfig
{
    FlowConfig ip_cfg;
    FlowConfig icmp_cfg;
    FlowConfig tcp_cfg;
    FlowConfig udp_cfg;
    FlowConfig user_cfg;
    FlowConfig file_cfg;
};

class StreamModule : public Module
{
public:
    StreamModule();

    bool set(const char*, Value&, SnortConfig*) override;

    const PegInfo* get_pegs() const override;
    ProfileStats* get_profile() const override;
    const StreamModuleConfig* get_data();

    void sum_stats() override;
    void show_stats() override;
    void reset_stats() override;

private:
    StreamModuleConfig config;
};

extern void base_sum();
extern void base_stats();
extern void base_reset();

#endif

