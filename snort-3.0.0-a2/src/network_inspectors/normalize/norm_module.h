//--------------------------------------------------------------------------
// Copyright (C) 2014-2015 Cisco and/or its affiliates. All rights reserved.
// Copyright (C) 2010-2013 Sourcefire, Inc.
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
// norm_module.h author Russ Combs <rucombs@cisco.com>

#ifndef NORM_MODULE_H
#define NORM_MODULE_H

#include "framework/module.h"
#include "norm.h"

#define NORM_NAME "normalizer"
#define NORM_HELP "packet scrubbing for inline mode"

extern THREAD_LOCAL ProfileStats norm_perf_stats;

class NormalizeModule : public Module
{
public:
    NormalizeModule();

    bool set(const char*, Value&, SnortConfig*) override;
    bool begin(const char*, int, SnortConfig*) override;
    bool end(const char*, int, SnortConfig*) override;

    ProfileStats* get_profile() const override;
    const PegInfo* get_pegs() const override;
    PegCount* get_counts() const override;

    const NormalizerConfig* get_config()
    { return &config; }

private:
    bool set_ip4(const char*, Value&, SnortConfig*);
    bool set_tcp(const char*, Value&, SnortConfig*);

    NormalizerConfig config;
};

#endif

