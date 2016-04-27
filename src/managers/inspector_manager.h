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
// inspector_manager.h author Russ Combs <rucombs@cisco.com>

#ifndef INSPECTOR_MANAGER_H
#define INSPECTOR_MANAGER_H

// Factory for Inspectors.
// Also provides packet evaluation.

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "main/snort_types.h"
#include "framework/base_api.h"
#include "framework/inspector.h"

#ifdef PIGLET
#include "framework/inspector.h"
#include "piglet/piglet_api.h"
#endif

struct Packet;
struct FrameworkPolicy;
struct SnortConfig;
struct InspectionPolicy;

//-------------------------------------------------------------------------

class InspectorManager
{
public:
    static void add_plugin(const InspectApi* api);
    static void dump_plugins(void);
    static void dump_buffers(void);
    static void release_plugins(void);

    static void new_policy(InspectionPolicy*);
    static void delete_policy(InspectionPolicy*);

    static void new_config(SnortConfig*);
    static void delete_config(SnortConfig*);

    static void instantiate(
        const InspectApi*, Module*, SnortConfig*, const char* name = nullptr);

    static void free_inspector(Inspector*);
    static InspectSsnFunc get_session(uint16_t proto);

    static InspectorType get_type(const char* key);
    SO_PUBLIC static Inspector* get_inspector(const char* key, bool dflt_only = false);

    static Inspector* get_binder();
    static Inspector* get_wizard();

    SO_PUBLIC static Inspector* acquire(const char* key, SnortConfig*);
    SO_PUBLIC static void release(Inspector*);

    static bool configure(SnortConfig*);
    static void print_config(SnortConfig*);

    static void thread_init(SnortConfig*);
    static void thread_stop(SnortConfig*);
    static void thread_term(SnortConfig*);

    static void release_policy(FrameworkPolicy*);
    static void dispatch_meta(FrameworkPolicy*, int type, const uint8_t* data);

    static void execute(Packet*);
    static void clear(Packet*);
    static void empty_trash();

#ifdef PIGLET
    static Inspector* instantiate(const char*, Module*, SnortConfig*);
#endif

private:
    static void bumble(Packet*);
    static void full_inspection(FrameworkPolicy*, Packet*);
};

#endif

