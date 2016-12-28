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
// event_manager.h author Russ Combs <rucombs@cisco.com>

#ifndef EVENT_MANAGER_H
#define EVENT_MANAGER_H

// Factory for Loggers.
// OutputSet is a group of Loggers that can be attached to external data.
// Also provides runtime logging.

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "main/snort_types.h"
#include "framework/base_api.h"

#ifdef PIGLET
#include "framework/logger.h"
#include "piglet/piglet_api.h"
#endif

#define OUTPUT_TYPE_FLAG__NONE  0x0
#define OUTPUT_TYPE_FLAG__ALERT 0x1
#define OUTPUT_TYPE_FLAG__LOG   0x2

struct Packet;
struct Event;
struct OutputSet;
struct SnortConfig;
struct LogApi;

//-------------------------------------------------------------------------

#ifdef PIGLET
struct LoggerWrapper
{
    LoggerWrapper(const LogApi* a, Logger* p) :
        api { a }, instance { p } { }

    ~LoggerWrapper()
    {
        if ( api && instance && api->dtor )
            api->dtor(instance);
    }

    const LogApi* api;
    Logger* instance;
};
#endif

class EventManager
{
public:
    static void add_plugin(const LogApi*);
    static void dump_plugins();
    static void release_plugins();

    static void instantiate(const char*, SnortConfig*);
    static void instantiate(const LogApi*, Module*, SnortConfig*);

    static unsigned get_output_type_flags(char*);

    static void add_output(OutputSet**, class Logger*);
    static void copy_outputs(OutputSet* dst, OutputSet* src);
    static void release_outputs(OutputSet*);

    static void open_outputs();
    static void close_outputs();

    static void call_alerters(OutputSet*, Packet*, const char* message, Event*);
    static void call_loggers(OutputSet*, Packet*, const char* message, Event*);

    static void enable_alerts(bool b) { alert_enabled = b; }
    static void enable_logs(bool b) { log_enabled = b; }

#ifdef PIGLET
    static LoggerWrapper* instantiate(const char* name, Module*, SnortConfig*);
#endif

private:
    static void instantiate(struct Output*, Module*, SnortConfig*);

    static bool alert_enabled;
    static bool log_enabled;
};

#endif

