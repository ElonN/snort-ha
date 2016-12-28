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

// stream_module.cc author Russ Combs <rucombs@cisco.com>

#include "stream_module.h"
#include "stream/stream.h"

#include <string>
using namespace std;

//-------------------------------------------------------------------------
// stream module
//-------------------------------------------------------------------------

#define CACHE_PARAMS(name, ssn, mem, prune, idle) \
static const Parameter name[] = \
{ \
    { "max_sessions", Parameter::PT_INT, "1:", ssn, \
      "maximum simultaneous sessions tracked before pruning" }, \
 \
    { "memcap", Parameter::PT_INT, "0:", mem, \
      "maximum cache memory before pruning (0 is unlimited)" }, \
 \
    { "pruning_timeout", Parameter::PT_INT, "1:", prune, \
      "minimum inactive time before being eligible for pruning" }, \
 \
    { "idle_timeout", Parameter::PT_INT, "1:", idle, \
      "maximum inactive time before retiring session tracker" }, \
 \
    { nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr } \
}

CACHE_PARAMS(ip_params,    "16384",  "23920640", "30", "180");
CACHE_PARAMS(icmp_params,  "32768",   "1048576", "30", "180");
CACHE_PARAMS(tcp_params,  "131072", "268435456", "30", "180");
CACHE_PARAMS(udp_params,   "65536",         "0", "30", "180");
CACHE_PARAMS(user_params,   "1024",   "1048576", "30", "180");
CACHE_PARAMS(file_params,   " 128",         "0", "30", "180");

#define CACHE_TABLE(cache, proto, params) \
    { cache, Parameter::PT_TABLE, params, nullptr, \
      "configure " proto " cache limits" }

static const Parameter s_params[] =
{
    CACHE_TABLE("ip_cache",   "ip",   ip_params),
    CACHE_TABLE("icmp_cache", "icmp", icmp_params),
    CACHE_TABLE("tcp_cache",  "tcp",  tcp_params),
    CACHE_TABLE("udp_cache",  "udp",  udp_params),
    CACHE_TABLE("user_cache", "user", user_params),
    CACHE_TABLE("file_cache", "file", file_params),

    { nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr }
};

StreamModule::StreamModule() :
    Module(MOD_NAME, MOD_HELP, s_params)
{ }

const PegInfo* StreamModule::get_pegs() const
{ return base_pegs; }

ProfileStats* StreamModule::get_profile() const
{ return &s5PerfStats; }

const StreamModuleConfig* StreamModule::get_data()
{
    return &config;
}

bool StreamModule::set(const char* fqn, Value& v, SnortConfig*)
{
    FlowConfig* fc = nullptr;

    if ( strstr(fqn, "ip_cache") )
        fc = &config.ip_cfg;

    else if ( strstr(fqn, "icmp_cache") )
        fc = &config.icmp_cfg;

    else if ( strstr(fqn, "tcp_cache") )
        fc = &config.tcp_cfg;

    else if ( strstr(fqn, "udp_cache") )
        fc = &config.udp_cfg;

    else if ( strstr(fqn, "user_cache") )
        fc = &config.user_cfg;

    else if ( strstr(fqn, "file_cache") )
        fc = &config.file_cfg;

    else
        return false;

    if ( v.is("memcap") )
        fc->mem_cap = v.get_long();

    else if ( v.is("max_sessions") )
        fc->max_sessions = v.get_long();

    else if ( v.is("pruning_timeout") )
        fc->pruning_timeout = v.get_long();

    else if ( v.is("idle_timeout") )
        fc->nominal_timeout = v.get_long();

    else
        return false;

    return true;
}

void StreamModule::sum_stats()
{ base_sum(); }

void StreamModule::show_stats()
{ base_stats(); }

void StreamModule::reset_stats()
{ base_reset(); }

