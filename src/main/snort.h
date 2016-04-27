//--------------------------------------------------------------------------
// Copyright (C) 2014-2015 Cisco and/or its affiliates. All rights reserved.
// Copyright (C) 2005-2013 Sourcefire, Inc.
// Copyright (C) 1998-2005 Martin Roesch <roesch@sourcefire.com>
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

#ifndef SNORT_H
#define SNORT_H

// Snort is the top-level application class.

#include <assert.h>
#include <sys/types.h>
#include <stdio.h>

extern "C" {
#include <daq.h>
}

class Flow;
struct Packet;
struct SnortConfig;

typedef void (* MainHook_f)(Packet*);

class Snort
{
public:
    static SnortConfig* get_reload_config();
    static void setup(int argc, char* argv[]);
    static void cleanup();

    static bool is_starting();
    static bool is_reloading();

    static void thread_init(const char* intf);
    static void thread_term();

    static void thread_idle();
    static void thread_rotate();

    static void capture_packet();
    static void decode_rebuilt_packet(Packet*, const DAQ_PktHdr_t*, const uint8_t* pkt, Flow*);
    static void detect_rebuilt_packet(Packet*);

    static DAQ_Verdict process_packet(
        Packet*, const DAQ_PktHdr_t*, const uint8_t* pkt, bool is_frag=false);

    static DAQ_Verdict fail_open(void*, const DAQ_PktHdr_t*, const uint8_t*);
    static DAQ_Verdict packet_callback(void*, const DAQ_PktHdr_t*, const uint8_t*);

    static void set_main_hook(MainHook_f);

private:
    static void init(int, char**);
    static void unprivileged_init();
    static void term();
    static void clean_exit(int);

private:
    static bool initializing;
    static bool reloading;
};

#endif

