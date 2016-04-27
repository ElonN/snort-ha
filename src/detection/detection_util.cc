//--------------------------------------------------------------------------
// Copyright (C) 2014-2015 Cisco and/or its affiliates. All rights reserved.
// Copyright (C) 2002-2013 Sourcefire, Inc.
// Copyright (C) 1998-2002 Martin Roesch <roesch@sourcefire.com>
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

#include "detection_util.h"

#include <time.h>
#include <string>

#include "main/snort_config.h"
#include "log/text_log.h"
#include "actions/actions.h"
#include "utils/stats.h"

THREAD_LOCAL DataPointer g_alt_data;
THREAD_LOCAL DataPointer g_file_data;

const char* http_buffer_name[HTTP_BUFFER_MAX] =
{
    "error/unset",
    "http_client_body",
    "http_cookie",
    "http_header",
    "http_method",
    "http_raw_cookie",
    "http_raw_header",
    "http_raw_uri",
    "http_stat_code",
    "http_stat_msg",
    "http_uri"
};

#define LOG_CHARS 16

static THREAD_LOCAL TextLog* tlog = NULL;
static THREAD_LOCAL unsigned nEvents = 0;

static void LogBuffer(const char* s, const uint8_t* p, unsigned n)
{
    char hex[(3*LOG_CHARS)+1];
    char txt[LOG_CHARS+1];
    unsigned odx = 0, idx = 0, at = 0;

    if ( !p )
        return;

    if ( n > snort_conf->event_trace_max )
        n = snort_conf->event_trace_max;

    for ( idx = 0; idx < n; idx++)
    {
        uint8_t byte = p[idx];
        sprintf(hex + 3*odx, "%2.02X ", byte);
        txt[odx++] = isprint(byte) ? byte : '.';

        if ( odx == LOG_CHARS )
        {
            txt[odx] = hex[3*odx] = '\0';
            TextLog_Print(tlog, "%s[%2u] %s %s\n", s, at, hex, txt);
            at = idx + 1;
            odx = 0;
        }
    }
    if ( odx )
    {
        txt[odx] = hex[3*odx] = '\0';
        TextLog_Print(tlog, "%s[%2u] %-48.48s %s\n", s, at, hex, txt);
    }
}

void EventTrace_Log(const Packet* p, const OptTreeNode* otn, int action)
{
    const char* acts = get_action_string((RuleType)action);

    if ( !tlog )
        return;

    TextLog_Print(tlog,
        "\nEvt=%u, Gid=%u, Sid=%u, Rev=%u, Act=%s\n",
        event_id, otn->sigInfo.generator,
        otn->sigInfo.id, otn->sigInfo.rev, acts);

    TextLog_Print(tlog,
        "Pkt=%lu, Sec=%u.%6u, Len=%u, Cap=%u\n",
        pc.total_from_daq, p->pkth->ts.tv_sec, p->pkth->ts.tv_usec,
        p->pkth->pktlen, p->pkth->caplen);

    TextLog_Print(tlog,
        "Pkt Bits: Flags=0x%X, Proto=0x%X, Err=0x%X\n",
        p->packet_flags, (unsigned)p->proto_bits, (unsigned)p->ptrs.decode_flags);

    TextLog_Print(tlog,
        "Pkt Cnts: Dsz=%u, Alt=%u\n",
        (unsigned)p->dsize, (unsigned)p->alt_dsize);

    LogBuffer("Packet", p->data, p->alt_dsize);

    nEvents++;
}

void EventTrace_Init(void)
{
    if ( snort_conf->event_trace_max > 0 )
    {
        time_t now = time(NULL);
        char time_buf[26];
        ctime_r(&now, time_buf);

        std::string fname;
        get_instance_file(fname, "event_trace.txt");

        tlog = TextLog_Init (fname.c_str(), 128, 8*1024*1024);
        TextLog_Print(tlog, "\nTrace started at %s", time_buf);
        TextLog_Print(tlog, "Trace max_data is %u bytes\n", snort_conf->event_trace_max);
    }
}

void EventTrace_Term(void)
{
    if ( tlog )
    {
        time_t now = time(NULL);
        char time_buf[26];
        ctime_r(&now, time_buf);

        TextLog_Print(tlog, "\nTraced %u events\n", nEvents);
        TextLog_Print(tlog, "Trace stopped at %s", time_buf);
        TextLog_Term(tlog);
    }
}

