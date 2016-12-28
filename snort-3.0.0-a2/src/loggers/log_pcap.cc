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

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <sys/types.h>
#include <ctype.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <time.h>
#include <pcap.h>

extern "C" {
#include <sfbpf_dlt.h>
}

#include <string>

#include "main/snort_debug.h"
#include "main/snort_config.h"
#include "main/analyzer.h"
#include "framework/logger.h"
#include "framework/module.h"
#include "protocols/packet.h"
#include "events/event.h"
#include "parser/parser.h"
#include "packet_io/sfdaq.h"
#include "stream/stream_api.h"
#include "utils/util.h"
#include "utils/stats.h"

/*
 * <pcap file> ::= <pcap file hdr> [<pcap pkt hdr> <packet>]*
 * on 64 bit systems, some fields in the <pcap * hdr> are 8 bytes
 * but still stored on disk as 4 bytes.
 * eg: (sizeof(*pkth) = 24) > (dumped size = 16)
 * so we use PCAP_*_HDR_SZ defines in lieu of sizeof().
 */

#define PCAP_FILE_HDR_SZ (24)
#define PCAP_PKT_HDR_SZ  (16)

using namespace std;

struct LtdConfig
{
    string file;
    size_t limit;
};

struct LtdContext
{
    char* file;
    pcap_dumper_t* dumpd;
    time_t lastTime;
    size_t size;
};

static THREAD_LOCAL LtdContext context;

static void TcpdumpRollLogFile(LtdConfig*);

#define S_NAME "log_pcap"
#define F_NAME "log.pcap"

//-------------------------------------------------------------------------
// module stuff
//-------------------------------------------------------------------------

static const Parameter s_params[] =
{
    { "limit", Parameter::PT_INT, "0:", "0",
      "set limit (0 is unlimited)" },

    { "units", Parameter::PT_ENUM, "B | K | M | G", "B",
      "bytes | KB | MB | GB" },

    { nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr }
};

#define s_help \
    "log packet in pcap format"

class TcpdumpModule : public Module
{
public:
    TcpdumpModule() : Module(S_NAME, s_help, s_params) { }

    bool set(const char*, Value&, SnortConfig*) override;
    bool begin(const char*, int, SnortConfig*) override;
    bool end(const char*, int, SnortConfig*) override;

public:
    unsigned limit;
    unsigned units;
};

bool TcpdumpModule::set(const char*, Value& v, SnortConfig*)
{
    if ( v.is("limit") )
        limit = v.get_long();

    else if ( v.is("units") )
        units = v.get_long();

    else
        return false;

    return true;
}

bool TcpdumpModule::begin(const char*, int, SnortConfig*)
{
    limit = 0;
    units = 0;
    return true;
}

bool TcpdumpModule::end(const char*, int, SnortConfig*)
{
    while ( units-- )
        limit *= 1024;

    return true;
}

//-------------------------------------------------------------------------
// api stuff
//-------------------------------------------------------------------------

static inline size_t SizeOf(const DAQ_PktHdr_t* pkth)
{
    return PCAP_PKT_HDR_SZ + pkth->caplen;
}

static void LogTcpdumpSingle(
    LtdConfig* data, Packet* p, const char*, Event*)
{
    size_t dumpSize = SizeOf(p->pkth);

    if ( data->limit && (context.size + dumpSize > data->limit) )
        TcpdumpRollLogFile(data);

    pcap_dump((u_char*)context.dumpd,(struct pcap_pkthdr*)p->pkth,p->pkt);
    context.size += dumpSize;

    if (!SnortConfig::line_buffered_logging())  // FIXIT-L misnomer
    {
        fflush( (FILE*)context.dumpd);
    }
}

static void LogTcpdumpStream(
    LtdConfig*, Packet*, const char*, Event*)
{
// FIXIT-L log reassembled stream data with original packet?
// (take original packet headers and append reassembled data)
}

static void TcpdumpInitLogFile(LtdConfig*, int /*nostamps?*/)
{
    context.lastTime = time(NULL);

    string file;
    get_instance_file(file, F_NAME);

    {
        pcap_t* pcap;
        int dlt = DAQ_GetBaseProtocol();

        // convert these flavors of raw to the generic
        // for compatibility with libpcap 1.0.0
        if ( dlt == DLT_IPV4 || dlt == DLT_IPV6 )
            dlt = DLT_RAW;

        pcap = pcap_open_dead(dlt, DAQ_GetSnapLen());

        if ( !pcap )
            FatalError("%s: can't get pcap context\n", S_NAME);

        context.dumpd = pcap ? pcap_dump_open(pcap, file.c_str()) : NULL;

        if (context.dumpd == NULL)
        {
            FatalError("%s: can't open %s: %s\n",
                S_NAME, file.c_str(), pcap_geterr(pcap));
        }
        pcap_close(pcap);
    }

    context.file = SnortStrdup(file.c_str());
    context.size = PCAP_FILE_HDR_SZ;
}

static void TcpdumpRollLogFile(LtdConfig* data)
{
    time_t now = time(NULL);

    /* don't roll over any sooner than resolution
     * of filename discriminator
     */
    if ( now <= context.lastTime )
        return;

    /* close the output file */
    if ( context.dumpd != NULL )
    {
        pcap_dump_close(context.dumpd);
        context.dumpd = NULL;
        context.size = 0;
        free(context.file);
        context.file = nullptr;
    }

    /* Have to add stamps now to distinguish files */
    TcpdumpInitLogFile(data, 0);
}

static void SpoLogTcpdumpCleanup(LtdConfig*)
{
    /*
     * if we haven't written any data, dump the output file so there aren't
     * fragments all over the disk
     */
    if (context.file && !pc.log_pkts && !pc.total_alert_pkts)
    {
        int ret = unlink(context.file);

        if ( ret )
            ErrorMessage("Could not remove tcpdump output file %s: %s\n",
                context.file, get_error(errno));

        free(context.file);
        context.file = nullptr;
    }
}

//-------------------------------------------------------------------------
// logger stuff
//-------------------------------------------------------------------------

class PcapLogger : public Logger
{
public:
    PcapLogger(TcpdumpModule*);
    ~PcapLogger();

    void open() override;
    void close() override;
    void reset() override;

    void log(Packet*, const char* msg, Event*) override;

private:
    LtdConfig* config;
};

PcapLogger::PcapLogger(TcpdumpModule* m)
{
    config = new LtdConfig;
    config->limit = m->limit;
}

PcapLogger::~PcapLogger()
{
    SpoLogTcpdumpCleanup(config);
    delete config;
}

void PcapLogger::open()
{
    TcpdumpInitLogFile(config, SnortConfig::output_no_timestamp());
}

void PcapLogger::close()
{
    if ( context.dumpd )
    {
        pcap_dump_close(context.dumpd);
        context.dumpd = nullptr;
    }
    if ( context.file )
        free(context.file);
}

void PcapLogger::log(Packet* p, const char* msg, Event* event)
{
    if (p->packet_flags & PKT_REBUILT_STREAM)
        LogTcpdumpStream(config, p, msg, event);
    else
        LogTcpdumpSingle(config, p, msg, event);
}

void PcapLogger::reset()
{
    TcpdumpRollLogFile(config);
}

//-------------------------------------------------------------------------
// api stuff
//-------------------------------------------------------------------------

static Module* mod_ctor()
{ return new TcpdumpModule; }

static void mod_dtor(Module* m)
{ delete m; }

static Logger* tcpdump_ctor(SnortConfig*, Module* mod)
{ return new PcapLogger((TcpdumpModule*)mod); }

static void tcpdump_dtor(Logger* p)
{ delete p; }

static LogApi tcpdump_api
{
    {
        PT_LOGGER,
        sizeof(LogApi),
        LOGAPI_VERSION,
        0,
        API_RESERVED,
        API_OPTIONS,
        S_NAME,
        s_help,
        mod_ctor,
        mod_dtor
    },
    OUTPUT_TYPE_FLAG__LOG,
    tcpdump_ctor,
    tcpdump_dtor
};

#ifdef BUILDING_SO
SO_PUBLIC const BaseApi* snort_plugins[] =
{
    &tcpdump_api.base,
    nullptr
};
#else
const BaseApi* log_pcap = &tcpdump_api.base;
#endif

