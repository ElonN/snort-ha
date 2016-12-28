//--------------------------------------------------------------------------
// Copyright (C) 2014-2015 Cisco and/or its affiliates. All rights reserved.
// Copyright (C) 2003-2013 Sourcefire, Inc.
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

/* We use some Linux only socket capabilities */

#include <errno.h>
#include <stdlib.h>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#ifdef LINUX
#include <sys/socket.h>
#include <sys/un.h>

#include <string>
#include <vector>

#include "main/snort_types.h"
#include "main/snort_config.h"
#include "main/snort_debug.h"
#include "framework/logger.h"
#include "framework/module.h"
#include "managers/event_manager.h"
#include "detection/rules.h"
#include "detection/treenodes.h"
#include "events/event.h"
#include "hash/sfghash.h"
#include "parser/parser.h"
#include "target_based/snort_protocols.h"
#include "utils/util.h"

struct SfSock
{
    int connected;
    int sock;
    struct sockaddr_un addr;
};

struct RuleId
{
    unsigned gid;
    unsigned sid;
};

static THREAD_LOCAL SfSock context;

using namespace std;
typedef vector<RuleId> RuleVector;

#define s_name "alert_sfsocket"

//-------------------------------------------------------------------------
// alert_sfsocket module
//-------------------------------------------------------------------------

static const Parameter rule_params[] =
{
    { "gid", Parameter::PT_INT, "1:", "1",
      "rule generator ID" },

    { "sid", Parameter::PT_INT, "1:", "1",
      "rule signature ID" },

    { nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr }
};

static const Parameter s_params[] =
{
    { "file", Parameter::PT_STRING, nullptr, nullptr,
      "name of unix socket file" },

    { "rules", Parameter::PT_LIST, rule_params, nullptr,
      "name of unix socket file" },

    { nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr }
};

#define s_help \
    "output event over socket"

class SfSocketModule : public Module
{
public:
    SfSocketModule() : Module(s_name, s_help, s_params) { }

    bool set(const char*, Value&, SnortConfig*) override;
    bool begin(const char*, int, SnortConfig*) override;
    bool end(const char*, int, SnortConfig*) override;

public:
    string file;
    RuleVector rulez;
    RuleId rule;
};

bool SfSocketModule::set(const char*, Value& v, SnortConfig*)
{
    if ( v.is("file") )
        file = v.get_string();

    else if ( v.is("gid") )
        rule.gid = v.get_long();

    else if ( v.is("sid") )
        rule.sid = v.get_long();

    return true;
}

bool SfSocketModule::begin(const char*, int, SnortConfig*)
{
    file.erase();
    rule.gid = rule.sid = 1;
    return true;
}

bool SfSocketModule::end(const char* fqn, int, SnortConfig*)
{
    if ( !strcmp(fqn, "alert_sfsocket.rules") )
        rulez.push_back(rule);

    return true;
}

//-------------------------------------------------------------------------
// socket stuff

static int AlertSFSocket_Connect(void)
{
    /* check sock value */
    if (context.sock == -1)
        FatalError("AlertSFSocket: Invalid socket\n");

    if (connect(context.sock, (sockaddr*)&context.addr, sizeof(context.addr)) == -1)
    {
        if (errno == ECONNREFUSED || errno == ENOENT)
        {
            LogMessage("WARNING: AlertSFSocket: Unable to connect to socket: "
                "%s.\n", get_error(errno));
            return 1;
        }
        else
        {
            FatalError("AlertSFSocket: Unable to connect to socket "
                "(%i): %s\n", errno, get_error(errno));
        }
    }
    return 0;
}

static void sock_init(const char* args)
{
    if ( (context.sock = socket(AF_UNIX, SOCK_DGRAM, 0)) < 0 )
        FatalError("Unable to create socket: %s\n", get_error(errno));

    std::string name;
    get_instance_file(name, args);

    memset(&context.addr, 0, sizeof(context.addr));
    context.addr.sun_family = AF_UNIX;
    memcpy(context.addr.sun_path + 1, name.c_str(), strlen(name.c_str()));

    if (AlertSFSocket_Connect() == 0)
        context.connected = 1;
}

void send_sar(uint8_t* data, unsigned len)
{
    int tries = 0;

    do
    {
        tries++;
        /* connect as needed */
        if (!context.connected)
        {
            if (AlertSFSocket_Connect() != 0)
                break;
            context.connected = 1;
        }

        /* send request */
        if (send(context.sock, data, len, 0) == len)
        {
            /* success */
            return;
        }
        /* send failed */
        if (errno == ENOBUFS)
        {
            LogMessage("ERROR: AlertSFSocket: out of buffer space\n");
            break;
        }
        else if (errno == ECONNRESET)
        {
            context.connected = 0;
            LogMessage("WARNING: AlertSFSocket: connection reset, will attempt "
                "to reconnect.\n");
        }
        else if (errno == ECONNREFUSED)
        {
            LogMessage("WARNING: AlertSFSocket: connection refused, "
                "will attempt to reconnect.\n");
            context.connected = 0;
        }
        else if (errno == ENOTCONN)
        {
            LogMessage("WARNING: AlertSFSocket: not connected, "
                "will attempt to reconnect.\n");
            context.connected = 0;
        }
        else
        {
            LogMessage("ERROR: AlertSFSocket: unhandled error '%i' in send(): "
                "%s\n", errno, get_error(errno));
            context.connected = 0;
        }
    }
    while (tries <= 1);
    LogMessage("ERROR: AlertSFSocket: Alert not sent\n");
}

//-------------------------------------------------------------------------
// sig stuff

/* search for an OptTreeNode by sid in specific policy*/
// FIXIT-L wow - this should be encapsulated somewhere ...
// (actually, the whole reason for doing this needs to be rethought)
static OptTreeNode* OptTreeNode_Search(uint32_t, uint32_t sid)
{
    SFGHASH_NODE* hashNode;
    OptTreeNode* otn = NULL;
    RuleTreeNode* rtn = NULL;

    if (sid == 0)
        return NULL;

    for (hashNode = sfghash_findfirst(snort_conf->otn_map);
        hashNode;
        hashNode = sfghash_findnext(snort_conf->otn_map))
    {
        otn = (OptTreeNode*)hashNode->data;
        rtn = getRuntimeRtnFromOtn(otn);

        if ( rtn and is_network_protocol(rtn->proto) )
        {
            if (otn->sigInfo.id == sid)
                return otn;
        }
    }

    return NULL;
}

//-------------------------------------------------------------------------
// sar stuff

struct SnortActionRequest
{
    uint32_t event_id;
    uint32_t tv_sec;
    uint32_t generator;
    uint32_t sid;
    uint32_t src_ip;
    uint32_t dest_ip;
    uint16_t sport;
    uint16_t dport;
    uint8_t protocol;
};

void load_sar(Packet* packet, Event* event, SnortActionRequest& sar)
{
    if(!event || !packet || !packet->ptrs.ip_api.is_ip())
        return;

    // for now, only support ip4
    if ( !packet->ptrs.ip_api.is_ip4() )
        return;

    /* construct the action request */
    sar.event_id = event->event_id;
    sar.tv_sec = packet->pkth->ts.tv_sec;
    sar.generator = event->sig_info->generator;
    sar.sid = event->sig_info->id;

    // when ip6 is supported:
    // * suggest TLV format where T == family, L is implied by
    //   T (and not sent), and V is just the address octets in
    //   network order
    // * if T is made the 1st octet of struct, bytes to read
    //   can be determined by reading 1 byte
    // * addresses could be moved to end of struct in uint8_t[32]
    //   and only 1st 8 used for ip4
    sar.src_ip =  ntohl(packet->ptrs.ip_api.get_src()->ip32[0]);
    sar.dest_ip = ntohl(packet->ptrs.ip_api.get_dst()->ip32[0]);
    sar.protocol = packet->get_ip_proto_next();

    if (packet->is_tcp() || packet->is_udp())
    {
        sar.sport = packet->ptrs.sp;
        sar.dport = packet->ptrs.dp;
    }
    else
    {
        sar.sport = 0;
        sar.dport = 0;
    }
}

//-------------------------------------------------------------------------

class SfSocketLogger : public Logger
{
public:
    SfSocketLogger(SfSocketModule*);

    void configure(RuleId&);

    void open() override;
    void close() override;

    void alert(Packet*, const char* msg, Event*) override;

private:
    string file;
};

SfSocketLogger::SfSocketLogger(SfSocketModule* m)
{
    file = m->file;

    for ( auto r : m->rulez )
        configure(r);
}

void SfSocketLogger::configure(RuleId& r)
{
    OptTreeNode* otn = OptTreeNode_Search(r.gid, r.sid);

    if ( !otn )
        ParseError("Unable to find OptTreeNode for %u:%u\n", r.gid, r.sid);

    else
        EventManager::add_output(&otn->outputFuncs, this);
}

void SfSocketLogger::open()
{
    sock_init(file.c_str());
}

void SfSocketLogger::close()
{
    ::close(context.sock);
    context.sock = -1;
}

void SfSocketLogger::alert(Packet* packet, const char*, Event* event)
{
    SnortActionRequest sar;
    load_sar(packet, event, sar);
    send_sar((uint8_t*)&sar, sizeof(sar));
}

//-------------------------------------------------------------------------

static Module* mod_ctor()
{ return new SfSocketModule; }

static void mod_dtor(Module* m)
{ delete m; }

static Logger* sf_sock_ctor(SnortConfig*, Module* mod)
{ return new SfSocketLogger((SfSocketModule*)mod); }

static void sf_sock_dtor(Logger* p)
{ delete p; }

static LogApi sf_sock_api
{
    {
        PT_LOGGER,
        sizeof(LogApi),
        LOGAPI_VERSION,
        0,
        API_RESERVED,
        API_OPTIONS,
        s_name,
        s_help,
        mod_ctor,
        mod_dtor
    },
    OUTPUT_TYPE_FLAG__NONE,
    sf_sock_ctor,
    sf_sock_dtor
};

const BaseApi* alert_sf_socket = &sf_sock_api.base;

#endif   /* LINUX */

