//--------------------------------------------------------------------------
// Copyright (C) 2014-2015 Cisco and/or its affiliates. All rights reserved.
// Copyright (C) 2002-2013 Sourcefire, Inc.
// Copyright (C) 1998-2002 Martin Roesch <roesch@sourcefire.com>
// Copyright (C) 2000,2001 Andrew R. Baker <andrewb@uab.edu>
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
#include <string.h>
#include <sys/un.h>
#include <unistd.h>
#include <errno.h>

#include <string>

#include "main/snort_types.h"
#include "main/snort_debug.h"
#include "framework/logger.h"
#include "framework/module.h"
#include "events/event.h"
#include "protocols/packet.h"
#include "parser/parser.h"
#include "utils/util.h"
#include "packet_io/sfdaq.h"

#define UNSOCK_FILE "snort_alert"

/* this is equivalent to the 32-bit pcap pkthdr struct
 */
struct pcap_pkthdr32
{
    struct sf_timeval32 ts;   /* packet timestamp */
    uint32_t caplen;          /* packet capture length */
    uint32_t len;             /* packet "real" length */
};

/* this struct is for the alert socket code.... */
// FIXIT-L alert unix sock supports l2-l3-l4 encapsulations

const unsigned int ALERTMSG_LENGTH = 256;
struct Alertpkt
{
    uint8_t alertmsg[ALERTMSG_LENGTH]; /* variable.. */
    struct pcap_pkthdr32 pkth;
    uint32_t dlthdr;       /* datalink header offset. (ethernet, etc.. ) */
    uint32_t nethdr;       /* network header offset. (ip etc...) */
    uint32_t transhdr;     /* transport header offset (tcp/udp/icmp ..) */
    uint32_t data;
    uint32_t val;  /* which fields are valid. (NULL could be
                    * valids also) */
    /* Packet struct --> was null */
#define NOPACKET_STRUCT 0x1
    /* no transport headers in packet */
#define NO_TRANSHDR    0x2
    uint8_t pkt[65535];       // FIXIT-L move to end and send actual size

    uint32_t gid;
    uint32_t sid;
    uint32_t rev;
    uint32_t class_id;
    uint32_t priority;

    uint32_t event_id;
    uint32_t event_ref;
    struct sf_timeval32 ref_time;
};

struct UnixSock
{
    int socket;
    struct sockaddr_un addr;
    Alertpkt alert;
};

static THREAD_LOCAL UnixSock us;

#define s_name "alert_unixsock"

//-------------------------------------------------------------------------
// alert_unixsock module
//-------------------------------------------------------------------------

static const Parameter s_params[] =
{
    // FIXIT-L add name param?

    { nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr }
};

#define s_help \
    "output event over unix socket"

class UnixSockModule : public Module
{
public:
    UnixSockModule() : Module(s_name, s_help, s_params) { }

    bool set(const char*, Value&, SnortConfig*) override
    { return false; }
};

//-------------------------------------------------------------------------

static void get_alert_pkt(
    Packet* p, const char* msg, Event* event)
{
    DebugMessage(DEBUG_LOG, "Logging Alert data!\n");

    // FIXIT-L ugh ...
    memset((char*)&us.alert,0,sizeof(us.alert));

    us.alert.gid = event->sig_info->generator;
    us.alert.sid = event->sig_info->id;
    us.alert.rev = event->sig_info->rev;
    us.alert.class_id = event->sig_info->class_id;
    us.alert.priority = event->sig_info->priority;

    us.alert.event_id = event->event_id;
    us.alert.event_ref = event->event_reference;
    us.alert.ref_time = event->ref_time;

    if (p && p->pkt)
    {
        uint32_t snaplen = DAQ_GetSnapLen();
        memmove( (void*)&us.alert.pkth, (const void*)p->pkth,
            sizeof(us.alert.pkth));
        memmove(us.alert.pkt, (const void*)p->pkt,
            us.alert.pkth.caplen > snaplen ? snaplen : us.alert.pkth.caplen);
    }
    else
        us.alert.val|=NOPACKET_STRUCT;

    if (msg)
    {
        // FIXIT-L ugh ...
        memmove( (void*)us.alert.alertmsg, (const void*)msg,
            strlen(msg)>ALERTMSG_LENGTH-1 ? ALERTMSG_LENGTH - 1 : strlen(msg));
    }

    /* some data which will help monitoring utility to dissect packet */
    if (!(us.alert.val & NOPACKET_STRUCT))
    {
        if (p)
        {
            if (p->proto_bits & PROTO_BIT__ETH)
            {
                const eth::EtherHdr* eh = layer::get_eth_layer(p);
                us.alert.dlthdr=(char*)eh-(char*)p->pkt;
            }

            /* we don't log any headers besides eth yet */
            if (p->ptrs.ip_api.is_ip4() && p->pkt)
            {
                us.alert.nethdr=(char*)p->ptrs.ip_api.get_ip4h()-(char*)p->pkt;

                switch (p->type())
                {
                case PktType::TCP:
                    if (p->ptrs.tcph)
                        us.alert.transhdr=(char*)p->ptrs.tcph-(char*)p->pkt;
                    break;

                case PktType::UDP:
                    if (p->ptrs.udph)
                        us.alert.transhdr=(char*)p->ptrs.udph-(char*)p->pkt;
                    break;

                case PktType::ICMP:
                    if (p->ptrs.icmph)
                        us.alert.transhdr=(char*)p->ptrs.icmph-(char*)p->pkt;
                    break;

                default:
                    /* us.alert.transhdr is null due to initial memset */
                    us.alert.val|=NO_TRANSHDR;
                    break;
                } /* switch */
            }

            if (p->data && p->pkt)
                us.alert.data=p->data - p->pkt;
        }
    }
}

//-------------------------------------------------------------------------

static void OpenAlertSock(void)
{
    std::string name;
    get_instance_file(name, UNSOCK_FILE);

    if ( access(name.c_str(), W_OK) )
        ErrorMessage("%s file doesn't exist or isn't writable\n", name.c_str());

    memset((char*)&us.addr, 0, sizeof(us.addr));
    us.addr.sun_family = AF_UNIX;

    /* copy path over and preserve a null byte at the end */
    strncpy(us.addr.sun_path, name.c_str(), sizeof(us.addr.sun_path)-1);

    if ( (us.socket = socket(AF_UNIX, SOCK_DGRAM, 0)) < 0 )
        FatalError("socket() call failed: %s", get_error(errno));

#ifdef FREEBSD
    int buflen=sizeof(us.alert);

    if ( setsockopt(us.socket, SOL_SOCKET, SO_SNDBUF, (char*)&buflen, sizeof(int)) < 0 )
        FatalError("setsockopt() call failed: %s", get_error(errno));
#endif
}

//-------------------------------------------------------------------------

class UnixSockLogger : public Logger
{
public:
    UnixSockLogger() { }

    void open() override;
    void close() override;

    void alert(Packet*, const char* msg, Event*) override;
};

void UnixSockLogger::open()
{
    OpenAlertSock();
}

void UnixSockLogger::close()
{
    if ( us.socket >= 0 )
        ::close(us.socket);

    us.socket = -1;
}

void UnixSockLogger::alert(Packet* p, const char* msg, Event* event)
{
    get_alert_pkt(p, msg, event);

    if (sendto(us.socket,(const void*)&us.alert,sizeof(us.alert),
        0,(struct sockaddr*)&us.addr,sizeof(us.addr))==-1)
    {
        /* whatever we do to sign that some alerts could be missed */
    }
}

//-------------------------------------------------------------------------

static Module* mod_ctor()
{ return new UnixSockModule; }

static void mod_dtor(Module* m)
{ delete m; }

static Logger* unix_sock_ctor(SnortConfig*, Module*)
{ return new UnixSockLogger; }

static void unix_sock_dtor(Logger* p)
{ delete p; }

static LogApi unix_sock_api
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
    OUTPUT_TYPE_FLAG__ALERT,
    unix_sock_ctor,
    unix_sock_dtor
};

#ifdef BUILDING_SO
SO_PUBLIC const BaseApi* snort_plugins[] =
{
    &unix_sock_api.base,
    nullptr
};
#else
const BaseApi* alert_unix_sock = &unix_sock_api.base;
#endif

