//--------------------------------------------------------------------------
// Copyright (C) 2015-2015 Cisco and/or its affiliates. All rights reserved.
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
// sip.cc author Hui Cao <huica@cisco.com>

#include "sip.h"

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <assert.h>
#include <string.h>
#include <stdio.h>
#include <sys/types.h>

#include "main/snort_types.h"
#include "main/snort_debug.h"
#include "main/snort_config.h"
#include "time/profiler.h"
#include "stream/stream_api.h"
#include "file_api/file_api.h"
#include "parser/parser.h"
#include "framework/inspector.h"
#include "utils/sfsnprintfappend.h"
#include "target_based/snort_protocols.h"
#include "managers/inspector_manager.h"

#include "sip_utils.h"
#include "sip_module.h"

THREAD_LOCAL ProfileStats sipPerfStats;
THREAD_LOCAL SimpleStats sipstats;

/*
 * Function prototype(s)
 */
static void snort_sip(SIP_PROTO_CONF* GlobalConf, Packet* p);
static void FreeSipData(void*);

unsigned SipFlowData::flow_id = 0;
THREAD_LOCAL uint32_t numSessions = 0;

SipFlowData::~SipFlowData()
{
    FreeSipData(&session);
}

SIPData* SetNewSIPData(Packet* p, SIP_PROTO_CONF* config)
{
    static int MaxSessionsAlerted = 0;
    if (numSessions > config->maxNumSessions)
    {
        if (!MaxSessionsAlerted)
            SnortEventqAdd(GID_SIP, SIP_EVENT_MAX_SESSIONS);
        MaxSessionsAlerted = 1;
        return NULL;
    }
    else
    {
        MaxSessionsAlerted = 0;
    }
    SipFlowData* fd = new SipFlowData;
    p->flow->set_application_data(fd);
    numSessions++;
    return &fd->session;
}

SIPData* get_sip_session_data(Flow* flow)
{
    SipFlowData* fd = (SipFlowData*)flow->get_application_data(
        SipFlowData::flow_id);

    return fd ? &fd->session : NULL;
}

static void FreeSipData(void* data)
{
    SIPData* ssn = (SIPData*)data;

    if (numSessions > 0)
        numSessions--;

    /*Free all the dialog data*/
    sip_freeDialogs(&ssn->dialogs);
}

static void PrintSipConf(SIP_PROTO_CONF* config)
{
    SIPMethodNode* method;
    if (config == NULL)
        return;
    LogMessage("SIP config: \n");
    LogMessage("    Max number of sessions: %d %s \n",
        config->maxNumSessions,
        config->maxNumSessions
        == SIP_DEFAULT_MAX_SESSIONS ?
        "(Default)" : "");
    LogMessage("    Max number of dialogs in a session: %d %s \n",
        config->maxNumDialogsInSession,
        config->maxNumDialogsInSession
        == SIP_DEFAULT_MAX_DIALOGS_IN_SESSION ?
        "(Default)" : "");

    LogMessage("    Ignore media channel: %s\n",
        config->ignoreChannel ?
        "ENABLED" : "DISABLED");
    LogMessage("    Max URI length: %d %s \n",
        config->maxUriLen,
        config->maxUriLen
        == SIP_DEFAULT_MAX_URI_LEN ?
        "(Default)" : "");
    LogMessage("    Max Call ID length: %d %s \n",
        config->maxCallIdLen,
        config->maxCallIdLen
        == SIP_DEFAULT_MAX_CALL_ID_LEN ?
        "(Default)" : "");
    LogMessage("    Max Request name length: %d %s \n",
        config->maxRequestNameLen,
        config->maxRequestNameLen
        == SIP_DEFAULT_MAX_REQUEST_NAME_LEN ?
        "(Default)" : "");
    LogMessage("    Max From length: %d %s \n",
        config->maxFromLen,
        config->maxFromLen
        == SIP_DEFAULT_MAX_FROM_LEN ?
        "(Default)" : "");
    LogMessage("    Max To length: %d %s \n",
        config->maxToLen,
        config->maxToLen
        == SIP_DEFAULT_MAX_TO_LEN ?
        "(Default)" : "");
    LogMessage("    Max Via length: %d %s \n",
        config->maxViaLen,
        config->maxViaLen
        == SIP_DEFAULT_MAX_VIA_LEN ?
        "(Default)" : "");
    LogMessage("    Max Contact length: %d %s \n",
        config->maxContactLen,
        config->maxContactLen
        == SIP_DEFAULT_MAX_CONTACT_LEN ?
        "(Default)" : "");
    LogMessage("    Max Content length: %d %s \n",
        config->maxContentLen,
        config->maxContentLen
        == SIP_DEFAULT_MAX_CONTENT_LEN ?
        "(Default)" : "");
    LogMessage("\n");
    LogMessage("    Methods:\n");
    LogMessage("\t%s ",
        config->methodsConfig
        == SIP_METHOD_DEFAULT ?
        "(Default)" : "");
    method = config->methods;
    while (NULL != method)
    {
        LogMessage(" %s", method->methodName);
        method = method->nextm;
    }

    LogMessage("\n");
}

/*********************************************************************
 * Main entry point for SIP processing.
 *
 * Arguments:
 *  Packet * - pointer to packet structure
 *
 * Returns:
 *  int -   true
 *          false
 *
 *********************************************************************/
static inline int SIP_Process(Packet* p, SIPData* sessp, SIP_PROTO_CONF* config)
{
    int status;
    char* sip_buff = (char*)p->data;
    char* end;
    SIP_Roptions* pRopts;
    SIPMsg sipMsg;

    memset(&sipMsg, 0, SIPMSG_ZERO_LEN);

    /*Input parameters*/
    sipMsg.isTcp = p->has_tcp_data();

    end =  sip_buff + p->dsize;

    status = sip_parse(&sipMsg, sip_buff, end, config);

    if (true == status)
    {
        /*Update the dialog state*/
        SIP_updateDialog(&sipMsg, &(sessp->dialogs), p, config);
    }
    /*Update the session data*/
    pRopts = &(sessp->ropts);
    pRopts->methodFlag = sipMsg.methodFlag;
    pRopts->header_data = sipMsg.header;
    pRopts->header_len = sipMsg.headerLen;
    pRopts->body_len = sipMsg.bodyLen;
    pRopts->body_data = sipMsg.body_data;
    pRopts->status_code = sipMsg.status_code;

    DebugFormat(DEBUG_SIP, "SIP message header length: %d\n",
        sipMsg.headerLen);
    DebugFormat(DEBUG_SIP, "Parsed method: %.*s, Flag: 0x%x\n",
        sipMsg.methodLen, sipMsg.method, sipMsg.methodFlag);
    DebugFormat(DEBUG_SIP, "Parsed status code:  %d\n",
        sipMsg.status_code);
    DebugFormat(DEBUG_SIP, "Parsed header address: %p.\n",
        sipMsg.header);
    DebugFormat(DEBUG_SIP, "Parsed body address: %p.\n",
        sipMsg.body_data);

    sip_freeMsg(&sipMsg);
    return status;
}

/* Main runtime entry point for SIP preprocessor.
 * Analyzes SIP packets for anomalies/exploits.
 *
 * PARAMETERS:
 *
 * p:    Pointer to current packet to process.
 * contextp:    Pointer to context block, not used.
 *
 * RETURNS:     Nothing.
 */
static void snort_sip(SIP_PROTO_CONF* config, Packet* p)
{
    SIPData* sessp = NULL;
    PROFILE_VARS;

    MODULE_PROFILE_START(sipPerfStats);

    /* Attempt to get a previously allocated SIP block. */
    sessp = get_sip_session_data(p->flow);

    if (sessp == NULL)
    {
        /* Check the stream session. If it does not currently
         * have our SIP data-block attached, create one.
         */
        sessp = SetNewSIPData(p, config);

        if ( !sessp )
        {
            /* Could not get/create the session data for this packet. */
            MODULE_PROFILE_END(sipPerfStats);
            return;
        }
    }

    /* Don't process if we've missed packets */
    if (sessp->state_flags & SIP_FLG_MISSED_PACKETS)
    {
        MODULE_PROFILE_END(sipPerfStats);
        return;
    }

    SIP_Process(p,sessp, config);

    MODULE_PROFILE_END(sipPerfStats);
}

//-------------------------------------------------------------------------
// class stuff
//-------------------------------------------------------------------------

class Sip : public Inspector
{
public:
    Sip(SIP_PROTO_CONF*);
    ~Sip();

    void show(SnortConfig*) override;
    void eval(Packet*) override;
    bool get_buf(InspectionBuffer::Type, Packet*, InspectionBuffer&) override;
    SIPMethodNode *add_method(char* tok);

private:
    SIP_PROTO_CONF* config;
};

Sip::Sip(SIP_PROTO_CONF* pc)
{
    config = pc;
}

Sip::~Sip()
{
    if ( config )
    {
        SIP_DeleteMethods(config->methods);
        delete config;
    }
}

void Sip::show(SnortConfig*)
{
    PrintSipConf(config);
}

SIPMethodNode *Sip::add_method(char* tok)
{
    SIPMethodNode *method;
    method = SIP_FindMethod (config->methods, tok, strlen (tok));

    /*if method is not found, add it as a user defined method*/
    if (method == NULL)
    {
        method = SIP_AddUserDefinedMethod(tok, &config->methodsConfig, &config->methods );
    }

    return method;
}

void Sip::eval(Packet* p)
{
    // precondition - what we registered for
    assert((p->is_udp() and p->dsize and p->data) or p->has_tcp_data());

    ++sipstats.total_packets;
    snort_sip(config, p);
}

bool Sip::get_buf(
    InspectionBuffer::Type ibt, Packet* p, InspectionBuffer& b)
{
    SIPData* sd;
    SIP_Roptions* ropts;
    const uint8_t* data = NULL;
    unsigned len = 0;

    sd = get_sip_session_data(p->flow);
    if (!sd)
        return false;

    ropts = &sd->ropts;

    switch ( ibt )
    {
    case InspectionBuffer::IBT_HEADER:
        data = ropts->header_data;
        len = ropts->header_len;
        break;

    case InspectionBuffer::IBT_BODY:
        data = ropts->body_data;
        len = ropts->body_len;
        break;

    default:
        break;
    }

    if (!len)
        return false;

    b.data = data;
    b.len = len;

    return true;
}

//-------------------------------------------------------------------------
// api stuff
//-------------------------------------------------------------------------

static Module* mod_ctor()
{ return new SipModule; }

static void mod_dtor(Module* m)
{ delete m; }

static void sip_init()
{
    SipFlowData::init();
}

static Inspector* sip_ctor(Module* m)
{
    SipModule* mod = (SipModule*)m;
    return new Sip(mod->get_data());
}

static void sip_dtor(Inspector* p)
{
    delete p;
}

SIPMethodNode *add_sip_method(char *tok)
{
    Sip *sip_ins = (Sip*)InspectorManager::get_inspector("sip");
    assert(sip_ins);

    return(sip_ins->add_method(tok));
}

const InspectApi sip_api =
{
    {
        PT_INSPECTOR,
        sizeof(InspectApi),
        INSAPI_VERSION,
        0,
        API_RESERVED,
        API_OPTIONS,
        SIP_NAME,
        SIP_HELP,
        mod_ctor,
        mod_dtor
    },
    IT_SERVICE,
    (uint16_t)PktType::PDU | (uint16_t)PktType::UDP,
    nullptr, // buffers
    "sip",
    sip_init,
    nullptr, // pterm
    nullptr, // tinit
    nullptr, // tterm
    sip_ctor,
    sip_dtor,
    nullptr, // ssn
    nullptr  // reset
};

#ifdef BUILDING_SO
extern const BaseApi* ips_sip_header;
extern const BaseApi* ips_sip_body;
extern const BaseApi* ips_sip_method;
extern const BaseApi* ips_sip_stat_code;

SO_PUBLIC const BaseApi* snort_plugins[] =
{
    &sip_api.base,
    ips_sip_header,
    ips_sip_body,
    ips_sip_method,
    ips_sip_stat_code,
    nullptr
};
#else
const BaseApi* sin_sip = &sip_api.base;
#endif

