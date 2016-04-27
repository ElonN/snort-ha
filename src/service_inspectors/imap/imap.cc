//--------------------------------------------------------------------------
// Copyright (C) 2015 Cisco and/or its affiliates. All rights reserved.
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

// imap.cc author Bhagyashree Bantwal <bbantwal@cisco.com>

#include "imap.h"

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <assert.h>
#include <string.h>
#include <stdio.h>
#include <sys/types.h>

#include "main/snort_types.h"
#include "main/snort_debug.h"
#include "time/profiler.h"
#include "stream/stream_api.h"
#include "file_api/file_api.h"
#include "parser/parser.h"
#include "framework/inspector.h"
#include "target_based/snort_protocols.h"
#include "search_engines/search_tool.h"
#include "utils/sfsnprintfappend.h"
#include "protocols/ssl.h"
#include "mime/file_mime_process.h"

#include "imap_paf.h"
#include "imap_module.h"

THREAD_LOCAL ProfileStats imapPerfStats;
THREAD_LOCAL SimpleStats imapstats;

IMAPToken imap_known_cmds[] =
{
    { "APPEND",          6, CMD_APPEND },
    { "AUTHENTICATE",    12, CMD_AUTHENTICATE },
    { "CAPABILITY",      10, CMD_CAPABILITY },
    { "CHECK",           5, CMD_CHECK },
    { "CLOSE",           5, CMD_CLOSE },
    { "COMPARATOR",      10, CMD_COMPARATOR },
    { "COMPRESS",        8, CMD_COMPRESS },
    { "CONVERSIONS",     11, CMD_CONVERSIONS },
    { "COPY",            4, CMD_COPY },
    { "CREATE",          6, CMD_CREATE },
    { "DELETE",          6, CMD_DELETE },
    { "DELETEACL",       9, CMD_DELETEACL },
    { "DONE",            4, CMD_DONE },
    { "EXAMINE",         7, CMD_EXAMINE },
    { "EXPUNGE",         7, CMD_EXPUNGE },
    { "FETCH",           5, CMD_FETCH },
    { "GETACL",          6, CMD_GETACL },
    { "GETMETADATA",     11, CMD_GETMETADATA },
    { "GETQUOTA",        8, CMD_GETQUOTA },
    { "GETQUOTAROOT",    12, CMD_GETQUOTAROOT },
    { "IDLE",            4, CMD_IDLE },
    { "LIST",            4, CMD_LIST },
    { "LISTRIGHTS",      10, CMD_LISTRIGHTS },
    { "LOGIN",           5, CMD_LOGIN },
    { "LOGOUT",          6, CMD_LOGOUT },
    { "LSUB",            4, CMD_LSUB },
    { "MYRIGHTS",        8, CMD_MYRIGHTS },
    { "NOOP",            4, CMD_NOOP },
    { "NOTIFY",          6, CMD_NOTIFY },
    { "RENAME",          6, CMD_RENAME },
    { "SEARCH",          6, CMD_SEARCH },
    { "SELECT",          6, CMD_SELECT },
    { "SETACL",          6, CMD_SETACL },
    { "SETMETADATA",     11, CMD_SETMETADATA },
    { "SETQUOTA",        8, CMD_SETQUOTA },
    { "SORT",            4, CMD_SORT },
    { "STARTTLS",        8, CMD_STARTTLS },
    { "STATUS",          6, CMD_STATUS },
    { "STORE",           5, CMD_STORE },
    { "SUBSCRIBE",       9, CMD_SUBSCRIBE },
    { "THREAD",          6, CMD_THREAD },
    { "UID",             3, CMD_UID },
    { "UNSELECT",        8, CMD_UNSELECT },
    { "UNSUBSCRIBE",     11, CMD_UNSUBSCRIBE },
    { "X",               1, CMD_X },
    { NULL,              0, 0 }
};

IMAPToken imap_resps[] =
{
    { "CAPABILITY",      10, RESP_CAPABILITY },
    { "LIST",            4, RESP_LIST },
    { "LSUB",            4, RESP_LSUB },
    { "STATUS",          6, RESP_STATUS },
    { "SEARCH",          6, RESP_SEARCH },
    { "FLAGS",           5, RESP_FLAGS },
    { "EXISTS",          6, RESP_EXISTS },
    { "RECENT",          6, RESP_RECENT },
    { "EXPUNGE",         7, RESP_EXPUNGE },
    { "FETCH",           5, RESP_FETCH },
    { "BAD",             3, RESP_BAD },
    { "BYE",             3, RESP_BYE },
    { "NO",              2, RESP_NO },
    { "OK",              2, RESP_OK },
    { "PREAUTH",         7, RESP_PREAUTH },
    { "ENVELOPE",        8, RESP_ENVELOPE },
    { "UID",             3, RESP_UID },
    { NULL,   0,  0 }
};

SearchTool* imap_resp_search_mpse = nullptr;
SearchTool* imap_cmd_search_mpse = nullptr;

IMAPSearch imap_resp_search[RESP_LAST];
IMAPSearch imap_cmd_search[CMD_LAST];
THREAD_LOCAL const IMAPSearch* imap_current_search = NULL;
THREAD_LOCAL IMAPSearchInfo imap_search_info;

ImapFlowData::ImapFlowData() : FlowData(flow_id)
{ memset(&session, 0, sizeof(session)); }

ImapFlowData::~ImapFlowData()
{
    if(session.mime_ssn)
        delete(session.mime_ssn);
}

unsigned ImapFlowData::flow_id = 0;
static IMAPData* get_session_data(Flow* flow)
{
    ImapFlowData* fd = (ImapFlowData*)flow->get_application_data(
        ImapFlowData::flow_id);

    return fd ? &fd->session : NULL;
}

IMAPData* SetNewIMAPData(IMAP_PROTO_CONF* config, Packet* p)
{
    IMAPData* imap_ssn;
    ImapFlowData* fd = new ImapFlowData;

    p->flow->set_application_data(fd);
    imap_ssn = &fd->session;

    imap_ssn->mime_ssn= new ImapMime(&(config->decode_conf),&(config->log_config));
    //imap_ssn->mime_ssn.methods = &(imap_mime_methods);
    //imap_ssn->mime_ssn.config = config;

    if (p->packet_flags & SSNFLAG_MIDSTREAM)
    {
        DebugMessage(DEBUG_IMAP, "Got midstream packet - "
            "setting state to unknown\n");
        imap_ssn->state = STATE_UNKNOWN;
    }

    imap_ssn->body_read = imap_ssn->body_len = 0;

    return imap_ssn;
}

void IMAP_SearchInit(void)
{
    const IMAPToken* tmp;
    imap_cmd_search_mpse = new SearchTool();
    if (imap_cmd_search_mpse == NULL)
    {
        FatalError("Could not allocate memory for IMAP Command search.\n");
    }
    for (tmp = &imap_known_cmds[0]; tmp->name != NULL; tmp++)
    {
        imap_cmd_search[tmp->search_id].name = tmp->name;
        imap_cmd_search[tmp->search_id].name_len = tmp->name_len;
        imap_cmd_search_mpse->add(tmp->name, tmp->name_len, tmp->search_id);
    }
    imap_cmd_search_mpse->prep();

    imap_resp_search_mpse = new SearchTool();
    if (imap_resp_search_mpse == NULL)
    {
        FatalError("Could not allocate memory for IMAP Response search.\n");
    }
    for (tmp = &imap_resps[0]; tmp->name != NULL; tmp++)
    {
        imap_resp_search[tmp->search_id].name = tmp->name;
        imap_resp_search[tmp->search_id].name_len = tmp->name_len;
        imap_resp_search_mpse->add(tmp->name, tmp->name_len, tmp->search_id);
    }
    imap_resp_search_mpse->prep();
}

void IMAP_SearchFree(void)
{
    if (imap_cmd_search_mpse != NULL)
        delete imap_cmd_search_mpse;

    if (imap_resp_search_mpse != NULL)
        delete imap_resp_search_mpse;
}

static void IMAP_ResetState(Flow* ssn)
{
    IMAPData* imap_ssn = get_session_data(ssn);
    imap_ssn->state = STATE_COMMAND;
    imap_ssn->state_flags = 0;
    imap_ssn->body_read = imap_ssn->body_len = 0;
}

void IMAP_GetEOL(const uint8_t* ptr, const uint8_t* end,
    const uint8_t** eol, const uint8_t** eolm)
{
    assert(ptr and end and eol and eolm);

    const uint8_t* tmp_eol;
    const uint8_t* tmp_eolm;

    tmp_eol = (uint8_t*)memchr(ptr, '\n', end - ptr);
    if (tmp_eol == NULL)
    {
        tmp_eol = end;
        tmp_eolm = end;
    }
    else
    {
        /* end of line marker (eolm) should point to marker and
         *          * end of line (eol) should point to end of marker */
        if ((tmp_eol > ptr) && (*(tmp_eol - 1) == '\r'))
        {
            tmp_eolm = tmp_eol - 1;
        }
        else
        {
            tmp_eolm = tmp_eol;
        }

        /* move past newline */
        tmp_eol++;
    }

    *eol = tmp_eol;
    *eolm = tmp_eolm;
}

static void PrintImapConf(IMAP_PROTO_CONF* config)
{
    if (config == NULL)
        return;

    LogMessage("IMAP config: \n");

    config->decode_conf.print_decode_conf();

    LogMessage("\n");

}

static inline int InspectPacket(Packet* p)
{
    return p->has_paf_payload();
}

static int IMAP_Setup(Packet* p, IMAPData* ssn)
{
    int pkt_dir;

    /* Get the direction of the packet. */
    if ( p->packet_flags & PKT_FROM_SERVER )
        pkt_dir = IMAP_PKT_FROM_SERVER;
    else
        pkt_dir = IMAP_PKT_FROM_CLIENT;

    if (!(ssn->session_flags & IMAP_FLAG_CHECK_SSL))
        ssn->session_flags |= IMAP_FLAG_CHECK_SSL;
    /* Check to see if there is a reassembly gap.  If so, we won't know
     *      * what state we're in when we get the _next_ reassembled packet */
    if ((pkt_dir != IMAP_PKT_FROM_SERVER) &&
        (p->packet_flags & PKT_REBUILT_STREAM))
    {
        int missing_in_rebuilt =
            stream.missing_in_reassembled(p->flow, SSN_DIR_FROM_CLIENT);

        if (ssn->session_flags & IMAP_FLAG_NEXT_STATE_UNKNOWN)
        {
            DebugMessage(DEBUG_IMAP, "Found gap in previous reassembly buffer - "
                "set state to unknown\n");
            ssn->state = STATE_UNKNOWN;
            ssn->session_flags &= ~IMAP_FLAG_NEXT_STATE_UNKNOWN;
        }

        if (missing_in_rebuilt == SSN_MISSING_BEFORE)
        {
            DebugMessage(DEBUG_IMAP, "Found missing packets before "
                "in reassembly buffer - set state to unknown\n");
            ssn->state = STATE_UNKNOWN;
        }
    }

    return pkt_dir;
}

static int IMAP_SearchStrFound(void* id, void* , int index, void* , void* )
{
    int search_id = (int)(uintptr_t)id;

    imap_search_info.id = search_id;
    imap_search_info.index = index;
    imap_search_info.length = imap_current_search[search_id].name_len;

    /* Returning non-zero stops search, which is okay since we only look for one at a time */
    return 1;
}

/*
 * Handle COMMAND state
 *
 * @param   p       standard Packet structure
 * @param   ptr     pointer into p->data buffer to start looking at data
 * @param   end     points to end of p->data buffer
 *
 * @return          pointer into p->data where we stopped looking at data
 *                  will be end of line or end of packet
 */
static const uint8_t* IMAP_HandleCommand(Packet* p, IMAPData* imap_ssn, const uint8_t* ptr, const
    uint8_t* end)
{
    const uint8_t* eol;   /* end of line */
    const uint8_t* eolm;  /* end of line marker */
    int cmd_found;

    /* get end of line and end of line marker */
    IMAP_GetEOL(ptr, end, &eol, &eolm);

    /* FIXIT If the end of line marker coincides with the end of data we can't be
     * sure that we got a command and not a substring which we could tell through
     * inspection of the next packet. Maybe a command pending state where the first
     * char in the next packet is checked for a space and end of line marker */

    /* do not confine since there could be space chars before command */
    imap_current_search = &imap_cmd_search[0];
    cmd_found = imap_cmd_search_mpse->find(
        (const char*)ptr, eolm - ptr, IMAP_SearchStrFound);

    /* if command not found, alert and move on */
    if (!cmd_found)
    {
        if (imap_ssn->state == STATE_UNKNOWN)
        {
            DebugMessage(DEBUG_IMAP, "Command not found, but state is "
                "unknown - checking for SSL\n");

            /* check for encrypted */

            if ((imap_ssn->session_flags & IMAP_FLAG_CHECK_SSL) &&
                (IsSSL(ptr, end - ptr, p->packet_flags)))
            {
                DebugMessage(DEBUG_IMAP, "Packet is SSL encrypted\n");

                imap_ssn->state = STATE_TLS_DATA;

                /* Ignore data */
                return end;
            }
            else
            {
                DebugMessage(DEBUG_IMAP, "Not SSL - try data state\n");
                /* don't check for ssl again in this packet */
                if (imap_ssn->session_flags & IMAP_FLAG_CHECK_SSL)
                    imap_ssn->session_flags &= ~IMAP_FLAG_CHECK_SSL;

                imap_ssn->state = STATE_DATA;
                //imap_ssn->data_state = STATE_DATA_UNKNOWN;

                return ptr;
            }
        }
        else
        {
            SnortEventqAdd(GID_IMAP, IMAP_UNKNOWN_CMD);
            DebugMessage(DEBUG_IMAP, "No known command found\n");
            return eol;
        }
    }
    else
    {
        if (imap_ssn->state == STATE_UNKNOWN)
            imap_ssn->state = STATE_COMMAND;
    }

    if (imap_search_info.id == CMD_STARTTLS)
    {
        if (eol == end)
            imap_ssn->state = STATE_TLS_CLIENT_PEND;
    }

    return eol;
}

/*
 * Process client packet
 *
 * @param   packet  standard Packet structure
 *
 * @return  none
 */
static void IMAP_ProcessClientPacket(Packet* p, IMAPData* imap_ssn)
{
    const uint8_t* ptr = p->data;
    const uint8_t* end = p->data + p->dsize;

    IMAP_HandleCommand(p, imap_ssn, ptr, end);
}

/*
 * Process server packet
 *
 * @param   packet  standard Packet structure
 *
 */
static void IMAP_ProcessServerPacket(Packet* p, IMAPData* imap_ssn)
{
    int resp_found;
    const uint8_t *ptr;
    const uint8_t *end;
    const uint8_t *data_end;
    const uint8_t *eolm;
    const uint8_t *eol;
    int resp_line_len;
    const char *tmp = NULL;
    uint8_t *body_start = NULL;
    char *eptr;

    ptr = p->data;
    end = p->data + p->dsize;

    while (ptr < end)
    {
        if (imap_ssn->state == STATE_DATA)
        {
            DebugMessage(DEBUG_IMAP, "DATA STATE ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~\n");
            if ( imap_ssn->body_len > imap_ssn->body_read)
            {
                int len = imap_ssn->body_len - imap_ssn->body_read;

                if ( (end - ptr) < len )
                {
                    data_end = end;
                    len = data_end - ptr;
                }
                else
                    data_end = ptr + len;

                FilePosition position = get_file_position(p);

                int data_len = end - ptr;
                ptr = imap_ssn->mime_ssn->process_mime_data(p->flow, ptr, data_len, 0,
                    position);
                if ( ptr < data_end)
                    len = len - (data_end - ptr);

                imap_ssn->body_read += len;

                continue;
            }
            else
            {
                imap_ssn->body_len = imap_ssn->body_read = 0;
                IMAP_ResetState(p->flow);
            }
        }
        IMAP_GetEOL(ptr, end, &eol, &eolm);

        resp_line_len = eol - ptr;

        /* Check for response code */
        imap_current_search = &imap_resp_search[0];
        resp_found = imap_resp_search_mpse->find(
            (const char*)ptr, resp_line_len, IMAP_SearchStrFound);

        if (resp_found > 0)
        {
            const uint8_t* cmd_start = ptr + imap_search_info.index;
            switch (imap_search_info.id)
            {
            case RESP_FETCH:
                imap_ssn->body_len = imap_ssn->body_read = 0;
                imap_ssn->state = STATE_DATA;
                tmp = SnortStrcasestr((const char*)cmd_start, (eol - cmd_start), "BODY");
                if (tmp != NULL)
                    imap_ssn->state = STATE_DATA;
                else
                {
                    tmp = SnortStrcasestr((const char*)cmd_start, (eol - cmd_start), "RFC822");
                    if (tmp != NULL)
                        imap_ssn->state = STATE_DATA;
                    else
                        imap_ssn->state = STATE_UNKNOWN;
                }
                break;
            default:
                break;
            }
            if (imap_ssn->state == STATE_DATA)
            {
                body_start = (uint8_t*)memchr((char*)ptr, '{', (eol - ptr));
                if ( body_start == NULL )
                {
                    imap_ssn->state = STATE_UNKNOWN;
                }
                else
                {
                    if ( (body_start + 1) < (uint8_t*)eol )
                    {
                        uint32_t len =
                            (uint32_t)SnortStrtoul((const char*)(body_start + 1), &eptr, 10);

                        if (*eptr != '}')
                        {
                            imap_ssn->state = STATE_UNKNOWN;
                        }
                        else
                            imap_ssn->body_len = len;
                    }
                    else
                        imap_ssn->state = STATE_UNKNOWN;
                }
            }
        }
        else
        {
            DebugMessage(DEBUG_IMAP,
                "Server response not found - see if it's SSL data\n");

            if ((imap_ssn->session_flags & IMAP_FLAG_CHECK_SSL) &&
                (IsSSL(ptr, end - ptr, p->packet_flags)))
            {
                DebugMessage(DEBUG_IMAP, "Server response is an SSL packet\n");

                imap_ssn->state = STATE_TLS_DATA;

                return;
            }
            else if (imap_ssn->session_flags & IMAP_FLAG_CHECK_SSL)
            {
                imap_ssn->session_flags &= ~IMAP_FLAG_CHECK_SSL;
            }
            if ( (*ptr != '*') && (*ptr !='+') && (*ptr != '\r') && (*ptr != '\n') )
            {
                SnortEventqAdd(GID_IMAP, IMAP_UNKNOWN_RESP);
                DebugMessage(DEBUG_IMAP, "Server response not found\n");
            }
        }

        ptr = eol;
    }
}

/* Main runtime entry point for IMAP preprocessor.
 * Analyzes IMAP packets for anomalies/exploits.
 *
 * PARAMETERS:
 *
 * p:    Pointer to current packet to process.
 * contextp:    Pointer to context block, not used.
 *
 * RETURNS:     Nothing.
 */
static void snort_imap(IMAP_PROTO_CONF* config, Packet* p)
{
    IMAPData* imap_ssn = NULL;
    int pkt_dir;

    /* Attempt to get a previously allocated IMAP block. */
    imap_ssn = get_session_data(p->flow);

    if (imap_ssn == NULL)
    {
        /* Check the stream session. If it does not currently
         * have our IMAP data-block attached, create one.
         */
        imap_ssn = SetNewIMAPData(config, p);

        if ( !imap_ssn )
        {
            /* Could not get/create the session data for this packet. */
            return;
        }
    }

    pkt_dir = IMAP_Setup(p, imap_ssn);

    if (pkt_dir == IMAP_PKT_FROM_CLIENT)
    {
        /* This packet should be a tls client hello */
        if (imap_ssn->state == STATE_TLS_CLIENT_PEND)
        {
            if (IsTlsClientHello(p->data, p->data + p->dsize))
            {
                DebugMessage(DEBUG_IMAP,
                    "TLS DATA STATE ~~~~~~~~~~~~~~~~~~~~~~~~~\n");

                imap_ssn->state = STATE_TLS_SERVER_PEND;
                return;
            }
            else
            {
                /* reset state - server may have rejected STARTTLS command */
                imap_ssn->state = STATE_UNKNOWN;
            }
        }
        if ((imap_ssn->state == STATE_TLS_DATA)
            || (imap_ssn->state == STATE_TLS_SERVER_PEND))
        {
            return;
        }
        IMAP_ProcessClientPacket(p, imap_ssn);
        DebugMessage(DEBUG_IMAP, "IMAP client packet\n");
    }
    else
    {
        if (imap_ssn->state == STATE_TLS_SERVER_PEND)
        {
            if (IsTlsServerHello(p->data, p->data + p->dsize))
            {
                imap_ssn->state = STATE_TLS_DATA;
            }
            else if (!(stream.get_session_flags(p->flow) & SSNFLAG_MIDSTREAM)
                && !stream.missed_packets(p->flow, SSN_DIR_BOTH))
            {
                /* revert back to command state - assume server didn't accept STARTTLS */
                imap_ssn->state = STATE_UNKNOWN;
            }
            else
                return;
        }

        if (imap_ssn->state == STATE_TLS_DATA)
        {
            return;
        }
        if ( !InspectPacket(p))
        {
            /* Packet will be rebuilt, so wait for it */
            DebugMessage(DEBUG_IMAP, "Client packet will be reassembled\n");
            return;
        }
        else if (!(p->packet_flags & PKT_REBUILT_STREAM))
        {
            /* If this isn't a reassembled packet and didn't get
             * inserted into reassembly buffer, there could be a
             * problem.  If we miss syn or syn-ack that had window
             * scaling this packet might not have gotten inserted
             * into reassembly buffer because it fell outside of
             * window, because we aren't scaling it */
            imap_ssn->session_flags |= IMAP_FLAG_GOT_NON_REBUILT;
            imap_ssn->state = STATE_UNKNOWN;
        }
        else if (imap_ssn->session_flags & IMAP_FLAG_GOT_NON_REBUILT)
        {
            /* This is a rebuilt packet.  If we got previous packets
             * that were not rebuilt, state is going to be messed up
             * so set state to unknown. It's likely this was the
             * beginning of the conversation so reset state */
            DebugMessage(DEBUG_IMAP, "Got non-rebuilt packets before "
                "this rebuilt packet\n");

            imap_ssn->state = STATE_UNKNOWN;
            imap_ssn->session_flags &= ~IMAP_FLAG_GOT_NON_REBUILT;
        }
        /* Process as a server packet */
        IMAP_ProcessServerPacket(p, imap_ssn);
    }
}

void ImapMime::decode_alert()
{
    switch ( decode_state->get_decode_type() )
    {
    case DECODE_B64:
        SnortEventqAdd(GID_IMAP, IMAP_B64_DECODING_FAILED);
        break;
    case DECODE_QP:
        SnortEventqAdd(GID_IMAP, IMAP_QP_DECODING_FAILED);
        break;
    case DECODE_UU:
        SnortEventqAdd(GID_IMAP, IMAP_UU_DECODING_FAILED);
        break;

    default:
        break;
    }
}

void ImapMime::reset_state(Flow* ssn)
{
    IMAP_ResetState(ssn);
}


bool ImapMime::is_end_of_data(Flow* session)
{
    return imap_is_data_end(session);
}

//-------------------------------------------------------------------------
// class stuff
//-------------------------------------------------------------------------

class Imap : public Inspector
{
public:
    Imap(IMAP_PROTO_CONF*);
    ~Imap();

    bool configure(SnortConfig*) override;
    void show(SnortConfig*) override;
    void eval(Packet*) override;

    StreamSplitter* get_splitter(bool c2s) override
    { return new ImapSplitter(c2s); }

private:
    IMAP_PROTO_CONF* config;
};

Imap::Imap(IMAP_PROTO_CONF* pc)
{
    config = pc;
}

Imap::~Imap()
{
    if ( config )
        delete config;
}

bool Imap::configure(SnortConfig*)
{
    config->decode_conf.sync_all_depths();

    if (config->decode_conf.get_file_depth() > -1)
        config->log_config.log_filename = 1;

    return true;
}

void Imap::show(SnortConfig*)
{
    PrintImapConf(config);
}

void Imap::eval(Packet* p)
{
    PROFILE_VARS;
    // precondition - what we registered for
    assert(p->has_tcp_data());

    ++imapstats.total_packets;

    MODULE_PROFILE_START(imapPerfStats);

    snort_imap(config, p);

    MODULE_PROFILE_END(imapPerfStats);
}

//-------------------------------------------------------------------------
// api stuff
//-------------------------------------------------------------------------

static Module* mod_ctor()
{ return new ImapModule; }

static void mod_dtor(Module* m)
{ delete m; }

static void imap_init()
{
    ImapFlowData::init();
    IMAP_SearchInit();
}

static void imap_term()
{
    IMAP_SearchFree();
}

static Inspector* imap_ctor(Module* m)
{
    ImapModule* mod = (ImapModule*)m;
    return new Imap(mod->get_data());
}

static void imap_dtor(Inspector* p)
{
    delete p;
}

const InspectApi imap_api =
{
    {
        PT_INSPECTOR,
        sizeof(InspectApi),
        INSAPI_VERSION,
        0,
        API_RESERVED,
        API_OPTIONS,
        IMAP_NAME,
        IMAP_HELP,
        mod_ctor,
        mod_dtor
    },
    IT_SERVICE,
    (uint16_t)PktType::PDU,
    nullptr, // buffers
    "imap",
    imap_init,
    imap_term, // pterm
    nullptr, // tinit
    nullptr, // tterm
    imap_ctor,
    imap_dtor,
    nullptr, // ssn
    nullptr  // reset
};

#ifdef BUILDING_SO
SO_PUBLIC const BaseApi* snort_plugins[] =
{
    &imap_api.base,
    nullptr
};
#else
const BaseApi* sin_imap = &imap_api.base;
#endif

