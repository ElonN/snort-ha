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

// sip_module.h author Bhagyashree Bantwal <bbantwal@cisco.com>

#ifndef SIP_MODULE_H
#define SIP_MODULE_H

// Interface to the SIP service inspector

#include "framework/module.h"
#include "framework/bits.h"
#include "main/thread.h"
#include "sip_config.h"

#define GID_SIP 140

#define SIP_EVENT_MAX_SESSIONS        1
#define SIP_EVENT_EMPTY_REQUEST_URI   2
#define SIP_EVENT_BAD_URI             3
#define SIP_EVENT_EMPTY_CALL_ID       4
#define SIP_EVENT_BAD_CALL_ID         5
#define SIP_EVENT_BAD_CSEQ_NUM        6
#define SIP_EVENT_BAD_CSEQ_NAME       7
#define SIP_EVENT_EMPTY_FROM          8
#define SIP_EVENT_BAD_FROM            9
#define SIP_EVENT_EMPTY_TO            10
#define SIP_EVENT_BAD_TO              11
#define SIP_EVENT_EMPTY_VIA           12
#define SIP_EVENT_BAD_VIA             13
#define SIP_EVENT_EMPTY_CONTACT       14
#define SIP_EVENT_BAD_CONTACT         15
#define SIP_EVENT_BAD_CONTENT_LEN     16
#define SIP_EVENT_MULTI_MSGS          17
#define SIP_EVENT_MISMATCH_CONTENT_LEN          18
#define SIP_EVENT_INVALID_CSEQ_NAME             19
#define SIP_EVENT_AUTH_INVITE_REPLAY_ATTACK     20
#define SIP_EVENT_AUTH_INVITE_DIFF_SESSION      21
#define SIP_EVENT_BAD_STATUS_CODE               22
#define SIP_EVENT_EMPTY_CONTENT_TYPE            23
#define SIP_EVENT_INVALID_VERSION               24
#define SIP_EVENT_MISMATCH_METHOD               25
#define SIP_EVENT_UNKOWN_METHOD                 26
#define SIP_EVENT_MAX_DIALOGS_IN_A_SESSION      27

#define SIP_NAME "sip"
#define SIP_HELP "sip inspection"

struct SnortConfig;

extern THREAD_LOCAL SimpleStats sipstats;
extern THREAD_LOCAL ProfileStats sipPerfStats;

class SipModule : public Module
{
public:
    SipModule();
    ~SipModule();

    bool set(const char*, Value&, SnortConfig*) override;
    bool begin(const char*, int, SnortConfig*) override;
    bool end(const char*, int, SnortConfig*) override;

    unsigned get_gid() const override
    { return GID_SIP; }

    const RuleMap* get_rules() const override;
    const PegInfo* get_pegs() const override;
    PegCount* get_counts() const override;
    ProfileStats* get_profile() const override;

    SIP_PROTO_CONF* get_data();

private:
    SIP_PROTO_CONF* conf;
    std::string sip_methods;
};

#endif

