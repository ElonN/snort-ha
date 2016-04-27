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
// ips_manager.h author Russ Combs <rucombs@cisco.com>

#ifndef IPS_OPTION_H
#define IPS_OPTION_H

// All IPS rule keywords are realized as IpsOptions instantiated when rules
// are parsed.

#include "main/snort_types.h"
#include "framework/base_api.h"
#include "detection/rule_option_types.h"

struct Packet;

// this is the current version of the api
#define IPSAPI_VERSION ((BASE_API_VERSION << 16) | 0)

//-------------------------------------------------------------------------
// api for class
// eval and action are packet thread specific
//-------------------------------------------------------------------------

struct SnortConfig;

enum CursorActionType
{
    CAT_NONE,
    CAT_ADJUST,
    CAT_SET_OTHER,
    CAT_SET_RAW,
    CAT_SET_FILE,
    CAT_SET_BODY,
    CAT_SET_HEADER,
    CAT_SET_KEY,
};

class SO_PUBLIC IpsOption
{
public:
    virtual ~IpsOption() { }

    // main thread
    virtual uint32_t hash() const;
    virtual bool operator==(const IpsOption& ips) const;

    bool operator!=(const IpsOption& ips) const
    { return !(*this == ips); }

    // packet threads
    virtual bool is_relative() { return false; }
    virtual bool fp_research() { return false; }
    virtual int eval(class Cursor&, Packet*) { return true; }
    virtual void action(Packet*) { }

    option_type_t get_type() const { return type; }
    const char* get_name() const { return name; }

    virtual CursorActionType get_cursor_type() const
    { return CAT_NONE; }

    static int eval(void* v, Cursor& c, Packet* p)
    {
        IpsOption* opt = (IpsOption*)v;
        return opt->eval(c, p);
    }

    static CursorActionType get_cat(void* v)
    {
        IpsOption* opt = (IpsOption*)v;
        return opt->get_cursor_type();
    }

    static bool get_fp_only(void* v)
    {
        IpsOption* opt = (IpsOption*)v;
        return !opt->fp_research();
    }

protected:
    IpsOption(const char* s, option_type_t t = RULE_OPTION_TYPE_OTHER)
    { name = s; type = t; }

private:
    const char* name;
    option_type_t type;
};

enum RuleOptType
{
    OPT_TYPE_LOGGING,
    OPT_TYPE_DETECTION,
    OPT_TYPE_META,
    OPT_TYPE_MAX
};

typedef void (* IpsOptFunc)(SnortConfig*);

typedef IpsOption* (* IpsNewFunc)(class Module*, struct OptTreeNode*);
typedef void (* IpsDelFunc)(IpsOption*);

struct IpsApi
{
    BaseApi base;
    RuleOptType type;

    unsigned max_per_rule;
    unsigned protos;

    IpsOptFunc pinit;
    IpsOptFunc pterm;
    IpsOptFunc tinit;
    IpsOptFunc tterm;
    IpsNewFunc ctor;
    IpsDelFunc dtor;
    IpsOptFunc verify;
};

#endif

