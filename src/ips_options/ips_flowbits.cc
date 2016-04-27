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

/*
 ** Major rewrite: Hui Cao <hcao@sourcefire.com>
 **
 ** Add flowbits OR support
 **
 ** sp_flowbits
 **
 ** Purpose:
 **
 ** Wouldn't it be nice if we could do some simple state tracking
 ** across multiple packets?  Well, this allows you to do just that.
 **
 ** Effect:
 **
 ** - [Un]set a bitmask stored with the session
 ** - Check the value of the bitmask
 */

#include "ips_flowbits.h"

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <sys/types.h>

#include <string>
#include <forward_list>
using namespace std;

#include "main/snort_types.h"
#include "main/snort_debug.h"
#include "detection/treenodes.h"
#include "protocols/packet.h"
#include "parser/parser.h"
#include "utils/util.h"
#include "utils/stats.h"
#include "utils/sflsq.h"
#include "utils/bitop.h"
#include "hash/sfghash.h"
#include "parser/mstring.h"
#include "stream/stream_api.h"
#include "time/profiler.h"
#include "hash/sfhashfcn.h"
#include "detection/detection_defines.h"
#include "framework/ips_option.h"
#include "framework/parameter.h"
#include "framework/module.h"

#define s_name "flowbits"

static THREAD_LOCAL ProfileStats flowBitsPerfStats;

#define DEFAULT_FLOWBIT_GROUP  "default"
#define ALLOWED_SPECIAL_CHARS       ".-_"

#define DEFAULT_FLOWBIT_SIZE  1024
#define MAX_FLOWBIT_SIZE      2048

#define FLOWBITS_SET       0x01
#define FLOWBITS_UNSET     0x02
#define FLOWBITS_TOGGLE    0x04
#define FLOWBITS_ISSET     0x08
#define FLOWBITS_ISNOTSET  0x10
#define FLOWBITS_RESET     0x20
#define FLOWBITS_NOALERT   0x40
#define FLOWBITS_SETX      0x80

/**
**  The FLOWBITS_OBJECT is used to track the different
**  flowbit names that set/unset/etc. bits.  We use these
**  so that we can verify that the rules that use flowbits
**  make sense.
**
**  The types element tracks all the different operations that
**  may occur for a given object.  This is different from how
**  the type element is used from the FLOWBITS_OP structure.
*/
struct FLOWBITS_OBJECT
{
    uint16_t id;
    uint8_t types;
    int toggle;
    int set;
    int isset;
};

typedef enum
{
    FLOWBITS_AND,
    FLOWBITS_OR,
    FLOWBITS_ANY,
    FLOWBITS_ALL
}Flowbits_eval;

/**
**  This structure is the context ptr for each detection option
**  on a rule.  The id is associated with a FLOWBITS_OBJECT id.
**
**  The type element track only one operation.
*/
struct FLOWBITS_OP
{
    uint16_t* ids;
    uint8_t num_ids;
    uint8_t type;         /* Set, Unset, Invert, IsSet, IsNotSet, Reset  */
    Flowbits_eval eval;   /* and , or, all, any*/
    char* name;
    char* group;
    uint32_t group_id;
};

typedef struct _FLOWBITS_GRP
{
    uint16_t count;
    uint16_t max_id;
    char* name;
    uint32_t group_id;
    BitOp* GrpBitOp;
} FLOWBITS_GRP;

static SFGHASH* flowbits_grp_hash = NULL;

static std::forward_list<const FLOWBITS_OP*> op_list;

static int check_flowbits(
    uint8_t type, uint8_t evalType, uint16_t* ids, uint16_t num_ids,
    char* group, Packet* p);

class FlowBitsOption : public IpsOption
{
public:
    FlowBitsOption(FLOWBITS_OP* c) :
        IpsOption(s_name, RULE_OPTION_TYPE_FLOWBIT)
    { config = c; }

    ~FlowBitsOption();

    uint32_t hash() const override;
    bool operator==(const IpsOption&) const override;

    int eval(Cursor&, Packet*) override;

    bool is_set(uint8_t bits)
    { return (config->type & bits) != 0; }

private:
    FLOWBITS_OP* config;
};

//-------------------------------------------------------------------------
// class methods
//-------------------------------------------------------------------------

FlowBitsOption::~FlowBitsOption()
{
    if (config->ids)
        free(config->ids);
    if (config->name)
        free(config->name);
    if (config->group)
        free(config->group);

    free(config);
}

uint32_t FlowBitsOption::hash() const
{
    uint32_t a,b,c;
    const FLOWBITS_OP* data = config;
    int i;
    int j = 0;

    a = data->eval;
    b = data->type;
    c = 0;

    mix(a,b,c);
    mix_str(a,b,c,get_name());

    for (i = 0, j = 0; i < data->num_ids; i++, j++)
    {
        if (j >= 3)
        {
            a += data->ids[i - 2];
            b += data->ids[i - 1];
            c += data->ids[i];
            mix(a,b,c);
            j -= 3;
        }
    }
    if (1 == j)
    {
        a += data->ids[data->num_ids - 1];
        b += data->num_ids;
    }
    else if (2 == j)
    {
        a += data->ids[data->num_ids - 2];
        b += data->ids[data->num_ids - 1]|data->num_ids << 16;
    }

    c += data->group_id;

    final(a,b,c);

    return c;
}

bool FlowBitsOption::operator==(const IpsOption& ips) const
{
    if ( strcmp(get_name(), ips.get_name()) )
        return false;

    FlowBitsOption& rhs = (FlowBitsOption&)ips;
    FLOWBITS_OP* left = (FLOWBITS_OP*)&config;
    FLOWBITS_OP* right = (FLOWBITS_OP*)&rhs.config;
    int i;

    if ((left->num_ids != right->num_ids)||
        (left->eval != right->eval)||
        (left->type != right->type)||
        (left->group_id != right->group_id))
        return false;

    for (i = 0; i < left->num_ids; i++)
    {
        if (left->ids[i] != right->ids[i])
            return false;
    }

    return true;
}

int FlowBitsOption::eval(Cursor&, Packet* p)
{
    FLOWBITS_OP* flowbits = config;
    int rval = DETECTION_OPTION_NO_MATCH;

    PROFILE_VARS;

    if (!flowbits)
        return rval;

    MODULE_PROFILE_START(flowBitsPerfStats);

    rval = check_flowbits(flowbits->type, (uint8_t)flowbits->eval,
        flowbits->ids, flowbits->num_ids, flowbits->group, p);

    MODULE_PROFILE_END(flowBitsPerfStats);
    return rval;
}

//-------------------------------------------------------------------------
// helper methods
//-------------------------------------------------------------------------

static inline int clear_group_bit(BitOp* bitop, char* group)
{
    FLOWBITS_GRP* flowbits_grp;
    BitOp* GrpBitOp;
    unsigned int i, max_bytes;

    if ( group == NULL )
        return 0;

    // FIXIT-M why is the hash lookup done at runtime for flowbits groups?
    // a pointer to flowbis_grp should be in flowbits config data
    // this *should* be safe but iff splay mode is disabled
    flowbits_grp = (FLOWBITS_GRP*)sfghash_find(flowbits_grp_hash, group);
    if ( flowbits_grp == NULL )
        return 0;
    if ((bitop == NULL) || (bitop->get_max_bits() <= flowbits_grp->max_id) || flowbits_grp->count == 0)
        return 0;
    GrpBitOp = flowbits_grp->GrpBitOp;

    /* note, max_id is an index, not a count.
     * Calculate max_bytes by adding 8 to max_id, then dividing by 8.  */
    max_bytes = (flowbits_grp->max_id + 8) >> 3;
    for ( i = 0; i < max_bytes; i++ )
    {
        (*bitop)[i] &= ~((*GrpBitOp)[i]);
    }
    return 1;
}

static inline int toggle_group_bit(BitOp* bitop, char* group)
{
    FLOWBITS_GRP* flowbits_grp;
    BitOp* GrpBitOp;
    unsigned int i, max_bytes;

    if ( group == NULL )
        return 0;
    flowbits_grp = (FLOWBITS_GRP*)sfghash_find(flowbits_grp_hash, group);
    if ( flowbits_grp == NULL )
        return 0;
    if ((bitop == NULL) || (bitop->get_max_bits() <= flowbits_grp->max_id) || flowbits_grp->count == 0)
        return 0;
    GrpBitOp = flowbits_grp->GrpBitOp;

    /* note, max_id is an index, not a count.
     * Calculate max_bytes by adding 8 to max_id, then dividing by 8.  */
    max_bytes = (flowbits_grp->max_id + 8) >> 3;
    for ( i = 0; i < max_bytes; i++ )
    {
        (*bitop)[i] ^= (*GrpBitOp)[i];
    }
    return 1;
}

static inline int set_xbits_to_group(
    BitOp* bitop, uint16_t* ids, uint16_t num_ids, char* group)
{
    unsigned int i;
    if (!clear_group_bit(bitop, group))
        return 0;
    for (i = 0; i < num_ids; i++)
        bitop->set(ids[i]);
    return 1;
}

static inline int is_set_flowbits(
    BitOp* bitop, uint8_t eval, uint16_t* ids,
    uint16_t num_ids, char* group)
{
    unsigned int i;
    FLOWBITS_GRP* flowbits_grp;
    Flowbits_eval evalType = (Flowbits_eval)eval;

    switch (evalType)
    {
    case FLOWBITS_AND:
        for (i = 0; i < num_ids; i++)
        {
            if (!bitop->is_set(ids[i]))
                return 0;
        }
        return 1;
        break;
    case FLOWBITS_OR:
        for (i = 0; i < num_ids; i++)
        {
            if (bitop->is_set(ids[i]))
                return 1;
        }
        return 0;
        break;
    case FLOWBITS_ALL:
        flowbits_grp = (FLOWBITS_GRP*)sfghash_find(flowbits_grp_hash, group);
        if ( flowbits_grp == NULL )
            return 0;
        for ( i = 0; i <= (unsigned int)(flowbits_grp->max_id >>3); i++ )
        {
            uint8_t val = (*bitop)[i] &
                (*(flowbits_grp->GrpBitOp))[i];
            if (val != (*(flowbits_grp->GrpBitOp))[i])
                return 0;
        }
        return 1;
        break;
    case FLOWBITS_ANY:
        flowbits_grp = (FLOWBITS_GRP*)sfghash_find(flowbits_grp_hash, group);
        if ( flowbits_grp == NULL )
            return 0;
        for ( i = 0; i <= (unsigned int)(flowbits_grp->max_id >>3); i++ )
        {
            uint8_t val = (*bitop)[i] &
                (*(flowbits_grp->GrpBitOp))[i];
            if (val)
                return 1;
        }
        return 0;
        break;
    default:
        return 0;
    }
}

static int check_flowbits(
    uint8_t type, uint8_t evalType, uint16_t* ids, uint16_t num_ids, char* group, Packet* p)
{
    int rval = DETECTION_OPTION_NO_MATCH;
    BitOp* bitop;
    Flowbits_eval eval = (Flowbits_eval)evalType;
    int result = 0;
    int i;

    bitop = stream.get_flow_bitop(p);
    if (!bitop)
    {
        DebugMessage(DEBUG_FLOWBITS, "No FLOWBITS_DATA");
        return rval;
    }

    switch (type)
    {
    case FLOWBITS_SET:
        for (i = 0; i < num_ids; i++)
            bitop->set(ids[i]);
        result = 1;
        break;

    case FLOWBITS_SETX:
        result = set_xbits_to_group(bitop, ids, num_ids, group);
        break;

    case FLOWBITS_UNSET:
        if (eval == FLOWBITS_ALL )
            clear_group_bit(bitop, group);
        else
        {
            for (i = 0; i < num_ids; i++)
                bitop->clear(ids[i]);
        }
        result = 1;
        break;

    case FLOWBITS_RESET:
        if (!group)
            bitop->reset();
        else
            clear_group_bit(bitop, group);
        result = 1;
        break;

    case FLOWBITS_ISSET:

        if (is_set_flowbits(bitop,(uint8_t)eval, ids, num_ids, group))
        {
            result = 1;
        }
        else
        {
            rval = DETECTION_OPTION_FAILED_BIT;
        }

        break;

    case FLOWBITS_ISNOTSET:
        if (!is_set_flowbits(bitop, (uint8_t)eval, ids, num_ids, group))
        {
            result = 1;
        }
        else
        {
            rval = DETECTION_OPTION_FAILED_BIT;
        }
        break;

    case FLOWBITS_TOGGLE:
        if (group)
            toggle_group_bit(bitop, group);
        else
        {
            for (i = 0; i < num_ids; i++)
            {
                if (bitop->is_set(ids[i]))
                {
                    bitop->clear(ids[i]);
                }
                else
                {
                    bitop->set(ids[i]);
                }
            }
        }
        result = 1;

        break;

    case FLOWBITS_NOALERT:
        /*
         **  This logic allows us to put flowbits: noalert any where
         **  in the detection chain, and still do bit ops after this
         **  option.
         */
        return DETECTION_OPTION_NO_ALERT;

    default:
        /*
         **  Always return failure here.
         */
        return rval;
    }

    /*
     **  Now return what we found
     */
    if (result == 1)
    {
        rval = DETECTION_OPTION_MATCH;
    }

    return rval;
}

//-------------------------------------------------------------------------
// public methods
//-------------------------------------------------------------------------

static SFGHASH* flowbits_hash = NULL;
static SF_QUEUE* flowbits_bit_queue = NULL;
static uint16_t flowbits_count = 0;
static uint16_t flowbits_grp_count = 0;
static int flowbits_toggle = 1;

// FIXIT-L consider allocating flowbits on session on demand instead of
// preallocating.

unsigned int getFlowbitSize()
{
    return flowbits_count;
}

unsigned int getFlowbitSizeInBytes()
{
    return flowbits_count ? (flowbits_count + 7) >> 3 : 1;
}

void FlowbitResetCounts(void)
{
    SFGHASH_NODE* n;
    FLOWBITS_OBJECT* fb;

    if (flowbits_hash == NULL)
        return;

    for (n = sfghash_findfirst(flowbits_hash);
        n != NULL;
        n = sfghash_findnext(flowbits_hash))
    {
        fb = (FLOWBITS_OBJECT*)n->data;
        fb->set = 0;
        fb->isset = 0;
    }
}

int FlowBits_SetOperation(void* option_data)
{
    FlowBitsOption* p = (FlowBitsOption*)option_data;

    if (p->is_set(FLOWBITS_SET | FLOWBITS_SETX |FLOWBITS_UNSET | FLOWBITS_TOGGLE |
        FLOWBITS_RESET))
    {
        return 1;
    }
    return 0;
}

//-------------------------------------------------------------------------
// parsing methods
//-------------------------------------------------------------------------

static bool validateName(char* name)
{
    unsigned i;

    if (!name)
        return false;

    for (i=0; i<strlen(name); i++)
    {
        if (!isalnum(name[i])&&(NULL == strchr(ALLOWED_SPECIAL_CHARS,name[i])))
            return false;
    }
    return true;
}

static FLOWBITS_OBJECT* getFlowBitItem(char* flowbitName, FLOWBITS_OP* flowbits)
{
    FLOWBITS_OBJECT* flowbits_item;
    int hstatus;

    if (!validateName(flowbitName))
    {
        ParseAbort("Flowbits: flowbits name is limited to any alphanumeric string including %s"
            , ALLOWED_SPECIAL_CHARS);
    }

    flowbits_item = (FLOWBITS_OBJECT*)sfghash_find(flowbits_hash, flowbitName);

    if (flowbits_item == NULL)
    {
        flowbits_item = (FLOWBITS_OBJECT*)SnortAlloc(sizeof(FLOWBITS_OBJECT));

        if (sfqueue_count(flowbits_bit_queue) > 0)
        {
            flowbits_item->id = (uint16_t)(uintptr_t)sfqueue_remove(flowbits_bit_queue);
        }
        else
        {
            flowbits_item->id = flowbits_count++;

            if ( !flowbits_count )
            {
                ParseError("The number of flowbit IDs in the current ruleset exceeds "
                    "the maximum number of IDs that are allowed (65535).");
            }
        }

        hstatus = sfghash_add(flowbits_hash, flowbitName, flowbits_item);

        if (hstatus != SFGHASH_OK)
            ParseError("Could not add flowbits key (%s) to hash.",flowbitName);
    }
    flowbits_item->toggle = flowbits_toggle;
    flowbits_item->types |= flowbits->type;

    switch (flowbits->type)
    {
    case FLOWBITS_SET:
    case FLOWBITS_SETX:
    case FLOWBITS_UNSET:
    case FLOWBITS_TOGGLE:
    case FLOWBITS_RESET:
        flowbits_item->set++;
        break;
    case FLOWBITS_ISSET:
    case FLOWBITS_ISNOTSET:
        flowbits_item->isset++;
        break;
    default:
        break;
    }

    return flowbits_item;
}

static void processFlowbits(
    char* flowbits_names, FLOWBITS_OP* flowbits)
{
    char** toks;
    int num_toks;
    int i;
    char* flowbits_name;

    FLOWBITS_OBJECT* flowbits_item;

    if (!flowbits_names || ((*flowbits_names) == 0))
    {
        return;
    }

    DebugFormat(DEBUG_FLOWBITS, "flowbits tag id parsing %s\n",flowbits_names);

    flowbits_name = SnortStrdup(flowbits_names);

    if (NULL != strchr(flowbits_name, '|'))
    {
        if (NULL != strchr(flowbits_name, '&'))
        {
            ParseError("flowbits: flowbits tag id opcode '|' and '&' are used together.");
            return;
        }
        toks = mSplit(flowbits_name, "|", 0, &num_toks, 0);
        flowbits->ids = (uint16_t*)SnortAlloc(num_toks*sizeof(*(flowbits->ids)));
        flowbits->num_ids = num_toks;
        for (i = 0; i < num_toks; i++)
        {
            flowbits_item = getFlowBitItem(toks[i], flowbits);
            flowbits->ids[i] = flowbits_item->id;
        }
        flowbits->eval = FLOWBITS_OR;
        mSplitFree(&toks, num_toks);
    }
    else if (NULL != strchr(flowbits_name, '&'))
    {
        toks = mSplit(flowbits_name, "&", 0, &num_toks, 0);
        flowbits->ids = (uint16_t*)SnortAlloc(num_toks*sizeof(*(flowbits->ids)));
        flowbits->num_ids = num_toks;
        for (i = 0; i < num_toks; i++)
        {
            flowbits_item = getFlowBitItem(toks[i], flowbits);
            flowbits->ids[i] = flowbits_item->id;
        }
        flowbits->eval = FLOWBITS_AND;
        mSplitFree(&toks, num_toks);
    }
    else if (!strcasecmp(flowbits_name,"all"))
    {
        flowbits->eval = FLOWBITS_ALL;
    }
    else if (!strcasecmp(flowbits_name,"any"))
    {
        flowbits->eval = FLOWBITS_ANY;
    }
    else
    {
        flowbits_item = getFlowBitItem(flowbits_name, flowbits);
        flowbits->ids = (uint16_t*)SnortAlloc(sizeof(*(flowbits->ids)));
        flowbits->num_ids = 1;
        flowbits->ids[0] = flowbits_item->id;
    }

    free(flowbits_name);
}

void validateFlowbitsSyntax(FLOWBITS_OP* flowbits)
{
    switch (flowbits->type)
    {
    case FLOWBITS_SET:
        if ((flowbits->eval == FLOWBITS_AND) && (flowbits->ids))
            break;

        ParseError("flowbits: operation set uses syntax: flowbits:set,bit[&bit],[group].");
        return;

    case FLOWBITS_SETX:
        if ((flowbits->eval == FLOWBITS_AND)&&(flowbits->group) && (flowbits->ids) )
            break;

        ParseError("flowbits: operation setx uses syntax: flowbits:setx,bit[&bit],group.");
        return;

    case FLOWBITS_UNSET:
        if (((flowbits->eval == FLOWBITS_AND) && (!flowbits->group) && (flowbits->ids))
            ||((flowbits->eval == FLOWBITS_ALL) && (flowbits->group)))
            break;

        ParseError("flowbits: operation unset uses syntax: flowbits:unset,bit[&bit] OR"
            " flowbits:unset, all, group.");
        return;

    case FLOWBITS_TOGGLE:
        if (((flowbits->eval == FLOWBITS_AND) && (!flowbits->group) &&(flowbits->ids))
            ||((flowbits->eval == FLOWBITS_ALL) && (flowbits->group)))
            break;

        ParseError("flowbits: operation toggle uses syntax: flowbits:toggle,bit[&bit] OR"
            " flowbits:toggle,all,group.");
        return;

    case FLOWBITS_ISSET:
        if ((((flowbits->eval == FLOWBITS_AND) || (flowbits->eval == FLOWBITS_OR)) &&
            (!flowbits->group) && flowbits->ids)
            ||((((flowbits->eval == FLOWBITS_ANY))||(flowbits->eval == FLOWBITS_ALL)) &&
            (flowbits->group)))
            break;

        ParseError("flowbits: operation isset uses syntax: flowbits:isset,bit[&bit] OR "
            "flowbits:isset,bit[|bit] OR flowbits:isset,all,group OR flowbits:isset,any,group.");
        return;

    case FLOWBITS_ISNOTSET:
        if ((((flowbits->eval == FLOWBITS_AND) || (flowbits->eval == FLOWBITS_OR)) &&
            (!flowbits->group) && flowbits->ids)
            ||((((flowbits->eval == FLOWBITS_ANY))||(flowbits->eval == FLOWBITS_ALL)) &&
            (flowbits->group)))
            break;

        ParseError("flowbits: operation isnotset uses syntax: flowbits:isnotset,bit[&bit] OR "
            "flowbits:isnotset,bit[|bit] OR flowbits:isnotset,all,group OR flowbits:isnotset,any,group.");
        return;

    case FLOWBITS_RESET:
        if (flowbits->ids == NULL)
            break;
        ParseError(
            "flowbits: operation unset uses syntax: flowbits:reset OR flowbits:reset, group.");
        return;

    case FLOWBITS_NOALERT:
        if ((flowbits->ids == NULL) && (flowbits->group == NULL))
            break;
        ParseError("flowbits: operation noalert uses syntax: flowbits:noalert.");
        return;

    default:
        ParseError("flowbits: unknown opcode.");
        return;
    }
}

static FLOWBITS_GRP* getFlowBitGroup(char* groupName)
{
    int hstatus;
    FLOWBITS_GRP* flowbits_grp = NULL;

    if (!groupName)
        return NULL;

    if (!validateName(groupName))
    {
        ParseAbort(
            "flowbits: flowbits group name is limited to any alphanumeric string including %s",
            ALLOWED_SPECIAL_CHARS);
    }

    flowbits_grp = (FLOWBITS_GRP*)sfghash_find(flowbits_grp_hash, groupName);

    if ( !flowbits_grp )
    {
        // new group defined, add (bitop set later once we know size)
        flowbits_grp = (FLOWBITS_GRP*)SnortAlloc(sizeof(*flowbits_grp));
        hstatus = sfghash_add(flowbits_grp_hash, groupName, flowbits_grp);

        if (hstatus != SFGHASH_OK)
            ParseAbort("Could not add flowbits group (%s) to hash.\n",groupName);

        flowbits_grp_count++;
        flowbits_grp->group_id = flowbits_grp_count;
        flowbits_grp->name = SnortStrdup(groupName);
    }

    return flowbits_grp;
}

#ifdef DEBUG_MSGS
static void printOutFlowbits(FLOWBITS_OP* flowbits)
{
    int i;

    DebugFormat(DEBUG_FLOWBITS,"flowbits: type = %d\n",flowbits->type);
    DebugFormat(DEBUG_FLOWBITS,"flowbits: name = %s\n",flowbits->name);
    DebugFormat(DEBUG_FLOWBITS,"flowbits: eval = %d\n",flowbits->eval);
    DebugFormat(DEBUG_FLOWBITS,"flowbits: num_ids = %d\n",flowbits->num_ids);
    DebugFormat(DEBUG_FLOWBITS,"flowbits: grp_id = %d\n",flowbits->group_id);
    DebugFormat(DEBUG_FLOWBITS,"flowbits: group_name = %s\n",flowbits->group);
    for (i = 0; i < flowbits->num_ids; i++)
    {
        DebugFormat(DEBUG_FLOWBITS,"flowbits: value = %d\n",flowbits->ids[i]);
    }
}

#endif

static void processFlowBitsWithGroup(char* flowbitsName, char* groupName, FLOWBITS_OP* flowbits)
{
    FLOWBITS_GRP* flowbits_grp;

    flowbits_grp = getFlowBitGroup(groupName);
    processFlowbits(flowbitsName, flowbits);

    if (groupName && !(flowbits->group))
    {
        flowbits->group = SnortStrdup(groupName);
        flowbits->group_id = flowbits_grp->group_id;
    }
    validateFlowbitsSyntax(flowbits);
    DEBUG_WRAP(printOutFlowbits(flowbits));

    if ( flowbits->group )
        op_list.push_front(flowbits);
}

static FLOWBITS_OP* flowbits_parse(const char* data)
{
    char** toks;
    int num_toks;
    char* typeName = NULL;
    char* groupName = NULL;
    char* flowbitsName = NULL;
    FLOWBITS_GRP* flowbits_grp;

    FLOWBITS_OP* flowbits = (FLOWBITS_OP*)SnortAlloc(sizeof(*flowbits));

    toks = mSplit(data, ",", 0, &num_toks, 0);

    if (num_toks < 1)
    {
        ParseAbort("parseFlowArgs: Must specify flowbits operation.");
    }
    else if (num_toks > 3)
    {
        ParseAbort("parseFlowArgs: Too many arguments.");
    }

    typeName = toks[0];

    if (!strcasecmp("set",typeName))
    {
        flowbits->type = FLOWBITS_SET;
    }
    else if (!strcasecmp("setx",typeName))
    {
        flowbits->type = FLOWBITS_SETX;
    }
    else if (!strcasecmp("unset",typeName))
    {
        flowbits->type = FLOWBITS_UNSET;
    }
    else if (!strcasecmp("toggle",typeName))
    {
        flowbits->type = FLOWBITS_TOGGLE;
    }
    else if (!strcasecmp("isset",typeName))
    {
        flowbits->type = FLOWBITS_ISSET;
    }
    else if (!strcasecmp("isnotset",typeName))
    {
        flowbits->type = FLOWBITS_ISNOTSET;
    }
    else if (!strcasecmp("noalert", typeName))
    {
        if (num_toks > 1)
        {
            ParseAbort("flowbits: Do not specify a flowbits tag id for the keyword 'noalert'.");
        }

        flowbits->type = FLOWBITS_NOALERT;
        flowbits->ids   = NULL;
        flowbits->num_ids  = 0;
        flowbits->name  = SnortStrdup(typeName);

        mSplitFree(&toks, num_toks);
        return flowbits;
    }
    else if (!strcasecmp("reset",typeName))
    {
        if (num_toks > 2)
        {
            ParseAbort("flowbits: Too many arguments for the keyword 'reset'.");
        }

        if (num_toks == 2)
        {
            /*Save the group name*/
            groupName = SnortStrdup(toks[1]);
            flowbits_grp = getFlowBitGroup(groupName);
            flowbits->group = groupName;
            flowbits->group_id = flowbits_grp->group_id;
        }
        flowbits->type = FLOWBITS_RESET;
        flowbits->ids   = NULL;
        flowbits->num_ids   = 0;
        flowbits->name  = SnortStrdup(typeName);
        mSplitFree(&toks, num_toks);
        return flowbits;
    }
    else
    {
        ParseAbort("flowbits: Invalid token %s.", typeName);
    }

    flowbits->name = SnortStrdup(typeName);
    /*
     **  Let's parse the flowbits name
     */
    if ( num_toks < 2 )
    {
        ParseAbort("flowbit: flowbits tag id must be provided.");
    }

    flowbitsName = toks[1];

    if (num_toks == 3)
    {
        groupName = toks[2];
    }
    processFlowBitsWithGroup(flowbitsName, groupName, flowbits);

    mSplitFree(&toks, num_toks);
    return flowbits;
}

static void update_group(FLOWBITS_GRP* flowbits_grp, int id)
{
    flowbits_grp->count++;

    if ( flowbits_grp->max_id < id )
        flowbits_grp->max_id = id;

    flowbits_grp->GrpBitOp->set(id);
}

static void init_groups()
{
    if ( !flowbits_hash or !flowbits_grp_hash )
        return;

    unsigned size = getFlowbitSizeInBytes();

    for ( SFGHASH_NODE* n = sfghash_findfirst(flowbits_grp_hash);
        n != NULL;
        n= sfghash_findnext(flowbits_grp_hash) )
    {
        FLOWBITS_GRP* fbg = (FLOWBITS_GRP*)n->data;
        fbg->GrpBitOp = new BitOp(size);
        fbg->GrpBitOp->reset();
    }

    while ( !op_list.empty() )
    {
        const FLOWBITS_OP* fbop = op_list.front();
        FLOWBITS_GRP* fbg = (FLOWBITS_GRP*)sfghash_find(flowbits_grp_hash, fbop->group);
        assert(fbg);

        for ( int i = 0; i < fbop->num_ids; ++i )
            update_group(fbg, fbop->ids[i]);

        op_list.pop_front();
    }
}

static void FlowBitsVerify(void)
{
    SFGHASH_NODE* n;
    FLOWBITS_OBJECT* fb;
    unsigned num_flowbits = 0;
    unsigned unchecked = 0, unset = 0;

    if (flowbits_hash == NULL)
        return;

    for (n = sfghash_findfirst(flowbits_hash);
        n != NULL;
        n= sfghash_findnext(flowbits_hash))
    {
        fb = (FLOWBITS_OBJECT*)n->data;

        if (fb->toggle != flowbits_toggle)
        {
            if (sfqueue_add(flowbits_bit_queue, (NODE_DATA)(uintptr_t)fb->id) == -1)
            {
                ParseError("failed to add flow bit id to queue.");
                return;
            }

            sfghash_remove(flowbits_hash, n->key);
            continue;
        }

        if ((fb->set > 0) && (fb->isset == 0))
        {
            ParseWarning(WARN_FLOWBITS, "flowbits key '%s' is set but not checked.",
                (char*)n->key);
            unchecked++;
        }
        else if ((fb->isset > 0) && (fb->set == 0))
        {
            ParseWarning(WARN_FLOWBITS, "flowbits key '%s' is checked but not ever set.",
                (char*)n->key);
            unset++;
        }
        else if ((fb->set == 0) && (fb->isset == 0))
        {
            continue; /* don't count this bit as used */
        }

        num_flowbits++;
    }
    assert(num_flowbits == flowbits_count);

    flowbits_toggle ^= 1;

    if ( !num_flowbits )
        return;

    LogLabel("flowbits");
    LogCount("defined", num_flowbits);
    LogCount("not checked", unchecked);
    LogCount("not set", unset);
}

static void FlowItemFree(void* d)
{
    FLOWBITS_OBJECT* data = (FLOWBITS_OBJECT*)d;
    free(data);
}

static void FlowBitsGrpFree(void* d)
{
    FLOWBITS_GRP* data = (FLOWBITS_GRP*)d;
    if(data->GrpBitOp)
        delete data->GrpBitOp;
    if (data->name)
        free(data->name);
    free(data);
}

//-------------------------------------------------------------------------
// api methods
//-------------------------------------------------------------------------

static void flowbits_ginit(SnortConfig*)
{
    flowbits_hash = sfghash_new(10000, 0, 0, FlowItemFree);

    if ( !flowbits_hash )
        FatalError("Could not create flowbits hash.\n");

    // this is used during parse time and runtime so do NOT
    // enable splay mode (which is NOT useful here anyway)
    flowbits_grp_hash = sfghash_new(10000, 0, 0, FlowBitsGrpFree);

    if ( !flowbits_grp_hash )
    {
        FatalError("could not create flowbits group hash.\n");
        return;
    }

    flowbits_bit_queue = sfqueue_new();

    if ( !flowbits_bit_queue )
        FatalError("could not create flowbits bit queue.\n");
}

static void flowbits_gterm(SnortConfig*)
{
    if ( flowbits_hash )
    {
        sfghash_delete(flowbits_hash);
        flowbits_hash = NULL;
    }

    if ( flowbits_grp_hash )
    {
        sfghash_delete(flowbits_grp_hash);
        flowbits_grp_hash = NULL;
    }

    if ( flowbits_bit_queue )
    {
        sfqueue_free_all(flowbits_bit_queue, NULL);
        flowbits_bit_queue = NULL;
    }
}

//-------------------------------------------------------------------------
// module
//-------------------------------------------------------------------------

static const Parameter s_params[] =
{
    { "~command", Parameter::PT_STRING, nullptr, nullptr,
      "set|reset|isset|etc." },

    { "~arg1", Parameter::PT_STRING, nullptr, nullptr,
      "bits or group" },

    { "~arg2", Parameter::PT_STRING, nullptr, nullptr,
      "group if arg1 is bits" },

    { nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr }
};

#define s_help \
    "rule option to set and test arbitrary boolean flags"

class FlowbitsModule : public Module
{
public:
    FlowbitsModule() : Module(s_name, s_help, s_params) { }

    bool begin(const char*, int, SnortConfig*) override;
    bool set(const char*, Value&, SnortConfig*) override;

    ProfileStats* get_profile() const override
    { return &flowBitsPerfStats; }

public:
    string args;
};

bool FlowbitsModule::begin(const char*, int, SnortConfig*)
{
    args.clear();
    return true;
}

bool FlowbitsModule::set(const char*, Value& v, SnortConfig*)
{
    if ( v.is("~command") )
        args = v.get_string();

    else if ( v.is("~arg1") || v.is("~arg2") )
    {
        args += ", ";
        args += v.get_string();
    }
    else
        return false;

    return true;
}

//-------------------------------------------------------------------------
// api methods
//-------------------------------------------------------------------------

static Module* mod_ctor()
{
    return new FlowbitsModule;
}

static void mod_dtor(Module* m)
{
    delete m;
}

static IpsOption* flowbits_ctor(Module* p, OptTreeNode*)
{
    FlowbitsModule* m = (FlowbitsModule*)p;
    FLOWBITS_OP* fbop = flowbits_parse(m->args.c_str());
    return new FlowBitsOption(fbop);
}

static void flowbits_dtor(IpsOption* p)
{
    delete p;
}

// FIXIT-M updating statics during reload is bad, mkay?
static void flowbits_verify(SnortConfig*)
{
    init_groups();
    FlowBitsVerify();
}

#if 0
// FIXIT-M if add_detection_option() finds a dup, then
// we can leak the original group name if same as current
// also, why use new group name instead of original?
char* group_name =  ((FLOWBITS_OP*)idx_dup)->group;

if (flowbits->group)
{
    if (group_name && strcmp(group_name, flowbits->group))
        free(group_name);
    ((FLOWBITS_OP*)idx_dup)->group = SnortStrdup(flowbits->group);
}
// ... then delete current and use original
#endif

static const IpsApi flowbits_api =
{
    {
        PT_IPS_OPTION,
        sizeof(IpsApi),
        IPSAPI_VERSION,
        0,
        API_RESERVED,
        API_OPTIONS,
        s_name,
        s_help,
        mod_ctor,
        mod_dtor
    },
    OPT_TYPE_DETECTION,
    0, 0,
    flowbits_ginit,
    flowbits_gterm,
    nullptr,
    nullptr,
    flowbits_ctor,
    flowbits_dtor,
    flowbits_verify
};

const BaseApi* ips_flowbits = &flowbits_api.base;

