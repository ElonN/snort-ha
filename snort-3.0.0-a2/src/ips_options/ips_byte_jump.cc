//--------------------------------------------------------------------------
// Copyright (C) 2014-2015 Cisco and/or its affiliates. All rights reserved.
// Copyright (C) 2002-2013 Sourcefire, Inc.
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

/* sp_byte_jump
 * Author: Martin Roesch
 *
 * Purpose:
 *      Grab some number of bytes, convert them to their numeric
 *      representation, jump the cursor up that many bytes (for
 *      further pattern matching/byte_testing).
 *
 *
 * Arguments:
 *      Required:
 *      <bytes_to_grab>: number of bytes to pick up from the packet
 *      <offset>: number of bytes into the payload to grab the bytes
 *      Optional:
 *      ["relative"]: offset relative to last pattern match
 *      ["big"]: process data as big endian (default)
 *      ["little"]: process data as little endian
 *      ["string"]: converted bytes represented as a string needing conversion
 *      ["hex"]: converted string data is represented in hexidecimal
 *      ["dec"]: converted string data is represented in decimal
 *      ["oct"]: converted string data is represented in octal
 *      ["align"]: round the number of converted bytes up to the next
 *                 32-bit boundry
 *      ["post_offset"]: number of bytes to adjust after applying
 *
 *   sample rules:
 *   alert udp any any -> any 32770:34000 (content: "|00 01 86 B8|"; \
 *       content: "|00 00 00 01|"; distance: 4; within: 4; \
 *       byte_jump: 4, 12, relative, align; \
 *       byte_test: 4, >, 900, 20, relative; \
 *       msg: "statd format string buffer overflow";)
 *
 * Effect:
 *
 *      Reads in the indicated bytes, converts them to an numeric
 *      representation and then jumps the cursor up
 *      that number of bytes.  Returns 1 if the jump is in range (within the
 *      packet) and 0 if it's not.
 *
 * Comments:
 *
 * Any comments?
 *
 */

#include <sys/types.h>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include <stdlib.h>
#include <ctype.h>
#include <errno.h>

#include <string>

#include "extract.h"
#include "ips_byte_extract.h"
#include "main/snort_types.h"
#include "main/snort_debug.h"
#include "protocols/packet.h"
#include "parser/parser.h"
#include "utils/util.h"
#include "utils/snort_bounds.h"
#include "hash/sfhashfcn.h"
#include "time/profiler.h"
#include "detection/treenodes.h"
#include "detection/detection_defines.h"
#include "detection/detection_util.h"
#include "framework/cursor.h"
#include "framework/ips_option.h"
#include "framework/parameter.h"
#include "framework/module.h"

static THREAD_LOCAL ProfileStats byteJumpPerfStats;

#define s_name "byte_jump"
using namespace std;

typedef struct _ByteJumpData
{
    uint32_t bytes_to_grab;
    int32_t offset;
    uint8_t relative_flag;
    uint8_t data_string_convert_flag;
    uint8_t from_beginning_flag;
    uint8_t align_flag;
    int8_t endianess;
    uint32_t base;
    uint32_t multiplier;
    int32_t post_offset;
    int8_t offset_var;
} ByteJumpData;

class ByteJumpOption : public IpsOption
{
public:
    ByteJumpOption(const ByteJumpData& c) : IpsOption(s_name)
    { config = c; }

    ~ByteJumpOption() { }

    uint32_t hash() const override;
    bool operator==(const IpsOption&) const override;

    CursorActionType get_cursor_type() const override
    { return CAT_ADJUST; }

    bool is_relative() override
    { return (config.relative_flag == 1); }

    int eval(Cursor&, Packet*) override;

private:
    ByteJumpData config;
};

//-------------------------------------------------------------------------
// class methods
//-------------------------------------------------------------------------

uint32_t ByteJumpOption::hash() const
{
    uint32_t a,b,c;
    const ByteJumpData* data = &config;

    a = data->bytes_to_grab;
    b = data->offset;
    c = data->base;

    mix(a,b,c);

    a += (data->relative_flag << 24 |
        data->data_string_convert_flag << 16 |
        data->from_beginning_flag << 8 |
        data->align_flag);
    b += data->endianess;
    c += data->multiplier;

    mix(a,b,c);

    a += data->post_offset;
    b += data->offset_var;

    mix(a,b,c);
    mix_str(a,b,c,get_name());

    final(a,b,c);

    return c;
}

bool ByteJumpOption::operator==(const IpsOption& ips) const
{
    if ( strcmp(s_name, ips.get_name()) )
        return false;

    ByteJumpOption& rhs = (ByteJumpOption&)ips;
    ByteJumpData* left = (ByteJumpData*)&config;
    ByteJumpData* right = (ByteJumpData*)&rhs.config;

    if (( left->bytes_to_grab == right->bytes_to_grab) &&
        ( left->offset == right->offset) &&
        ( left->offset_var == right->offset_var) &&
        ( left->relative_flag == right->relative_flag) &&
        ( left->data_string_convert_flag == right->data_string_convert_flag) &&
        ( left->from_beginning_flag == right->from_beginning_flag) &&
        ( left->align_flag == right->align_flag) &&
        ( left->endianess == right->endianess) &&
        ( left->base == right->base) &&
        ( left->multiplier == right->multiplier) &&
        ( left->post_offset == right->post_offset))
    {
        return true;
    }

    return false;
}

int ByteJumpOption::eval(Cursor& c, Packet*)
{
    ByteJumpData* bjd = (ByteJumpData*)&config;
    int rval = DETECTION_OPTION_NO_MATCH;
    uint32_t jump = 0;
    uint32_t payload_bytes_grabbed = 0;
    int32_t offset;

    PROFILE_VARS;
    MODULE_PROFILE_START(byteJumpPerfStats);

    /* Get values from byte_extract variables, if present. */
    if (bjd->offset_var >= 0 && bjd->offset_var < NUM_BYTE_EXTRACT_VARS)
    {
        uint32_t extract_offset;
        GetByteExtractValue(&extract_offset, bjd->offset_var);
        offset = (int32_t)extract_offset;
    }
    else
    {
        offset = bjd->offset;
    }

    const uint8_t* const start_ptr = c.buffer();
    const int dsize = c.size();
    const uint8_t* const end_ptr = start_ptr + dsize;
    const uint8_t* const base_ptr = offset +
        ((bjd->relative_flag) ? c.start() : start_ptr);

    /* Both of the extraction functions contain checks to ensure the data
     * is inbounds and will return no match if it isn't */
    if ( !bjd->data_string_convert_flag )
    {
        if ( byte_extract(
            bjd->endianess, bjd->bytes_to_grab,
            base_ptr, start_ptr, end_ptr, &jump) )
        {
            MODULE_PROFILE_END(byteJumpPerfStats);
            return rval;
        }

        payload_bytes_grabbed = bjd->bytes_to_grab;
    }
    else
    {
        int32_t tmp = string_extract(
            bjd->bytes_to_grab, bjd->base,
            base_ptr, start_ptr, end_ptr, &jump);

        if (tmp < 0)
        {
            MODULE_PROFILE_END(byteJumpPerfStats);
            return rval;
        }
        payload_bytes_grabbed = tmp;
    }
    // Negative offsets that put us outside the buffer should have been caught
    // in the extraction routines
    assert(base_ptr >= c.buffer());

    if (bjd->multiplier)
        jump *= bjd->multiplier;

    /* if we need to align on 32-bit boundries, round up to the next
     * 32-bit value
     */
    if (bjd->align_flag)
    {
        if ((jump % 4) != 0)
        {
            jump += (4 - (jump % 4));
        }
    }

    if ( !bjd->from_beginning_flag )
    {
        jump += payload_bytes_grabbed;
        jump += c.get_pos();
    }

    jump += offset;
    jump += bjd->post_offset;

    if ( !c.set_pos(jump) )
    {
        MODULE_PROFILE_END(byteJumpPerfStats);
        return rval;
    }
    else
    {
        rval = DETECTION_OPTION_MATCH;
    }

    MODULE_PROFILE_END(byteJumpPerfStats);
    return rval;
}

//-------------------------------------------------------------------------
// module
//-------------------------------------------------------------------------

static const Parameter s_params[] =
{
    { "~count", Parameter::PT_INT, "1:10", nullptr,
      "number of bytes to pick up from the buffer" },

    { "~offset", Parameter::PT_STRING, nullptr, nullptr,
      "variable name or number of bytes into the buffer to start processing" },

    { "relative", Parameter::PT_IMPLIED, nullptr, nullptr,
      "offset from cursor instead of start of buffer" },

    { "from_beginning", Parameter::PT_IMPLIED, nullptr, nullptr,
      "jump from start of buffer instead of cursor" },

    { "multiplier", Parameter::PT_INT, "1:65535", "1",
      "scale extracted value by given amount" },

    { "align", Parameter::PT_INT, "0:4", "0",
      "round the number of converted bytes up to the next 2- or 4-byte boundary" },

    { "post_offset", Parameter::PT_INT, "-65535:65535", "0",
      "also skip forward or backwards (positive of negative value) this number of bytes" },

    { "big", Parameter::PT_IMPLIED, nullptr, nullptr,
      "big endian" },

    { "little", Parameter::PT_IMPLIED, nullptr, nullptr,
      "little endian" },

    { "dce", Parameter::PT_IMPLIED, nullptr, nullptr,
      "dcerpc2 determines endianness" },

    { "string", Parameter::PT_IMPLIED, nullptr, nullptr,
      "convert from string" },

    { "hex", Parameter::PT_IMPLIED, nullptr, nullptr,
      "convert from hex string" },

    { "oct", Parameter::PT_IMPLIED, nullptr, nullptr,
      "convert from octal string" },

    { "dec", Parameter::PT_IMPLIED, nullptr, nullptr,
      "convert from decimal string" },

    { nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr }
};

#define s_help \
    "rule option to move the detection cursor"

class ByteJumpModule : public Module
{
public:
    ByteJumpModule() : Module(s_name, s_help, s_params) { }

    bool begin(const char*, int, SnortConfig*) override;
    bool end(const char*, int, SnortConfig*) override;
    bool set(const char*, Value&, SnortConfig*) override;

    ProfileStats* get_profile() const override
    { return &byteJumpPerfStats; }

    ByteJumpData data;
    string var;
};

bool ByteJumpModule::begin(const char*, int, SnortConfig*)
{
    memset(&data, 0, sizeof(data));
    var.clear();
    data.multiplier = 1;
    return true;
}

bool ByteJumpModule::end(const char*, int, SnortConfig*)
{
    if ( var.empty() )
        data.offset_var = BYTE_EXTRACT_NO_VAR;
    else
    {
        data.offset_var = GetVarByName(var.c_str());

        if (data.offset_var == BYTE_EXTRACT_NO_VAR)
        {
            ParseError(BYTE_EXTRACT_INVALID_ERR_STR, "byte_jump", var.c_str());
            return false;
        }
    }
    unsigned e1 = ffs(data.endianess);
    unsigned e2 = ffs(data.endianess >> e1);

    if ( e1 && e2 )
    {
        ParseError("byte_jump has multiple arguments "
            "specifying the type of string conversion. Use only "
            "one of 'dec', 'hex', or 'oct'.");
        return false;
    }
    return true;
}

bool ByteJumpModule::set(const char*, Value& v, SnortConfig*)
{
    if ( v.is("~count") )
        data.bytes_to_grab = v.get_long();

    else if ( v.is("~offset") )
    {
        long n;
        if ( v.strtol(n) )
            data.offset = n;
        else
            var = v.get_string();
    }
    else if ( v.is("relative") )
        data.relative_flag = 1;

    else if ( v.is("from_beginning") )
        data.from_beginning_flag = 1;

    else if ( v.is("align") )
        data.align_flag = 1;

    else if ( v.is("multiplier") )
        data.multiplier = v.get_long();

    else if ( v.is("post_offset") )
        data.post_offset = v.get_long();

    else if ( v.is("big") )
        data.endianess |= ENDIAN_BIG;

    else if ( v.is("little") )
        data.endianess |= ENDIAN_LITTLE;

    else if ( v.is("dce") )
        data.endianess |= ENDIAN_FUNC;

    else if ( v.is("string") )
    {
        data.data_string_convert_flag = 1;
        data.base = 10;
    }
    else if ( v.is("dec") )
        data.base = 10;

    else if ( v.is("hex") )
        data.base = 16;

    else if ( v.is("oct") )
        data.base = 8;

    else
        return false;

    return true;
}

//-------------------------------------------------------------------------
// api methods
//-------------------------------------------------------------------------

static Module* mod_ctor()
{
    return new ByteJumpModule;
}

static void mod_dtor(Module* m)
{
    delete m;
}

static IpsOption* byte_jump_ctor(Module* p, OptTreeNode*)
{
    ByteJumpModule* m = (ByteJumpModule*)p;
    return new ByteJumpOption(m->data);
}

static void byte_jump_dtor(IpsOption* p)
{
    delete p;
}

static const IpsApi byte_jump_api =
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
    nullptr,
    nullptr,
    nullptr,
    nullptr,
    byte_jump_ctor,
    byte_jump_dtor,
    nullptr
};

#ifdef BUILDING_SO
SO_PUBLIC const BaseApi* snort_plugins[] =
{
    &byte_jump_api.base,
    nullptr
};
#else
const BaseApi* ips_byte_jump = &byte_jump_api.base;
#endif

