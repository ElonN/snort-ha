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
// codec_module.cc author Josh Rosenbaum <jrosenba@cisco.com>

#include "codecs/codec_module.h"

#define codec_module_help \
    "general decoder rules"

CodecModule::CodecModule() : Module("decode", codec_module_help)
{ }

static const RuleMap general_decode_rules[] =
{
    { DECODE_IP_BAD_PROTO, "BAD-TRAFFIC bad IP protocol" },
    { DECODE_IP_MULTIPLE_ENCAPSULATION,
      "two or more IP (v4 and/or v6) encapsulation layers present" },
    { DECODE_ZERO_LENGTH_FRAG, "fragment with zero length" },
    { DECODE_BAD_TRAFFIC_LOOPBACK, "bad traffic loopback IP" },
    { DECODE_BAD_TRAFFIC_SAME_SRCDST, "bad traffic same src/dst IP" },
    { DECODE_IP_UNASSIGNED_PROTO, "BAD-TRAFFIC unassigned/reserved IP protocol" },

    { DECODE_TOO_MANY_LAYERS, "too many protocols present" },
    { 0, nullptr },
};

const RuleMap* CodecModule::get_rules() const
{ return general_decode_rules; }

