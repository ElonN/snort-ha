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
// nhttp_field.h author Tom Peters <thopeter@cisco.com>

#ifndef NHTTP_FIELD_H
#define NHTTP_FIELD_H

#include <stdint.h>
#include <stdio.h>
#include <assert.h>

// Individual pieces of the message found during parsing.
// Length values <= 0 are StatusCode values and imply that the start pointer is meaningless.
// Never use the start pointer without verifying that length > 0.
class Field
{
public:
    int32_t length = NHttpEnums::STAT_NOTCOMPUTE;
    const uint8_t* start = nullptr;

    static const Field FIELD_NULL;

    Field(int32_t length_, const uint8_t* start_) : length(length_), start(start_) { }
    explicit Field(int32_t length_) : length(length_) { assert(length<=0); }
    Field() = default;
    void print(FILE* output, const char* name, bool int_vals = false) const;
};

#endif

