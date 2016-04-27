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
// swapper.h author Russ Combs <rucombs@cisco.com>

#ifndef SWAPPER_H
#define SWAPPER_H

// used to make thread local, pointer-based config swaps by packet threads

struct SnortConfig;
struct tTargetBasedConfig;

class Swapper
{
public:
    Swapper(SnortConfig*, tTargetBasedConfig*);
    Swapper(SnortConfig*, SnortConfig*);
    Swapper(tTargetBasedConfig*, tTargetBasedConfig*);
    ~Swapper();

    void apply();

private:
    SnortConfig* old_conf;
    SnortConfig* new_conf;

    tTargetBasedConfig* old_attribs;
    tTargetBasedConfig* new_attribs;
};

#endif

