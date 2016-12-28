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
// flush_bucket.h author Russ Combs <rucombs@cisco.com>

#ifndef FLUSH_BUCKET_H
#define FLUSH_BUCKET_H

#include "main/snort_types.h"
#include "main/thread.h"

class FlushBucket
{
public:
    virtual ~FlushBucket() { }
    virtual uint16_t get_next() = 0;

    static uint16_t get_size();
    static void set(unsigned sz);
    static void clear();

protected:
    FlushBucket() { }
};

class ConstFlushBucket : public FlushBucket
{
public:
    ConstFlushBucket(uint16_t sz)
    { size = sz; }

    uint16_t get_next()
    { return size; }

private:
    uint16_t size;
};

class StaticFlushBucket : public FlushBucket
{
public:
    StaticFlushBucket();
    uint16_t get_next();

private:
    unsigned idx;
};

class RandomFlushBucket : public StaticFlushBucket
{
public:
    RandomFlushBucket();
};

#endif

