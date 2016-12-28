//--------------------------------------------------------------------------
// Copyright (C) 2014-2015 Cisco and/or its affiliates. All rights reserved.
// Copyright (C) 1998-2013 Sourcefire, Inc.
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
// sf_email_attach_decode.h author Bhagyashree Bantwal <bbantwal@cisco.com>

#ifndef FILE_MIME_DECODE_H
#define FILE_MIME_DECODE_H

// Email attachment decoder, supports Base64, QP, UU, and Bit7/8

#include <stdlib.h>

#include "decode_base.h"
#include "file_mime_config.h"

#include "main/snort_types.h"

enum DecodeType
{
    DECODE_NONE = 0,
    DECODE_B64,
    DECODE_QP,
    DECODE_UU,
    DECODE_BITENC,
    DECODE_ALL
} ;

class MimeDecode
{
public:
    MimeDecode(DecodeConfig* conf);
    ~MimeDecode();

    // get the decode type from buffer
    // bool cnt_xf: true if there is transfer encode defined, false otherwise
    void process_decode_type(const char* start, int length, bool cnt_xf);

    // Main function to decode file data
    DecodeResult decode_data(const uint8_t* start, const uint8_t* end);

    // Retrieve the decoded data the previous decode_data() call
    int get_decoded_data(uint8_t** buf,  uint32_t* size);

    int get_detection_depth();

    void clear_decode_state();
    void reset_decoded_bytes();

    DecodeType get_decode_type();

private:
    DecodeType decode_type = DECODE_NONE;
    DecodeConfig* config;
    DataDecode* decoder = NULL;
};

// FIXIT-L: add statistics
//struct MimeStats
//{
//    uint64_t memcap_exceeded;
//    uint64_t attachments[DECODE_ALL];
//    uint64_t decoded_bytes[DECODE_ALL];
//};

#endif

