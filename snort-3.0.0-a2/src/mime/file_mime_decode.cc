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
// Author: Bhagyashree Bantwal <bbantwal@sourcefire.com>

#include <mime/decode_uu.h>
#include "file_mime_decode.h"
#include "decode_b64.h"
#include "decode_bit.h"
#include "decode_qp.h"
#include "decode_uu.h"
#include "utils/snort_bounds.h"
#include "utils/util_unfold.h"
#include "utils/util.h"

void MimeDecode::reset_decoded_bytes()
{
    if (decoder)
        decoder->reset_decoded_bytes();
}

void MimeDecode::clear_decode_state()
{
    decode_type = DECODE_NONE;
    if (decoder)
        decoder->reset_decode_state();
}

void MimeDecode::process_decode_type(const char* start, int length, bool cnt_xf)
{
    const char* tmp = NULL;

    if (decoder)
        delete decoder;

    decoder = nullptr;

    if (cnt_xf)
    {
        if (config->get_b64_depth() > -1)
        {
            tmp = SnortStrcasestr(start, length, "base64");
            if ( tmp != NULL )
            {
                decode_type = DECODE_B64;
                decoder = new B64Decode(config->get_b64_depth());
                return;
            }
        }

        if (config->get_qp_depth() > -1)
        {
            tmp = SnortStrcasestr(start, length, "quoted-printable");
            if ( tmp != NULL )
            {
                decode_type = DECODE_QP;
                decoder = new QPDecode(config->get_qp_depth());
                return;
            }
        }

        if (config->get_uu_depth() > -1)
        {
            tmp = SnortStrcasestr(start, length, "uuencode");
            if ( tmp != NULL )
            {
                decode_type = DECODE_UU;
                decoder = new UUDecode(config->get_uu_depth());
                return;
            }
        }
    }

    if (config->get_bitenc_depth() > -1)
    {
        decode_type = DECODE_BITENC;
        decoder = new BitDecode(config->get_bitenc_depth());
        return;
    }
}

DecodeResult MimeDecode::decode_data(const uint8_t* start, const uint8_t* end)
{
    return (decoder? decoder->decode_data(start,end):DECODE_SUCCESS);
}

int MimeDecode::get_detection_depth()
{
    return (decoder?decoder->get_detection_depth():0);
}

int MimeDecode::get_decoded_data(uint8_t** buf,  uint32_t* size)
{
    return (decoder? decoder->get_decoded_data(buf, size):0);
}

DecodeType MimeDecode::get_decode_type()
{
    return decode_type;
}

MimeDecode::MimeDecode(DecodeConfig* conf)
{
    config = conf;
}

MimeDecode::~MimeDecode()
{
    if (decoder)
        delete decoder;
}
