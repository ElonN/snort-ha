//--------------------------------------------------------------------------
// Copyright (C) 2014-2015 Cisco and/or its affiliates. All rights reserved.
// Copyright (C) 2012-2013 Sourcefire, Inc.
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

// file_mime_process.h author Hui Cao <huica@cisco.com>

#ifndef FILE_MIME_PAF_H
#define FILE_MIME_PAF_H

// Provides list of MIME processing functions. Encoded file data will be decoded
// and file name will be extracted from MIME header

#include <pcre.h>

#include "decode_base.h"
#include "file_mime_config.h"
#include "file_api/file_api.h"

/* State tracker for data */
enum MimeDataState
{
    MIME_PAF_FINDING_BOUNDARY_STATE,
    MIME_PAF_FOUND_BOUNDARY_STATE
};

/* State tracker for Boundary Signature */
enum MimeBoundaryState
{
    MIME_PAF_BOUNDARY_UNKNOWN = 0,      /* UNKNOWN */
    MIME_PAF_BOUNDARY_LF,               /* '\n' */
    MIME_PAF_BOUNDARY_HYPEN_FIRST,      /* First '-' */
    MIME_PAF_BOUNDARY_HYPEN_SECOND      /* Second '-' */
};

/* State tracker for end of pop/smtp command */
enum DataEndState
{
    PAF_DATA_END_UNKNOWN,         /* Start or UNKNOWN */
    PAF_DATA_END_FIRST_CR,        /* First '\r' */
    PAF_DATA_END_FIRST_LF,        /* First '\n' */
    PAF_DATA_END_DOT,             /* '.' */
    PAF_DATA_END_SECOND_CR,       /* Second '\r' */
    PAF_DATA_END_SECOND_LF        /* Second '\n' */
};

#define MAX_MIME_BOUNDARY_LEN  70  /* Max length of boundary string, defined in RFC 2046 */

struct MimeDataPafInfo
{
    MimeDataState data_state;
    char boundary[ MAX_MIME_BOUNDARY_LEN + 1];            /* MIME boundary string + '\0' */
    int boundary_len;
    char* boundary_search;
    MimeBoundaryState boundary_state;
};

static inline bool scanning_boundary(MimeDataPafInfo* mime_info, uint32_t boundary_start,
    uint32_t* fp)
{
    if (boundary_start &&
        mime_info->data_state == MIME_PAF_FOUND_BOUNDARY_STATE &&
        mime_info->boundary_state != MIME_PAF_BOUNDARY_UNKNOWN)
    {
        *fp = boundary_start;
        return true;
    }

    return false;
}

void reset_mime_paf_state(MimeDataPafInfo *data_info);
/*  Process data boundary and flush each file based on boundary*/
bool process_mime_paf_data(MimeDataPafInfo *data_info,  uint8_t val);
bool check_data_end(void *end_state,  uint8_t val);

#endif

