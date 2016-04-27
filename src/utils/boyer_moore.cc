//--------------------------------------------------------------------------
// Copyright (C) 2014-2015 Cisco and/or its affiliates. All rights reserved.
// Copyright (C) 2002-2013 Sourcefire, Inc.
// Copyright (C) 1998-2002 Martin Roesch <roesch@sourcefire.com>
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

// boyer_moore.cc was split out of mstring.cc which had these comments:

/***************************************************************************
 *
 * File: MSTRING.C
 *
 * Purpose: Provide a variety of string functions not included in libc.  Makes
 *          up for the fact that the libstdc++ is hard to get reference
 *          material on and I don't want to write any more non-portable c++
 *          code until I have solid references and libraries to use.
 *
 * History:
 *
 * Date:      Author:  Notes:
 * ---------- ------- ----------------------------------------------
 *  08/19/98    MFR    Initial coding begun
 *  03/06/99    MFR    Added Boyer-Moore pattern match routine, don't use
 *                     mContainsSubstr() any more if you don't have to
 *  12/31/99	JGW    Added a full Boyer-Moore implementation to increase
 *                     performance. Added a case insensitive version of mSearch
 *  07/24/01    MFR    Fixed Regex pattern matcher introduced by Fyodor
 *
 **************************************************************************/
#include "boyer_moore.h"

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <sys/types.h>

#include "main/snort_types.h"
#include "main/snort_debug.h"
#include "utils/util.h"

#ifdef TEST_MSTRING
int main()
{
    char test[] = "\0\0\0\0\0\0\0\0\0CKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\0\0";
    char find[] = "CKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\0\0";

/*   char test[] = "\x90\x90\x90\x90\x90\x90\xe8\xc0\xff\xff\xff/bin/sh\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90";
     char find[] = "\xe8\xc0\xff\xff\xff/bin/sh";  */
    int i;
    int toks;
    int* shift;
    int* skip;

/*   shift=make_shift(find,sizeof(find)-1);
     skip=make_skip(find,sizeof(find)-1); */

    DebugFormat(DEBUG_PATTERN_MATCH,"%d\n",
        mSearch(test, sizeof(test) - 1, find,
        sizeof(find) - 1, shift, skip));

    return 0;
}

#endif

/****************************************************************
 *
 *  Function: make_skip(char *, int)
 *
 *  Purpose: Create a Boyer-Moore skip table for a given pattern
 *
 *  Parameters:
 *      ptrn => pattern
 *      plen => length of the data in the pattern buffer
 *
 *  Returns:
 *      int * - the skip table
 *
 ****************************************************************/
int* make_skip(char* ptrn, int plen)
{
    int i;
    int* skip = (int*)SnortAlloc(256* sizeof(int));

    for ( i = 0; i < 256; i++ )
        skip[i] = plen + 1;

    while (plen != 0)
        skip[(unsigned char)*ptrn++] = plen--;

    return skip;
}

/****************************************************************
 *
 *  Function: make_shift(char *, int)
 *
 *  Purpose: Create a Boyer-Moore shift table for a given pattern
 *
 *  Parameters:
 *      ptrn => pattern
 *      plen => length of the data in the pattern buffer
 *
 *  Returns:
 *      int * - the shift table
 *
 ****************************************************************/
int* make_shift(char* ptrn, int plen)
{
    int* shift = (int*)SnortAlloc(plen * sizeof(int));
    int* sptr = shift + plen - 1;
    char* pptr = ptrn + plen - 1;
    char c;

    c = ptrn[plen - 1];

    *sptr = 1;

    while (sptr-- != shift)
    {
        char* p1 = ptrn + plen - 2, * p2, * p3;

        do
        {
            while (p1 >= ptrn && *p1-- != c)
                ;

            p2 = ptrn + plen - 2;
            p3 = p1;

            while (p3 >= ptrn && *p3-- == *p2-- && p2 >= pptr)
                ;
        }
        while (p3 >= ptrn && p2 >= pptr);

        *sptr = shift + plen - sptr + p2 - p3;

        pptr--;
    }

    return shift;
}

/****************************************************************
 *
 *  Function: mSearch(char *, int, char *, int)
 *
 *  Purpose: Determines if a string contains a (non-regex)
 *           substring.
 *
 *  Parameters:
 *      buf => data buffer we want to find the data in
 *      blen => data buffer length
 *      ptrn => pattern to find
 *      plen => length of the data in the pattern buffer
 *      skip => the B-M skip array
 *      shift => the B-M shift array
 *
 *  Returns:
 *      -1 if not found or offset >= 0 if found
 *
 ****************************************************************/
int mSearch(
    const char* buf, int blen, const char* ptrn, int plen, int* skip, int* shift)
{
    DebugFormat(DEBUG_PATTERN_MATCH,"buf: %p  blen: %d  ptrn: %p  "
        "plen: %d\n", buf, blen, ptrn, plen);

    if (plen == 0)
        return -1;

    int b_idx = plen;

    while (b_idx <= blen)
    {
        int p_idx = plen, skip_stride, shift_stride;

        while (buf[--b_idx] == ptrn[--p_idx])
        {
            if (p_idx == 0)
                return b_idx;
        }

        skip_stride = skip[(unsigned char)buf[b_idx]];
        shift_stride = shift[p_idx];

        b_idx += (skip_stride > shift_stride) ? skip_stride : shift_stride;
    }

    return -1;
}

/****************************************************************
 *
 *  Function: mSearchCI(char *, int, char *, int)
 *
 *  Purpose: Determines if a string contains a (non-regex)
 *           substring matching is case insensitive
 *
 *  Parameters:
 *      buf => data buffer we want to find the data in
 *      blen => data buffer length
 *      ptrn => pattern to find
 *      plen => length of the data in the pattern buffer
 *      skip => the B-M skip array
 *      shift => the B-M shift array
 *
 *  Returns:
 *      -1 if not found or offset >= 0 if found
 *
 ****************************************************************/
int mSearchCI(
    const char* buf, int blen, const char* ptrn, int plen, int* skip, int* shift)
{
    int b_idx = plen;

    if (plen == 0)
        return -1;

    while (b_idx <= blen)
    {
        int p_idx = plen, skip_stride, shift_stride;

        while ((unsigned char)ptrn[--p_idx] == toupper((unsigned char)buf[--b_idx]))
        {
            if (p_idx == 0)
                return b_idx;
        }

        skip_stride = skip[toupper((unsigned char)buf[b_idx])];
        shift_stride = shift[p_idx];

        b_idx += (skip_stride > shift_stride) ? skip_stride : shift_stride;
    }

    return -1;
}

/****************************************************************
 *
 *  Function: mSearchREG(char *, int, char *, int)
 *
 *  Purpose: Determines if a string contains a (regex)
 *           substring.
 *
 *  Parameters:
 *      buf => data buffer we want to find the data in
 *      blen => data buffer length
 *      ptrn => pattern to find
 *      plen => length of the data in the pattern buffer
 *      skip => the B-M skip array
 *      shift => the B-M shift array
 *
 *  Returns:
 *      1 = found, 0 = not found
 *
 ****************************************************************/
int mSearchREG(
    const char* buf, int blen, const char* ptrn, int plen, int* skip, int* shift)
{
    int b_idx = plen;
    int literal = 0;
    int regexcomp = 0;
#ifdef DEBUG_MSGS
    int cmpcnt = 0;
#endif /* DEBUG_MSGS */

    DebugFormat(DEBUG_PATTERN_MATCH, "buf: %p  blen: %d  ptrn: %p "
        " plen: %d b_idx: %d\n", buf, blen, ptrn, plen, b_idx);
    DebugFormat(DEBUG_PATTERN_MATCH, "packet data: \"%s\"\n", buf);
    DebugFormat(DEBUG_PATTERN_MATCH, "matching for \"%s\"\n", ptrn);

    if (plen == 0)
        return 1;

    while (b_idx <= blen)
    {
        int p_idx = plen, skip_stride, shift_stride;

        DebugFormat(DEBUG_PATTERN_MATCH, "Looping... "
            "([%d]0x%X (%c) -> [%d]0x%X(%c))\n",
            b_idx, buf[b_idx-1],
            buf[b_idx-1],
            p_idx, ptrn[p_idx-1], ptrn[p_idx-1]);

        while (buf[--b_idx] == ptrn[--p_idx]
            || (ptrn[p_idx] == '?' && !literal)
            || (ptrn[p_idx] == '*' && !literal)
            || (ptrn[p_idx] == '\\' && !literal))
        {
            DebugFormat(DEBUG_PATTERN_MATCH, "comparing: b:%c -> p:%c\n",
                buf[b_idx], ptrn[p_idx]);
#ifdef DEBUG_MSGS
            cmpcnt++;
#endif

            if (literal)
                literal = 0;
            if (!literal && ptrn[p_idx] == '\\')
                literal = 1;
            if (ptrn[p_idx] == '*')
            {
                DebugMessage(DEBUG_PATTERN_MATCH,"Checking wildcard matching...\n");
                while (p_idx != 0 && ptrn[--p_idx] == '*')
                    ;                                      /* fool-proof */

                while (buf[--b_idx] != ptrn[p_idx])
                {
                    DebugFormat(DEBUG_PATTERN_MATCH,
                        "comparing: b[%d]:%c -> p[%d]:%c\n",
                        b_idx, buf[b_idx], p_idx, ptrn[p_idx]);

                    regexcomp++;
                    if (b_idx == 0)
                    {
                        DebugMessage(DEBUG_PATTERN_MATCH,
                            "b_idx went to 0, returning 0\n");
                        return 0;
                    }
                }

                DebugFormat(DEBUG_PATTERN_MATCH,
                    "got wildcard final char match! (b[%d]: %c -> p[%d]: %c\n",
                    b_idx, buf[b_idx], p_idx, ptrn[p_idx]);
            }

            if (p_idx == 0)
            {
                DebugFormat(DEBUG_PATTERN_MATCH, "match: compares = %d.\n",
                    cmpcnt);
                return 1;
            }

            if (b_idx == 0)
                break;
        }

        DebugMessage(DEBUG_PATTERN_MATCH, "skip-shifting...\n");
        skip_stride = skip[(unsigned char)buf[b_idx]];
        shift_stride = shift[p_idx];

        b_idx += (skip_stride > shift_stride) ? skip_stride : shift_stride;
        DebugFormat(DEBUG_PATTERN_MATCH, "b_idx skip-shifted to %d\n", b_idx);
        b_idx += regexcomp;
        DebugFormat(DEBUG_PATTERN_MATCH,
            "b_idx regex compensated %d steps, to %d\n", regexcomp, b_idx);
        regexcomp = 0;
    }

    DebugFormat(DEBUG_PATTERN_MATCH, "no match: compares = %d, b_idx = %d, "
        "blen = %d\n", cmpcnt, b_idx, blen);

    return 0;
}

