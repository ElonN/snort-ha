//--------------------------------------------------------------------------
// Copyright (C) 2014-2015 Cisco and/or its affiliates. All rights reserved.
// Copyright (C) 2004-2013 Sourcefire, Inc.
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
 * Steven A. Sturges <ssturges@sourcefire.com>
 * Daniel J. Roelker <droelker@sourcefire.com>
 * Marc A. Norton <mnorton@sourcefire.com>
 */

#include "ftp_parse.h"

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <errno.h>

#include "ftpp_return_codes.h"
#include "ftpp_ui_config.h"
#include "ftp_cmd_lookup.h"
#include "ftp_bounce_lookup.h"
#include "ftpp_si.h"
#include "pp_telnet.h"
#include "pp_ftp.h"

#include "main/snort_types.h"
#include "main/snort_debug.h"
#include "stream/stream_api.h"
#include "time/profiler.h"
#include "detection/detection_util.h"
#include "parser/parser.h"
#include "parser/mstring.h"
#include "utils/sfsnprintfappend.h"
#include "sfip/sf_ip.h"

#define CONF_SEPARATORS " "

#define ALLOW_BOUNCE      "bounce_to"
#define CMD_VALIDITY      "cmd_validity"

/*
 * Optional parameter delimiters
 */
#define START_OPT_FMT       "["
#define END_OPT_FMT         "]"
#define START_CHOICE_FMT    "{"
#define END_CHOICE_FMT      "}"
#define OR_FMT              "|"

/*
 * The cmd_validity keyword can be used with the format keyword to
 * restrict data types.  The interpretation is specific to the data
 * type.  'format' is only supported with date & char data types.
 *
 * A few examples:
 *
 * 1. Will perform validity checking of an FTP Mode command to
 * check for one of the characters A, S, B, or C.
 *
 * cmd_validity MODE char ASBC
 *
 *
 * 2. Will perform validity checking of an FTP MDTM command to
 * check for an optional date argument following the format
 * specified.  The date would uses the YYYYMMDDHHmmss+TZ format.
 *
 * cmd_validity MDTM [ date nnnnnnnnnnnnnn[.n[n[n]]] ] string
 *
 *
 * 3. Will perform validity checking of an FTP ALLO command to
 * check for an integer, then optionally, the letter R and another
 * integer.
 *
 * cmd_validity ALLO int [ char R int ]
 */

/*
 * The def_max_param_len & alt_max_param_len keywords can be used to
 * restrict parameter length for one or more commands.  The space
 * separated list of commands is enclosed in {}s.
 *
 * A few examples:
 *
 * 1. Restricts all command parameters to 100 characters
 *
 * def_max_param_len 100
 *
 * 2. Overrides CWD pathname to 256 characters
 *
 * alt_max_param_len 256 { CWD }
 *
 * 3. Overrides PWD & SYST to no parameters
 *
 * alt_max_param_len 0 { PWD SYST }
 *
 */

static char* maxToken = NULL;

static char* mystrtok(char* s, const char* delim)
{
    static char* last = NULL;
    if ( s || last )
        last = strtok(s, delim);
    return last;
}

static char* NextToken(const char* delimiters)
{
    char* retTok = mystrtok(NULL, delimiters);
    if ( maxToken && retTok > maxToken)
        return NULL;

    return retTok;
}

/*
 * Function: SetOptionalsNext(FTP_PARAM_FMT *ThisFmt,
 *                            FTP_PARAM_FMT *NextFmt,
 *                            FTP_PARAM_FMT **choices,
 *                            int numChoices)
 *
 * Purpose: Recursively updates the next value for nodes in the FTP
 *          Parameter validation tree.
 *
 * Arguments: ThisFmt       => pointer to an FTP parameter validation node
 *            NextFmt       => pointer to an FTP parameter validation node
 *            choices       => pointer to a list of FTP parameter
 *                             validation nodes
 *            numChoices    => the number of nodes in the list
 *
 * Returns: int     => an error code integer (0 = success,
 *                     >0 = non-fatal error, <0 = fatal error)
 *
 */
static void SetOptionalsNext(FTP_PARAM_FMT* ThisFmt, FTP_PARAM_FMT* NextFmt,
    FTP_PARAM_FMT** choices, int numChoices)
{
    if (!ThisFmt)
        return;

    if (ThisFmt->optional)
    {
        if (ThisFmt->next_param_fmt == NULL)
        {
            ThisFmt->next_param_fmt = NextFmt;
            if (numChoices)
            {
                ThisFmt->numChoices = numChoices;
                ThisFmt->choices = (FTP_PARAM_FMT**)calloc(numChoices, sizeof(FTP_PARAM_FMT*));
                if (ThisFmt->choices == NULL)
                {
                    ParseAbort("failed to allocate memory");
                }

                memcpy(ThisFmt->choices, choices, sizeof(FTP_PARAM_FMT*) * numChoices);
            }
        }
        else
        {
            SetOptionalsNext(ThisFmt->next_param_fmt, NextFmt,
                choices, numChoices);
        }
    }
    else
    {
        int i;
        SetOptionalsNext(ThisFmt->optional_fmt, ThisFmt->next_param_fmt,
            ThisFmt->choices, ThisFmt->numChoices);
        for (i=0; i<ThisFmt->numChoices; i++)
        {
            SetOptionalsNext(ThisFmt->choices[i], ThisFmt,
                choices, numChoices);
        }
        SetOptionalsNext(ThisFmt->next_param_fmt, ThisFmt,
            choices, numChoices);
    }
}

/*
 * Function: ProcessDateFormat(FTP_DATE_FMT *dateFmt,
 *                             FTP_DATE_FMT *LastNonOptFmt,
 *                             char **format)
 *
 * Purpose: Sets the value for nodes in the FTP Date validation tree.
 *
 * Arguments: dateFmt       => pointer to an FTP date validation node
 *            LastNonOptFmt => pointer to previous FTP date validation node
 *            format        => pointer to next part of date validation string
 *                             Updated on function exit.
 *
 * Returns: int     => an error code integer (0 = success,
 *                     >0 = non-fatal error, <0 = fatal error)
 *
 */
static int ProcessDateFormat(FTP_DATE_FMT* dateFmt,
    FTP_DATE_FMT* LastNonOptFmt,
    char** format)
{
    char* curr_format;
    int iRet = FTPP_SUCCESS;
    int curr_len = 0;
    char* curr_ch;
    char* start_ch;
    FTP_DATE_FMT* CurrFmt = dateFmt;

    if (!dateFmt)
        return FTPP_INVALID_ARG;

    if (!format || !*format)
        return FTPP_INVALID_ARG;

    start_ch = curr_ch = *format;

    while (*curr_ch != '\0')
    {
        switch (*curr_ch)
        {
        case 'n':
        case 'C':
        case '+':
        case '-':
        case '.':
            curr_len++;
            curr_ch++;
            break;
        case '[':
            curr_ch++;
            if (curr_len > 0)
            {
                FTP_DATE_FMT* OptFmt;
                OptFmt = (FTP_DATE_FMT*)calloc(1, sizeof(FTP_DATE_FMT));
                if (OptFmt == NULL)
                {
                    FatalError("Failed to allocate memory");
                }

                curr_format = (char*)calloc(curr_len + 1, sizeof(char));
                if (curr_format == NULL)
                {
                    FatalError("Failed to allocate memory");
                }

                strncpy(curr_format, start_ch, curr_len);
                CurrFmt->format_string = curr_format;
                curr_len = 0;
                CurrFmt->optional = OptFmt;
                OptFmt->prev = CurrFmt;
                iRet = ProcessDateFormat(OptFmt, CurrFmt, &curr_ch);
                if (iRet != FTPP_SUCCESS)
                {
                    free(OptFmt);
                    free(curr_format);
                    return iRet;
                }
            }
            start_ch = curr_ch;
            break;
        case ']':
            curr_ch++;
            if (curr_len > 0)
            {
                curr_format = (char*)calloc(curr_len + 1, sizeof(char));
                if (curr_format == NULL)
                {
                    FatalError("Failed to allocate memory");
                }

                strncpy(curr_format, start_ch, curr_len);
                CurrFmt->format_string = curr_format;
            }
            *format = curr_ch;
            return FTPP_SUCCESS;
            break;
        case '{':
            curr_ch++;
            {
                FTP_DATE_FMT* NewFmt;
                NewFmt = (FTP_DATE_FMT*)calloc(1, sizeof(FTP_DATE_FMT));
                if (NewFmt == NULL)
                {
                    FatalError("Failed to allocate memory");
                }

                if (curr_len > 0)
                {
                    curr_format = (char*)calloc(curr_len + 1, sizeof(char));
                    if (curr_format == NULL)
                    {
                        FatalError("Failed to allocate memory");
                    }

                    strncpy(curr_format, start_ch, curr_len);
                    CurrFmt->format_string = curr_format;
                    curr_len = 0;
                }
                else
                {
                    CurrFmt->empty = 1;
                }
                NewFmt->prev = LastNonOptFmt;
                CurrFmt->next_a = NewFmt;
                iRet = ProcessDateFormat(NewFmt, CurrFmt, &curr_ch);
                if (iRet != FTPP_SUCCESS)
                {
                    return iRet;
                }
                NewFmt = (FTP_DATE_FMT*)calloc(1, sizeof(FTP_DATE_FMT));
                if (NewFmt == NULL)
                {
                    FatalError("Failed to allocate memory");
                }

                NewFmt->prev = LastNonOptFmt;
                CurrFmt->next_b = NewFmt;
                iRet = ProcessDateFormat(NewFmt, CurrFmt, &curr_ch);
                if (iRet != FTPP_SUCCESS)
                {
                    return iRet;
                }

                NewFmt = (FTP_DATE_FMT*)calloc(1, sizeof(FTP_DATE_FMT));
                if (NewFmt == NULL)
                {
                    FatalError("Failed to allocate memory");
                }

                NewFmt->prev = CurrFmt;
                CurrFmt->next = NewFmt;
                iRet = ProcessDateFormat(NewFmt, CurrFmt, &curr_ch);
                if (iRet != FTPP_SUCCESS)
                {
                    return iRet;
                }
            }
            break;
        case '}':
            curr_ch++;
            if (curr_len > 0)
            {
                curr_format = (char*)calloc(curr_len + 1, sizeof(char));
                if (curr_format == NULL)
                {
                    FatalError("Failed to allocate memory");
                }

                strncpy(curr_format, start_ch, curr_len);
                CurrFmt->format_string = curr_format;
                *format = curr_ch;
                return FTPP_SUCCESS;
            }
            else
            {
                CurrFmt->empty = 1;
                *format = curr_ch;
                return FTPP_SUCCESS;
            }
            break;
        case '|':
            curr_ch++;
            if (curr_len > 0)
            {
                curr_format = (char*)calloc(curr_len + 1, sizeof(char));
                if (curr_format == NULL)
                {
                    FatalError("Failed to allocate memory");
                }

                strncpy(curr_format, start_ch, curr_len);
                CurrFmt->format_string = curr_format;
                *format = curr_ch;
                return FTPP_SUCCESS;
            }
            else
            {
                CurrFmt->empty = 1;
                *format = curr_ch;
                return FTPP_SUCCESS;
            }
            break;
        default:
            /* Uh, shouldn't get this.  */
            return FTPP_INVALID_ARG;
            break;
        }
    }

    if (curr_len > 0)
    {
        curr_format = (char*)calloc(curr_len + 1, sizeof(char));
        if (curr_format == NULL)
        {
            FatalError("Failed to allocate memory");
        }

        strncpy(curr_format, start_ch, curr_len);
        CurrFmt->format_string = curr_format;
    }

    /* Should've closed all options & ORs  */
    *format = curr_ch;
    return FTPP_SUCCESS;
}

/*
 * Function: DoNextFormat(FTP_PARAM_FMT *ThisFmt, int allocated,
 *                 char *ErrorString, int ErrStrLen)
 *
 * Purpose: Processes the next FTP parameter validation node.
 *
 * Arguments: ThisFmt       => pointer to an FTP parameter validation node
 *            allocated     => indicator whether the next node is allocated
 *            ErrorString   => error string buffer
 *            ErrStrLen     => the length of the error string buffer
 *
 * Returns: int     => an error code integer (0 = success,
 *                     >0 = non-fatal error, <0 = fatal error)
 *
 */
int DoNextFormat(FTP_PARAM_FMT* ThisFmt, int allocated,
    char* ErrorString, int ErrStrLen)
{
    FTP_PARAM_FMT* NextFmt;
    int iRet = FTPP_SUCCESS;
    char* fmt = NextToken(CONF_SEPARATORS);

    if (!fmt)
        return FTPP_INVALID_ARG;

    if (!strcmp(END_CMD_FORMAT, fmt))
    {
        return FTPP_SUCCESS;
    }

    if (!strcmp(fmt, OR_FMT))
    {
        return FTPP_OR_FOUND;
    }

    if (!strcmp(fmt, END_OPT_FMT))
    {
        return FTPP_OPT_END_FOUND;
    }

    if (!strcmp(fmt, END_CHOICE_FMT))
    {
        return FTPP_CHOICE_END_FOUND;
    }

    if (!strcmp(fmt, START_OPT_FMT))
    {
        NextFmt = (FTP_PARAM_FMT*)calloc(1, sizeof(FTP_PARAM_FMT));
        if (NextFmt == NULL)
        {
            ParseError("Failed to allocate memory");
        }

        ThisFmt->optional_fmt = NextFmt;
        NextFmt->optional = 1;
        NextFmt->prev_param_fmt = ThisFmt;
        if (ThisFmt->optional)
            NextFmt->prev_optional = 1;
        iRet = DoNextFormat(NextFmt, 1, ErrorString, ErrStrLen);
        if (iRet != FTPP_OPT_END_FOUND)
        {
            return FTPP_INVALID_ARG;
        }

        return DoNextFormat(ThisFmt, 0, ErrorString, ErrStrLen);
    }

    if (!strcmp(fmt, START_CHOICE_FMT))
    {
        int numChoices = 1;
        do
        {
            FTP_PARAM_FMT** tmpChoices = (FTP_PARAM_FMT**)calloc(numChoices,
                sizeof(FTP_PARAM_FMT*));
            if (tmpChoices == NULL)
            {
                ParseError("Failed to allocate memory");
            }

            if (ThisFmt->numChoices)
            {
                /* explicit check that we have enough room for copy */
                if (numChoices <= ThisFmt->numChoices)
                    ParseError("Can't do memcpy - index out of range ");

                memcpy(tmpChoices, ThisFmt->choices,
                    sizeof(FTP_PARAM_FMT*) * ThisFmt->numChoices);
            }
            NextFmt = (FTP_PARAM_FMT*)calloc(1, sizeof(FTP_PARAM_FMT));
            if (NextFmt == NULL)
            {
                ParseError("Failed to allocate memory");
            }

            ThisFmt->numChoices = numChoices;
            tmpChoices[numChoices-1] = NextFmt;
            if (ThisFmt->choices)
                free(ThisFmt->choices);
            ThisFmt->choices = tmpChoices;
            NextFmt->prev_param_fmt = ThisFmt;
            iRet = DoNextFormat(NextFmt, 1, ErrorString, ErrStrLen);
            numChoices++;
        }
        while (iRet == FTPP_OR_FOUND);

        if (iRet != FTPP_CHOICE_END_FOUND)
        {
            return FTPP_INVALID_ARG;
        }

        return DoNextFormat(ThisFmt, 0, ErrorString, ErrStrLen);
    }

    if (!allocated)
    {
        NextFmt = (FTP_PARAM_FMT*)calloc(1, sizeof(FTP_PARAM_FMT));
        if (NextFmt == NULL)
        {
            ParseError("Failed to allocate memory");
        }

        NextFmt->prev_param_fmt = ThisFmt;
        ThisFmt->next_param_fmt = NextFmt;
        if (ThisFmt->optional)
            NextFmt->prev_optional = 1;
    }
    else
    {
        NextFmt = ThisFmt;
    }

    /* If its not an end cmd, OR, START/END Opt...
     * it must be a parameter specification.
     */
    /* Setup the type & format specs  */
    if (!strcmp(fmt, F_INT))
    {
        NextFmt->type = e_int;
    }
    else if (!strcmp(fmt, F_NUMBER))
    {
        NextFmt->type = e_number;
    }
    else if (!strcmp(fmt, F_CHAR))
    {
        char* chars_allowed = NextToken(CONF_SEPARATORS);
        NextFmt->type = e_char;
        NextFmt->format.chars_allowed = 0;
        while (*chars_allowed != 0)
        {
            int bitNum = (*chars_allowed & 0x1f);
            NextFmt->format.chars_allowed |= (1 << (bitNum-1));
            chars_allowed++;
        }
    }
    else if (!strcmp(fmt, F_DATE))
    {
        FTP_DATE_FMT* DateFmt;
        char* format = NextToken(CONF_SEPARATORS);
        NextFmt->type = e_date;
        DateFmt = (FTP_DATE_FMT*)calloc(1, sizeof(FTP_DATE_FMT));
        if (DateFmt == NULL)
        {
            ParseError("Failed to allocate memory");
        }

        NextFmt->format.date_fmt = DateFmt;
        iRet = ProcessDateFormat(DateFmt, NULL, &format);
        if (iRet)
        {
            snprintf(ErrorString, ErrStrLen,
                "Illegal format %s for token '%s'.",
                format, CMD_VALIDITY);

            return FTPP_INVALID_ARG;
        }
    }
    else if ( *fmt == *F_LITERAL )
    {
        char* end = strchr(++fmt, *F_LITERAL);
        int len = end ? end - fmt : 0;

        if ( len < 1 )
        {
            snprintf(
                ErrorString, ErrStrLen,
                "Illegal format '' for token '%s'.", CMD_VALIDITY
                );
            return FTPP_INVALID_ARG;
        }
        NextFmt->type = e_literal;
        NextFmt->format.literal = (char*)calloc(1, len+1);
        if ( !NextFmt->format.literal )
        {
            ParseError("Failed to allocate memory");
        }
        strncpy(NextFmt->format.literal, fmt, len);
        NextFmt->format.literal[len] = '\0';
    }
    else if (!strcmp(fmt, F_STRING))
    {
        NextFmt->type = e_unrestricted;
    }
    else if (!strcmp(fmt, F_HOST_PORT))
    {
        NextFmt->type = e_host_port;
    }
    else if (!strcmp(fmt, F_LONG_HOST_PORT))
    {
        NextFmt->type = e_long_host_port;
    }
    else if (!strcmp(fmt, F_EXTD_HOST_PORT))
    {
        NextFmt->type = e_extd_host_port;
    }
    else
    {
        snprintf(ErrorString, ErrStrLen,
            "Illegal format type %s for token '%s'.",
            fmt, CMD_VALIDITY);

        return FTPP_INVALID_ARG;
    }

    return DoNextFormat(NextFmt, 0, ErrorString, ErrStrLen);
}

/*
 * Function: ProcessFTPCmdValidity(FTP_SERVER_PROTO_CONF *ServerConf,
 *                              char *ErrorString, int ErrStrLen)
 *
 * Purpose: Process the ftp cmd validity configuration.
 *          This sets the FTP command parameter validation tree.
 *
 * Arguments: ServerConf    => pointer to the FTP server configuration
 *            confOption    => pointer to the name of the option
 *            ErrorString   => error string buffer
 *            ErrStrLen     => the length of the error string buffer
 *
 * Returns: int     => an error code integer (0 = success,
 *                     >0 = non-fatal error, <0 = fatal error)
 *
 */
int ProcessFTPCmdValidity(
    FTP_SERVER_PROTO_CONF* ServerConf,
    const char* cmd, const char* fmt,
    char* ErrorString, int ErrStrLen)
{
    FTP_CMD_CONF* FTPCmd = NULL;
    FTP_PARAM_FMT* HeadFmt = NULL;

    char buf[1024];
    strncpy(buf, fmt, sizeof(buf));
    buf[sizeof(buf)-1] = '\0';

    int iRet;
    fmt = mystrtok(buf, CONF_SEPARATORS);

    if (!fmt)
    {
        snprintf(ErrorString, ErrStrLen,
            "Invalid cmd validity format.");

        return FTPP_FATAL_ERR;
    }

    if (strcmp(START_CMD_FORMAT, fmt))
    {
        snprintf(ErrorString, ErrStrLen,
            "Must start a cmd validity with the '%s' token.",
            START_CMD_FORMAT);

        return FTPP_FATAL_ERR;
    }

    HeadFmt = (FTP_PARAM_FMT*)calloc(1, sizeof(FTP_PARAM_FMT));
    if (HeadFmt == NULL)
    {
        FatalError("Failed to allocate memory");
    }

    HeadFmt->type = e_head;

    iRet = DoNextFormat(HeadFmt, 0, ErrorString, ErrStrLen);

    /* Need to check to be sure we got a complete command  */
    if (iRet)
    {
        return FTPP_FATAL_ERR;
    }

    SetOptionalsNext(HeadFmt, NULL, NULL, 0);

    FTPCmd = ftp_cmd_lookup_find(ServerConf->cmd_lookup, cmd,
        strlen(cmd), &iRet);
    if (FTPCmd == NULL)
    {
        /* Add it to the list  */
        // note that struct includes 1 byte for null, so just add len
        FTPCmd = (FTP_CMD_CONF*)calloc(1, sizeof(FTP_CMD_CONF)+strlen(cmd));
        if (FTPCmd == NULL)
        {
            FatalError("Failed to allocate memory");
        }

        strcpy(FTPCmd->cmd_name, cmd);

        FTPCmd->max_param_len = ServerConf->def_max_param_len;
        ftp_cmd_lookup_add(ServerConf->cmd_lookup, cmd, strlen(cmd), FTPCmd);
    }

    FTPCmd->check_validity = 1;
    if (FTPCmd->param_format)
    {
        ftpp_ui_config_reset_ftp_cmd_format(FTPCmd->param_format);
        FTPCmd->param_format = NULL;
    }
    FTPCmd->param_format = HeadFmt;

    return FTPP_SUCCESS;
}

/*
 * Function:  ParseBounceTo(char *token, FTP_BOUNCE_TO*)
 *
 * Purpose: Extract the IP address, masking bits (CIDR format), and
 *          port information from an FTP Bounce To configuration.
 *
 * Arguments: token         => string pointer to the FTP bounce configuration
 *                             required format:  IP/CIDR,port[,portHi]\0
 *            FTP_BOUNCE_TO => populated with parsed data
 *
 * Returns:   int           => an error code integer (0 = success,
 *                             >0 = non-fatal error, <0 = fatal error)
 *
 */
int ParseBounceTo(char* token, FTP_BOUNCE_TO* bounce)
{
    char** toks;
    int num_toks;
    long int port_lo;
    char* endptr = NULL;
    sfip_t tmp_ip;

    toks = mSplit(token, ",", 3, &num_toks, 0);
    if (num_toks < 2)
        return FTPP_INVALID_ARG;

    if (sfip_pton(toks[0], &tmp_ip) != SFIP_SUCCESS)
    {
        mSplitFree(&toks, num_toks);
        return FTPP_INVALID_ARG;
    }

    memcpy(&bounce->ip, &tmp_ip, sizeof(sfip_t));

    port_lo = SnortStrtol(toks[1], &endptr, 10);
    if ((errno == ERANGE) || (*endptr != '\0') ||
        (port_lo < 0) || (port_lo >= MAXPORTS))
    {
        mSplitFree(&toks, num_toks);
        return FTPP_INVALID_ARG;
    }

    bounce->portlo = (unsigned short)port_lo;

    if (num_toks == 3)
    {
        long int port_hi = SnortStrtol(toks[2], &endptr, 10);

        if ((errno == ERANGE) || (*endptr != '\0') ||
            (port_hi < 0) || (port_hi >= MAXPORTS))
        {
            mSplitFree(&toks, num_toks);
            return FTPP_INVALID_ARG;
        }

        if (bounce->portlo != (unsigned short)port_hi)
        {
            bounce->porthi = (unsigned short)port_hi;
            if (bounce->porthi < bounce->portlo)
            {
                unsigned short tmp = bounce->porthi;
                bounce->porthi = bounce->portlo;
                bounce->portlo = tmp;
            }
        }
    }

    mSplitFree(&toks, num_toks);
    return FTPP_SUCCESS;
}

/* FIXIT: Maybe want to redo this with high-speed searcher for ip/port.
 * Would be great if we could handle both full addresses and
 * subnets quickly -- using CIDR format.  Need something that would
 * return most specific match -- ie a specific host is more specific
 * than subnet.
 */
int ProcessFTPAllowBounce(
    FTP_CLIENT_PROTO_CONF* ClientConf,
    const uint8_t* addr, unsigned len,
    Port low, Port high)
{
    FTP_BOUNCE_TO* newBounce =
        (FTP_BOUNCE_TO*)calloc(1, sizeof(FTP_BOUNCE_TO));

    if (newBounce == NULL)
    {
        ParseError("Failed to allocate memory for Bounce");
        return FTPP_FATAL_ERR;
    }
    sfip_set_raw(&newBounce->ip, addr, len == 4 ? AF_INET : AF_INET6);
    newBounce->portlo = low;
    newBounce->porthi = high;

    int iRet = ftp_bounce_lookup_add(
        ClientConf->bounce_lookup, &newBounce->ip, newBounce);

    if (iRet)
    {
        ParseError("Failed to add configuration for Bounce object '%s'.", ALLOW_BOUNCE);
        free(newBounce);
        return FTPP_FATAL_ERR;
    }

    return FTPP_SUCCESS;
}

