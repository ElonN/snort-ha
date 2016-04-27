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
 *
 * Description:
 *
 * This file wraps the FTPTelnet functionality for Snort
 * and starts the Normalization & Protocol checks.
 *
 * The file takes a Packet structure from the Snort IDS to start the
 * FTP/Telnet Normalization & Protocol checks.  It also uses the Stream
 * Interface Module which is also Snort-centric.  Mainly, just a wrapper
 * to FTP/Telnet functionality, but a key part to starting the basic flow.
 *
 * The main bulk of this file is taken up with user configuration and
 * parsing.  The reason this is so large is because FTPTelnet takes
 * very detailed configuration parameters for each specified FTP client,
 * to provide detailed control over an internal network and robust control
 * of the external network.
 */

#include "ft_main.h"

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
#include "utils/sfsnprintfappend.h"
#include "framework/data_bus.h"
#include "sfip/sf_ip.h"

#ifdef PERF_PROFILING
// FIXIT-M ftp, http, etc. should not be calling snort_detect()
static THREAD_LOCAL int ftppDetectCalled = 0;
static THREAD_LOCAL ProfileStats ftppDetectPerfStats;

void ft_update_perf(ProfileStats& stats)
{
    if (ftppDetectCalled)
    {
        stats.ticks -= ftppDetectPerfStats.ticks;
        /* And Reset ticks to 0 */
        ftppDetectPerfStats.ticks = 0;
        ftppDetectCalled = 0;
    }
}

#endif

void CleanupFTPCMDConf(void* ftpCmd)
{
    FTP_CMD_CONF* FTPCmd = (FTP_CMD_CONF*)ftpCmd;
    /* Free the FTP_PARAM_FMT stuff... */
    ftpp_ui_config_reset_ftp_cmd(FTPCmd);

    free(FTPCmd);
}

void CleanupFTPServerConf(void* serverConf)
{
    FTP_SERVER_PROTO_CONF* ServerConf = (FTP_SERVER_PROTO_CONF*)serverConf;
    if (ServerConf == NULL)
        return;

    /* Iterate through each cmd_lookup for this server */
#if 0
    int iRet = FTPP_SUCCESS;
    FTP_CMD_CONF* cmdConf = ftp_cmd_lookup_first(ServerConf->cmd_lookup, &iRet);

    while (cmdConf && (iRet == FTPP_SUCCESS))
    {
        if ( cmdConf->param_format )
        {
            free(cmdConf->param_format);
            cmdConf->param_format = nullptr;
        }
        cmdConf = ftp_cmd_lookup_next(ServerConf->cmd_lookup, &iRet);
    }
#endif
    ftp_cmd_lookup_cleanup(&ServerConf->cmd_lookup);
}

void CleanupFTPBounceTo(void* ftpBounce)
{
    FTP_BOUNCE_TO* FTPBounce = (FTP_BOUNCE_TO*)ftpBounce;
    free(FTPBounce);
}

void CleanupFTPClientConf(void* clientConf)
{
    FTP_CLIENT_PROTO_CONF* ClientConf = (FTP_CLIENT_PROTO_CONF*)clientConf;
    if (ClientConf == NULL)
        return;

    /* Iterate through each bounce_lookup for this client */
    ftp_bounce_lookup_cleanup(&ClientConf->bounce_lookup);
}

/*
 * Function: CheckFTPCmdOptions(FTP_SERVER_PROTO_CONF *serverConf)
 *
 * Purpose: This checks that the FTP configuration provided has
 *          options for CMDs that make sense:
 *          -- check if max_len == 0 & there is a cmd_validity
 *
 * Arguments: serverConf    => pointer to Server Configuration
 *
 * Returns: 0               => no errors
 *          1               => errors
 *
 */
int CheckFTPCmdOptions(FTP_SERVER_PROTO_CONF* serverConf)
{
    FTP_CMD_CONF* cmdConf;
    int iRet =0;
    int config_error = 0;

    cmdConf = ftp_cmd_lookup_first(serverConf->cmd_lookup, &iRet);
    while (cmdConf && (iRet == FTPP_SUCCESS))
    {
        size_t len = strlen(cmdConf->cmd_name);
        if ( len > serverConf->max_cmd_len )
            serverConf->max_cmd_len = len;

        len = cmdConf->max_param_len;
        if ( !len )
            len = serverConf->def_max_param_len;

        if ( cmdConf->check_validity && !len )
        {
            ErrorMessage("FTPConfigCheck() configuration for server, "
                "command '%s' has max length of 0 and parameters to validate\n",
                cmdConf->cmd_name);
            config_error = 1;
        }
        cmdConf = ftp_cmd_lookup_next(serverConf->cmd_lookup, &iRet);
    }

    return config_error;
}

/*
 * Function: CheckFTPServerConfigs(void)
 *
 * Purpose: This checks that the FTP server configurations are reasonable
 *
 * Arguments: None
 *
 * Returns: -1 on error
 *
 */
int CheckFTPServerConfigs(
    SnortConfig*, FTP_SERVER_PROTO_CONF* serverConf)
{
    if (CheckFTPCmdOptions(serverConf))
    {
        ErrorMessage("FTPConfigCheck(): invalid configuration for FTP commands\n");
        return -1;
    }
    return 0;
}

/*
 * Function: FTPConfigCheck(void)
 *
 * Purpose: This checks that the FTP configuration provided includes
 *          the default configurations for Server & Client.
 *
 * Arguments: None
 *
 * Returns: None
 *
 */
// FIXIT-L eliminate legacy void* cruft
int FTPCheckConfigs(SnortConfig* sc, void* pData)
{
    FTP_SERVER_PROTO_CONF* config = (FTP_SERVER_PROTO_CONF*)pData;

    if ( !config )
    {
        ErrorMessage("FTP configuration requires "
            "default client and default server configurations.\n");
        return -1;
    }
#if 0
    if ( file_api->get_max_file_depth() < 0 )
    {
        // FIXIT-M need to change to IT_SERVICE and FTPTelnetChecks
        // for optimization
    }
#endif
    int rval;
    if ((rval = CheckFTPServerConfigs(sc, config)))
        return rval;

    return 0;
}

/*
 * Function: do_detection(Packet *p)
 *
 * Purpose: This is the routine that directly performs the rules checking
 *          for each of the FTP & telnet preprocessing modules.
 *
 * Arguments: p             => pointer to the packet structure
 *
 * Returns: None
 *
 */
void do_detection(Packet* p)
{
    PROFILE_VARS;

    /*
     * If we get here we either had a client or server request/response.
     * We do the detection here, because we're starting a new paradigm
     * about protocol decoders.
     *
     * Protocol decoders are now their own detection engine, since we are
     * going to be moving protocol field detection from the generic
     * detection engine into the protocol module.  This idea scales much
     * better than having all these Packet struct field checks in the
     * main detection engine for each protocol field.
     */
    MODULE_PROFILE_START(ftppDetectPerfStats);
    get_data_bus().publish(PACKET_EVENT, p);

    DisableInspection(p);
    MODULE_PROFILE_END(ftppDetectPerfStats);
#ifdef PERF_PROFILING
    ftppDetectCalled = 1;
#endif
}

