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

#include "parse_ip.h"

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <netdb.h>
#include <ctype.h>
#include <sys/types.h>

#include "parser.h"
#include "main/snort_debug.h"
#include "sfip/sf_vartable.h"
#include "sfip/sf_ipvar.h"
#include "utils/util.h"

sfip_var_t* sfip_var_from_string(const char* addr)
{
    sfip_var_t* ret;
    int ret_code;
    vartable_t* ip_vartable;

    ip_vartable = get_ips_policy()->ip_vartable;

    DebugFormat(DEBUG_CONFIGRULES,"Got address string: %s\n", addr);

    ret = (sfip_var_t*)SnortAlloc(sizeof(sfip_var_t));

    if ((ret_code = sfvt_add_to_var(ip_vartable, ret, addr)) != SFIP_SUCCESS)
    {
        if (ret_code == SFIP_LOOKUP_FAILURE)
        {
            ParseError("Undefined variable in the string: %s", addr);
            return ret;
        }
        else if (ret_code == SFIP_CONFLICT)
        {
            ParseError("Negated IP ranges that equal to or are"
                " more-specific than non-negated ranges are not allowed."
                " Consider inverting the logic: %s.", addr);
            return ret;
        }
        else
        {
            ParseError("Unable to process the IP address: %s", addr);
            return ret;
        }
    }

    return ret;
}

