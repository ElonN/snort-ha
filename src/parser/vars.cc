//--------------------------------------------------------------------------
// Copyright (C) 2014-2015 Cisco and/or its affiliates. All rights reserved.
// Copyright (C) 2013-2013 Sourcefire, Inc.
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

#include "vars.h"

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <sys/types.h>
#include <sys/stat.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <errno.h>
#include <ctype.h>
#include <unistd.h>
#include <stdarg.h>
#include <pcap.h>
#include <grp.h>
#include <pwd.h>
#include <fnmatch.h>

#include "config_file.h"
#include "parser/parser.h"
#include "cmd_line.h"
#include "parse_ports.h"

#include "main/snort_debug.h"
#include "main/snort_config.h"
#include "detection/rules.h"
#include "detection/treenodes.h"
#include "detection/detect.h"
#include "detection/tag.h"
#include "detection/signature.h"
#include "detection/sfrim.h"
#include "utils/util.h"
#include "utils/snort_bounds.h"
#include "utils/sflsq.h"
#include "ports/port_object.h"
#include "protocols/packet.h"
#include "filters/sfthreshold.h"
#include "filters/sfthd.h"
#include "filters/rate_filter.h"
#include "filters/detection_filter.h"
#include "hash/sfghash.h"
#include "sfip/sf_vartable.h"
#include "sfip/sf_ip.h"
#include "sfip/sf_ipvar.h"
#include "time/ppm.h"
#include "packet_io/active.h"
#include "file_api/libs/file_config.h"
#include "framework/ips_option.h"

#ifdef UNIT_TEST
#include "test/catch.hpp"
#endif

//-------------------------------------------------------------------------
// var node stuff
//-------------------------------------------------------------------------

void config_set_var(SnortConfig* sc, const char* val)
{
    {
        const char* equal_ptr = strchr(val, '=');
        VarNode* node;

        if (equal_ptr == NULL)
        {
            ParseError("Format for command line variable definitions "
                "is:\n -S var=value\n");
            return;
        }

        /* Save these and parse when snort conf is parsed so
         * they can be added to the snort conf configuration */
        node = (VarNode*)SnortAlloc(sizeof(VarNode));
        node->name = SnortStrndup(val, equal_ptr - val);

        /* Make sure it's not already in the list */
        if (sc->var_list != NULL)
        {
            VarNode* tmp = sc->var_list;

            while (tmp != NULL)
            {
                if (strcasecmp(tmp->name, node->name) == 0)
                {
                    ParseError("Duplicate variable name: %s.\n",
                        tmp->name);
                    return;
                }

                tmp = tmp->next;
            }
        }

        node->value = SnortStrdup(equal_ptr + 1);
        node->line = SnortStrdup(val);
        node->next = sc->var_list;
        sc->var_list = node;

        /* Put line in a parser parsable form - we know the
         * equals is already there */
        *strchr(node->line, '=') = ' ';
    }
}

void FreeVarList(VarNode* head)
{
    while (head != NULL)
    {
        VarNode* tmp = head;

        head = head->next;

        if (tmp->name != NULL)
            free(tmp->name);

        if (tmp->value != NULL)
            free(tmp->value);

        if (tmp->line != NULL)
            free(tmp->line);

        free(tmp);
    }
}

//-------------------------------------------------------------------------
// var table stuff
//-------------------------------------------------------------------------

/*
 * PortVarDefine
 *
 *  name - portlist name, i.e. http, smtp, ...
 *  s    - port number, port range, or a list of numbers/ranges in brackets
 *
 *  examples:
 *  portvar http [80,8080,8138,8700:8800,!8711]
 *  portvar http $http_basic
 */
int PortVarDefine(SnortConfig* sc, const char* name, const char* s)
{
    PortObject* po;
    POParser pop;
    int rstat;
    PortVarTable* portVarTable = get_ips_policy()->portVarTable;

    DisallowCrossTableDuplicateVars(sc, name, VAR_TYPE__PORTVAR);

    if ( SnortStrcasestr(s,strlen(s),"any") ) /* this allows 'any' or '[any]' */
    {
        if (strstr(s,"!"))
        {
            ParseError("illegal use of negation and 'any': %s.", s);
        }

        po = PortObjectNew();
        if ( !po )
        {
            ParseAbort("PortVarTable missing an 'any' variable.");
        }
        PortObjectSetName(po, name);
        PortObjectAddPortAny(po);
    }
    else
    {
        /* Parse the Port List info into a PortObject  */
        po = PortObjectParseString(portVarTable, &pop, name, s, 0);
        if (!po)
        {
            const char* errstr = PortObjectParseError(&pop);
            ParseAbort("PortVar Parse error: (pos=%d,error=%s)\n>>%s\n>>%*s.",
                pop.pos,errstr,s,pop.pos,"^");
        }
    }

    /* Add The PortObject to the PortList Table */
    rstat = PortVarTableAdd(portVarTable, po);
    if ( rstat < 0 )
    {
        ParseError("PortVarTableAdd failed with '%s', exiting.", po->name);
    }
    else if ( rstat > 0 )
    {
        ParseWarning(WARN_VARS, "PortVar '%s', already defined.", po->name);
    }

#if 0
    LogMessage("PortVar '%s' defined : ",po->name);
    PortObjectPrintPortsRaw(po);
    LogMessage("\n");
#endif

    return 0;
}

/****************************************************************************
 *
 * Function: VarAlloc()
 *
 * Purpose: allocates memory for a variable
 *
 * Arguments: none
 *
 * Returns: pointer to new VarEntry
 *
 ***************************************************************************/
VarEntry* VarAlloc()
{
    VarEntry* pve;

    pve = (VarEntry*)SnortAlloc(sizeof(VarEntry));

    return( pve);
}

/****************************************************************************
 *
 * Function: VarIsIpAddr(char *, char *)
 *
 * Purpose: Checks if a var is an IP address. Necessary since moving forward
 *          we want all IP addresses handled by the IP variable table.
 *          If a list is given, this checks each value.
 *
 * Arguments: value => the string to check
 *
 * Returns: 1 if IP address, 0 otherwise
 *
 ***************************************************************************/
int VarIsIpAddr(vartable_t* ip_vartable, const char* value)
{
    const char* tmp;

    /* empty list, consider this an IP address */
    if ((*value == '[') && (*(value+1) == ']'))
        return 1;

    while (*value == '!' || *value == '[')
        value++;

    /* Check for dotted-quad */
    if ( isdigit((int)*value) &&
        ((tmp = strchr(value, (int)'.')) != NULL) &&
        ((tmp = strchr(tmp+1, (int)'.')) != NULL) &&
        (strchr(tmp+1, (int)'.') != NULL))
        return 1;

    /* IPv4 with a mask, and fewer than 4 fields */
    else if ( isdigit((int)*value) &&
        (strchr(value+1, (int)':') == NULL) &&
        ((tmp = strchr(value+1, (int)'/')) != NULL) &&
        isdigit((int)(*(tmp+1))) )
        return 1;

    /* IPv6 */
    else if ((tmp = strchr(value, (int)':')) != NULL)
    {
        const char* tmp2;

        if ((tmp2 = strchr(tmp+1, (int)':')) == NULL)
            return 0;

        for (tmp++; tmp < tmp2; tmp++)
            if (!isxdigit((int)*tmp))
                return 0;

        return 1;
    }
    /* Any */
    else if (!strncmp(value, "any", 3))
        return 1;

    /* Check if it's a variable containing an IP */
    else if (sfvt_lookup_var(ip_vartable, value+1) || sfvt_lookup_var(ip_vartable, value))
        return 1;

    return 0;
}

/****************************************************************************
 *
 * Function: CheckBrackets(char *)
 *
 * Purpose: Check that the brackets match up in a string that
 *          represents a list.
 *
 * Arguments: value => the string to check
 *
 * Returns: 1 if the brackets match correctly, 0 otherwise
 *
 ***************************************************************************/
static int CheckBrackets(char* value)
{
    int num_brackets = 0;

    while (*value == '!')
        value++;

    if ((value[0] != '[') || value[strlen(value)-1] != ']')
    {
        /* List does not begin or end with a bracket. */
        return 0;
    }

    while ((*value != '\0') && (num_brackets >= 0))
    {
        if (*value == '[')
            num_brackets++;
        else if (*value == ']')
            num_brackets--;
        value++;
    }
    if (num_brackets != 0)
    {
        /* Mismatched brackets */
        return 0;
    }

    return 1;
}

/****************************************************************************
 *
 * Function: VarIsIpList(vartable_t *, char*)
 *
 * Purpose: Checks if a var is a list of IP addresses.
 *
 * Arguments: value => the string to check
 *
 * Returns: 1 if each item is an IP address, 0 otherwise
 *
 ***************************************************************************/
int VarIsIpList(vartable_t* ip_vartable, const char* value)
{
    char* copy, * item;
    int item_is_ip = 1;

    copy = SnortStrdup((const char*)value);

    /* Ensure that the brackets are correct. */
    if (strchr((const char*)copy, ','))
    {
        /* This is a list! */
        if (CheckBrackets(copy) == 0)
        {
            free(copy);
            return 0;
        }
    }

    /* There's no need to worry about the list structure here.
     * We just strip out the IP delimiters and process each one. */
    char* lasts = nullptr;
    item = strtok_r(copy, "[],!", &lasts);
    while ((item != NULL) && item_is_ip)
    {
        item_is_ip = VarIsIpAddr(ip_vartable, item);
        item = strtok_r(NULL, "[],!", &lasts);
    }

    free(copy);
    return item_is_ip;
}

/****************************************************************************
 *
 * Function: DisallowCrossTableDuplicateVars(char *, int)
 *
 * Purpose: ParseErrors if the a variable name is redefined across variable
 *          types.  Enforcing this mutual exclusion prevents the
 *          catatrophe where the variable lookup fall-through (see VarSearch)
 *          finds an unintended variable from the wrong table.  Note:  VarSearch
 *          is only necessary for ExpandVars.
 *
 * Arguments: name => The name of the variable
 *            var_type => The type of the variable that is about to be defined.
 *                        The corresponding variable table will not be searched.
 *
 * Returns: void function
 *
 ***************************************************************************/
void DisallowCrossTableDuplicateVars(
    SnortConfig*, const char* name, VarType var_type)
{
    IpsPolicy* dp = get_ips_policy();
    VarEntry* var_table = dp->var_table;
    PortVarTable* portVarTable = dp->portVarTable;
    vartable_t* ip_vartable = dp->ip_vartable;
    VarEntry* p = var_table;

    /* If this is a faked Portvar, treat as a portvar */
    if ((var_type == VAR_TYPE__DEFAULT) &&
        (strstr(name, "_PORT") || strstr(name, "PORT_")))
    {
        var_type = VAR_TYPE__PORTVAR;
    }

    switch (var_type)
    {
    case VAR_TYPE__DEFAULT:
        if (PortVarTableFind(portVarTable, name)
            || sfvt_lookup_var(ip_vartable, name)
            )
        {
            ParseError("can not redefine variable name %s to be of type "
                "'var'. Use a different name.", name);
        }
        break;

    case VAR_TYPE__PORTVAR:
        if (var_table != NULL)
        {
            do
            {
                if (strcasecmp(p->name, name) == 0)
                {
                    ParseError("can not redefine variable name %s to be of "
                        "type 'portvar'. Use a different name.", name);
                }
                p = p->next;
            }
            while (p != var_table);
        }

        if (sfvt_lookup_var(ip_vartable, name))
        {
            ParseError("can not redefine variable name %s to be of type "
                "'portvar'. Use a different name.", name);
        }

        break;

    case VAR_TYPE__IPVAR:
        if (var_table != NULL)
        {
            do
            {
                if (strcasecmp(p->name, name) == 0)
                {
                    ParseError("can not redefine variable name %s to be of "
                        "type 'ipvar'. Use a different name.", name);
                }

                p = p->next;
            }
            while (p != var_table);
        }

        if (PortVarTableFind(portVarTable, name))
        {
            ParseError("can not redefine variable name %s to be of type "
                "'ipvar'. Use a different name.", name);
        }

    default:
        /* Invalid function usage */
        break;
    }
}

/****************************************************************************
 *
 * Function: VarDefine(char *, char *)
 *
 * Purpose: define the contents of a variable
 *
 * Arguments: name => the name of the variable
 *            value => the contents of the variable
 *
 * Returns: void function
 *
 ***************************************************************************/
VarEntry* VarDefine(
    SnortConfig* sc, const char* name, const char* value)
{
    IpsPolicy* dp = get_ips_policy();
    VarEntry* var_table = dp->var_table;
    vartable_t* ip_vartable = dp->ip_vartable;
    VarEntry* p;
    uint32_t var_id = 0;

    if (value == NULL)
    {
        ParseAbort("bad value in variable definition.  Make sure you don't "
            "have a '$' in the var name.");
    }

    if (VarIsIpList(ip_vartable, value))
    {
        SFIP_RET ret;

        if (ip_vartable == NULL)
            return NULL;

        /* Verify a variable by this name is not already used as either a
         * portvar or regular var.  Enforcing this mutual exclusion prevents the
         * catatrophe where the variable lookup fall-through (see VarSearch)
         * finds an unintended variable from the wrong table.  Note:  VarSearch
         * is only necessary for ExpandVars. */
        DisallowCrossTableDuplicateVars(sc, name, VAR_TYPE__IPVAR);

        if ((ret = sfvt_define(ip_vartable, name, value)) != SFIP_SUCCESS)
        {
            switch (ret)
            {
            case SFIP_ARG_ERR:
                ParseAbort("the following is not allowed: %s.", value);
                break;

            case SFIP_DUPLICATE:
                ParseWarning(WARN_VARS, "Var '%s' redefined.", name);
                break;

            case SFIP_CONFLICT:
                ParseAbort("negated IP ranges that are more general than "
                    "non-negated ranges are not allowed. Consider "
                    "inverting the logic in %s.", name);
                break;

            case SFIP_NOT_ANY:
                ParseAbort("!any is not allowed in %s", name);
                break;

            default:
                ParseAbort("failed to parse the IP address: %s.", value);
            }
        }
        return NULL;
    }
    /* Check if this is a variable that stores an IP */
    else if (*value == '$')
    {
        sfip_var_t* var;
        if ((var = sfvt_lookup_var(ip_vartable, value)) != NULL)
        {
            sfvt_define(ip_vartable, name, value);
            return NULL;
        }
    }

    DebugFormat(DEBUG_PORTLISTS,
        "VarDefine: name=%s value=%s\n",name,value);

    /* Check to see if this variable is just being aliased */
    if (var_table != NULL)
    {
        VarEntry* tmp = var_table;

        do
        {
            /* value+1 to move past $ */
            if (strcmp(tmp->name, value+1) == 0)
            {
                var_id = tmp->id;
                break;
            }

            tmp = tmp->next;
        }
        while (tmp != var_table);
    }

    value = ExpandVars(sc, value);
    if (!value)
    {
        ParseAbort("could not expand var('%s').", name);
    }

    DebugFormat(DEBUG_PORTLISTS,
        "VarDefine: name=%s value=%s (expanded)\n",name,value);

    DisallowCrossTableDuplicateVars(sc, name, VAR_TYPE__DEFAULT);

    if (var_table == NULL)
    {
        p = VarAlloc();
        p->name  = SnortStrdup(name);
        p->value = SnortStrdup(value);

        p->prev = p;
        p->next = p;

        dp->var_table = p;

        p->id = dp->var_id++;

        return p;
    }

    /* See if an existing variable is being redefined */
    p = var_table;

    do
    {
        if (strcasecmp(p->name, name) == 0)
        {
            if (p->value != NULL)
                free(p->value);

            p->value = SnortStrdup(value);
            ParseWarning(WARN_VARS, "Var '%s' redefined\n", p->name);
            return p;
        }

        p = p->next;
    }
    while (p != var_table);     /* List is circular */

    p = VarAlloc();
    p->name  = SnortStrdup(name);
    p->value = SnortStrdup(value);
    p->prev = var_table;
    p->next = var_table->next;
    p->next->prev = p;
    var_table->next = p;

    if (!var_id)
        p->id = dp->var_id++;
    else
        p->id = var_id;

#ifdef XXXXXXX
    vlen = strlen(value);
    LogMessage("Var '%s' defined, value len = %d chars", p->name, vlen);

    if ( vlen < 64 )
    {
        LogMessage(", value = %s\n", value);
    }
    else
    {
        LogMessage("\n");
        n = 128;
        s = value;
        while (vlen)
        {
            if ( n > vlen )
                n = vlen;
            LogMessage("   %.*s\n", n, s);
            s    += n;
            vlen -= n;
        }
    }
#endif

    return p;
}

void DeleteVars(VarEntry* var_table)
{
    VarEntry* q, * p = var_table;

    while (p)
    {
        q = p->next;
        if (p->name)
            free(p->name);
        if (p->value)
            free(p->value);
        if (p->addrset)
        {
            sfvar_free(p->addrset);
        }
        free(p);
        p = q;
        if (p == var_table)
            break;  /* Grumble, it's a friggin circular list */
    }
}

const char* VarSearch(SnortConfig* sc, const char* name)
{
    IpsPolicy* dp = get_ips_policy();
    VarEntry* var_table = dp->var_table;
    PortVarTable* portVarTable = dp->portVarTable;
    vartable_t* ip_vartable = dp->ip_vartable;
    sfip_var_t* ipvar;

    if ((ipvar = sfvt_lookup_var(ip_vartable, name)) != NULL)
        return ExpandVars(sc, ipvar->value);

    /* XXX Return a string value */
    if (PortVarTableFind(portVarTable, name))
        return name;

    if (var_table != NULL)
    {
        VarEntry* p = var_table;
        do
        {
            if (strcasecmp(p->name, name) == 0)
                return p->value;
            p = p->next;
        }
        while (p != var_table);
    }

    return NULL;
}

/****************************************************************************
 *
 * Function: VarGet(SnortConfig *, char *)
 *
 * Purpose: get the contents of a variable
 *
 * Arguments: name => the name of the variable
 *
 * Returns: char * to contents of variable or ParseErrors on an
 *          undefined variable name
 *
 ***************************************************************************/
const char* VarGet(SnortConfig*, const char* name)
{
    IpsPolicy* dp = get_ips_policy();
    VarEntry* var_table = dp->var_table;
    vartable_t* ip_vartable = dp->ip_vartable;
    sfip_var_t* var;

// XXX-IPv6 This function should never be used if IP6 support is enabled!
// Infact it won't presently even work for IP variables since the raw ASCII
// value is never stored, and is never meant to be used.

    if ((var = sfvt_lookup_var(ip_vartable, name)) == NULL)
    {
        /* Do the old style lookup since it wasn't found in
         * the variable table */
        if (var_table != NULL)
        {
            VarEntry* p = var_table;
            do
            {
                if (strcasecmp(p->name, name) == 0)
                    return p->value;
                p = p->next;
            }
            while (p != var_table);
        }

        ParseError("undefined variable name: %s.", name);
    }

    return name;
}

/****************************************************************************
 *
 * Function: ExpandVars()
 *
 * Purpose: expand all variables in a string
 *
 * Arguments:
 *  SnortConfig *
 *      The snort config that has the vartables.
 *  char *
 *      The name of the variable.
 *
 * Returns:
 *  char *
 *      The expanded string.  Note that the string is returned in a
 *      static variable and most likely needs to be string dup'ed.
 *
 ***************************************************************************/
const char* ExpandVars(SnortConfig* sc, const char* string)
{
    static char estring[ 65536 ];  // FIXIT-L convert this foo to a std::string

    char rawvarname[128], varname[128], varaux[128], varbuffer[128];
    char varmodifier;
    const char* varcontents;
    int varname_completed, c, i, j, iv, jv, l_string, name_only;
    int quote_toggle = 0;

    if (!string || !*string || !strchr(string, '$'))
        return(string);

    memset((char*)estring, 0, sizeof(estring));

    i = j = 0;
    l_string = strlen(string);
    DebugFormat(DEBUG_CONFIGRULES, "ExpandVars, Before: %s\n", string);

    while (i < l_string && j < (int)sizeof(estring) - 1)
    {
        c = string[i++];

        if (c == '"')
        {
            /* added checks to make sure that we are inside a quoted string
             */
            quote_toggle ^= 1;
        }

        if (c == '$' && !quote_toggle)
        {
            memset((char*)rawvarname, 0, sizeof(rawvarname));
            varname_completed = 0;
            name_only = 1;
            iv = i;
            jv = 0;

            if (string[i] == '(')
            {
                name_only = 0;
                iv = i + 1;
            }

            while (!varname_completed
                && iv < l_string
                && jv < (int)sizeof(rawvarname) - 1)
            {
                c = string[iv++];

                if ((name_only && !(isalnum(c) || c == '_'))
                    || (!name_only && c == ')'))
                {
                    varname_completed = 1;

                    if (name_only)
                        iv--;
                }
                else
                {
                    rawvarname[jv++] = (char)c;
                }
            }

            if (varname_completed || iv == l_string)
            {
                char* p;

                i = iv;

                varcontents = NULL;

                memset((char*)varname, 0, sizeof(varname));
                memset((char*)varaux, 0, sizeof(varaux));
                varmodifier = ' ';

                p = strchr(rawvarname, ':');
                if (p)
                {
                    SnortStrncpy(varname, rawvarname, p - rawvarname);

                    if (strlen(p) >= 2)
                    {
                        varmodifier = *(p + 1);
                        SnortStrncpy(varaux, p + 2, sizeof(varaux));
                    }
                }
                else
                    SnortStrncpy(varname, rawvarname, sizeof(varname));

                memset((char*)varbuffer, 0, sizeof(varbuffer));

                varcontents = VarSearch(sc, varname);

                switch (varmodifier)
                {
                case '-':
                    if (!varcontents || !strlen(varcontents))
                        varcontents = varaux;
                    break;

                case '?':
                    if (!varcontents || !strlen(varcontents))
                    {
                        if (strlen(varaux))
                            ParseAbort("%s", varaux);
                        else
                            ParseAbort("undefined variable '%s'.", varname);
                    }
                    break;
                }

                /* If variable not defined now, we're toast */
                if (!varcontents || !strlen(varcontents))
                    ParseAbort("undefined variable name: %s.", varname);

                if (varcontents)
                {
                    int l_varcontents = strlen(varcontents);

                    iv = 0;

                    while (iv < l_varcontents && j < (int)sizeof(estring) - 1)
                        estring[j++] = varcontents[iv++];
                }
            }
            else
            {
                estring[j++] = '$';
            }
        }
        else
        {
            estring[j++] = (char)c;
        }
    }

    DebugFormat(DEBUG_CONFIGRULES, "ExpandVars, After: %s\n", estring);

    return estring;
}

void AddVarToTable(SnortConfig* sc, const char* name, const char* value)
{
    //TODO: snort.cfg and rules should use PortVar instead ...this allows compatability for now.
    if (strstr(name, "_PORT") || strstr(name, "PORT_"))
    {
        DebugMessage(DEBUG_CONFIGRULES,"PortVar\n");
        PortVarDefine(sc, name, value);
    }
    else
    {
        VarDefine(sc, name, value);
    }
}

//--------------------------------------------------------------------------
// unit tests 
//--------------------------------------------------------------------------

#ifdef UNIT_TEST

TEST_CASE("config_set_var-success", "[vars]")
{
    SnortConfig* sc = new SnortConfig;

    sc->var_list = NULL;

    config_set_var(sc, "A=B");

    REQUIRE(sc->var_list != NULL);
    REQUIRE(sc->var_list->name != NULL);
    REQUIRE(sc->var_list->value != NULL);
    REQUIRE(*(sc->var_list->name) == 'A');
    REQUIRE(*(sc->var_list->value) == 'B');
}

TEST_CASE("config_set_var-existing-success", "[vars]")
{
    SnortConfig* sc = new SnortConfig;
    VarNode* vn1 = new VarNode;
    VarNode* vn2 = new VarNode;

    sc->var_list = vn1;
    vn1->name = (char*)"C";
    vn1->next = vn2;
    vn2->name = (char*)"D";
    vn2->next = NULL;

    config_set_var(sc, "A=B");

    REQUIRE(sc->var_list != NULL);
    REQUIRE(sc->var_list->name != NULL);
    REQUIRE(sc->var_list->value != NULL);
    REQUIRE(*(sc->var_list->name) == 'A');
    REQUIRE(*(sc->var_list->value) == 'B');
}

TEST_CASE("config_set_var-duplicate-error", "[vars]")
{
    SnortConfig* sc = new SnortConfig;
    VarNode* vn1 = new VarNode;
    VarNode* vn2 = new VarNode;

    sc->var_list = vn1;
    vn1->name = (char*)"C";
    vn1->next = vn2;
    vn2->name = (char*)"A";
    vn2->next = NULL;

    config_set_var(sc, "A=B");
}

TEST_CASE("config_set_var-no_equals_sign-error", "[vars]")
{
    SnortConfig* sc = new SnortConfig;

    config_set_var(sc, "A");
}

#endif
