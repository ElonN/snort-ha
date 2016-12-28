//--------------------------------------------------------------------------
// Copyright (C) 2014-2015 Cisco and/or its affiliates. All rights reserved.
// Copyright (C) 2005-2013 Sourcefire, Inc.
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

#include "parse_ports.h"
#include "ports/port_table.h"
#include "main/snort_debug.h"
#include "utils/snort_bounds.h"
#include "utils/util.h"

static int POParserInit(POParser* pop, const char* s, PortVarTable* pvTable)
{
    memset(pop,0,sizeof(POParser));
    pop->pos     = 0;
    pop->s       = s;
    pop->slen    = strlen(s);
    pop->errflag = 0;
    pop->pvTable = pvTable;

    return 0;
}

/*
    Get a Char
*/
static int POPGetChar(POParser* pop)
{
    int c;
    if ( pop->slen > 0 )
    {
        c = pop->s[0];
        pop->slen--;
        pop->s++;
        pop->pos++;
        DebugFormat(DEBUG_PORTLISTS,"GetChar: %c, %d bytes left\n",c, pop->slen);
        return c;
    }
    return 0;
}

/*
   Skip whitespace till we find a non-whitespace char
*/
static int POPGetChar2(POParser* pop)
{
    int c;
    for (;; )
    {
        c=POPGetChar(pop);
        if ( !c )
            return 0;

        if ( isspace(c) || c==',' )
            continue;

        break;
    }
    return c;
}

/*
   Restore last char
*/
static void POPUnGetChar(POParser* pop)
{
    if ( pop->pos > 0 )
    {
        pop->slen++;
        pop->s--;
        pop->pos--;
    }
}

/*
  Peek at next char
*/
static int POPPeekChar(POParser* pop)
{
    if ( pop->slen > 0)
    {
        return pop->s[0];
    }
    return 0;
}

#ifdef XXXX
/* copy a simple alpha string */
static void POPeekString(POParser* p, char* s, int smax)
{
    int c;
    int cnt = 0;
    int k = p->slen;

    smax--;

    s[0] = 0;

    while ( k > 0  && cnt < smax )
    {
        c = p->s[ cnt ];

        if ( c ==  0     )
            break;
        if ( !isalpha(c) )
            break;

        s[ cnt++ ] = c;
        s[ cnt   ] = 0;
        k--;
    }
}

static void POGetString(POParser* p, char* s, int smax)
{
    int c;
    int cnt = 0;

    smax--;

    s[0] = 0;

    while ( p->slen > 0  && cnt < smax )
    {
        c = p->s[ 0 ];

        if ( c ==  0     )
            break;
        if ( !isalpha(c) )
            break;

        s[ cnt++ ] = c;
        s[ cnt   ] = 0;
        p->slen--;
        p->s++;
    }
}

#endif

/*
   Skip whitespace : ' ', '\t', '\n'
*/
static int POPSkipSpace(POParser* p)
{
    int c;
    for ( c  = POPPeekChar(p);
        c != 0;
        c  = POPPeekChar(p) )
    {
        if ( !isspace(c) && c != ',' )
            return c;

        POPGetChar(p);
    }
    return 0;
}

/*
  Get the Port Object Name
*/
static char* POParserName(POParser* pop)
{
    int k = 0;
    int c;

    /* check if were done  */
    if ( !pop || !pop->s || !*(pop->s) )
        return 0;

    /* Start the name - skip space */
    c = POPGetChar2(pop);
    if ( !c )
        return 0;

    if ( c== '$' ) /* skip leading '$' - old Var indicator */
    {
        c = POPGetChar2(pop);
        if ( !c )
            return 0;
    }

    if ( isalnum(c) )
    {
        pop->token[k++] = (char)c;
        pop->token[k]   = (char)0;
    }
    else
    {
        POPUnGetChar(pop);
        return 0; /* not a name */
    }

    for ( c  = POPGetChar(pop);
        c != 0 && k < POP_MAX_BUFFER_SIZE;
        c  = POPGetChar(pop) )
    {
        if ( isalnum(c) || c== '_' || c=='-' || c=='.' )
        {
            pop->token[k++] = (char)c;
            pop->token[k]   = (char)0;
        }
        else
        {
            POPUnGetChar(pop);
            break;
        }
    }

    DebugFormat(DEBUG_PORTLISTS,">>> POParserName : %s\n",pop->token);

    return SnortStrdup(pop->token);
}

/*
*   Read an unsigned short (a port)
*/
static uint16_t POParserGetShort(POParser* pop)
{
    int c;
    int k = 0;
    char buffer[32];
    char* pend;

    POPSkipSpace(pop);

    buffer[0] = 0;

    while ( (c = POPGetChar(pop)) != 0 )
    {
        if ( isdigit(c) )
        {
            buffer[k++]=(char)c;
            buffer[k]  =0;
            if ( k == sizeof(buffer)-1 )
                break;                         /* thats all that fits */
        }
        else
        {
            if ( c && ( c!= ':' && c != ' ' && c != ']' && c != ',' && c != '\t' && c != '\n' ) )
            {
                pop->errflag = POPERR_NOT_A_NUMBER;
                return 0;
            }
            POPUnGetChar(pop);
            break;
        }
    }

    c  = (int)strtoul(buffer,&pend,10);

    if (c > 65535 || c < 0)
    {
        pop->errflag = POPERR_BOUNDS;
        return 0;
    }

    DebugFormat(DEBUG_PORTLISTS,"GetUNumber: %d\n",c);

    return c;
}

static PortObject* _POParseVar(POParser* pop)
{
    PortObject* pox;
    char* name;

    name  = POParserName(pop);

    if (!name)
    {
        pop->pos++;
        pop->errflag = POPERR_NO_NAME;
        return NULL;
    }

    pox = PortVarTableFind(pop->pvTable, name);
    free(name);

    if (!pox)
    {
        pop->errflag = POPERR_BAD_VARIABLE;
        return NULL;
    }

    pox = PortObjectDup(pox);

    if (!pox)
    {
        pop->errflag = POPERR_MALLOC_FAILED;
        return NULL;
    }

    return pox;
}

static PortObject* _POParsePort(POParser* pop)
{
    uint16_t hport, lport;
    char c;
    PortObject* po = PortObjectNew();

    if (!po)
    {
        pop->errflag = POPERR_MALLOC_FAILED;
        return NULL;
    }

    pop->token[0]=0;

    /* The string in pop should only be of the form <port> or <port>:<port> */
    lport = POParserGetShort(pop);

    if (pop->errflag)
    {
        PortObjectFree(po);
        return NULL;
    }

    c = POPPeekChar(pop);

    if ( c == ':' ) /* half open range */
    {
        POPGetChar(pop);
        c = POPPeekChar(pop);

        if (((c == 0) && (pop->slen == 0)) ||
            (c == ','))
        {
            /* Open ended range, highport is 65k */
            hport = MAXPORTS-1;
            PortObjectAddRange(po, lport, hport, 0);
            return po;
        }

        if ( !isdigit((int)c) ) /* not a number */
        {
            pop->errflag = POPERR_NOT_A_NUMBER;
            PortObjectFree(po);
            return NULL;
        }

        hport = POParserGetShort(pop);

        if ( pop->errflag )
        {
            PortObjectFree(po);
            return NULL;
        }

        if (lport > hport)
        {
            pop->errflag = POPERR_INVALID_RANGE;
            PortObjectFree(po);
            return NULL;
        }

        PortObjectAddRange(po, lport, hport, 0);
    }
    else
    {
        PortObjectAddPort(po, lport, 0);
    }

    return po;
}

// FIXIT-L this creates 1 PortObject per port in the list
// and then consolidates into one PortObject; it should
// just create a single PortObject and put each port into
// appropriate PortItems
static PortObject* _POParseString(POParser* pop)
{
    PortObject* po;
    PortObject* potmp = NULL;
    int local_neg = 0;
    char c;
    int list_count = 0;

    po = PortObjectNew();

    if (!po)
    {
        pop->errflag = POPERR_MALLOC_FAILED;
        return NULL;
    }

    while ( (c = POPGetChar2(pop)) != 0 )
    {
        if (c == '!')
        {
            local_neg = 1;
            continue;
        }

        if (c == '$')
        {
            /* Don't dup this again - the returned PortObject has already
             * been dup'ed */
            potmp = _POParseVar(pop);
        }
        /* Start of a list. Tokenize list and recurse on it */
        else if (c == '[')
        {
            POParser local_pop;
            char* tok;
            const char* end;

            list_count++;

            if ( (end = strrchr(pop->s, (int)']')) == NULL )
            {
                pop->errflag = POPERR_NO_ENDLIST_BRACKET;
                PortObjectFree(po);
                return NULL;
            }

            if ( (tok = SnortStrndup(pop->s, end - pop->s)) == NULL)
            {
                pop->errflag = POPERR_MALLOC_FAILED;
                PortObjectFree(po);
                return NULL;
            }

            POParserInit(&local_pop, tok, pop->pvTable);

            /* Recurse */
            potmp = _POParseString(&local_pop);
            free(tok);

            if (!potmp)
            {
                pop->errflag = local_pop.errflag;
                PortObjectFree(po);
                return NULL;
            }

            /* Advance "cursor" to end of this list */
            for (; c && pop->s != end; c = POPGetChar2(pop))
                ;
        }
        else if (c == ']')
        {
            list_count--;

            if (list_count < 0)
            {
                pop->errflag = POPERR_EXTRA_BRACKET;
                PortObjectFree(po);
                return NULL;
            }

            continue;
        }
        else
        {
            POPUnGetChar(pop);

            potmp = _POParsePort(pop);
        }

        if (!potmp)
        {
            PortObjectFree(po);
            return NULL;
        }

        if (local_neg)
        {
            /* Note: this intentionally only sets the negation flag!
               The actual negation will take place when normalization is called */
            PortObjectToggle(potmp);

            local_neg = 0;
        }

        if (PortObjectAddPortObject(po, potmp, &pop->errflag))
        {
            PortObjectFree(po);
            PortObjectFree(potmp);
            return NULL;
        }

        if (potmp)
        {
            PortObjectFree(potmp);
            potmp = NULL;
        }
    }

    /* Check for mis-matched brackets */
    if (list_count)
    {
        if (list_count > 0)
            pop->errflag = POPERR_NO_ENDLIST_BRACKET;
        else
            pop->errflag = POPERR_EXTRA_BRACKET;

        PortObjectFree(po);
        return NULL;
    }

    return po;
}

/*
*   PortObject : name value
*   PortObject : name [!][ value value value ... ]
*
*   value : [!]port
*           [!]low-port[:high-port]
*
*  inputs:
*  pvTable - PortVarTable to search for PortVar references in the current PortVar
*      pop - parsing structure
*        s - string with port object text
*
* nameflag - indicates a name must be present, this allows usage for
*            embedded rule or portvar declarations of portlists
* returns:
*      (PortObject *) - a normalized version
*/
PortObject* PortObjectParseString(PortVarTable* pvTable, POParser* pop,
    const char* name, const char* s, int nameflag)
{
    PortObject* po, * potmp;

    DebugFormat(DEBUG_PORTLISTS,"PortObjectParseString: %s\n",s);

    POParserInit(pop, s, pvTable);

    po = PortObjectNew();
    if (!po)
    {
        pop->errflag=POPERR_MALLOC_FAILED;
        return 0;
    }

    if ( nameflag ) /* parse a name */
    {
        po->name = POParserName(pop);
        if (!po->name )
        {
            pop->errflag=POPERR_NO_NAME;
            PortObjectFree(po);
            return 0;
        }
    }
    else
    {
        if ( name )
            po->name = SnortStrdup(name);
        else
            po->name = SnortStrdup("noname");
    }

    // LogMessage("PortObjectParseString: po->name=%s\n",po->name);

    potmp = _POParseString(pop);

    if (!potmp)
    {
        PortObjectFree(po);
        return NULL;
    }

    PortObjectNormalize(potmp);

    if (PortObjectAddPortObject(po, potmp, &pop->errflag))
    {
        PortObjectFree(po);
        PortObjectFree(potmp);
        return NULL;
    }

    PortObjectFree(potmp);

    return po;
}

const char* PortObjectParseError(POParser* pop)
{
    switch ( pop->errflag )
    {
    case POPERR_NO_NAME:            return "no name";
    case POPERR_NO_ENDLIST_BRACKET: return "no end of list bracket."
               " Elements must be comma seperated,"
               " and no spaces may appear between"
               " brackets.";
    case POPERR_NOT_A_NUMBER:       return "not a number";
    case POPERR_EXTRA_BRACKET:      return "extra list bracket";
    case POPERR_NO_DATA:            return "no data";
    case POPERR_ADDITEM_FAILED:     return "add item failed";
    case POPERR_MALLOC_FAILED:      return "mem alloc failed";
    case POPERR_INVALID_RANGE:      return "invalid port range";
    case POPERR_DUPLICATE_ENTRY:    return "duplicate ports in list";
    case POPERR_BOUNDS:             return "value out of bounds for a port";
    case POPERR_BAD_VARIABLE:       return "unrecognized variable";
    default:
        break;
    }
    return "unknown POParse error";
}

