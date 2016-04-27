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

#include "port_object2.h"

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <ctype.h>

#include <memory>

#include "port_object.h"
#include "port_item.h"
#include "port_table.h"
#include "port_utils.h"

#include "main/snort_types.h"
#include "main/snort_config.h"
#include "main/snort_debug.h"
#include "detection/sfrim.h"
#include "parser/parser.h"
#include "utils/snort_bounds.h"
#include "utils/util.h"
#include "hash/sfhashfcn.h"

#define PO_EXTRA_RULE_CNT 25

//-------------------------------------------------------------------------
// PortObject2 - private
//-------------------------------------------------------------------------

/* This is the opposite of ntohl/htonl defines, and does the
 * swap on big endian hardware */
#ifdef WORDS_BIGENDIAN
#define SWAP_BYTES(a) \
    ((((uint32_t)(a) & 0xFF000000) >> 24) | \
    (((uint32_t)(a) & 0x00FF0000) >> 8) | \
    (((uint32_t)(a) & 0x0000FF00) << 8) | \
    (((uint32_t)(a) & 0x000000FF) << 24))
#else
#define SWAP_BYTES(a) (a)
#endif

static unsigned po_rule_hash_func(SFHASHFCN* p, unsigned char* k, int n)
{
    unsigned char* key;
    int ikey = *(int*)k;

    /* Since the input is really an int, put the bytes into a normalized
     * order so that the hash function returns consistent results across
     * on BE & LE hardware. */
    ikey = SWAP_BYTES(ikey);

    /* Set a pointer to the key to pass to the hashing function */
    key = (unsigned char*)&ikey;

    return sfhashfcn_hash(p, key, n);
}

static int* RuleHashToSortedArray(SFGHASH* rh)
{
    int* prid;
    int* ra;
    int k = 0;
    SFGHASH_NODE* node;

    if ( !rh )
        return 0;

    if (!rh->count)
        return NULL;

    ra = (int*)SnortAlloc(rh->count * sizeof(int));

    for ( node = sfghash_findfirst(rh);
        node != 0 && k < (int)rh->count;
        node = sfghash_findnext(rh) )
    {
        prid = (int*)node->data;
        if ( prid )
        {
            ra[k++] = *prid;
        }
    }

    /* sort the array */
    qsort(ra,rh->count,sizeof(int),integer_compare);

    return ra;
}

//-------------------------------------------------------------------------
// PortObject2 - public
//-------------------------------------------------------------------------

/*
    Create a new PortObject2
*/
PortObject2* PortObject2New(int nrules)
{
    PortObject2* po = (PortObject2*)SnortAlloc(sizeof(PortObject2));

    po->item_list =(SF_LIST*)sflist_new();

    if ( !po->item_list )
    {
        free(po);
        return 0;
    }

    po->rule_hash =(SFGHASH*)sfghash_new(nrules,sizeof(int),0,
        free /* frees data - should be rule id ptrs == (int*) */);
    if ( !po->rule_hash )
    {
        sflist_free_all(po->item_list, free);
        free(po);
        return 0;
    }

    /* Use hash function defined above for hashing the key as an int. */
    sfghash_set_keyops(po->rule_hash, po_rule_hash_func, memcmp);

    //sfhashfcn_static( po->rule_hash->sfhashfcn ); /* FIXIT: Leave this in, else we get different
    // events */

    return po;
}

/*
 *  Free the PortObject2
 */
void PortObject2Free(void* pvoid)
{
    PortObject2* po = (PortObject2*)pvoid;
    DEBUG_WRAP(static int pof2_cnt = 0; pof2_cnt++; );

    DebugFormat(DEBUG_PORTLISTS,"PortObjectFree2-Cnt: %d ptr=%p\n",pof2_cnt,pvoid);

    if ( !po )
        return;

    if ( po->name )
        free (po->name);
    if ( po->item_list)
        sflist_free_all(po->item_list, free);
    if ( po->rule_hash)
        sfghash_delete(po->rule_hash);

    if (po->port_list)
        delete po->port_list;

    if (po->data && po->data_free)
    {
        po->data_free(po->data);
    }

    free(po);
}

/*
 * Dup the PortObjects Item List, Name, and RuleList->RuleHash
 */
PortObject2* PortObject2Dup(PortObject* po)
{
    PortObject2* ponew = NULL;
    PortObjectItem* poi = NULL;
    PortObjectItem* poinew = NULL;
    SF_LNODE* lpos = NULL;
    int* prid = NULL;
    int* prule = NULL;

    if ( !po )
        return NULL;

    if ( !po->rule_list )
        return NULL;

    ponew = PortObject2New(po->rule_list->count + PO_EXTRA_RULE_CNT);
    if ( !ponew )
        return NULL;

    /* Dup the Name */
    if ( po->name )
        ponew->name = strdup(po->name);
    else
        ponew->name = strdup("dup");

    if ( !ponew->name )
    {
        free(ponew);
        return NULL;
    }

    /* Dup the Item List */
    if ( po->item_list )
    {
        for (poi =(PortObjectItem*)sflist_first(po->item_list,&lpos);
            poi != NULL;
            poi =(PortObjectItem*)sflist_next(&lpos) )
        {
            poinew = PortObjectItemDup(poi);

            if (!poinew)
            {
                free(ponew);
                return NULL;
            }

            PortObjectAddItem( (PortObject*)ponew, poinew, NULL);
        }
    }

    /* Dup the input rule list */
    if ( po->rule_list )
    {
        for (prid  = (int*)sflist_first(po->rule_list,&lpos);
            prid != 0;
            prid  = (int*)sflist_next(&lpos) )
        {
            prule = (int*)calloc(1,sizeof(int));
            if (!prule)
            {
                free(ponew);
                return NULL;
            }
            *prule = *prid;
            if ( sfghash_add(ponew->rule_hash, prule, prule) != SFGHASH_OK )
            {
                free(prule);
            }
        }
    }

    return ponew;
}

void PortObject2Iterate(PortObject2* po, PortObjectIterator f, void* pv)
{
    PortObjectItem* poi;
    SF_LNODE* cursor;

    for ( poi = (PortObjectItem*)sflist_first(po->item_list, &cursor);
        poi;
        poi = (PortObjectItem*)sflist_next(&cursor) )
    {
        if ( !poi->any() )
        {
            for ( int i = poi->lport; i<= poi->hport; i++ )
                f(i, pv);
        }
    }
}

/* Dup and append rule list numbers from pob to poa */
PortObject2* PortObject2AppendPortObject(PortObject2* poa, PortObject* pob)
{
    int* prid;
    int* prid2;
    SF_LNODE* lpos;

    for ( prid = (int*)sflist_first(pob->rule_list,&lpos);
        prid!= 0;
        prid = (int*)sflist_next(&lpos) )
    {
        prid2 = (int*)calloc(1, sizeof(int));
        if ( !prid2 )
            return 0;
        *prid2 = *prid;
        if ( sfghash_add(poa->rule_hash,prid2,prid2) != SFGHASH_OK )
        {
            free(prid2);
        }
    }
    return poa;
}

/* Dup and append rule list numbers from pob to poa */
PortObject2* PortObject2AppendPortObject2(PortObject2* poa, PortObject2* pob)
{
    int* prid;
    int* prid2;
    SFGHASH_NODE* node;

    for ( node = sfghash_findfirst(pob->rule_hash);
        node!= NULL;
        node = sfghash_findnext(pob->rule_hash) )
    {
        prid = (int*)node->data;
        if ( !prid )
            continue;

        prid2 = (int*)calloc(1, sizeof(int));
        if ( !prid2 )
            return 0;

        *prid2 = *prid;
        if ( sfghash_add(poa->rule_hash,prid2,prid2) != SFGHASH_OK )
        {
            free(prid2);
        }
    }
    return poa;
}

/*
 *  Append Ports and Rules from pob to poa
 */
PortObject2* PortObjectAppendEx2(PortObject2* poa, PortObject* pob)
{
    // LogMessage("PortObjectAppendEx: appending ports\n");
    if ( !PortObjectAppend((PortObject*)poa, pob) )
        return 0;

    //  LogMessage("PortObjectAppendEx: appending rules\n");
    if ( !PortObject2AppendPortObject(poa, pob) )
        return 0;

    return poa;
}

void PortObject2PrintPorts(PortObject2* po)
{
    PortObjectItem* poi = NULL;
    SF_LNODE* pos = NULL;
    int bufsize = sizeof(po_print_buf);

    po_print_buf[0] = '\0';

    SnortSnprintfAppend(po_print_buf, bufsize, " PortObject ");

    if ( po->name )
    {
        SnortSnprintfAppend(po_print_buf, bufsize, "%s ", po->name);
    }

    SnortSnprintfAppend(po_print_buf, bufsize,
        " Id:%d  Ports:%d Rules:%d\n {\n Ports [",
        po->id, po->item_list->count, po->rule_hash->count);

    if ( PortObjectHasAny( (PortObject*)po) )
    {
        SnortSnprintfAppend(po_print_buf, bufsize, "any");
    }
    else
    {
        for (poi=(PortObjectItem*)sflist_first(po->item_list,&pos);
            poi != 0;
            poi=(PortObjectItem*)sflist_next(&pos) )
        {
            PortObjectItemPrint(poi, po_print_buf, bufsize);
        }
    }

    SnortSnprintfAppend(po_print_buf, bufsize, " ]\n }\n");
    LogMessage("%s", po_print_buf);
}

void PortObject2PrintEx(PortObject2* po,
    void (* print_index_map)(int index, char* buf, int bufsize) )
{
    PortObjectItem* poi = NULL;
    SF_LNODE* pos = NULL;
    int k=0;
    int* rlist = NULL;
    unsigned int i;
    int bufsize = sizeof(po_print_buf);

    po_print_buf[0] = '\0';

    SnortSnprintfAppend(po_print_buf, bufsize, " PortObject2 ");

    if ( po->name )
        SnortSnprintfAppend(po_print_buf, bufsize, "%s ",po->name);

    SnortSnprintfAppend(po_print_buf, bufsize, " Id:%d  Ports:%d Rules:%d PortUsageCnt=%d\n {\n",
        po->id, po->item_list->count, po->rule_hash->count, po->port_cnt);

    SnortSnprintfAppend(po_print_buf, bufsize, "  Ports [\n  ");

    if ( PortObjectHasAny( (PortObject*)po) )
    {
        SnortSnprintfAppend(po_print_buf, bufsize, "any");
    }
    else
    {
        for (poi=(PortObjectItem*)sflist_first(po->item_list,&pos);
            poi != 0;
            poi=(PortObjectItem*)sflist_next(&pos) )
        {
            PortObjectItemPrint(poi, po_print_buf, bufsize);
        }
    }

    SnortSnprintfAppend(po_print_buf, bufsize, "  ]\n");

    rlist = RuleHashToSortedArray(po->rule_hash);
    if (!rlist )
        return;

    SnortSnprintfAppend(po_print_buf, bufsize, "  Rules [ \n ");
    for (i=0; i<po->rule_hash->count; i++)
    {
        if ( print_index_map )
        {
            print_index_map(rlist[i], po_print_buf, bufsize);
        }
        else
        {
            SnortSnprintfAppend(po_print_buf, bufsize, " %d", rlist[i]);
        }
        k++;
        if ( k == 25 )
        {
            k=0;
            SnortSnprintfAppend(po_print_buf, bufsize, " \n ");
        }
    }
    SnortSnprintfAppend(po_print_buf, bufsize, "  ]\n }\n");

    LogMessage("%s", po_print_buf);

    free(rlist);
}

void PortObject2Print(PortObject2* po)
{
    PortObject2PrintEx(po, rule_index_map_print_index);
}

