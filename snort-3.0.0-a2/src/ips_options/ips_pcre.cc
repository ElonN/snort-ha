//--------------------------------------------------------------------------
// Copyright (C) 2014-2015 Cisco and/or its affiliates. All rights reserved.
// Copyright (C) 2003-2013 Sourcefire, Inc.
// Copyright (C) 2003 Brian Caswell <bmc@snort.org>
// Copyright (C) 2003 Michael J. Pomraning <mjp@securepipe.com>
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

#include "ips_pcre.h"

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <sys/types.h>
#include <pcre.h>

#include "main/snort_types.h"
#include "main/snort_debug.h"
#include "main/snort_config.h"
#include "protocols/packet.h"
#include "parser/parser.h"
#include "utils/util.h"
#include "utils/snort_bounds.h"
#include "hash/sfhashfcn.h"
#include "time/profiler.h"
#include "detection/treenodes.h"
#include "detection/detection_defines.h"
#include "detection/detection_util.h"
#include "framework/cursor.h"
#include "framework/ips_option.h"
#include "framework/parameter.h"
#include "framework/module.h"

#ifndef PCRE_STUDY_JIT_COMPILE
#define PCRE_STUDY_JIT_COMPILE 0
#endif

#define NO_JIT // uncomment to disable JIT for Xcode

#ifdef NO_JIT
#define PCRE_STUDY_FLAGS 0
#define pcre_release(x) pcre_free(x)
#else
#define PCRE_STUDY_FLAGS PCRE_STUDY_JIT_COMPILE
#define pcre_release(x) pcre_free_study(x)
#endif

#define SNORT_PCRE_RELATIVE         0x00010 // relative to the end of the last match
#define SNORT_PCRE_INVERT           0x00020 // invert detect
#define SNORT_PCRE_ANCHORED         0x00040
#define SNORT_OVERRIDE_MATCH_LIMIT  0x00080 // Override default limits on match & match recursion

#define s_name "pcre"

/*
 * we need to specify the vector length for our pcre_exec call.  we only care
 * about the first vector, which if the match is successful will include the
 * offset to the end of the full pattern match.  If we decide to store other
 * matches, make *SURE* that this is a multiple of 3 as pcre requires it.
 */
// the wrong size caused the pcre lib to segfault but that has since been
// fixed.  it may be that with the updated lib, the need to get the size
// exactly correct is obviated and thus the need to reload as well.

/* Since SO rules are loaded 1 time at startup, regardless of
 * configuraton, we won't pcre_capture count again, so save the max.  */
static int s_ovector_max = 0;

// this is a temporary value used during parsing and set in snort conf
// by verify; search uses the value in snort conf
static int s_ovector_size = 0;

static THREAD_LOCAL ProfileStats pcrePerfStats;

//-------------------------------------------------------------------------
// implementation foo
//-------------------------------------------------------------------------

static void pcre_capture(
    const void* code, const void* extra)
{
    int tmp_ovector_size = 0;

    pcre_fullinfo((const pcre*)code, (const pcre_extra*)extra,
        PCRE_INFO_CAPTURECOUNT, &tmp_ovector_size);

    if (tmp_ovector_size > s_ovector_size)
        s_ovector_size = tmp_ovector_size;
}

static void pcre_check_anchored(PcreData* pcre_data)
{
    int rc;
    unsigned long int options = 0;

    if ((pcre_data == NULL) || (pcre_data->re == NULL) || (pcre_data->pe == NULL))
        return;

    rc = pcre_fullinfo(pcre_data->re, pcre_data->pe, PCRE_INFO_OPTIONS, (void*)&options);
    switch (rc)
    {
    /* pcre_fullinfo fails for the following:
     * PCRE_ERROR_NULL - the argument code was NULL
     *                   the argument where was NULL
     * PCRE_ERROR_BADMAGIC - the "magic number" was not found
     * PCRE_ERROR_BADOPTION - the value of what was invalid
     * so a failure here means we passed in bad values and we should
     * probably fatal error */

    case 0:
        /* This is the success code */
        break;

    case PCRE_ERROR_NULL:
        ParseError("pcre_fullinfo: code and/or where were NULL.");
        return;

    case PCRE_ERROR_BADMAGIC:
        ParseError("pcre_fullinfo: compiled code didn't have correct magic.");
        return;

    case PCRE_ERROR_BADOPTION:
        ParseError("pcre_fullinfo: option type is invalid.");
        return;

    default:
        ParseError("pcre_fullinfo: Unknown error code.");
        return;
    }

    if ((options & PCRE_ANCHORED) && !(options & PCRE_MULTILINE))
    {
        /* This means that this pcre rule option shouldn't be reevaluted
         * even if any of it's relative children should fail to match.
         * It is anchored to the cursor set by the previous cursor setting
         * rule option */
        pcre_data->options |= SNORT_PCRE_ANCHORED;
    }
}

static void pcre_parse(const char* data, PcreData* pcre_data)
{
    const char* error;
    char* re, * free_me;
    char* opts;
    char delimit = '/';
    int erroffset;
    int compile_flags = 0;

    if (data == NULL)
    {
        ParseError("pcre requires a regular expression");
        return;
    }

    free_me = SnortStrdup(data);
    re = free_me;

    /* get rid of starting and ending whitespace */
    while (isspace((int)re[strlen(re)-1]))
        re[strlen(re)-1] = '\0';
    while (isspace((int)*re))
        re++;

    if (*re == '!')
    {
        pcre_data->options |= SNORT_PCRE_INVERT;
        re++;
        while (isspace((int)*re))
            re++;
    }

    if ( *re == '"')
        re++;

    if ( re[strlen(re)-1] == '"' )
        re[strlen(re) - 1] = '\0';

    /* 'm//' or just '//' */

    if (*re == 'm')
    {
        re++;
        if (!*re)
            goto syntax;

        /* Space as a ending delimiter?  Uh, no. */
        if (isspace((int)*re))
            goto syntax;
        /* using R would be bad, as it triggers RE */
        if (*re == 'R')
            goto syntax;

        delimit = *re;
    }
    else if (*re != delimit)
        goto syntax;

    pcre_data->expression = SnortStrdup(re);

    /* find ending delimiter, trim delimit chars */
    opts = strrchr(re, delimit);
    if (opts == NULL)
        goto syntax;

    if (!((opts - re) > 1)) /* empty regex(m||) or missing delim not OK */
        goto syntax;

    re++;
    *opts++ = '\0';

    /* process any /regex/ismxR options */
    while (*opts != '\0')
    {
        switch (*opts)
        {
        case 'i':  compile_flags |= PCRE_CASELESS;            break;
        case 's':  compile_flags |= PCRE_DOTALL;              break;
        case 'm':  compile_flags |= PCRE_MULTILINE;           break;
        case 'x':  compile_flags |= PCRE_EXTENDED;            break;

        /*
         * these are pcre specific... don't work with perl
         */
        case 'A':  compile_flags |= PCRE_ANCHORED;            break;
        case 'E':  compile_flags |= PCRE_DOLLAR_ENDONLY;      break;
        case 'G':  compile_flags |= PCRE_UNGREEDY;            break;

        /*
         * these are snort specific don't work with pcre or perl
         */
        case 'R':  pcre_data->options |= SNORT_PCRE_RELATIVE; break;
        case 'O':  pcre_data->options |= SNORT_OVERRIDE_MATCH_LIMIT; break;

        default:
            ParseError("unknown/extra pcre option encountered");
            return;
        }
        opts++;
    }

    /* now compile the re */
    DebugFormat(DEBUG_PATTERN_MATCH, "pcre: compiling %s\n", re);
    pcre_data->re = pcre_compile(re, compile_flags, &error, &erroffset, NULL);

    if (pcre_data->re == NULL)
    {
        ParseError(": pcre compile of '%s' failed at offset "
            "%d : %s", re, erroffset, error);
        return;
    }

    /* now study it... */
    pcre_data->pe = pcre_study(pcre_data->re, PCRE_STUDY_FLAGS, &error);

    if (pcre_data->pe)
    {
        if ((SnortConfig::get_pcre_match_limit() != -1) &&
            !(pcre_data->options & SNORT_OVERRIDE_MATCH_LIMIT))
        {
            if (pcre_data->pe->flags & PCRE_EXTRA_MATCH_LIMIT)
            {
                pcre_data->pe->match_limit = SnortConfig::get_pcre_match_limit();
            }
            else
            {
                pcre_data->pe->flags |= PCRE_EXTRA_MATCH_LIMIT;
                pcre_data->pe->match_limit = SnortConfig::get_pcre_match_limit();
            }
        }

#ifdef PCRE_EXTRA_MATCH_LIMIT_RECURSION
        if ((SnortConfig::get_pcre_match_limit_recursion() != -1) &&
            !(pcre_data->options & SNORT_OVERRIDE_MATCH_LIMIT))
        {
            if (pcre_data->pe->flags & PCRE_EXTRA_MATCH_LIMIT_RECURSION)
            {
                pcre_data->pe->match_limit_recursion =
                    SnortConfig::get_pcre_match_limit_recursion();
            }
            else
            {
                pcre_data->pe->flags |= PCRE_EXTRA_MATCH_LIMIT_RECURSION;
                pcre_data->pe->match_limit_recursion =
                    SnortConfig::get_pcre_match_limit_recursion();
            }
        }
#endif
    }
    else
    {
        if (!(pcre_data->options & SNORT_OVERRIDE_MATCH_LIMIT) &&
            ((SnortConfig::get_pcre_match_limit() != -1) ||
             (SnortConfig::get_pcre_match_limit_recursion() != -1)))
        {
            pcre_data->pe = (pcre_extra*)SnortAlloc(sizeof(pcre_extra));
            if (SnortConfig::get_pcre_match_limit() != -1)
            {
                pcre_data->pe->flags |= PCRE_EXTRA_MATCH_LIMIT;
                pcre_data->pe->match_limit = SnortConfig::get_pcre_match_limit();
            }

#ifdef PCRE_EXTRA_MATCH_LIMIT_RECURSION
            if (SnortConfig::get_pcre_match_limit_recursion() != -1)
            {
                pcre_data->pe->flags |= PCRE_EXTRA_MATCH_LIMIT_RECURSION;
                pcre_data->pe->match_limit_recursion =
                    SnortConfig::get_pcre_match_limit_recursion();
            }
#endif
        }
    }

    if (error != NULL)
    {
        ParseError("pcre study failed : %s", error);
        return;
    }

    pcre_capture(pcre_data->re, pcre_data->pe);
    pcre_check_anchored(pcre_data);

    free(free_me);
    return;

syntax:
    free(free_me);

    // ensure integrity from parse error to fatal error
    if ( !pcre_data->expression )
        pcre_data->expression = SnortStrdup("");

    ParseError("unable to parse pcre regex %s", data);
}

/**
 * Perform a search of the PCRE data.
 *
 * @param pcre_data structure that options and patterns are passed in
 * @param buf buffer to search
 * @param len size of buffer
 * @param found_offset pointer to an integer so that we know where the search ended
 *
 * *found_offset will be set to -1 when the find is unsucessful OR the routine is inverted
 *
 * @return 1 when we find the string, 0 when we don't (unless we've been passed a flag to invert)
 */
static bool pcre_search(
    const PcreData* pcre_data,
    const uint8_t* buf,
    int len,
    int start_offset,
    int* found_offset)
{
    bool matched;
    int result;

    if (pcre_data == NULL
        || buf == NULL
        || len <= 0
        || found_offset == NULL)
    {
        DebugMessage(DEBUG_PATTERN_MATCH,
            "Returning 0 because we didn't have the required parameters!\n");
        return false;
    }

    *found_offset = -1;

    SnortState* ss = snort_conf->state + get_instance_id();
    assert(ss->pcre_ovector);

    result = pcre_exec(
        pcre_data->re,  /* result of pcre_compile() */
        pcre_data->pe,  /* result of pcre_study()   */
        (const char*)buf, /* the subject string */
        len,            /* the length of the subject string */
        start_offset,   /* start at offset 0 in the subject */
        0,              /* options(handled at compile time */
        ss->pcre_ovector,      /* vector for substring information */
        snort_conf->pcre_ovector_size); /* number of elements in the vector */

    if (result >= 0)
    {
        matched = true;

        /* From the PCRE man page: When a match is successful, information
         * about captured substrings is returned in pairs of integers,
         * starting at the beginning of ovector, and continuing up to
         * two-thirds of its length at the most.  The first element of a
         * pair is set to the offset of the first character in a substring,
         * and the second is set to the offset of the first character after
         * the end of a substring. The first pair, ovector[0] and
         * ovector[1], identify the portion of the subject string matched
         * by the entire pattern.  The next pair is used for the first
         * capturing subpattern, and so on. The value returned by
         * pcre_exec() is the number of pairs that have been set. If there
         * are no capturing subpatterns, the return value from a successful
         * match is 1, indicating that just the first pair of offsets has
         * been set.
         *
         * In Snort's case, the ovector size only allows for the first pair
         * and a single int for scratch space.
         */

        *found_offset = ss->pcre_ovector[1];
    }
    else if (result == PCRE_ERROR_NOMATCH)
    {
        matched = false;
    }
    else
    {
        DebugFormat(DEBUG_PATTERN_MATCH, "pcre_exec error : %d \n", result);
        return false;
    }

    /* invert sense of match */
    if (pcre_data->options & SNORT_PCRE_INVERT)
    {
        matched = !matched;
    }

    return matched;
}

//-------------------------------------------------------------------------
// class methods
//-------------------------------------------------------------------------

class PcreOption : public IpsOption
{
public:
    PcreOption(PcreData* c) :
        IpsOption(s_name, RULE_OPTION_TYPE_PCRE)
    { config = c; }

    ~PcreOption();

    uint32_t hash() const override;
    bool operator==(const IpsOption&) const override;

    bool is_relative() override
    { return (config->options & SNORT_PCRE_RELATIVE) != 0; }

    int eval(Cursor&, Packet*) override;

    PcreData* get_data()
    { return config; }

    void set_data(PcreData* pcre)
    { config = pcre; }

private:
    PcreData* config;
};

PcreOption::~PcreOption()
{
    if ( !config )
        return;

    if (config->expression)
        free(config->expression);

    if (config->pe)
        pcre_release(config->pe);

    if (config->re)
        free(config->re);

    free(config);
}

uint32_t PcreOption::hash() const
{
    int i,j,k,l,expression_len;
    uint32_t a,b,c,tmp;
    const PcreData* data = config;

    expression_len = strlen(data->expression);
    a = b = c = 0;

    for (i=0,j=0; i<expression_len; i+=4)
    {
        tmp = 0;
        k = expression_len - i;
        if (k > 4)
            k=4;

        for (l=0; l<k; l++)
        {
            tmp |= *(data->expression + i + l) << l*8;
        }

        switch (j)
        {
        case 0:
            a += tmp;
            break;
        case 1:
            b += tmp;
            break;
        case 2:
            c += tmp;
            break;
        }
        j++;

        if (j == 3)
        {
            mix(a,b,c);
            j=0;
        }
    }

    if (j != 0)
    {
        mix(a,b,c);
    }

    a += data->options;

    mix_str(a,b,c,get_name());
    final(a,b,c);

    return c;
}

bool PcreOption::operator==(const IpsOption& ips) const
{
    if ( strcmp(get_name(), ips.get_name()) )
        return false;

    PcreOption& rhs = (PcreOption&)ips;
    PcreData* left = config;
    PcreData* right = rhs.config;

    if (( strcmp(left->expression, right->expression) == 0) &&
        ( left->options == right->options))
    {
        return true;
    }

    return false;
}

int PcreOption::eval(Cursor& c, Packet*)
{
    PcreData* pcre_data = config;
    int found_offset = -1;  /* where is the ending location of the pattern */
    bool matched = false;

    PROFILE_VARS;
    MODULE_PROFILE_START(pcrePerfStats);

    // short circuit this for testing pcre performance impact
    if (SnortConfig::no_pcre())
    {
        MODULE_PROFILE_END(pcrePerfStats);
        return DETECTION_OPTION_NO_MATCH;
    }

    unsigned pos = c.get_delta();

    if ( !pos && is_relative() )
        pos = c.get_pos();

    if ( pos > c.size() )
        return 0;

    matched = pcre_search(pcre_data, c.buffer(), c.size(), pos, &found_offset);

    if (matched)
    {
        if ( found_offset > 0 )
        {
            c.set_pos(found_offset);
            c.set_delta(found_offset);
        }
        MODULE_PROFILE_END(pcrePerfStats);
        return DETECTION_OPTION_MATCH;
    }

    MODULE_PROFILE_END(pcrePerfStats);
    return DETECTION_OPTION_NO_MATCH;
}

//-------------------------------------------------------------------------
// public methods
//-------------------------------------------------------------------------

PcreData* pcre_get_data(void* pv)
{
    PcreOption* opt = (PcreOption*)pv;
    return opt->get_data();
}

// we always advance by found_offset so no adjustments to cursor are done
// here; note also that this means relative pcre matches on overlapping
// patterns won't work.  given the test pattern "ABABACD":
//
// ( sid:1; content:"ABA"; content:"C"; within:1; )
// ( sid:2; pcre:"/ABA/"; content:"C"; within:1; )
//
// sid 1 will fire but sid 2 will NOT.  this example is easily fixed by
// using content, but more advanced pcre won't work for the relative /
// overlap case.

bool pcre_next(PcreData* pcre)
{
    if ((pcre->options & (SNORT_PCRE_INVERT | SNORT_PCRE_ANCHORED)))
    {
        return false; // no go
    }

    return true;  // continue
}

void pcre_setup(SnortConfig* sc)
{
    for ( unsigned i = 0; i < sc->num_slots; ++i )
    {
        SnortState* ss = sc->state + i;
        ss->pcre_ovector = (int*)SnortAlloc(s_ovector_max*sizeof(int));
    }
}

void pcre_cleanup(SnortConfig* sc)
{
    for ( unsigned i = 0; i < sc->num_slots; ++i )
    {
        SnortState* ss = sc->state + i;

        if ( ss->pcre_ovector )
            free(ss->pcre_ovector);

        ss->pcre_ovector = nullptr;
    }
}

//-------------------------------------------------------------------------
// module
//-------------------------------------------------------------------------

static const Parameter s_params[] =
{
    { "~regex", Parameter::PT_STRING, nullptr, nullptr,
      "Snort regular expression" },

    { nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr }
};

#define s_help \
    "rule option for matching payload data with regex"

class PcreModule : public Module
{
public:
    PcreModule() : Module(s_name, s_help, s_params)
    { data = nullptr; }

    ~PcreModule()
    { delete data; }

    bool begin(const char*, int, SnortConfig*) override;
    bool set(const char*, Value&, SnortConfig*) override;

    ProfileStats* get_profile() const override
    { return &pcrePerfStats; }

    PcreData* get_data();

private:
    PcreData* data;
};

PcreData* PcreModule::get_data()
{
    PcreData* tmp = data;
    data = nullptr;
    return tmp;
}

bool PcreModule::begin(const char*, int, SnortConfig*)
{
    data = (PcreData*)SnortAlloc(sizeof(*data));
    return true;
}

bool PcreModule::set(const char*, Value& v, SnortConfig*)
{
    if ( v.is("~regex") )
        pcre_parse(v.get_string(), data);

    else
        return false;

    return true;
}

//-------------------------------------------------------------------------
// api methods
//-------------------------------------------------------------------------

static Module* mod_ctor()
{
    return new PcreModule;
}

static void mod_dtor(Module* m)
{
    delete m;
}

static IpsOption* pcre_ctor(Module* p, OptTreeNode*)
{
    PcreModule* m = (PcreModule*)p;
    PcreData* d = m->get_data();
    return new PcreOption(d);
}

static void pcre_dtor(IpsOption* p)
{
    delete p;
}

static void pcre_verify(SnortConfig* sc)
{
    /* The pcre_fullinfo() function can be used to find out how many
     * capturing subpatterns there are in a compiled pattern. The
     * smallest size for ovector that will allow for n captured
     * substrings, in addition to the offsets of the substring matched
     * by the whole pattern, is (n+1)*3.  */
    s_ovector_size += 1;
    s_ovector_size *= 3;

    if (s_ovector_size > s_ovector_max)
        s_ovector_max = s_ovector_size;

    sc->pcre_ovector_size = s_ovector_size;
    s_ovector_size = 0;
}

static const IpsApi pcre_api =
{
    {
        PT_IPS_OPTION,
        sizeof(IpsApi),
        IPSAPI_VERSION,
        0,
        API_RESERVED,
        API_OPTIONS,
        s_name,
        s_help,
        mod_ctor,
        mod_dtor
    },
    OPT_TYPE_DETECTION,
    0, 0,
    nullptr,
    nullptr,
    nullptr,
    nullptr,
    pcre_ctor,
    pcre_dtor,
    pcre_verify
};

const BaseApi* ips_pcre = &pcre_api.base;

