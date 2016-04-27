//--------------------------------------------------------------------------
// Copyright (C) 2014-2015 Cisco and/or its affiliates. All rights reserved.
// Copyright (C) 2002-2013 Sourcefire, Inc.
// Copyright (C) 2002 Martin Roesch <roesch@sourcefire.com>
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

#ifndef UTIL_H
#define UTIL_H

// Miscellaneous functions and macros
// FIXIT-L this needs to be refactored and stripped of cruft

#define TIMEBUF_SIZE 26

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <sys/time.h>
#include <sys/types.h>
#include <stdlib.h>
#include <errno.h>
#include <unistd.h>
#include <string.h>
#include <ctype.h>

#ifdef LINUX
#include <sys/syscall.h>
#endif

#include <string>

#include "main/snort_types.h"
#include "log/messages.h"

#define SNORT_SNPRINTF_SUCCESS 0
#define SNORT_SNPRINTF_TRUNCATION 1
#define SNORT_SNPRINTF_ERROR -1

#define SNORT_STRNCPY_SUCCESS 0
#define SNORT_STRNCPY_TRUNCATION 1
#define SNORT_STRNCPY_ERROR -1

#define SNORT_STRNLEN_ERROR -1

#define SECONDS_PER_DAY  86400  /* number of seconds in a day  */
#define SECONDS_PER_HOUR  3600  /* number of seconds in a hour */
#define SECONDS_PER_MIN     60     /* number of seconds in a minute */

#define STD_BUF  1024

#define COPY4(x, y) \
    x[0] = y[0]; x[1] = y[1]; x[2] = y[2]; x[3] = y[3];

#define COPY16(x,y) \
    x[0] = y[0]; x[1] = y[1]; x[2] = y[2]; x[3] = y[3]; \
    x[4] = y[4]; x[5] = y[5]; x[6] = y[6]; x[7] = y[7]; \
    x[8] = y[8]; x[9] = y[9]; x[10] = y[10]; x[11] = y[11]; \
    x[12] = y[12]; x[13] = y[13]; x[14] = y[14]; x[15] = y[15];

SO_PUBLIC extern char** protocol_names;

void StoreSnortInfoStrings(void);
int DisplayBanner(void);
int gmt2local(time_t);
void ts_print(register const struct timeval*, char*);
void CheckLogDir(void);
char* read_infile(const char* key, const char* fname);
void CleanupProtoNames(void);
void CreatePidFile(pid_t);
void ClosePidFile(void);
void SetUidGid(int, int);
void InitGroups(int, int);
void SetChroot(std::string root_dir, std::string& log_dir);
void InitProtoNames(void);

// these functions are deprecated; use C++ strings instead
SO_PUBLIC int SnortSnprintf(char*, size_t, const char*, ...)
    __attribute__((format (printf, 3, 4)));
SO_PUBLIC int SnortSnprintfAppend(char*, size_t, const char*, ...)
    __attribute__((format (printf, 3, 4)));

SO_PUBLIC char* SnortStrdup(const char*);
SO_PUBLIC char* SnortStrndup(const char*, size_t);

SO_PUBLIC const char* SnortStrcasestr(const char* s, int slen, const char* substr);
SO_PUBLIC const char* SnortStrnStr(const char* s, int slen, const char* searchstr);
SO_PUBLIC const char* SnortStrnPbrk(const char* s, int slen, const char* accept);

SO_PUBLIC int SnortStrncpy(char*, const char*, size_t);
SO_PUBLIC int SnortStrnlen(const char*, int);

int CheckValueInRange(const char* value_str, const char* option,
    unsigned long lo, unsigned long hi, unsigned long* value);

char* CurrentWorkingDir(void);
char* GetAbsolutePath(const char* dir);
char* StripPrefixDir(char* prefix, char* dir);

#if defined(NOCOREFILE)
void SetNoCores(void);
#endif

static inline void* SnortAlloc(unsigned long size)
{
    void* pv = calloc(size, sizeof(char));

    if ( pv )
        return pv;

    // FIXIT-M do not FatalError() on runtime allocation failures
    FatalError("Unable to allocate memory (%lu requested)\n", size);

    return NULL;
}

static inline long SnortStrtol(const char* nptr, char** endptr, int base)
{
    long iRet;
    errno = 0;
    iRet = strtol(nptr, endptr, base);

    return iRet;
}

static inline unsigned long SnortStrtoul(const char* nptr, char** endptr, int base)
{
    unsigned long iRet;
    errno = 0;
    iRet = strtoul(nptr, endptr, base);

    return iRet;
}

// Checks to make sure we're not going to evaluate a negative number for which
// strtoul() gladly accepts and parses returning an underflowed wrapped unsigned
// long without error.
// Buffer passed in MUST be '\0' terminated.
//
// Returns
//  int
//    -1 if buffer is nothing but spaces or first non-space character is a
//       negative sign.  Also if errno is EINVAL (which may be due to a bad
//       base) or there was nothing to convert.
//     0 on success
//
// Populates pointer to uint32_t value passed in which should
// only be used on a successful return from this function.
//
// Also will set errno to ERANGE on a value returned from strtoul that is
// greater than UINT32_MAX, but still return success.
//
static inline int SnortStrToU32(const char* buffer, char** endptr,
    uint32_t* value, int base)
{
    unsigned long int tmp;

    if ((buffer == NULL) || (endptr == NULL) || (value == NULL))
        return -1;

    // Only positive numbers should be processed and strtoul will
    // eat up white space and process '-' and '+' so move past
    // white space and check for a negative sign.
    while (isspace((int)*buffer))
        buffer++;

    // If all spaces or a negative sign is found, return error.
    // XXX May also want to exclude '+' as well.
    if ((*buffer == '\0') || (*buffer == '-'))
        return -1;

    tmp = SnortStrtoul(buffer, endptr, base);

    // The user of the function should check for ERANGE in errno since this
    // function can be used such that an ERANGE error is acceptable and
    // value gets truncated to UINT32_MAX.
    if ((errno == EINVAL) || (*endptr == buffer))
        return -1;

    // If value is greater than a UINT32_MAX set value to UINT32_MAX
    // and errno to ERANGE
    if (tmp > UINT32_MAX)
    {
        tmp = UINT32_MAX;
        errno = ERANGE;
    }

    *value = (uint32_t)tmp;

    return 0;
}

static inline long SnortStrtolRange(const char* nptr, char** endptr, int base, long lo, long hi)
{
    long iRet = SnortStrtol(nptr, endptr, base);
    if ((iRet > hi) || (iRet < lo))
        *endptr = (char*)nptr;

    return iRet;
}

static inline unsigned long SnortStrtoulRange(const char* nptr, char** endptr, int base, unsigned
    long lo, unsigned long hi)
{
    unsigned long iRet = SnortStrtoul(nptr, endptr, base);
    if ((iRet > hi) || (iRet < lo))
        *endptr = (char*)nptr;

    return iRet;
}

static inline int IsEmptyStr(const char* str)
{
    const char* end;

    if (str == NULL)
        return 1;

    end = str + strlen(str);

    while ((str < end) && isspace((int)*str))
        str++;

    if (str == end)
        return 1;

    return 0;
}

static inline pid_t gettid(void)
{
#if defined(LINUX) && defined(SYS_gettid)
    return syscall(SYS_gettid);
#else
    return getpid();
#endif
}

SO_PUBLIC const char* get_error(int errnum);

// get_tok() provided to retrofit distributed calls to
// strtok() to use strtok_r().  use strtok_r() directly
// for new code.  get_tok() is thread safe but not
// reentrant.
char* get_tok(char* s, const char* delim);

#endif

