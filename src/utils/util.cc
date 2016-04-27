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

#include "util.h"

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <assert.h>
#include <dirent.h>
#include <fnmatch.h>
#include <stdarg.h>
#include <syslog.h>
#include <errno.h>
#include <time.h>
#include <signal.h>
#include <unistd.h>
#include <pcap.h>
#include <string.h>
#include <grp.h>
#include <pwd.h>
#include <netdb.h>
#include <limits.h>
#include <fcntl.h>
#include <luajit-2.0/luajit.h>
#include <zlib.h>

#ifdef HAVE_OPENSSL_SHA
#include <openssl/crypto.h>
#endif

#ifdef HAVE_LZMA
#include <lzma.h>
#endif

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/resource.h>

#include "sflsq.h"
#include "main/snort_config.h"
#include "main/snort_debug.h"
#include "main/snort_types.h"
#include "main/build.h"
#include "parser/parser.h"
#include "packet_io/sfdaq.h"
#include "packet_io/active.h"
#include "ips_options/ips_pcre.h"
#include "time/ppm.h"
#include "time/packet_time.h"
#include "time/timersub.h"
#include "stream/stream.h"

#ifdef PATH_MAX
#define PATH_MAX_UTIL PATH_MAX
#else
#define PATH_MAX_UTIL 1024
#endif

char** protocol_names = NULL;

/****************************************************************************
 * Store interesting data in memory that would not otherwise be visible
 * in a CORE(5) file
 ***************************************************************************/
#define SNORT_VERSION_STRING ("### Snort Version " VERSION " Build " BUILD "\n")
#define SNORT_VERSION_STRLEN sizeof(SNORT_VERSION_STRING)
char __snort_version_string[SNORT_VERSION_STRLEN];

void StoreSnortInfoStrings(void)
{
    strncpy(__snort_version_string, SNORT_VERSION_STRING,
        sizeof(__snort_version_string));
}

#undef SNORT_VERSION_STRING
#undef SNORT_VERSION_STRLEN

/****************************************************************************
 *
 * Function: DisplayBanner()
 *
 * Purpose:  Show valuable proggie info
 *
 * Arguments: None.
 *
 * Returns: 0 all the time
 *
 ****************************************************************************/
int DisplayBanner(void)
{
    const char* info = getenv("HOSTTYPE");

    if ( !info )
        info="from 2.9.7-177";  // last sync with head

    const char* ljv = LUAJIT_VERSION;
    while ( *ljv && !isdigit(*ljv) )
        ++ljv;

    LogMessage("\n");
    LogMessage("   ,,_     -*> Snort++ <*-\n");
    LogMessage("  o\"  )~   Version %s (Build %s) %s\n",
        VERSION, BUILD, info);
    LogMessage("   ''''    By Martin Roesch & The Snort Team\n");
    LogMessage("           http://snort.org/contact#team\n");
    LogMessage(
        "           Copyright (C) 2014-2015 Cisco and/or its affiliates. All rights reserved.\n");
    LogMessage("           Copyright (C) 1998-2013 Sourcefire, Inc., et al.\n");
#ifdef HAVE_PCAP_LIB_VERSION
    LogMessage("           Using %s\n", pcap_lib_version());
#endif
    LogMessage("           Using LuaJIT version %s\n", ljv);
    LogMessage("           Using PCRE version %s\n", pcre_version());
    LogMessage("           Using ZLIB version %s\n", zlib_version);
#ifdef HAVE_LZMA
    LogMessage("           Using LZMA version %s\n", lzma_version_string());
#endif
#ifdef HAVE_OPENSSL_SHA
    LogMessage("           Using %s\n", SSLeay_version(SSLEAY_VERSION));
#endif
    LogMessage("\n");

    return 0;
}

/****************************************************************************
 *
 * Function: ts_print(const struct, char *)
 *
 * Purpose: Generate a time stamp and stuff it in a buffer.  This one has
 *          millisecond precision.  Oh yeah, I ripped this code off from
 *          TCPdump, props to those guys.
 *
 * Arguments: timeval => clock struct coming out of libpcap
 *            timebuf => buffer to stuff timestamp into
 *
 * Returns: void function
 *
 ****************************************************************************/
void ts_print(const struct timeval* tvp, char* timebuf)
{
    int s;
    int localzone;
    time_t Time;
    struct timeval tv;
    struct timezone tz;
    struct tm* lt;    /* place to stick the adjusted clock data */

    /* if null was passed, we use current time */
    if (!tvp)
    {
        /* manual page (for linux) says tz is never used, so.. */
        memset((char*)&tz, 0, sizeof(tz));
        gettimeofday(&tv, &tz);
        tvp = &tv;
    }

    localzone = snort_conf->thiszone;

    /*
    **  If we're doing UTC, then make sure that the timezone is correct.
    */
    if (SnortConfig::output_use_utc())
        localzone = 0;

    s = (tvp->tv_sec + localzone) % 86400;
    Time = (tvp->tv_sec + localzone) - s;

    struct tm ttm;
    lt = gmtime_r(&Time, &ttm);

    if (SnortConfig::output_include_year())
    {
        int year = (lt->tm_year >= 100) ? (lt->tm_year - 100) : lt->tm_year;

        (void)SnortSnprintf(timebuf, TIMEBUF_SIZE,
            "%02d/%02d/%02d-%02d:%02d:%02d.%06u",
            lt->tm_mon + 1, lt->tm_mday, year,
            s / 3600, (s % 3600) / 60, s % 60,
            (u_int)tvp->tv_usec);
    }
    else
    {
        (void)SnortSnprintf(timebuf, TIMEBUF_SIZE,
            "%02d/%02d-%02d:%02d:%02d.%06u", lt->tm_mon + 1,
            lt->tm_mday, s / 3600, (s % 3600) / 60, s % 60,
            (u_int)tvp->tv_usec);
    }
}

/****************************************************************************
 *
 * Function: gmt2local(time_t)
 *
 * Purpose: Figures out how to adjust the current clock reading based on the
 *          timezone you're in.  Ripped off from TCPdump.
 *
 * Arguments: time_t => offset from GMT
 *
 * Returns: offset seconds from GMT
 *
 ****************************************************************************/
int gmt2local(time_t t)
{
    if (t == 0)
        t = time(NULL);

    struct tm gmt;
    gmtime_r(&t, &gmt);

    struct tm loc;
    localtime_r(&t, &loc);

    int dt = (loc.tm_hour - gmt.tm_hour) * 60 * 60 +
        (loc.tm_min - gmt.tm_min) * 60;

    int dir = loc.tm_year - gmt.tm_year;

    if (dir == 0)
        dir = loc.tm_yday - gmt.tm_yday;

    dt += dir * 24 * 60 * 60;

    return(dt);
}

static FILE* pid_lockfile = NULL;
static FILE* pid_file = NULL;

void CreatePidFile(pid_t pid)
{
    snort_conf->pid_filename = snort_conf->log_dir;
    snort_conf->pid_filename += "/snort.pid";

    if ( !SnortConfig::no_lock_pid_file() )
    {
        std::string pid_lockfilename = snort_conf->pid_filename;
        pid_lockfilename += ".lck";
        int lock_fd;

        /* First, lock the PID file */
        pid_lockfile = fopen(pid_lockfilename.c_str(), "w");

        if ( pid_lockfile )
        {
            struct flock lock;
            lock_fd = fileno(pid_lockfile);

            lock.l_type = F_WRLCK;
            lock.l_whence = SEEK_SET;
            lock.l_start = 0;
            lock.l_len = 0;

            if (fcntl(lock_fd, F_SETLK, &lock) == -1)
            {
                ClosePidFile();
                ParseError("Failed to Lock PID File \"%s\" for PID \"%d\"\n",
                    snort_conf->pid_filename.c_str(), (int)pid);
                return;
            }
        }
    }

    /* Okay, were able to lock PID file, now open and write PID */
    pid_file = fopen(snort_conf->pid_filename.c_str(), "w");
    if (pid_file)
    {
        LogMessage("Writing PID \"%d\" to file \"%s\"\n", (int)pid,
            snort_conf->pid_filename.c_str());
        fprintf(pid_file, "%d\n", (int)pid);
        fflush(pid_file);
    }
    else
    {
        const char* error = get_error(errno);
        ErrorMessage("Failed to create pid file %s, Error: %s",
            snort_conf->pid_filename.c_str(), error);
        snort_conf->pid_filename.clear();
    }
}

/****************************************************************************
 *
 * Function: ClosePidFile(char *)
 *
 * Purpose:  Releases lock on a PID file
 *
 * Arguments: None
 *
 * Returns: void function
 *
 ****************************************************************************/
void ClosePidFile(void)
{
    if (pid_file)
    {
        fclose(pid_file);
        pid_file = NULL;
    }
    if (pid_lockfile)
    {
        fclose(pid_lockfile);
        pid_lockfile = NULL;
    }
}

/****************************************************************************
 *
 * Function: SetUidGid()
 *
 * Purpose:  Sets safe UserID and GroupID if needed
 *
 * Arguments: none
 *
 * Returns: void function
 *
 ****************************************************************************/
void SetUidGid(int user_id, int group_id)
{
    if ((group_id != -1) && (getgid() != (gid_t)group_id))
    {
        if ( !DAQ_Unprivileged() )
            ParseError("cannot set uid and gid - %s DAQ does not"
                " support unprivileged operation.\n", DAQ_GetType());

        else if (setgid(group_id) < 0)
            ParseError("Cannot set gid: %d\n", group_id);

        else
            LogMessage("Set gid to %d\n", group_id);
    }

    if ((user_id != -1) && (getuid() != (uid_t)user_id))
    {
        if ( !DAQ_Unprivileged() )
            ParseError("cannot set uid and gid - %s DAQ does not"
                " support unprivileged operation.\n", DAQ_GetType());

        else if (setuid(user_id) < 0)
            ParseError("Can not set uid: %d\n", user_id);

        else
            LogMessage("Set uid to %d\n", user_id);
    }
}

/****************************************************************************
 *
 * Function: InitGroups()
 *
 * Purpose:  Sets the groups of the process based on the UserID with the
 *           GroupID added
 *
 * Arguments: none
 *
 * Returns: void function
 *
 ****************************************************************************/
void InitGroups(int user_id, int group_id)
{
    if ((user_id != -1) && (getuid() == 0))
    {
        struct passwd* pw = getpwuid(user_id);  // main thread only

        if (pw != NULL)
        {
            /* getpwuid and initgroups may use the same static buffers */
            char* username = SnortStrdup(pw->pw_name);

            if (initgroups(username, group_id) < 0)
            {
                ParseError("Can not initgroups(%s,%d)", username, group_id);
            }

            free(username);
        }

        /** Just to be on the safe side... **/
        endgrent();
        endpwent();
    }
}

//-------------------------------------------------------------------------

// FIXIT-L  This is a duplicate of PacketManager::get_proto_name().0
void InitProtoNames(void)
{
    int i;

    if (protocol_names == NULL)
        protocol_names = (char**)SnortAlloc(sizeof(char*) * NUM_IP_PROTOS);

    for (i = 0; i < NUM_IP_PROTOS; i++)
    {
#ifndef VALGRIND_TESTING
        struct protoent* pt = getprotobynumber(i);  // main thread only

        if (pt != NULL)
        {
            size_t j;

            protocol_names[i] = SnortStrdup(pt->p_name);
            for (j = 0; j < strlen(protocol_names[i]); j++)
                protocol_names[i][j] = toupper(protocol_names[i][j]);
        }
        else
#endif
        {
            char protoname[10];

            SnortSnprintf(protoname, sizeof(protoname), "PROTO:%03d", i);
            protocol_names[i] = SnortStrdup(protoname);
        }
    }
}

void CleanupProtoNames(void)
{
    if (protocol_names != NULL)
    {
        int i;

        for (i = 0; i < NUM_IP_PROTOS; i++)
        {
            if (protocol_names[i] != NULL)
                free(protocol_names[i]);
        }

        free(protocol_names);
        protocol_names = NULL;
    }
}

/****************************************************************************
 *
 * Function: read_infile(const char* key, const char* file)
 *
 * Purpose: Reads the BPF filters in from a file.  Ripped from tcpdump.
 *
 * Arguments: fname => the name of the file containing the BPF filters
 *
 * Returns: the processed BPF string
 *
 ****************************************************************************/
char* read_infile(const char* key, const char* fname)
{
    int fd, cc;
    char* cp, * cmt;
    struct stat buf;

    fd = open(fname, O_RDONLY);

    if (fd < 0)
    {
        ParseError("can't open %s = %s: %s\n", key, fname, get_error(errno));
        return nullptr;
    }

    if (fstat(fd, &buf) < 0)
    {
        ParseError("can't stat %s: %s\n", fname, get_error(errno));
        return nullptr;
    }

    cp = (char*)SnortAlloc(((u_int)buf.st_size + 1) * sizeof(char));

    cc = read(fd, cp, (int)buf.st_size);

    if (cc < 0)
    {
        ParseError("read %s: %s\n", fname, get_error(errno));
        free(cp);
        return nullptr;
    }

    if (cc != buf.st_size)
    {
        ParseError("short read %s (%d != %d)\n", fname, cc, (int)buf.st_size);
        free(cp);
        return nullptr;
    }

    cp[(int)buf.st_size] = '\0';

    close(fd);

    /* Treat everything upto the end of the line as a space
     *  so that we can put comments in our BPF filters
     */

    while ((cmt = strchr(cp, '#')) != NULL)
    {
        while (*cmt != '\r' && *cmt != '\n' && *cmt != '\0')
        {
            *cmt++ = ' ';
        }
    }

    /** LogMessage("BPF filter file: %s\n", fname); **/

    return(cp);
}

/* Guaranteed to be '\0' terminated even if truncation occurs.
 *
 * returns  SNORT_SNPRINTF_SUCCESS if successful
 * returns  SNORT_SNPRINTF_TRUNCATION on truncation
 * returns  SNORT_SNPRINTF_ERROR on error
 */
int SnortSnprintf(char* buf, size_t buf_size, const char* format, ...)
{
    va_list ap;
    int ret;

    if (buf == NULL || buf_size <= 0 || format == NULL)
        return SNORT_SNPRINTF_ERROR;

    /* zero first byte in case an error occurs with
     * vsnprintf, so buffer is null terminated with
     * zero length */
    buf[0] = '\0';
    buf[buf_size - 1] = '\0';

    va_start(ap, format);

    ret = vsnprintf(buf, buf_size, format, ap);

    va_end(ap);

    if (ret < 0)
        return SNORT_SNPRINTF_ERROR;

    if (buf[buf_size - 1] != '\0' || (size_t)ret >= buf_size)
    {
        /* result was truncated */
        buf[buf_size - 1] = '\0';
        return SNORT_SNPRINTF_TRUNCATION;
    }

    return SNORT_SNPRINTF_SUCCESS;
}

/* Appends to a given string
 * Guaranteed to be '\0' terminated even if truncation occurs.
 *
 * returns SNORT_SNPRINTF_SUCCESS if successful
 * returns SNORT_SNPRINTF_TRUNCATION on truncation
 * returns SNORT_SNPRINTF_ERROR on error
 */
int SnortSnprintfAppend(char* buf, size_t buf_size, const char* format, ...)
{
    int str_len;
    int ret;
    va_list ap;

    if (buf == NULL || buf_size <= 0 || format == NULL)
        return SNORT_SNPRINTF_ERROR;

    str_len = SnortStrnlen(buf, buf_size);

    /* since we've already checked buf and buf_size an error
     * indicates no null termination, so just start at
     * beginning of buffer */
    if (str_len == SNORT_STRNLEN_ERROR)
    {
        buf[0] = '\0';
        str_len = 0;
    }

    buf[buf_size - 1] = '\0';

    va_start(ap, format);

    ret = vsnprintf(buf + str_len, buf_size - (size_t)str_len, format, ap);

    va_end(ap);

    if (ret < 0)
        return SNORT_SNPRINTF_ERROR;

    if (buf[buf_size - 1] != '\0' || (size_t)ret >= buf_size)
    {
        /* truncation occured */
        buf[buf_size - 1] = '\0';
        return SNORT_SNPRINTF_TRUNCATION;
    }

    return SNORT_SNPRINTF_SUCCESS;
}

/* Guaranteed to be '\0' terminated even if truncation occurs.
 *
 * Arguments:  dst - the string to contain the copy
 *             src - the string to copy from
 *             dst_size - the size of the destination buffer
 *                        including the null byte.
 *
 * returns SNORT_STRNCPY_SUCCESS if successful
 * returns SNORT_STRNCPY_TRUNCATION on truncation
 * returns SNORT_STRNCPY_ERROR on error
 *
 * Note: Do not set dst[0] = '\0' on error since it's possible that
 * dst and src are the same pointer - it will at least be null
 * terminated in any case
 */
int SnortStrncpy(char* dst, const char* src, size_t dst_size)
{
    char* ret = NULL;

    if (dst == NULL || src == NULL || dst_size <= 0)
        return SNORT_STRNCPY_ERROR;

    dst[dst_size - 1] = '\0';

    ret = strncpy(dst, src, dst_size);

    /* Not sure if this ever happens but might as
     * well be on the safe side */
    if (ret == NULL)
        return SNORT_STRNCPY_ERROR;

    if (dst[dst_size - 1] != '\0')
    {
        /* result was truncated */
        dst[dst_size - 1] = '\0';
        return SNORT_STRNCPY_TRUNCATION;
    }

    return SNORT_STRNCPY_SUCCESS;
}

char* SnortStrndup(const char* src, size_t dst_size)
{
    char* ret = (char*)SnortAlloc(dst_size + 1);
    int ret_val;

    ret_val = SnortStrncpy(ret, src, dst_size + 1);

    if (ret_val == SNORT_STRNCPY_ERROR)
    {
        free(ret);
        return NULL;
    }

    return ret;
}

/* Determines whether a buffer is '\0' terminated and returns the
 * string length if so
 *
 * returns the string length if '\0' terminated
 * returns SNORT_STRNLEN_ERROR if not '\0' terminated
 */
int SnortStrnlen(const char* buf, int buf_size)
{
    int i = 0;

    if (buf == NULL || buf_size <= 0)
        return SNORT_STRNLEN_ERROR;

    for (i = 0; i < buf_size; i++)
    {
        if (buf[i] == '\0')
            break;
    }

    if (i == buf_size)
        return SNORT_STRNLEN_ERROR;

    return i;
}

char* SnortStrdup(const char* str)
{
    assert(str);
    char* copy = strdup(str);

    if ( !copy )
    {
        FatalError("Unable to duplicate string: %s\n", str);
    }

    return copy;
}

/*
 * Find first occurrence of char of accept in s, limited by slen.
 * A 'safe' version of strpbrk that won't read past end of buffer s
 * in cases that s is not NULL terminated.
 *
 * This code assumes 'accept' is a static string.
 */
const char* SnortStrnPbrk(const char* s, int slen, const char* accept)
{
    char ch;
    const char* s_end;
    if (!s || (slen == 0) || !*s || !accept)
        return NULL;

    s_end = s + slen;
    while (s < s_end)
    {
        ch = *s;
        if (strchr(accept, ch))
            return s;
        s++;
    }
    return NULL;
}

/*
 * Find first occurrence of searchstr in s, limited by slen.
 * A 'safe' version of strstr that won't read past end of buffer s
 * in cases that s is not NULL terminated.
 */
const char* SnortStrnStr(const char* s, int slen, const char* searchstr)
{
    char ch, nc;
    int len;
    if (!s || (slen == 0) || !*s || !searchstr)
        return NULL;

    if ((ch = *searchstr++) != 0)
    {
        len = strlen(searchstr);
        do
        {
            do
            {
                if ((nc = *s++) == 0)
                {
                    return NULL;
                }
                slen--;
                if (slen == 0)
                    return NULL;
            }
            while (nc != ch);
            if (slen - len < 0)
                return NULL;
        }
        while (memcmp(s, searchstr, len) != 0);
        s--;
    }
    return s;
}

/*
 * Find first occurrence of substring in s, ignore case.
*/
const char* SnortStrcasestr(const char* s, int slen, const char* substr)
{
    char ch, nc;
    int len;

    if (!s || (slen == 0) || !*s || !substr)
        return NULL;

    if ((ch = *substr++) != 0)
    {
        ch = tolower((char)ch);
        len = strlen(substr);
        do
        {
            do
            {
                if ((nc = *s++) == 0)
                {
                    return NULL;
                }
                slen--;
                if (slen == 0)
                    return NULL;
            }
            while ((char)tolower((uint8_t)nc) != ch);
            if (slen - len < 0)
                return NULL;
        }
        while (strncasecmp(s, substr, len) != 0);
        s--;
    }
    return s;
}

/**
 * Chroot and adjust the snort_conf->log_dir reference
 *
 * @param directory directory to chroot to
 * @param logstore ptr to snort_conf->log_dir which must be dynamically allocated
 */
void SetChroot(std::string directory, std::string& logstore)
{
    char* absdir;
    size_t abslen;

    if ( logstore.empty() )
    {
        ParseError("Null log directory\n");
        return;
    }

    DebugFormat(DEBUG_INIT,"SetChroot: %s\n", CurrentWorkingDir());

    const char* logdir = GetAbsolutePath(logstore.c_str());

    DebugFormat(DEBUG_INIT, "SetChroot: %s\n", CurrentWorkingDir());

    /* change to the directory */
    if (chdir(directory.c_str()) != 0)
    {
        ParseError("SetChroot: Can not chdir to \"%s\": %s\n", directory.c_str(),
            get_error(errno));
        return;
    }

    /* always returns an absolute pathname */
    absdir = CurrentWorkingDir();

    if (absdir == NULL)
    {
        ParseError("NULL Chroot found\n");
        return;
    }

    abslen = strlen(absdir);

    DebugFormat(DEBUG_INIT, "ABS: %s %d\n", absdir, abslen);

    /* make the chroot call */
    if (chroot(absdir) < 0)
    {
        ParseError("Can not chroot to \"%s\": absolute: %s: %s\n",
            directory.c_str(), absdir, get_error(errno));
        return;
    }

    DebugFormat(DEBUG_INIT,"chroot success (%s ->", absdir);
    DebugFormat(DEBUG_INIT,"%s)\n ", CurrentWorkingDir());

    /* change to "/" in the new directory */
    if (chdir("/") < 0)
    {
        ParseError("Can not chdir to \"/\" after chroot: %s\n",
            get_error(errno));
        return;
    }

    DebugFormat(DEBUG_INIT,"chdir success (%s)\n", CurrentWorkingDir());

    if (strncmp(absdir, logdir, strlen(absdir)))
    {
        ParseError("Absdir is not a subset of the logdir");
        return;
    }

    if (abslen >= strlen(logdir))
    {
        logstore = "/";
    }
    else
    {
        logstore = logdir + abslen;
    }

    DebugFormat(DEBUG_INIT,"new logdir from %s to %s\n",
        logdir, logstore.c_str());

    LogMessage("Chroot directory = %s\n", directory.c_str());
}

/**
 * Return a ptr to the absolute pathname of snort.  This memory must
 * be copied to another region if you wish to save it for later use.
 */
char* CurrentWorkingDir(void)
{
    static THREAD_LOCAL char buf[PATH_MAX_UTIL + 1];

    if (getcwd((char*)buf, PATH_MAX_UTIL) == NULL)
    {
        return NULL;
    }

    buf[PATH_MAX_UTIL] = '\0';

    return (char*)buf;
}

/**
 * Given a directory name, return a ptr to a static
 */
char* GetAbsolutePath(const char* dir)
{
    char* savedir, * dirp;
    static THREAD_LOCAL char buf[PATH_MAX_UTIL + 1];

    if (dir == NULL)
    {
        return NULL;
    }

    savedir = strdup(CurrentWorkingDir());

    if (savedir == NULL)
    {
        return NULL;
    }

    if (chdir(dir) < 0)
    {
        LogMessage("Can't change to directory: %s\n", dir);
        free(savedir);
        return NULL;
    }

    dirp = CurrentWorkingDir();

    if (dirp == NULL)
    {
        LogMessage("Unable to access current directory\n");
        free(savedir);
        return NULL;
    }
    else
    {
        strncpy(buf, dirp, PATH_MAX_UTIL);
        buf[PATH_MAX_UTIL] = '\0';
    }

    if (chdir(savedir) < 0)
    {
        LogMessage("Can't change back to directory: %s\n", dir);
        free(savedir);
        return NULL;
    }

    free(savedir);
    return (char*)buf;
}

int CheckValueInRange(const char* value_str, const char* option,
    unsigned long lo, unsigned long hi, unsigned long* value)
{
    char* endptr;
    uint32_t val;

    if ( value_str == NULL )
    {
        ParseError("invalid format for %s.", option);
        return -1;
    }

    if (SnortStrToU32(value_str, &endptr, &val, 10))
    {
        ParseError("invalid format for %s.", option);
        return -1;
    }

    if (*endptr)
    {
        ParseError("invalid format for %s.", option);
        return -1;
    }

    *value = val;

    if ( (errno == ERANGE) || (*value) < lo || (*value) > hi)
    {
        ParseError("invalid value for %s."
            "It should range between %u and %u.", option,
            lo, hi);
        return -1;
    }

    return 0;
}

void SetNoCores(void)
{
    struct rlimit rlim;

    getrlimit(RLIMIT_CORE, &rlim);
    rlim.rlim_max = 0;
    setrlimit(RLIMIT_CORE, &rlim);
}

const char* get_error(int errnum)
{
    static THREAD_LOCAL char buf[128];
    (void)strerror_r(errnum, buf, sizeof(buf));
    return buf;
}

char* get_tok(char* s, const char* delim)
{
    static THREAD_LOCAL char* lasts = nullptr;
    return strtok_r(s, delim, &lasts);
}

