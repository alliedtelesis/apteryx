/**
 * @file internal.h
 * Internal header for Apteryx.
 *
 * Copyright 2014, Allied Telesis Labs New Zealand, Ltd
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 3 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this library. If not, see <http://www.gnu.org/licenses/>
 */
#ifndef _INTERNAL_H_
#define _INTERNAL_H_
#include <stdio.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <inttypes.h>
#include <assert.h>
#include <ctype.h>
#include <string.h>
#include <sys/time.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <syslog.h>
#include <glib.h>

/* Default UNIX socket path */
#define APTERYX_SERVER  "unix:///tmp/apteryx"
/* Default PID file */
#define APTERYX_PID     "/var/run/apteryxd.pid"

#define RPC_TIMEOUT_US 1000000
#define RPC_CLIENT_TIMEOUT_US 1000000
#define RPC_TEST_DELAY_MASK 0x7FF

/* Mode */
typedef enum
{
    MODE_SET,
    MODE_GET,
    MODE_FIND,
    MODE_TRAVERSE,
    MODE_WATCH,
    MODE_PROVIDE,
    MODE_PROXY,
    MODE_PRUNE,
    MODE_TIMESTAMP,
    MODE_TEST,
} APTERYX_MODE;

/* Debug */
extern bool apteryx_debug;

static inline uint64_t
get_time_us (void)
{
    struct timeval tv;
    gettimeofday (&tv, NULL);
    return (tv.tv_sec * (uint64_t) 1000000 + tv.tv_usec);
}

static inline uint32_t htol32 (uint32_t v)
{
    if (htons(1) == 1)
        return ((v>>24)&0xff) | ((v>>8)&0xff00) | ((v<<8)&0xff0000) | ((v << 24)&0xff000000);
    else
        return v;
}
#define ltoh32 htol32

#define DEBUG(fmt, args...) \
    if (apteryx_debug) \
    { \
        syslog (LOG_DEBUG, fmt, ## args); \
        printf ("[%"PRIu64":%d] ", get_time_us (), getpid ()); \
        printf (fmt, ## args); \
    }

#define NOTICE(fmt, args...) \
    { \
        syslog (LOG_NOTICE, fmt, ## args); \
        if (apteryx_debug) \
        { \
            fprintf (stderr, "[%"PRIu64":%d] ", get_time_us (), getpid ()); \
            fprintf (stderr, "NOTICE: "); \
            fprintf (stderr, fmt, ## args); \
        } \
    }

#define ERROR(fmt, args...) \
    { \
        syslog (LOG_ERR, fmt, ## args); \
        if (apteryx_debug) \
        { \
            fprintf (stderr, "[%"PRIu64":%d] ", get_time_us (), getpid ()); \
            fprintf (stderr, "ERROR: "); \
            fprintf (stderr, fmt, ## args); \
        } \
    }

#define ASSERT(assertion, rcode, fmt, args...) \
    if (!(assertion)) \
    { \
        syslog (LOG_ERR, fmt, ## args); \
        if (apteryx_debug) \
        { \
            fprintf (stderr, "[%"PRIu64":%d] ", get_time_us (), getpid ()); \
            fprintf (stderr, "ASSERT: "); \
            fprintf (stderr, fmt, ## args); \
        } \
        rcode; \
    }

#define FATAL(fmt, args...) \
    { \
        syslog (LOG_CRIT, fmt, ## args); \
        fprintf (stderr, "[%"PRIu64":%d] ", get_time_us (), getpid ()); \
        fprintf (stderr, "ERROR: "); \
        fprintf (stderr, fmt, ## args); \
        running = false; \
    }

#define CRITICAL(fmt, args...) \
    { \
        syslog (LOG_CRIT, fmt, ## args); \
        fprintf (stderr, "[%"PRIu64":%d] ", get_time_us (), getpid ()); \
        fprintf (stderr, "ERROR: "); \
        fprintf (stderr, fmt, ## args); \
    }

/* Callback */
typedef struct _cb_info_t
{
    bool active;

    const char *guid;
    const char *path;
    const char *uri;
    uint64_t id;
    uint64_t cb;

    GList **list;
    int refcnt;
    uint32_t count;
} cb_info_t;

/* Database API */
extern pthread_rwlock_t db_lock;
void db_init (void);
void db_shutdown (bool force);
bool db_add (const char *path, const unsigned char *value, size_t length, uint64_t ts);
bool db_add_no_lock (const char *path, const unsigned char *value, size_t length, uint64_t ts);
bool db_delete (const char *path, uint64_t ts);
bool db_delete_no_lock (const char *path, uint64_t ts);
bool db_get (const char *path, unsigned char **value, size_t *length);
GList *db_search (const char *path);
bool db_prune (const char *path);
uint64_t db_timestamp (const char *path);

/* Apteryx configuration */
void config_init (void);

/* Callbacks to clients */
extern GList *watch_list;
extern GList *validation_list;
extern GList *provide_list;
extern GList *index_list;
extern GList *proxy_list;
void cb_init (void);
cb_info_t * cb_create (GList **list, const char *guid, const char *path, uint64_t id, uint64_t callback);
void cb_destroy (cb_info_t *cb);
void cb_release (cb_info_t *cb);
cb_info_t * cb_find (GList **list, const char *guid);
#define CB_MATCH_PART       (1<<0)
#define CB_MATCH_EXACT      (1<<1)
#define CB_MATCH_WILD       (1<<2)
#define CB_MATCH_CHILD      (1<<3)
#define CB_MATCH_WILD_PATH  (1<<4)
#define CB_PATH_MATCH_PART  (1<<5)
GList *cb_match (GList **list, const char *path, int critera);
void cb_shutdown (void);

/* Tests */
void run_unit_tests (const char *filter);

#endif /* _INTERNAL_H_ */
