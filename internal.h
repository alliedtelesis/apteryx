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
#include <ctype.h>
#include <string.h>
#include <sys/time.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <syslog.h>
#include <glib.h>
#include <protobuf-c/protobuf-c.h>

/* Default UNIX socket path */
#define APTERYX_SERVER  "unix:///tmp/apteryx"
/* Default PID file */
#define APTERYX_PID     "/var/run/apteryxd.pid"

/* Mode */
typedef enum
{
    MODE_SET,
    MODE_GET,
    MODE_FIND,
    MODE_TRAVERSE,
    MODE_WATCH,
    MODE_PROVIDE,
    MODE_PRUNE,
    MODE_TIMESTAMP,
} APTERYX_MODE;

/* Debug */
extern bool debug;
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
    if (debug) \
    { \
        syslog (LOG_DEBUG, fmt, ## args); \
        printf ("[%"PRIu64":%d] ", get_time_us (), getpid ()); \
        printf (fmt, ## args); \
    }
#define ERROR(fmt, args...) \
    { \
        syslog (LOG_ERR, fmt, ## args); \
        if (debug) \
        { \
            fprintf (stderr, "[%"PRIu64":%d] ", get_time_us (), getpid ()); \
            fprintf (stderr, "ERROR: "); \
            fprintf (stderr, fmt, ## args); \
        } \
    }

#define FATAL(fmt, args...) \
    { \
        syslog (LOG_CRIT, fmt, ## args); \
        fprintf (stderr, "[%"PRIu64":%d] ", get_time_us (), getpid ()); \
        fprintf (stderr, "ERROR: "); \
        fprintf (stderr, fmt, ## args); \
        running = false; \
    }

/* Callback */
typedef struct _cb_info_t
{
    const char *guid;
    const char *path;
    uint64_t id;
    uint64_t cb;
    uint32_t count;
} cb_info_t;

/* Watch, provide and validation callbacks */
extern GList *watch_list;
extern GList *validation_list;
extern GList *provide_list;
extern pthread_mutex_t list_lock;

/* Free cb info */
static inline void
cb_info_destroy (gpointer data)
{
    cb_info_t *info = (cb_info_t*)data;
    if (info->guid)
        free ((void *) info->guid);
    if (info->path)
        free ((void *) info->path);
    free (info);
}

static inline gpointer
cb_info_copy (cb_info_t *cb)
{
    cb_info_t *copy = calloc (1, sizeof (*copy));
    *copy = *cb;
    if (cb->guid)
        copy->guid = strdup (cb->guid);
    if (cb->path)
        copy->path = strdup (cb->path);
    return (gpointer)copy;
}

static inline cb_info_t *
cb_info_get (GList *list, const char *guid)
{
    GList *iter = NULL;
    cb_info_t *info;
    for (iter = list; iter; iter = iter->next)
    {
        info = (cb_info_t *) iter->data;
        if (info->guid && strcmp (info->guid, guid) == 0)
            break;
        info = NULL;
    }
    return info;
}

static inline cb_info_t *
cb_info_find (GList *list, const char *path, uint64_t id, uint64_t cb)
{
    GList *iter = NULL;
    cb_info_t *info;
    for (iter = list; iter; iter = iter->next)
    {
        /* We only allow a func to watch once per path+socket */
        info = (cb_info_t *) iter->data;
        if (info->id == id && info->cb == cb && strcmp (info->path, path) == 0)
            break;
        info = NULL;
    }
    return info;
}

/* Counters */
typedef struct _counters_t
{
    uint32_t set;
    uint32_t set_invalid;
    uint32_t get;
    uint32_t get_invalid;
    uint32_t search;
    uint32_t search_invalid;
    uint32_t watched;
    uint32_t watched_no_match;
    uint32_t watched_no_handler;
    uint32_t watched_timeout;
    uint32_t validation;
    uint32_t validation_failed;
    uint32_t provided;
    uint32_t provided_no_handler;
    uint32_t prune;
    uint32_t prune_invalid;
    uint32_t get_ts;
    uint32_t get_ts_invalid;
} counters_t;
#define INC_COUNTER(c) (void)g_atomic_int_inc(&c);

/* GLobal counters */
extern counters_t counters;

/* Database API */
void db_init (void);
void db_shutdown (void);
bool db_add (const char *path, const unsigned char *value, size_t length);
bool db_delete (const char *path);
bool db_get (const char *path, unsigned char **value, size_t *length);
GList *db_search (const char *path);
uint64_t db_get_timestamp (const char *path);

/* RPC API */
#define RPC_TIMEOUT_US 1000000
bool rpc_provide_service (const char *url, ProtobufCService *service, int num_threads, int stopfd);
bool rpc_bind_url (const char *id, const char *url);
bool rpc_unbind_url (const char *id, const char *url);
ProtobufCService *rpc_connect_service (const char *url, const ProtobufCServiceDescriptor *descriptor);

/* Apteryx configuration */
void config_init (void);

/* SHM cache */
#define APTERYX_SHM_KEY    0xda7aba5e
void cache_init (void);
void cache_shutdown (bool force);
bool cache_set (const char *path, const char *value);
char* cache_get (const char *path);
char* cache_dump_table (void);

#endif /* _INTERNAL_H_ */
