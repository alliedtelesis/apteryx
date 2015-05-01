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
#include <inttypes.h>
#include <ctype.h>
#include <sys/time.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <syslog.h>
#include <glib.h>
#include <protobuf-c/protobuf-c.h>

/* UNIX socket paths */
#define APTERYX_SERVER  "/tmp/apteryx"

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
#define APTERYX_SETTINGS "/apteryx/"
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

/* Internal */
#define APTERYX_SETTINGS "/apteryx/"
/* Counters */
typedef struct _counters_t
{
    uint32_t set;
    uint32_t set_invalid;
    uint32_t get;
    uint32_t get_invalid;
    uint32_t search;
    uint32_t search_invalid;
    uint32_t watch;
    uint32_t watch_invalid;
    uint32_t unwatch;
    uint32_t unwatch_invalid;
    uint32_t watched;
    uint32_t watched_no_match;
    uint32_t watched_no_handler;
    uint32_t watched_timeout;
    uint32_t validation;
    uint32_t validation_invalid;
    uint32_t unvalidation;
    uint32_t unvalidation_invalid;
    uint32_t provide;
    uint32_t provide_invalid;
    uint32_t unprovide;
    uint32_t unprovide_invalid;
    uint32_t provided;
    uint32_t provided_no_handler;
    uint32_t prune;
    uint32_t prune_invalid;
    uint32_t get_ts;
    uint32_t get_ts_invalid;
} counters_t;
#define INC_COUNTER(c) (void)g_atomic_int_inc(&c);

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
bool rpc_provide_service (const char *name, ProtobufCService *service, int num_threads, int stopfd);
ProtobufCService *rpc_connect_service (const char *name, const ProtobufCServiceDescriptor *descriptor);

/* SHM cache */
#define APTERYX_SHM_KEY    0xda7aba5e
void cache_init (void);
void cache_shutdown (bool force);
bool cache_set (const char *path, const char *value);
char* cache_get (const char *path);
char* cache_dump_table (void);

#endif /* _INTERNAL_H_ */
