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

char _bytes_to_string[1024];
static inline char *
bytes_to_string (unsigned char *buffer, size_t length)
{
    char *pt = _bytes_to_string;
    int i;
    _bytes_to_string[0] = '\0';
    for (i = 0; i < length; i++, buffer++)
    {
        if (isprint (*buffer))
            pt += sprintf (pt, "%c", *((char *) buffer));
        else
            pt += sprintf (pt, "\\%02x", *buffer);
    }
    return _bytes_to_string;
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
        fprintf (stderr, "[%"PRIu64":%d] ", get_time_us (), getpid ()); \
        fprintf (stderr, "ERROR: "); \
        fprintf (stderr, fmt, ## args); \
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
    uint64_t set;
    uint64_t set_invalid;
    uint64_t get;
    uint64_t get_invalid;
    uint64_t search;
    uint64_t search_invalid;
    uint64_t watch;
    uint64_t watch_invalid;
    uint64_t watched;
    uint64_t watched_no_match;
    uint64_t watched_no_handler;
    uint64_t watched_timeout;
    uint64_t provide;
    uint64_t provide_invalid;
    uint64_t provided;
    uint64_t provided_no_handler;
    uint64_t prune;
    uint64_t prune_invalid;
} counters_t;
#define INC_COUNTER(c) (void)__sync_fetch_and_add(&c, 1);

/* Database API */
void db_init (void);
void db_shutdown (void);
bool db_add (const char *path, const unsigned char *value, size_t length);
bool db_delete (const char *path);
bool db_get (const char *path, unsigned char **value, size_t *length);
GList *db_search (const char *path);

/* RPC API */
#define RPC_TIMEOUT_US 1000000
bool rpc_provide_service (const char *name, ProtobufCService *service, int num_threads, int stopfd);
ProtobufCService *rpc_connect_service (const char *name, const ProtobufCServiceDescriptor *descriptor);

/* SHM cache */
#define APTERYX_SHM_KEY    0xda7aba5e
void cache_init (void);
void cache_shutdown (bool force);
bool cache_set (const char *path, unsigned char *value, size_t size);
bool cache_get (const char *path, unsigned char **value, size_t *size);

#endif /* _INTERNAL_H_ */
