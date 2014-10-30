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
#include <google/protobuf-c/protobuf-c.h>

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
        fprintf (stderr, "ERROR: "); \
        fprintf (stderr, fmt, ## args); \
    }

#define FATAL(fmt, args...) \
    { \
        syslog (LOG_CRIT, fmt, ## args); \
        fprintf (stderr, "ERROR: "); \
        fprintf (stderr, fmt, ## args); \
        running = false; \
    }

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
    uint64_t provide;
    uint64_t provide_invalid;
    uint64_t provided;
    uint64_t provided_no_handler;
    uint64_t prune;
    uint64_t prune_invalid;
} counters_t;

/* Database API */
void db_init (void);
void db_shutdown (void);
bool db_add (const char *path, const unsigned char *value, size_t length);
bool db_delete (const char *path);
bool db_get (const char *path, unsigned char **value, size_t *length);
GList *db_search (const char *path);

/* RPC API */
bool rpc_provide_service (const char *name, ProtobufCService *service, int num_threads, int stopfd);
ProtobufCService *rpc_connect_service (const char *name, const ProtobufCServiceDescriptor *descriptor);

#ifdef NEW_PROTOBUF_C_RPC
#define protobuf_c_return int32_t
#define protobuf_c_return_good 0
#define protobuf_c_return_bad -1
#define APTERYX__SERVER__INIT APTERYX_SERVER_INIT
#define apteryx__Server_Service apteryx_server_Service
#define apteryx__server__descriptor apteryx_server_descriptor

#define APTERYX__CLIENT__INIT APTERYX_CLIENT_INIT
#define apteryx__Client_Service apteryx_client_Service
#define apteryx__client__descriptor apteryx_client_descriptor

#define apteryx__OKResult apteryx_OKResult
#define apteryx__OKResult_Closure apteryx_OKResult_Closure
#define APTERYX__OKRESULT__INIT APTERYX_OKRESULT_INIT

#define apteryx__Set apteryx_Set
#define APTERYX__SET__INIT APTERYX_SET_INIT
#define apteryx__server__set apteryx_server_set

#define apteryx__Get apteryx_Get
#define APTERYX__GET__INIT APTERYX_GET_INIT
#define apteryx__server__get apteryx_server_get

#define apteryx__GetResult apteryx_GetResult
#define apteryx__GetResult_Closure apteryx_GetResult_Closure
#define APTERYX__GET_RESULT__INIT APTERYX_GET_RESULT_INIT

#define apteryx__Search apteryx_Search
#define APTERYX__SEARCH__INIT APTERYX_SEARCH_INIT
#define apteryx__server__search apteryx_server_search

#define apteryx__SearchResult apteryx_SearchResult
#define apteryx__SearchResult_Closure apteryx_SearchResult_Closure
#define APTERYX__SEARCH_RESULT__INIT APTERYX_SEARCH_RESULT_INIT

#define apteryx__Watch apteryx_Watch
#define APTERYX__WATCH__INIT APTERYX_WATCH_INIT
#define apteryx__client__watch apteryx_client_watch
#define apteryx__server__watch apteryx_server_watch

#define apteryx__Provide apteryx_Provide
#define APTERYX__PROVIDE__INIT APTERYX_PROVIDE_INIT
#define apteryx__client__provide apteryx_client_provide
#define apteryx__server__provide apteryx_server_provide

#define apteryx__Prune apteryx_Prune
#define APTERYX__PRUNE__INIT APTERYX_PRUNE_INIT
#define apteryx__server__prune apteryx_server_prune

#else
#define protobuf_c_return void
#define protobuf_c_return_good
#define protobuf_c_return_bad
#endif

#endif /* _INTERNAL_H_ */
