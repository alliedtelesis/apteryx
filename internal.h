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
#include "common.h"

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
    MODE_PROXY,
    MODE_PRUNE,
    MODE_TIMESTAMP,
    MODE_TEST,
} APTERYX_MODE;

/* Callback */
struct callback_node;
typedef struct _cb_info_t
{
    bool active;
    char type;
    const char *guid;
    const char *path;
    const char *uri;
    uint64_t id;
    uint64_t cb;

    struct callback_node *node;
    int refcnt;
    uint32_t count;
} cb_info_t;

#define X_FIELDS \
    X(uint32_t, set) \
    X(uint32_t, set_invalid) \
    X(uint32_t, get) \
    X(uint32_t, get_invalid) \
    X(uint32_t, search) \
    X(uint32_t, search_invalid) \
    X(uint32_t, traverse) \
    X(uint32_t, traverse_invalid) \
    X(uint32_t, indexed) \
    X(uint32_t, indexed_no_handler) \
    X(uint32_t, indexed_timeout) \
    X(uint32_t, watched) \
    X(uint32_t, watched_no_handler) \
    X(uint32_t, watched_timeout) \
    X(uint32_t, validated) \
    X(uint32_t, validated_no_handler) \
    X(uint32_t, validated_timeout) \
    X(uint32_t, provided) \
    X(uint32_t, provided_no_handler) \
    X(uint32_t, provided_timeout) \
    X(uint32_t, proxied) \
    X(uint32_t, proxied_no_handler) \
    X(uint32_t, proxied_timeout) \
    X(uint32_t, prune) \
    X(uint32_t, prune_invalid) \
    X(uint32_t, find) \
    X(uint32_t, find_invalid) \
    X(uint32_t, timestamp) \
    X(uint32_t, timestamp_invalid)

/* Counters */
typedef struct _counters_t
{
#define X(type, name) type name;
    X_FIELDS
#undef X
} counters_t;
#define INC_COUNTER(c) (void)g_atomic_int_inc(&c);

/* GLobal counters */
extern counters_t counters;

/* Database API */
extern pthread_rwlock_t db_lock;
void db_init (void);
void db_shutdown (void);
bool db_add (const char *path, const unsigned char *value, size_t length, uint64_t ts);
bool db_add_no_lock (const char *path, const unsigned char *value, size_t length, uint64_t ts);
bool db_delete (const char *path, uint64_t ts);
void db_prune (const char *path);
bool db_delete_no_lock (const char *path, uint64_t ts);
bool db_get (const char *path, unsigned char **value, size_t *length);
GList *db_search (const char *path);
uint64_t db_timestamp (const char *path);

/* RPC API */
#define RPC_TIMEOUT_US 1000000
#define RPC_CLIENT_TIMEOUT_US 1000000
typedef struct rpc_instance_s *rpc_instance;
#define RPC_TEST_DELAY_MASK 0x7FF
extern bool rpc_test_random_watch_delay;
rpc_instance rpc_init (ProtobufCService *service, const ProtobufCServiceDescriptor *descriptor, int timeout);
void rpc_shutdown (rpc_instance rpc);
bool rpc_server_bind (rpc_instance rpc, const char *guid, const char *url);
bool rpc_server_release (rpc_instance rpc, const char *guid);
int rpc_server_process (rpc_instance rpc, bool poll);
ProtobufCService *rpc_client_connect (rpc_instance rpc, const char *url);
void rpc_client_release (rpc_instance rpc, ProtobufCService *service, bool keep);

/* Apteryx configuration */
void config_init (void);
void config_shutdown (void);
/* Returns a list of paths */
GList *config_search_providers (const char *path);

/* Returns a list of cb_info_t* */
GList *config_get_indexers (const char *path);
GList *config_get_providers (const char *path);
GList *config_get_proxies (const char *path);
GList *config_get_watchers (const char *path);
GList *config_get_validators (const char *path);

/* Callbacks to clients */
struct callback_node * cb_init (void);
cb_info_t * cb_create (struct callback_node *list, const char *guid, const char *path, uint64_t id, uint64_t callback);
void cb_disable (cb_info_t *cb);
void cb_destroy (cb_info_t *cb);
void cb_take(cb_info_t *cb);
void cb_release (cb_info_t *cb);
#define CB_MATCH_PART       (1<<0)
#define CB_MATCH_EXACT      (1<<1)
#define CB_MATCH_WILD       (1<<2)
#define CB_MATCH_CHILD      (1<<3)
#define CB_MATCH_WILD_PATH  (1<<4)
#define CB_PATH_MATCH_PART  (1<<5)
GList *cb_match (struct callback_node *list, const char *path);
/* Returns a list of paths */
GList *cb_search (struct callback_node *node, const char *path);
void cb_shutdown (struct callback_node *root);

/* Schema */
typedef void sch_instance;
typedef void sch_node;
sch_instance* sch_load (const char *path);
void sch_free (sch_instance *schema);
sch_node* sch_lookup (sch_instance *schema, const char *path);
bool sch_is_leaf (sch_node *node);
bool sch_is_readable (sch_node *node);
bool sch_is_writable (sch_node *node);
char* sch_name (sch_node *node);
char* sch_translate_to (sch_node *node, char *value);
char* sch_translate_from (sch_node *node, char *value);

/* Tests */
void run_unit_tests (const char *filter);

#endif /* _INTERNAL_H_ */
