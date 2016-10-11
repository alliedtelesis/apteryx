/**
 * @file apteryx.c
 * API for configuration and state shared between Apteryx processes.
 * Features:
 * - A simple path:value database.
 * - Tree like structure with each node being a value.
 * - Path specified in directory format (e.g. /root/node1/node2).
 * - Searching for nodes children requires substring search of the path.
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
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <pthread.h>
#include <poll.h>
#include <semaphore.h>
#include <errno.h>
#include "internal.h"
#include "apteryx.h"
#include <glib.h>

/* Configuration */
bool apteryx_debug = false;                      /* Debug enabled */
static const char *default_url = APTERYX_SERVER; /* Default path to Apteryx database */
static int ref_count = 0;               /* Library reference count */
static pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER; /* Protect globals */
//static rpc_instance rpc = NULL;         /* RPC Service */
//static bool bound = false;              /* Do we have a listen socket open */
//static bool have_callbacks = false;     /* Have we ever registered any callbacks */
//
//static pthread_mutex_t pending_watches_lock = PTHREAD_MUTEX_INITIALIZER;
//static pthread_cond_t no_pending_watches = PTHREAD_COND_INITIALIZER;
//static int pending_watch_count = 0;

static const char *
validate_path (const char *path, char **url)
{
    /* Database path or none at all */
    if (path && path[0] == '/')
    {
        /* Use the default URL */
        if (url)
            *url = strdup(default_url);
        return path;
    }
    /* Check for a full URL */
    else if (path &&
      (strncmp (path, "unix://", 7) == 0 ||
       strncmp (path, "tcp://", 6) == 0))
    {
        if (url)
            *url = strdup (path);
        char *tmp = strstr (path + 6, ":/");
        if (!tmp)
        {
            ERROR ("Invalid path (%s)!\n", path);
            return NULL;
        }
        path = tmp + 1;
        tmp = strstr (*url + 6, ":/");
        if (tmp)
        {
            tmp[0] = '\0';
        }
        return path;
    }
    else if (path)
    {
        ERROR ("Invalid path (%s)!\n", path);
    }
    return NULL;
}

#if 0
/* Callback for indexed items */
static void
apteryx__index (Apteryx__Client_Service *service,
                  const Apteryx__Index *index,
                  Apteryx__SearchResult_Closure closure, void *closure_data)
{
    Apteryx__SearchResult result = APTERYX__SEARCH_RESULT__INIT;
    apteryx_index_callback cb = (apteryx_index_callback) (long) index->cb;
    GList *results = NULL;
    GList *iter = NULL;
    int i;
    (void) service;

    DEBUG ("INDEX CB: \"%s\" (0x%"PRIx64",0x%"PRIx64")\n",
            index->path, index->id, index->cb);

    /* Call the callback */
    if (cb)
        results = cb (index->path);

    /* Return result */
    result.n_paths = g_list_length (results);
    if (result.n_paths > 0)
    {
        result.paths = (char **) malloc (result.n_paths * sizeof (char *));
        for (i = 0, iter = results; iter; iter = g_list_next (iter), i++)
        {
            DEBUG ("         = %s\n", (char *) iter->data);
            result.paths[i] = (char *) iter->data;
        }
    }
    closure (&result, closure_data);
    g_list_free_full (results, free);
    if (result.paths)
        free (result.paths);
    return;
}

/* Callback for watched items */
static void
apteryx__watch (Apteryx__Client_Service *service,
                const Apteryx__Watch *watch,
                Apteryx__NoResult_Closure closure, void *closure_data)
{
    (void) service;
    char *value = NULL;

    DEBUG ("WATCH CB \"%s\" = \"%s\" (0x%"PRIx64",0x%"PRIx64")\n",
           watch->path, watch->value,
           watch->id, watch->cb);

    if (watch->value && (watch->value[0] != '\0'))
    {
        value = watch->value;
    }

    pthread_mutex_lock (&pending_watches_lock);
    ++pending_watch_count;
    pthread_mutex_unlock (&pending_watches_lock);

    /* Call callback */
    if (watch->cb)
        ((apteryx_watch_callback) (long) watch->cb) (watch->path, value);
    pthread_mutex_lock (&pending_watches_lock);
    if (--pending_watch_count == 0)
        pthread_cond_signal(&no_pending_watches);
    pthread_mutex_unlock (&pending_watches_lock);

    return;
}

/* Callback for validated items */
static void
apteryx__validate (Apteryx__Client_Service *service,
                const Apteryx__Validate *validate,
                Apteryx__ValidateResult_Closure closure, void *closure_data)
{
    Apteryx__ValidateResult result = APTERYX__VALIDATE_RESULT__INIT;
    (void) service;
    char *value = NULL;

    DEBUG ("VALIDATE CB \"%s\" = \"%s\" (0x%"PRIx64",0x%"PRIx64")\n",
           validate->path, validate->value,
           validate->id, validate->cb);

    if (!validate->cb)
    {
        result.result = 0;
        goto exit;
    }

    /* We want to wait for all pending watches to be processed */
    pthread_mutex_lock (&pending_watches_lock);
    if (pending_watch_count)
    {
        pthread_cond_wait (&no_pending_watches, &pending_watches_lock);
        pthread_mutex_unlock (&pending_watches_lock);
    }
    else
        pthread_mutex_unlock (&pending_watches_lock);


    if (validate->value && (validate->value[0] != '\0'))
    {
        value = validate->value;
    }
    result.result = ((apteryx_validate_callback)(size_t)validate->cb) (validate->path, value);

exit:
    /* Return result */
    closure (&result, closure_data);
    return;
}

/* Callback for provided items */
static void
apteryx__provide (Apteryx__Client_Service *service,
                  const Apteryx__Provide *provide,
                  Apteryx__GetResult_Closure closure, void *closure_data)
{
    Apteryx__GetResult result = APTERYX__GET_RESULT__INIT;
    apteryx_provide_callback cb = (apteryx_provide_callback) (long) provide->cb;
    char *value = NULL;
    (void) service;

    DEBUG ("PROVIDE CB: \"%s\" (0x%"PRIx64",0x%"PRIx64")\n",
           provide->path, provide->id, provide->cb);

    /* Call the callback */
    if (cb)
        value = cb (provide->path);

    /* Return result */
    result.value = value;
    closure (&result, closure_data);
    if (value)
        free (value);
    return;
}

static Apteryx__Client_Service apteryx_client_service = APTERYX__CLIENT__INIT (apteryx__);

static void
handle_ok_response (const Apteryx__OKResult *result, void *closure_data)
{
    if (result == NULL)
    {
        *(protobuf_c_boolean *) closure_data = false;
        errno = -ETIMEDOUT;
    }
    else
    {
        *(protobuf_c_boolean *) closure_data = (result->result == 0);
        if (result->result)
            errno = result->result;
    }
}
#endif

bool
apteryx_init (bool debug_enabled)
{
    /* Increment refcount */
    pthread_mutex_lock (&lock);
    ref_count++;
    apteryx_debug |= debug_enabled;
    if (ref_count == 1)
    {
        /* Initialise the database */
        db_init ();
        /* Initialise callbacks to clients */
        cb_init ();
        /* Configuration Set/Get */
        config_init ();
    }
//    if (ref_count == 1)
//    {
//        char * uri = NULL;
//
//        /* Create RPC instance */
//        rpc = rpc_init ((ProtobufCService *)&apteryx_client_service, &apteryx__server__descriptor, RPC_CLIENT_TIMEOUT_US);
//        if (rpc == NULL)
//        {
//            ERROR ("Init: Failed to initialise RPC service\n");
//            ref_count--;
//            pthread_mutex_unlock (&lock);
//            return false;
//        }
//
//        /* Only need to bind if we have previously added callbacks */
//        if (have_callbacks)
//        {
//            /* Bind to the default uri for this client */
//            if (asprintf ((char **) &uri, APTERYX_SERVER".%"PRIu64, (uint64_t) getpid ()) <= 0
//                    || !rpc_server_bind (rpc, uri, uri))
//            {
//                ERROR ("Failed to bind uri %s\n", uri);
//                ref_count--;
//                pthread_mutex_unlock (&lock);
//                free ((void*) uri);
//                return false;
//            }
//            DEBUG ("Bound to uri %s\n", uri);
//            bound = true;
//            free ((void*) uri);
//        }
//    }
    pthread_mutex_unlock (&lock);

    /* Ready to go */
    if (ref_count == 1)
        DEBUG ("Init: Initialised\n");
    return true;
}

bool
apteryx_shutdown (void)
{
    ASSERT ((ref_count > 0), return false, "SHUTDOWN: Not initialised\n");

    /* Decrement ref count */
    pthread_mutex_lock (&lock);
    ref_count--;
    pthread_mutex_unlock (&lock);

    /* Check if there are still other users */
    if (ref_count > 0)
    {
        DEBUG ("SHUTDOWN: More users (refcount=%d)\n", ref_count);
        return true;
    }

    /* Shutdown */
    DEBUG ("SHUTDOWN: Shutting down\n");
    db_shutdown (false);
//    rpc_shutdown (rpc);
//    bound = false;
    DEBUG ("SHUTDOWN: Shutdown\n");
    return true;
}


bool
apteryx_shutdown_force (void)
{
    while (ref_count > 0)
        apteryx_shutdown ();
    return true;
}

int
apteryx_process (bool poll)
{
    ASSERT ((ref_count > 0), return false, "PROCESS: Not initialised\n");
//    return rpc_server_process (rpc, poll);
    return 0;
}

bool
apteryx_prune (const char *path)
{
    ASSERT ((ref_count > 0), return false, "PRUNE: Not initialised\n");
    ASSERT (path, return false, "PRUNE: Invalid parameters\n");

    /* Prune from database */
    db_prune (path);

    /* Success */
    return true;

//    char *url = NULL;
//    ProtobufCService *rpc_client;
//    Apteryx__Prune prune = APTERYX__PRUNE__INIT;
//    protobuf_c_boolean is_done = 0;
//
//    ASSERT ((ref_count > 0), return false, "PRUNE: Not initialised\n");
//    ASSERT (path, return false, "PRUNE: Invalid parameters\n");
//
//    DEBUG ("PRUNE: %s\n", path);
//
//    /* Check path */
//    path = validate_path (path, &url);
//    if (!path)
//    {
//        ERROR ("PRUNE: invalid path (%s)!\n", path);
//        assert (!apteryx_debug || path);
//        return false;
//    }
//
//    /* IPC */
//    rpc_client = rpc_client_connect (rpc, url);
//    if (!rpc_client)
//    {
//        ERROR ("PRUNE: Path(%s) Failed to connect to server: %s\n", path, strerror (errno));
//        free (url);
//        return false;
//    }
//    prune.path = (char *) path;
//    apteryx__server__prune (rpc_client, &prune, handle_ok_response, &is_done);
//    if (!is_done)
//    {
//        ERROR ("PRUNE: No response\n");
//        rpc_client_release (rpc, rpc_client, false);
//        free (url);
//        return false;
//    }
//    rpc_client_release (rpc, rpc_client, true);
//    free (url);

    /* Success */
    return true;
}

bool
apteryx_dump (const char *path, FILE *fp)
{
//    char *value = NULL;
//
//    ASSERT ((ref_count > 0), return false, "DUMP: Not initialised\n");
//    ASSERT (path, return false, "DUMP: Invalid parameters\n");
//    ASSERT (fp, return false, "DUMP: Invalid parameters\n");
//
//    DEBUG ("DUMP: %s\n", path);
//
//    /* Check initialised */
//    if (ref_count <= 0)
//    {
//        ERROR ("DUMP: not initialised!\n");
//        assert(ref_count > 0);
//        return false;
//    }
//
//    if (strlen (path) > 0 && (value = apteryx_get (path)))
//    {
//        fprintf (fp, "%-64s%s\n", path, value);
//        free (value);
//    }
//
//    char *_path = NULL;
//    int len = asprintf (&_path, "%s/", path);
//    if (len >= 0)
//    {
//        GList *children, *iter;
//        children = apteryx_search (_path);
//        for (iter = children; iter; iter = g_list_next (iter))
//        {
//            apteryx_dump ((const char *) iter->data, fp);
//        }
//        g_list_free_full (children, free);
//        free (_path);
//    }
    return true;
}

static int
validate_set (const char *path, const char *value)
{
    GList *validators = NULL;
    GList *iter = NULL;
    int32_t result = 0;

    /* Retrieve a list of validators for this path */
    validators = cb_match (&validation_list, path,
            CB_MATCH_EXACT|CB_MATCH_WILD|CB_MATCH_CHILD|CB_MATCH_WILD_PATH);
    if (!validators)
        return 0;

    /* Call each validator */
    for (iter = validators; iter; iter = g_list_next (iter))
    {
        cb_info_t *validator = iter->data;

        DEBUG ("VALIDATE CB %s = %s (0x%"PRIx64",0x%"PRIx64")\n",
                 validator->path, value, validator->id, validator->cb);

        apteryx_validate_callback cb = (apteryx_validate_callback) (long) validator->cb;
        result = cb (path, value);
        if (result < 0)
        {
            DEBUG ("Set of %s to %s rejected by process %"PRIu64" (%d)\n",
                    (char *)path, (char*)value, validator->id, result);
            break;
        }
    }
    g_list_free_full (validators, (GDestroyNotify) cb_release);

    /* This one is fine, but lock is still held */
    return result < 0 ? result : 1;
}

static void
notify_watchers (const char *path)
{
    GList *watchers = NULL;
    GList *iter = NULL;
    char *value = NULL;
    size_t vsize;

    /* Retrieve a list of watchers for this path */
    watchers = cb_match (&watch_list, path,
            CB_MATCH_EXACT|CB_MATCH_WILD|CB_MATCH_CHILD|CB_MATCH_WILD_PATH);
    if (!watchers)
        return;

    /* Find the new value for this path */
    value = NULL;
    vsize = 0;
    db_get (path, (unsigned char**)&value, &vsize);

    /* Call each watcher */
    for (iter = watchers; iter; iter = g_list_next (iter))
    {
        cb_info_t *watcher = iter->data;

        DEBUG ("WATCH CB %s = %s (%s 0x%"PRIx64",0x%"PRIx64",%s)\n",
                path, value, watcher->path, watcher->id, watcher->cb, watcher->uri);

        apteryx_watch_callback cb = (apteryx_watch_callback) (long) watcher->cb;
        DEBUG ("WATCH \"%s\" (0x%"PRIx64",0x%"PRIx64")\n",
                watcher->path, watcher->id, watcher->cb);
        cb (path, value);
    }
    g_list_free_full (watchers, (GDestroyNotify) cb_release);

    /* Free memory if allocated */
    if (value)
        g_free (value);
}

bool
apteryx_cas (const char *path, const char *value, uint64_t ts)
{
    bool db_result = false;
    int validation_result = false;

    ASSERT ((ref_count > 0), return false, "SET: Not initialised\n");
    ASSERT (path, return false, "SET: Invalid parameters\n");

    DEBUG ("SET: %s = %s\n", path, value);

    if (value && value[0] == '\0')
        value = NULL;

    /* Validate first */
    validation_result = validate_set (path, value);
    if (validation_result < 0)
    {
        DEBUG ("SET: %s = %s refused by validate\n", path, value);
        errno = validation_result;
        return false;
    }

    /* Add/Delete to/from database */
    if (value)
        db_result = db_add_no_lock (path, (unsigned char*)value, strlen (value) + 1, ts);
    else
        db_result = db_delete_no_lock (path, ts);
    if (!db_result)
    {
        DEBUG ("SET: %s = %s refused by DB\n", path, value);
        errno = -EBUSY;
    }

    /* Notify watchers */
    notify_watchers (path);

    return db_result;

//    char *url = NULL;
//    ProtobufCService *rpc_client;
//    Apteryx__Set set = APTERYX__SET__INIT;
//    Apteryx__PathValue _pv = APTERYX__PATH_VALUE__INIT;
//    Apteryx__PathValue *pv[1] = {&_pv};
//    protobuf_c_boolean result = 0;
//
//    ASSERT ((ref_count > 0), return false, "SET: Not initialised\n");
//    ASSERT (path, return false, "SET: Invalid parameters\n");
//
//    DEBUG ("SET: %s = %s\n", path, value);
//
//    /* Check path */
//    path = validate_path (path, &url);
//    if (!path || path[strlen(path) - 1] == '/')
//    {
//        ERROR ("SET: invalid path (%s)!\n", path);
//        free (url);
//        assert (!apteryx_debug || path);
//        return false;
//    }
//
//    /* IPC */
//    rpc_client = rpc_client_connect (rpc, url);
//    if (!rpc_client)
//    {
//        ERROR ("SET: Path(%s) Failed to connect to server: %s\n", path, strerror (errno));
//        free (url);
//        return false;
//    }
//    pv[0]->path = (char *) path;
//    pv[0]->value = (char *) value;
//    set.n_sets = 1;
//    set.sets = pv;
//    set.ts = ts;
//    apteryx__server__set (rpc_client, &set, handle_ok_response, &result);
//    if (!result && errno == -ETIMEDOUT)
//    {
//        DEBUG ("SET: No response\n");
//        rpc_client_release (rpc, rpc_client, false);
//        free (url);
//        return false;
//    }
//    else if (!result)
//    {
//        DEBUG ("SET: Error response: %s\n", strerror (errno));
//    }
//    rpc_client_release (rpc, rpc_client, true);
//    free (url);
//
//    /* Success */
//    return result;
}

bool
apteryx_set (const char *path, const char *value)
{
    return apteryx_cas (path, value, UINT64_MAX);
}

bool
apteryx_cas_string (const char *path, const char *key, const char *value, uint64_t ts)
{
    char *full_path;
    size_t len;
    bool res = false;

    /* Create full path */
    if (key)
        len = asprintf (&full_path, "%s/%s", path, key);
    else
        len = asprintf (&full_path, "%s", path);
    if (len)
    {
        res = apteryx_cas (full_path, value, ts);
        free (full_path);
    }
    return res;
}

bool
apteryx_set_string (const char *path, const char *key, const char *value)
{
    return apteryx_cas_string (path, key, value, UINT64_MAX);
}

bool
apteryx_cas_int (const char *path, const char *key, int32_t value, uint64_t ts)
{
    char *full_path;
    size_t len;
    char *v;
    bool res = false;

    /* Create full path */
    if (key)
        len = asprintf (&full_path, "%s/%s", path, key);
    else
        len = asprintf (&full_path, "%s", path);
    if (len)
    {
        /* Store as a string at the moment */
        len = asprintf ((char **) &v, "%d", value);
        if (len)
        {
            res = apteryx_cas (full_path, v, ts);
            free ((void *) v);
        }
        free (full_path);
    }
    return res;
}

bool
apteryx_set_int (const char *path, const char *key, int32_t value)
{
    return apteryx_cas_int (path, key, value, UINT64_MAX);
}

//typedef struct _get_data_t
//{
//    char *value;
//    bool done;
//} get_data_t;
//
//static void
//handle_get_response (const Apteryx__GetResult *result, void *closure_data)
//{
//    get_data_t *data = (get_data_t *)closure_data;
//    data->done = false;
//    if (result == NULL)
//    {
//        ERROR ("GET: Error processing request.\n");
//        errno = -ETIMEDOUT;
//    }
//    else
//    {
//        data->done = true;
//        if (result->value && result->value[0] != '\0')
//        {
//            data->value = strdup (result->value);
//        }
//    }
//}

static char *
provide_get (const char *path)
{
    GList *providers = NULL;
    char *value = NULL;
    GList *iter = NULL;

    /* Retrieve a list of providers for this path */
    providers = cb_match (&provide_list, path,
            CB_MATCH_EXACT|CB_MATCH_WILD|CB_MATCH_CHILD|CB_MATCH_WILD_PATH);
    if (!providers)
        return 0;

    /* Find the first good provider */
    for (iter = providers; iter; iter = g_list_next (iter))
    {
        cb_info_t *provider = iter->data;

        DEBUG ("PROVIDE CB \"%s\" (0x%"PRIx64",0x%"PRIx64")\n",
               provider->path, provider->id, provider->cb);

        apteryx_provide_callback cb = (apteryx_provide_callback) (long) provider->cb;
        DEBUG ("PROVIDE LOCAL \"%s\" (0x%"PRIx64",0x%"PRIx64")\n",
                                   provider->path, provider->id, provider->cb);
        value = cb (path);
        break;
    }
    g_list_free_full (providers, (GDestroyNotify) cb_release);

    return value;
}

char *
apteryx_get (const char *path)
{
    char *value = NULL;
    size_t vsize = 0;

    ASSERT ((ref_count > 0), return NULL, "GET: Not initialised\n");
    ASSERT (path, return NULL, "GET: Invalid parameters\n");

    /* Proxy first */
//    if ((value = proxy_get (path)) == NULL)
    {
        /* Database second */
        if (!db_get (path, (unsigned char**)&value, &vsize))
        {
            /* Provide third */
            if ((value = provide_get (path)) == NULL)
            {
                DEBUG ("GET: not in database or provided or proxied\n");
            }
        }
    }

    return value;
//    char *url = NULL;
//    char *value = NULL;
//    ProtobufCService *rpc_client;
//    Apteryx__Get get = APTERYX__GET__INIT;
//    get_data_t data = {0};
//
//    ASSERT ((ref_count > 0), return NULL, "GET: Not initialised\n");
//    ASSERT (path, return NULL, "GET: Invalid parameters\n");
//
//    DEBUG ("GET: %s\n", path);
//
//    /* Check path */
//    path = validate_path (path, &url);
//    if (!path || path[strlen(path)-1] == '/')
//    {
//        ERROR ("GET: invalid path (%s)!\n", path);
//        free (url);
//        assert (!apteryx_debug || path);
//        return NULL;
//    }
//
//    /* IPC */
//    rpc_client = rpc_client_connect (rpc, url);
//    if (!rpc_client)
//    {
//        ERROR ("GET: Path(%s) Failed to connect to server: %s\n", path, strerror (errno));
//        free (url);
//        return NULL;
//    }
//    get.path = (char *) path;
//    apteryx__server__get (rpc_client, &get, handle_get_response, &data);
//    if (!data.done)
//    {
//        ERROR ("GET: No response\n");
//        rpc_client_release (rpc, rpc_client, false);
//    }
//    else
//    {
//        rpc_client_release (rpc, rpc_client, true);
//        value = data.value;
//    }
//    free (url);
//
//    DEBUG ("    = %s\n", value);
//    return value;
}

char *
apteryx_get_string (const char *path, const char *key)
{
    char *full_path;
    size_t len;
    char *value = NULL;
    char *str = NULL;

    /* Create full path */
    if (key)
        len = asprintf (&full_path, "%s/%s", path, key);
    else
        len = asprintf (&full_path, "%s", path);
    if (len)
    {
        if ((value = apteryx_get ((const char *) full_path)))
        {
            str = (char *) value;
        }
        free (full_path);
    }
    return str;
}

int32_t
apteryx_get_int (const char *path, const char *key)
{
    char *full_path;
    size_t len;
    char *v = NULL;
    char *rem = NULL;
    int32_t value = -1;

    /* Create full path */
    if (key)
        len = asprintf (&full_path, "%s/%s", path, key);
    else
        len = asprintf (&full_path, "%s", path);
    if (len)
    {
        if (apteryx_debug)
        {
            errno = 0;
        }

        if ((v = apteryx_get (full_path)))
        {
            value = strtol ((char *) v, &rem, 0);

            if (*rem != '\0')
            {
                errno = -ERANGE;
                value = -1;
            }

            free (v);
        }
        else
        {
            errno = -ERANGE;
        }

        if (apteryx_debug && errno == -ERANGE)
        {
            DEBUG ("Cannot represent value as int: %s\n", v);
        }

        free (full_path);
    }
    return value;
}

bool
apteryx_has_value (const char *path)
{
    char *value = NULL;
    value = apteryx_get (path);
    if (value)
    {
        free (value);
        return true;
    }
    return false;
}

GNode *
apteryx_find_child (GNode *parent, const char *name)
{
    GNode *node;

    for (node = g_node_first_child (parent); node; node = node->next)
    {
        if (strcmp (APTERYX_NAME (node), name) == 0)
        {
            return node;
        }
    }
    return NULL;
}

static inline gboolean
_node_free (GNode *node, gpointer data)
{
    free ((void *)node->data);
    return FALSE;
}

void
apteryx_free_tree (GNode* root)
{
    if (root)
    {
        g_node_traverse (root, G_PRE_ORDER, G_TRAVERSE_ALL, -1, _node_free, NULL);
        g_node_destroy (root);
    }
}

static GNode *
merge (GNode *left, GNode *right, int (*cmp) (const char *a, const char *b))
{
    if (!left)
        return right;
    if (!right)
        return left;
    if (cmp (left->data, right->data) < 0)
    {
        left->next = merge (left->next, right, cmp);
        left->next->prev = left;
        left->prev = NULL;
        return left;
    }
    else
    {
        right->next = merge (left, right->next, cmp );
        right->next->prev = right;
        right->prev = NULL;
        return right;
    }
}

static GNode *
split (GNode *head)
{
    GNode *left, *right;
    left = right = head;
    while (right->next && right->next->next)
    {
        right = right->next->next;
        left = left->next;
    }
    right = left->next;
    left->next = NULL;
    return right;
}

static GNode *
merge_sort (GNode *head, int (*cmp) (const char *a, const char *b))
{
    GNode *left, *right;
    if (!head || !head->next)
        return head;
    left = head;
    right = split (left);
    left = merge_sort (left, cmp);
    right = merge_sort (right, cmp);
    return merge (left, right, cmp);
}

void
apteryx_sort_children (GNode *parent, int (*cmp) (const char *a, const char *b))
{
    if (parent)
        parent->children = merge_sort (parent->children, cmp);
}

static char *
_node_to_path (GNode *node, char **buf)
{
    /* don't put a trailing / on */
    char end = 0;
    if (!*buf)
    {
        *buf = strdup ("");
        end = 1;
    }

    if (node && node->parent)
        _node_to_path (node->parent, buf);

    char *tmp = NULL;
    if (asprintf (&tmp, "%s%s%s", *buf ? : "",
            node ? (char*)node->data : "/",
            end ? "" : "/") > 0)
    {
        free (*buf);
        *buf = tmp;
    }
    return tmp;
}

char *
apteryx_node_path (GNode* node)
{
    char *path = NULL;
    _node_to_path (node, &path);
    return path;
}

static gboolean
_set_multi (GNode *node, gpointer data)
{
    bool *rc = (bool *)data;
    uint64_t ts = UINT64_MAX;

    if (APTERYX_HAS_VALUE(node))
    {
        char *path = apteryx_node_path (node);
        DEBUG ("SET_TREE: %s = %s\n", path, APTERYX_VALUE (node));
        *rc = apteryx_cas (path, APTERYX_VALUE (node), ts);
        if (!*rc)
            return true;
    }
    return false;

//    Apteryx__Set *set = (Apteryx__Set *)data;
//
//    if (APTERYX_HAS_VALUE(node))
//    {
//        char *path = apteryx_node_path (node);
//        Apteryx__PathValue *pv = calloc (1, sizeof (Apteryx__PathValue));
//        DEBUG ("SET_TREE: %s = %s\n", path, APTERYX_VALUE (node));
//        pv->base.descriptor = &apteryx__path_value__descriptor;
//        pv->path = (char *) path;
//        pv->value = (char *) APTERYX_VALUE (node);
//        set->sets[set->n_sets++] = pv;
//    }
//    return FALSE;
}

bool
apteryx_cas_tree (GNode* root, uint64_t ts)
{
    const char *path = NULL;
    char *url = NULL;
    bool rc = true;

    ASSERT ((ref_count > 0), return false, "SET_TREE: Not initialised\n");
    ASSERT (root, return false, "SET_TREE: Invalid parameters\n");

    DEBUG ("SET_TREE: %d paths\n", g_node_n_nodes (root, G_TRAVERSE_LEAVES));

    /* Check path */
    path = validate_path (APTERYX_NAME (root), &url);

    if (path && strcmp (path, "/") == 0)
    {
        path = "";
    }

    if (!path || (strlen (path) > 0 && path[strlen(path) - 1] == '/'))
    {
        ERROR ("SET_TREE: invalid path (%s)!\n", path);
        assert (!apteryx_debug || path);
        free (url);
        return false;
    }

    g_node_traverse (root, G_PRE_ORDER, G_TRAVERSE_NON_LEAFS, -1, _set_multi, &rc);
    /* Return result */
    return rc;

//    const char *path = NULL;
//    char *old_root_name = NULL;
//    char *url = NULL;
//    bool rc = true;
//
//    ASSERT ((ref_count > 0), return false, "SET_TREE: Not initialised\n");
//    ASSERT (root, return false, "SET_TREE: Invalid parameters\n");
//
//    DEBUG ("SET_TREE: %d paths\n", g_node_n_nodes (root, G_TRAVERSE_LEAVES));
//
//    /* Check path */
//    path = validate_path (APTERYX_NAME (root), &url);
//
//    if (path && strcmp (path, "/") == 0)
//    {
//        path = "";
//    }
//
//    if (!path || (strlen (path) > 0 && path[strlen(path) - 1] == '/'))
//    {
//        ERROR ("SET_TREE: invalid path (%s)!\n", path);
//        assert (!apteryx_debug || path);
//        free (url);
//        return false;
//    }
//
//    /* IPC */
//    rpc_client = rpc_client_connect (rpc, url);
//    if (!rpc_client)
//    {
//        ERROR ("SET_TREE: Path(%s) Failed to connect to server: %s\n", path, strerror (errno));
//        free (url);
//        return false;
//    }
//
//    /* Save sanitized root path (less URL) to root node */
//    old_root_name = APTERYX_NAME (root);
//    root->data = (char*) path;
//
//    /* Create the list of Paths/Value's */
//    set.n_sets = g_node_n_nodes (root, G_TRAVERSE_LEAVES);
//    set.sets = malloc (set.n_sets * sizeof (Apteryx__PathValue *));
//    set.n_sets = 0;
//    g_node_traverse (root, G_PRE_ORDER, G_TRAVERSE_NON_LEAFS, -1, _set_multi, &set);
//    set.ts = ts;
//    apteryx__server__set (rpc_client, &set, handle_ok_response, &is_done);
//    if (!is_done)
//    {
//        DEBUG ("SET_TREE: Failed %s\n", strerror(errno));
//        rpc_client_release (rpc, rpc_client, false);
//        rc = false;
//    }
//    else
//    {
//        rpc_client_release (rpc, rpc_client, true);
//    }
//    free (url);
//
//    /* Cleanup message */
//    for (i=0; i<set.n_sets; i++)
//    {
//        Apteryx__PathValue *pv = set.sets[i];
//        free (pv->path);
//        free (pv);
//    }
//    free (set.sets);
//
//    /* Reinstate original root name */
//    root->data = old_root_name;
//
//    /* Return result */
//    return rc;
}

bool
apteryx_set_tree (GNode* root)
{
    return apteryx_cas_tree (root, UINT64_MAX);
}

typedef struct _traverse_data_t
{
    GNode* root;
    bool done;
} traverse_data_t;

static void
path_to_node (GNode* root, const char *path, const char *value)
{
    const char *next;
    GNode *node;

    if (path && path[0] == '/')
    {
        path++;
        next = strchr (path, '/');
        if (!next)
        {
            APTERYX_LEAF (root, strdup (path), strdup (value));
        }
        else
        {
            char *name = strndup (path, next - path);
            for (node = g_node_first_child (root); node;
                    node = g_node_next_sibling (node))
            {
                if (strcmp (APTERYX_NAME (node), name) == 0)
                {
                    root = node;
                    free (name);
                    break;
                }
            }
            if (!node)
            {
                root = APTERYX_NODE (root, name);
            }
            path_to_node (root, next, value);
        }
    }
    return;
}

//static void
//handle_traverse_response (const Apteryx__TraverseResult *result, void *closure_data)
//{
//    traverse_data_t *data = (traverse_data_t *)closure_data;
//    const char *path = APTERYX_NAME (data->root);
//    int i;
//
//    data->done = false;
//    if (result == NULL)
//    {
//        ERROR ("TRAVERSE: Error processing request.\n");
//        errno = -ETIMEDOUT;
//        apteryx_free_tree (data->root);
//        data->root = NULL;
//    }
//    else if (result->pv == NULL)
//    {
//        DEBUG ("    = (null)\n");
//        apteryx_free_tree (data->root);
//        data->root = NULL;
//        data->done = true;
//    }
//    else if (result->n_pv == 1 &&
//        strcmp (path, result->pv[0]->path) == 0)
//    {
//        Apteryx__PathValue *pv = result->pv[0];
//        DEBUG ("  %s = %s\n", pv->path, pv->value);
//        g_node_append_data (data->root, (gpointer)strdup (pv->value));
//        data->done = true;
//    }
//    else if (result->n_pv != 0)
//    {
//        int slen = strlen (path);
//        for (i = 0; i < result->n_pv; i++)
//        {
//            Apteryx__PathValue *pv = result->pv[i];
//            DEBUG ("  %s = %s\n", pv->path + slen, pv->value);
//            path_to_node (data->root, pv->path + slen, pv->value);
//        }
//        data->done = true;
//    }
//}

/* This function returns true if indexers were called (list may still be NULL) */
static bool
index_get (const char *path, GList **result)
{
    GList *indexers = NULL;
    GList *results = NULL;
    GList *iter = NULL;

    /* Retrieve a list of providers for this path */
    indexers = cb_match (&index_list, path,
            CB_MATCH_EXACT|CB_MATCH_WILD|CB_MATCH_CHILD);
    if (!indexers)
    {
        *result = NULL;
        return false;
    }

    /* Find the first good indexer */
    for (iter = indexers; iter; iter = g_list_next (iter))
    {
        cb_info_t *indexer = iter->data;

        DEBUG ("INDEX CB \"%s\" (0x%"PRIx64",0x%"PRIx64")\n",
                indexer->path, indexer->id, indexer->cb);

        apteryx_index_callback cb = (apteryx_index_callback) (long) indexer->cb;
        results = cb (path);
        break;
    }
    g_list_free_full (indexers, (GDestroyNotify) cb_release);

    *result = results;
    return true;
}

static void
_traverse_paths (GNode* root, const char *path)
{
    GList *children, *iter;
    char *value = NULL;
    size_t vsize;

    /* Look for a value - db first */
    if (!db_get (path, (unsigned char**)&value, &vsize))
    {
        /* Provide next */
        value = provide_get (path);
    }
    if (value)
    {
        if (strcmp (path, root->data) == 0)
        {
            DEBUG ("  %s = %s\n", path, value);
            g_node_append_data (root, (gpointer)strdup (value));
        }
        else
        {
            int slen = strlen (root->data);
            DEBUG ("  %s = %s\n", path + slen, value);
            path_to_node (root, path + slen, value);
        }
    }

    /* Check for children - index first */
    char *path_s = g_strdup_printf ("%s/", path);
    if (!index_get (path_s, &children))
    {
        /* Search database next */
        children = db_search (path_s);

        /* Append any provided paths */
        GList *providers = NULL;
        providers = cb_match (&provide_list, path_s, CB_MATCH_PART);
        for (iter = providers; iter; iter = g_list_next (iter))
        {
            cb_info_t *provider = iter->data;
            char *ptr, *ppath;
            int len = strlen (path_s);

            if (strcmp (provider->path, path_s) == 0)
                continue;

            ppath = g_strdup (provider->path);
            if ((ptr = strchr (&ppath[len+1], '/')) != 0)
                   *ptr = '\0';
            if (!g_list_find_custom (children, ppath, (GCompareFunc) strcmp))
                children = g_list_prepend (children, ppath);
            else
                g_free (ppath);
        }
        g_list_free_full (providers, (GDestroyNotify) cb_release);
    }
    for (iter = children; iter; iter = g_list_next (iter))
    {
        _traverse_paths (root, (const char *) iter->data);
    }
    g_list_free_full (children, g_free);
    g_free (path_s);
}

GNode*
apteryx_get_tree (const char *path)
{
    char *url = NULL;
    GNode* root = NULL;

    ASSERT ((ref_count > 0), return NULL, "GET_TREE: Not initialised\n");
    ASSERT (path, return NULL, "GET_TREE: Invalid parameters\n");

    DEBUG ("GET_TREE: %s\n", path);

    /* Check path */
    path = validate_path (path, &url);
    if (!path || path[strlen(path) - 1] == '/')
    {
        ERROR ("GET_TREE: invalid path (%s)!\n", path);
        assert (!apteryx_debug || path);
        free (url);
        return false;
    }

    root = g_node_new (strdup (path));

    /* Proxy first */
//    root = proxy_traverse (traverse->path);
//    if (!root)
    {
        /* Traverse (local) paths */
        _traverse_paths (root, path);
    }

    if (!root->children)
    {
        apteryx_free_tree (root);
        root = NULL;
    }

    free (url);
    return root;

//    char *url = NULL;
//    ProtobufCService *rpc_client;
//    Apteryx__Traverse traverse = APTERYX__TRAVERSE__INIT;
//    traverse_data_t data = {0};
//
//    ASSERT ((ref_count > 0), return NULL, "GET_TREE: Not initialised\n");
//    ASSERT (path, return NULL, "GET_TREE: Invalid parameters\n");
//
//    DEBUG ("GET_TREE: %s\n", path);
//
//    /* Check path */
//    path = validate_path (path, &url);
//    if (!path || path[strlen(path) - 1] == '/')
//    {
//        ERROR ("GET_TREE: invalid path (%s)!\n", path);
//        assert (!apteryx_debug || path);
//        free (url);
//        return false;
//    }
//
//    /* IPC */
//    rpc_client = rpc_client_connect (rpc, url);
//    if (!rpc_client)
//    {
//        ERROR ("TRAVERSE: Path(%s) Failed to connect to server: %s\n", path, strerror (errno));
//        free (url);
//        return false;
//    }
//    traverse.path = (char *) path;
//    data.root = g_node_new (strdup (path));
//    apteryx__server__traverse (rpc_client, &traverse, handle_traverse_response, &data);
//    if (!data.done)
//    {
//        ERROR ("TRAVERSE: No response\n");
//        rpc_client_release (rpc, rpc_client, false);
//        apteryx_free_tree (data.root);
//        data.root = NULL;
//        free (url);
//        return NULL;
//    }
//    rpc_client_release (rpc, rpc_client, true);
//    free (url);
//    return data.root;
//    return NULL;
}

//typedef struct _search_data_t
//{
//    GList *paths;
//    bool done;
//} search_data_t;
//
//static void
//handle_search_response (const Apteryx__SearchResult *result, void *closure_data)
//{
//    search_data_t *data = (search_data_t *)closure_data;
//    int i;
//
//    data->done = false;
//    data->paths = NULL;
//    if (result == NULL)
//    {
//        ERROR ("SEARCH: Error processing request.\n");
//        errno = -ETIMEDOUT;
//    }
//    else if (result->paths == NULL)
//    {
//        DEBUG ("    = (null)\n");
//        data->done = true;
//    }
//    else if (result->n_paths != 0)
//    {
//        for (i = 0; i < result->n_paths; i++)
//        {
//            DEBUG ("    = %s\n", result->paths[i]);
//            data->paths = g_list_prepend (data->paths,
//                              (gpointer) strdup (result->paths[i]));
//        }
//        data->done = true;
//    }
//}

GList *
apteryx_search (const char *path)
{
    char *url = NULL;
    GList *results = NULL;
    GList *iter = NULL;

    ASSERT ((ref_count > 0), return NULL, "SEARCH: Not initialised\n");
    ASSERT (path, return NULL, "SEARCH: Invalid parameters\n");

    DEBUG ("SEARCH: %s\n", path);

    /* Check path */
    path = validate_path (path, &url);
    if (!path)
    {
        ERROR ("SEARCH: invalid root (%s)!\n", path);
        free (url);
        assert (!apteryx_debug || path);
        return false;
    }

    /* Validate path */
    if (!path ||
        strcmp (path, "/") == 0 ||
        strcmp (path, "/*") == 0 ||
        strcmp (path, "*") == 0 ||
        strlen (path) == 0)
    {
        path = "";
    }
    else if (path[0] != '/' ||
             path[strlen (path) - 1] != '/' ||
             strstr (path, "//") != NULL)
    {
        free (url);
        ERROR ("SEARCH: invalid root (%s)!\n", path);
        assert(!apteryx_debug || path[0] == '/');
        assert(!apteryx_debug || path[strlen (path) - 1] == '/');
        assert(!apteryx_debug || strstr (path, "//") == NULL);
        return NULL;
    }

    /* Proxy first */
//    results = proxy_search (path);
    if (!results)
    {
        /* Indexers second */
        if (index_get (path, &results) == true)
        {
            DEBUG (" (index result:)\n");
        }
        else
        {
            /* Search database next */
            results = db_search (path);

            /* Append any provided paths */
            GList *providers = NULL;
            providers = cb_match (&provide_list, path, CB_MATCH_PART);
            for (iter = providers; iter; iter = g_list_next (iter))
            {
                cb_info_t *provider = iter->data;
                int len = strlen (path);
                /* If there is a provider for a single node below here it may
                 * show as a "*" entry in this list, which is not desirable */
                if (strlen (provider->path) > strlen (path) &&
                    provider->path[strlen (path)] == '*')
                {
                    continue;
                }
                char *ptr, *provider_path = g_strdup (provider->path);
                if ((ptr = strchr (&provider_path[len ? len : len+1], '/')) != 0)
                    *ptr = '\0';
                if (!g_list_find_custom (results, provider_path, (GCompareFunc) strcmp))
                    results = g_list_prepend (results, provider_path);
                else
                    g_free (provider_path);
            }
            g_list_free_full (providers, (GDestroyNotify) cb_release);
        }
    }
    free (url);
    return results;
//    char *url = NULL;
//    ProtobufCService *rpc_client;
//    Apteryx__Search search = APTERYX__SEARCH__INIT;
//    search_data_t data = {0};
//
//    ASSERT ((ref_count > 0), return NULL, "SEARCH: Not initialised\n");
//    ASSERT (path, return NULL, "SEARCH: Invalid parameters\n");
//
//    DEBUG ("SEARCH: %s\n", path);
//
//    /* Check path */
//    path = validate_path (path, &url);
//    if (!path)
//    {
//        ERROR ("SEARCH: invalid root (%s)!\n", path);
//        free (url);
//        assert (!apteryx_debug || path);
//        return false;
//    }
//
//    /* Validate path */
//    if (!path ||
//        strcmp (path, "/") == 0 ||
//        strcmp (path, "/*") == 0 ||
//        strcmp (path, "*") == 0 ||
//        strlen (path) == 0)
//    {
//        path = "";
//    }
//    else if (path[0] != '/' ||
//             path[strlen (path) - 1] != '/' ||
//             strstr (path, "//") != NULL)
//    {
//        free (url);
//        ERROR ("SEARCH: invalid root (%s)!\n", path);
//        assert(!apteryx_debug || path[0] == '/');
//        assert(!apteryx_debug || path[strlen (path) - 1] == '/');
//        assert(!apteryx_debug || strstr (path, "//") == NULL);
//        return NULL;
//    }
//
//    /* IPC */
//    rpc_client = rpc_client_connect (rpc, url);
//    if (!rpc_client)
//    {
//        ERROR ("SEARCH: Path(%s) Failed to connect to server: %s\n", path, strerror (errno));
//        free (url);
//        return false;
//    }
//    search.path = (char *) path;
//    apteryx__server__search (rpc_client, &search, handle_search_response, &data);
//    if (!data.done)
//    {
//        ERROR ("SEARCH: No response\n");
//        rpc_client_release (rpc, rpc_client, false);
//        free (url);
//        return NULL;
//    }
//    rpc_client_release (rpc, rpc_client, true);
//    free (url);
//
//    /* Result */
//    return data.paths;
//    return NULL;
}

char *
apteryx_search_simple (const char *path)
{
    GList *paths = apteryx_search (path);
    char *tmp = NULL, *result = NULL;
    GList *iter;

    if (!paths)
    {
        return NULL;
    }
    for (iter = g_list_first (paths); iter; iter = g_list_next (iter))
    {
        if (result)
        {
            ASSERT (asprintf (&tmp, "%s\n%s", result, (char *) iter->data) > 0,
                    tmp = NULL, "SEARCH: Memory allocation failure\n");
        }
        else
        {
            ASSERT (asprintf (&tmp, "%s", (char *) iter->data) > 0, tmp = NULL,
                    tmp = NULL, "SEARCH: Memory allocation failure\n");
        }
        if (result)
            free (result);
        result = tmp;
        tmp = NULL;
    }
    g_list_free_full (paths, free);

    return result;
}

static GList *
search_path (const char *path)
{
    GList *results = NULL;
    GList *iter = NULL;

    /* Proxy first */
//    results = proxy_search (path);
    if (!results)
    {
        /* Indexers second */
        if (index_get (path, &results) == true)
        {
            DEBUG (" (index result:)\n");
        }
        else
        {
            /* Search database next */
            results = db_search (path);

            /* Append any provided paths */
            GList *providers = NULL;
            providers = cb_match (&provide_list, path, CB_MATCH_PART);
            for (iter = providers; iter; iter = g_list_next (iter))
            {
                cb_info_t *provider = iter->data;
                int len = strlen (path);
                /* If there is a provider for a single node below here it may
                 * show as a "*" entry in this list, which is not desirable */
                if (strlen (provider->path) > strlen (path) &&
                    provider->path[strlen (path)] == '*')
                {
                    continue;
                }
                char *ptr, *provider_path = g_strdup (provider->path);
                if ((ptr = strchr (&provider_path[len ? len : len+1], '/')) != 0)
                    *ptr = '\0';
                if (!g_list_find_custom (results, provider_path, (GCompareFunc) strcmp))
                    results = g_list_prepend (results, provider_path);
                else
                    g_free (provider_path);
            }
            g_list_free_full (providers, (GDestroyNotify) cb_release);
        }
    }
    return results;
}

static char *
get_value (const char *path)
{
    char *value = NULL;
    size_t vsize = 0;

    /* Proxy first */
//    if ((value = proxy_get (path)) == NULL)
    {
        /* Database second */
        if (!db_get (path, (unsigned char**)&value, &vsize))
        {
            /* Provide third */
            if ((value = provide_get (path)) == NULL)
            {
                DEBUG ("GET: not in database or provided or proxied\n");
            }
        }
    }

    return value;
}

GList *
apteryx_find (const char *path, const char *value)
{
    GList *possible_matches = NULL;
    GList *iter = NULL;
    char *tmp = NULL;
    char *ptr = NULL;
    char *chunk;
    GList *matches = NULL;

    DEBUG ("FIND: %s = %s\n", path, value);

    /* Grab first level (from root) */
    tmp = g_strdup (path);
    chunk = strtok_r( tmp, "*", &ptr);
    if (chunk)
    {
        possible_matches = search_path (chunk);
    }

    /* For each * do a search + add keys, then re-search */
    while ((chunk = strtok_r (NULL, "*", &ptr)) != NULL)
    {
        GList *last_round = possible_matches;
        possible_matches = NULL;
        for (iter = g_list_first (last_round); iter; iter = g_list_next (iter))
        {
            char *next_level = NULL;
            next_level = g_strdup_printf("%s%s", (char*) iter->data, chunk);
            possible_matches = g_list_concat (search_path (next_level), possible_matches);
            g_free (next_level);
        }
        g_list_free_full (last_round, g_free);
    }

    /* Go through each path match and see if all keys match */
    for (iter = g_list_first (possible_matches); iter; iter = g_list_next (iter))
    {
        bool possible_match = true;
        char *key = NULL;
        char *val = NULL;

        key = g_strdup_printf("%s%s", (char*)iter->data,
                          strrchr (path, '*') + 1);
        val = get_value (key);

        /* A "" value on a match maps to no return value from provider / database */
        if (strlen (value) == 0 && val == NULL)
        {
            possible_match = true;
        }
        else if ((strlen (value) == 0 && val != NULL) ||
                (val == NULL && strlen (value) > 0))
        {
            /* Match miss - we can stop checking */
            possible_match = false;
        }
        else if (strcmp (val, value) != 0)
        {
            /* Match miss - we can stop checking */
            possible_match = false;
        }
        g_free (key);
        g_free (val);

        /* All keys match, so this is a good path */
        if (possible_match)
        {
            matches = g_list_prepend (matches, g_strdup ((char*)iter->data));
        }
    }
    g_list_free_full (possible_matches, g_free);
    return matches;
//    char *url = NULL;
//    ProtobufCService *rpc_client;
//    Apteryx__Find find = APTERYX__FIND__INIT;
//    search_data_t data = {0};
//    Apteryx__PathValue pv = {
//            .base.descriptor = &apteryx__path_value__descriptor,
//            .path = (char*) path,
//            .value = (char*) value
//    };
//
//    char *tmp_path = NULL;
//
//    ASSERT ((ref_count > 0), return NULL, "FIND: Not initialised\n");
//    ASSERT (path, return NULL, "FIND: Invalid parameters\n");
//    ASSERT (value, return NULL, "FIND: Invalid parameters\n");
//
//    DEBUG ("FIND: %s = %s\n", path, value);
//
//    /* Check path */
//    path = validate_path (path, &url);
//    if (!path)
//    {
//        ERROR ("FIND: invalid root (%s)!\n", path);
//        free (url);
//        assert (!apteryx_debug || path);
//        return false;
//    }
//
//    /* Validate path */
//    if (!path ||
//        strcmp (path, "/") == 0 ||
//        strcmp (path, "/*") == 0 ||
//        strcmp (path, "*") == 0 ||
//        strlen (path) == 0)
//    {
//        path = "";
//    }
//    else if (path[0] != '/' ||
//             strstr (path, "//") != NULL)
//    {
//        free (url);
//        ERROR ("FIND: invalid root (%s)!\n", path);
//        assert(!apteryx_debug || path[0] == '/');
//        assert(!apteryx_debug || strstr (path, "//") == NULL);
//        return NULL;
//    }
//
//    /* Remove the trailing key */
//    tmp_path = strdup (path);
//    if (strrchr (tmp_path, '*'))
//        *strrchr (tmp_path, '*') = '\0';
//
//    find.path = tmp_path;
//    find.n_matches = 1;
//    find.matches = malloc (find.n_matches * sizeof (Apteryx__PathValue *));
//    find.matches[0] = &pv;
//
//    /* IPC */
//    rpc_client = rpc_client_connect (rpc, url);
//    if (!rpc_client)
//    {
//        ERROR ("FIND: Path(%s) Failed to connect to server: %s\n", path, strerror (errno));
//        free (url);
//        free (tmp_path);
//        return false;
//    }
//
//    apteryx__server__find (rpc_client, &find, handle_search_response, &data);
//    if (!data.done)
//    {
//        ERROR ("FIND: No response\n");
//        rpc_client_release (rpc, rpc_client, false);
//        free (url);
//        free (tmp_path);
//        return NULL;
//    }
//    rpc_client_release (rpc, rpc_client, true);
//    free (url);
//
//    free (tmp_path);
//    free (find.matches);
//
//    /* Result */
//    return data.paths;
//    return NULL;
}

//static gboolean
//_find_multi (GNode *node, gpointer data)
//{
//    Apteryx__Find *find = (Apteryx__Find *)data;
//
//    if (APTERYX_HAS_VALUE(node))
//    {
//        char *path = apteryx_node_path (node);
//        Apteryx__PathValue *pv = calloc (1, sizeof (Apteryx__PathValue));
//        DEBUG ("FIND_TREE: %s = %s\n", path, APTERYX_VALUE (node));
//        pv->base.descriptor = &apteryx__path_value__descriptor;
//        pv->path = (char *) path;
//        pv->value = (char *) APTERYX_VALUE (node);
//        find->matches[find->n_matches++] = pv;
//    }
//    return FALSE;
//}

GList *
apteryx_find_tree (GNode *root)
{
//    char *url = NULL;
//    ProtobufCService *rpc_client;
//    Apteryx__Find find = APTERYX__FIND__INIT;
//    search_data_t data = {0};
//    const char *path = APTERYX_NAME(root);
//    int i;
//
//    ASSERT ((ref_count > 0), return NULL, "FIND: Not initialised\n");
//    ASSERT (path, return NULL, "FIND: Invalid parameters\n");
//
//    DEBUG ("FIND_TREE: %s\n", path);
//
//    /* Check path */
//    path = validate_path (path, &url);
//
//    /* Validate path */
//    if (!path ||
//        strcmp (path, "/") == 0 ||
//        strcmp (path, "/*") == 0 ||
//        strcmp (path, "*") == 0 ||
//        strlen (path) == 0)
//    {
//        path = "";
//    }
//    else if (path[0] != '/' ||
//             strstr (path, "//") != NULL)
//    {
//        free (url);
//        ERROR ("FIND: invalid root (%s)!\n", path);
//        assert(!apteryx_debug || path[0] == '/');
//        assert(!apteryx_debug || strstr (path, "//") == NULL);
//        return NULL;
//    }
//
//    /* IPC */
//    rpc_client = rpc_client_connect (rpc, url);
//    if (!rpc_client)
//    {
//        ERROR ("FIND: Path(%s) Failed to connect to server: %s\n", path, strerror (errno));
//        free (url);
//        return false;
//    }
//
//    find.path = (char *) path;
//    find.n_matches = g_node_n_nodes (root, G_TRAVERSE_LEAVES);
//    find.matches = malloc (find.n_matches * sizeof (Apteryx__PathValue *));
//    find.n_matches = 0;
//    g_node_traverse (root, G_PRE_ORDER, G_TRAVERSE_NON_LEAFS, -1, _find_multi, &find);
//
//    apteryx__server__find (rpc_client, &find, handle_search_response, &data);
//    if (!data.done)
//    {
//        ERROR ("FIND: No response\n");
//        rpc_client_release (rpc, rpc_client, false);
//        free (url);
//        return NULL;
//    }
//    rpc_client_release (rpc, rpc_client, true);
//    free (url);
//
//    /* Cleanup message */
//    for (i = 0; i < find.n_matches; i++)
//    {
//        Apteryx__PathValue *pv = find.matches[i];
//        free (pv->path);
//        free (pv);
//    }
//    free (find.matches);
//
//    /* Result */
//    return data.paths;
    return NULL;
}

static bool
add_callback (const char *type, const char *path, void *cb)
{
    size_t pid = getpid ();
    char _path[PATH_MAX];

    ASSERT ((ref_count > 0), return false, "ADD_CB: Not initialised\n");
    ASSERT (type, return false, "ADD_CB: Invalid type\n");
    ASSERT (path, return false, "ADD_CB: Invalid path\n");
    ASSERT (cb, return false, "ADD_CB: Invalid callback\n");

//    if (!bound)
//    {
//        char * uri = NULL;
//
//        /* Bind to the default uri for this client */
//        pthread_mutex_lock (&lock);
//        if (asprintf ((char **) &uri, APTERYX_SERVER".%"PRIu64, (uint64_t) getpid ()) <= 0
//                || !rpc_server_bind (rpc, uri, uri))
//        {
//            ERROR ("Failed to bind uri %s\n", uri);
//            pthread_mutex_unlock (&lock);
//            free ((void*) uri);
//            return false;
//        }
//        DEBUG ("Bound to uri %s\n", uri);
//        pthread_mutex_unlock (&lock);
//        free ((void*) uri);
//        bound = true;
//    }

    if (sprintf (_path, "%s/%zX-%zX-%zX",
            type, (size_t)pid, (size_t)cb, (size_t)g_str_hash (path)) <= 0)
        return false;
    if (!apteryx_set (_path, path))
        return false;
//    have_callbacks = true;
    return true;
}

static bool
delete_callback (const char *type, const char *path,  void *cb)
{
    char _path[PATH_MAX];

    ASSERT ((ref_count > 0), return false, "DEL_CB: Not initialised\n");
    ASSERT (type, return false, "DEL_CB: Invalid type\n");
    ASSERT (path, return false, "DEL_CB: Invalid path\n");
    ASSERT (cb, return false, "DEL_CB: Invalid callback\n");

    if (sprintf (_path, "%s/%zX-%zX-%zX",
            type, (size_t)getpid (), (size_t)cb, (size_t)g_str_hash (path)) <= 0)
        return false;
    if (!apteryx_set (_path, NULL))
        return false;
    return true;
}

bool
apteryx_index (const char *path, apteryx_index_callback cb)
{
    return add_callback (APTERYX_INDEXERS_PATH, path, (void *)cb);
}

bool
apteryx_unindex (const char *path, apteryx_index_callback cb)
{
    return delete_callback (APTERYX_INDEXERS_PATH, path, (void *)cb);
}

bool
apteryx_watch (const char *path, apteryx_watch_callback cb)
{
    return add_callback (APTERYX_WATCHERS_PATH, path, (void *)cb);
}

bool
apteryx_unwatch (const char *path, apteryx_watch_callback cb)
{
    return delete_callback (APTERYX_WATCHERS_PATH, path, (void *)cb);
}

bool
apteryx_validate (const char *path, apteryx_validate_callback cb)
{
    return add_callback (APTERYX_VALIDATORS_PATH, path, (void *)cb);
}

bool
apteryx_unvalidate (const char *path, apteryx_validate_callback cb)
{
    return delete_callback (APTERYX_VALIDATORS_PATH, path, (void *)cb);
}

bool
apteryx_provide (const char *path, apteryx_provide_callback cb)
{
    return add_callback (APTERYX_PROVIDERS_PATH, path, (void *)cb);
}

bool
apteryx_unprovide (const char *path, apteryx_provide_callback cb)
{
    return delete_callback (APTERYX_PROVIDERS_PATH, path, (void *)cb);
}

//static void
//handle_timestamp_response (const Apteryx__TimeStampResult *result, void *closure_data)
//{
//    uint64_t *data = (uint64_t *)closure_data;
//
//    if (result == NULL)
//    {
//        ERROR ("TIMESTAMP: Error processing request.\n");
//        errno = -ETIMEDOUT;
//    }
//    else
//    {
//        *data = result->value;
//    }
//}

uint64_t
apteryx_timestamp (const char *path)
{
    uint64_t value = 0;

    ASSERT ((ref_count > 0), return 0, "TIMESTAMP: Not initialised\n");
    ASSERT (path, return 0, "TIMESTAMP: Invalid parameters\n");

    DEBUG ("TIMESTAMP: %s\n", path);

    /* Proxy first */
//    if ((value = proxy_timestamp (get->path)) == 0)
    {
        /* Lookup value */
        value = db_timestamp (path);
    }

    DEBUG ("    = %"PRIu64"\n", value);
    return value;

//    char *url = NULL;
//    uint64_t value = 0;
//    ProtobufCService *rpc_client;
//    Apteryx__Get get = APTERYX__GET__INIT;
//
//    ASSERT ((ref_count > 0), return 0, "TIMESTAMP: Not initialised\n");
//    ASSERT (path, return 0, "TIMESTAMP: Invalid parameters\n");
//
//    DEBUG ("TIMESTAMP: %s\n", path);
//
//    /* Check path */
//    path = validate_path (path, &url);
//    /* if path is empty, or path ends in '/' but is not the root db path (ie "/") */
//    if (!path ||
//        ((path[strlen(path)-1] == '/') && strlen(path) > 1))
//    {
//        ERROR ("TIMESTAMP: invalid path (%s)!\n", path);
//        free (url);
//        assert (!apteryx_debug || path);
//        return 0;
//    }
//
//    /* IPC */
//    rpc_client = rpc_client_connect (rpc, url);
//    if (!rpc_client)
//    {
//        ERROR ("TIMESTAMP: Path(%s) Failed to connect to server: %s\n", path, strerror (errno));
//        free (url);
//        return 0;
//    }
//    get.path = (char *) path;
//    apteryx__server__timestamp (rpc_client, &get, handle_timestamp_response, &value);
//    rpc_client_release (rpc, rpc_client, true);
//    free (url);
//
//    DEBUG ("    = %"PRIu64"\n", value);
//    return value;
}
