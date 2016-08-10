/**
 * @file apteryx.c
 * Server application for Apteryx.
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
#include <ctype.h>
#include <errno.h>
#include <sys/poll.h>
#include <arpa/inet.h>
#include "apteryx.h"
#include "apteryx.pb-c.h"
#include "internal.h"

/* Debug */
bool apteryx_debug = false;

/* Run while true */
static bool running = true;

/* RPC Service */
rpc_instance rpc = NULL;
rpc_instance proxy_rpc = NULL;

/* Statistics and debug */
counters_t counters = {};

/* Synchronise validation */
static pthread_mutex_t validating;

/* Callbacks for client communication */
static void
handle_set_response (const Apteryx__OKResult *result, void *closure_data)
{
    if (result == NULL)
    {
        *(int *) closure_data = -ETIMEDOUT;
    }
    else
    {
        *(int *) closure_data = result->result;
    }
}

typedef struct _get_data_t
{
    char *value;
    bool done;
} get_data_t;

static void
handle_get_response (const Apteryx__GetResult *result, void *closure_data)
{
    get_data_t *data = (get_data_t *)closure_data;
    data->done = false;
    if (result == NULL)
    {
        ERROR ("GET: Error processing request.\n");
    }
    else
    {
        data->done = true;
        if (result->value && result->value[0] != '\0')
        {
            data->value = g_strdup (result->value);
        }
    }
}

/* Indexer */
typedef struct _search_data_t
{
    GList *paths;
    bool done;
} search_data_t;

static void
handle_search_response (const Apteryx__SearchResult *result, void *closure_data)
{
    search_data_t *data = (search_data_t *)closure_data;
    int i;
    data->paths = NULL;
    data->done = false;
    if (result == NULL)
    {
        ERROR ("SEARCH: Error processing request.\n");
    }
    else if (result->paths == NULL)
    {
        DEBUG ("    = (null)\n");
        data->done = true;
    }
    else if (result->n_paths != 0)
    {
        for (i = 0; i < result->n_paths; i++)
        {
            data->paths = g_list_prepend (data->paths,
                              (gpointer) g_strdup (result->paths[i]));
        }
        data->done = true;
    }
}

/* Traverse (get tree) */
typedef struct _traverse_data_t
{
    GList *paths;
    const char *path;
    bool done;
} traverse_data_t;

static void
handle_traverse_response (const Apteryx__TraverseResult *result, void *closure_data)
{
    traverse_data_t *data = (traverse_data_t *)closure_data;
    int i;

    data->done = false;
    data->paths = NULL;
    if (result == NULL)
    {
        ERROR ("TRAVERSE: Error processing request.\n");
        errno = -ETIMEDOUT;
    }
    else if (result->pv == NULL)
    {
        DEBUG ("    = (null)\n");
        data->done = true;
    }
    else if (result->n_pv != 0)
    {
        int slen = strlen (data->path);
        for (i = 0; i < result->n_pv; i++)
        {
            Apteryx__PathValue *pvread = result->pv[i];
            Apteryx__PathValue *pv = calloc (1, sizeof (Apteryx__PathValue));
            pv->path = strdup (pvread->path + slen);
            pv->value = strdup (pvread->value);
            DEBUG ("  %s = %s\n", pv->path, pv->value);
            data->paths = g_list_prepend (data->paths, pv);
        }
        data->done = true;
    }
}

static void
handle_ok_response (const Apteryx__OKResult *result, void *closure_data)
{
    if (result == NULL)
    {
        *(protobuf_c_boolean *) closure_data = false;
    }
    else
    {
        *(protobuf_c_boolean *) closure_data = (result->result == 0);
    }
}

static void
handle_timestamp_response (const Apteryx__TimeStampResult *result, void *closure_data)
{
    uint64_t *data = (uint64_t *)closure_data;
    if (result == NULL)
    {
        ERROR ("TIMESTAMP: Error processing request.\n");
        *data = 0;
    }
    else
    {
        *data = result->value;
    }
}

static void
handle_validate_response (const Apteryx__ValidateResult *result, void *closure_data)
{
    if (!result)
        *(int32_t *) closure_data = -ETIMEDOUT;
    else
        *(int32_t *) closure_data = result->result;
}

static void
handle_watch_response (const Apteryx__NoResult *result, void *closure_data)
{
    *(protobuf_c_boolean *) closure_data = (result != NULL);
}

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
        ProtobufCService *rpc_client;
        Apteryx__Index index = APTERYX__INDEX__INIT;
        search_data_t data = {0};

        /* Check for local provider */
        if (indexer->id == getpid ())
        {
            apteryx_index_callback cb = (apteryx_index_callback) (long) indexer->cb;
            DEBUG ("INDEX LOCAL \"%s\" (0x%"PRIx64",0x%"PRIx64")\n",
                    indexer->path, indexer->id, indexer->cb);
            results = cb (path);
            break;
        }

        DEBUG ("INDEX CB \"%s\" (0x%"PRIx64",0x%"PRIx64")\n",
                indexer->path, indexer->id, indexer->cb);

        /* Setup IPC */
        rpc_client = rpc_client_connect (rpc, indexer->uri);
        if (!rpc_client)
        {
            /* Throw away the no good validator */
            ERROR ("Invalid INDEX CB %s (0x%"PRIx64",0x%"PRIx64")\n",
                    indexer->path, indexer->id, indexer->cb);
            cb_destroy (indexer);
            INC_COUNTER (counters.indexed_no_handler);
            continue;
        }

        /* Do remote get */
        index.path = (char *) path;
        index.id = indexer->id;
        index.cb = indexer->cb;
        apteryx__client__index (rpc_client, &index, handle_search_response, &data);
        if (!data.done)
        {
            INC_COUNTER (counters.indexed_timeout);
            ERROR ("No response from indexer for path \"%s\"\n", (char *)path);
            rpc_client_release (rpc, rpc_client, false);
        }
        else
        {
            rpc_client_release (rpc, rpc_client, true);
        }

        /* Result */
        INC_COUNTER (counters.indexed);
        INC_COUNTER (indexer->count);
        if (data.paths)
        {
            results = data.paths;
            break;
        }
    }
    g_list_free_full (indexers, (GDestroyNotify) cb_release);

    *result = results;
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

    /* Protect sensitive values with this lock - released in apteryx_set */
    pthread_mutex_lock (&validating);

    /* Call each validator */
    for (iter = validators; iter; iter = g_list_next (iter))
    {
        cb_info_t *validator = iter->data;
        ProtobufCService *rpc_client;
        Apteryx__Validate validate = APTERYX__VALIDATE__INIT;

        /* Check for local validator */
        if (validator->id == getpid ())
        {
            apteryx_watch_callback cb = (apteryx_watch_callback) (long) validator->cb;
            DEBUG ("VALIDATE LOCAL \"%s\" (0x%"PRIx64",0x%"PRIx64")\n",
                    validator->path, validator->id, validator->cb);
            cb (path, value);
            continue;
        }

        DEBUG ("VALIDATE CB %s = %s (0x%"PRIx64",0x%"PRIx64")\n",
                 validator->path, value, validator->id, validator->cb);

        /* Setup IPC */
        rpc_client = rpc_client_connect (rpc, validator->uri);
        if (!rpc_client)
        {
            /* Throw away the no good validator */
            ERROR ("Invalid VALIDATE CB %s (0x%"PRIx64",0x%"PRIx64")\n",
                    validator->path, validator->id, validator->cb);
            cb_destroy (validator);
            INC_COUNTER (counters.validated_no_handler);
            continue;
        }

        /* Do remote validate */
        validate.path = (char *)path;
        validate.value = (char *)value;
        validate.id = validator->id;
        validate.cb = validator->cb;
        apteryx__client__validate (rpc_client, &validate, handle_validate_response, &result);
        if (result < 0)
        {
            DEBUG ("Set of %s to %s rejected by process %"PRIu64" (%d)\n",
                    (char *)path, (char*)value, validator->id, result);
            INC_COUNTER (counters.validated_timeout);
            rpc_client_release (rpc, rpc_client, false);
            break;
        }
        else
        {
            rpc_client_release (rpc, rpc_client, true);
        }

        INC_COUNTER (counters.validated);
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
        ProtobufCService *rpc_client;
        protobuf_c_boolean is_done = false;
        Apteryx__Watch watch = APTERYX__WATCH__INIT;

        /* Check for local watcher */
        if (watcher->id == getpid ())
        {
            apteryx_watch_callback cb = (apteryx_watch_callback) (long) watcher->cb;
            DEBUG ("WATCH LOCAL \"%s\" (0x%"PRIx64",0x%"PRIx64")\n",
                    watcher->path, watcher->id, watcher->cb);
            cb (path, value);
            continue;
        }

        DEBUG ("WATCH CB %s = %s (%s 0x%"PRIx64",0x%"PRIx64",%s)\n",
                path, value, watcher->path, watcher->id, watcher->cb, watcher->uri);

        /* Setup IPC */
        rpc_client = rpc_client_connect (rpc, watcher->uri);
        if (!rpc_client)
        {
            /* Throw away the no good validator */
            ERROR ("Invalid WATCH CB %s (0x%"PRIx64",0x%"PRIx64")\n",
                   watcher->path, watcher->id, watcher->cb);
            cb_destroy (watcher);
            INC_COUNTER (counters.watched_no_handler);
            continue;
        }

        /* Do remote watch */
        watch.path = (char *)path;
        watch.value = value;
        watch.id = watcher->id;
        watch.cb = watcher->cb;
        apteryx__client__watch (rpc_client, &watch, handle_watch_response, &is_done);
        if (!is_done)
        {
            INC_COUNTER (counters.watched_timeout);
            ERROR ("Failed to notify watcher for path \"%s\"\n", (char *)path);
            rpc_client_release (rpc, rpc_client, false);
        }
        else
        {
            rpc_client_release (rpc, rpc_client, true);
        }

        INC_COUNTER (counters.watched);
        INC_COUNTER (watcher->count);
    }
    g_list_free_full (watchers, (GDestroyNotify) cb_release);

    /* Free memory if allocated */
    if (value)
        g_free (value);
}

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
        ProtobufCService *rpc_client;
        get_data_t data = {0};
        Apteryx__Provide provide = APTERYX__PROVIDE__INIT;

        /* Check for local provider */
        if (provider->id == getpid ())
        {
            apteryx_provide_callback cb = (apteryx_provide_callback) (long) provider->cb;
            DEBUG ("PROVIDE LOCAL \"%s\" (0x%"PRIx64",0x%"PRIx64")\n",
                                       provider->path, provider->id, provider->cb);
            value = cb (path);
            break;
        }

        DEBUG ("PROVIDE CB \"%s\" (0x%"PRIx64",0x%"PRIx64")\n",
               provider->path, provider->id, provider->cb);

        /* Setup IPC */
        rpc_client = rpc_client_connect (rpc, provider->uri);
        if (!rpc_client)
        {
            /* Throw away the no good validator */
            ERROR ("Invalid PROVIDE CB %s (0x%"PRIx64",0x%"PRIx64")\n",
                   provider->path, provider->id, provider->cb);
            cb_destroy (provider);
            INC_COUNTER (counters.provided_no_handler);
            continue;
        }

        /* Do remote get */
        provide.path = (char *) path;
        provide.id = provider->id;
        provide.cb = provider->cb;
        apteryx__client__provide (rpc_client, &provide, handle_get_response, &data);
        if (!data.done)
        {
            INC_COUNTER (counters.provided_timeout);
            ERROR ("No response from provider for path \"%s\"\n", (char *)path);
            rpc_client_release (rpc, rpc_client, false);
        }
        else
        {
            rpc_client_release (rpc, rpc_client, true);
        }

        /* Result */
        INC_COUNTER (counters.provided);
        INC_COUNTER (provider->count);
        if (data.value)
        {
            value = data.value;
            break;
        }
    }
    g_list_free_full (providers, (GDestroyNotify) cb_release);

    return value;
}

static ProtobufCService *
find_proxy (const char **path, cb_info_t **proxy_pt)
{
    ProtobufCService *rpc_client = NULL;
    GList *proxies = NULL;
    GList *iter = NULL;

    *proxy_pt = NULL;

    /* Retrieve a list of proxies for this path */
    proxies = cb_match (&proxy_list, *path,
            CB_MATCH_EXACT|CB_MATCH_WILD|CB_MATCH_CHILD);
    if (!proxies)
        return NULL;

    /* Find the first good proxy */
    for (iter = proxies; iter; iter = g_list_next (iter))
    {
        cb_info_t *proxy = iter->data;
        int len = strlen (proxy->path);

        /* Setup IPC */
        rpc_client = rpc_client_connect (proxy_rpc, proxy->uri);
        if (!rpc_client)
        {
            ERROR ("Invalid PROXY CB %s (%s)\n", proxy->path, proxy->uri);
            cb_destroy (proxy);
            INC_COUNTER (counters.proxied_no_handler);
            continue;
        }
        INC_COUNTER (counters.proxied);
        INC_COUNTER (proxy->count);

        /* Strip proxied path */
        if (proxy->path[len-1] == '*')
            len -= 1;
        if (proxy->path[len-1] == '/')
            len -= 1;
        *path = *path  + len;
        DEBUG ("PROXY CB \"%s\" to \"%s\"\n", *path, proxy->uri);
        *proxy_pt = proxy;
        break;
    }
    g_list_free_full (proxies, (GDestroyNotify) cb_release);
    return rpc_client;
}

static int
proxy_set (const char *path, const char *value, uint64_t ts)
{
    ProtobufCService *rpc_client;
    Apteryx__Set set = APTERYX__SET__INIT;
    Apteryx__PathValue _pv = APTERYX__PATH_VALUE__INIT;
    Apteryx__PathValue *pv[1] = {&_pv};
    int result = 1;
    cb_info_t *proxy = NULL;

    /* Find and connect to a proxied instance */
    rpc_client = find_proxy (&path, &proxy);
    if (!rpc_client)
    {
        /* A positive value is interpreted as proxy not found */
        return 1;
    }

    /* Do remote set */
    pv[0]->path = (char *) path;
    pv[0]->value = (char *) value;
    set.n_sets = 1;
    set.sets = pv;
    set.ts = ts;
    apteryx__server__set (rpc_client, &set, handle_set_response, &result);
    if (result == -ETIMEDOUT)
    {
        /* We got no response. Kill the socket. */
        ERROR ("PROXY SET: No response\n");
        rpc_client_release (rpc, rpc_client, false);
    }
    else
    {
        /* We got some response */
        if (result != 0)
            DEBUG ("PROXY SET: Error response: %s\n", strerror (-result));
        rpc_client_release (rpc, rpc_client, true);
    }
    return result;
}

static char *
proxy_get (const char *path)
{
    ProtobufCService *rpc_client;
    Apteryx__Get get = APTERYX__GET__INIT;
    get_data_t data = {0};
    cb_info_t *proxy = NULL;
    char *value = NULL;

    /* Find and connect to a proxied instance */
    rpc_client = find_proxy (&path, &proxy);
    if (!rpc_client)
        return NULL;

    /* Do remote get */
    get.path = (char *) path;
    apteryx__server__get (rpc_client, &get, handle_get_response, &data);
    if (!data.done)
    {
        INC_COUNTER (counters.proxied_timeout);
        ERROR ("No response from proxy for path \"%s\"\n", (char *)path);
        rpc_client_release (rpc, rpc_client, false);
    }
    else
    {
        rpc_client_release (rpc, rpc_client, true);
        value = data.value;
    }

    return value;
}

static GList *
proxy_search (const char *path)
{
    const char *in_path = path;
    ProtobufCService *rpc_client;
    Apteryx__Search search = APTERYX__SEARCH__INIT;
    search_data_t data = {0};
    cb_info_t *proxy = NULL;

    /* Find and connect to a proxied instance */
    rpc_client = find_proxy (&path, &proxy);
    if (!rpc_client)
        return NULL;

    /* Do remote search */
    search.path = (char *) path;
    apteryx__server__search (rpc_client, &search, handle_search_response, &data);
    if (!data.done)
    {
        INC_COUNTER (counters.proxied_timeout);
        ERROR ("No response from proxy for path \"%s\"\n", (char *)path);
        rpc_client_release (rpc, rpc_client, false);
    }
    else
    {
        rpc_client_release (rpc, rpc_client, true);
        /* Prepend local path to start of all search results */
        size_t path_len = path - in_path;
        char *local_path = g_malloc0 (path_len + 1);
        strncpy (local_path, in_path, path_len);
        GList *itr = data.paths;
        for (; itr; itr = itr->next)
        {
            char *tmp = g_strdup_printf ("%s%s", local_path, (char *)itr->data);
            g_free (itr->data);
            itr->data = tmp;
        }
        g_free (local_path);
    }

    return data.paths;
}

static GList *
proxy_traverse (const char *path)
{
    const char *in_path = path;
    ProtobufCService *rpc_client;
    Apteryx__Traverse traverse = APTERYX__TRAVERSE__INIT;
    traverse_data_t data = {0};
    cb_info_t *proxy = NULL;

    /* Find and connect to a proxied instance */
    rpc_client = find_proxy (&path, &proxy);
    if (!rpc_client)
        return NULL;

    /* Do remote traverse */
    traverse.path = (char *) path;
    data.path = path;
    apteryx__server__traverse (rpc_client, &traverse, handle_traverse_response, &data);
    if (!data.done)
    {
        INC_COUNTER (counters.proxied_timeout);
        ERROR ("No response from proxy for path \"%s\"\n", (char *)path);
        rpc_client_release (rpc, rpc_client, false);
    }
    else
    {
        DEBUG ("TRAVERSE: %s (proxies as %s)\n", in_path, path);
        rpc_client_release (rpc, rpc_client, true);
        /* Prepend full path to start of all search results */
        GList *itr = data.paths;
        for (; itr; itr = itr->next)
        {
            Apteryx__PathValue *pv = (Apteryx__PathValue *) itr->data;
            char *tmp = g_strconcat (in_path, pv->path, NULL);
            g_free (pv->path);
            pv->path = tmp;
        }
    }

    return data.paths;
}

static int
proxy_prune (const char *path)
{
    ProtobufCService *rpc_client;
    Apteryx__Prune prune = APTERYX__PRUNE__INIT;
    protobuf_c_boolean is_done = 0;
    cb_info_t *proxy = NULL;

    /* Find and connect to a proxied instance */
    rpc_client = find_proxy (&path, &proxy);
    if (!rpc_client)
        return false;

    /* Do remote prune */
    prune.path = (char *) path;
    apteryx__server__prune (rpc_client, &prune, handle_ok_response, &is_done);
    if (!is_done)
    {
        ERROR ("PROXY PRUNE: No response\n");
        rpc_client_release (rpc, rpc_client, false);
        return false;
    }
    rpc_client_release (rpc, rpc_client, true);

    return true;
}

static uint64_t
proxy_timestamp (const char *path)
{
    ProtobufCService *rpc_client;
    Apteryx__Get get = APTERYX__GET__INIT;
    uint64_t value = 0;
    cb_info_t *proxy = NULL;

    /* Find and connect to a proxied instance */
    rpc_client = find_proxy (&path, &proxy);
    if (!rpc_client)
        return 0;

    /* Do remote timestamp */
    get.path = (char *) path;
    apteryx__server__timestamp (rpc_client, &get, handle_timestamp_response, &value);
    if (!value)
    {
        INC_COUNTER (counters.proxied_timeout);
        ERROR ("No response from proxy for path \"%s\"\n", (char *)path);
        rpc_client_release (rpc, rpc_client, false);
        return value;
    }
    rpc_client_release (rpc, rpc_client, true);

    return value;
}

static void
apteryx__set (Apteryx__Server_Service *service,
              const Apteryx__Set *set,
              Apteryx__OKResult_Closure closure, void *closure_data)
{
    Apteryx__OKResult result = APTERYX__OKRESULT__INIT;
    const char *path = NULL;
    const char *value = NULL;
    result.result = 0;
    int validation_result = 0;
    int validation_lock = 0;
    int proxy_result = 0;
    bool db_result = false;
    int i;

    /* Check parameters */
    if (set == NULL || set->n_sets == 0 || set->sets == NULL)
    {
        ERROR ("SET: Invalid parameters.\n");
        result.result = -EINVAL;
        closure (&result, closure_data);
        INC_COUNTER (counters.set_invalid);
        return;
    }
    INC_COUNTER (counters.set);

    /* Debug */
    for (i=0; apteryx_debug && i<set->n_sets; i++)
    {
        DEBUG ("SET: %s = %s\n", set->sets[i]->path, set->sets[i]->value);
    }

    /* Proxy first */
    for (i=0; i<set->n_sets; i++)
    {
        path = set->sets[i]->path;
        value = set->sets[i]->value;
        if (value && value[0] == '\0')
            value = NULL;

        proxy_result = proxy_set (path, value, set->ts);
        if (proxy_result == 0)
        {
            /*  Result success */
            DEBUG ("SET: %s = %s proxied\n", path, value);
            /* Mark the set as processed */
            notify_watchers (set->sets[i]->path);
            free (set->sets[i]->path);
            set->sets[i]->path = NULL;
        }
        else if (proxy_result < 0)
        {
            result.result = proxy_result;
            goto exit;
        }
    }

    /* Validate */
    for (i=0; i<set->n_sets; i++)
    {
        path = set->sets[i]->path;
        if (!path)
            continue;
        value = set->sets[i]->value;
        if (value && value[0] == '\0')
            value = NULL;

        /* Validate new data */
        validation_result = validate_set (path, value);
        if (validation_result != 0)
            validation_lock++;
        if (validation_result < 0)
        {
            DEBUG ("SET: %s = %s refused by validate\n", path, value);
            result.result = validation_result;
            goto exit;
        }
    }

    /* Set in the database */
    pthread_rwlock_wrlock (&db_lock);
    for (i=0; i<set->n_sets; i++)
    {
        path = set->sets[i]->path;
        if (!path)
            continue;
        value = set->sets[i]->value;
        if (value && value[0] == '\0')
            value = NULL;

        /* Add/Delete to/from database */
        if (value)
            db_result = db_add_no_lock (path, (unsigned char*)value, strlen (value) + 1, set->ts);
        else
            db_result = db_delete_no_lock (path, set->ts);
        if (!db_result)
        {
            DEBUG ("SET: %s = %s refused by DB\n", path, value);
            result.result = -EBUSY;
            pthread_rwlock_unlock (&db_lock);
            goto exit;
        }
    }
    pthread_rwlock_unlock (&db_lock);

    /* Set succeeded */
    result.result = 0;

exit:
    /* Return result and notify watchers */
    if (validation_result >= 0 && result.result == 0)
    {
        /* Notify watchers */
        for (i=0; i<set->n_sets; i++)
        {
            if (set->sets[i]->path)
                notify_watchers (set->sets[i]->path);
        }
    }

    /* Return result */
    closure (&result, closure_data);

    /* Release validation lock - this is a sensitive value */
    while (validation_lock)
    {
        DEBUG("SET: unlocking mutex\n");
        pthread_mutex_unlock (&validating);
        validation_lock--;
    }
    return;
}

static char *
get_value (const char *path)
{
    char *value = NULL;
    size_t vsize = 0;

    /* Proxy first */
    if ((value = proxy_get (path)) == NULL)
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

static void
apteryx__get (Apteryx__Server_Service *service,
              const Apteryx__Get *get,
              Apteryx__GetResult_Closure closure, void *closure_data)
{
    Apteryx__GetResult result = APTERYX__GET_RESULT__INIT;
    char *value = NULL;

    /* Check parameters */
    if (get == NULL || get->path == NULL)
    {
        ERROR ("GET: Invalid parameters.\n");
        closure (NULL, closure_data);
        INC_COUNTER (counters.get_invalid);
        return;
    }
    INC_COUNTER (counters.get);

    DEBUG ("GET: %s\n", get->path);

    /* Lookup value */
    value = get_value (get->path);

    /* Send result */
    DEBUG ("     = %s\n", value);
    result.value = value;
    closure (&result, closure_data);
    if (value)
        g_free (value);
    return;
}

static GList *
search_path (const char *path)
{
    GList *results = NULL;
    GList *iter = NULL;

    /* Proxy first */
    results = proxy_search (path);
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

static void
apteryx__search (Apteryx__Server_Service *service,
                 const Apteryx__Search *search,
                 Apteryx__SearchResult_Closure closure, void *closure_data)
{
    Apteryx__SearchResult result = APTERYX__SEARCH_RESULT__INIT;
    GList *results = NULL;
    GList *iter = NULL;
    int i;
    (void) service;

    /* Check parameters */
    if (search == NULL || search->path == NULL)
    {
        ERROR ("SEARCH: Invalid parameters.\n");
        closure (NULL, closure_data);
        INC_COUNTER (counters.search_invalid);
        return;
    }
    INC_COUNTER (counters.search);

    DEBUG ("SEARCH: %s\n", search->path);

    results = search_path (search->path);

    /* Prepare the results */
    result.n_paths = g_list_length (results);
    if (result.n_paths > 0)
    {
        result.paths = (char **) g_malloc (result.n_paths * sizeof (char *));
        for (i = 0, iter = results; iter; iter = g_list_next (iter), i++)
        {
            DEBUG ("         = %s\n", (char *) iter->data);
            result.paths[i] = (char *) iter->data;
        }
    }

    /* Send result */
    closure (&result, closure_data);
    g_list_free_full (results, g_free);
    if (result.paths)
        g_free (result.paths);
    return;
}


static void
apteryx__find (Apteryx__Server_Service *service,
              const Apteryx__Find *find,
              Apteryx__SearchResult_Closure closure, void *closure_data)
{
    Apteryx__SearchResult result = APTERYX__SEARCH_RESULT__INIT;
    GList *possible_matches = NULL;
    GList *iter = NULL;
    char *tmp = NULL;
    char *ptr = NULL;
    char *chunk;
    GList *matches = NULL;
    int i;

    /* Check parameters */
    if (find == NULL || find->n_matches == 0 || find->matches == NULL)
    {
        ERROR ("FIND: Invalid parameters.\n");
        INC_COUNTER (counters.find_invalid);
        goto exit;
    }
    INC_COUNTER (counters.find);

    /* Debug */
    for (i = 0; apteryx_debug && i < find->n_matches; i++)
    {
        DEBUG ("FIND: %s = %s\n", find->matches[i]->path, find->matches[i]->value);
    }

    /* Grab first level (from root) */
    tmp = g_strdup (find->path);
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
        for (i = 0; i < find->n_matches && possible_match; i++)
        {
            char *key = NULL;
            char *value = NULL;

            key = g_strdup_printf("%s%s", (char*)iter->data,
                              strrchr (find->matches[i]->path, '*') + 1);
            value = get_value (key);


            /* A "" value on a match maps to no return value from provider / database */
            if (strlen (find->matches[i]->value) == 0 && value == NULL)
            {
                possible_match = true;
            }
            else if ((strlen (find->matches[i]->value) == 0 && value != NULL) ||
                    (value == NULL && strlen (find->matches[i]->value) > 0))
            {
                /* Match miss - we can stop checking */
                possible_match = false;
            }
            else if (strcmp (value, find->matches[i]->value) != 0)
            {
                /* Match miss - we can stop checking */
                possible_match = false;
            }

            g_free (key);
            g_free (value);
        }

        /* All keys match, so this is a good path */
        if (possible_match)
        {
            matches = g_list_prepend (matches, g_strdup ((char*)iter->data));
        }
    }
    g_list_free_full (possible_matches, g_free);

    DEBUG ("FIND: matches:\n");
    /* Prepare the results */
    result.n_paths = g_list_length (matches);
    if (result.n_paths > 0)
    {
        result.paths = (char **) g_malloc (result.n_paths * sizeof (char *));
        for (i = 0, iter = g_list_first (matches); iter; iter = g_list_next (iter), i++)
        {
            DEBUG ("         = %s\n", (char *) iter->data);
            result.paths[i] = (char *) iter->data;
        }
    }
    else
    {
        DEBUG ("         NONE\n");
    }

exit:
    /* Return result */
    closure (&result, closure_data);

    /* Cleanup */
    g_free (tmp);
    g_list_free_full (matches, g_free);
    if (result.paths)
        g_free (result.paths);

    return;
}

static void
_traverse_paths (GList **pvlist, const char *path)
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
        Apteryx__PathValue *pv = NULL;

        /* Allocate a new pv */
        pv = g_malloc0 (sizeof (Apteryx__PathValue));
        pv->path = g_strdup (path);
        pv->value = value;

        /* Add to the list */
        *pvlist = g_list_prepend (*pvlist, pv);
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
        _traverse_paths (pvlist, (const char *) iter->data);
    }
    g_list_free_full (children, g_free);
    g_free (path_s);
}

static void
apteryx__traverse (Apteryx__Server_Service *service,
                 const Apteryx__Traverse *traverse,
                 Apteryx__TraverseResult_Closure closure, void *closure_data)
{
    Apteryx__TraverseResult result = APTERYX__TRAVERSE_RESULT__INIT;
    GList *iter, *pvlist = NULL;
    (void) service;

    /* Check parameters */
    if (traverse == NULL || traverse->path == NULL)
    {
        ERROR ("TRAVERSE: Invalid parameters.\n");
        closure (NULL, closure_data);
        INC_COUNTER (counters.traverse_invalid);
        return;
    }
    INC_COUNTER (counters.traverse);

    DEBUG ("TRAVERSE: %s\n", traverse->path);

    /* Proxy first */
    pvlist = proxy_traverse (traverse->path);
    if (!pvlist)
    {
        /* Traverse (local) paths */
        _traverse_paths (&pvlist, traverse->path);
    }

    if (pvlist)
    {
        result.n_pv = 0;
        result.pv = g_malloc (g_list_length (pvlist) * sizeof (Apteryx__PathValue *));
        for (iter = pvlist; iter; iter = g_list_next (iter))
        {
            Apteryx__PathValue *pv = (Apteryx__PathValue *) iter->data;
            pv->base.descriptor = &apteryx__path_value__descriptor;
            DEBUG ("  %s = %s\n", pv->path, pv->value);
            result.pv[result.n_pv++] = pv;
        }
    }

    /* Send result */
    closure (&result, closure_data);
    if (pvlist)
    {
        for (iter = pvlist; iter; iter = g_list_next (iter))
        {
            Apteryx__PathValue *pv = (Apteryx__PathValue *) iter->data;
            g_free (pv->path);
            g_free (pv->value);
            g_free (pv);
        }
        g_free (result.pv);
        g_list_free (pvlist);
    }
    return;
}

static void
_search_paths (GList **paths, const char *path)
{
    GList *children, *iter;
    children = db_search (path);
    for (iter = children; iter; iter = g_list_next (iter))
    {
        _search_paths (paths, (const char *) iter->data);
    }
    *paths = g_list_concat (children, *paths);
}

static void
apteryx__prune (Apteryx__Server_Service *service,
                const Apteryx__Prune *prune,
                Apteryx__OKResult_Closure closure, void *closure_data)
{
    Apteryx__OKResult result = APTERYX__OKRESULT__INIT;
    result.result = 0;
    GList *paths = NULL, *iter;
    (void) service;

    /* Check parameters */
    if (prune == NULL || prune->path == NULL)
    {
        ERROR ("PRUNE: Invalid parameters.\n");
        result.result = -EINVAL;
        closure (&result, closure_data);
        INC_COUNTER (counters.prune_invalid);
        return;
    }
    INC_COUNTER (counters.prune);

    DEBUG ("PRUNE: %s\n", prune->path);

    /* Proxy first */
    if (proxy_prune (prune->path))
    {
        /* Return result */
        closure (&result, closure_data);
        return;
    }

    /* Collect the list of deleted paths for notification */
    paths = g_list_prepend(paths, g_strdup(prune->path));
    _search_paths (&paths, prune->path);

    /* Prune from database */
    db_delete (prune->path, UINT64_MAX);

    /* Return result */
    closure (&result, closure_data);

    /* Call watchers for each pruned path */
    for (iter = paths; iter; iter = g_list_next (iter))
    {
        notify_watchers ((const char *)iter->data);
    }

    g_list_free_full (paths, g_free);
    return;
}

static void
apteryx__timestamp (Apteryx__Server_Service *service,
                        const Apteryx__Get *get,
                        Apteryx__TimeStampResult_Closure closure, void *closure_data)
{
    Apteryx__TimeStampResult result = APTERYX__TIME_STAMP_RESULT__INIT;
    uint64_t value = 0;

    /* Check parameters */
    if (get == NULL || get->path == NULL)
    {
        ERROR ("TIMESTAMP: Invalid parameters.\n");
        closure (NULL, closure_data);
        INC_COUNTER (counters.timestamp_invalid);
        return;
    }
    INC_COUNTER (counters.timestamp);

    DEBUG ("TIMESTAMP: %s\n", get->path);

    /* Proxy first */
    if ((value = proxy_timestamp (get->path)) == 0)
    {
        /* Lookup value */
        value = db_timestamp (get->path);
    }

    /* Send result */
    DEBUG ("     = %"PRIu64"\n", value);
    result.value = value;
    closure (&result, closure_data);
    return;
}

static Apteryx__Server_Service apteryx_server_service = APTERYX__SERVER__INIT (apteryx__);

void
termination_handler (void)
{
    running = false;
}

void
help (void)
{
    printf ("Usage: apteryxd [-h] [-b] [-d] [-p <pidfile>] [-l <url>]\n"
            "  -h   show this help\n"
            "  -b   background mode\n"
            "  -d   enable verbose debug\n"
            "  -m   memory profiling\n"
            "  -p   use <pidfile> (defaults to "APTERYX_PID")\n"
            "  -l   listen on URL <url> (defaults to "APTERYX_SERVER")\n");
}

int
main (int argc, char **argv)
{
    const char *pid_file = APTERYX_PID;
    const char *url = APTERYX_SERVER;
    bool background = false;
    pthread_mutexattr_t callback_recursive;
    FILE *fp;
    int i;

    /* Parse options */
    while ((i = getopt (argc, argv, "hdmbp:l:")) != -1)
    {
        switch (i)
        {
        case 'd':
            apteryx_debug = true;
            background = false;
            break;
        case 'b':
            background = true;
            break;
        case 'p':
            pid_file = optarg;
            break;
        case 'l':
            url = optarg;
            break;
        case 'm':
            g_mem_set_vtable (glib_mem_profiler_table);
            break;
        case '?':
        case 'h':
        default:
            help ();
            return 0;
        }
    }

    /* Handle SIGTERM/SIGINT/SIGPIPE gracefully */
    signal (SIGTERM, (__sighandler_t) termination_handler);
    signal (SIGINT, (__sighandler_t) termination_handler);
    signal (SIGPIPE, SIG_IGN);

    /* Daemonize */
    if (background && fork () != 0)
    {
        /* Parent */
        return 0;
    }

    /* Create pid file */
    if (background)
    {
        fp = fopen (pid_file, "w");
        if (!fp)
        {
            ERROR ("Failed to create PID file %s\n", pid_file);
            goto exit;
        }
        fprintf (fp, "%d\n", getpid ());
        fclose (fp);
    }

    /* Initialise the database */
    db_init ();
    /* Initialise callbacks to clients */
    cb_init ();
    /* Configuration Set/Get */
    config_init ();

    /* Create a lock for currently-validating */
    pthread_mutexattr_init (&callback_recursive);
    pthread_mutexattr_settype (&callback_recursive, PTHREAD_MUTEX_RECURSIVE);
    pthread_mutex_init (&validating, &callback_recursive);

    /* Init the RPC for the server instance */
    rpc = rpc_init ((ProtobufCService *)&apteryx_server_service, &apteryx__client__descriptor, RPC_TIMEOUT_US);
    if (rpc == NULL)
    {
        ERROR ("Failed to initialise RPC service\n");
        goto exit;
    }

    /* Create server and process requests */
    if (!rpc_server_bind (rpc, url, url))
    {
        ERROR ("Failed to start rpc service\n");
        goto exit;
    }

    /* Init the RPC for the proxy client */
    proxy_rpc = rpc_init (NULL, &apteryx__server__descriptor, RPC_TIMEOUT_US);
    if (proxy_rpc == NULL)
    {
        ERROR ("Failed to initialise proxy RPC service\n");
        goto exit;
    }

    /* Loop while running */
    while (running)
    {
        pause ();
    }

exit:
    DEBUG ("Exiting\n");

    /* Cleanup callbacks */
    cb_shutdown ();
    db_shutdown ();
    if (proxy_rpc)
    {
        rpc_shutdown (proxy_rpc);
    }
    if (rpc)
    {
        rpc_server_release (rpc, url);
        rpc_shutdown (rpc);
    }

    /* Remove the pid file */
    if (background)
        unlink (pid_file);

    /* Memory profiling */
    g_mem_profile ();

    return 0;
}
