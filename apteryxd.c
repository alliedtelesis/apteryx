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
bool debug = false;

/* Run while true */
static bool running = true;
static int stopfd = -1;

/* Statistics and debug */
counters_t counters = {};

/* Synchronise validation */
static pthread_mutex_t validating;

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
    if (result == NULL)
    {
        ERROR ("INDEX: Error processing request.\n");
    }
    else if (result->paths == NULL)
    {
        DEBUG ("    = (null)\n");
    }
    else if (result->n_paths != 0)
    {
        for (i = 0; i < result->n_paths; i++)
        {
            DEBUG ("    = %s\n", result->paths[i]);
            data->paths = g_list_append (data->paths,
                              (gpointer) strdup (result->paths[i]));
        }
    }
    data->done = true;
}

static GList *
index_get (const char *path)
{
    GList *indexers = NULL;
    GList *results = NULL;
    GList *iter = NULL;

    /* Retrieve a list of providers for this path */
    indexers = cb_match (&index_list, path,
            CB_MATCH_EXACT|CB_MATCH_WILD|CB_MATCH_CHILD);
    if (!indexers)
        return NULL;

    /* Find the first good indexer */
    for (iter = indexers; iter; iter = g_list_next (iter))
    {
        cb_info_t *indexer = iter->data;
        ProtobufCService *rpc_client;
        Apteryx__Index index = APTERYX__INDEX__INIT;
        search_data_t data = {0};
        char service_name[64];

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
        sprintf (service_name, APTERYX_SERVER ".%"PRIu64"", indexer->id);
        rpc_client = rpc_connect_service (service_name, &apteryx__client__descriptor);
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
        }

        /* Destroy the service */
        protobuf_c_service_destroy (rpc_client);

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

    return results;
}

static void
handle_validate_response (const Apteryx__ValidateResult *result, void *closure_data)
{
    if (!result)
        *(int32_t *) closure_data = -ETIMEDOUT;
    else
        *(int32_t *) closure_data = result->result;
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
        char service_name[64];

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
        sprintf (service_name, APTERYX_SERVER ".%"PRIu64"", validator->id);
        rpc_client = rpc_connect_service (service_name, &apteryx__client__descriptor);
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
            /* Destroy the service */
            protobuf_c_service_destroy (rpc_client);
            INC_COUNTER (counters.validated_timeout);
            break;
        }

        /* Destroy the service */
        protobuf_c_service_destroy (rpc_client);
        INC_COUNTER (counters.validated);
    }
    g_list_free_full (validators, (GDestroyNotify) cb_release);

    /* This one is fine, but lock is still held */
    return result < 0 ? result : 1;
}

static void
handle_watch_response (const Apteryx__OKResult *result, void *closure_data)
{
    *(protobuf_c_boolean *) closure_data = (result != NULL);
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
            CB_MATCH_EXACT|CB_MATCH_WILD|CB_MATCH_CHILD);
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
        char service_name[64];

        /* Check for local watcher */
        if (watcher->id == getpid ())
        {
            apteryx_watch_callback cb = (apteryx_watch_callback) (long) watcher->cb;
            DEBUG ("WATCH LOCAL \"%s\" (0x%"PRIx64",0x%"PRIx64")\n",
                    watcher->path, watcher->id, watcher->cb);
            cb (path, value);
            continue;
        }

        DEBUG ("WATCH CB %s = %s (%s 0x%"PRIx64",0x%"PRIx64")\n",
                path, value, watcher->path, watcher->id, watcher->cb);

        /* Setup IPC */
        sprintf (service_name, APTERYX_SERVER ".%"PRIu64"", watcher->id);
        rpc_client = rpc_connect_service (service_name, &apteryx__client__descriptor);
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
        }

        /* Destroy the service */
        protobuf_c_service_destroy (rpc_client);
        INC_COUNTER (counters.watched);
        INC_COUNTER (watcher->count);
    }
    g_list_free_full (watchers, (GDestroyNotify) cb_release);

    /* Free memory if allocated */
    if (value)
        free (value);
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
    if (result == NULL)
    {
        ERROR ("GET: Error processing request.\n");
    }
    else if (result->value && result->value[0] != '\0')
    {
        data->value = strdup (result->value);
    }
    data->done = true;
}

static char *
provide_get (const char *path)
{
    GList *providers = NULL;
    char *value = NULL;
    GList *iter = NULL;

    /* Retrieve a list of providers for this path */
    providers = cb_match (&provide_list, path,
            CB_MATCH_EXACT|CB_MATCH_WILD|CB_MATCH_CHILD);
    if (!providers)
        return 0;

    /* Find the first good provider */
    for (iter = providers; iter; iter = g_list_next (iter))
    {
        cb_info_t *provider = iter->data;
        ProtobufCService *rpc_client;
        get_data_t data = {0};
        Apteryx__Provide provide = APTERYX__PROVIDE__INIT;
        char service_name[64];

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
        sprintf (service_name, APTERYX_SERVER ".%"PRIu64"", provider->id);
        rpc_client = rpc_connect_service (service_name, &apteryx__client__descriptor);
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
        }

        /* Destroy the service */
        protobuf_c_service_destroy (rpc_client);

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

static char *
proxy_get (const char *path)
{
    GList *proxies = NULL;
    char *value = NULL;
    GList *iter = NULL;

    /* Retrieve a list of proxies for this path */
    proxies = cb_match (&proxy_list, path,
            CB_MATCH_EXACT|CB_MATCH_WILD|CB_MATCH_CHILD);
    if (!proxies)
        return 0;

    /* Find the first good proxy */
    for (iter = proxies; iter; iter = g_list_next (iter))
    {
        cb_info_t *proxy = iter->data;
        int len = strlen (proxy->path);
        ProtobufCService *rpc_client;
        get_data_t data = {0};
        Apteryx__Provide provide = APTERYX__PROVIDE__INIT;

        /* Strip proxied path */
        if (proxy->path[len-1] == '*')
            len -= 1;
        if (proxy->path[len-1] == '/')
            len -= 1;
        path = path + len;
        DEBUG ("PROXY CB \"%s\" to \"%s\"\n", path, proxy->uri);

        /* Setup IPC */
        rpc_client = rpc_connect_service (proxy->uri, &apteryx__client__descriptor);
        if (!rpc_client)
        {
            ERROR ("Invalid PROXY CB %s (0x%"PRIx64",0x%"PRIx64")\n",
                    proxy->path, proxy->id, proxy->cb);
            cb_destroy (proxy);
            INC_COUNTER (counters.proxied_no_handler);
            continue;
        }

        /* Do remote get */
        provide.path = (char *) path;
        provide.id = proxy->id;
        provide.cb = proxy->cb;
        apteryx__client__provide (rpc_client, &provide,
                                  handle_get_response, &data);
        if (!data.done)
        {
            INC_COUNTER (counters.proxied_timeout);
            ERROR ("No response from proxy for path \"%s\"\n", (char *)path);
        }

        /* Destroy the service */
        protobuf_c_service_destroy (rpc_client);

        /* Result */
        INC_COUNTER (counters.proxied);
        INC_COUNTER (proxy->count);
        if (data.value)
        {
            value = data.value;
            break;
        }
    }
    g_list_free_full (proxies, (GDestroyNotify) cb_release);
    return value;
}

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

static int
proxy_set (const char *path, const char *value)
{
    GList *proxies = NULL;
    GList *iter = NULL;
    int result = 1;

    /* Retrieve a list of proxies for this path */
    proxies = cb_match (&proxy_list, path,
            CB_MATCH_EXACT|CB_MATCH_WILD|CB_MATCH_CHILD);
    if (!proxies)
        return 1;

    /* Find the first good proxy */
    for (iter = proxies; iter; iter = g_list_next (iter))
    {
        cb_info_t *proxy = iter->data;
        int len = strlen (proxy->path);
        ProtobufCService *rpc_client;
        Apteryx__Set set = APTERYX__SET__INIT;

        /* Strip proxied path */
        if (proxy->path[len-1] == '*')
            len -= 1;
        if (proxy->path[len-1] == '/')
            len -= 1;
        path = path + len;
        DEBUG ("PROXY CB \"%s\" to \"%s\"\n", path, proxy->uri);

        /* Setup IPC */
        rpc_client = rpc_connect_service (proxy->uri, &apteryx__server__descriptor);
        if (!rpc_client)
        {
            ERROR ("Invalid PROXY CB %s (0x%"PRIx64",0x%"PRIx64")\n",
                    proxy->path, proxy->id, proxy->cb);
            cb_destroy (proxy);
            INC_COUNTER (counters.proxied_no_handler);
            continue;
        }

        /* Do remote set */
        set.path = (char *) path;
        set.value = (char *) value;
        apteryx__server__set (rpc_client, &set, handle_set_response, &result);

        INC_COUNTER (counters.proxied);
        INC_COUNTER (proxy->count);

        /* Destroy the service */
        protobuf_c_service_destroy (rpc_client);
        break;
    }
    g_list_free_full (proxies, (GDestroyNotify) cb_release);
    return result;
}

static void
apteryx__set (Apteryx__Server_Service *service,
              const Apteryx__Set *set,
              Apteryx__OKResult_Closure closure, void *closure_data)
{
    Apteryx__OKResult result = APTERYX__OKRESULT__INIT;
    result.result = 0;
    int validation_result = 0;
    int proxy_result = 0;

    /* Check parameters */
    if (set == NULL || set->path == NULL)
    {
        ERROR ("SET: Invalid parameters.\n");
        result.result = -EINVAL;
        closure (&result, closure_data);
        INC_COUNTER (counters.set_invalid);
        return;
    }
    INC_COUNTER (counters.set);

    DEBUG ("SET: %s = %s\n", set->path, set->value);

    /* Check proxy first */
    proxy_result = proxy_set (set->path, set->value);
    if (proxy_result <= 0)
    {
        DEBUG ("SET: %s = %s proxied (result=%d)\n",
                set->path, set->value, proxy_result);
        result.result = proxy_result;
        goto exit;
    }

    /* Validate new data */
    validation_result = validate_set (set->path, set->value);
    if (validation_result < 0)
    {
        DEBUG ("SET: %s = %s refused by validate\n", set->path, set->value);
        result.result = validation_result;
        goto exit;
    }

    /* Add/Delete to/from database */
    if (set->value && set->value[0] != '\0')
        db_add (set->path, (unsigned char*)set->value, strlen (set->value) + 1);
    else
        db_delete (set->path);

#ifdef USE_SHM_CACHE
    if (set->value && set->value[0] != '\0')
        cache_set (set->path, set->value);
    else
        cache_set (set->path, NULL);
#endif

    /* Set succeeded */
    result.result = 0;

exit:
    /* Return result */
    closure (&result, closure_data);

    if (validation_result >= 0)
    {
        /* Notify watchers */
        notify_watchers (set->path);
    }

    /* Release validation lock - this is a sensitive value */
    if (validation_result)
    {
        DEBUG("SET: unlocking mutex\n");
        pthread_mutex_unlock (&validating);
    }
    return;
}

static void
apteryx__get (Apteryx__Server_Service *service,
              const Apteryx__Get *get,
              Apteryx__GetResult_Closure closure, void *closure_data)
{
    Apteryx__GetResult result = APTERYX__GET_RESULT__INIT;
    char *value = NULL;
    size_t vsize = 0;

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
    value = NULL;
    vsize = 0;
    /* Proxy first */
    if ((value = proxy_get (get->path)) == NULL)
    {
        /* Database second */
        if (!db_get (get->path, (unsigned char**)&value, &vsize))
        {
            /* Provide third */
            if ((value = provide_get (get->path)) == NULL)
            {
                DEBUG ("GET: not in database or provided or proxied\n");
            }
        }
#ifdef USE_SHM_CACHE
        else
        {
            cache_set (get->path, value);
        }
#endif
    }

    /* Send result */
    DEBUG ("     = %s\n", value);
    result.value = value;
    closure (&result, closure_data);
    if (value)
        free (value);
    return;
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

    /* Search database first */
    results = db_search (search->path);
    if (!results)
    {
        /* Then indexers */
        results = index_get (search->path);
        if (!results)
        {
            /* Then provided paths */
            GList *providers = NULL;
            providers = cb_match (&provide_list, search->path, CB_MATCH_PART);
            for (iter = providers; iter; iter = g_list_next (iter))
            {
                cb_info_t *provider = iter->data;
                int len = strlen (search->path);
                char *ptr, *path = strdup (provider->path);
                if ((ptr = strchr (&path[len ? len : len+1], '/')) != 0)
                    *ptr = '\0';
                if (!g_list_find_custom (results, path, (GCompareFunc) strcmp))
                    results = g_list_append (results, path);
                else
                    free (path);
            }
            g_list_free_full (providers, (GDestroyNotify) cb_release);
        }
    }

    /* Prepare the results */
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

    /* Send result */
    closure (&result, closure_data);
    g_list_free_full (results, free);
    if (result.paths)
        free (result.paths);
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
    *paths = g_list_concat (*paths, children);
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

    /* Collect the list of deleted paths for notification */
    paths = g_list_append(paths, strdup(prune->path));
    _search_paths (&paths, prune->path);

    /* Prune from database */
    db_delete (prune->path);

    /* Return result */
    closure (&result, closure_data);

    /* Call watchers for each pruned path */
#ifdef USE_SHM_CACHE
    for (iter = paths; iter; iter = g_list_next (iter))
    {
        cache_set ((const char *) iter->data, NULL);
    }
#endif
    for (iter = paths; iter; iter = g_list_next (iter))
    {
        notify_watchers ((const char *) iter->data);
    }

    g_list_free_full (paths, free);
    return;
}

static void
apteryx__get_timestamp (Apteryx__Server_Service *service,
                        const Apteryx__Get *get,
                        Apteryx__GetTimeStampResult_Closure closure, void *closure_data)
{
    Apteryx__GetTimeStampResult result = APTERYX__GET_TIME_STAMP_RESULT__INIT;
    uint64_t value = 0;

    /* Check parameters */
    if (get == NULL || get->path == NULL)
    {
        ERROR ("GET: Invalid parameters.\n");
        closure (NULL, closure_data);
        INC_COUNTER (counters.get_ts_invalid);
        return;
    }
    INC_COUNTER (counters.get_ts);

    DEBUG ("GET: %s\n", get->path);

    /* Lookup value */
    value = db_get_timestamp (get->path);

    /* Send result */
    DEBUG ("     = %"PRIu64"\n", value);
    result.value = value;
    closure (&result, closure_data);
    return;
}

static Apteryx__Server_Service apteryx_service = APTERYX__SERVER__INIT (apteryx__);

void
termination_handler (void)
{
    uint8_t dummy = 1;
    running = false;
    if (write (stopfd, &dummy, 1) !=1)
        ERROR ("Failed to stop server %s\n", strerror (errno));
}

void
help (void)
{
    printf ("Usage: apteryxd [-h] [-b] [-d] [-p <pidfile>] [-l <url>]\n"
            "  -h   show this help\n"
            "  -b   background mode\n"
            "  -d   enable verbose debug\n"
            "  -p   use <pidfile> (defaults to "APTERYX_PID")\n"
            "  -l   listen on URL <url> (defaults to "APTERYX_SERVER")\n");
}

int
main (int argc, char **argv)
{
    const char *pid_file = APTERYX_PID;
    const char *url = APTERYX_SERVER;
    bool background = false;
    int pipefd[2];
    FILE *fp;
    int i;

    /* Parse options */
    while ((i = getopt (argc, argv, "hdbp:l:")) != -1)
    {
        switch (i)
        {
        case 'd':
            debug = true;
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

#ifdef USE_SHM_CACHE
    /* Init cache */
    cache_init ();
#endif

    /* Create a lock for currently-validating */
    pthread_mutex_init (&validating, NULL);

    /* Create fd to stop server */
    if (pipe (pipefd) != 0)
    {
        ERROR ("Failed to create pipe\n");
        goto exit;
    }
    stopfd = pipefd[1];

    /* Create server and process requests - 4 threads */
    if (!rpc_provide_service (url, (ProtobufCService *)&apteryx_service, 8, pipefd[0]))
    {
        ERROR ("Failed to start rpc service\n");
    }

exit:
    DEBUG ("Exiting\n");

    /* Close the pipe */
    close (pipefd[0]);
    close (pipefd[1]);

#ifdef USE_SHM_CACHE
    /* Shut cache */
    cache_shutdown (true);
#endif
    /* Cleanup callbacks */
    cb_shutdown ();
    /* Clean up the database */
    db_shutdown ();

    /* Remove the pid file */
    if (background)
        unlink (pid_file);

    return 0;
}
