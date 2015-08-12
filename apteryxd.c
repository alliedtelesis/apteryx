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
        ERROR ("SEARCH: Error processing request.\n");
    }
    else if (result->paths == NULL)
    {
        DEBUG ("    = (null)\n");
    }
    else if (result->n_paths != 0)
    {
        for (i = 0; i < result->n_paths; i++)
        {
            data->paths = g_list_append (data->paths,
                              (gpointer) strdup (result->paths[i]));
        }
    }
    data->done = true;
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
    }
    *data = result->value;
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
handle_watch_response (const Apteryx__OKResult *result, void *closure_data)
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
        rpc_client = rpc_connect_service_sock (indexer->sock, &apteryx__client__descriptor);
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
        rpc_connect_deref (rpc_client);

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
        rpc_client = rpc_connect_service_sock (validator->sock, &apteryx__client__descriptor);
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
        /* Destroy the service */
        rpc_connect_deref (rpc_client);
        if (result < 0)
        {
            DEBUG ("Set of %s to %s rejected by process %"PRIu64" (%d)\n",
                    (char *)path, (char*)value, validator->id, result);
            INC_COUNTER (counters.validated_timeout);
            break;
        }

        INC_COUNTER (counters.validated);
    }
    g_list_free_full (validators, (GDestroyNotify) cb_release);

    /* This one is fine, but lock is still held */
    return result < 0 ? result : 1;
}

static void
notify_watchers (const char *path, rpc_socket sock)
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

        /* Check for local watcher */
        if (watcher->id == getpid ())
        {
            apteryx_internal_watch_callback cb = (apteryx_internal_watch_callback) (long) watcher->cb;
            DEBUG ("WATCH LOCAL \"%s\" (0x%"PRIx64",0x%"PRIx64")\n",
                    watcher->path, watcher->id, watcher->cb);
            cb (path, value, sock);
            continue;
        }

        DEBUG ("WATCH CB %s = %s (%s 0x%"PRIx64",0x%"PRIx64")\n",
                path, value, watcher->path, watcher->id, watcher->cb);

        /* Setup IPC */
        rpc_client = rpc_connect_service_sock (watcher->sock, &apteryx__client__descriptor);
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
        rpc_connect_deref (rpc_client);
        INC_COUNTER (counters.watched);
        INC_COUNTER (watcher->count);
    }
    g_list_free_full (watchers, (GDestroyNotify) cb_release);

    /* Free memory if allocated */
    if (value)
        free (value);
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
        rpc_client = rpc_connect_service_sock (provider->sock, &apteryx__client__descriptor);
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
        rpc_connect_deref (rpc_client);

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
find_proxy (const char **path)
{
    ProtobufCService *rpc_client = NULL;
    GList *proxies = NULL;
    GList *iter = NULL;

    /* Retrieve a list of proxies for this path */
    proxies = cb_match (&proxy_list, *path,
            CB_MATCH_EXACT|CB_MATCH_WILD|CB_MATCH_CHILD);
    if (!proxies)
        return 0;

    /* Find the first good proxy */
    for (iter = proxies; iter; iter = g_list_next (iter))
    {
        cb_info_t *proxy = iter->data;
        int len = strlen (proxy->path);

        /* Setup IPC */
        rpc_client = rpc_connect_service (proxy->uri, &apteryx__server__descriptor, NULL);
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
        break;
    }
    g_list_free_full (proxies, (GDestroyNotify) cb_release);
    return rpc_client;
}

static int
proxy_set (const char *path, const char *value)
{
    ProtobufCService *rpc_client;
    Apteryx__Set set = APTERYX__SET__INIT;
    Apteryx__PathValue _pv = APTERYX__PATH_VALUE__INIT;
    Apteryx__PathValue *pv[1] = {&_pv};
    int result = 1;

    /* Find and connect to a proxied instance */
    rpc_client = find_proxy (&path);
    if (!rpc_client)
        return 1;

    /* Do remote set */
    pv[0]->path = (char *) path;
    pv[0]->value = (char *) value;
    set.n_sets = 1;
    set.sets = pv;
    apteryx__server__set (rpc_client, &set, handle_set_response, &result);

    /* Destroy the service */
    rpc_connect_deref (rpc_client);

    return result;
}

static char *
proxy_get (const char *path)
{
    ProtobufCService *rpc_client;
    Apteryx__Get get = APTERYX__GET__INIT;
    get_data_t data = {0};

    /* Find and connect to a proxied instance */
    rpc_client = find_proxy (&path);
    if (!rpc_client)
        return NULL;

    /* Do remote get */
    get.path = (char *) path;
    apteryx__server__get (rpc_client, &get, handle_get_response, &data);
    if (!data.done)
    {
        INC_COUNTER (counters.proxied_timeout);
        ERROR ("No response from proxy for path \"%s\"\n", (char *)path);
    }

    /* Destroy the service */
    rpc_connect_deref (rpc_client);

    return data.value;
}

static GList *
proxy_search (const char *path)
{
    const char *in_path = path;
    ProtobufCService *rpc_client;
    Apteryx__Search search = APTERYX__SEARCH__INIT;
    search_data_t data = {0};

    /* Find and connect to a proxied instance */
    rpc_client = find_proxy (&path);
    if (!rpc_client)
        return NULL;

    /* Do remote search */
    search.path = (char *) path;
    apteryx__server__search (rpc_client, &search, handle_search_response, &data);
    if (!data.done)
    {
        INC_COUNTER (counters.proxied_timeout);
        ERROR ("No response from proxy for path \"%s\"\n", (char *)path);
    }
    else
    {
        /* Prepend local path to start of all search results */
        size_t path_len = path - in_path;
        char *local_path = calloc (path_len + 1, sizeof (char));
        strncpy (local_path, in_path, path_len);
        GList *itr = data.paths;
        for (; itr; itr = itr->next)
        {
            char *tmp = NULL;
            if (asprintf (&tmp, "%s%s", local_path, (char *)itr->data) >= 0)
            {
                free (itr->data);
                itr->data = tmp;
            }
        }
        free (local_path);
    }

    /* Destroy the service */
    rpc_connect_deref (rpc_client);

    return data.paths;
}

static int
proxy_prune (const char *path)
{
    ProtobufCService *rpc_client;
    Apteryx__Prune prune = APTERYX__PRUNE__INIT;
    protobuf_c_boolean is_done = 0;

    /* Find and connect to a proxied instance */
    rpc_client = find_proxy (&path);
    if (!rpc_client)
        return false;

    /* Do remote prune */
    prune.path = (char *) path;
    apteryx__server__prune (rpc_client, &prune, handle_ok_response, &is_done);
    rpc_connect_deref (rpc_client);
    if (!is_done)
    {
        ERROR ("PRUNE: No response\n");
        return false;
    }

    return true;
}

static uint64_t
proxy_timestamp (const char *path)
{
    ProtobufCService *rpc_client;
    Apteryx__Get get = APTERYX__GET__INIT;
    uint64_t value = 0;

    /* Find and connect to a proxied instance */
    rpc_client = find_proxy (&path);
    if (!rpc_client)
        return 0;

    /* Do remote timestamp */
    get.path = (char *) path;
    apteryx__server__timestamp (rpc_client, &get, handle_timestamp_response, &value);
    if (!value)
    {
        INC_COUNTER (counters.proxied_timeout);
        ERROR ("No response from proxy for path \"%s\"\n", (char *)path);
    }

    /* Destroy the service */
    rpc_connect_deref (rpc_client);

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
    int proxy_result = 0;
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

    /* For each Path Value in the set */
    for (i=0; i<set->n_sets; i++)
    {
        path = set->sets[i]->path;
        value = set->sets[i]->value;
        if (value && value[0] == '\0')
            value = NULL;

        DEBUG ("SET: %s = %s\n", path, value);

        /* Check proxy first */
        proxy_result = proxy_set (path, value);
        if (proxy_result <= 0)
        {
            DEBUG ("SET: %s = %s proxied (result=%d)\n",
                    path, value, proxy_result);
            result.result = proxy_result;
            goto exit;
        }

        /* Validate new data */
        validation_result = validate_set (path, value);
        if (validation_result < 0)
        {
            DEBUG ("SET: %s = %s refused by validate\n", path, value);
            result.result = validation_result;
            goto exit;
        }

        /* Add/Delete to/from database */
        if (value)
            db_add (path, (unsigned char*)value, strlen (value) + 1);
        else
            db_delete (path);
    }

    /* Set succeeded */
    result.result = 0;

exit:
    /* Return result */
    closure (&result, closure_data);

    if (validation_result >= 0)
    {
        /* Notify watchers for each Path Value in the set*/
        for (i=0; i<set->n_sets; i++)
        {
            notify_watchers (set->sets[i]->path, rpc_socket_current ());
        }
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

    /* Proxy first */
    results = proxy_search (search->path);
    if (!results)
    {
        /* Indexers second */
        if (index_get (search->path, &results) == true)
        {
            DEBUG (" (index result:)\n");
        }
        else
        {
            /* Search database next */
            results = db_search (search->path);

            /* Append any provided paths */
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

    /* Proxy first */
    if (proxy_prune (prune->path))
    {
        /* Return result */
        closure (&result, closure_data);
        return;
    }

    /* Collect the list of deleted paths for notification */
    paths = g_list_append(paths, strdup(prune->path));
    _search_paths (&paths, prune->path);

    /* Prune from database */
    db_delete (prune->path);

    /* Return result */
    closure (&result, closure_data);

    /* Call watchers for each pruned path */
    for (iter = paths; iter; iter = g_list_next (iter))
    {
        notify_watchers ((const char *)iter->data, rpc_socket_current ());
    }

    g_list_free_full (paths, free);
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

    /* Create a lock for currently-validating */
    pthread_mutex_init (&validating, NULL);

    /* Init the RPC */
    rpc_init ();

    /* Create fd to stop server */
    if (pipe (pipefd) != 0)
    {
        ERROR ("Failed to create pipe\n");
        goto exit;
    }
    stopfd = pipefd[1];

    /* Create server and process requests */
    if (!rpc_provide_service (url, (ProtobufCService *)&apteryx_service, pipefd[0]))
    {
        ERROR ("Failed to start rpc service\n");
    }

exit:
    DEBUG ("Exiting\n");

    /* Close the pipe */
    close (pipefd[0]);
    close (pipefd[1]);

    /* Cleanup callbacks */
    cb_shutdown ();
    /* Clean up the database */
    db_shutdown ();

    /* Remove the pid file */
    if (background)
        unlink (pid_file);

    return 0;
}
