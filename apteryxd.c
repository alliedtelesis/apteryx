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
        rpc_client rpc_client;
        rpc_message_t msg = {};

        /* Check for local provider */
        if (indexer->id == getpid ())
        {
            apteryx_index_callback cb = (apteryx_index_callback) (long) indexer->ref;
            DEBUG ("INDEX LOCAL \"%s\" (0x%"PRIx64",0x%"PRIx64")\n",
                    indexer->path, indexer->id, indexer->ref);
            results = cb (path);
            break;
        }

        DEBUG ("INDEX CB \"%s\" (0x%"PRIx64",0x%"PRIx64")\n",
                indexer->path, indexer->id, indexer->ref);

        /* Setup IPC */
        rpc_client = rpc_client_connect (rpc, indexer->uri);
        if (!rpc_client)
        {
            /* Throw away the no good validator */
            ERROR ("Invalid INDEX CB %s (0x%"PRIx64",0x%"PRIx64")\n",
                    indexer->path, indexer->id, indexer->ref);
            cb_destroy (indexer);
            INC_COUNTER (counters.indexed_no_handler);
            continue;
        }

        /* Do remote index */
        rpc_msg_encode_uint8 (&msg, MODE_INDEX);
        rpc_msg_encode_uint64 (&msg, indexer->ref);
        rpc_msg_encode_string (&msg, path);
        if (!rpc_msg_send (rpc_client, &msg))
        {
            ERROR ("INDEX: No response\n");
            rpc_msg_reset (&msg);
            rpc_client_release (rpc, rpc_client, false);
            INC_COUNTER (counters.indexed_timeout);
            continue;
        }
        while ((path = rpc_msg_decode_string (&msg)) != NULL)
        {
            results = g_list_prepend (results, (gpointer) strdup (path));
        }
        rpc_msg_reset (&msg);
        rpc_client_release (rpc, rpc_client, true);

        INC_COUNTER (counters.indexed);
        INC_COUNTER (indexer->count);

        if (results)
            break;
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
        rpc_client rpc_client;
        rpc_message_t msg = {};

        /* Check for local validator */
        if (validator->id == getpid ())
        {
            apteryx_watch_callback cb = (apteryx_watch_callback) (long) validator->ref;
            DEBUG ("VALIDATE LOCAL \"%s\" (0x%"PRIx64",0x%"PRIx64")\n",
                    validator->path, validator->id, validator->ref);
            cb (path, value);
            continue;
        }

        DEBUG ("VALIDATE CB %s = %s (0x%"PRIx64",0x%"PRIx64")\n",
                 validator->path, value, validator->id, validator->ref);

        /* Setup IPC */
        rpc_client = rpc_client_connect (rpc, validator->uri);
        if (!rpc_client)
        {
            /* Throw away the no good validator */
            ERROR ("Invalid VALIDATE CB %s (0x%"PRIx64",0x%"PRIx64")\n",
                    validator->path, validator->id, validator->ref);
            cb_destroy (validator);
            INC_COUNTER (counters.validated_no_handler);
            continue;
        }

        /* Do remote validate */
        rpc_msg_encode_uint8 (&msg, MODE_VALIDATE);
        rpc_msg_encode_uint64 (&msg, validator->ref);
        rpc_msg_encode_string (&msg, path);
        if (value)
            rpc_msg_encode_string (&msg, value);
        else
            rpc_msg_encode_string (&msg, "");
        if (!rpc_msg_send (rpc_client, &msg))
        {
            INC_COUNTER (counters.validated_timeout);
            ERROR ("Failed to validate for path \"%s\"\n", (char *)path);
            rpc_client_release (rpc, rpc_client, false);
            rpc_msg_reset (&msg);
            result = errno;
            break;
        }
        rpc_client_release (rpc, rpc_client, true);
        result = (int32_t) rpc_msg_decode_uint64 (&msg);
        rpc_msg_reset (&msg);
        INC_COUNTER (counters.validated);
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
notify_watchers (const char *path, bool ack)
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
        rpc_client rpc_client;
        rpc_message_t msg = {};

        /* Check for local watcher */
        if (watcher->id == getpid ())
        {
            apteryx_watch_callback cb = (apteryx_watch_callback) (long) watcher->ref;
            DEBUG ("WATCH LOCAL \"%s\" (0x%"PRIx64",0x%"PRIx64")\n",
                    watcher->path, watcher->id, watcher->ref);
            cb (path, value);
            continue;
        }

        DEBUG ("WATCH CB %s = %s (%s 0x%"PRIx64",0x%"PRIx64",%s)\n",
                path, value, watcher->path, watcher->id, watcher->ref, watcher->uri);

        /* IPC */
        rpc_client = rpc_client_connect (rpc, watcher->uri);
        if (!rpc_client)
        {
            /* Throw away the no good validator */
            ERROR ("Invalid WATCH CB %s (0x%"PRIx64",0x%"PRIx64")\n",
                   watcher->path, watcher->id, watcher->ref);
            cb_destroy (watcher);
            INC_COUNTER (counters.watched_no_handler);
            continue;
        }
        rpc_msg_encode_uint8 (&msg, ack ? MODE_WATCH_WITH_ACK : MODE_WATCH);
        rpc_msg_encode_uint64 (&msg, watcher->ref);
        rpc_msg_encode_string (&msg, path);
        if (value)
            rpc_msg_encode_string (&msg, value);
        else
            rpc_msg_encode_string (&msg, "");
        if (!rpc_msg_send (rpc_client, &msg))
        {
            INC_COUNTER (counters.watched_timeout);
            ERROR ("Failed to notify watcher for path \"%s\"\n", (char *)path);
            rpc_client_release (rpc, rpc_client, false);
        }
        else
        {
            rpc_client_release (rpc, rpc_client, true);
        }
        rpc_msg_reset (&msg);

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
        rpc_client rpc_client;
        rpc_message_t msg = {};

        /* Check for local provider */
        if (provider->id == getpid ())
        {
            apteryx_provide_callback cb = (apteryx_provide_callback) (long) provider->ref;
            DEBUG ("PROVIDE LOCAL \"%s\" (0x%"PRIx64",0x%"PRIx64")\n",
                                       provider->path, provider->id, provider->ref);
            value = cb (path);
            break;
        }

        DEBUG ("PROVIDE CB \"%s\" (0x%"PRIx64",0x%"PRIx64")\n",
               provider->path, provider->id, provider->ref);

        /* Setup IPC */
        rpc_client = rpc_client_connect (rpc, provider->uri);
        if (!rpc_client)
        {
            /* Throw away the no good validator */
            ERROR ("Invalid PROVIDE CB %s (0x%"PRIx64",0x%"PRIx64")\n",
                   provider->path, provider->id, provider->ref);
            cb_destroy (provider);
            INC_COUNTER (counters.provided_no_handler);
            continue;
        }

        /* Do remote get */
        rpc_msg_encode_uint8 (&msg, MODE_PROVIDE);
        rpc_msg_encode_uint64 (&msg, provider->ref);
        rpc_msg_encode_string (&msg, path);
        if (!rpc_msg_send (rpc_client, &msg))
        {
            INC_COUNTER (counters.provided_timeout);
            ERROR ("No response from provider for path \"%s\"\n", (char *)path);
            rpc_client_release (rpc, rpc_client, false);
        }
        else
        {
            rpc_client_release (rpc, rpc_client, true);
            value = rpc_msg_decode_string (&msg);
            if (value)
                value = strdup (value);
        }
        rpc_msg_reset (&msg);

        INC_COUNTER (counters.provided);
        INC_COUNTER (provider->count);
        if (value)
            break;
    }
    g_list_free_full (providers, (GDestroyNotify) cb_release);

    return value;
}

static void*
find_proxy (const char **path, cb_info_t **proxy_pt)
{
    rpc_client rpc_client;
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

static int32_t
proxy_set (const char *path, const char *value, uint64_t ts)
{
    rpc_client rpc_client;
    rpc_message_t msg = {};
    int32_t result = 1;
    cb_info_t *proxy = NULL;

    /* Find and connect to a proxied instance */
    rpc_client = find_proxy (&path, &proxy);
    if (!rpc_client)
    {
        /* A positive value is interpreted as proxy not found */
        return 1;
    }

    /* Do remote set */
    rpc_msg_encode_uint8 (&msg, MODE_SET);
    rpc_msg_encode_uint64 (&msg, ts);
    rpc_msg_encode_string (&msg, path);
    if (value)
        rpc_msg_encode_string (&msg, value);
    else
        rpc_msg_encode_string (&msg, "");
    if (!rpc_msg_send (rpc_client, &msg))
    {
        ERROR ("PROXY SET: No response\n");
        rpc_msg_reset (&msg);
        rpc_client_release (rpc, rpc_client, false);
    }
    else
    {
        result = rpc_msg_decode_uint64 (&msg);
        rpc_msg_reset (&msg);
        if (result < 0)
        {
            DEBUG ("PROXY SET: Error response: %s\n", strerror (-result));
            errno = result;
        }
        rpc_client_release (rpc, rpc_client, true);
    }
    return result;
}

static char *
proxy_get (const char *path)
{
    rpc_client rpc_client;
    rpc_message_t msg = {};
    cb_info_t *proxy = NULL;
    char *value = NULL;

    /* Find and connect to a proxied instance */
    rpc_client = find_proxy (&path, &proxy);
    if (!rpc_client)
        return NULL;

    /* Do remote get */
    rpc_msg_encode_uint8 (&msg, MODE_GET);
    rpc_msg_encode_string (&msg, path);
    if (!rpc_msg_send (rpc_client, &msg))
    {
        INC_COUNTER (counters.proxied_timeout);
        ERROR ("No response from proxy for path \"%s\"\n", (char *)path);
        rpc_client_release (rpc, rpc_client, false);
    }
    else
    {
        rpc_client_release (rpc, rpc_client, true);
        value = rpc_msg_decode_string (&msg);
        if (value)
            value = strdup (value);
    }
    rpc_msg_reset (&msg);

    return value;
}

static GList *
proxy_search (const char *path)
{
    rpc_client rpc_client;
    rpc_message_t msg = {};
    GList *paths = NULL;
    const char *in_path = path;
    cb_info_t *proxy = NULL;

    /* Find and connect to a proxied instance */
    rpc_client = find_proxy (&path, &proxy);
    if (!rpc_client)
        return NULL;

    /* Do remote search */
    rpc_msg_encode_uint8 (&msg, MODE_SEARCH);
    rpc_msg_encode_string (&msg, path);
    if (!rpc_msg_send (rpc_client, &msg))
    {
        INC_COUNTER (counters.proxied_timeout);
        ERROR ("No response from proxy for path \"%s\"\n", (char *)path);
        rpc_client_release (rpc, rpc_client, false);
    }
    else
    {
        /* Prepend local path to start of all search results */
        size_t path_len = path - in_path;
        char *local_path = g_malloc0 (path_len + 1);
        strncpy (local_path, in_path, path_len);
        while ((path = rpc_msg_decode_string (&msg)) != NULL)
        {
            char *tmp = g_strdup_printf ("%s%s", local_path, path);
            paths = g_list_prepend (paths, (gpointer) tmp);
        }
        g_free (local_path);
        rpc_client_release (rpc, rpc_client, true);
    }
    rpc_msg_reset (&msg);

    return paths;
}

static bool
proxy_traverse (GList **paths, GList **values, const char *path)
{
    rpc_client rpc_client;
    rpc_message_t msg = {};
    const char *in_path = path;
    int slen;
    char *value;

    cb_info_t *proxy = NULL;

    /* Find and connect to a proxied instance */
    rpc_client = find_proxy (&path, &proxy);
    if (!rpc_client)
        return false;
    slen = strlen (path);

    /* Do remote traverse */
    rpc_msg_encode_uint8 (&msg, MODE_TRAVERSE);
    rpc_msg_encode_string (&msg, path);
    if (!rpc_msg_send (rpc_client, &msg))
    {
        INC_COUNTER (counters.proxied_timeout);
        ERROR ("No response from proxy for path \"%s\"\n", (char *)path);
        rpc_msg_reset (&msg);
        rpc_client_release (rpc, rpc_client, false);
        return false;
    }
    path = rpc_msg_decode_string (&msg);
    if (path)
    {
        while (path)
        {
            value = rpc_msg_decode_string (&msg);
            *paths = g_list_prepend (*paths, (gpointer) g_strconcat (in_path, path + slen, NULL));
            *values = g_list_prepend (*values, (gpointer) g_strdup (value));
            path = rpc_msg_decode_string (&msg);
        }
    }
    else
    {
        DEBUG ("(P)  = (null)\n");
    }
    rpc_msg_reset (&msg);
    rpc_client_release (rpc, rpc_client, true);

    return true;
}

static int32_t
proxy_prune (const char *path)
{
    rpc_client rpc_client;
    rpc_message_t msg = {};
    cb_info_t *proxy = NULL;
    int32_t result = 0;

    /* Find and connect to a proxied instance */
    rpc_client = find_proxy (&path, &proxy);
    if (!rpc_client)
        return 1;

    /* Do remote prune */
    rpc_msg_encode_uint8 (&msg, MODE_PRUNE);
    rpc_msg_encode_string (&msg, path);
    if (!rpc_msg_send (rpc_client, &msg))
    {
        ERROR ("PROXY PRUNE: No response\n");
        rpc_msg_reset (&msg);
        rpc_client_release (rpc, rpc_client, false);
        return -ETIMEDOUT;
    }
    result = rpc_msg_decode_uint64 (&msg);
    rpc_msg_reset (&msg);
    if (result < 0)
    {
        DEBUG ("PROXY PRUNE: Error response: %s\n", strerror (-result));
    }
    rpc_client_release (rpc, rpc_client, true);
    return result;
}

static uint64_t
proxy_timestamp (const char *path)
{
    rpc_client rpc_client;
    rpc_message_t msg = {};
    uint64_t value = 0;
    cb_info_t *proxy = NULL;

    /* Find and connect to a proxied instance */
    rpc_client = find_proxy (&path, &proxy);
    if (!rpc_client)
        return 0;

    /* Do remote timestamp */
    rpc_msg_encode_uint8 (&msg, MODE_TIMESTAMP);
    rpc_msg_encode_string (&msg, path);
    if (!rpc_msg_send (rpc_client, &msg))
    {
        INC_COUNTER (counters.proxied_timeout);
        ERROR ("No response from proxy for path \"%s\"\n", (char *)path);
        rpc_client_release (rpc, rpc_client, false);
        return value;
    }
    value = rpc_msg_decode_uint64 (&msg);
    rpc_msg_reset (&msg);
    rpc_client_release (rpc, rpc_client, true);
    return value;
}

static bool
handle_set (rpc_message msg, bool ack)
{
    int result = 0;
    uint64_t ts = 0;
    GList *paths = NULL;
    GList *ipath;
    char *path;
    GList *values = NULL;
    GList *ivalue;
    char *value;
    int proxy_result = 0;
    int validation_result = 0;
    int validation_lock = 0;
    bool db_result = false;

    /* Parse the parameters */
    ts = rpc_msg_decode_uint64 (msg);
    while ((path = rpc_msg_decode_string (msg)) != NULL)
    {
        value = rpc_msg_decode_string (msg);
        DEBUG ("SET: %s = %s\n", path, value);
        paths = g_list_prepend (paths, path);
        values = g_list_prepend (values, value);
    }
    paths = g_list_reverse (paths);
    values = g_list_reverse (values);
    INC_COUNTER (counters.set);

    /* Proxy first */
    for (ipath = g_list_first (paths), ivalue = g_list_first (values);
         ipath && ivalue; ipath = g_list_next (ipath), ivalue = g_list_next (ivalue))
    {
        path = (char *) ipath->data;
        value = (char *) ivalue->data;
        if (value && value[0] == '\0')
            value = NULL;

        proxy_result = proxy_set (path, value, ts);
        if (proxy_result == 0)
        {
            /*  Result success */
            DEBUG ("SET: %s = %s proxied\n", path, value);
            /* Mark the set as processed */
            notify_watchers (path, ack);
            ipath->data = NULL;
        }
        else if (proxy_result < 0)
        {
            result = proxy_result;
            goto exit;
        }
    }

    /* Validate */
    for (ipath = g_list_first (paths), ivalue = g_list_first (values);
         ipath && ivalue; ipath = g_list_next (ipath), ivalue = g_list_next (ivalue))
    {
        path = (char *) ipath->data;
        if (!path)
            continue;
        value = (char *) ivalue->data;
        if (value && value[0] == '\0')
            value = NULL;

        /* Validate new data */
        validation_result = validate_set (path, value);
        if (validation_result != 0)
            validation_lock++;
        if (validation_result < 0)
        {
            DEBUG ("SET: %s = %s refused by validate\n", path, value);
            result = validation_result;
            goto exit;
        }
    }

    /* Set in the database */
    pthread_rwlock_wrlock (&db_lock);
    for (ipath = g_list_first (paths), ivalue = g_list_first (values);
         ipath && ivalue; ipath = g_list_next (ipath), ivalue = g_list_next (ivalue))
    {
        path = (char *) ipath->data;
        if (!path)
            continue;
        value = (char *) ivalue->data;
        if (value && value[0] == '\0')
            value = NULL;

        /* Add/Delete to/from database */
        if (value)
            db_result = db_add_no_lock (path, (unsigned char*)value, strlen (value) + 1, ts);
        else
            db_result = db_delete_no_lock (path, ts);
        if (!db_result)
        {
            DEBUG ("SET: %s = %s refused by DB\n", path, value);
            result = -EBUSY;
            pthread_rwlock_unlock (&db_lock);
            goto exit;
        }
    }
    pthread_rwlock_unlock (&db_lock);

exit:
    /* Return result and notify watchers */
    if (validation_result >= 0 && result == 0)
    {
        /* Notify watchers */
        for (ipath = g_list_first (paths), ivalue = g_list_first (values);
             ipath && ivalue; ipath = g_list_next (ipath), ivalue = g_list_next (ivalue))
        {
            path = (char *) ipath->data;
            if (path)
                notify_watchers (path, ack);
        }
    }

    /* Release validation lock - this is a sensitive value */
    while (validation_lock)
    {
        DEBUG("SET: unlocking mutex\n");
        pthread_mutex_unlock (&validating);
        validation_lock--;
    }

    /* Send result */
    rpc_msg_reset (msg);
    rpc_msg_encode_uint64 (msg, result);
    g_list_free (paths);
    g_list_free (values);
    return true;
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

static bool
handle_get (rpc_message msg)
{
    const char *path;
    char *value = NULL;

    /* Parse the parameters */
    path = rpc_msg_decode_string (msg);
    if (path == NULL)
    {
        ERROR ("GET: Invalid parameters.\n");
        INC_COUNTER (counters.get_invalid);
        rpc_msg_reset (msg);
        return false;
    }
    INC_COUNTER (counters.get);

    DEBUG ("GET: %s\n", path);

    /* Lookup value */
    value = get_value (path);

    /* Send result */
    DEBUG ("     = %s\n", value);
    rpc_msg_reset (msg);
    if (value)
    {
        rpc_msg_encode_string (msg, value);
        g_free (value);
    }
    return true;
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

static bool
handle_search (rpc_message msg)
{
    const char *path;
    GList *results = NULL;
    GList *iter = NULL;

    /* Check parameters */
    path = rpc_msg_decode_string (msg);
    if (path == NULL)
    {
        ERROR ("SEARCH: Invalid parameters.\n");
        INC_COUNTER (counters.search_invalid);
        rpc_msg_reset (msg);
        return false;
    }
    INC_COUNTER (counters.search);

    DEBUG ("SEARCH: %s\n", path);

    results = search_path (path);

    /* Prepare the results */
    rpc_msg_reset (msg);
    for (iter = results; iter; iter = g_list_next (iter))
    {
        DEBUG ("         = %s\n", (char *) iter->data);
        rpc_msg_encode_string (msg, (char *)iter->data);
    }
    g_list_free_full (results, g_free);
    return true;
}

static bool
handle_find (rpc_message msg)
{
    const char *rpath;
    GList *paths = NULL;
    GList *ipath;
    char *path;
    GList *values = NULL;
    GList *ivalue;
    char *value;
    GList *possible_matches = NULL;
    GList *iter = NULL;
    char *tmp = NULL;
    char *ptr = NULL;
    char *chunk;
    GList *matches = NULL;

    /* Parse the parameters */
    rpath = rpc_msg_decode_string (msg);
    if (rpath == NULL)
    {
        ERROR ("FIND: Invalid parameters.\n");
        INC_COUNTER (counters.find_invalid);
        rpc_msg_reset (msg);
        return false;
    }
    while ((path = rpc_msg_decode_string (msg)) != NULL)
    {
        value = rpc_msg_decode_string (msg);
        DEBUG ("FIND: %s = %s\n", path, value);
        paths = g_list_prepend (paths, path);
        values = g_list_prepend (values, value);
    }
    paths = g_list_reverse (paths);
    values = g_list_reverse (values);
    INC_COUNTER (counters.find);

    /* Grab first level (from root) */
    tmp = g_strdup (rpath);
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
        for (ipath = g_list_first (paths), ivalue = g_list_first (values);
             ipath && ivalue && possible_match;
             ipath = g_list_next (ipath), ivalue = g_list_next (ivalue))
        {
            char *key = NULL;
            char *value = NULL;

            key = g_strdup_printf("%s%s", (char*)iter->data,
                              strrchr (ipath->data, '*') + 1);
            value = get_value (key);


            /* A "" value on a match maps to no return value from provider / database */
            if (strlen (ivalue->data) == 0 && value == NULL)
            {
                possible_match = true;
            }
            else if ((strlen (ivalue->data) == 0 && value != NULL) ||
                    (value == NULL && strlen (ivalue->data) > 0))
            {
                /* Match miss - we can stop checking */
                possible_match = false;
            }
            else if (strcmp (value, ivalue->data) != 0)
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
    rpc_msg_reset (msg);
    if (g_list_length (matches) > 0)
    {
        for (iter = matches; iter; iter = g_list_next (iter))
        {
            DEBUG ("         = %s\n", (char *) iter->data);
            rpc_msg_encode_string (msg, (char *)iter->data);
        }
    }
    else
    {
        DEBUG ("         NONE\n");
    }

    /* Cleanup */
    g_free (tmp);
    g_list_free_full (matches, g_free);
    g_list_free (paths);
    g_list_free (values);
    return true;
}

static void
_traverse_paths (GList **paths, GList **values, const char *path)
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
        *paths = g_list_prepend (*paths, (gpointer) g_strdup (path));
        *values = g_list_prepend (*values, (gpointer) value);
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
        _traverse_paths (paths, values, (const char *) iter->data);
    }
    g_list_free_full (children, g_free);
    g_free (path_s);
}

static bool
handle_traverse (rpc_message msg)
{
    const char *path;
    const char *value;
    GList *paths = NULL;
    GList *ipath;
    GList *values = NULL;
    GList *ivalue;

    /* Parse the parameters */
    path = rpc_msg_decode_string (msg);
    if (path == NULL)
    {
        ERROR ("TRAVERSE: Invalid parameters.\n");
        INC_COUNTER (counters.traverse_invalid);
        rpc_msg_reset (msg);
        return false;
    }
    INC_COUNTER (counters.traverse);

    DEBUG ("TRAVERSE: %s\n", path);

    /* Proxy first */
    if (!proxy_traverse (&paths, &values, path))
    {
        /* Traverse (local) paths */
        _traverse_paths (&paths, &values, path);
    }
    paths = g_list_reverse (paths);
    values = g_list_reverse (values);

    /* Send result */
    rpc_msg_reset (msg);
    for (ipath = g_list_first (paths), ivalue = g_list_first (values);
         ipath && ivalue; ipath = g_list_next (ipath), ivalue = g_list_next (ivalue))
    {
        path = (char *) ipath->data;
        value = (char *) ivalue->data;
        DEBUG ("  %s = %s\n", path, value);
        rpc_msg_encode_string (msg, path);
        rpc_msg_encode_string (msg, value);
    }
    g_list_free_full (paths, g_free);
    g_list_free_full (values, g_free);

    return true;
}

static void
_search_paths (GList **paths, const char *path)
{
    GList *children, *iter;
    char *value = NULL;
    size_t vsize = 0;

    children = db_search (path);
    for (iter = children; iter; iter = g_list_next (iter))
    {
        const char *_path = (const char *) iter->data;
        if (db_get (_path, (unsigned char**) &value, &vsize))
        {
            *paths = g_list_prepend (*paths, g_strdup (_path));
            g_free (value);
        }
        _search_paths (paths, _path);
    }
    g_list_free_full (children, g_free);
}

static bool
handle_prune (rpc_message msg)
{
    int32_t result = 0;
    const char *path;
    GList *paths = NULL, *iter;
    int32_t validation_result = 0;
    int validation_lock = 0;
    char *value = NULL;
    size_t vsize = 0;

    /* Parse the parameters */
    path = rpc_msg_decode_string (msg);
    if (path == NULL)
    {
        ERROR ("PRUNE: Invalid parameters.\n");
        INC_COUNTER (counters.prune_invalid);
        rpc_msg_reset (msg);
        return false;
    }
    INC_COUNTER (counters.prune);

    DEBUG ("PRUNE: %s\n", path);

    /* Proxy first */
    result = proxy_prune (path);
    if (result <= 0)
    {
        /* Return result */
        rpc_msg_reset (msg);
        rpc_msg_encode_uint64 (msg, (uint64_t) result);
        return true;
    }
    result = 0;

    /* Collect the list of deleted paths for notification */
    if (db_get (path, (unsigned char**)&value, &vsize))
    {
        paths = g_list_prepend (paths, g_strdup (path));
        g_free (value);
    }
    _search_paths (&paths, path);

    /* Call validators for each pruned path to ensure the path can be set to NULL. */
    for (iter = paths; iter; iter = g_list_next (iter))
    {
        const char *path = (const char *)iter->data;
        validation_result = validate_set (path, NULL);
        if (validation_result != 0)
            validation_lock++;
        if (validation_result < 0)
        {
            DEBUG ("PRUNE: %s refused by validate\n", path);
            result = validation_result;
            break;
        }
    }

    /* Only do the prune if it is valid to do so. */
    if (validation_result >= 0)
    {
        /* Prune from database */
        db_delete (path, UINT64_MAX);
    }

    if (validation_result >= 0)
    {
        /* Call watchers for each pruned path */
        for (iter = paths; iter; iter = g_list_next (iter))
        {
            notify_watchers ((const char *)iter->data, false);
        }
    }

    /* Release validation lock - this is a sensitive value */
    while (validation_lock)
    {
        DEBUG("PRUNE: unlocking mutex\n");
        pthread_mutex_unlock (&validating);
        validation_lock--;
    }

    rpc_msg_reset (msg);
    rpc_msg_encode_uint64 (msg, (uint64_t) result);
    g_list_free_full (paths, g_free);
    return true;
}

static bool
handle_timestamp (rpc_message msg)
{
    uint64_t value;
    const char *path;

    /* Parse the parameters */
    path = rpc_msg_decode_string (msg);
    if (path == NULL)
    {
        ERROR ("TIMESTAMP: Invalid parameters.\n");
        INC_COUNTER (counters.timestamp_invalid);
        return false;
    }

    DEBUG ("TIMESTAMP: %s\n", path);
    INC_COUNTER (counters.timestamp);

    /* Proxy first */
    if ((value = proxy_timestamp (path)) == 0)
    {
        /* Lookup value */
        value = db_timestamp (path);
    }

    /* Send result */
    DEBUG ("     = %"PRIu64"\n", value);
    rpc_msg_reset (msg);
    rpc_msg_encode_uint64 (msg, value);
    return true;
}

static bool
msg_handler (rpc_message msg)
{
    APTERYX_MODE mode = rpc_msg_decode_uint8 (msg);
    switch (mode)
    {
    case MODE_SET_WITH_ACK:
        return handle_set (msg, true);
    case MODE_SET:
        return handle_set (msg, false);
    case MODE_GET:
        return handle_get (msg);
    case MODE_SEARCH:
        return handle_search (msg);
    case MODE_FIND:
        return handle_find (msg);
    case MODE_TRAVERSE:
        return handle_traverse (msg);
    case MODE_PRUNE:
        return handle_prune (msg);
    case MODE_TIMESTAMP:
        return handle_timestamp (msg);
    default:
        ERROR ("MSG: Unexpected mode %d\n", mode);
        break;
    }
    return false;
}

void
termination_handler (void)
{
    running = false;
}

void
help (void)
{
    printf ("Usage: apteryxd [-h] [-b] [-d] [-p <pidfile>] [-r <runfile>] [-l <url>]\n"
            "  -h   show this help\n"
            "  -b   background mode\n"
            "  -d   enable verbose debug\n"
            "  -p   use <pidfile> (background mode only)\n"
            "  -r   use <runfile>\n"
            "  -l   listen on URL <url> (defaults to "APTERYX_SERVER")\n");
}

int
main (int argc, char **argv)
{
    const char *pid_file = NULL;
    const char *run_file = NULL;
    const char *url = APTERYX_SERVER;
    bool background = false;
    pthread_mutexattr_t callback_recursive;
    FILE *fp;
    int i;

    /* Parse options */
    while ((i = getopt (argc, argv, "hdbp:r:l:")) != -1)
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
        case 'r':
            run_file = optarg;
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
    if (background && pid_file)
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
    rpc = rpc_init (RPC_TIMEOUT_US, msg_handler);
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
    proxy_rpc = rpc_init (RPC_TIMEOUT_US, NULL);
    if (proxy_rpc == NULL)
    {
        ERROR ("Failed to initialise proxy RPC service\n");
        goto exit;
    }

    /* Create run file */
    if (run_file)
    {
        fp = fopen (run_file, "w");
        if (!fp)
        {
            ERROR ("Failed to create RUN file %s\n", run_file);
            goto exit;
        }
        fclose (fp);
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
    if (background && pid_file)
        unlink (pid_file);

    /* Remove the run file */
    if (run_file)
        unlink (run_file);

    return 0;
}
