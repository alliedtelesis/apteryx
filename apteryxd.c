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
#include <sys/wait.h>
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
    indexers = config_get_indexers (path);
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
            cb_disable (indexer);
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

        /* Result */
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
    validators = config_get_validators (path);
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
            cb_disable (validator);
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
    watchers = config_get_watchers (path);
    if (!watchers)
        return;

    /* Find the new value for this path */
    value = NULL;
    vsize = 0;
    db_get (path, (unsigned char **) &value, &vsize);

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
            cb_disable (watcher);
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
            ERROR ("Failed to notify watcher for path \"%s\"\n", (char *) path);
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

static uint64_t
calculate_timestamp (void)
{
    struct timespec tms;
    uint64_t micros = 0;
    if (clock_gettime(CLOCK_MONOTONIC_RAW, &tms)) {
        return 0;
    }

    micros = ((uint64_t)tms.tv_sec) * 1000000;
    micros += tms.tv_nsec/1000;
    return micros;
}

static void
call_refreshers (const char *path)
{
    GList *refreshers = NULL;
    GList *iter = NULL;
    uint64_t timestamp;
    uint64_t now;
    uint64_t timeout = 0;

    /* Retrieve a list of refreshers for this path */
    refreshers = config_get_refreshers (path);
    if (!refreshers)
        return;

    /* Get the time of the request */
    now = calculate_timestamp ();
    /* Get the latest timestamp for the path */
    timestamp = db_timestamp (path);

    /* Call each refresher */
    for (iter = refreshers; iter; iter = g_list_next (iter))
    {
        cb_info_t *refresher = iter->data;
        rpc_client rpc_client;
        rpc_message_t msg = {};

        if (pthread_mutex_trylock (&refresher->lock))
        {
            /* If this refresher was being called when we came in, take the lock once
             * the last call has finished, and get the new timestamp.
             */
            pthread_mutex_lock (&refresher->lock);
            timestamp = db_timestamp (path);
        }

        /* Check if it is time to refresh */
        if (now < (timestamp + refresher->timeout))
        {
            DEBUG ("Not refreshing %s (now:%"PRIu64" < (ts:%"PRIu64" + to:%"PRIu64"))\n",
                   path, now, timestamp, refresher->timeout);
            goto unlock;
        }
        DEBUG ("Refreshing %s (now:%"PRIu64" >= (ts:%"PRIu64" + to:%"PRIu64"))\n",
               path, now, timestamp, refresher->timeout);

        /* Check for local refresher */
        if (refresher->id == getpid ())
        {
            apteryx_refresh_callback cb = (apteryx_refresh_callback) (long) refresher->ref;
            DEBUG ("REFRESH LOCAL \"%s\" (0x%"PRIx64",0x%"PRIx64")\n",
                    refresher->path, refresher->id, refresher->ref);
            timeout = cb (path);
            if (refresher->timeout == 0 || timeout < refresher->timeout)
                refresher->timeout = timeout;
            goto unlock;
        }

        DEBUG ("REFRESH CB %s (%s 0x%"PRIx64",0x%"PRIx64",%s)\n",
                path, refresher->path, refresher->id, refresher->ref, refresher->uri);

        /* IPC */
        rpc_client = rpc_client_connect (rpc, refresher->uri);
        if (!rpc_client)
        {
            /* Throw away the no good validator */
            ERROR ("Invalid REFRESH CB %s (0x%"PRIx64",0x%"PRIx64")\n",
                   refresher->path, refresher->id, refresher->ref);
            cb_disable (refresher);
            INC_COUNTER (counters.refreshed_no_handler);
            goto unlock;
        }
        rpc_msg_encode_uint8 (&msg, MODE_REFRESH);
        rpc_msg_encode_uint64 (&msg, refresher->ref);
        rpc_msg_encode_string (&msg, path);
        if (!rpc_msg_send (rpc_client, &msg))
        {
            INC_COUNTER (counters.refreshed_timeout);
            ERROR ("Failed to notify refresher for path \"%s\"\n", (char *) path);
            rpc_client_release (rpc, rpc_client, false);
        }
        else
        {
            rpc_client_release (rpc, rpc_client, true);
            timeout = rpc_msg_decode_uint64 (&msg);
            DEBUG ("REFRESH again in %"PRIu64"us\n", timeout);
            if (refresher->timeout == 0 || timeout < refresher->timeout)
                refresher->timeout = timeout;
            /* Make sure the DB has up to date timestamps */
            db_update_timestamps (path, now);
        }
        rpc_msg_reset (&msg);

        INC_COUNTER (counters.refreshed);
        INC_COUNTER (refresher->count);
    unlock:
        pthread_mutex_unlock (&refresher->lock);
    }
    g_list_free_full (refreshers, (GDestroyNotify) cb_release);
}

static char *
provide_get (const char *path)
{
    GList *providers = NULL;
    char *value = NULL;
    GList *iter = NULL;

    /* Retrieve a list of providers for this path */
    providers = config_get_providers (path);
    if (!providers)
        return NULL;

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
            cb_disable (provider);
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
    proxies = config_get_proxies (*path);
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
            cb_disable (proxy);
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
        /* Call refreshers */
        call_refreshers (path);

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
    GList *iter;

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
            /* Call refreshers */
            call_refreshers (path);

            /* Search database next */
            results = db_search (path);
            DEBUG (" Got %d entries from database...\n", g_list_length (results));
            /* Append any provided or refreshed paths */
            GList *callbacks = NULL;
            callbacks = config_search_providers (path);
            callbacks = g_list_concat (config_search_refreshers (path), callbacks);
            DEBUG (" Got %d entries from providers and refreshers...\n", g_list_length (callbacks));
            for (iter = callbacks; iter; iter = iter->next)
            {
                char *p = (char*)iter->data;
                if (!g_list_find_custom (results, p, (GCompareFunc)strcmp))
                    results = g_list_prepend (results, strdup (p));
            }
            g_list_free_full (callbacks, free);
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

    /* Call refreshers */
    call_refreshers (path);

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
        /* Call refreshers for the search path */
        call_refreshers (path_s);

        /* Search database next */
        children = db_search (path_s);
        DEBUG (" Got %d entries from database...\n", g_list_length (children));
        /* Append any provided or refreshed paths */
        GList *callbacks = NULL;
        callbacks = config_search_providers (path_s);
        callbacks = g_list_concat (config_search_refreshers (path_s), callbacks);
        DEBUG (" Got %d entries from providers and refreshers...\n", g_list_length (callbacks));
        for (iter = callbacks; iter; iter = iter->next)
        {
            char *p = (char*)iter->data;
            if (!g_list_find_custom (children, p, (GCompareFunc)strcmp))
                children = g_list_prepend (children, strdup (p));
        }
        g_list_free_full (callbacks, free);
    }
    for (iter = children; iter; iter = g_list_next (iter))
    {
        DEBUG ("TRAVERSE: %s\n", (const char *) iter->data);
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
handle_query (rpc_message msg)
{
    char *path;
    char *value;
    GList *paths = NULL;
    GList *ipath;
    GList *ivalue;
    GList *value_matches = NULL;
    GList *possible_matches = NULL;
    GList *matches = NULL;
    GList *iter = NULL;
    GList *iter2 = NULL;
    char *tmp = NULL;
    char *ptr = NULL;
    char *chunk;

    INC_COUNTER (counters.query);

    while ((path = rpc_msg_decode_string (msg)) != NULL)
    {
        paths = g_list_prepend (paths, path);
        DEBUG ("QUERY: %s\n", path);
    }
    paths = g_list_reverse (paths);
    for (iter2 = g_list_first (paths); iter2; iter2 = g_list_next (iter2))
    {
        bool traverse = false;
        bool one_level = false;

        if (strchr (iter2->data, '*') == NULL)
        {
            value = get_value ((char *) iter2->data);
            if (value)
            {
                matches = g_list_prepend (matches, g_strdup ((char *) iter2->data));
                value_matches = g_list_prepend (value_matches, g_strdup (value));
            }
            g_free (value);
        }
        else
        {
            /* Path contains a "*".
             * Grab first level (from root) */
            tmp = g_strdup (iter2->data);
            if (tmp[strlen (tmp) - 1] == '*')
            {
                traverse = true;
            }
            else if (tmp[strlen (tmp) - 1] == '/')
            {
                one_level = true;
            }
            *strrchr (tmp, '*') = '\0';
            chunk = strtok_r (tmp, "*", &ptr);
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

                    next_level = g_strdup_printf ("%s%s", (char *) iter->data, chunk);
                    possible_matches =
                        g_list_concat (search_path (next_level), possible_matches);
                    g_free (next_level);
                }
                g_list_free_full (last_round, g_free);
            }
            if (traverse)
            {
                for (iter = g_list_first (possible_matches); iter;
                     iter = g_list_next (iter))
                {
                    _traverse_paths (&matches, &value_matches, (char *) iter->data);
                }
            }
            else
            {
                /* Go through each path match and see if all keys match */
                for (iter = g_list_first (possible_matches); iter;
                     iter = g_list_next (iter))
                {
                    char *key = NULL;

                    key = g_strdup_printf ("%s%s", (char *) iter->data,
                                           strrchr (iter2->data, '*') + 1);
                    if (one_level)
                    {
                        /* Remove the slash off the end of the string */
                        key[strlen (key) - 1] = '\0';
                    }
                    value = get_value (key);
                    if (value)
                    {
                        matches = g_list_prepend (matches, g_strdup (key));
                        value_matches = g_list_prepend (value_matches, g_strdup (value));
                    }
                    g_free (value);
                    g_free (key);
                }
            }
            g_free (tmp);
            g_list_free_full (possible_matches, g_free);
        }
    }
    /* Send result */
    rpc_msg_reset (msg);
    for (ipath = g_list_first (matches), ivalue = g_list_first (value_matches);
         ipath && ivalue; ipath = g_list_next (ipath), ivalue = g_list_next (ivalue))
    {
        DEBUG ("  %s = %s\n", (char *) ipath->data, (char *) ivalue->data);
        rpc_msg_encode_string (msg, (char *) ipath->data);
        rpc_msg_encode_string (msg, (char *) ivalue->data);
    }
    g_list_free_full (matches, g_free);
    g_list_free_full (value_matches, g_free);
    g_list_free (paths);

    return true;
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
        /* Prune from database - but protect /apteryx */
        if (strcmp (path, "/") == 0)
        {
            GList *nodes = db_search (path);
            GList *iter = NULL;
            for (iter = nodes; iter; iter = iter->next)
            {
                const char *child_path = (const char*)iter->data;
                if (strcmp(child_path, "/apteryx"))
                {
                    db_prune (child_path);
                }
            }
            g_list_free_full (nodes, free);
        }
        else
        {
            db_prune (path);
        }
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
handle_memuse (rpc_message msg)
{
    uint64_t value;
    const char *path;

    /* Parse the parameters */
    path = rpc_msg_decode_string (msg);
    if (path == NULL)
    {
        ERROR ("MEMUSE: Invalid parameters.\n");
        INC_COUNTER (counters.memuse_invalid);
        return false;
    }

    DEBUG ("MEMUSE: %s\n", path);
    INC_COUNTER (counters.memuse);

    /* Lookup value */
    value = db_memuse (path);

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
    case MODE_QUERY:
        return handle_query (msg);
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
    case MODE_MEMUSE:
        return handle_memuse (msg);
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

    int child_ready[2] = { 0 };

    if (background)
    {
        int rc = pipe (child_ready);
        if (rc)
        {
            perror ("pipe:");
            return 0;
        }

        int child_pid = fork ();
        if (child_pid > 0)
        {
            /* Parent */
            close (child_ready[1]);

            /* Give the child 30 seconds to start */
            struct pollfd fd;
            fd.fd = child_ready[0];
            fd.events = POLLIN;
            int ret = poll(&fd, 1, 30000);

            char buf[2];
            ssize_t rz = 0;
            if (ret > 0)
            {
                rz = read (child_ready[0], buf, 2);
            }
            close (child_ready[0]);

            if (ret <= 0 || rz != 2)
            {
                /* Oh no :( */
                ERROR ("Child not ready ...");
                kill (child_pid, SIGTERM);
                waitpid (child_pid, NULL, 0);
                return -1;
            }

            return 0;
        }
        else if (child_pid == 0)
        {
            close (child_ready[0]);
        }
        else
        {
            ERROR ("Forking failed");
            goto exit;
        }

        /* Create pid file */
        if (pid_file)
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
    }


    /* Initialise the database */
    db_init ();
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

    if (background)
    {
        /* Tell our parent we are ready */
        ssize_t sz = write (child_ready[1], "1\n", 2);
        if (sz < 2)
        {
            ERROR ("Failed to notify parent, we are going to die\n");
        }
    }

    /* Loop while running */
    while (running)
    {
        pause ();
    }

exit:
    DEBUG ("Exiting\n");

    if (background)
    {
        close (child_ready[0]);
        close (child_ready[1]);
    }

    /* Cleanup callbacks */
    if (proxy_rpc)
    {
        rpc_shutdown (proxy_rpc);
    }
    if (rpc)
    {
        rpc_server_release (rpc, url);
        rpc_shutdown (rpc);
    }

    db_shutdown ();
    config_shutdown ();

    /* Remove the pid file */
    if (background && pid_file)
        unlink (pid_file);

    /* Remove the run file */
    if (run_file)
        unlink (run_file);

    return 0;
}
