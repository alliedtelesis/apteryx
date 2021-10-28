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
    uint64_t start, duration;
    bool res;

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
        start = get_time_us ();
        res = rpc_msg_send (rpc_client, &msg);
        duration = get_time_us () - start;
        if (!res)
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
        if (!GET_COUNTER (indexer->min) || duration < GET_COUNTER (indexer->min))
            SET_COUNTER (indexer->min, duration);
        if (duration > GET_COUNTER (indexer->max))
            SET_COUNTER (indexer->max, duration);
        ADD_COUNTER (indexer->total, duration);
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
    uint64_t start, duration;
    bool res;

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
        start = get_time_us ();
        res = rpc_msg_send (rpc_client, &msg);
        duration = get_time_us () - start;
        if (!res)
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

        /* Result */
        INC_COUNTER (counters.validated);
        if (!GET_COUNTER (validator->min) || duration < GET_COUNTER (validator->min))
            SET_COUNTER (validator->min, duration);
        if (duration > GET_COUNTER (validator->max))
            SET_COUNTER (validator->max, duration);
        ADD_COUNTER (validator->total, duration);
        INC_COUNTER (validator->count);
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

/* For a list of paths find the common starting
 * path including the trailing back-slash */
static gchar *
find_common_path (GList *paths)
{
    gchar *cpath = NULL;
    GList *iter;

    for (iter = g_list_first (paths); iter; iter = g_list_next (iter))
    {
        gchar *path = (gchar *) iter->data;
        if (!path)
            continue;
        if (cpath == NULL)
            cpath = g_strconcat (path, "/", NULL);
        else
        {
            int last_slash = 0;
            int i = 0;
            while (1)
            {
                if (cpath[i] == '\0')
                    break;
                if (cpath[i] != path[i])
                {
                    g_free (cpath);
                    cpath = g_strndup (path, last_slash + 1);
                    break;
                }
                if (cpath[i] == '/')
                    last_slash = i;
                i++;
            }
        }
    }
    if (cpath && cpath[0] == '/' && cpath[1] == '\0')
    {
        g_free (cpath);
        cpath = NULL;
    }
    return cpath;
}

static gint
compare_watcher (cb_info_t *a, cb_info_t *b)
{
    if (a->id == b->id && a->ref == b->ref)
        return 0;
    return -1;
}

static void
send_watch_notification (cb_info_t *watcher, GList *paths, GList *values, int ack)
{
    rpc_client rpc_client;
    rpc_message_t msg = {};
    GList *ipath;
    GList *ivalue;
    uint64_t start, duration;
    bool res;

    /* IPC */
    rpc_client = rpc_client_connect (rpc, watcher->uri);
    if (!rpc_client)
    {
        /* Throw away the no good validator */
        ERROR ("Invalid WATCH CB %s (0x%"PRIx64",0x%"PRIx64")\n",
                watcher->path, watcher->id, watcher->ref);
        cb_disable (watcher);
        INC_COUNTER (counters.watched_no_handler);
        return;
    }
    rpc_msg_encode_uint8 (&msg, ack ? MODE_WATCH_WITH_ACK : MODE_WATCH);
    rpc_msg_encode_uint64 (&msg, watcher->ref);
    for (ipath = g_list_first (paths), ivalue = g_list_first (values);
         ipath;
         ipath = g_list_next (ipath), ivalue = g_list_next (ivalue))
    {
        rpc_msg_encode_string (&msg, (char *) ipath->data);
        if (ivalue && ivalue->data)
            rpc_msg_encode_string (&msg, (char *) ivalue->data);
        else
            rpc_msg_encode_string (&msg, "");
    }
    start = get_time_us ();
    res = rpc_msg_send (rpc_client, &msg);
    duration = get_time_us () - start;
    if (!res)
    {
        INC_COUNTER (counters.watched_timeout);
        ERROR ("Failed to notify watcher for path \"%s\"\n", watcher->path);
        rpc_client_release (rpc, rpc_client, false);
    }
    else
    {
        rpc_client_release (rpc, rpc_client, true);
    }
    rpc_msg_reset (&msg);

    INC_COUNTER (counters.watched);
    if (!GET_COUNTER (watcher->min) || duration < GET_COUNTER (watcher->min))
        SET_COUNTER (watcher->min, duration);
    if (duration > GET_COUNTER (watcher->max))
        SET_COUNTER (watcher->max, duration);
    ADD_COUNTER (watcher->total, duration);
    INC_COUNTER (watcher->count);
}

static void
notify_watchers (GList *paths, GList *values, bool ack)
{
    GList *common_watchers = NULL;
    GList *used_watchers = NULL;
    gchar *cpath = NULL;
    GList *ipath;
    GList *ivalue;

    /* Try to send all values at once if they have a common path */
    if (g_list_length (paths) > 1)
        cpath = find_common_path (paths);
    if (cpath)
    {
        common_watchers = config_get_watchers (cpath);
        if (common_watchers)
        {
            GList *iter = NULL;
            for (iter = common_watchers; iter; iter = g_list_next (iter))
            {
                cb_info_t *watcher = iter->data;

                if (watcher->id != getpid ())
                {
                    send_watch_notification (watcher, paths, values, ack);
                    /* Remember so we dont use this one again */
                    used_watchers = g_list_append (used_watchers, watcher);
                }
            }
        }
        g_free (cpath);
    }

    /* Find all watchers that did not match the common path */
    ipath = g_list_first (paths);
    ivalue = values ? g_list_first (values) : NULL;
    while (ipath)
    {
        gchar *path = (gchar *) ipath->data;
        gchar *value = ivalue ? (gchar *) ivalue->data : NULL;
        GList *watchers;

        if (path && (watchers = config_get_watchers (path)))
        {
            GList *iter;
            for (iter = watchers; iter; iter = g_list_next (iter))
            {
                cb_info_t *watcher = iter->data;
                if (g_list_find_custom (used_watchers, iter->data, (GCompareFunc) compare_watcher))
                    continue;
                if (watcher->id == getpid ())
                {
                    apteryx_watch_callback cb = (apteryx_watch_callback) (long) watcher->ref;
                    DEBUG ("WATCH LOCAL \"%s\" (0x%"PRIx64",0x%"PRIx64")\n",
                            watcher->path, watcher->id, watcher->ref);
                    if (value && (value[0] == '\0'))
                        cb (path, NULL);
                    else
                        cb (path, value);
                    continue;
                }
                GList *paths = g_list_append(NULL, (void *) path);
                GList *values = g_list_append(NULL, (void *) value);
                send_watch_notification (watcher, paths, values, ack);
                g_list_free (paths);
                g_list_free (values);
            }
            g_list_free_full (watchers, (GDestroyNotify) cb_release);
        }
        ipath = g_list_next (ipath);
        ivalue = ivalue ? g_list_next (ivalue) : NULL;
    }
    g_list_free (used_watchers);
    g_list_free_full (common_watchers, (GDestroyNotify) cb_release);
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
        uint64_t start, duration;
        bool res;

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
        start = get_time_us ();
        res = rpc_msg_send (rpc_client, &msg);
        duration = get_time_us () - start;
        if (!res)
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
        if (!GET_COUNTER (refresher->min) || duration < GET_COUNTER (refresher->min))
            SET_COUNTER (refresher->min, duration);
        if (duration > GET_COUNTER (refresher->max))
            SET_COUNTER (refresher->max, duration);
        ADD_COUNTER (refresher->total, duration);
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
        uint64_t start, duration;
        bool res;

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
        start = get_time_us ();
        res = rpc_msg_send (rpc_client, &msg);
        duration = get_time_us () - start;
        if (!res)
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
        if (!GET_COUNTER (provider->min) || duration < GET_COUNTER (provider->min))
            SET_COUNTER (provider->min, duration);
        if (duration > GET_COUNTER (provider->max))
            SET_COUNTER (provider->max, duration);
        ADD_COUNTER (provider->total, duration);
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
    rpc_msg_encode_uint8 (&msg, rpc_value);
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

typedef struct {
    GList *paths;
    GList *values;
} key_value_lists;

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
            end ? "" : "/") >= 0)
    {
        free (*buf);
        *buf = tmp;
    }
    return tmp;
}


static gboolean
_gather_values (GNode *node, gpointer data)
{
    key_value_lists *lists = (key_value_lists *) data;
    if (APTERYX_HAS_VALUE(node))
    {
        char *path = NULL;
        /* Create the apteryx path for this node. */
        _node_to_path (node, &path);
        lists->paths = g_list_prepend (lists->paths, path);
        lists->values = g_list_prepend (lists->values, g_strdup (APTERYX_VALUE (node)));
    }
    return FALSE;
}

/* Removes a node and any hanging parents from a GNode tree */
static GNode *
remove_node (GNode *_root, const char *_path)
{
    gchar *path = g_strdup (_path);
    GNode *root = _root;
    char *tok;
    char *chunk;
    chunk = strtok_r(path, "/", &tok);
    while (chunk)
    {
        for (GNode *node = g_node_first_child (root); node; node = g_node_next_sibling (node)) {
            /* Find the node in question. */
            if ((g_strcmp0 (APTERYX_NAME (node), chunk) == 0))
            {
                if (APTERYX_HAS_VALUE(node))
                {
                    /* If this node has a value remove it, and free the node. */
                    g_node_unlink (node);
                    g_free (APTERYX_NAME (node));
                    g_free (APTERYX_VALUE (node));
                    g_node_destroy (node);

                    /* Head up the tree freeing any that we can. */
                    while (root && APTERYX_NUM_NODES(root) <= 1)
                    {
                        /* Save the node we are removing */
                        node = root;
                        /* Prepare to move up */
                        root = node->parent;
                        g_node_unlink (node);
                        g_free (node->data);
                        g_node_destroy (node);
                    }
                    /* Done removing + cleaning up tree. */
                    goto exit;
                }
                else
                {
                    /* If this isn't a leaf, move down a level. */
                    root = node;
                    break;
                }
            }
        }

        /* Move on to the next piece of the path. */
        chunk = strtok_r (NULL, "/", &tok);
    };

exit:
    g_free (path);
    return root;
}

static bool
handle_set (rpc_message msg, bool ack)
{
    int result = 0;
    uint64_t ts = 0;
    GList *paths = NULL;
    GList *ipath;
    const char *path;
    GList *values = NULL;
    GList *ivalue;
    const char *value;
    GNode *root;
    char *root_path = NULL;
    int proxy_result = 0;
    int validation_result = 0;
    int validation_lock = 0;
    bool db_result = false;
    key_value_lists lists = { NULL, NULL };

    /* Parse the parameters */
    ts = rpc_msg_decode_uint64 (msg);
    root = rpc_msg_decode_tree (msg);

    if (!root)
    {
        ERROR ("SET: Failed to decode message\n");
        return false;
    }

    /* Figure out if we need the lists for checking callbacks */
    _node_to_path(root, &root_path);
    if (config_tree_has_proxies(root_path) ||
        config_tree_has_validators(root_path) ||
        config_tree_has_watchers(root_path))
        {
            /* If we have to search for any proxies / validators / watchers then build a list
             * of paths.+ values.
             */
            g_node_traverse (root, G_PRE_ORDER, G_TRAVERSE_NON_LEAFS, -1, _gather_values, &lists);
        }

    paths = g_list_reverse (lists.paths);
    values = g_list_reverse (lists.values);
    INC_COUNTER (counters.set);

    /* Proxy first */
    ipath = g_list_first (paths);
    ivalue = g_list_first (values);

    /* Don't bother with this loop if there are no proxies */
    if (config_tree_has_proxies(root_path))
    {
        while (ipath && ivalue)
        {
            path = (const char *) ipath->data;
            value = (const char *) ivalue->data;
            if (value && value[0] == '\0')
                value = NULL;

            proxy_result = proxy_set (path, value, ts);
            if (proxy_result == 0)
            {
                /* Result success */
                DEBUG ("SET: %s = %s proxied\n", path, value);
                /* Call any watchers */
                GList *wpaths = g_list_append (NULL, (gpointer) path);
                GList *wvalues = g_list_append (NULL, (gpointer) value);
                GList *next;
                notify_watchers (wpaths, wvalues, ack);
                g_list_free (wpaths);
                g_list_free (wvalues);

                /* This value needs to be removed from the tree */
                root = remove_node(root, path);

                /* Safely remove from both lists as we dont need to do any more processing */
                  next = g_list_next (ipath);
                  paths = g_list_delete_link (paths, ipath);
                  ipath = next;
                  next = g_list_next (ivalue);
                  values = g_list_delete_link (values, ivalue);
                  ivalue = next;
                  continue;
              }
              else if (proxy_result < 0)
              {
                  result = proxy_result;
                  goto exit;
              }
              ipath = g_list_next (ipath);
              ivalue = g_list_next (ivalue);
          }
    }

    /* Validate, if there are any present */
    if (config_tree_has_validators(root_path))
    {
        for (ipath = g_list_first (paths), ivalue = g_list_first (values);
             ipath && ivalue; ipath = g_list_next (ipath), ivalue = g_list_next (ivalue))
        {
            path = (const char *) ipath->data;
            value = (const char *) ivalue->data;
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
    }

    /* Set in the database */
    pthread_rwlock_wrlock (&db_lock);
    db_result = db_update_no_lock (root, ts);
    if (!db_result)
    {
        DEBUG ("SET: tree rejected by DB (%ld)\n", ts);
        result = -EBUSY;
    }
    pthread_rwlock_unlock (&db_lock);

exit:
    /* Return result and notify watchers */
    if (validation_result >= 0 && result == 0)
    {
        /* Notify watchers, if any are present */
        if (config_tree_has_watchers (root_path))
        {
            notify_watchers (paths, values, ack);
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
    g_free (root_path);
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

typedef enum {
    cb_index = 0x1,
    cb_provide = 0x2,
    cb_refresh = 0x4,
    cb_all = cb_index | cb_provide | cb_refresh,
} cb_lookup_required;

static char
_update_path_callbacks (const char *path, char cb_lookup)
{
    if (cb_lookup & cb_index)
        if (!config_tree_has_indexers (path))
            cb_lookup &=~ cb_index;

    if (cb_lookup & cb_provide)
        if (!config_tree_has_providers (path))
            cb_lookup &=~ cb_provide;

    if (cb_lookup & cb_refresh)
        if (!config_tree_has_refreshers (path))
            cb_lookup &=~ cb_refresh;

    return cb_lookup;
}

static void
_traverse_paths (GList **paths, GList **values, const char *path, char cb_lookup)
{
    GList *children, *iter;
    char *value = NULL;
    size_t vsize;

    /* Look for a value - db first */
    if (!db_get (path, (unsigned char**)&value, &vsize) && (cb_lookup & cb_provide))
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
    if (!(cb_lookup & cb_index) || !index_get (path_s, &children))
    {
        /* Search database next */
        children = db_search (path_s);
        DEBUG (" Got %d entries from database...\n", g_list_length (children));
        /* Append any provided or refreshed paths */
        GList *callbacks = NULL;
        if (cb_lookup & cb_provide)
            callbacks = config_search_providers (path_s);

        if (cb_lookup & cb_refresh)
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

    cb_lookup = _update_path_callbacks (path_s, cb_lookup);

    for (iter = children; iter; iter = g_list_next (iter))
    {
        DEBUG ("TRAVERSE: %s\n", (const char *) iter->data);
        _traverse_paths (paths, values, (const char *) iter->data, cb_lookup);
    }
    g_list_free_full (children, g_free);
    g_free (path_s);
}

static void
refreshers_traverse (const char *top_path, char cb_lookup)
{
    GList *iter, *paths = NULL;
    gchar *needle = g_strdup_printf("%s/", top_path);

    call_refreshers (needle);

    if (!config_tree_has_refreshers (top_path))
    {
        free (needle);
        return;
    }

    if (cb_lookup & cb_index)
    {
        index_get (top_path, &paths);
        paths = g_list_concat (config_search_indexers (needle), paths);
    }

    /* We might be able to find our way down to a refresher */
    if (cb_lookup & cb_refresh)
    {
        paths = g_list_concat (config_search_refreshers (needle), paths);
    }

    if (cb_lookup & cb_provide)
    {
        paths = g_list_concat (config_search_providers (needle), paths);
    }
    paths = g_list_concat (db_search (needle), paths);

    cb_lookup = _update_path_callbacks (needle, cb_lookup);
    free (needle);

    for (iter = paths; iter; iter = g_list_next (iter))
    {
        const char *path = (const char *) iter->data;
        refreshers_traverse (path, cb_lookup);
    }
    g_list_free_full (paths, g_free);
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

    /* Call refreshers */
    refreshers_traverse (path, cb_all);

    /* Proxy first */
    if (!proxy_traverse (&paths, &values, path))
    {
        /* Traverse (local) paths and make sure the database
         * doesn't change while we're reading it. If there are
         * providers or indexers we are unable to serve a tree
         * from a single point in time, so don't bother with
         * the locking.
         * */
        bool lock_possible = true;
        GList *callbacks = NULL;
        callbacks = config_search_providers (path);
        if (!callbacks)
            callbacks = config_search_indexers (path);
        if (callbacks)
        {
            lock_possible = false;
            g_list_free_full (callbacks, free);
        }
        if (lock_possible)
            pthread_rwlock_rdlock (&db_lock);
        _traverse_paths (&paths, &values, path, cb_all);
        if (lock_possible)
            pthread_rwlock_unlock (&db_lock);
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
                    _traverse_paths (&matches, &value_matches, (char *) iter->data, cb_all);
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
        notify_watchers (paths, NULL, false);
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
