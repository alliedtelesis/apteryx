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
#include <malloc.h>
#include "apteryx.h"
#include "internal.h"

/* Run while true */
static bool running = true;

/* RPC Service */
rpc_instance rpc = NULL;
rpc_instance proxy_rpc = NULL;

/* Statistics and debug */
counters_t counters = {};

/* Synchronise validation */
static pthread_mutex_t validating;

/* Sin bin for processes that have not responded in time. */
struct sin_bin_entry {
    char *uri;
    uint64_t timeout;
};
static GList *sin_bin = NULL;
static pthread_mutex_t sin_bin_lock = PTHREAD_MUTEX_INITIALIZER;

static bool
check_indexed_path (const char *indexed, const char *path, int path_length)
{
    /* Indexed paths must be longer than the path we searched for. */
    if (strlen (indexed) <= path_length)
    {
        return false;
    }
    /* Indexed paths must start with the search path. */
    if (strncmp (path, indexed, path_length))
    {
        return false;
    }
    /* Indexed paths must only fill in one directory below. */
    if (strchr (indexed + path_length, '/'))
    {
        return false;
    }

    return true;
}

/* This function returns true if indexers were called (list may still be NULL) */
static bool
index_get (const char *path, GList **result)
{
    GList *indexers = NULL;
    GList *results = NULL;
    GList *iter = NULL;
    uint64_t start, duration;
    bool res;
    const char *rpath;
    int path_length = strlen (path);

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
        while ((rpath = rpc_msg_decode_string (&msg)) != NULL)
        {
            if (check_indexed_path(rpath, path, path_length))
            {
                results = g_list_prepend (results, (gpointer) strdup (rpath));
            }
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

static void
send_watch_notification (cb_info_t *watcher, GNode *root, int ack)
{
    rpc_client rpc_client;
    rpc_message_t msg = {};
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
    rpc_msg_encode_tree (&msg, root);

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

static int
local_callback (GNode *node, gpointer _cb)
{
    apteryx_watch_callback cb = _cb;

    char *path = apteryx_node_path(node->parent);
    if (!node->data || ((char*)node->data)[0] == '\0')
        cb (path, NULL);
    else
        cb (path, node->data);
    g_free(path);
    return true;
}

static void
notify_watchers (GNode *root, bool ack, uint64_t ns, uint64_t pid)
{
    if (!root)
        return;

    GList *watchers = config_get_watchers_tree(root);
    for (GList *iter = watchers; iter; iter = g_list_next (iter))
    {
        struct cb_tree_info *watcher = iter->data;
        cb_info_t *watcher_info = watcher->cb;

        if (watcher_info->id == getpid ())
        {
            apteryx_watch_callback cb = (apteryx_watch_callback) (long) watcher_info->ref;
            DEBUG ("WATCH LOCAL \"%s\" (0x%"PRIx64",0x%"PRIx64")\n",
                    watcher_info->path, watcher_info->id, watcher_info->ref);
            g_node_traverse (watcher->data, G_PRE_ORDER, G_TRAVERSE_LEAVES, -1, local_callback, cb);
            continue;
        }
        /* Skip watchers that don't want to be notified for their own sets */
        if ((watcher_info->flags & WATCH_F_MASK_MYSELF) && watcher_info->ns == ns && watcher_info->id == pid)
        {
            continue;
        }
        send_watch_notification (watcher_info, watcher->data, ack);
    }
    g_list_free_full (watchers, (GDestroyNotify) cb_tree_release);
}

static char *
get_refresher_path (const char *path, cb_info_t *refresher)
{
    const char *rpath = refresher->path;
    char *cpath = g_malloc0 (strlen (path) + strlen (rpath) + 1);
    const char *wild;
    int offset = 0;

    /* Resolve any wildcards in either path */
    while (*path && *rpath)
    {
        if (*path == '*' && *rpath == '*')
        {
            while (*path)
                path++;
            while (*rpath)
                rpath++;
        }
        else if (*path == '*')
        {
            while (*rpath != '/' && *rpath != '\0')
            {
                cpath[offset++] = *rpath;
                rpath++;
            }
            path++;
        }
        else if (*rpath == '*')
        {
            while (*path != '/' && *path != '\0')
            {
                cpath[offset++] = *path;
                path++;
            }
            rpath++;
        }
        else
        {
            cpath[offset++] = *rpath;
            rpath++;
            path++;
        }
    }

    /* Append any left over requester path if the refresher is not single level */
    if (*path && rpath[-1] != '/')
    {
        /* Append any requester path that we do not need to resolve */
        while (*path && *path != '*')
        {
            cpath[offset++] = *path;
            path++;
        }
    }

    /* Append any refresher path that we do not need to resolve */
    while (*rpath && *rpath != '*')
    {
        cpath[offset++] = *rpath;
        rpath++;
    }

    /* Check there are not unresolved wildcards */
    if ((*rpath && ((wild = strchr (rpath, '*')) != NULL) && wild != &rpath[strlen (rpath)] - 1) ||
        (*path && ((wild = strchr (path, '*')) != NULL)  && wild != &path[strlen (path)] - 1))
    {
        free (cpath);
        cpath = NULL;
    }
    return cpath;
}


static const char*
get_process_name (const uint64_t ns, const uint64_t pid)
{
    static char name[1024];
    name[0] = '\0';
    if (ns != getns ())
    {
        sprintf (name, APTERYX_CLIENT_ID, ns, pid);
        return name;
    }
    sprintf (name, "/proc/%"PRIu64"/cmdline", pid);
    FILE* f = fopen (name,"r");
    if (f)
    {
        size_t size;
        size = fread (name, sizeof(char), 1024, f);
        if (size > 0)
        {
            if ('\n' == name[size-1])
                name[size-1]='\0';
        }
        fclose(f);
    }
    if (strrchr (name, '/'))
        return strrchr (name, '/') + 1;
    return name;
}

/* Returns true if this uri can currently be used, false otherwise. */
static bool
sin_bin_check (const char *uri)
{
    GList *iter, *next;
    uint64_t now = get_time_us ();

    pthread_mutex_lock (&sin_bin_lock);
    /* First remove any expired entries. */
    for (iter = sin_bin; iter; iter = next)
    {
        struct sin_bin_entry *entry = (struct sin_bin_entry *)iter->data;
        next = iter->next;
        if (entry->timeout < now)
        {
            g_free (entry->uri);
            g_free (entry);
            sin_bin = g_list_delete_link (sin_bin, iter);
        }
    }

    /* If the entry is in the sinbin, return false. */
    for (iter = sin_bin; iter; iter = iter->next)
    {
        struct sin_bin_entry *entry = (struct sin_bin_entry *)iter->data;
        if (strcmp (entry->uri, uri) == 0)
        {
            pthread_mutex_unlock (&sin_bin_lock);
            return false;
        }
    }
    pthread_mutex_unlock (&sin_bin_lock);
    return true;
}

static void
sin_bin_add (const char *uri)
{
    struct sin_bin_entry *entry = g_malloc0 (sizeof (struct sin_bin_entry));
    entry->uri = g_strdup (uri);
    entry->timeout = get_time_us () + (2 * RPC_CLIENT_TIMEOUT_US);
    pthread_mutex_lock (&sin_bin_lock);
    sin_bin = g_list_prepend (sin_bin, entry);
    pthread_mutex_unlock (&sin_bin_lock);
}

static bool
call_refreshers (const char *path, bool dry_run)
{
    GList *refreshers = NULL;
    GList *iter = NULL;
    uint64_t now;
    uint64_t timeout = 0;
    bool refresh_due = false;
    char *cpath = NULL;

    /* Retrieve a list of refreshers for this path */
    refreshers = config_get_refreshers (path);
    if (!refreshers)
        return false;

    /* Get the time of the request */
    now = get_time_us ();

    /* Call each refresher */
    for (iter = refreshers; iter; iter = g_list_next (iter))
    {
        cb_info_t *refresher = iter->data;
        rpc_client rpc_client;
        rpc_message_t msg = {};
        uint64_t start, duration;
        bool res;

        pthread_mutex_lock (&refresher->lock);

        /* Get a path suitable for passing to the refresher */
        cpath = get_refresher_path (path, refresher);
        if (!cpath)
        {
            DEBUG ("Not enough state to refresh %s for %s\n", refresher->path, path);
            goto unlock;
        }
        DEBUG ("PATH:%s RPATH:%s CPATH:%s\n", path, refresher->path, cpath);

        /* We can skip this refresher if the refresher has been called recently AND
         * the last call was for a path equal to or less specific than this one,
         * but don't nag a process that has been timing out until the expiry time
         * is actually hit. */
        if (now < (refresher->timestamp + refresher->timeout) &&
            (strncmp (refresher->last_path, cpath, strlen (refresher->last_path)) == 0 &&
             (*(refresher->last_path + strlen (refresher->last_path) - 1) == '/' ||
              *(cpath + strlen (refresher->last_path)) == '/' ||
              *(cpath + strlen (refresher->last_path)) == '\0')))
        {
            DEBUG ("Not refreshing %s (now:%"PRIu64" < (ts:%"PRIu64" + to:%"PRIu64"))\n",
                   cpath, now, refresher->timestamp, refresher->timeout);
            goto unlock;
        }

        /* Check to see if this process is in the sinbin */
        if (sin_bin_check (refresher->uri) == false)
        {
            DEBUG ("REFRESH: Not Refreshing %s - %s in sinbin\n", cpath, get_process_name (refresher->ns, refresher->id));
            goto unlock;
        }

        if (now >= (refresher->timestamp + refresher->timeout))
        {
            DEBUG ("Refreshing %s (now:%"PRIu64" >= (ts:%"PRIu64" + to:%"PRIu64"))\n",
                cpath, now, refresher->timestamp, refresher->timeout);
        }
        else
        {
            DEBUG ("Refreshing %s (< %s)\n", cpath, refresher->last_path);
        }

        /* Check for local refresher */
        if (refresher->id == getpid ())
        {
            apteryx_refresh_callback cb = (apteryx_refresh_callback) (long) refresher->ref;
            DEBUG ("REFRESH LOCAL \"%s\" (0x%"PRIx64",0x%"PRIx64")\n",
                    refresher->path, refresher->id, refresher->ref);
            timeout = cb (cpath);
            if (refresher->timeout == 0 || timeout < refresher->timeout)
                refresher->timeout = timeout;
            /* Record the last time we ran this refresher */
            refresher->timestamp = now;
            /* Record the path we refreshed (without any trailing /'s)*/
            if (refresher->last_path)
                free (refresher->last_path);
            refresher->last_path = g_strdup (cpath);
            goto unlock;
        }

        DEBUG ("REFRESH CB %s (%s 0x%"PRIx64",0x%"PRIx64",%s)\n",
                cpath, refresher->path, refresher->id, refresher->ref, refresher->uri);

        /* IPC */
        if (!dry_run)
        {
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
            rpc_msg_encode_string (&msg, cpath);
            start = get_time_us ();
            res = rpc_msg_send (rpc_client, &msg);
            duration = get_time_us () - start;
            if (!res)
            {
                INC_COUNTER (counters.refreshed_timeout);
                ERROR ("REFRESH: No response from %s for path \"%s\"\n", get_process_name (refresher->ns, refresher->id), (char *) path);
                rpc_client_release (rpc, rpc_client, false);

                /* Put this process in the sin bin for a while. */
                sin_bin_add (refresher->uri);
            }
            else
            {
                rpc_client_release (rpc, rpc_client, true);
                timeout = rpc_msg_decode_uint64 (&msg);
                DEBUG ("REFRESH again in %"PRIu64"us\n", timeout);
                if (refresher->timeout == 0 || timeout < refresher->timeout)
                    refresher->timeout = timeout;
                /* Record the last time we ran this refresher */
                refresher->timestamp = now;
                /* Record the path we refreshed (without any trailing /'s)*/
                if (refresher->last_path)
                    free (refresher->last_path);
                refresher->last_path = g_strdup (cpath);
            }
            rpc_msg_reset (&msg);

            INC_COUNTER (counters.refreshed);
            if (!GET_COUNTER (refresher->min) || duration < GET_COUNTER (refresher->min))
                SET_COUNTER (refresher->min, duration);
            if (duration > GET_COUNTER (refresher->max))
                SET_COUNTER (refresher->max, duration);
            ADD_COUNTER (refresher->total, duration);
            INC_COUNTER (refresher->count);
        }
        else
        {
            refresh_due = true;
        }
    unlock:
        free (cpath);
        pthread_mutex_unlock (&refresher->lock);
    }
    g_list_free_full (refreshers, (GDestroyNotify) cb_release);
    return refresh_due;
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

    char *key = node ? node->data : "";
    if (key[0] == '/' && key[1] == '\0')
        key++;

    if (asprintf (&tmp, "%s%s%s", *buf ? : "",
            key,
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


static bool
proxy_traverse (GList **paths, GList **values, const char *path)
{
    rpc_client rpc_client;
    rpc_message_t msg = { 0 };
    const char *in_path = path;
    key_value_lists lists = { NULL, NULL };
    GNode *root = NULL;

    cb_info_t *proxy = NULL;

    /* Find and connect to a proxied instance */
    rpc_client = find_proxy (&path, &proxy);
    if (!rpc_client)
        return false;

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

    root = rpc_msg_decode_tree (&msg);

    /* Prepend this remote tree with our proxy path */
    if (root)
    {
        gchar *new_root_key = g_strdup_printf("%.*s%s", (int)(path - in_path), in_path, APTERYX_NAME(root));
        g_free(root->data);
        root->data = new_root_key;
        g_node_traverse (root, G_PRE_ORDER, G_TRAVERSE_NON_LEAFS, -1, _gather_values, &lists);
    }

    *paths = lists.paths;
    *values = lists.values;

    rpc_msg_reset (&msg);
    rpc_client_release (rpc, rpc_client, true);
    apteryx_free_tree(root);

    return true;
}

static GNode *
proxy_query (GNode *query, const char *path)
{
    rpc_client rpc_client;
    rpc_message_t msg = {};
    cb_info_t *proxy = NULL;
    GNode *node = NULL;
    GNode *pnode = NULL;
    GNode *pquery = NULL;
    GNode *root = NULL;

    /* Find and connect to a proxied instance */
    rpc_client = find_proxy (&path, &proxy);
    if (!rpc_client) {
        return NULL;
    }

    /* Need to trim off root of the query tree, up until the proxied node */
    int len = strlen (proxy->path);
    if (proxy->path[len-1] == '*')
        len -= 1;
    if (proxy->path[len-1] == '/')
        len -= 1;
    char *local_path = g_malloc0 (len + 1);
    strncpy (local_path, proxy->path, len);

    /* Create a temp query without the proxy path */
    node = apteryx_path_node (query->children, local_path);
    pnode = g_node_first_child (node);
    g_node_unlink (pnode);
    pquery = APTERYX_NODE (NULL, "");
    g_node_prepend (pquery, pnode);

    /* Do remote query */
    rpc_msg_encode_uint8 (&msg, MODE_QUERY);
    rpc_msg_encode_tree (&msg, pquery);

    /* Restore the original query */
    g_node_unlink (pnode);
    g_node_destroy (pquery);
    g_node_prepend (node, pnode);

    if (!rpc_msg_send (rpc_client, &msg))
    {
        INC_COUNTER (counters.proxied_timeout);
        ERROR ("No response from proxy for path \"%s\"\n", (char *)path);
        rpc_client_release (rpc, rpc_client, false);
        g_free (local_path);
        return NULL;
    }

    root = rpc_msg_decode_tree (&msg);

    /* Prepend this remote tree with our proxy path */
    if (root)
    {
        gchar *new_root_key = g_strdup_printf("%s%s", local_path, APTERYX_NAME(root));
        g_free(root->data);
        root->data = new_root_key;
    }
    g_free (local_path);

    rpc_msg_reset (&msg);
    rpc_client_release (rpc, rpc_client, true);

    return root;
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

/* Removes a node and any hanging parents from a GNode tree */
static GNode *
remove_node (GNode *_root, const char *_path)
{
    gchar *path = g_strdup (_path);
    GNode *root = _root;
    char *tok;
    char *chunk;

    /* Skip forward - the path really should start with the key of the
     * root node.
     */
    if (strncmp(APTERYX_NAME(root), path, strlen(APTERYX_NAME(root))) != 0)
    {
        return _root;
    }

    /* This tree consists of a single node that we are removing. */
    if (strlen(path + strlen (APTERYX_NAME (root))) == 0)
    {
        /* Got it in one. */
        g_node_unlink (root);
        g_free (APTERYX_NAME (root));
        g_free (APTERYX_VALUE (root));
        g_node_destroy (root);
        root = NULL;
        goto exit;
    }

    /* Skip past the root node part of the path */
    chunk = strtok_r (path + strlen (APTERYX_NAME(root)), "/", &tok);
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
    GList *ipath;
    const char *path;
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

    /* Remove any duplicate nodes */
    apteryx_uniqify_tree (root, g_free);

    if (!root)
    {
        ERROR ("SET: Failed to decode message\n");
        return false;
    }
    DEBUG ("SET:\n");
    DEBUG_TREE (root);

    /* Figure out if we need the lists for checking callbacks */
    _node_to_path(root, &root_path);
    if (config_tree_has_proxies(root_path) ||
        config_tree_has_validators(root_path))
    {
        /* If we have to search for any proxies / validators then build a list
            * of paths + values.
            */
        g_node_traverse (root, G_PRE_ORDER, G_TRAVERSE_NON_LEAFS, -1, _gather_values, &lists);
    }

    INC_COUNTER (counters.set);

    /* Don't bother with this loop if there are no proxies */
    if (config_tree_has_proxies(root_path))
    {
        /* Proxy first */
        ipath = g_list_first (lists.paths);
        ivalue = g_list_first (lists.values);
        for (ipath = g_list_first (lists.paths), ivalue = lists.values; ipath; ipath=ipath->next, ivalue = ivalue->next)
        {
            path = (const char *) ipath->data;
            value = (const char *) ivalue->data;
            if (value && value[0] == '\0')
                value = NULL;

            proxy_result = proxy_set (path, value, ts);
            if (proxy_result == 0 && root)
            {
                /* Result success */
                DEBUG ("SET: %s = %s proxied\n", path, value);
                /* Call any watchers */
                GNode *proxy_tree = APTERYX_NODE(NULL, g_strdup(""));
                apteryx_path_to_node(proxy_tree, path, value);
                notify_watchers (proxy_tree, ack, msg->ns, msg->pid);
                apteryx_free_tree(proxy_tree);

                /* This value needs to be removed from the tree */
                root = remove_node(root, path);
                continue;
            }
            else if (proxy_result < 0)
            {
                result = proxy_result;
                goto exit;
            }
        }
    }

    /* Validate, if there are any present */
    if (config_tree_has_validators(root_path))
    {
        for (ipath = g_list_first (lists.paths), ivalue = g_list_first (lists.values);
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

    if (root)
    {
        /* Set in the database */
        pthread_rwlock_wrlock (&db_lock);
        db_result = db_update_no_lock (root, ts);
        if (!db_result)
        {
            DEBUG ("SET: tree rejected by DB (%" PRIu64 ")\n", ts);
            result = -EBUSY;
        }
        pthread_rwlock_unlock (&db_lock);
    }


exit:
    g_list_free_full (lists.paths, g_free);
    g_list_free_full (lists.values, g_free);
    /* Return result and notify watchers */
    if (validation_result >= 0 && result == 0)
    {
        /* Notify watchers, if any are present */
        if (config_tree_has_watchers (root_path))
        {
            notify_watchers (root, ack, msg->ns, msg->pid);
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
    g_free (root_path);
    apteryx_free_tree (root);
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
        call_refreshers (path, false);

        /* Provide second */
        if ((value = provide_get (path)) == NULL)
        {
            /* Database third */
            if (!db_get (path, (unsigned char**)&value, &vsize))
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
            call_refreshers (path, false);

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
    if (matches)
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
_traverse_paths (GNode **root, const char *path, char cb_lookup)
{
    /* Grab the entire content of the database below here */
    *root = db_get_all(path);
}

static void
refreshers_traverse (const char *top_path, char cb_lookup, bool top_level)
{
    GList *iter, *paths = NULL;
    gchar *needle = g_strdup_printf("%s/", top_path);

    /* We need to check this node as well as any children */
    call_refreshers (top_path, false);
    call_refreshers (needle, false);

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

    cb_lookup = _update_path_callbacks (top_path, cb_lookup);
    free (needle);

    for (iter = paths; iter; iter = g_list_next (iter))
    {
        const char *path = (const char *) iter->data;
        refreshers_traverse (path, cb_lookup, false);
    }
    g_list_free_full (paths, g_free);
}

static GList *
collect_provided_paths(const char *_path, GNode *root)
{
    gchar *path = _path ? g_strdup(_path) : apteryx_node_path(root);
    GList *result = NULL;
    GList *provided_paths = NULL;

    if (!config_tree_has_providers(path))
    {
        goto exit;
    }

    /* Get the matches at this level */
    GList *search_result = config_get_providers(path);
    if(search_result)
    {
        provided_paths = g_list_prepend(provided_paths, g_strdup(path));
        g_list_free_full (search_result, (GDestroyNotify) cb_release);
    }

    gchar *needle = g_strdup_printf("%s/", path);
    index_get(needle, &result);
    result = g_list_concat(result, config_search_providers(needle));
    result = g_list_concat(result, config_search_indexers(needle));
    result = g_list_concat(result, db_search(needle));
    g_free(needle);

    /* We need to make these lists unique without iterating them over and over */
    GHashTable *uniq_paths = g_hash_table_new (g_str_hash, g_str_equal);
    for (GList *iter = result; iter; iter = iter->next)
    {
        g_hash_table_insert(uniq_paths, iter->data, iter->data);
    }
    GHashTableIter uniq_iter;
    gpointer key, value;
    g_hash_table_iter_init (&uniq_iter, uniq_paths);
    while (g_hash_table_iter_next (&uniq_iter, &key, &value))
    {
        /* Do something with key and value */
        provided_paths = g_list_concat(provided_paths, collect_provided_paths(key, root));
    }

    /* Clean up temp structures */
    g_hash_table_destroy(uniq_paths);
    g_list_free_full(result, g_free);

exit:
    g_free(path);
    return provided_paths;
}

static bool
handle_traverse (rpc_message msg)
{
    const char *path;
    const char *value;
    char *p = NULL;
    GList *paths = NULL;
    GList *ipath;
    GList *values = NULL;
    GList *ivalue;
    GNode *root = NULL;
    GList *providers = NULL;

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
    refreshers_traverse (path, cb_all, true);

    /* Proxy first */
    if (!proxy_traverse (&paths, &values, path))
    {
        /* Grab everything from the database */
        _traverse_paths (&root, path, cb_all);
    }
    else {
        p = g_strdup(path);
        root = APTERYX_NODE (NULL, p);
    }

    /* Build a list of provided paths by filling in any * nodes with values from
     * either callbacks or the database
     */
    providers = collect_provided_paths(NULL, root);
    for (GList *iter = providers; iter; iter = iter->next)
    {
        char *fetched_value = provide_get (iter->data);
        if (fetched_value)
        {
            paths = g_list_prepend(paths, g_strdup(iter->data));
            values = g_list_prepend(values, fetched_value);
        }
    }
    g_list_free_full (providers, g_free);

    paths = g_list_reverse (paths);
    values = g_list_reverse (values);

    /* Send result */
    if (paths)
    {
        for (ipath = g_list_first (paths), ivalue = g_list_first (values);
            ipath && ivalue; ipath = g_list_next (ipath), ivalue = g_list_next (ivalue))
        {
            path = (char *) ipath->data;
            value = (char *) ivalue->data;
            /* Overwrite any database values with those from provide */
            apteryx_path_to_node (root, path, value ?: "");
        }
    }

    DEBUG ("TRAVERSE RESULT\n");
    DEBUG_TREE (root);

    rpc_msg_reset (msg);
    if (g_node_first_child(root))
        rpc_msg_encode_tree (msg, root);

    /* Paths / values are freed with the tree */
    g_list_free_full (paths, g_free);
    g_list_free_full (values, g_free);
    apteryx_free_tree (root);

    return true;
}

static GNode *
break_up_trunk(GNode *query)
{
    if (strcmp(query->data, "") == 0)
        return query;

    gchar *broken_key = g_strdup(query->data);
    GNode *old_root = query;
    GNode *new_root = APTERYX_NODE (NULL, g_strdup(""));
    query = new_root;
    char *next = broken_key;
    gchar *next_key;

    do
    {
        next_key = g_strdup(next + 1);
        if (strchr(next_key, '/'))
            *strchr(next_key, '/') = '\0';
        new_root = g_node_append_data(new_root, next_key);
        next = strchr(next + 1, '/');
    } while (next);

    g_node_prepend(new_root->parent, old_root);
    g_free(old_root->data);
    old_root->data = next_key;
    g_node_destroy(new_root);
    g_free(broken_key);

    return query;
}

GList *
collect_provided_paths_query(GNode *query)
{
    GList *matches = NULL;
    const char *match_key = query->data;
    char *path = apteryx_node_path (query);

    /* We don't need to go right to the end - that is a value */
    if (G_NODE_IS_LEAF(query))
    {
        free(path);
        return NULL;
    }

    if (strcmp(match_key, "") == 0)
    {
        matches = g_list_concat (matches, config_search_providers (path));
    }
    else if (strcmp(match_key, "*") == 0)
    {
        if (APTERYX_HAS_VALUE(query))
        {
            /* Get everything from here down */
            matches = collect_provided_paths(NULL, query->parent);
        }
        else
        {
            GList *result = NULL;
            gchar *ppath = apteryx_node_path (query->parent);
            gchar *needle = g_strdup_printf ("%s/", ppath);
            g_free (ppath);

            /* Look to see what this path could expand to */
            index_get (needle, &result);
            result = g_list_concat (result, config_search_providers (needle));
            g_free (needle);

            /* Free the wildcard key before we reuse this node in the next loop. */
            g_free (query->data);

            /* Call down the tree with the wildcard node replaced with the possible
             * values found via the indexer callbacks and searching the providers.
             */
            for (GList *iter = result; iter; iter = iter->next)
            {
                query->data = iter->data + strlen (path) - 1;
                for (GNode *child = g_node_first_child (query); child; child = g_node_next_sibling (child))
                {
                    matches = g_list_concat (matches, collect_provided_paths_query (child));
                }
            }
            g_list_free_full (result, g_free);

            /* Put the wildcard key back. */
            query->data = g_strdup ("*");
        }
    }
    else
    {
        if (g_node_first_child(query))
        {
            for (GNode *iter = g_node_first_child(query); iter; iter = g_node_next_sibling(iter))
            {
                /* Got to a leaf, we now need to search for providers that match. */
                if (iter->data == NULL)
                {
                    matches = g_list_concat (matches, config_search_providers (path));
                    break;
                }
                else
                {
                    matches = g_list_concat (matches, collect_provided_paths_query (iter));
                }
            }
        }
    }
    g_free (path);
    return matches;
}

static void _refresh_paths (GNode *node, gpointer data)
{
    /* Handle end of path matches (including wildcards) */
    if (g_node_n_children (node) == 1 && (!node->children->data || g_node_n_children (node->children) == 0))
    {
        char *path = NULL;
        _node_to_path (node, &path);
        call_refreshers (path, false);
        free (path);
    }

    /* Handle wildcards */
    if (g_strcmp0 (node->data, "*") == 0)
    {
        char *path = NULL;
        _node_to_path (node->parent, &path);

        /* Match any wildcard refreshers at this level */
        char *lpath = g_strdup_printf ("%s/", path);
        call_refreshers (lpath, false);
        free (lpath);

        /* Find matches for values in the DB */
        GList *paths = db_search (path);
        for (GList *iter = paths; iter; iter = iter->next)
        {
            GNode *fake, *child;

            if (g_node_n_children (node) == 1 && (!node->children->data || g_node_n_children (node->children) == 0))
            {
                fake = g_node_new ((char *)iter->data);
                child = g_node_prepend_data (fake, (gpointer)"*");
                g_node_prepend_data (child, (gpointer)NULL);
            }
            else
            {
                fake = g_node_copy (node);
                fake->data = (gpointer)iter->data;
            }
            _refresh_paths (fake, NULL);
            g_node_destroy (fake);
        }
        g_list_free_full(paths, g_free);
        free (path);
    }

    /* Traverse children */
    g_node_children_foreach (node, G_TRAVERSE_NON_LEAFS, _refresh_paths, NULL);
    return;
}

/* g_node_traverse function to check if we have any filters to work with */
static gboolean _tree_has_filter (GNode *node, gpointer data)
{
    if (node->data)
    {
        *((bool *)data) = true;
        return false;
    }
    return false;
}

/* Fill in values we know (ones that matched the filter) */
static gboolean _copy_filter_to_result (GNode *node, gpointer data)
{
    GNode *result = data;
    if (result && node && node->data)
    {
        char *path = apteryx_node_path(node->parent);
        apteryx_path_to_node(result, path, node->data);
        g_free(path);
    }
    return false;
}


static gboolean
_expand_wildcards (GNode *query_node, gpointer data)
{
    GNode *result_tree = data;
    GNode *next_node = NULL;
    GNode *child;

    char *path = apteryx_node_path(query_node);
    next_node = g_node_new(strdup(query_node->data));

    if (strcmp(query_node->data, "*") == 0)
    {
        /* Terminal *, we're done here. */
        if (G_NODE_IS_LEAF(g_node_first_child(query_node)))
        {
            g_node_prepend_data(next_node, g_node_first_child(query_node)->data ? strdup(g_node_first_child(query_node)->data) : NULL);
            goto done;
        }
        /* Need to find matches in the database for this tree */
        GList *paths = NULL;

        /* Chop off the trailing "/*" */
        path[strlen(path)-1] = '\0';

        /* Find the possible nodes below this one to match against. */
        paths = search_path (path);
        char *saved_key = query_node->data;
        for (GList *iter = paths; iter; iter = iter->next)
        {
            char *key = iter->data + strlen(path);
            query_node->data = strdup(key);
            _expand_wildcards (query_node, result_tree);
            free(query_node->data);
        }
        g_list_free_full(paths, g_free);
        query_node->data = saved_key;
        free(path);
        apteryx_free_tree(next_node);
        return true;
    }

    for (child = g_node_first_child(query_node); child; child = g_node_next_sibling(child))
    {
        if (G_NODE_IS_LEAF(child))
        {
            char *value = NULL;
            size_t length;

            if (child->data == NULL)
            {
                g_node_prepend_data(next_node, NULL);
            }
            else
            {
                /* Get values from database + providers. If a provider value matches
                 * here we won't call it again later - we will reuse the value from the
                 * filter (which we know to be the same).
                 */
                value = provide_get(path);
                if (!value)
                    db_get (path, (unsigned char**) &value, &length);

                if (value && strcmp(child->data, value) == 0)
                {
                    g_node_prepend_data(next_node, value);
                }
                else
                {
                    g_free(value);
                    break;
                }
            }
        }
        else if (child->data)
        {
            _expand_wildcards(child, next_node);
        }
    }

done:
    /* Got at least one match for each one... */
    if (g_node_n_children(query_node) <= g_node_n_children(next_node))
    {
        g_node_prepend(result_tree, next_node);
    }
    else
    {
        apteryx_free_tree(next_node);
    }
    free(path);
    return true;
}


static bool
handle_query (rpc_message msg)
{
    GList *paths = NULL;
    GList *providers, *ipath, *ivalue;
    gchar *path, *value;
    GNode *root = NULL;
    GNode *query;
    GList *values = NULL;

    DEBUG ("QUERY\n");
    INC_COUNTER (counters.query);

    GNode *query_head = rpc_msg_decode_tree(msg);
    if (!query_head)
    {
        goto done;
    }
    DEBUG_TREE (query_head);

    /* Get root path */
    char *root_path = apteryx_node_path(query_head);
    char *wildcard = strstr(root_path, "/*");
    if (wildcard)
        *wildcard = '\0';

    /* Sometimes the branch has stars in it. Break it up for processing */
    query_head = break_up_trunk(query_head);

    /* Proxy first */
    root = proxy_query (query_head, root_path);
    if (root)
    {
        /* Return result */
        free (root_path);
        goto done;
    }
    free (root_path);

    /* Attempt to call refreshers for all paths in the query */
    g_node_children_foreach (query_head, G_TRAVERSE_NON_LEAFS, _refresh_paths, NULL);

    /* If we have a filter adjust the query to only have matching subtrees */
    bool has_filter = false;
    g_node_traverse (query_head, G_PRE_ORDER, G_TRAVERSE_LEAFS, -1, _tree_has_filter, &has_filter);
    if (has_filter)
    {
        /* Fill the expanded tree in with matching paths */
        GNode *expanded_tree = APTERYX_NODE (NULL, strdup (""));
        g_node_traverse (query_head, G_PRE_ORDER, G_TRAVERSE_NON_LEAFS, 1, _expand_wildcards, expanded_tree);
        apteryx_free_tree (query_head);
        query_head = g_node_first_child (expanded_tree);
        if (query_head)
        {
            g_node_unlink (query_head);
        }
        apteryx_free_tree (expanded_tree);
        if (!query_head)
        {
            goto done;
        }
    }
    /* Query the database */
    root = db_query (query_head);

    /* Grab all providers that match this tree */
    query = g_node_first_child(query_head);

    providers = collect_provided_paths_query(query);
    paths = values = NULL;
    for (GList *iter = providers; iter; iter = iter->next)
    {
        char *fetched_value = provide_get (iter->data);
        if (fetched_value)
        {
            paths = g_list_prepend(paths, g_strdup(iter->data));
            values = g_list_prepend(values, fetched_value);
        }
    }
    g_list_free_full(providers, g_free);

    /* Jam results into the tree to send - if they match the query */
    if (paths)
    {
        /* In the case where the query returned nothing we need a root
         * node here to add the provided values, but not prior to this
         * if statement.
         */
        if (!root)
        {
            root = APTERYX_NODE (NULL, g_strdup (APTERYX_NAME (query_head)));
        }

        for (ipath = g_list_first (paths), ivalue = g_list_first (values);
            ipath && ivalue; ipath = g_list_next (ipath), ivalue = g_list_next (ivalue))
        {
            path = (char *) ipath->data;
            value = (char *) ivalue->data;
            /* Overwrite any database values with those from provide */
            apteryx_path_to_node (root, path, value);
        }
    }

    /* We won't call providers for the filtered values - fill them in from the query */
    g_node_traverse (query_head, G_PRE_ORDER, G_TRAVERSE_LEAFS, -1, _copy_filter_to_result, root);

    DEBUG ("QUERY RESULT");
    DEBUG_TREE (root);

    /* Send result */
done:
    rpc_msg_reset (msg);
    if (root)
        rpc_msg_encode_tree(msg, root);

    g_list_free_full (paths, g_free);
    g_list_free_full (values, g_free);

    if (query_head)
    {
        apteryx_free_tree(query_head);
    }
    if (root)
    {
        apteryx_free_tree(root);
    }

    return true;
}

static int
set_to_null (GNode *node, gpointer _unused)
{
    if (node->data)
        g_free (node->data);
    node->data = NULL;
    return false;
}

static bool
handle_prune (rpc_message msg)
{
    int32_t result = 0;
    const char *path;
    GList *paths = NULL;
    int32_t validation_result = 0;
    int validation_lock = 0;

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
    GNode *root = db_get_all(path);

    /* We are setting all these to NULL */
    g_node_traverse (root, G_IN_ORDER, G_TRAVERSE_LEAVES, -1, set_to_null, NULL);

    /* Call validators for each pruned path to ensure the path can be set to NULL. */
    if (config_tree_has_validators(path))
    {
        /* If we have to search for any proxies / validators / watchers then build a list
         * of paths + values.
         */
        key_value_lists lists = { NULL, NULL };
        g_node_traverse (root, G_PRE_ORDER, G_TRAVERSE_NON_LEAFS, -1, _gather_values, &lists);
        for (GList *iter = lists.paths; iter; iter = g_list_next (iter))
        {
            const char *v_path = (const char *)iter->data;
            validation_result = validate_set (v_path, NULL);
            if (validation_result != 0)
                validation_lock++;
            if (validation_result < 0)
            {
                DEBUG ("PRUNE: %s refused by validate\n", v_path);
                result = validation_result;
                break;
            }
        }
        g_list_free_full (lists.paths, g_free);
        g_list_free_full (lists.values, g_free);
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
        notify_watchers (root, false, msg->ns, msg->pid);
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
    apteryx_free_tree (root);
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
        if (config_tree_has_providers (path))
        {
            value = get_time_us ();
        }
        else
        {
            call_refreshers (path, false);
            value = db_timestamp (path);
        }
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
    if (path[0] == '.' && path[1] == '\0')
    {
        /* Total memory in use */
        struct mallinfo2 mi = mallinfo2 ();
        value = (unsigned int) (mi.uordblks) + (unsigned int) (mi.hblkhd);
    }
    else if (path[0] == '.' && path[1] == '.' && path[2] == '\0')
    {
        /* Total memory allocated */
        struct mallinfo2 mi = mallinfo2 ();
        value = (unsigned int) (mi.arena) + (unsigned int) (mi.hblkhd);
    }
    else
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
    printf ("Usage: apteryxd [-h] [-b] [-d] [-s] [-p <pidfile>] [-r <runfile>] [-l <url>]\n"
            "  -h   show this help\n"
            "  -b   background mode\n"
            "  -d   enable verbose debug\n"
            "  -s   reuse client sockets for callbacks\n"
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
    bool reuse_sock = false;
    pthread_mutexattr_t callback_recursive;
    FILE *fp;
    int i;
    /* Parse options */
    while ((i = getopt (argc, argv, "hdbsp:r:l:")) != -1)
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
        case 's':
            reuse_sock = true;
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
    rpc = rpc_init (RPC_TIMEOUT_US, reuse_sock, msg_handler);
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
    proxy_rpc = rpc_init (RPC_TIMEOUT_US, false, NULL);
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
        rpc = NULL;
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
