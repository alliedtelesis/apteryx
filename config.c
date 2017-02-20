/**
 * @file config.c
 * Used for Apteryx configuration by Apteryx.
 *
 * Copyright 2015, Allied Telesis Labs New Zealand, Ltd
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
#include <glib.h>
#include "apteryx.h"
#include "internal.h"

/* RPC Service */
extern rpc_instance rpc;

/* Callback structures */
static struct callback_node *watch_list;
static struct callback_node *validation_list;
static struct callback_node *provide_list;
static struct callback_node *index_list;
static struct callback_node *proxy_list;
static GHashTable *guid_to_callback = NULL;

static bool
handle_debug_set (const char *path, const char *value)
{
    if (value)
        apteryx_debug = atoi (value);
    else
        apteryx_debug = false;
    DEBUG ("DEBUG %s\n", apteryx_debug ? "enabled" : "disabled");
    return true;
}

static bool
handle_sockets_set (const char *path, const char *value)
{
    const char *guid = path + strlen (APTERYX_SOCKETS_PATH "/");
    bool res = true;

    DEBUG ("SOCKET %s:%s\n", guid, value);

    if (value)
        res = rpc_server_bind (rpc, guid, value);
    else
        res = rpc_server_release (rpc, guid);

    return res;
}

static cb_info_t *
find_callback (const char *guid)
{
    cb_info_t *found = g_hash_table_lookup (guid_to_callback, guid);
    if (found)
    {
        cb_take (found);
    }
    return found;
}

static cb_info_t *
update_callback (struct callback_node *list, const char *guid, const char *value)
{
    cb_info_t *cb;
    uint64_t pid, callback, hash;

    /* Parse callback info from the encoded guid */
    if (sscanf (guid, "%" PRIX64 "-%" PRIx64 "-%" PRIx64 "", &pid, &callback, &hash) != 3)
    {
        ERROR ("Invalid GUID (%s)\n", guid ? : "NULL");
        return NULL;
    }

    /* Find an existing callback */
    cb = find_callback (guid);
    if (!cb && !value)
    {
        DEBUG ("Attempting to remove non-existant Callback GUID(%s)\n", guid);
        return NULL;
    }
    else if (cb && value)
    {
        DEBUG ("Callback GUID(%s) already exists - releasing old version\n", guid);
        g_hash_table_remove (guid_to_callback, (char *) cb->guid);
        cb_disable (cb);
        cb_release (cb);
    }

    /* Create or destroy */
    if (value)
    {
        /* Create a callback */
        DEBUG ("Callback GUID(%s) created\n", guid);
        if (cb)
        {
            cb_disable (cb);
            cb_release (cb);
        }
        cb = cb_create (list, guid, value, pid, callback);

        /* This will either replace the entry removed above, or add a new one. */
        g_hash_table_replace (guid_to_callback, (char *) cb->guid, cb);
    }
    else
    {
        /* Remove the callback */
        DEBUG ("Callback GUID(%s) released\n", guid);
        if (cb)
        {
            g_hash_table_remove (guid_to_callback, (char *) cb->guid);
            cb_disable (cb);
            cb_release (cb);
        }
    }

    /* Return the reference */
    return cb;
}

static bool
handle_indexers_set (const char *path, const char *value)
{
    const char *guid = path + strlen (APTERYX_INDEXERS_PATH"/");
    cb_info_t *cb;

    DEBUG ("CFG-Index: %s = %s\n", guid, value);

    cb = update_callback (&index_list, guid, value);
    cb_release (cb);
    return true;
}

static bool
handle_watchers_set (const char *path, const char *value)
{
    const char *guid = path + strlen (APTERYX_WATCHERS_PATH"/");
    cb_info_t *cb;

    DEBUG ("CFG-Watch: %s = %s\n", guid, value);

    cb = update_callback (&watch_list, guid, value);
    cb_release (cb);
    return true;
}

static bool
handle_providers_set (const char *path, const char *value)
{
    const char *guid = path + strlen (APTERYX_PROVIDERS_PATH"/");
    cb_info_t *cb;

    DEBUG ("CFG-Provide: %s = %s\n", guid, value);

    cb = update_callback (&provide_list, guid, value);
    cb_release (cb);
    return true;
}

static bool
handle_validators_set (const char *path, const char *value)
{
    const char *guid = path + strlen (APTERYX_VALIDATORS_PATH"/");
    cb_info_t *cb;

    DEBUG ("CFG-Validate: %s = %s\n", guid, value);

    cb = update_callback (&validation_list, guid, value);
    cb_release (cb);
    return true;
}

static bool
handle_proxies_set (const char *path, const char *value)
{
    const char *guid = path + strlen (APTERYX_PROXIES_PATH"/");
    cb_info_t *cb;

    DEBUG ("CFG-Proxy: %s = %s\n", guid, value);

    if (value)
    {
        if (value &&
            strncmp (value, "unix://", 7) != 0 &&
            strncmp (value, "tcp://", 6) != 0)
        {
            ERROR ("Invalid Callback URL (%s)\n", value);
            return false;
        }
        path = strrchr (value, ':') + 1;
        cb = update_callback (proxy_list, guid, path);
        if (cb->uri)
        {
            g_free ((void *) cb->uri);
        }
        cb->uri = g_strndup (value, strlen (value) - strlen (path) - 1);
        strcpy ((char*)cb->path, path);
        DEBUG ("CFG-Proxy: %s to %s\n", cb->path, cb->uri);
    }
    else
    {
        cb = find_callback (guid);
    }
    cb_release (cb);
    return true;
}


static GList*
handle_counters_index (const char *path)
{
    GList *paths = NULL;
#define X(type, name) \
    paths = g_list_append (paths, strdup (APTERYX_COUNTERS"/"#name));
X_FIELDS
#undef X
    return paths;
}

static char*
handle_counters_get (const char *path)
{
    char *counter = strrchr (path, '/');
    char *value = NULL;
#define X(type, name) \
    if (strcmp ("/"#name, counter) == 0 && \
        asprintf (&value, "%d", counters.name) > 0) \
        return value;
    X_FIELDS
#undef X
    return value;
}

void
config_shutdown ()
{
    cb_shutdown (watch_list);
    cb_shutdown (validation_list);
    cb_shutdown (provide_list);
    cb_shutdown (index_list);
    cb_shutdown (proxy_list);
}

GList *
config_get_indexers (const char *path)
{
    return cb_match (index_list, path);
}

GList *
config_search_providers (const char *path)
{
    return cb_search (provide_list, path);
}

GList *
config_get_providers (const char *path)
{
    return cb_match (provide_list, path);
}

GList *
config_get_proxies (const char *path)
{
    return cb_match (proxy_list, path);
}

GList *
config_get_watchers (const char *path)
{
    return cb_match (watch_list, path);
}

GList *
config_get_validators (const char *path)
{
    return cb_match (validation_list, path);
}

void
config_init (void)
{
    cb_info_t *cb;

    watch_list = cb_init ();
    validation_list = cb_init ();
    provide_list = cb_init ();
    index_list = cb_init ();
    proxy_list = cb_init ();

    guid_to_callback = g_hash_table_new (g_str_hash, g_str_equal);

    /* Debug set */
    cb = cb_create (watch_list, "debug", APTERYX_DEBUG_PATH,
                    (uint64_t) getpid (), (uint64_t) (size_t) handle_debug_set);
    cb_release (cb);

    /* Counters */
    cb = cb_create (index_list, "counters", APTERYX_COUNTERS "/",
                    (uint64_t) getpid (), (uint64_t) (size_t) handle_counters_index);
    cb_release (cb);
    cb = cb_create (provide_list, "counters", APTERYX_COUNTERS "/",
                    (uint64_t) getpid (), (uint64_t) (size_t) handle_counters_get);
    cb_release (cb);

    /* Sockets */
    cb = cb_create (watch_list, "sockets", APTERYX_SOCKETS_PATH "/",
                    (uint64_t) getpid (), (uint64_t) (size_t) handle_sockets_set);
    cb_release (cb);

    /* Indexers */
    cb = cb_create (watch_list, "indexers", APTERYX_INDEXERS_PATH "/",
                    (uint64_t) getpid (), (uint64_t) (size_t) handle_indexers_set);
    cb_release (cb);

    /* Watchers */
    cb = cb_create (watch_list, "watchers", APTERYX_WATCHERS_PATH "/",
                    (uint64_t) getpid (), (uint64_t) (size_t) handle_watchers_set);
    cb_release (cb);

    /* Providers */
    cb = cb_create (watch_list, "providers", APTERYX_PROVIDERS_PATH "/",
                    (uint64_t) getpid (), (uint64_t) (size_t) handle_providers_set);
    cb_release (cb);

    /* Validators */
    cb = cb_create (watch_list, "validators", APTERYX_VALIDATORS_PATH "/",
                    (uint64_t) getpid (), (uint64_t) (size_t) handle_validators_set);
    cb_release (cb);

    /* Proxies */
    cb = cb_create (watch_list, "proxies", APTERYX_PROXIES_PATH "/",
                    (uint64_t) getpid (), (uint64_t) (size_t) handle_proxies_set);
    cb_release (cb);
    if (!cb)
    {
        return;
    }
}
