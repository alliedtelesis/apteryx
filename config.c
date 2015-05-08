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

static bool
handle_debug_set (const char *path, const char *value)
{
    if (value)
        debug = atoi (value);
    else
        debug = false;
    DEBUG ("DEBUG %s\n", debug ? "enabled" : "disabled");
    return true;
}

static bool
handle_sockets_set (const char *path, const char *value)
{
    const char *guid = path + strlen (APTERYX_SOCKETS_PATH"/");
    bool res = true;

    DEBUG ("SOCKET %s:%s\n", guid, value);

    if (value)
        res = rpc_bind_url (guid, value);
    else
        res = rpc_unbind_url (guid, value);

    return res;
}

static cb_info_t *
update_callback (GList **list, const char *guid, const char *value)
{
    cb_info_t *cb;
    uint64_t pid, callback, hash;

    /* Parse callback info from the encoded guid */
    if (sscanf (guid, "%"PRIX64"-%"PRIx64"-%"PRIx64"",
            &pid, &callback, &hash) != 3)
    {
        ERROR ("Invalid GUID (%s)\n", guid ?: "NULL");
        return NULL;
    }

    /* Find an existing callback */
    cb = cb_find (list, guid);
    if (!cb && !value)
    {
        DEBUG ("Non-existant Callback GUID(%s)\n", guid);
        return NULL;
    }
    else if (cb && value)
    {
        DEBUG ("Callback GUID(%s) already exists - releasing old version\n", guid);
        cb_destroy (cb);
        cb_release (cb);
    }

    /* Create or destroy */
    if (value)
    {
        /* Create a callback */
        DEBUG ("Callback GUID(%s) created\n", guid);
        cb = cb_create (list, guid, value, pid, callback);
    }
    else
    {
        /* Remove the callback */
        DEBUG ("Callback GUID(%s) released\n", guid);
        cb_destroy (cb);
    }

    /* Return the reference */
    return cb;
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

    cb = update_callback (&proxy_list, guid, value);
    if (cb && value)
    {
        if (strncmp (value, "unix://", 7) != 0 &&
            strncmp (value, "tcp://", 6) != 0)
        {
            ERROR ("Invalid Callback URL (%s)\n", value);
            cb_release (cb);
            return false;
        }
        path = strrchr (value, ':') + 1;
        if (cb->uri)
            free ((void *) cb->uri);
        cb->uri = strndup (value, strlen (value) - strlen (path) - 1);
        strcpy ((char*)cb->path, path);
        DEBUG ("CFG-Proxy: %s to %s\n", cb->path, cb->uri);
    }
    cb_release (cb);
    return true;
}

static char*
handle_counters_get (const char *path)
{
    char *value;
    char *buffer = NULL;

    value = buffer = malloc (4096); /* Currently around 500 bytes */

    buffer += sprintf (buffer, "\n");
    buffer += sprintf (buffer, "%-24s%"PRIu32"\n", "set", counters.set);
    buffer += sprintf (buffer, "%-24s%"PRIu32"\n", "set_invalid", counters.set_invalid);
    buffer += sprintf (buffer, "%-24s%"PRIu32"\n", "get", counters.get);
    buffer += sprintf (buffer, "%-24s%"PRIu32"\n", "get_invalid", counters.get_invalid);
    buffer += sprintf (buffer, "%-24s%"PRIu32"\n", "search", counters.search);
    buffer += sprintf (buffer, "%-24s%"PRIu32"\n", "search_invalid", counters.search_invalid);
    buffer += sprintf (buffer, "%-24s%"PRIu32"\n", "watched", counters.watched);
    buffer += sprintf (buffer, "%-24s%"PRIu32"\n", "watched_no_handler", counters.watched_no_handler);
    buffer += sprintf (buffer, "%-24s%"PRIu32"\n", "watched_timeout", counters.watched_timeout);
    buffer += sprintf (buffer, "%-24s%"PRIu32"\n", "validated", counters.validated);
    buffer += sprintf (buffer, "%-24s%"PRIu32"\n", "validated_no_handler", counters.validated_no_handler);
    buffer += sprintf (buffer, "%-24s%"PRIu32"\n", "validated_timeout", counters.validated_timeout);
    buffer += sprintf (buffer, "%-24s%"PRIu32"\n", "provided", counters.provided);
    buffer += sprintf (buffer, "%-24s%"PRIu32"\n", "provided_no_handler", counters.provided_no_handler);
    buffer += sprintf (buffer, "%-24s%"PRIu32"\n", "provided_timeout", counters.provided_timeout);
    buffer += sprintf (buffer, "%-24s%"PRIu32"\n", "proxied", counters.proxied);
    buffer += sprintf (buffer, "%-24s%"PRIu32"\n", "proxied_no_handler", counters.proxied_no_handler);
    buffer += sprintf (buffer, "%-24s%"PRIu32"\n", "proxied_timeout", counters.proxied_timeout);
    buffer += sprintf (buffer, "%-24s%"PRIu32"\n", "prune", counters.prune);
    buffer += sprintf (buffer, "%-24s%"PRIu32"\n", "prune_invalid", counters.prune_invalid);
    buffer += sprintf (buffer, "%-24s%"PRIu32"\n", "get_timestamp", counters.get_ts);
    buffer += sprintf (buffer, "%-24s%"PRIu32"\n", "get_timestamp_invalid", counters.get_ts_invalid);

    return value;
}

#ifdef USE_SHM_CACHE
static char*
handle_cache_get (const char *path)
{
    return cache_dump_table ();
}
#endif

void
config_init (void)
{
    cb_info_t *cb;

    /* Debug set */
    cb = cb_create (&watch_list, "debug", APTERYX_DEBUG_PATH,
            (uint64_t) getpid (), (uint64_t) (size_t) handle_debug_set);
    cb_release (cb);

    /* Counters */
    cb = cb_create (&provide_list, "counters", APTERYX_COUNTERS,
            (uint64_t) getpid (), (uint64_t) (size_t) handle_counters_get);
    cb_release (cb);

    /* Sockets */
    cb = cb_create (&watch_list, "sockets", APTERYX_SOCKETS_PATH"/",
            (uint64_t) getpid (), (uint64_t) (size_t) handle_sockets_set);
    cb_release (cb);

    /* Watchers */
    cb = cb_create (&watch_list, "watchers", APTERYX_WATCHERS_PATH"/",
            (uint64_t) getpid (), (uint64_t) (size_t) handle_watchers_set);
    cb_release (cb);

    /* Providers */
    cb = cb_create (&watch_list, "providers", APTERYX_PROVIDERS_PATH"/",
            (uint64_t) getpid (), (uint64_t) (size_t) handle_providers_set);
    cb_release (cb);

    /* Validators */
    cb = cb_create (&watch_list, "validators", APTERYX_VALIDATORS_PATH"/",
            (uint64_t) getpid (), (uint64_t) (size_t) handle_validators_set);
    cb_release (cb);

    /* Proxies */
    cb = cb_create (&watch_list, "proxies", APTERYX_PROXIES_PATH"/",
            (uint64_t) getpid (), (uint64_t) (size_t) handle_proxies_set);
    cb_release (cb);

#ifdef USE_SHM_CACHE
    /* Cache */
    cb = cb_create (&watch_list, "cache", APTERYX_CACHE,
            (uint64_t) getpid (), (uint64_t) (size_t) handle_cache_get);
    cb_release (cb);
#endif
}
