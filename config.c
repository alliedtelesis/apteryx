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
#include "internal.h"

static bool
handle_debug_set (const char *path, void *priv, const char *value)
{
    if (value)
        debug = atoi (value);
    else
        debug = false;
    DEBUG ("DEBUG %s\n", debug ? "enabled" : "disabled");
    return true;
}

static bool
update_callback (GList **list, const char *guid, const char *value)
{
    cb_info_t *info;
    uint64_t pid, cb, hash;

    //TEMP until full URL client support implemented
    if (sscanf (guid, "%"PRIX64"-%"PRIx64"-%"PRIx64"", &pid, &cb, &hash) != 3)
    {
        ERROR ("Invalid GUID(%s)\n", guid);
        return false;
    }

    /* Find an existing callback */
    pthread_mutex_lock (&list_lock);
    info = cb_info_get (*list, guid);
    if (!info && !value)
    {
        pthread_mutex_unlock (&list_lock);
        ERROR ("Invalid Callback GUID(%s)\n", guid);
        return true;
    }

    /* New settings require a new callback */
    if (!info)
    {
        info = (cb_info_t *) calloc (1, sizeof (cb_info_t));
        info->guid = strdup (guid);
        *list = g_list_prepend (*list , info);
    }

    /* Make the change */
    if (value)
    {
        /* Create/update a callback */
        if (info->path)
            free ((void *) info->path);
        info->path = strdup (value);
        //TEMP until full URL client support implemented
        info->id = pid;
        info->cb = cb;
        info->priv = 0;
    }
    else
    {
        /* Remove the callback */
        *list = g_list_remove (*list, info);
        cb_info_destroy ((gpointer) info);
    }
    pthread_mutex_unlock (&list_lock);

    return true;
}

static bool
handle_watchers_set (const char *path, void *priv, const char *value)
{
    const char *guid = path + strlen (APTERYX_SETTINGS"watchers/");
    DEBUG ("CFG-Watch: %s = %s\n", guid, value);
    return update_callback (&watch_list, guid, value);
}

static bool
handle_providers_set (const char *path, void *priv, const char *value)
{
    const char *guid = path + strlen (APTERYX_SETTINGS"providers/");
    DEBUG ("CFG-Provide: %s = %s\n", guid, value);
    return update_callback (&provide_list, guid, value);
}

static bool
handle_validators_set (const char *path, void *priv, const char *value)
{
    const char *guid = path + strlen (APTERYX_SETTINGS"validators/");
    DEBUG ("CFG-Validate: %s = %s\n", guid, value);
    return update_callback (&validation_list, guid, value);
}

static char*
handle_counters_get (const char *path, void *priv)
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
    buffer += sprintf (buffer, "%-24s%"PRIu32"\n", "watched_no_match", counters.watched_no_match);
    buffer += sprintf (buffer, "%-24s%"PRIu32"\n", "watched_no_handler", counters.watched_no_handler);
    buffer += sprintf (buffer, "%-24s%"PRIu32"\n", "watched_timeout", counters.watched_timeout);
    buffer += sprintf (buffer, "%-24s%"PRIu32"\n", "validation", counters.validation);
    buffer += sprintf (buffer, "%-24s%"PRIu32"\n", "validation failed", counters.validation_failed);
    buffer += sprintf (buffer, "%-24s%"PRIu32"\n", "provided", counters.provided);
    buffer += sprintf (buffer, "%-24s%"PRIu32"\n", "provided_no_handler", counters.provided_no_handler);
    buffer += sprintf (buffer, "%-24s%"PRIu32"\n", "prune", counters.prune);
    buffer += sprintf (buffer, "%-24s%"PRIu32"\n", "prune_invalid", counters.prune_invalid);
    buffer += sprintf (buffer, "%-24s%"PRIu32"\n", "get_timestamp", counters.get_ts);
    buffer += sprintf (buffer, "%-24s%"PRIu32"\n", "get_timestamp_invalid", counters.get_ts_invalid);

    return value;
}

#ifdef USE_SHM_CACHE
static char*
handle_cache_get (const char *path, void *priv)
{
    return cache_dump_table ();
}
#endif

void
config_init (void)
{
    cb_info_t *info;

    /* Debug set */
    info = (cb_info_t *) calloc (1, sizeof (cb_info_t));
    info->path = strdup (APTERYX_SETTINGS"debug");
    info->id = (uint64_t) getpid ();
    info->cb = (uint64_t) (size_t) handle_debug_set;
    info->priv = 0;
    watch_list = g_list_prepend (watch_list, info);

    /* Counters */
    info = (cb_info_t *) calloc (1, sizeof (cb_info_t));
    info->path = strdup (APTERYX_SETTINGS"counters");
    info->id = (uint64_t) getpid ();
    info->cb = (uint64_t) (size_t) handle_counters_get;
    info->priv = 0;
    provide_list = g_list_prepend (provide_list, info);

    /* Watchers */
    info = (cb_info_t *) calloc (1, sizeof (cb_info_t));
    info->path = strdup (APTERYX_SETTINGS"watchers/");
    info->id = (uint64_t) getpid ();
    info->cb = (uint64_t) (size_t) handle_watchers_set;
    info->priv = 0;
    watch_list = g_list_prepend (watch_list, info);

    /* Providers */
    info = (cb_info_t *) calloc (1, sizeof (cb_info_t));
    info->path = strdup (APTERYX_SETTINGS"providers/");
    info->id = (uint64_t) getpid ();
    info->cb = (uint64_t) (size_t) handle_providers_set;
    info->priv = 0;
    watch_list = g_list_prepend (watch_list, info);

    /* Validators */
    info = (cb_info_t *) calloc (1, sizeof (cb_info_t));
    info->path = strdup (APTERYX_SETTINGS"validators/");
    info->id = (uint64_t) getpid ();
    info->cb = (uint64_t) (size_t) handle_validators_set;
    info->priv = 0;
    watch_list = g_list_prepend (watch_list, info);

#ifdef USE_SHM_CACHE
    /* Cache */
    info = (cb_info_t *) calloc (1, sizeof (cb_info_t));
    info->path = strdup (APTERYX_SETTINGS"cache");
    info->id = (uint64_t) getpid ();
    info->cb = (uint64_t) (size_t) handle_cache_get;
    info->priv = 0;
    provide_list = g_list_prepend (provide_list, info);
#endif
}
