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
    buffer += sprintf (buffer, "%-24s%"PRIu32"\n", "watch", counters.watch);
    buffer += sprintf (buffer, "%-24s%"PRIu32"\n", "watch_invalid", counters.watch_invalid);
    buffer += sprintf (buffer, "%-24s%"PRIu32"\n", "unwatch", counters.unwatch);
    buffer += sprintf (buffer, "%-24s%"PRIu32"\n", "unwatch_invalid", counters.unwatch_invalid);
    buffer += sprintf (buffer, "%-24s%"PRIu32"\n", "watched", counters.watched);
    buffer += sprintf (buffer, "%-24s%"PRIu32"\n", "watched_no_match", counters.watched_no_match);
    buffer += sprintf (buffer, "%-24s%"PRIu32"\n", "watched_no_handler", counters.watched_no_handler);
    buffer += sprintf (buffer, "%-24s%"PRIu32"\n", "watched_timeout", counters.watched_timeout);
    buffer += sprintf (buffer, "%-24s%"PRIu32"\n", "validation", counters.validation);
    buffer += sprintf (buffer, "%-24s%"PRIu32"\n", "validation_invalid", counters.validation_invalid);
    buffer += sprintf (buffer, "%-24s%"PRIu32"\n", "unvalidation", counters.unvalidation);
    buffer += sprintf (buffer, "%-24s%"PRIu32"\n", "unvalidation_invalid", counters.unvalidation_invalid);
    buffer += sprintf (buffer, "%-24s%"PRIu32"\n", "provide", counters.provide);
    buffer += sprintf (buffer, "%-24s%"PRIu32"\n", "provide_invalid", counters.provide_invalid);
    buffer += sprintf (buffer, "%-24s%"PRIu32"\n", "unprovide", counters.unprovide);
    buffer += sprintf (buffer, "%-24s%"PRIu32"\n", "unprovide_invalid", counters.unprovide_invalid);
    buffer += sprintf (buffer, "%-24s%"PRIu32"\n", "provided", counters.provided);
    buffer += sprintf (buffer, "%-24s%"PRIu32"\n", "provided_no_handler", counters.provided_no_handler);
    buffer += sprintf (buffer, "%-24s%"PRIu32"\n", "prune", counters.prune);
    buffer += sprintf (buffer, "%-24s%"PRIu32"\n", "prune_invalid", counters.prune_invalid);
    buffer += sprintf (buffer, "%-24s%"PRIu32"\n", "get_timestamp", counters.get_ts);
    buffer += sprintf (buffer, "%-24s%"PRIu32"\n", "get_timestamp_invalid", counters.get_ts_invalid);

    return value;
}

char*
get_process_name_by_pid (int pid)
{
    char* name = (char*)calloc (1024, sizeof (char));
    if (name)
    {
        sprintf (name, "/proc/%d/cmdline",pid);
        FILE* f = fopen(name,"r");
        if (f)
        {
            size_t size;
            size = fread (name, sizeof (char), 1024, f);
            if (size>0)
            {
                char *app;
                if ('\n' == name[size-1])
                    name[size-1]='\0';
                app = strrchr (name, '/');
                if (app)
                    strncpy (name, app+1, strlen (app+1) + 1);
            }
            fclose (f);
        }
    }
    return name;
}

static char*
handle_callbacks_get (const char *path, void *priv)
{
    GList *list;
    GList *iter = NULL;
    char *res = NULL;
    int len;
    char *lname;

    switch ((size_t)priv)
    {
        case 0:
            list = watch_list;
            lname = "watches";
            break;
        case 1:
            list = validation_list;
            lname = "validations";
            break;
        case 2:
            list = provide_list;
            lname = "provides";
            break;
        default:
            list = watch_list;
            lname = "error (watches)";
            break;
    }
    len = asprintf (&res, "%s: %d\n", lname, g_list_length (list)) + 1;
    for (iter = list; iter && len; iter = iter->next)
    {
        cb_info_t *info = (cb_info_t *) iter->data;
        char *new = NULL;
        char *process = get_process_name_by_pid (info->id);
        len = asprintf (&new, "%s %-16s 0x%16.16"PRIx64" 0x%16.16"PRIx64" %-48s %"PRIu32"\n",
                res, process, info->cb, info->priv, info->path, info->count);
        free (process);
        if (len)
        {
            free (res);
            res = new;
        }
    }

    return res;
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
    info->path = strdup (APTERYX_SETTINGS"watchers");
    info->id = (uint64_t) getpid ();
    info->cb = (uint64_t) (size_t) handle_callbacks_get;
    info->priv = 0;
    provide_list = g_list_prepend (provide_list, info);

    /* Validations */
    info = (cb_info_t *) calloc (1, sizeof (cb_info_t));
    info->path = strdup (APTERYX_SETTINGS"validation");
    info->id = (uint64_t) getpid ();
    info->cb = (uint64_t) (size_t) handle_callbacks_get;
    info->priv = 1;
    provide_list = g_list_prepend (provide_list, info);

    /* Providers */
    info = (cb_info_t *) calloc (1, sizeof (cb_info_t));
    info->path = strdup (APTERYX_SETTINGS"providers");
    info->id = (uint64_t) getpid ();
    info->cb = (uint64_t) (size_t) handle_callbacks_get;
    info->priv = 2;
    provide_list = g_list_prepend (provide_list, info);

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
