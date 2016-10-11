/**
 * @file rpc.c
 * Used for back-end storage of AWP Info data.
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
#include "internal.h"
#include "apteryx.h"

bool
rpc_init (void)
{
    return true;
}

void
rpc_shutdown (bool force)
{

}

GList*
rpc_index_search (const char *path)
{
    GList *indexers = NULL;
    GList *results = NULL;
    GList *iter = NULL;

    /* Retrieve a list of providers for this path */
    indexers = cb_match (&index_list, path,
            CB_MATCH_EXACT|CB_MATCH_WILD|CB_MATCH_CHILD);
    if (!indexers)
    {
        return NULL;
    }

    /* Find the first good indexer */
    for (iter = indexers; iter; iter = g_list_next (iter))
    {
        cb_info_t *indexer = iter->data;

        DEBUG ("INDEX CB \"%s\" (0x%"PRIx64",0x%"PRIx64")\n",
                indexer->path, indexer->id, indexer->cb);

        apteryx_index_callback cb = (apteryx_index_callback) (long) indexer->cb;
        results = cb (path);
        break;
    }
    g_list_free_full (indexers, (GDestroyNotify) cb_release);

    return results;
}

void
rpc_notify_watchers (const char *path, const char *value)
{
    GList *watchers = NULL;
    GList *iter = NULL;

    /* Retrieve a list of watchers for this path */
    watchers = cb_match (&watch_list, path,
            CB_MATCH_EXACT|CB_MATCH_WILD|CB_MATCH_CHILD|CB_MATCH_WILD_PATH);
    if (!watchers)
        return;

    /* Call each watcher */
    for (iter = watchers; iter; iter = g_list_next (iter))
    {
        cb_info_t *watcher = iter->data;

        DEBUG ("WATCH CB %s = %s (%s 0x%"PRIx64",0x%"PRIx64",%s)\n",
                path, value, watcher->path, watcher->id, watcher->cb, watcher->uri);

        apteryx_watch_callback cb = (apteryx_watch_callback) (long) watcher->cb;
        DEBUG ("WATCH \"%s\" (0x%"PRIx64",0x%"PRIx64")\n",
                watcher->path, watcher->id, watcher->cb);
        cb (path, value);
    }
    g_list_free_full (watchers, (GDestroyNotify) cb_release);
}

int
rpc_validate_set (const char *path, const char *value)
{
    GList *validators = NULL;
    GList *iter = NULL;
    int32_t result = 0;

    /* Retrieve a list of validators for this path */
    validators = cb_match (&validation_list, path,
            CB_MATCH_EXACT|CB_MATCH_WILD|CB_MATCH_CHILD|CB_MATCH_WILD_PATH);
    if (!validators)
        return 0;

    /* Call each validator */
    for (iter = validators; iter; iter = g_list_next (iter))
    {
        cb_info_t *validator = iter->data;

        DEBUG ("VALIDATE CB %s = %s (0x%"PRIx64",0x%"PRIx64")\n",
                 validator->path, value, validator->id, validator->cb);

        apteryx_validate_callback cb = (apteryx_validate_callback) (long) validator->cb;
        result = cb (path, value);
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

char*
rpc_provide_get (const char *path)
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

        DEBUG ("PROVIDE CB \"%s\" (0x%"PRIx64",0x%"PRIx64")\n",
               provider->path, provider->id, provider->cb);

        apteryx_provide_callback cb = (apteryx_provide_callback) (long) provider->cb;
        DEBUG ("PROVIDE LOCAL \"%s\" (0x%"PRIx64",0x%"PRIx64")\n",
                                   provider->path, provider->id, provider->cb);
        value = cb (path);
        break;
    }
    g_list_free_full (providers, (GDestroyNotify) cb_release);

    return value;
}
