/**
 * @file callbacks.c
 * Used for a watchers, providers, validators and proxies.
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

GList *watch_list = NULL;
GList *validation_list = NULL;
GList *provide_list = NULL;
GList *proxy_list = NULL;
static pthread_mutex_t list_lock = PTHREAD_MUTEX_INITIALIZER;

cb_info_t *
cb_create (GList **list, const char *guid, const char *path,
        uint64_t id, uint64_t callback)
{
    cb_info_t *cb = (cb_info_t *) calloc (1, sizeof (cb_info_t));
    cb->active = true;
    cb->guid = strdup (guid);
    cb->path = strdup (path);
    cb->id = id;
    cb->cb = callback;
    cb->list = list;
    cb->refcnt = 1;
    cb->refcnt++;
    pthread_mutex_lock (&list_lock);
    *list = g_list_prepend (*list, cb);
    pthread_mutex_unlock (&list_lock);
    return cb;
}

static void
cb_free (gpointer data, void *param)
{
    cb_info_t *cb = (cb_info_t*)data;
    if (cb->list)
        *cb->list = g_list_remove (*cb->list, cb);
    if (cb->guid)
        free ((void *) cb->guid);
    if (cb->path)
        free ((void *) cb->path);
    if (cb->uri)
        free ((void *) cb->uri);
    free (cb);
}

void
cb_destroy (cb_info_t *cb)
{
    cb->active = false;
}

void
cb_release (cb_info_t *cb)
{
    if (!cb)
        return;
    pthread_mutex_lock (&list_lock);
    cb->refcnt--;
    if ((!cb->active && cb->refcnt == 1) || cb->refcnt <= 0)
    {
        cb_free (cb, NULL);
    }
    pthread_mutex_unlock (&list_lock);
}

cb_info_t *
cb_find (GList **list, const char *guid)
{
    GList *iter = NULL;
    cb_info_t *cb;

    pthread_mutex_lock (&list_lock);
    for (iter = *list; iter; iter = iter->next)
    {
        cb = (cb_info_t *) iter->data;
        if (cb->active && cb->guid && strcmp (cb->guid, guid) == 0)
        {
            cb->refcnt++;
            break;
        }
        cb = NULL;
    }
    pthread_mutex_unlock (&list_lock);
    return cb;
}

GList *
cb_match (GList **list, const char *path, int criteria)
{
    GList *matches = NULL;
    GList *iter = NULL;

    pthread_mutex_lock (&list_lock);
    for (iter = *list; iter; iter = g_list_next (iter))
    {
        cb_info_t *cb = iter->data;
        bool match = false;
        int len = strlen (cb->path);
        const char *ptr = cb->path + len - 1;

        /* Active */
        if (!cb->active)
            continue;

        /* Exact match */
        if ((criteria & CB_MATCH_EXACT) &&
            strcmp (cb->path, path) == 0)
        {
            match = true;
        }
        /* Wildcard root path */
        else if ((criteria & CB_MATCH_WILD) &&
                  *ptr == '*' && strncmp (path, cb->path, len - 1) == 0)
        {
            match = true;
        }
        /* Direct child */
        else if ((criteria & CB_MATCH_CHILD) &&
                  *ptr == '/' && strncmp (path, cb->path, len - 1) == 0 &&
                  strlen(path) >= len && !strchr (path + len, '/'))
        {
            match = true;
        }
        /* Wildcard intermediate node */
        else if ((criteria & CB_MATCH_WILD_PATH) &&
                  (ptr = strchr(cb->path, '*')) != NULL)
        {
            /* Match up to the '*' */
            if (strncmp(path, cb->path, ptr - cb->path - 1) == 0)
            {
                const char *after_needle = ptr + 1;
                const char *after_haystack = path + strlen(path) - strlen(after_needle);

                /* Match after the star */
                if (strcmp(after_needle, after_haystack) == 0)
                {
                    match = true;
                }
            }
        }

        /* Match */
        if (match)
        {
            cb->refcnt++;
            matches = g_list_append (matches, cb);
            cb->count++;
        }
    }
    pthread_mutex_unlock (&list_lock);

    return matches;
}

void
cb_init (void)
{
    return;
}

void
cb_shutdown (void)
{
    /* Cleanup lists */
    g_list_foreach (watch_list, cb_free, NULL);
    g_list_foreach (provide_list, cb_free, NULL);
    g_list_foreach (validation_list, cb_free, NULL);
    g_list_foreach (proxy_list, cb_free, NULL);
    return;
}
