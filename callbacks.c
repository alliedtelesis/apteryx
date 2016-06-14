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
#ifdef TEST
#include <CUnit/CUnit.h>
#include <CUnit/Basic.h>
#endif

GList *watch_list = NULL;
GList *validation_list = NULL;
GList *provide_list = NULL;
GList *index_list = NULL;
GList *proxy_list = NULL;
static pthread_mutex_t list_lock = PTHREAD_MUTEX_INITIALIZER;

cb_info_t *
cb_create (GList **list, const char *guid, const char *path,
        uint64_t id, uint64_t callback)
{
    cb_info_t *cb = (cb_info_t *) g_malloc0 (sizeof (cb_info_t));
    cb->active = true;
    cb->guid = g_strdup (guid);
    cb->path = g_strdup (path);
    cb->id = id;
    cb->uri = g_strdup_printf (APTERYX_SERVER".%"PRIu64, cb->id);
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
        g_free ((void *) cb->guid);
    if (cb->path)
        g_free ((void *) cb->path);
    if (cb->uri)
        g_free ((void *) cb->uri);
    g_free (cb);
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
    cb_info_t *cb = NULL;

    pthread_mutex_lock (&list_lock);
    for (iter = *list; iter; iter = g_list_next (iter))
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

        /* Part match on path */
        if ((criteria & CB_MATCH_PART) &&
            strncmp (cb->path, path, strlen (path)) == 0)
        {
            match = true;
        }
        /* Part match on cb->path */
        else if ((criteria & CB_PATH_MATCH_PART) &&
            strncmp (cb->path, path, strlen (cb->path)) == 0)
        {
            match = true;
        }
        /* Exact match */
        else if ((criteria & CB_MATCH_EXACT) &&
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
            if (strncmp(path, cb->path, ptr - cb->path) == 0)
            {
                const char *after_needle = ptr + 1;
                const char *after_haystack = path + strlen(path) - strlen(after_needle);

                /* Match after the star */
                if (strcmp(after_needle, after_haystack) == 0)
                {
                    match = true;
                }
                else
                {
                    const char *pattern = cb->path;
                    const char *p = path;

                    while (*pattern && *p)
                    {
                        if (*pattern == '*')
                        {
                            /* skip to '/' */
                            while (*p && *p != '/') p++;
                            pattern++;
                        }
                        else if (*pattern == *p)
                        {
                            pattern++;
                            p++;
                        }
                        else
                        {
                            break;
                        }
                    }

                    if (*pattern == '\0' && *p && !strcmp (pattern - 1, "*"))
                    {
                        match = true;
                    }
                    else if (*pattern == '\0' && *p == '\0')
                    {
                        match = true;
                    }
                    else
                    {
                        match = false;
                    }
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
    g_list_foreach (index_list, cb_free, NULL);
    g_list_foreach (proxy_list, cb_free, NULL);
    return;
}

#ifdef TEST
#define TEST_CB_MAX_ENTRIES 100000
#define TEST_CB_MAX_ITERATIONS 100

void
test_cb_init ()
{
    cb_init ();
    cb_shutdown ();
}

void
test_cb_release ()
{
    cb_info_t *cb;
    cb = cb_create (&watch_list, "abc", "/test", 1, 0);
    cb_release (cb);
    CU_ASSERT (cb->refcnt == 1);
    cb_release (cb);
    CU_ASSERT (g_list_length (watch_list) == 0);
}

void
test_cb_destroy ()
{
    cb_info_t *cb;
    cb = cb_create (&watch_list, "abc", "/test", 1, 0);
    cb_destroy (cb);
    CU_ASSERT (g_list_length (watch_list) == 1);
    cb_release (cb);
    CU_ASSERT (g_list_length (watch_list) == 0);
}

typedef enum
{
    INDEX_LAST,
    INDEX_FIRST,
    INDEX_RANDOM,
} PERF_TEST_INDEX;
static bool
match_perf_test (PERF_TEST_INDEX index)
{
    bool ret = false;
    char path[128];
    char guid[128];
    cb_info_t *cb;
    uint64_t start;
    int i;

    cb_init ();
    for (i = 0; i < TEST_CB_MAX_ENTRIES; i++)
    {
        sprintf (path, "/database/test%d/test%d", i, i);
        sprintf (guid, "%zX", (size_t)g_str_hash (path));
        cb = cb_create (&watch_list, guid, path, 1, 0);
        cb_release (cb);
    }
    CU_ASSERT (g_list_length (watch_list) == TEST_CB_MAX_ENTRIES);

    start = get_time_us ();
    for (i = 0; i < TEST_CB_MAX_ITERATIONS; i++)
    {
        GList *matches;
        int test = index == INDEX_FIRST ? 0 :
                (index == INDEX_LAST ? (TEST_CB_MAX_ENTRIES - 1) :
                  random () % TEST_CB_MAX_ENTRIES);
        sprintf (path, "/database/test%d/test%d", test, test);
        matches = cb_match (&watch_list, path,
                CB_MATCH_EXACT|CB_MATCH_WILD|CB_MATCH_CHILD);
        if (g_list_length (matches) != 1)
            goto exit;
        g_list_free_full (matches, (GDestroyNotify) cb_release);
    }
    printf ("%"PRIu64"us ... ", (get_time_us () - start) / TEST_CB_MAX_ITERATIONS);
    ret = true;
exit:
    g_list_foreach (watch_list, cb_free, NULL);
    CU_ASSERT (g_list_length (watch_list) == 0);
    watch_list = NULL;
    cb_shutdown ();
    return ret;
}

void
test_cb_match_perf_first ()
{
    CU_ASSERT (match_perf_test (INDEX_FIRST));
}

void
test_cb_match_perf_last ()
{
    CU_ASSERT (match_perf_test (INDEX_LAST));
}

void
test_cb_match_perf_random ()
{
    CU_ASSERT (match_perf_test (INDEX_RANDOM));
}

CU_TestInfo tests_callbacks[] = {
    { "init", test_cb_init },
    { "release", test_cb_release },
    { "destroy", test_cb_destroy },
    { "match performance random", test_cb_match_perf_random },
    { "match performance first", test_cb_match_perf_first },
    { "match performance last", test_cb_match_perf_last },
    CU_TEST_INFO_NULL,
};
#endif
