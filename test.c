/**
 * @file test.c
 * Unit tests for the Apteryx API
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
#include <sys/types.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <assert.h>
#include <CUnit/CUnit.h>
#include <CUnit/Basic.h>
#include "apteryx.h"
#include "internal.h"

#define TEST_SLEEP_TIMEOUT  100000
#define TEST_TCP_URL        "tcp://127.0.0.1:9999"
#define TEST_TCP6_URL       "tcp://[::1]:9999"

static bool
assert_apteryx_empty (void)
{
    GList *paths = apteryx_search ("/");
    GList *iter;
    bool ret = true;
    for (iter = paths; iter; iter = g_list_next (iter))
    {
        char *path = (char *) (iter->data);
        if (strncmp (APTERYX_PATH, path, strlen (path)) != 0)
        {
            if (ret) fprintf (stderr, "\n");
            fprintf (stderr, "ERROR: Node still set: %s\n", path);
            ret = false;
        }
    }
    g_list_free_full (paths, free);
    return ret;
}

void
test_set_get ()
{
    const char *path = "/entity/zones/private/name";
    char *value = NULL;

    CU_ASSERT (apteryx_set (path, "private"));
    CU_ASSERT ((value = apteryx_get (path)) != NULL);
    CU_ASSERT (value && strcmp (value, "private") == 0);
    free ((void *) value);
    CU_ASSERT (apteryx_set (path, NULL));
    CU_ASSERT (assert_apteryx_empty ());
}

void
test_set_get_raw ()
{
    const char *path = "/entity/zones/private/raw";
    char bytes[] = { 0x1, 0x2, 0x3, 0x4, 0x0, 0x6, 0x7, 0x8 };
    char *value;

    CU_ASSERT (apteryx_set (path, bytes));
    CU_ASSERT ((value = apteryx_get (path)) != NULL);
    CU_ASSERT (value && strlen (value) == 4);
    CU_ASSERT (value && memcmp (value, bytes, 4) == 0);
    free ((void *) value);
    CU_ASSERT (apteryx_set (path, NULL));
    CU_ASSERT (assert_apteryx_empty ());
}

void
test_multiple_leaves ()
{
    const char *path1 = "/entity/zones/private/name";
    const char *path2 = "/entity/zones/private/active";
    const char *value = NULL;

    CU_ASSERT (apteryx_set (path1, "private"));
    CU_ASSERT (apteryx_set (path2, "1"));

    CU_ASSERT ((value = apteryx_get (path1)) != NULL);
    CU_ASSERT (value != NULL);
    CU_ASSERT (value && strcmp (value, "private") == 0);
    free ((void *) value);

    CU_ASSERT ((value = apteryx_get (path2)) != NULL);
    CU_ASSERT (value != NULL);
    CU_ASSERT (value && strcmp (value, "1") == 0);
    free ((void *) value);

    CU_ASSERT (apteryx_set (path1, NULL));
    CU_ASSERT (apteryx_set (path2, NULL));
    CU_ASSERT (assert_apteryx_empty ());
}

void
test_overwrite ()
{
    const char *path = "/entity/zones/private/name";
    const char *value = NULL;

    CU_ASSERT (apteryx_set (path, "private"));
    CU_ASSERT (apteryx_set (path, "public"));
    CU_ASSERT ((value = apteryx_get (path)) != NULL);
    CU_ASSERT (value != NULL);
    CU_ASSERT (value && strcmp (value, "public") == 0);
    free ((void *) value);

    CU_ASSERT (apteryx_set (path, NULL));
    CU_ASSERT (assert_apteryx_empty ());
}

void
test_delete ()
{
    const char *path = "/entity/zones/private/name";
    const char *value = NULL;

    CU_ASSERT (apteryx_set (path, "private"));
    CU_ASSERT ((value = apteryx_get (path)) != NULL);
    CU_ASSERT (value != NULL);
    free ((void *) value);
    CU_ASSERT (apteryx_set (path, NULL));
    CU_ASSERT ((value = apteryx_get (path)) == NULL);
    CU_ASSERT (assert_apteryx_empty ());
}

#define thread_count 5
static int _multi_write_thread_data[thread_count];
int
_multi_write_thread (void *data)
{
    int i;
    int id = (long int) data;
    char *path = NULL;

    if (asprintf (&path, "/counters/thread%d", id) < 0)
        return 0;
    _multi_write_thread_data[id] = 0;
    apteryx_set_int (path, NULL, _multi_write_thread_data[id]);
    for (i = 0; i < thread_count; i++)
    {
        _multi_write_thread_data[id] = apteryx_get_int (path, NULL);
        apteryx_set_int (path, NULL, _multi_write_thread_data[id] + 1);
    }
    free (path);
    return 0;
}

void
test_thread_multi_write ()
{
    long int i;
    pthread_t writers[thread_count];
    for (i = 0; i < thread_count; i++)
    {
        pthread_create (&writers[i], NULL, (void *) &_multi_write_thread, (void *) i);
    }
    for (i = 0; i < thread_count; i++)
    {
        pthread_join (writers[i], NULL);
    }
    for (i = 0; i < thread_count; i++)
    {
        char *path = NULL;
        CU_ASSERT (_multi_write_thread_data[i] == thread_count - 1);
        CU_ASSERT (asprintf (&path, "/counters/thread%ld", i) > 0);
        apteryx_set (path, NULL);
        free (path);
    }
    apteryx_prune ("/counters");
    CU_ASSERT (assert_apteryx_empty ());
}

void
test_process_multi_write ()
{
    long int i;
    int writers[thread_count];
    apteryx_shutdown ();
    for (i = 0; i < thread_count; i++)
    {
        writers[i] = fork ();
        if (writers[i] == 0)
        {
            apteryx_init (debug);
            _multi_write_thread ((void *) i);
            exit (0);
        }
    }
    apteryx_init (debug);

    for (i = 0; i < thread_count; i++)
    {
        int status = 0;
        waitpid (writers[i], &status, 0);
    }
    for (i = 0; i < thread_count; i++)
    {
        char *path = NULL;
        CU_ASSERT (asprintf (&path, "/counters/thread%d", (int) i) > 0)
            CU_ASSERT (apteryx_get_int (path, NULL) == thread_count);
        free (path);
    }
    apteryx_prune ("/counters");
    CU_ASSERT (assert_apteryx_empty ());
}

void
test_perf_set ()
{
    const char *path = "/entity/zones/private/name";
    uint64_t start;
    int i;
    bool res;

    start = get_time_us ();
    for (i = 0; i < 1000; i++)
    {
        CU_ASSERT ((res = apteryx_set (path, "private")));
        if (!res)
            goto exit;
    }
    printf ("%ldus ... ", (get_time_us () - start) / 1000);
  exit:
    CU_ASSERT (apteryx_set (path, NULL));
    CU_ASSERT (assert_apteryx_empty ());
}

void
test_perf_tcp_set ()
{
    const char *path = TEST_TCP_URL":/entity/zones/private/name";
    uint64_t start;
    int i;
    bool res;

    CU_ASSERT (apteryx_bind (TEST_TCP_URL));
    usleep (TEST_SLEEP_TIMEOUT);
    start = get_time_us ();
    for (i = 0; i < 1000; i++)
    {
        CU_ASSERT ((res = apteryx_set (path, "private")));
        if (!res)
            goto exit;
    }
    printf ("%ldus ... ", (get_time_us () - start) / 1000);
exit:
    CU_ASSERT (apteryx_set (path, NULL));
    CU_ASSERT (apteryx_unbind (TEST_TCP_URL));
    CU_ASSERT (assert_apteryx_empty ());
}

void
test_perf_tcp6_set ()
{
    const char *path = TEST_TCP6_URL":/entity/zones/private/name";
    uint64_t start;
    int i;
    bool res;

    CU_ASSERT (apteryx_bind (TEST_TCP6_URL));
    usleep (TEST_SLEEP_TIMEOUT);
    start = get_time_us ();
    for (i = 0; i < 1000; i++)
    {
        CU_ASSERT ((res = apteryx_set (path, "private")));
        if (!res)
            goto exit;
    }
    printf ("%ldus ... ", (get_time_us () - start) / 1000);
exit:
    CU_ASSERT (apteryx_set (path, NULL));
    CU_ASSERT (apteryx_unbind (TEST_TCP6_URL));
    CU_ASSERT (assert_apteryx_empty ());
}

void
test_get_no_value ()
{
    const char *path = "/entity/zones/private/name";
    const char *value = NULL;

    CU_ASSERT ((value = apteryx_get (path)) == NULL);
    CU_ASSERT (assert_apteryx_empty ());
}

void
test_perf_get ()
{
    const char *path = "/entity/zones/private/name";
    const char *value = NULL;
    uint64_t start;
    int i;

    CU_ASSERT (apteryx_set (path, "private"));
    start = get_time_us ();
    for (i = 0; i < 1000; i++)
    {
        CU_ASSERT ((value = apteryx_get (path)) != NULL);
        if (!value)
            goto exit;
        free ((void *) value);
    }
    printf ("%ldus ... ", (get_time_us () - start) / 1000);
  exit:
    CU_ASSERT (apteryx_set (path, NULL));
    CU_ASSERT (assert_apteryx_empty ());
}

void
test_perf_tcp_get ()
{
    const char *path = TEST_TCP_URL":/entity/zones/private/name";
    const char *value = NULL;
    uint64_t start;
    int i;

    CU_ASSERT (apteryx_bind (TEST_TCP_URL));
    usleep (TEST_SLEEP_TIMEOUT);
    CU_ASSERT (apteryx_set (path, "private"));
    start = get_time_us ();
    for (i = 0; i < 1000; i++)
    {
        CU_ASSERT ((value = apteryx_get (path)) != NULL);
        if (!value)
            goto exit;
        free ((void *) value);
    }
    printf ("%ldus ... ", (get_time_us () - start) / 1000);
exit:
    CU_ASSERT (apteryx_set (path, NULL));
    CU_ASSERT (apteryx_unbind (TEST_TCP_URL))
    CU_ASSERT (assert_apteryx_empty ());
}

void
test_perf_tcp6_get ()
{
    const char *path = TEST_TCP6_URL":/entity/zones/private/name";
    const char *value = NULL;
    uint64_t start;
    int i;

    CU_ASSERT (apteryx_bind (TEST_TCP6_URL));
    usleep (TEST_SLEEP_TIMEOUT);
    CU_ASSERT (apteryx_set (path, "private"));
    start = get_time_us ();
    for (i = 0; i < 1000; i++)
    {
        CU_ASSERT ((value = apteryx_get (path)) != NULL);
        if (!value)
            goto exit;
        free ((void *) value);
    }
    printf ("%ldus ... ", (get_time_us () - start) / 1000);
exit:
    CU_ASSERT (apteryx_set (path, NULL));
    CU_ASSERT (apteryx_unbind (TEST_TCP6_URL))
    CU_ASSERT (assert_apteryx_empty ());
}

void
test_perf_get_null ()
{
    const char *path = "/entity/zones/private/name";
    const char *value = NULL;
    uint64_t start;
    int i;

    start = get_time_us ();
    for (i = 0; i < 1000; i++)
    {
        CU_ASSERT ((value = apteryx_get (path)) == NULL);
        if (value != NULL)
            goto exit;
    }
    printf ("%ldus ... ", (get_time_us () - start) / 1000);
  exit:
    CU_ASSERT (assert_apteryx_empty ());
}

void
test_set_get_int ()
{
    const char *path = "/entity/zones";
    int value = 123456;

    CU_ASSERT (apteryx_set_int (path, "count", value));

    int v = 0;

    CU_ASSERT ((v = apteryx_get_int (path, "count")) == value);

    CU_ASSERT (apteryx_set_string (path, "count", NULL));
    CU_ASSERT (assert_apteryx_empty ());
}

void
test_set_get_string ()
{
    const char *path = "/entity/zones";
    const char *value = "123456";

    CU_ASSERT (apteryx_set_string (path, "count", value));

    char *v = NULL;

    CU_ASSERT ((v = apteryx_get_string (path, "count")) != NULL);
    CU_ASSERT (v && strcmp (v, value) == 0);

    free (v);
    CU_ASSERT (apteryx_set_string (path, "count", NULL));
    CU_ASSERT (assert_apteryx_empty ());
}

void
test_search_paths ()
{
    GList *paths = NULL;

    CU_ASSERT (apteryx_set_string ("/entity/zones", NULL, "-"));
    CU_ASSERT (apteryx_set_string ("/entity/zones/private", NULL, "-"));
    CU_ASSERT (apteryx_set_string ("/entity/zones/private/description", NULL, "lan"));
    CU_ASSERT (apteryx_set_string
               ("/entity/zones/private/networks/description", NULL, "engineers"));
    CU_ASSERT (apteryx_set_string ("/entity/zones/public", NULL, "-"));
    CU_ASSERT (apteryx_set_string ("/entity/zones/public/description", NULL, "wan"));

    CU_ASSERT ((paths = apteryx_search ("/")) != NULL);
    g_list_free_full (paths, free);
    CU_ASSERT ((paths = apteryx_search ("/entity/")) != NULL);
    g_list_free_full (paths, free);
    CU_ASSERT (apteryx_search ("/nothere/") == NULL);

    CU_ASSERT ((paths = apteryx_search ("/entity/zones/")) != NULL);
    CU_ASSERT (g_list_length (paths) == 2);
    CU_ASSERT (g_list_find_custom (paths, "/entity/zones/private", (GCompareFunc) strcmp) !=
               NULL);
    CU_ASSERT (g_list_find_custom (paths, "/entity/zones/public", (GCompareFunc) strcmp) !=
               NULL);
    g_list_free_full (paths, free);

    CU_ASSERT (apteryx_set_string ("/entity/zones", NULL, NULL));
    CU_ASSERT (apteryx_set_string ("/entity/zones/private", NULL, NULL));
    CU_ASSERT (apteryx_set_string ("/entity/zones/private/description", NULL, NULL));
    CU_ASSERT (apteryx_set_string
               ("/entity/zones/private/networks/description", NULL, NULL));
    CU_ASSERT (apteryx_set_string ("/entity/zones/public", NULL, NULL));
    CU_ASSERT (apteryx_set_string ("/entity/zones/public/description", NULL, NULL));
    CU_ASSERT (assert_apteryx_empty ());
}

void
test_search_paths_root ()
{
    GList *paths = NULL;

    CU_ASSERT (apteryx_set_string ("/interfaces", NULL, "-"));
    CU_ASSERT (apteryx_set_string ("/interfaces/eth0", NULL, "-"));
    CU_ASSERT (apteryx_set_string ("/interfaces/eth0/state", NULL, "up"));
    CU_ASSERT (apteryx_set_string ("/entities", NULL, "-"));
    CU_ASSERT (apteryx_set_string ("/entities/zones", NULL, "-"));
    CU_ASSERT (apteryx_set_string ("/entities/zones/public", NULL, "-"));
    CU_ASSERT (apteryx_set_string ("/entities/zones/public/active", NULL, "true"));

    CU_ASSERT ((paths = apteryx_search (NULL)) == NULL);
    CU_ASSERT ((paths = apteryx_search ("")) == NULL);
    CU_ASSERT ((paths = apteryx_search ("*")) == NULL);
    CU_ASSERT ((paths = apteryx_search ("/")) != NULL);
    CU_ASSERT (g_list_length (paths) == 2);
    CU_ASSERT (g_list_find_custom (paths, "/interfaces", (GCompareFunc) strcmp) != NULL);
    CU_ASSERT (g_list_find_custom (paths, "/entities", (GCompareFunc) strcmp) != NULL);
    g_list_free_full (paths, free);
    paths = NULL;

    CU_ASSERT (apteryx_set_string ("/interfaces", NULL, NULL));
    CU_ASSERT (apteryx_set_string ("/interfaces/eth0", NULL, NULL));
    CU_ASSERT (apteryx_set_string ("/interfaces/eth0/state", NULL, NULL));
    CU_ASSERT (apteryx_set_string ("/entities", NULL, NULL));
    CU_ASSERT (apteryx_set_string ("/entities/zones", NULL, NULL));
    CU_ASSERT (apteryx_set_string ("/entities/zones/public", NULL, NULL));
    CU_ASSERT (apteryx_set_string ("/entities/zones/public/active", NULL, NULL));
    CU_ASSERT (assert_apteryx_empty ());
}

void
test_perf_search ()
{
    GList *paths = NULL;
    uint64_t start;
    int i;

    CU_ASSERT (apteryx_set_string ("/interfaces", NULL, "-"));
    CU_ASSERT (apteryx_set_string ("/interfaces/eth0", NULL, "-"));
    start = get_time_us ();
    for (i = 0; i < 1000; i++)
    {
        CU_ASSERT ((paths = apteryx_search ("/")) != NULL);
        if (paths == NULL)
            goto exit;
        g_list_free_full (paths, free);
    }
    printf ("%ldus ... ", (get_time_us () - start) / 1000);
  exit:
    CU_ASSERT (apteryx_set_string ("/interfaces", NULL, NULL));
    CU_ASSERT (apteryx_set_string ("/interfaces/eth0", NULL, NULL));
    CU_ASSERT (assert_apteryx_empty ());
}

static GList*
test_index_cb (const char *path)
{
    GList *paths = NULL;
    paths = g_list_append (paths, strdup ("/counters/rx"));
    paths = g_list_append (paths, strdup ("/counters/tx"));
    return paths;
}

static GList*
test_index_cb2 (const char *path)
{
    GList *paths = NULL;
    paths = g_list_append (paths, strdup ("/counters/up"));
    paths = g_list_append (paths, strdup ("/counters/down"));
    return paths;
}

static GList*
test_index_cb_wild (const char *path)
{
    GList *paths = NULL;
    if (strcmp (path, "/counters/") == 0)
    {
        paths = g_list_append (paths, strdup ("/counters/rx"));
        paths = g_list_append (paths, strdup ("/counters/tx"));
    }
    else if (strcmp (path, "/counters/rx/") == 0)
    {
        paths = g_list_append (paths, strdup ("/counters/rx/pkts"));
        paths = g_list_append (paths, strdup ("/counters/rx/bytes"));
    }
    else
    {
        paths = g_list_append (paths, strdup ("/counters/tx/pkts"));
        paths = g_list_append (paths, strdup ("/counters/tx/bytes"));
    }
    return paths;
}

void
test_index ()
{
    char *path = "/counters/";
    GList *paths = NULL;

    CU_ASSERT (apteryx_index (path, test_index_cb));
    CU_ASSERT ((paths = apteryx_search (path)) != NULL);
    CU_ASSERT (g_list_length (paths) == 2);
    CU_ASSERT (g_list_find_custom (paths, "/counters/rx", (GCompareFunc) strcmp) != NULL);
    CU_ASSERT (g_list_find_custom (paths, "/counters/tx", (GCompareFunc) strcmp) != NULL);
    g_list_free_full (paths, free);
    CU_ASSERT (apteryx_unindex (path, test_index_cb));
    CU_ASSERT (assert_apteryx_empty ());
}

void
test_index_wildcard ()
{
    char *path = "/counters/*";
    GList *paths = NULL;

    CU_ASSERT (apteryx_index (path, test_index_cb_wild));
    CU_ASSERT ((paths = apteryx_search ("/counters/")) != NULL);
    CU_ASSERT (g_list_length (paths) == 2);
    CU_ASSERT (g_list_find_custom (paths, "/counters/rx", (GCompareFunc) strcmp) != NULL);
    CU_ASSERT (g_list_find_custom (paths, "/counters/tx", (GCompareFunc) strcmp) != NULL);
    for (GList * _iter = paths; _iter; _iter = _iter->next)
    {
        char *_path = NULL;
        GList *subpaths = NULL;

        CU_ASSERT (asprintf (&_path, "%s/", (char *) _iter->data) > 0);
        CU_ASSERT ((subpaths = apteryx_search (_path)) != NULL);
        CU_ASSERT (g_list_length (paths) == 2);
        if (strcmp (_path, "/counters/rx/") == 0)
        {
            CU_ASSERT (g_list_find_custom (subpaths, "/counters/rx/pkts", (GCompareFunc) strcmp) != NULL);
            CU_ASSERT (g_list_find_custom (subpaths, "/counters/rx/bytes", (GCompareFunc) strcmp) != NULL);
        }
        else
        {
            CU_ASSERT (g_list_find_custom (subpaths, "/counters/tx/pkts", (GCompareFunc) strcmp) != NULL);
            CU_ASSERT (g_list_find_custom (subpaths, "/counters/tx/bytes", (GCompareFunc) strcmp) != NULL);
        }
        g_list_free_full (subpaths, free);
        free (_path);
    }
    g_list_free_full (paths, free);
    CU_ASSERT (apteryx_unindex (path, test_index_cb_wild));
    CU_ASSERT (assert_apteryx_empty ());
}

void
test_index_after_db ()
{
    char *path = "/counters/";
    GList *paths = NULL;

    CU_ASSERT (apteryx_set ("/counters/up", "1"));
    CU_ASSERT (apteryx_set ("/counters/down", "2"));
    CU_ASSERT (apteryx_index (path, test_index_cb));
    CU_ASSERT ((paths = apteryx_search (path)) != NULL);
    CU_ASSERT (g_list_length (paths) == 2);
    CU_ASSERT (g_list_find_custom (paths, "/counters/up", (GCompareFunc) strcmp) != NULL);
    CU_ASSERT (g_list_find_custom (paths, "/counters/down", (GCompareFunc) strcmp) != NULL);
    g_list_free_full (paths, free);
    CU_ASSERT (apteryx_unindex (path, test_index_cb));
    CU_ASSERT (apteryx_set ("/counters/up", NULL));
    CU_ASSERT (apteryx_set ("/counters/down", NULL));
    CU_ASSERT (assert_apteryx_empty ());
}

void
test_index_replace_handler ()
{
    char *path = "/counters/";
    GList *paths = NULL;

    CU_ASSERT (apteryx_index (path, test_index_cb));
    CU_ASSERT (apteryx_index (path, test_index_cb2));
    CU_ASSERT ((paths = apteryx_search (path)) != NULL);
    CU_ASSERT (g_list_length (paths) == 2);
    CU_ASSERT (g_list_find_custom (paths, "/counters/up", (GCompareFunc) strcmp) != NULL);
    CU_ASSERT (g_list_find_custom (paths, "/counters/down", (GCompareFunc) strcmp) != NULL);
    g_list_free_full (paths, free);
    CU_ASSERT (apteryx_unindex (path, test_index_cb2));
    CU_ASSERT (apteryx_unindex (path, test_index_cb));
    CU_ASSERT (assert_apteryx_empty ());
}

void
test_index_no_handler ()
{
    char *path = "/counters/";

    CU_ASSERT (apteryx_search (path) == NULL);
    CU_ASSERT (assert_apteryx_empty ());
}

void
test_index_remove_handler ()
{
    char *path = "/counters/";

    CU_ASSERT (apteryx_index (path, test_index_cb));
    CU_ASSERT (apteryx_unindex (path, test_index_cb));
    CU_ASSERT (apteryx_search (path) == NULL);
    CU_ASSERT (assert_apteryx_empty ());
}

void
test_prune ()
{
    GList *paths = NULL;

    CU_ASSERT (apteryx_set_string ("/interfaces", NULL, "-"));
    CU_ASSERT (apteryx_set_string ("/interfaces/eth0", NULL, "-"));
    CU_ASSERT (apteryx_set_string ("/interfaces/eth0/state", NULL, "up"));
    CU_ASSERT (apteryx_set_string ("/entities", NULL, "-"));
    CU_ASSERT (apteryx_set_string ("/entities/zones", NULL, "-"));
    CU_ASSERT (apteryx_set_string ("/entities/zones/public", NULL, "-"));
    CU_ASSERT (apteryx_set_string ("/entities/zones/private", NULL, "-"));
    CU_ASSERT (apteryx_prune ("/interfaces"));

    CU_ASSERT ((paths = apteryx_search ("/interfaces/")) == NULL);
    CU_ASSERT ((paths = apteryx_search ("/entities/zones/")) != NULL);
    CU_ASSERT (g_list_length (paths) == 2);
    g_list_free_full (paths, free);
    CU_ASSERT (apteryx_prune ("/entities"));
    CU_ASSERT (assert_apteryx_empty ());
}

static char *_path = NULL;
static char *_value = NULL;
static bool
test_watch_callback (const char *path, const char *value)
{
    if (_path)
        free (_path);
    if (_value)
        free (_value);

    _path = strdup (path);
    if (value)
        _value = strdup (value);
    else
        _value = NULL;
    return true;
}

void
_watch_cleanup ()
{
    if (_path)
        free (_path);
    if (_value)
        free (_value);
    _path = _value = NULL;
    CU_ASSERT (assert_apteryx_empty ());
}

void
test_watch ()
{
    _path = _value = NULL;
    const char *path = "/entity/zones/private/state";

    CU_ASSERT (apteryx_set_string (path, NULL, "up"));
    CU_ASSERT (apteryx_watch (path, test_watch_callback));
    CU_ASSERT (apteryx_set_string (path, NULL, "down"));
    usleep (TEST_SLEEP_TIMEOUT);
    CU_ASSERT (_path && strcmp (_path, path) == 0);
    CU_ASSERT (_value && strcmp (_value, "down") == 0);
    CU_ASSERT (apteryx_unwatch (path, test_watch_callback));
    apteryx_set_string (path, NULL, NULL);
    _watch_cleanup ();
}

static int
test_watch_thread_client (void *data)
{
    const char *path = "/entity/zones/private/state";

    apteryx_set_string (path, NULL, "down");

    return 0;
}

void
test_watch_thread ()
{
    pthread_t client;
    const char *path = "/entity/zones/private/state";

    _path = _value = NULL;

    CU_ASSERT (apteryx_set_string (path, NULL, "up"));
    CU_ASSERT (apteryx_watch (path, test_watch_callback));

    pthread_create (&client, NULL, (void *) &test_watch_thread_client, (void *) NULL);
    pthread_join (client, NULL);
    usleep (TEST_SLEEP_TIMEOUT);

    CU_ASSERT (_path && strcmp (_path, path) == 0);
    CU_ASSERT (_value && strcmp (_value, "down") == 0);
    CU_ASSERT (apteryx_unwatch (path, test_watch_callback));
    apteryx_set_string (path, NULL, NULL);
    _watch_cleanup ();
}

void
test_watch_fork ()
{
    const char *path = "/entity/zones/private/state";
    int pid;
    int status;

    _path = _value = NULL;

    apteryx_shutdown ();
    if ((pid = fork ()) == 0)
    {
        apteryx_init (debug);
        usleep (TEST_SLEEP_TIMEOUT);
        apteryx_set_string (path, NULL, "down");
        while (1);
    }
    else if (pid > 0)
    {
        apteryx_init (debug);
        //CU_ASSERT (apteryx_set_string (path, NULL, "up"));
        CU_ASSERT (apteryx_watch (path, test_watch_callback));
        usleep (TEST_SLEEP_TIMEOUT * 2);
        kill (pid, 15);
        waitpid (pid, &status, 0);
        CU_ASSERT (WEXITSTATUS (status) == 0);
    }
    else if (pid < 0)
    {
        CU_ASSERT (0);  //fork failed
    }

    CU_ASSERT (_path && strcmp (_path, path) == 0);
    CU_ASSERT (_value && strcmp (_value, "down") == 0);
    CU_ASSERT (apteryx_unwatch (path, test_watch_callback));
    apteryx_set_string (path, NULL, NULL);
    _watch_cleanup ();
}

void
test_watch_no_match ()
{
    _path = _value = NULL;
    const char *path1 = "/entity/zones/private/state";
    const char *path2 = "/entity/zones/private/active";

    CU_ASSERT (apteryx_set_string (path1, NULL, "up"));
    usleep (TEST_SLEEP_TIMEOUT);
    CU_ASSERT (apteryx_watch (path1, test_watch_callback));
    CU_ASSERT (apteryx_set_string (path2, NULL, "true"));
    CU_ASSERT (_path == NULL);
    CU_ASSERT (_value == NULL);
    CU_ASSERT (apteryx_unwatch (path1, test_watch_callback));
    CU_ASSERT (apteryx_set_string (path1, NULL, NULL));
    CU_ASSERT (apteryx_set_string (path2, NULL, NULL));
    _watch_cleanup ();
}

void
test_watch_remove ()
{
    _path = _value = NULL;
    const char *path = "/entity/zones/private/state";

    CU_ASSERT (apteryx_set_string (path, NULL, "up"));
    usleep (TEST_SLEEP_TIMEOUT);
    CU_ASSERT (apteryx_watch (path, test_watch_callback));
    CU_ASSERT (apteryx_unwatch (path, test_watch_callback));
    usleep (TEST_SLEEP_TIMEOUT);
    CU_ASSERT (apteryx_set_string (path, NULL, "down"));

    CU_ASSERT (_path == NULL);
    CU_ASSERT (_value == NULL);
    CU_ASSERT (apteryx_set_string (path, NULL, NULL));
    _watch_cleanup ();
}

void
test_watch_unset_wildcard_path ()
{
    _path = _value = NULL;
    const char *path = "/entity/zones/private/state";

    CU_ASSERT (apteryx_set_string (path, NULL, "up"));
    usleep (TEST_SLEEP_TIMEOUT);
    CU_ASSERT (apteryx_watch ("/entity/zones/private/*", test_watch_callback));
    CU_ASSERT (apteryx_set (path, NULL));
    usleep (TEST_SLEEP_TIMEOUT);

    CU_ASSERT (_path && strcmp (path, _path) == 0);
    CU_ASSERT (_value == NULL);

    CU_ASSERT (apteryx_unwatch ("/entity/zones/private/*", test_watch_callback));
    _watch_cleanup ();
}

void
test_watch_one_level_path ()
{
    _path = _value = NULL;
    const char *path = "/entity/zones/private/state";

    CU_ASSERT (apteryx_set_string (path, NULL, "up"));
    CU_ASSERT (apteryx_watch
               ("/entity/zones/private/", test_watch_callback));
    CU_ASSERT (apteryx_set_string (path, NULL, "down"));
    usleep (TEST_SLEEP_TIMEOUT);
    CU_ASSERT (_path && strcmp (_path, path) == 0);
    CU_ASSERT (_value && strcmp (_value, "down") == 0);

    CU_ASSERT (apteryx_unwatch ("/entity/zones/private/", test_watch_callback));
    CU_ASSERT (apteryx_set_string (path, NULL, NULL));
    _watch_cleanup ();
}


void
test_watch_one_level_path_prune ()
{
    _path = _value = NULL;
    const char *path = "/entity/zones/private";

    CU_ASSERT (apteryx_set_string (path, "state", "up"));
    CU_ASSERT (apteryx_watch
               ("/entity/zones/private/", test_watch_callback));
    CU_ASSERT (apteryx_prune ("/entity/zones/private/state"));
    usleep (TEST_SLEEP_TIMEOUT);
    CU_ASSERT (_path && strstr (_path, path));

    CU_ASSERT (apteryx_unwatch ("/entity/zones/private/", test_watch_callback));
    CU_ASSERT (apteryx_set_string (path, "state", NULL));
    _watch_cleanup ();
}

void
test_watch_wildcard ()
{
    _path = _value = NULL;
    const char *path = "/entity/zones/private/state";

    CU_ASSERT (apteryx_set_string (path, NULL, "up"));
    CU_ASSERT (apteryx_watch ("/entity/zones/*", test_watch_callback));
    CU_ASSERT (apteryx_set_string (path, NULL, "down"));
    usleep (TEST_SLEEP_TIMEOUT);
    CU_ASSERT (_path && strcmp (_path, path) == 0);
    CU_ASSERT (_value && strcmp (_value, "down") == 0);

    CU_ASSERT (apteryx_unwatch ("/entity/zones/*", test_watch_callback));
    CU_ASSERT (apteryx_set_string (path, NULL, NULL));
    _watch_cleanup ();
}

/* We now only support wildcards on the end. This test confirms that we don't support this.
 */
void
test_watch_wildcard_not_last ()
{
    _path = _value = NULL;
    const char *path = "/entity/zones/public/state";

    usleep (TEST_SLEEP_TIMEOUT);
    CU_ASSERT (apteryx_watch
               ("/entity/zones/*/state", test_watch_callback));
    CU_ASSERT (apteryx_set_string (path, NULL, "up"));
    usleep (TEST_SLEEP_TIMEOUT);
    CU_ASSERT (_path == NULL);
    CU_ASSERT (apteryx_unwatch ("/entity/zones/*/state", test_watch_callback));
    CU_ASSERT (apteryx_set_string (path, NULL, NULL));
    _watch_cleanup ();
}

void
test_watch_wildcard_miss ()
{
    _path = _value = NULL;

    CU_ASSERT (apteryx_watch
               ("/entity/zones/private/*", test_watch_callback));
    CU_ASSERT (apteryx_watch
               ("/entity/zones/private/active", test_watch_callback));
    CU_ASSERT (apteryx_watch ("/entity/other/*", test_watch_callback));
    CU_ASSERT (apteryx_set_string ("/entity/zones/public/state", NULL, "up"));
    usleep (TEST_SLEEP_TIMEOUT);

    CU_ASSERT (_path == NULL);
    CU_ASSERT (_value == NULL);

    CU_ASSERT (apteryx_unwatch ("/entity/zones/private/*", test_watch_callback));
    CU_ASSERT (apteryx_unwatch ("/entity/zones/private/active", test_watch_callback));
    CU_ASSERT (apteryx_unwatch ("/entity/other/*", test_watch_callback));

    apteryx_set_string ("/entity/zones/public/state", NULL, NULL);
    _watch_cleanup ();
}

static bool
test_watch_set_callback_get_cb (const char *path, const char *value)
{
    char *value2 = NULL;
    CU_ASSERT ((value2 = apteryx_get (path)) != NULL);
    CU_ASSERT (value && value2 && strcmp (value, value2) == 0);
    free ((void *) value2);
    return true;
}

void
test_watch_set_callback_get ()
{
    const char *path = "/entity/zones/private/state";
    CU_ASSERT (apteryx_watch (path, test_watch_set_callback_get_cb));
    CU_ASSERT (apteryx_set_string (path, NULL, "up"));
    usleep (TEST_SLEEP_TIMEOUT);
    CU_ASSERT (apteryx_unwatch (path, test_watch_set_callback_get_cb));
    usleep (TEST_SLEEP_TIMEOUT);
    CU_ASSERT (apteryx_set_string (path, NULL, NULL));
    _watch_cleanup ();
}

static bool
test_watch_set_callback_set_cb (const char *path, const char *value)
{
    apteryx_set_string (path, NULL, "down");
    return true;
}

void
test_watch_set_callback_set ()
{
    const char *path = "/entity/zones/private/state";
    CU_ASSERT (apteryx_watch (path, test_watch_set_callback_set_cb));
    CU_ASSERT (apteryx_set_string (path, NULL, "up"));
    usleep (TEST_SLEEP_TIMEOUT);
    CU_ASSERT (apteryx_unwatch (path, test_watch_set_callback_set_cb));
    usleep (TEST_SLEEP_TIMEOUT);
    CU_ASSERT (apteryx_set_string (path, NULL, NULL));
    usleep (2*RPC_TIMEOUT_US); /* At least */
    _watch_cleanup ();
}

static bool
test_watch_set_callback_unwatch_cb (const char *path, const char *value)
{
    apteryx_unwatch (path, test_watch_set_callback_unwatch_cb);
    return true;
}

void
test_watch_set_callback_unwatch ()
{
    const char *path = "/entity/zones/private/state";
    CU_ASSERT (apteryx_watch (path, test_watch_set_callback_unwatch_cb));
    CU_ASSERT (apteryx_set_string (path, NULL, "up"));
    usleep (TEST_SLEEP_TIMEOUT);
    CU_ASSERT (apteryx_set_string (path, NULL, NULL));
    _watch_cleanup ();
}

bool test_watch_set_thread_done = false;
static bool
test_watch_set_thread_cb (const char *path, const char *value)
{
    apteryx_unwatch (path, test_watch_set_thread_cb);
    apteryx_set_string (path, NULL, "down");
    test_watch_set_thread_done = true;
    return true;
}

static int
test_watch_set_thread_client (void *data)
{
    const char *path = "/entity/zones/private/state";
    apteryx_watch (path, test_watch_set_thread_cb);
    while (!test_watch_set_thread_done)
        usleep (10);
    return 0;
}

void
test_watch_set_thread ()
{
    pthread_t client;
    const char *path = "/entity/zones/private/state";
    char *value;

    _path = _value = NULL;
    pthread_create (&client, NULL, (void *) &test_watch_set_thread_client, (void *) NULL);
    usleep (TEST_SLEEP_TIMEOUT);
    CU_ASSERT (apteryx_set_string (path, NULL, "up"));
    pthread_join (client, NULL);
    CU_ASSERT ((value = apteryx_get (path)) != NULL);
    CU_ASSERT (value && strcmp (value, "down") == 0);
    free ((void *) value);
    apteryx_set_string (path, NULL, NULL);
    _watch_cleanup ();
}

static int _cb_count = 0;
static bool
test_watch_adds_watch_cb (const char *path, const char *value)
{
    if (strcmp (path, "/entity/zones/public/state") == 0)
    {
        _cb_count++;
        apteryx_watch (path, test_watch_callback);
        apteryx_unwatch ("/entity/zones/public/*", test_watch_adds_watch_cb);
    }
    return true;
}

void
test_watch_adds_watch ()
{
    _path = _value = NULL;

    apteryx_watch ("/entity/zones/public/*", test_watch_adds_watch_cb);
    apteryx_set_string ("/entity/zones/public/state", NULL, "new_cb");
    usleep (TEST_SLEEP_TIMEOUT);
    CU_ASSERT (_cb_count == 1);
    apteryx_set_string ("/entity/zones/public/state", NULL, "new_cb_two");
    usleep (TEST_SLEEP_TIMEOUT);
    CU_ASSERT (_cb_count == 1);
    CU_ASSERT (_path && strcmp ("/entity/zones/public/state", _path) == 0);
    CU_ASSERT (_value && strcmp ("new_cb_two", _value) == 0);
    apteryx_unwatch ("/entity/zones/public/state", test_watch_callback);
    apteryx_set_string ("/entity/zones/public/state", NULL, NULL);
    _watch_cleanup ();
}

static bool
test_watch_removes_all_watchs_cb (const char *path, const char *value)
{
    if (path && strcmp (path, "/entity/zones/public/state") == 0)
    {
        _cb_count++;
        apteryx_unwatch ("/entity/zones/public/state",test_watch_removes_all_watchs_cb);
        apteryx_unwatch ("/entity/zones/public/*", test_watch_removes_all_watchs_cb);
        apteryx_unwatch ("/*", test_watch_removes_all_watchs_cb);
        apteryx_unwatch ("/entity/zones/public/active", test_watch_removes_all_watchs_cb);
    }
    return true;
}

void
test_watch_removes_all_watches ()
{
    const char *path = "/entity/zones/public/state";
    _cb_count = 0;
    _path = _value = NULL;

    apteryx_set_string (path, NULL, "new_cb_two");
    usleep (TEST_SLEEP_TIMEOUT);
    apteryx_watch ("/*", test_watch_removes_all_watchs_cb);
    apteryx_watch ("/entity/zones/public/*", test_watch_removes_all_watchs_cb);
    apteryx_watch ("/entity/zones/public/active", test_watch_removes_all_watchs_cb);
    apteryx_watch ("/entity/zones/public/state", test_watch_removes_all_watchs_cb);
    apteryx_set (path, NULL);
    usleep (TEST_SLEEP_TIMEOUT);
    CU_ASSERT (_cb_count == 3);
    apteryx_set_string (path, NULL, "new_cb_two");
    usleep (TEST_SLEEP_TIMEOUT);
    CU_ASSERT (_cb_count == 3);
    apteryx_set_string (path, NULL, NULL);
    _watch_cleanup ();
}

static bool
test_watch_count_callback (const char *path, const char *value)
{
    char *v;
    CU_ASSERT ((asprintf ((char **) &v, "%d", _cb_count)+1) != 0);
    CU_ASSERT (strcmp ((char*)value, v) == 0);
    free (v);
    _cb_count++;
    return true;
}

static bool
test_watch_busy_callback (const char *path, const char *value)
{
    int i;
    for (i=0;i<100;i++)
    {
        CU_ASSERT (apteryx_set_int ("/interfaces/eth0/packets", NULL, i));
    }
    usleep (RPC_TIMEOUT_US);
    return true;
}

void
test_watch_when_busy ()
{
    _cb_count = 0;
    CU_ASSERT (apteryx_set_int ("/interfaces/eth0/packets", NULL, 0));
    CU_ASSERT (apteryx_watch ("/interfaces/eth0/packets", test_watch_count_callback));
    CU_ASSERT (apteryx_watch ("/busy/watch", test_watch_busy_callback));
    CU_ASSERT (apteryx_set_string ("/busy/watch", NULL, "go"));
    usleep (2*RPC_TIMEOUT_US);
    CU_ASSERT (_cb_count == 100);
    CU_ASSERT (apteryx_get_int ("/interfaces/eth0/packets", NULL) == 99);
    CU_ASSERT (apteryx_unwatch ("/interfaces/eth0/packets", test_watch_count_callback));
    CU_ASSERT (apteryx_unwatch ("/busy/watch", test_watch_busy_callback));
    apteryx_set ("/interfaces/eth0/packets", NULL);
    apteryx_set ("/busy/watch", NULL);
    _watch_cleanup ();
}

static pthread_mutex_t watch_lock;
static bool
test_perf_watch_callback (const char *path, const char *value)
{
    pthread_mutex_unlock (&watch_lock);
    return true;
}

void
test_perf_watch ()
{
    _path = _value = NULL;
    const char *path = "/entity/zones/private/state";
    uint64_t start;
    int i;

    pthread_mutex_init (&watch_lock, NULL);
    CU_ASSERT (apteryx_watch (path, test_perf_watch_callback));
    start = get_time_us ();
    for (i = 0; i < 1000; i++)
    {
        pthread_mutex_lock (&watch_lock);
        CU_ASSERT (apteryx_set (path, "down"));
    }
    pthread_mutex_destroy (&watch_lock);
    printf ("%ldus ... ", (get_time_us () - start) / 1000);

    CU_ASSERT (apteryx_unwatch (path, test_perf_watch_callback));
    apteryx_set_string (path, NULL, NULL);
    CU_ASSERT (assert_apteryx_empty ());
}

int
test_validate_callback(const char *path, const char *value)
{
    return 0;
}

int
test_validate_refuse_callback(const char *path, const char *value)
{
    return -EPERM;
}

void
test_validate()
{
    _path = _value = NULL;
    const char *path = "/entity/zones/private/state";

    CU_ASSERT (apteryx_validate (path, test_validate_callback));
    CU_ASSERT (apteryx_set_string (path, NULL, "down"));
    CU_ASSERT (apteryx_validate (path, test_validate_refuse_callback));
    CU_ASSERT (!apteryx_set_string (path, NULL, "up"));
    CU_ASSERT (errno == -EPERM);
    usleep (TEST_SLEEP_TIMEOUT);
    CU_ASSERT (apteryx_unvalidate (path, test_validate_callback));
    CU_ASSERT (apteryx_unvalidate (path, test_validate_refuse_callback));
    apteryx_set_string (path, NULL, NULL);
}

void
test_validate_one_level()
{
    _path = _value = NULL;
    const char *path = "/entity/zones/private/";

    CU_ASSERT (apteryx_validate (path, test_validate_refuse_callback));
    usleep (TEST_SLEEP_TIMEOUT);
    CU_ASSERT (!apteryx_set_string ("/entity/zones/private", "state", "up"));
    usleep (TEST_SLEEP_TIMEOUT);
    CU_ASSERT (apteryx_unvalidate (path, test_validate_refuse_callback));
    apteryx_set_string (path, "state", NULL);
}

void
test_validate_wildcard()
{
    _path = _value = NULL;
    const char *path = "/entity/zones/*";

    CU_ASSERT (apteryx_validate (path, test_validate_refuse_callback));
    usleep (TEST_SLEEP_TIMEOUT);
    CU_ASSERT (!apteryx_set_string ("/entity/zones/one/two", "state", "up"));
    usleep (TEST_SLEEP_TIMEOUT);
    CU_ASSERT (apteryx_unvalidate (path, test_validate_refuse_callback));
    apteryx_set_string (path, NULL, NULL);
}

void
test_validate_wildcard_internal()
{
    _path = _value = NULL;
    const char *path = "/entity/*/private/state";

    CU_ASSERT (apteryx_validate (path, test_validate_refuse_callback));
    usleep (TEST_SLEEP_TIMEOUT);
    CU_ASSERT (!apteryx_set_string ("/entity/zones/private", "state", "up"));
    CU_ASSERT (apteryx_set_string ("/entity/zones/private", "link", "up"));
    usleep (TEST_SLEEP_TIMEOUT);
    CU_ASSERT (apteryx_unvalidate (path, test_validate_refuse_callback));
    apteryx_set_string ("/entity/zones/private", "state", NULL);
    apteryx_set_string ("/entity/zones/private", "link", NULL);
    CU_ASSERT (assert_apteryx_empty ());
}

static int already_set = 0;
static int failed = 0;

static int
test_validate_thread_client (void *data)
{
    const char *path = "/entity/zones/private/state";

    if(!apteryx_set_string (path, NULL, (char*)data))
        failed = errno;
    return 0;
}

int
test_validate_conflicting_callback(const char *path, const char *value)
{
    return !already_set ? 0 : -EPERM;
}

static bool
test_validate_test_watch_callback (const char *path, const char *value)
{
    usleep (900000);
    already_set++;
    return true;
}

void
test_validate_conflicting ()
{
    pthread_t client1, client2;
    const char *path = "/entity/zones/private/state";

    failed = 0;
    already_set = 0;

    _path = _value = NULL;

    CU_ASSERT (apteryx_validate (path, test_validate_conflicting_callback));
    CU_ASSERT (apteryx_watch (path, test_validate_test_watch_callback));
    usleep (TEST_SLEEP_TIMEOUT);
    pthread_create (&client1, NULL, (void *) &test_validate_thread_client, "up");
    pthread_create (&client2, NULL, (void *) &test_validate_thread_client, "down");
    pthread_join (client1, NULL);
    pthread_join (client2, NULL);
    CU_ASSERT (failed == -EPERM);
    usleep (TEST_SLEEP_TIMEOUT);

    CU_ASSERT (apteryx_unvalidate (path, test_validate_conflicting_callback));
    CU_ASSERT (apteryx_unwatch (path, test_validate_test_watch_callback));
    apteryx_set_string (path, NULL, NULL);
    CU_ASSERT (assert_apteryx_empty ());
}

static char*
test_provide_callback_up (const char *path)
{
    return strdup ("up");
}

static char*
test_provide_callback_down (const char *path)
{
    return strdup ("down");
}

void
test_provide ()
{
    const char *path = "/interfaces/eth0/state";
    const char *value = NULL;

    CU_ASSERT (apteryx_provide (path, test_provide_callback_up));
    CU_ASSERT (( value = apteryx_get (path)) != NULL);
    CU_ASSERT (value && strcmp (value, "up") == 0);
    if (value)
        free ((void *) value);
    apteryx_unprovide (path, test_provide_callback_up);
    CU_ASSERT (assert_apteryx_empty ());
}

void
test_provide_replace_handler ()
{
    const char *path = "/interfaces/eth0/state";
    const char *value = NULL;

    CU_ASSERT (apteryx_provide (path, test_provide_callback_up));
    CU_ASSERT (apteryx_provide (path, test_provide_callback_down));
    CU_ASSERT ((value = apteryx_get (path)) != NULL);
    CU_ASSERT (value && strcmp (value, "down") == 0);
    if (value)
        free ((void *) value);
    apteryx_unprovide (path, test_provide_callback_up);
    apteryx_unprovide (path, test_provide_callback_down);
    CU_ASSERT (assert_apteryx_empty ());
}

void
test_provide_no_handler ()
{
    const char *path = "/interfaces/eth0/state";
    const char *value = NULL;

    CU_ASSERT ((value = apteryx_get (path)) == NULL);
    CU_ASSERT (assert_apteryx_empty ());
}

void
test_provide_remove_handler ()
{
    const char *path = "/interfaces/eth0/state";
    const char *value = NULL;

    CU_ASSERT (apteryx_provide (path, test_provide_callback_up));
    CU_ASSERT (apteryx_unprovide (path, test_provide_callback_up));
    CU_ASSERT ((value = apteryx_get (path)) == NULL);
    CU_ASSERT (assert_apteryx_empty ());
}

static char*
test_provide_timeout_cb (const char *path)
{
    sleep (1.2);
    return strdup ("down");
}

void
test_provide_timeout ()
{
    const char *path = "/interfaces/eth0/state";
    const char *value = NULL;

    CU_ASSERT (apteryx_provide (path, test_provide_timeout_cb));
    CU_ASSERT ((value = apteryx_get (path)) == NULL);
    CU_ASSERT (errno == -ETIMEDOUT);
    if (value)
        free ((void *) value);
    apteryx_unprovide (path, test_provide_timeout_cb);
    CU_ASSERT ((value = apteryx_get (path)) == NULL);
    CU_ASSERT (assert_apteryx_empty ());
}

bool test_provide_thread_running = false;
static int
test_provide_thread_client (void *data)
{
    const char *path = "/interfaces/eth0/state";

    apteryx_provide (path, test_provide_callback_up);

    while (test_provide_thread_running)
        usleep (TEST_SLEEP_TIMEOUT);

    apteryx_unprovide (path, test_provide_callback_up);

    return 0;
}

void
test_provide_different_thread ()
{
    const char *path = "/interfaces/eth0/state";
    const char *value = NULL;
    pthread_t client;

    test_provide_thread_running = true;
    pthread_create (&client, NULL, (void *) &test_provide_thread_client, (void *) NULL);
    usleep (50000);

    CU_ASSERT ((value = apteryx_get (path)) != NULL);
    CU_ASSERT (value && strcmp (value, "up") == 0);
    if (value)
        free ((void *) value);

    test_provide_thread_running = false;
    pthread_cancel (client);
    pthread_join (client, NULL);
    apteryx_unprovide (path, test_provide_callback_up);
    CU_ASSERT (assert_apteryx_empty ());
}

void
test_provide_different_process ()
{
    const char *path = "/interfaces/eth0/state";
    const char *value = NULL;
    int pid;
    int status;

    apteryx_shutdown ();
    if ((pid = fork ()) == 0)
    {
        apteryx_init (debug);
        CU_ASSERT (apteryx_provide (path, test_provide_callback_up));
        usleep (100000);
        apteryx_unprovide (path, test_provide_callback_up);
        exit (0);
    }
    else if (pid > 0)
    {
        apteryx_init (debug);
        usleep (50000);
        CU_ASSERT ((value = apteryx_get (path)) != NULL);
        CU_ASSERT (value && strcmp (value, "up") == 0);
        if (value)
            free ((void *) value);
        waitpid (pid, &status, 0);
        CU_ASSERT (WEXITSTATUS (status) == 0);
    }
    else if (pid < 0)
    {
        CU_ASSERT (0);
    }
    CU_ASSERT (assert_apteryx_empty ());
}

static char*
test_provide_callback_get_cb (const char *path)
{
    return apteryx_get ("/interfaces/eth0/state");
}

void
test_provide_callback_get ()
{
    const char *path1 = "/interfaces/eth0/state";
    const char *path2 = "/interfaces/eth0/status";
    const char *value = NULL;

    apteryx_set (path1, "up");
    CU_ASSERT (apteryx_provide (path2, test_provide_callback_get_cb));
    CU_ASSERT ((value = apteryx_get (path2)) != NULL);
    CU_ASSERT (value && strcmp (value, "up") == 0);
    if (value)
        free ((void *) value);
    apteryx_unprovide (path2, test_provide_callback_get_cb);
    apteryx_set (path1, NULL);
    CU_ASSERT (assert_apteryx_empty ());
}

void
test_provide_callback_get_null ()
{
    const char *path = "/interfaces/eth0/status";
    const char *value = NULL;

    CU_ASSERT (apteryx_provide (path, test_provide_callback_get_cb));
    errno = 0;
    CU_ASSERT ((value = apteryx_get (path)) == NULL);
    CU_ASSERT (errno != -ETIMEDOUT);
    apteryx_unprovide (path, test_provide_callback_get_cb);
    CU_ASSERT (assert_apteryx_empty ());
}

void
test_provide_search ()
{
    const char *path = "/interfaces/eth0/state";
    GList *paths = NULL;

    CU_ASSERT (apteryx_provide (path, test_provide_callback_up));
    CU_ASSERT ((paths = apteryx_search ("/interfaces/eth0/")) != NULL);
    CU_ASSERT (g_list_length (paths) == 1);
    CU_ASSERT (g_list_find_custom (paths, path, (GCompareFunc) strcmp) != NULL);
    g_list_free_full (paths, free);
    apteryx_unprovide (path, test_provide_callback_up);
    CU_ASSERT (assert_apteryx_empty ());
}

void
test_provide_after_db ()
{
    const char *path = "/interfaces/eth0/state";
    const char *value = NULL;

    CU_ASSERT (apteryx_set (path, "down"));
    CU_ASSERT (apteryx_provide (path, test_provide_callback_up));
    CU_ASSERT (( value = apteryx_get (path)) != NULL);
    CU_ASSERT (value && strcmp (value, "down") == 0);
    if (value)
        free ((void *) value);
    apteryx_unprovide (path, test_provide_callback_up);
    CU_ASSERT (apteryx_set (path, NULL));
    CU_ASSERT (assert_apteryx_empty ());
}

void
test_perf_provide ()
{
    const char *path = "/entity/zones/private/state";
    const char *value = NULL;
    uint64_t start;
    int i;

    CU_ASSERT (apteryx_provide (path, test_provide_callback_up));
    start = get_time_us ();
    for (i = 0; i < 1000; i++)
    {
        CU_ASSERT ((value = apteryx_get (path)) != NULL);
        if (!value)
            goto exit;
        free ((void *) value);
    }
    printf ("%ldus ... ", (get_time_us () - start) / 1000);
  exit:
    apteryx_unprovide (path, test_provide_callback_up);
    CU_ASSERT (assert_apteryx_empty ());
}

void
test_proxy_get ()
{
    const char *value = NULL;

    CU_ASSERT (apteryx_set ("/test/local", "test"));
    CU_ASSERT (apteryx_bind (TEST_TCP_URL));
    CU_ASSERT (apteryx_proxy ("/test/remote/*", TEST_TCP_URL));
    CU_ASSERT ((value = apteryx_get ("/test/remote/test/local")) != NULL);
    CU_ASSERT (value && strcmp (value, "test") == 0);
    if (value)
        free ((void *) value);
    CU_ASSERT (apteryx_unproxy ("/test/remote/*", TEST_TCP_URL));
    CU_ASSERT (apteryx_unbind (TEST_TCP_URL));
    CU_ASSERT (apteryx_set ("/test/local", NULL));
    CU_ASSERT (assert_apteryx_empty ());
}

void
test_proxy_set ()
{
    const char *value = NULL;

    CU_ASSERT (apteryx_bind (TEST_TCP_URL));
    CU_ASSERT (apteryx_proxy ("/test/remote/*", TEST_TCP_URL));
    CU_ASSERT (apteryx_set ("/test/remote/test/local", "test"));
    CU_ASSERT ((value = apteryx_get ("/test/local")) != NULL);
    CU_ASSERT (value && strcmp (value, "test") == 0);
    if (value)
        free ((void *) value);
    CU_ASSERT (apteryx_unproxy ("/test/remote/*", TEST_TCP_URL));
    CU_ASSERT (apteryx_unbind (TEST_TCP_URL));
    CU_ASSERT (apteryx_set ("/test/local", NULL));
    CU_ASSERT (apteryx_set ("/test/remote/test/local", NULL));
    CU_ASSERT (assert_apteryx_empty ());
}

void
test_proxy_not_listening ()
{
    CU_ASSERT (apteryx_set ("/test/local", "test"));
    CU_ASSERT (apteryx_proxy ("/test/remote/*", TEST_TCP_URL));
    CU_ASSERT (apteryx_get ("/test/remote/test/local") == NULL);
    CU_ASSERT (apteryx_unproxy ("/test/remote/*", TEST_TCP_URL));
    CU_ASSERT (apteryx_set ("/test/local", NULL));
    CU_ASSERT (assert_apteryx_empty ());
}

void
test_proxy_before_db_get ()
{
    const char *value = NULL;

    CU_ASSERT (apteryx_set ("/test/local", "dog"));
    CU_ASSERT (apteryx_set ("/test/remote/test/local", "cat"));
    cache_set ("/test/remote/test/local", NULL);
    CU_ASSERT (apteryx_bind (TEST_TCP_URL));
    CU_ASSERT (apteryx_proxy ("/test/remote/*", TEST_TCP_URL));
    CU_ASSERT ((value = apteryx_get ("/test/remote/test/local")) != NULL);
    CU_ASSERT (value && strcmp (value, "dog") == 0);
    if (value)
        free ((void *) value);
    CU_ASSERT (apteryx_unproxy ("/test/remote/*", TEST_TCP_URL));
    CU_ASSERT (apteryx_unbind (TEST_TCP_URL));
    CU_ASSERT (apteryx_set ("/test/remote/test/local", NULL));
    CU_ASSERT (apteryx_set ("/test/local", NULL));
    CU_ASSERT (assert_apteryx_empty ());
}

void
test_proxy_before_db_set ()
{
    CU_ASSERT (apteryx_bind (TEST_TCP_URL));
    CU_ASSERT (apteryx_proxy ("/test/remote/*", TEST_TCP_URL));
    CU_ASSERT (apteryx_set ("/test/remote/test/local", "test"));
    CU_ASSERT (apteryx_unproxy ("/test/remote/*", TEST_TCP_URL));
    CU_ASSERT (apteryx_unbind (TEST_TCP_URL));
    CU_ASSERT (apteryx_get ("/test/remote/test/local") == NULL);
    CU_ASSERT (apteryx_set ("/test/remote/test/local", NULL));
    CU_ASSERT (apteryx_set ("/test/local", NULL));
    CU_ASSERT (assert_apteryx_empty ());
}

void
test_proxy_set_validated ()
{
    CU_ASSERT (apteryx_validate ("/test/local", test_validate_refuse_callback));
    CU_ASSERT (apteryx_bind (TEST_TCP_URL));
    CU_ASSERT (apteryx_proxy ("/test/remote/*", TEST_TCP_URL));
    CU_ASSERT (!apteryx_set ("/test/remote/test/local", "test"));
    CU_ASSERT (errno == -EPERM);
    CU_ASSERT (apteryx_unvalidate ("/test/local", test_validate_refuse_callback));
    CU_ASSERT (apteryx_unproxy ("/test/remote/*", TEST_TCP_URL));
    CU_ASSERT (apteryx_unbind (TEST_TCP_URL));
    CU_ASSERT (apteryx_set ("/test/local", NULL));
    CU_ASSERT (assert_apteryx_empty ());
}

void
test_proxy_search ()
{
    GList *paths = NULL;

    CU_ASSERT (apteryx_set ("/test/local/cat", "felix"));
    CU_ASSERT (apteryx_set ("/test/local/dog", "fido"));
    CU_ASSERT (apteryx_bind (TEST_TCP_URL));
    CU_ASSERT (apteryx_proxy ("/test/remote/*", TEST_TCP_URL));
    CU_ASSERT ((paths = apteryx_search ("/test/remote/test/local/")) != NULL);
    CU_ASSERT (g_list_length (paths) == 2);
    CU_ASSERT (g_list_find_custom (paths, "/test/local/cat",
            (GCompareFunc) strcmp) != NULL);
    CU_ASSERT (g_list_find_custom (paths, "/test/local/dog",
            (GCompareFunc) strcmp) != NULL);
    g_list_free_full (paths, free);
    CU_ASSERT (apteryx_unproxy ("/test/remote/*", TEST_TCP_URL));
    CU_ASSERT (apteryx_unbind (TEST_TCP_URL));
    CU_ASSERT (apteryx_set ("/test/local/cat", NULL));
    CU_ASSERT (apteryx_set ("/test/local/dog", NULL));
    CU_ASSERT (assert_apteryx_empty ());
}

void
test_proxy_prune ()
{
    GList *paths = NULL;

    CU_ASSERT (apteryx_set_string ("/interfaces", NULL, "-"));
    CU_ASSERT (apteryx_set_string ("/interfaces/eth0", NULL, "-"));
    CU_ASSERT (apteryx_set_string ("/interfaces/eth0/state", NULL, "up"));
    CU_ASSERT (apteryx_set_string ("/entities", NULL, "-"));
    CU_ASSERT (apteryx_set_string ("/entities/zones", NULL, "-"));
    CU_ASSERT (apteryx_set_string ("/entities/zones/public", NULL, "-"));
    CU_ASSERT (apteryx_set_string ("/entities/zones/private", NULL, "-"));

    CU_ASSERT (apteryx_bind (TEST_TCP_URL));
    CU_ASSERT (apteryx_proxy ("/test/remote/*", TEST_TCP_URL));
    CU_ASSERT (apteryx_prune ("/test/remote/interfaces"));
    CU_ASSERT ((paths = apteryx_search ("/interfaces/")) == NULL);
    CU_ASSERT ((paths = apteryx_search ("/entities/zones/")) != NULL);
    CU_ASSERT (g_list_length (paths) == 2);
    g_list_free_full (paths, free);

    CU_ASSERT (apteryx_prune ("/test/remote/entities"));
    CU_ASSERT (assert_apteryx_empty ());
    CU_ASSERT (apteryx_unproxy ("/test/remote/*", TEST_TCP_URL));
    CU_ASSERT (apteryx_unbind (TEST_TCP_URL));
}

void
test_proxy_timestamp ()
{
    uint64_t ts = 0;

    CU_ASSERT (apteryx_set ("/test/local", "test"));
    CU_ASSERT ((ts = apteryx_timestamp ("/test/local")) != 0);
    CU_ASSERT (apteryx_bind (TEST_TCP_URL));
    CU_ASSERT (apteryx_proxy ("/test/remote/*", TEST_TCP_URL));
    CU_ASSERT (apteryx_timestamp ("/test/remote/test/local") == ts);
    CU_ASSERT (apteryx_unproxy ("/test/remote/*", TEST_TCP_URL));
    CU_ASSERT (apteryx_unbind (TEST_TCP_URL));
    CU_ASSERT (apteryx_set ("/test/local", NULL));
    CU_ASSERT (assert_apteryx_empty ());
}

static bool
test_deadlock_callback (const char *path, const char *value)
{
    apteryx_set("/test/goes/here", "changed");
    return true;
}

void
test_deadlock ()
{
    int i;

    for (i = 0; i < 1000; i++)
    {
        char *path = NULL;
        CU_ASSERT (asprintf(&path, "/test/zones/private/state/%d", i) > 0);
        CU_ASSERT (apteryx_set (path, "set"));
        CU_ASSERT (apteryx_watch (path, test_deadlock_callback));
        free (path);
    }
    CU_ASSERT (apteryx_prune("/test"));
    usleep(1000);
    apteryx_shutdown();
    apteryx_init(false);

    for (i = 0; i < 1000; i++)
    {
        char *path = NULL;
        CU_ASSERT (asprintf(&path, "/test/zones/private/state/%d", i) > 0);
        CU_ASSERT (apteryx_unwatch (path, test_deadlock_callback));
        free (path);
    }
    CU_ASSERT (apteryx_prune("/test"));
    usleep (TEST_SLEEP_TIMEOUT);
    CU_ASSERT (assert_apteryx_empty ());
}

static bool
test_deadlock2_callback (const char *path, const char *value)
{
    apteryx_watch (path, test_deadlock_callback);
    return true;
}

void
test_deadlock2 ()
{
    int i;

    for (i = 0; i < 1000; i++)
    {
        char *path = NULL;
        CU_ASSERT (asprintf(&path, "/test/zones/private/state/%d", i) > 0);
        CU_ASSERT (apteryx_set (path, "set"));
        CU_ASSERT (apteryx_watch (path, test_deadlock2_callback));
        free (path);
    }
    CU_ASSERT (apteryx_prune ("/test"));
    usleep (200);
    apteryx_shutdown ();
    apteryx_init (false);

    for (i = 0; i < 1000; i++)
    {
        char *path = NULL;
        CU_ASSERT (asprintf (&path, "/test/zones/private/state/%d", i) > 0);
        CU_ASSERT (apteryx_unwatch (path, test_deadlock2_callback));
        CU_ASSERT (apteryx_unwatch (path, test_deadlock_callback));
        free (path);
    }
    CU_ASSERT (apteryx_prune ("/test"));
    usleep (TEST_SLEEP_TIMEOUT);
    CU_ASSERT (assert_apteryx_empty ());
}

void
_dump_config (FILE *fd, char *root, int tab)
{
    GList *paths = apteryx_search (root);
    for (GList * path = paths; path; path = path->next)
    {
        char *value = apteryx_get (path->data);
        if (value)
        {
            fprintf (fd, "%*.s%-16s %s\n", tab * 4, " ", strrchr (path->data, '/') + 1,
                     value);
            free (value);
        }
        else
            fprintf (fd, "%*.s%-16s\n", tab * 4, " ", strrchr (path->data, '/') + 1);

        char *sub_path;
        if (asprintf (&sub_path, "%s/", (char *) path->data))
        {
            _dump_config (fd, sub_path, tab + 1);
            free (sub_path);
        }
    }
    g_list_free_full (paths, free);
}

void
test_docs ()
{
    apteryx_set_string ("/interfaces/eth0", "description", "our lan");
    apteryx_set_string ("/interfaces/eth0", "state", "up");
    apteryx_set_int ("/interfaces/eth0/counters", "in_pkts", 10);
    apteryx_set_int ("/interfaces/eth0/counters/out_pkts", NULL, 20);
    apteryx_set_string ("/interfaces/eth1/description", NULL, "our wan");
    apteryx_set_string ("/interfaces/eth1/state", NULL, "down");

    printf ("\nInterfaces:\n");
    GList *paths = apteryx_search ("/interfaces/");
    for (GList * _iter = paths; _iter; _iter = _iter->next)
    {
        char *path, *value;
        path = (char *) _iter->data;
        printf ("  %s\n", strrchr (path, '/') + 1);
        value = apteryx_get_string (path, "description");
        printf ("    description     %s\n", value);
        free ((void *) value);
        value = apteryx_get_string (path, "state");
        printf ("    state           %s\n", value);
        free ((void *) value);
    }
    g_list_free_full (paths, free);

    apteryx_set_string ("/interfaces/eth0", "description", NULL);
    apteryx_set_string ("/interfaces/eth0", "state", NULL);
    apteryx_set_string ("/interfaces/eth0/counters", "in_pkts", NULL);
    apteryx_set_string ("/interfaces/eth0/counters/out_pkts", NULL, NULL);
    apteryx_set_string ("/interfaces/eth1/description", NULL, NULL);
    apteryx_set_string ("/interfaces/eth1/state", NULL, NULL);
    CU_ASSERT (assert_apteryx_empty ());
}

static int
suite_init (void)
{
    return 0;
}

static int
suite_clean (void)
{
    return 0;
}

static CU_TestInfo tests_api[] = {
    { "doc example", test_docs },
    { "set and get", test_set_get },
    { "set and get raw byte streams", test_set_get_raw },
    { "multiple leaves", test_multiple_leaves },
    { "set/get string", test_set_get_string },
    { "set/get int", test_set_get_int },
    { "get no value", test_get_no_value },
    { "overwrite", test_overwrite },
    { "delete", test_delete },
    { "search paths", test_search_paths },
    { "search root path", test_search_paths_root },
    { "multi threads writing to same table", test_thread_multi_write },
    { "multi processes writing to same table", test_process_multi_write },
    { "prune", test_prune },
    { "shutdown deadlock", test_deadlock },
    { "shutdown deadlock 2", test_deadlock2 },
    CU_TEST_INFO_NULL,
};

static CU_TestInfo tests_api_index[] = {
    { "index", test_index },
    { "index wildcard", test_index_wildcard },
    { "index after db", test_index_after_db },
    { "index replace handler", test_index_replace_handler },
    { "index no handler", test_index_no_handler },
    { "index remove handler", test_index_remove_handler },
    CU_TEST_INFO_NULL,
};

static CU_TestInfo tests_api_watch[] = {
    { "watch", test_watch },
    { "watch set from different thread", test_watch_thread },
    { "watch set from different process", test_watch_fork },
    { "watch no match", test_watch_no_match },
    { "watch remove", test_watch_remove },
    { "watch unset wildcard path", test_watch_unset_wildcard_path },
    { "watch one level path", test_watch_one_level_path },
    { "watch_one_level_path_prune", test_watch_one_level_path_prune},
    { "watch wildcard", test_watch_wildcard },
    { "watch wildcard not last", test_watch_wildcard_not_last },
    { "watch wildcard miss", test_watch_wildcard_miss },
    { "watch set callback get", test_watch_set_callback_get },
    { "watch set callback unwatch", test_watch_set_callback_unwatch },
    { "watch set callback set recursive", test_watch_set_callback_set },
    { "watch and set from another thread", test_watch_set_thread },
    { "watch adds / removes watches", test_watch_adds_watch },
    { "watch removes multiple watches", test_watch_removes_all_watches },
    { "watch when busy", test_watch_when_busy },
    CU_TEST_INFO_NULL,
};

static CU_TestInfo tests_api_validate[] = {
    { "validate", test_validate },
    { "validate one level", test_validate_one_level },
    { "validate wildcard", test_validate_wildcard },
    { "validate wildcard internal", test_validate_wildcard_internal },
    { "validate conflicting", test_validate_conflicting },
    CU_TEST_INFO_NULL,
};

static CU_TestInfo tests_api_provide[] = {
    { "provide", test_provide },
    { "provider timeout", test_provide_timeout },
    { "provide replace handler", test_provide_replace_handler },
    { "provide no handler", test_provide_no_handler },
    { "provide remove handler", test_provide_remove_handler },
    { "provide from different threads", test_provide_different_thread },
    { "provide from different process", test_provide_different_process },
    { "provide callback get", test_provide_callback_get },
    { "provide callback get null", test_provide_callback_get_null },
    { "provide search", test_provide_search },
    { "provide after db", test_provide_after_db },
    CU_TEST_INFO_NULL,
};

static CU_TestInfo tests_api_proxy[] = {
    { "proxy get", test_proxy_get },
    { "proxy set", test_proxy_set },
    { "proxy not listening", test_proxy_not_listening },
    { "proxy before db get", test_proxy_before_db_get },
    { "proxy before db set", test_proxy_before_db_set },
    { "proxy set validated", test_proxy_set_validated },
    { "proxy search", test_proxy_search },
    { "proxy prune", test_proxy_prune },
    { "proxy timestamp", test_proxy_timestamp },
    CU_TEST_INFO_NULL,
};

static CU_TestInfo tests_performance[] = {
    { "set", test_perf_set },
    { "set(tcp)", test_perf_tcp_set },
    { "set(tcp6)", test_perf_tcp6_set },
    { "get", test_perf_get },
    { "get(tcp)", test_perf_tcp_get },
    { "get(tcp6)", test_perf_tcp6_get },
    { "get null", test_perf_get_null },
    { "search", test_perf_search },
    { "watch", test_perf_watch },
    { "provide", test_perf_provide },
    CU_TEST_INFO_NULL,
};

extern CU_TestInfo tests_database_internal[];
extern CU_TestInfo tests_database[];
extern CU_TestInfo tests_callbacks[];

static CU_SuiteInfo suites[] = {
    { "Database Internal", suite_init, suite_clean, tests_database_internal },
    { "Database", suite_init, suite_clean, tests_database },
    { "Callbacks", suite_init, suite_clean, tests_callbacks },
    { "Apteryx API", suite_init, suite_clean, tests_api },
    { "Apteryx API Index", suite_init, suite_clean, tests_api_index },
    { "Apteryx API Watch", suite_init, suite_clean, tests_api_watch },
    { "Apteryx API Validate", suite_init, suite_clean, tests_api_validate },
    { "Apteryx API Provide", suite_init, suite_clean, tests_api_provide },
    { "Apteryx API Proxy", suite_init, suite_clean, tests_api_proxy },
    { "Apteryx Performance", suite_init, suite_clean, tests_performance },
    CU_SUITE_INFO_NULL,
};

int
main (int argc, char **argv)
{
    int c;

    while ((c = getopt (argc, argv, "d")) != -1)
    {
        switch (c)
        {
        case 'd':
            debug = true;
            break;
        case '?':
        case 'h':
        default:
            printf ("Usage: test_apteryx [-d]\n"
                    "  -h   show this help\n" "  -d   debug\n");
            return 0;
        }
    }

    /* Initialise Apteryx */
    apteryx_init (debug);

    /* Initialize the CUnit test registry */
    if (CUE_SUCCESS != CU_initialize_registry ())
        return CU_get_error ();

    /* Add tests */
    assert (NULL != CU_get_registry ());
    assert (!CU_is_test_running ());
    if (CU_register_suites (suites) != CUE_SUCCESS)
    {
        fprintf (stderr, "suite registration failed - %s\n", CU_get_error_msg ());
        exit (EXIT_FAILURE);
    }

    /* Run all tests using the CUnit Basic interface */
    CU_basic_set_mode (CU_BRM_VERBOSE);
    CU_set_error_action (CUEA_IGNORE);
    CU_basic_run_tests ();
    CU_cleanup_registry ();

    /* Shutdown Apteryx */
    apteryx_shutdown ();
    return CU_get_error ();
}
