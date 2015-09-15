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
#include <sys/un.h>
#include <assert.h>
#include <CUnit/CUnit.h>
#include <CUnit/Basic.h>
#include "apteryx.h"
#include "internal.h"

#define TEST_PATH           "/test"
#define TEST_ITERATIONS     1000
#define TEST_SLEEP_TIMEOUT  100000
#define TEST_TCP_URL        "tcp://127.0.0.1:9999"
#define TEST_TCP6_URL       "tcp://[::1]:9999"
#define TEST_RPC_PATH       "/tmp/apteryx.test"
#define TEST_PORT_NUM       9999
#define TEST_MESSAGE_SIZE   100

static bool
assert_apteryx_empty (void)
{
    GList *paths = apteryx_search ("/");
    GList *iter;
    bool ret = true;
    for (iter = paths; iter; iter = g_list_next (iter))
    {
        char *path = (char *) (iter->data);
        if (strncmp (TEST_PATH, path, strlen (TEST_PATH)) == 0)
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
    const char *path = TEST_PATH"/entity/zones/private/name";
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
    const char *path = TEST_PATH"/entity/zones/private/raw";
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
test_set_get_long_path ()
{
    char *path = NULL;
    char *value = NULL;
    int i;

    CU_ASSERT (asprintf (&path, "%s", TEST_PATH));
    for (i=0; i<1024; i++)
    {
        char *old = path;
        CU_ASSERT (asprintf (&path, "%s/%08x", old, rand ()));
        free (old);
    }
    CU_ASSERT (apteryx_set (path, "private"));
    CU_ASSERT ((value = apteryx_get (path)) != NULL);
    CU_ASSERT (value && strcmp (value, "private") == 0);
    free ((void *) value);
    CU_ASSERT (apteryx_set (path, NULL));
    free ((void *) path);
    CU_ASSERT (assert_apteryx_empty ());
}

void
test_set_get_large_value ()
{
    const char *path = TEST_PATH"/value";
    char *svalue, *gvalue;
    int len = 1024*1024;

    svalue = calloc (1, len);
    memset (svalue, 'a', len-1);
    CU_ASSERT (apteryx_set (path, svalue));
    CU_ASSERT ((gvalue = apteryx_get (path)) != NULL);
    CU_ASSERT (gvalue && strcmp (gvalue, svalue) == 0);
    free ((void *) gvalue);
    free ((void *) svalue);
    CU_ASSERT (apteryx_set (path, NULL));
    CU_ASSERT (assert_apteryx_empty ());
}

void
test_multiple_leaves ()
{
    const char *path1 = TEST_PATH"/entity/zones/private/name";
    const char *path2 = TEST_PATH"/entity/zones/private/active";
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
    const char *path = TEST_PATH"/entity/zones/private/name";
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
    const char *path = TEST_PATH"/entity/zones/private/name";
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

    if (asprintf (&path, TEST_PATH"/counters/thread%d", id) < 0)
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
        CU_ASSERT (asprintf (&path, TEST_PATH"/counters/thread%li", i) > 0);
        apteryx_set (path, NULL);
        free (path);
    }
    apteryx_prune (TEST_PATH"/counters");
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
        CU_ASSERT (asprintf (&path, TEST_PATH"/counters/thread%d", (int) i) > 0)
            CU_ASSERT (apteryx_get_int (path, NULL) == thread_count);
        free (path);
    }
    apteryx_prune (TEST_PATH"/counters");
    CU_ASSERT (assert_apteryx_empty ());
}

void
test_perf_dummy ()
{
    const char *path = TEST_PATH"/entity/zones/private/name";
    int i;
    bool res;

    for (i = 0; i < TEST_ITERATIONS; i++)
    {
        CU_ASSERT ((res = apteryx_set (path, "private")));
        if (!res)
            goto exit;
    }
exit:
    CU_ASSERT (apteryx_set (path, NULL));
    CU_ASSERT (assert_apteryx_empty ());
}

void
test_perf_set ()
{
    uint64_t start;
    int i;
    bool res;

    start = get_time_us ();
    for (i = 0; i < TEST_ITERATIONS; i++)
    {
        char *path = NULL;
        CU_ASSERT (asprintf(&path, TEST_PATH"/zones/%d/state", i) > 0);
        CU_ASSERT ((res = apteryx_set (path, "private")));
        free (path);
        if (!res)
            goto exit;
    }
    printf ("%"PRIu64"us ... ", (get_time_us () - start) / TEST_ITERATIONS);
exit:
    for (i = 0; i < TEST_ITERATIONS; i++)
    {
        char *path = NULL;
        CU_ASSERT (asprintf(&path, TEST_PATH"/zones/%d/state", i) > 0);
        CU_ASSERT (apteryx_set (path, NULL));
        free (path);
    }
    CU_ASSERT (assert_apteryx_empty ());
}

void
test_perf_tcp_set ()
{
    const char *path = TEST_TCP_URL":"TEST_PATH"/entity/zones/private/name";
    uint64_t start;
    int i;
    bool res;

    CU_ASSERT (apteryx_bind (TEST_TCP_URL));
    usleep (TEST_SLEEP_TIMEOUT);
    start = get_time_us ();
    for (i = 0; i < TEST_ITERATIONS; i++)
    {
        CU_ASSERT ((res = apteryx_set (path, "private")));
        if (!res)
            goto exit;
    }
    printf ("%"PRIu64"us ... ", (get_time_us () - start) / TEST_ITERATIONS);
exit:
    CU_ASSERT (apteryx_set (path, NULL));
    CU_ASSERT (apteryx_unbind (TEST_TCP_URL));
    CU_ASSERT (assert_apteryx_empty ());
}

void
test_perf_tcp6_set ()
{
    const char *path = TEST_TCP6_URL":"TEST_PATH"/entity/zones/private/name";
    uint64_t start;
    int i;
    bool res;

    CU_ASSERT (apteryx_bind (TEST_TCP6_URL));
    usleep (TEST_SLEEP_TIMEOUT);
    start = get_time_us ();
    for (i = 0; i < TEST_ITERATIONS; i++)
    {
        CU_ASSERT ((res = apteryx_set (path, "private")));
        if (!res)
            goto exit;
    }
    printf ("%"PRIu64"us ... ", (get_time_us () - start) / TEST_ITERATIONS);
exit:
    CU_ASSERT (apteryx_set (path, NULL));
    CU_ASSERT (apteryx_unbind (TEST_TCP6_URL));
    CU_ASSERT (assert_apteryx_empty ());
}

void
test_get_no_value ()
{
    const char *path = TEST_PATH"/entity/zones/private/name";
    const char *value = NULL;

    CU_ASSERT ((value = apteryx_get (path)) == NULL);
    CU_ASSERT (assert_apteryx_empty ());
}


void
_perf_setup (int count, bool cleanup)
{
    int i;
    for (i = 0; i < count; i++)
    {
        char *path = NULL;
        CU_ASSERT (asprintf(&path, TEST_PATH"/zones/%d/state", i) > 0);
        if (cleanup)
            apteryx_set (path, NULL);
        else
            apteryx_set (path, "private");
        free (path);
    }
}

void
test_perf_get ()
{
    const char *value = NULL;
    uint64_t start;
    int i;

    _perf_setup (TEST_ITERATIONS, FALSE);
    start = get_time_us ();
    for (i = 0; i < TEST_ITERATIONS; i++)
    {
        char *path = NULL;
        CU_ASSERT (asprintf(&path, TEST_PATH"/zones/%d/state", i) > 0);
        CU_ASSERT ((value = apteryx_get (path)) != NULL);
        free (path);
        if (!value)
            goto exit;
        free ((void *) value);
    }
    printf ("%"PRIu64"us ... ", (get_time_us () - start) / TEST_ITERATIONS);
exit:
    _perf_setup (TEST_ITERATIONS, TRUE);
    CU_ASSERT (assert_apteryx_empty ());
}

void
test_perf_tcp_get ()
{
    const char *value = NULL;
    uint64_t start;
    int i;

    CU_ASSERT (apteryx_bind (TEST_TCP_URL));
    _perf_setup (TEST_ITERATIONS, FALSE);
    start = get_time_us ();
    for (i = 0; i < TEST_ITERATIONS; i++)
    {
        char *path = NULL;
        CU_ASSERT (asprintf(&path, TEST_TCP_URL":"TEST_PATH"/zones/%d/state", i) > 0);
        CU_ASSERT ((value = apteryx_get (path)) != NULL);
        free (path);
        if (!value)
            goto exit;
        free ((void *) value);
    }
    printf ("%"PRIu64"us ... ", (get_time_us () - start) / TEST_ITERATIONS);
exit:
    _perf_setup (TEST_ITERATIONS, TRUE);
    CU_ASSERT (apteryx_unbind (TEST_TCP_URL))
    CU_ASSERT (assert_apteryx_empty ());
}

void
test_perf_tcp6_get ()
{
    const char *value = NULL;
    uint64_t start;
    int i;

    CU_ASSERT (apteryx_bind (TEST_TCP6_URL));
    usleep (TEST_SLEEP_TIMEOUT);
    _perf_setup (TEST_ITERATIONS, FALSE);
    start = get_time_us ();
    for (i = 0; i < TEST_ITERATIONS; i++)
    {
        char *path = NULL;
        CU_ASSERT (asprintf(&path, TEST_TCP6_URL":"TEST_PATH"/zones/%d/state", i) > 0);
        CU_ASSERT ((value = apteryx_get (path)) != NULL);
        free (path);
        if (!value)
            goto exit;
        free ((void *) value);
    }
    printf ("%"PRIu64"us ... ", (get_time_us () - start) / TEST_ITERATIONS);
exit:
    _perf_setup (TEST_ITERATIONS, TRUE);
    CU_ASSERT (apteryx_unbind (TEST_TCP6_URL))
    CU_ASSERT (assert_apteryx_empty ());
}

void
test_perf_get_null ()
{
    const char *value = NULL;
    uint64_t start;
    int i;

    start = get_time_us ();
    for (i = 0; i < TEST_ITERATIONS; i++)
    {
        char *path = NULL;
        CU_ASSERT (asprintf(&path, TEST_PATH"/zones/%d/state", i) > 0);
        CU_ASSERT ((value = apteryx_get (path)) == NULL);
        free (path);
        if (value != NULL)
            goto exit;
    }
    printf ("%"PRIu64"us ... ", (get_time_us () - start) / TEST_ITERATIONS);
exit:
    CU_ASSERT (assert_apteryx_empty ());
}

void
test_set_get_int ()
{
    const char *path = TEST_PATH"/entity/zones";
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
    const char *path = TEST_PATH"/entity/zones";
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

    CU_ASSERT (apteryx_set_string (TEST_PATH"/entity/zones", NULL, "-"));
    CU_ASSERT (apteryx_set_string (TEST_PATH"/entity/zones/private", NULL, "-"));
    CU_ASSERT (apteryx_set_string (TEST_PATH"/entity/zones/private/description", NULL, "lan"));
    CU_ASSERT (apteryx_set_string
               (TEST_PATH"/entity/zones/private/networks/description", NULL, "engineers"));
    CU_ASSERT (apteryx_set_string (TEST_PATH"/entity/zones/public", NULL, "-"));
    CU_ASSERT (apteryx_set_string (TEST_PATH"/entity/zones/public/description", NULL, "wan"));

    CU_ASSERT ((paths = apteryx_search (TEST_PATH"/")) != NULL);
    g_list_free_full (paths, free);
    CU_ASSERT ((paths = apteryx_search (TEST_PATH"/entity/")) != NULL);
    g_list_free_full (paths, free);
    CU_ASSERT (apteryx_search (TEST_PATH"/nothere/") == NULL);

    CU_ASSERT ((paths = apteryx_search (TEST_PATH"/entity/zones/")) != NULL);
    CU_ASSERT (g_list_length (paths) == 2);
    CU_ASSERT (g_list_find_custom (paths, TEST_PATH"/entity/zones/private", (GCompareFunc) strcmp) !=
               NULL);
    CU_ASSERT (g_list_find_custom (paths, TEST_PATH"/entity/zones/public", (GCompareFunc) strcmp) !=
               NULL);
    g_list_free_full (paths, free);

    CU_ASSERT (apteryx_set_string (TEST_PATH"/entity/zones", NULL, NULL));
    CU_ASSERT (apteryx_set_string (TEST_PATH"/entity/zones/private", NULL, NULL));
    CU_ASSERT (apteryx_set_string (TEST_PATH"/entity/zones/private/description", NULL, NULL));
    CU_ASSERT (apteryx_set_string
               (TEST_PATH"/entity/zones/private/networks/description", NULL, NULL));
    CU_ASSERT (apteryx_set_string (TEST_PATH"/entity/zones/public", NULL, NULL));
    CU_ASSERT (apteryx_set_string (TEST_PATH"/entity/zones/public/description", NULL, NULL));
    CU_ASSERT (assert_apteryx_empty ());
}

void
test_search_paths_root ()
{
    GList *paths = NULL;

    CU_ASSERT (apteryx_set_string (TEST_PATH"/interfaces/eth0", NULL, "-"));
    CU_ASSERT ((paths = apteryx_search (NULL)) == NULL);
    CU_ASSERT ((paths = apteryx_search ("")) == NULL);
    CU_ASSERT ((paths = apteryx_search ("*")) == NULL);
    CU_ASSERT ((paths = apteryx_search ("/")) != NULL);
    CU_ASSERT (g_list_find_custom (paths, TEST_PATH, (GCompareFunc) strcmp) != NULL);
    g_list_free_full (paths, free);
    paths = NULL;

    CU_ASSERT (apteryx_set_string (TEST_PATH"/interfaces/eth0", NULL, NULL));
    CU_ASSERT (assert_apteryx_empty ());
}

void
test_perf_search ()
{
    GList *paths = NULL;
    uint64_t start;
    int i;

    CU_ASSERT (apteryx_set_string (TEST_PATH"/interfaces", NULL, "-"));
    CU_ASSERT (apteryx_set_string (TEST_PATH"/interfaces/eth0", NULL, "-"));
    start = get_time_us ();
    for (i = 0; i < TEST_ITERATIONS; i++)
    {
        CU_ASSERT ((paths = apteryx_search ("/")) != NULL);
        if (paths == NULL)
            goto exit;
        g_list_free_full (paths, free);
    }
    printf ("%"PRIu64"us ... ", (get_time_us () - start) / TEST_ITERATIONS);
exit:
    CU_ASSERT (apteryx_set_string (TEST_PATH"/interfaces", NULL, NULL));
    CU_ASSERT (apteryx_set_string (TEST_PATH"/interfaces/eth0", NULL, NULL));
    CU_ASSERT (assert_apteryx_empty ());
}

static GList*
test_index_cb (const char *path)
{
    GList *paths = NULL;
    paths = g_list_append (paths, strdup (TEST_PATH"/counters/rx"));
    paths = g_list_append (paths, strdup (TEST_PATH"/counters/tx"));
    return paths;
}

static GList*
test_index_cb2 (const char *path)
{
    GList *paths = NULL;
    paths = g_list_append (paths, strdup (TEST_PATH"/counters/up"));
    paths = g_list_append (paths, strdup (TEST_PATH"/counters/down"));
    return paths;
}

static GList*
test_index_cb_wild (const char *path)
{
    GList *paths = NULL;
    if (strcmp (path, TEST_PATH"/counters/") == 0)
    {
        paths = g_list_append (paths, strdup (TEST_PATH"/counters/rx"));
        paths = g_list_append (paths, strdup (TEST_PATH"/counters/tx"));
    }
    else if (strcmp (path, TEST_PATH"/counters/rx/") == 0)
    {
        paths = g_list_append (paths, strdup (TEST_PATH"/counters/rx/pkts"));
        paths = g_list_append (paths, strdup (TEST_PATH"/counters/rx/bytes"));
    }
    else
    {
        paths = g_list_append (paths, strdup (TEST_PATH"/counters/tx/pkts"));
        paths = g_list_append (paths, strdup (TEST_PATH"/counters/tx/bytes"));
    }
    return paths;
}

void
test_index ()
{
    char *path = TEST_PATH"/counters/";
    GList *paths = NULL;

    CU_ASSERT (apteryx_index (path, test_index_cb));
    CU_ASSERT ((paths = apteryx_search (path)) != NULL);
    CU_ASSERT (g_list_length (paths) == 2);
    CU_ASSERT (g_list_find_custom (paths, TEST_PATH"/counters/rx", (GCompareFunc) strcmp) != NULL);
    CU_ASSERT (g_list_find_custom (paths, TEST_PATH"/counters/tx", (GCompareFunc) strcmp) != NULL);
    g_list_free_full (paths, free);
    CU_ASSERT (apteryx_unindex (path, test_index_cb));
    CU_ASSERT (assert_apteryx_empty ());
}

void
test_index_wildcard ()
{
    char *path = TEST_PATH"/counters/*";
    GList *paths = NULL;

    CU_ASSERT (apteryx_index (path, test_index_cb_wild));
    CU_ASSERT ((paths = apteryx_search (TEST_PATH"/counters/")) != NULL);
    CU_ASSERT (g_list_length (paths) == 2);
    CU_ASSERT (g_list_find_custom (paths, TEST_PATH"/counters/rx", (GCompareFunc) strcmp) != NULL);
    CU_ASSERT (g_list_find_custom (paths, TEST_PATH"/counters/tx", (GCompareFunc) strcmp) != NULL);
    for (GList * _iter = paths; _iter; _iter = _iter->next)
    {
        char *_path = NULL;
        GList *subpaths = NULL;

        CU_ASSERT (asprintf (&_path, "%s/", (char *) _iter->data) > 0);
        CU_ASSERT ((subpaths = apteryx_search (_path)) != NULL);
        CU_ASSERT (g_list_length (paths) == 2);
        if (strcmp (_path, TEST_PATH"/counters/rx/") == 0)
        {
            CU_ASSERT (g_list_find_custom (subpaths, TEST_PATH"/counters/rx/pkts", (GCompareFunc) strcmp) != NULL);
            CU_ASSERT (g_list_find_custom (subpaths, TEST_PATH"/counters/rx/bytes", (GCompareFunc) strcmp) != NULL);
        }
        else
        {
            CU_ASSERT (g_list_find_custom (subpaths, TEST_PATH"/counters/tx/pkts", (GCompareFunc) strcmp) != NULL);
            CU_ASSERT (g_list_find_custom (subpaths, TEST_PATH"/counters/tx/bytes", (GCompareFunc) strcmp) != NULL);
        }
        g_list_free_full (subpaths, free);
        free (_path);
    }
    g_list_free_full (paths, free);
    CU_ASSERT (apteryx_unindex (path, test_index_cb_wild));
    CU_ASSERT (assert_apteryx_empty ());
}

void
test_index_before_db ()
{
    char *path = TEST_PATH"/counters/";
    GList *paths = NULL;

    CU_ASSERT (apteryx_set (TEST_PATH"/counters/up", "1"));
    CU_ASSERT (apteryx_set (TEST_PATH"/counters/down", "2"));
    CU_ASSERT (apteryx_index (path, test_index_cb));
    CU_ASSERT ((paths = apteryx_search (path)) != NULL);
    CU_ASSERT (g_list_length (paths) == 2);
    CU_ASSERT (g_list_find_custom (paths, TEST_PATH"/counters/rx", (GCompareFunc) strcmp) != NULL);
    CU_ASSERT (g_list_find_custom (paths, TEST_PATH"/counters/tx", (GCompareFunc) strcmp) != NULL);
    g_list_free_full (paths, free);
    CU_ASSERT (apteryx_unindex (path, test_index_cb));
    CU_ASSERT (apteryx_set (TEST_PATH"/counters/up", NULL));
    CU_ASSERT (apteryx_set (TEST_PATH"/counters/down", NULL));
    CU_ASSERT (assert_apteryx_empty ());
}

void
test_index_replace_handler ()
{
    char *path = TEST_PATH"/counters/";
    GList *paths = NULL;

    CU_ASSERT (apteryx_index (path, test_index_cb));
    CU_ASSERT (apteryx_index (path, test_index_cb2));
    CU_ASSERT ((paths = apteryx_search (path)) != NULL);
    CU_ASSERT (g_list_length (paths) == 2);
    CU_ASSERT (g_list_find_custom (paths, TEST_PATH"/counters/up", (GCompareFunc) strcmp) != NULL);
    CU_ASSERT (g_list_find_custom (paths, TEST_PATH"/counters/down", (GCompareFunc) strcmp) != NULL);
    g_list_free_full (paths, free);
    CU_ASSERT (apteryx_unindex (path, test_index_cb2));
    CU_ASSERT (apteryx_unindex (path, test_index_cb));
    CU_ASSERT (assert_apteryx_empty ());
}

void
test_index_no_handler ()
{
    char *path = TEST_PATH"/counters/";

    CU_ASSERT (apteryx_search (path) == NULL);
    CU_ASSERT (assert_apteryx_empty ());
}

void
test_index_remove_handler ()
{
    char *path = TEST_PATH"/counters/";

    CU_ASSERT (apteryx_index (path, test_index_cb));
    CU_ASSERT (apteryx_unindex (path, test_index_cb));
    CU_ASSERT (apteryx_search (path) == NULL);
    CU_ASSERT (assert_apteryx_empty ());
}

static char *
_dummy_provide(const char *d)
{
    return NULL;
}

static GList *
_null_index(const char *d)
{
    return NULL;
}

void
test_index_and_provide ()
{
    char *path = TEST_PATH"/counters/*";

    CU_ASSERT (apteryx_provide (path, _dummy_provide));
    CU_ASSERT (apteryx_index (path, _null_index));
    CU_ASSERT (apteryx_search (TEST_PATH"/counters/") == NULL);
    CU_ASSERT (apteryx_unprovide (path, _dummy_provide));
    CU_ASSERT (apteryx_unindex (path, _null_index));
    CU_ASSERT (assert_apteryx_empty ());
}

void
test_prune ()
{
    GList *paths = NULL;

    CU_ASSERT (apteryx_set_string (TEST_PATH"/interfaces", NULL, "-"));
    CU_ASSERT (apteryx_set_string (TEST_PATH"/interfaces/eth0", NULL, "-"));
    CU_ASSERT (apteryx_set_string (TEST_PATH"/interfaces/eth0/state", NULL, "up"));
    CU_ASSERT (apteryx_set_string (TEST_PATH"/entities", NULL, "-"));
    CU_ASSERT (apteryx_set_string (TEST_PATH"/entities/zones", NULL, "-"));
    CU_ASSERT (apteryx_set_string (TEST_PATH"/entities/zones/public", NULL, "-"));
    CU_ASSERT (apteryx_set_string (TEST_PATH"/entities/zones/private", NULL, "-"));
    CU_ASSERT (apteryx_prune (TEST_PATH"/interfaces"));

    CU_ASSERT ((paths = apteryx_search (TEST_PATH"/interfaces/")) == NULL);
    CU_ASSERT ((paths = apteryx_search (TEST_PATH"/entities/zones/")) != NULL);
    CU_ASSERT (g_list_length (paths) == 2);
    g_list_free_full (paths, free);
    CU_ASSERT (apteryx_prune (TEST_PATH"/entities"));
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
    const char *path = TEST_PATH"/entity/zones/private/state";

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
    const char *path = TEST_PATH"/entity/zones/private/state";

    apteryx_set_string (path, NULL, "down");

    return 0;
}

void
test_watch_thread ()
{
    pthread_t client;
    const char *path = TEST_PATH"/entity/zones/private/state";

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
    const char *path = TEST_PATH"/entity/zones/private/state";
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
    const char *path1 = TEST_PATH"/entity/zones/private/state";
    const char *path2 = TEST_PATH"/entity/zones/private/active";

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
    const char *path = TEST_PATH"/entity/zones/private/state";

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
    const char *path = TEST_PATH"/entity/zones/private/state";

    CU_ASSERT (apteryx_set_string (path, NULL, "up"));
    usleep (TEST_SLEEP_TIMEOUT);
    CU_ASSERT (apteryx_watch (TEST_PATH"/entity/zones/private/*", test_watch_callback));
    CU_ASSERT (apteryx_set (path, NULL));
    usleep (TEST_SLEEP_TIMEOUT);

    CU_ASSERT (_path && strcmp (path, _path) == 0);
    CU_ASSERT (_value == NULL);

    CU_ASSERT (apteryx_unwatch (TEST_PATH"/entity/zones/private/*", test_watch_callback));
    _watch_cleanup ();
}

void
test_watch_one_level_path ()
{
    _path = _value = NULL;
    const char *path = TEST_PATH"/entity/zones/private/state";

    CU_ASSERT (apteryx_set_string (path, NULL, "up"));
    CU_ASSERT (apteryx_watch
               (TEST_PATH"/entity/zones/private/", test_watch_callback));
    CU_ASSERT (apteryx_set_string (path, NULL, "down"));
    usleep (TEST_SLEEP_TIMEOUT);
    CU_ASSERT (_path && strcmp (_path, path) == 0);
    CU_ASSERT (_value && strcmp (_value, "down") == 0);

    CU_ASSERT (apteryx_unwatch (TEST_PATH"/entity/zones/private/", test_watch_callback));
    CU_ASSERT (apteryx_set_string (path, NULL, NULL));
    _watch_cleanup ();
}


void
test_watch_one_level_path_prune ()
{
    _path = _value = NULL;
    const char *path = TEST_PATH"/entity/zones/private";

    CU_ASSERT (apteryx_set_string (path, "state", "up"));
    CU_ASSERT (apteryx_watch
               (TEST_PATH"/entity/zones/private/", test_watch_callback));
    CU_ASSERT (apteryx_prune (TEST_PATH"/entity/zones/private/state"));
    usleep (TEST_SLEEP_TIMEOUT);
    CU_ASSERT (_path && strstr (_path, path));

    CU_ASSERT (apteryx_unwatch (TEST_PATH"/entity/zones/private/", test_watch_callback));
    CU_ASSERT (apteryx_set_string (path, "state", NULL));
    _watch_cleanup ();
}

void
test_watch_wildpath ()
{
    _path = _value = NULL;
    const char *path = TEST_PATH"/entity/zones/private/interface/state";

    CU_ASSERT (apteryx_set_string (path, NULL, "up"));
    CU_ASSERT (apteryx_watch (TEST_PATH"/entity/zones/*/interface/*", test_watch_callback));
    CU_ASSERT (apteryx_set_string (path, NULL, "down"));
    usleep (TEST_SLEEP_TIMEOUT);
    CU_ASSERT (_path && strcmp (_path, path) == 0);
    CU_ASSERT (_value && strcmp (_value, "down") == 0);

    CU_ASSERT (apteryx_unwatch (TEST_PATH"/entity/zones/*/interface/*", test_watch_callback));
    CU_ASSERT (apteryx_set_string (path, NULL, NULL));
    _watch_cleanup ();
}

void
test_watch_wildcard ()
{
    _path = _value = NULL;
    const char *path = TEST_PATH"/entity/zones/private/state";

    CU_ASSERT (apteryx_set_string (path, NULL, "up"));
    CU_ASSERT (apteryx_watch (TEST_PATH"/entity/zones/*", test_watch_callback));
    CU_ASSERT (apteryx_set_string (path, NULL, "down"));
    usleep (TEST_SLEEP_TIMEOUT);
    CU_ASSERT (_path && strcmp (_path, path) == 0);
    CU_ASSERT (_value && strcmp (_value, "down") == 0);

    CU_ASSERT (apteryx_unwatch (TEST_PATH"/entity/zones/*", test_watch_callback));
    CU_ASSERT (apteryx_set_string (path, NULL, NULL));
    _watch_cleanup ();
}

/* We now support wildcards in the watch path
 */
void
test_watch_wildcard_not_last ()
{
    _path = _value = NULL;
    const char *path = TEST_PATH"/entity/zones/public/state";

    usleep (TEST_SLEEP_TIMEOUT);
    CU_ASSERT (apteryx_watch
               (TEST_PATH"/entity/zones/*/state", test_watch_callback));
    CU_ASSERT (apteryx_set_string (path, NULL, "up"));
    usleep (TEST_SLEEP_TIMEOUT);
    CU_ASSERT (_path && strcmp(_path, path) == 0);
    CU_ASSERT (apteryx_unwatch (TEST_PATH"/entity/zones/*/state", test_watch_callback));
    CU_ASSERT (apteryx_set_string (path, NULL, NULL));
    _watch_cleanup ();
}

void
test_watch_wildcard_miss ()
{
    _path = _value = NULL;

    CU_ASSERT (apteryx_watch
               (TEST_PATH"/entity/zones/private/*", test_watch_callback));
    CU_ASSERT (apteryx_watch
               (TEST_PATH"/entity/zones/private/active", test_watch_callback));
    CU_ASSERT (apteryx_watch (TEST_PATH"/entity/other/*", test_watch_callback));
    CU_ASSERT (apteryx_set_string (TEST_PATH"/entity/zones/public/state", NULL, "up"));
    usleep (TEST_SLEEP_TIMEOUT);

    CU_ASSERT (_path == NULL);
    CU_ASSERT (_value == NULL);

    CU_ASSERT (apteryx_unwatch (TEST_PATH"/entity/zones/private/*", test_watch_callback));
    CU_ASSERT (apteryx_unwatch (TEST_PATH"/entity/zones/private/active", test_watch_callback));
    CU_ASSERT (apteryx_unwatch (TEST_PATH"/entity/other/*", test_watch_callback));

    apteryx_set_string (TEST_PATH"/entity/zones/public/state", NULL, NULL);
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
    const char *path = TEST_PATH"/entity/zones/private/state";
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
    const char *path = TEST_PATH"/entity/zones/private/state";
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
    const char *path = TEST_PATH"/entity/zones/private/state";
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
    const char *path = TEST_PATH"/entity/zones/private/state";
    apteryx_watch (path, test_watch_set_thread_cb);
    while (!test_watch_set_thread_done)
        usleep (10);
    return 0;
}

void
test_watch_set_thread ()
{
    pthread_t client;
    const char *path = TEST_PATH"/entity/zones/private/state";
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
    if (strcmp (path, TEST_PATH"/entity/zones/public/state") == 0)
    {
        _cb_count++;
        apteryx_watch (path, test_watch_callback);
        apteryx_unwatch (TEST_PATH"/entity/zones/public/*", test_watch_adds_watch_cb);
    }
    return true;
}

void
test_watch_adds_watch ()
{
    _path = _value = NULL;

    apteryx_watch (TEST_PATH"/entity/zones/public/*", test_watch_adds_watch_cb);
    apteryx_set_string (TEST_PATH"/entity/zones/public/state", NULL, "new_cb");
    usleep (TEST_SLEEP_TIMEOUT);
    CU_ASSERT (_cb_count == 1);
    apteryx_set_string (TEST_PATH"/entity/zones/public/state", NULL, "new_cb_two");
    usleep (TEST_SLEEP_TIMEOUT);
    CU_ASSERT (_cb_count == 1);
    CU_ASSERT (_path && strcmp (TEST_PATH"/entity/zones/public/state", _path) == 0);
    CU_ASSERT (_value && strcmp ("new_cb_two", _value) == 0);
    apteryx_unwatch (TEST_PATH"/entity/zones/public/state", test_watch_callback);
    apteryx_set_string (TEST_PATH"/entity/zones/public/state", NULL, NULL);
    _watch_cleanup ();
}

static bool
test_watch_removes_all_watchs_cb (const char *path, const char *value)
{
    if (path && strcmp (path, TEST_PATH"/entity/zones/public/state") == 0)
    {
        _cb_count++;
        apteryx_unwatch (TEST_PATH"/entity/zones/public/state",test_watch_removes_all_watchs_cb);
        apteryx_unwatch (TEST_PATH"/entity/zones/public/*", test_watch_removes_all_watchs_cb);
        apteryx_unwatch (TEST_PATH"/*", test_watch_removes_all_watchs_cb);
        apteryx_unwatch (TEST_PATH"/entity/zones/public/active", test_watch_removes_all_watchs_cb);
    }
    return true;
}

void
test_watch_removes_all_watches ()
{
    const char *path = TEST_PATH"/entity/zones/public/state";
    _cb_count = 0;
    _path = _value = NULL;

    apteryx_set_string (path, NULL, "new_cb_two");
    usleep (TEST_SLEEP_TIMEOUT);
    apteryx_watch (TEST_PATH"/*", test_watch_removes_all_watchs_cb);
    apteryx_watch (TEST_PATH"/entity/zones/public/*", test_watch_removes_all_watchs_cb);
    apteryx_watch (TEST_PATH"/entity/zones/public/active", test_watch_removes_all_watchs_cb);
    apteryx_watch (TEST_PATH"/entity/zones/public/state", test_watch_removes_all_watchs_cb);
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
        CU_ASSERT (apteryx_set_int (TEST_PATH"/interfaces/eth0/packets", NULL, i));
    }
    usleep (RPC_TIMEOUT_US);
    return true;
}

void
test_watch_when_busy ()
{
    _cb_count = 0;
    CU_ASSERT (apteryx_set_int (TEST_PATH"/interfaces/eth0/packets", NULL, 0));
    CU_ASSERT (apteryx_watch (TEST_PATH"/interfaces/eth0/packets", test_watch_count_callback));
    CU_ASSERT (apteryx_watch (TEST_PATH"/busy/watch", test_watch_busy_callback));
    CU_ASSERT (apteryx_set_string (TEST_PATH"/busy/watch", NULL, "go"));
    usleep (2*RPC_TIMEOUT_US);
    CU_ASSERT (_cb_count == 100);
    CU_ASSERT (apteryx_get_int (TEST_PATH"/interfaces/eth0/packets", NULL) == 99);
    CU_ASSERT (apteryx_unwatch (TEST_PATH"/interfaces/eth0/packets", test_watch_count_callback));
    CU_ASSERT (apteryx_unwatch (TEST_PATH"/busy/watch", test_watch_busy_callback));
    apteryx_set (TEST_PATH"/interfaces/eth0/packets", NULL);
    apteryx_set (TEST_PATH"/busy/watch", NULL);
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
    const char *path = TEST_PATH"/entity/zones/private/state";
    uint64_t start;
    int i;

    pthread_mutex_init (&watch_lock, NULL);
    CU_ASSERT (apteryx_watch (path, test_perf_watch_callback));
    start = get_time_us ();
    for (i = 0; i < TEST_ITERATIONS; i++)
    {
        pthread_mutex_lock (&watch_lock);
        CU_ASSERT (apteryx_set (path, "down"));
    }
    pthread_mutex_destroy (&watch_lock);
    printf ("%"PRIu64"us ... ", (get_time_us () - start) / TEST_ITERATIONS);

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
    const char *path = TEST_PATH"/entity/zones/private/state";

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
    const char *path = TEST_PATH"/entity/zones/private/";

    CU_ASSERT (apteryx_validate (path, test_validate_refuse_callback));
    usleep (TEST_SLEEP_TIMEOUT);
    CU_ASSERT (!apteryx_set_string (TEST_PATH"/entity/zones/private", "state", "up"));
    usleep (TEST_SLEEP_TIMEOUT);
    CU_ASSERT (apteryx_unvalidate (path, test_validate_refuse_callback));
    apteryx_set_string (path, "state", NULL);
}

void
test_validate_wildcard()
{
    _path = _value = NULL;
    const char *path = TEST_PATH"/entity/zones/*";

    CU_ASSERT (apteryx_validate (path, test_validate_refuse_callback));
    usleep (TEST_SLEEP_TIMEOUT);
    CU_ASSERT (!apteryx_set_string (TEST_PATH"/entity/zones/one/two", "state", "up"));
    usleep (TEST_SLEEP_TIMEOUT);
    CU_ASSERT (apteryx_unvalidate (path, test_validate_refuse_callback));
    apteryx_set_string (path, NULL, NULL);
}

void
test_validate_wildcard_internal()
{
    _path = _value = NULL;
    const char *path = TEST_PATH"/entity/*/private/state";

    CU_ASSERT (apteryx_validate (path, test_validate_refuse_callback));
    usleep (TEST_SLEEP_TIMEOUT);
    CU_ASSERT (!apteryx_set_string (TEST_PATH"/entity/zones/private", "state", "up"));
    CU_ASSERT (apteryx_set_string (TEST_PATH"/entity/zones/private", "link", "up"));
    usleep (TEST_SLEEP_TIMEOUT);
    CU_ASSERT (apteryx_unvalidate (path, test_validate_refuse_callback));
    apteryx_set_string (TEST_PATH"/entity/zones/private", "state", NULL);
    apteryx_set_string (TEST_PATH"/entity/zones/private", "link", NULL);
    CU_ASSERT (assert_apteryx_empty ());
}

static int already_set = 0;
static int failed = 0;

static int
test_validate_thread_client (void *data)
{
    const char *path = TEST_PATH"/entity/zones/private/state";

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
    /* Block long enough to serialise the 2nd validate, avoiding RPC timeout */
    usleep (RPC_TIMEOUT_US - 10000);
    already_set++;
    return true;
}

void
test_validate_conflicting ()
{
    pthread_t client1, client2;
    const char *path = TEST_PATH"/entity/zones/private/state";

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
    const char *path = TEST_PATH"/interfaces/eth0/state";
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
    const char *path = TEST_PATH"/interfaces/eth0/state";
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
    const char *path = TEST_PATH"/interfaces/eth0/state";
    const char *value = NULL;

    CU_ASSERT ((value = apteryx_get (path)) == NULL);
    CU_ASSERT (assert_apteryx_empty ());
}

void
test_provide_remove_handler ()
{
    const char *path = TEST_PATH"/interfaces/eth0/state";
    const char *value = NULL;

    CU_ASSERT (apteryx_provide (path, test_provide_callback_up));
    CU_ASSERT (apteryx_unprovide (path, test_provide_callback_up));
    CU_ASSERT ((value = apteryx_get (path)) == NULL);
    CU_ASSERT (assert_apteryx_empty ());
}

static char*
test_provide_timeout_cb (const char *path)
{
    usleep (1.1 * RPC_TIMEOUT_US);
    return strdup ("down");
}

void
test_provide_timeout ()
{
    const char *path = TEST_PATH"/interfaces/eth0/state";
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
    const char *path = TEST_PATH"/interfaces/eth0/state";

    apteryx_provide (path, test_provide_callback_up);

    while (test_provide_thread_running)
        usleep (TEST_SLEEP_TIMEOUT);

    apteryx_unprovide (path, test_provide_callback_up);

    return 0;
}

void
test_provide_different_thread ()
{
    const char *path = TEST_PATH"/interfaces/eth0/state";
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
    const char *path = TEST_PATH"/interfaces/eth0/state";
    const char *value = NULL;
    int pid;
    int status;

    apteryx_shutdown ();
    if ((pid = fork ()) == 0)
    {
        apteryx_init (debug);
        CU_ASSERT (apteryx_provide (path, test_provide_callback_up));
        usleep (RPC_TIMEOUT_US);
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
    return apteryx_get (TEST_PATH"/interfaces/eth0/state");
}

void
test_provide_callback_get ()
{
    const char *path1 = TEST_PATH"/interfaces/eth0/state";
    const char *path2 = TEST_PATH"/interfaces/eth0/status";
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
    const char *path = TEST_PATH"/interfaces/eth0/status";
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
    const char *path = TEST_PATH"/interfaces/eth0/state";
    GList *paths = NULL;

    CU_ASSERT (apteryx_provide (path, test_provide_callback_up));
    CU_ASSERT ((paths = apteryx_search (TEST_PATH"/interfaces/eth0/")) != NULL);
    CU_ASSERT (g_list_length (paths) == 1);
    CU_ASSERT (g_list_find_custom (paths, path, (GCompareFunc) strcmp) != NULL);
    g_list_free_full (paths, free);
    apteryx_unprovide (path, test_provide_callback_up);
    CU_ASSERT (assert_apteryx_empty ());
}

void
test_provide_search_db ()
{
    const char *path1 = TEST_PATH"/interfaces/eth0/state";
    const char *path2 = TEST_PATH"/interfaces/eth0/speed";
    GList *paths = NULL;

    CU_ASSERT (apteryx_provide (path1, test_provide_callback_up));
    CU_ASSERT (apteryx_set (path2, "100"));
    CU_ASSERT ((paths = apteryx_search (TEST_PATH"/interfaces/eth0/")) != NULL);
    CU_ASSERT (g_list_length (paths) == 2);
    CU_ASSERT (g_list_find_custom (paths, path1, (GCompareFunc) strcmp) != NULL);
    CU_ASSERT (g_list_find_custom (paths, path2, (GCompareFunc) strcmp) != NULL);
    g_list_free_full (paths, free);
    apteryx_unprovide (path1, test_provide_callback_up);
    CU_ASSERT (apteryx_set (path2, NULL));
    CU_ASSERT (assert_apteryx_empty ());
}

void
test_provide_after_db ()
{
    const char *path = TEST_PATH"/interfaces/eth0/state";
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
test_tree_nodes ()
{
    GNode* root;

    root = APTERYX_NODE (NULL, TEST_PATH"/interfaces/eth0");
    APTERYX_LEAF (root, "state", "up");
    APTERYX_LEAF (root, "speed", "1000");
    APTERYX_LEAF (root, "duplex", "full");
    CU_ASSERT (root != NULL);
    CU_ASSERT (g_node_n_nodes (root, G_TRAVERSE_LEAFS) == 3);
    CU_ASSERT (g_node_n_children (root) == 3);
    CU_ASSERT (!APTERYX_HAS_VALUE(root));
    CU_ASSERT (strcmp (APTERYX_NAME (g_node_nth_child (root, 0)), "state") == 0);
    CU_ASSERT (APTERYX_HAS_VALUE(g_node_nth_child (root, 0)));
    CU_ASSERT (strcmp (APTERYX_VALUE (g_node_nth_child (root, 0)), "up") == 0);
    CU_ASSERT (strcmp (APTERYX_NAME (g_node_nth_child (root, 1)), "speed") == 0);
    CU_ASSERT (APTERYX_HAS_VALUE(g_node_nth_child (root, 1)));
    CU_ASSERT (strcmp (APTERYX_VALUE (g_node_nth_child (root, 1)), "1000") == 0);
    CU_ASSERT (strcmp (APTERYX_NAME (g_node_nth_child (root, 2)), "duplex") == 0);
    CU_ASSERT (APTERYX_HAS_VALUE(g_node_nth_child (root, 2)));
    CU_ASSERT (strcmp (APTERYX_VALUE (g_node_nth_child (root, 2)), "full") == 0);
    g_node_destroy (root);
    CU_ASSERT (assert_apteryx_empty ());
}

void
test_tree_nodes_deep ()
{
    GNode *root, *node;
    char *name, *path;
    int i;

    CU_ASSERT ((name = strdup (TEST_PATH"/root")) != NULL);
    CU_ASSERT ((root = APTERYX_NODE (NULL, name)) != NULL);
    node = root;
    for (i=0; i<1024; i++)
    {
        name = NULL;
        CU_ASSERT (asprintf (&name, "%d", i));
        CU_ASSERT ((node = APTERYX_NODE (node, name)) != NULL);
    }
    path = apteryx_node_path (node);
    CU_ASSERT (strlen (path) == 4020);
    free (path);
    CU_ASSERT (g_node_n_children (node) == 0);
    CU_ASSERT (APTERYX_NUM_NODES (root) == 1024);
    CU_ASSERT (g_node_n_nodes (root, G_TRAVERSE_ALL) == 1025);
    CU_ASSERT (g_node_n_nodes (root, G_TRAVERSE_LEAVES) == 1);
    CU_ASSERT (g_node_n_children (root) == 1);
    CU_ASSERT (!APTERYX_HAS_VALUE(root));
    apteryx_free_tree (root);
    CU_ASSERT (assert_apteryx_empty ());
}

void
test_tree_nodes_wide ()
{
    GNode *root, *node;
    char *name, *value, *path;
    int i;

    CU_ASSERT ((name = strdup (TEST_PATH"/root")) != NULL);
    CU_ASSERT ((root = APTERYX_NODE (NULL, name)) != NULL);
    for (i=0; i<1024; i++)
    {
        name = value = NULL;
        CU_ASSERT (asprintf (&name, "%d", i));
        CU_ASSERT (asprintf (&value, "%d", i));
        APTERYX_LEAF (root, name, value);
    }
    CU_ASSERT ((node = g_node_first_child (root)) != NULL);
    path = apteryx_node_path (node);
    CU_ASSERT (strlen (path) == 12);
    free (path);
    CU_ASSERT ((node = g_node_last_child (root)) != NULL);
    path = apteryx_node_path (node);
    CU_ASSERT (strlen (path) == 15);
    free (path);
    CU_ASSERT (APTERYX_NUM_NODES (root) == 1025);
    CU_ASSERT (g_node_n_nodes (root, G_TRAVERSE_ALL) == 2049);
    CU_ASSERT (g_node_n_nodes (root, G_TRAVERSE_LEAVES) == 1024);
    CU_ASSERT (g_node_n_children (root) == 1024);
    CU_ASSERT (!APTERYX_HAS_VALUE(root));
    apteryx_free_tree (root);
    CU_ASSERT (assert_apteryx_empty ());
}

void
test_tree_docs ()
{
    GNode* root = APTERYX_NODE (NULL, "/interfaces/eth0");
    GNode* state = APTERYX_NODE (root, "state");
    APTERYX_LEAF (state, "state", "up");
    APTERYX_LEAF (state, "speed", "1000");
    APTERYX_LEAF (state, "duplex", "full");
    printf ("\nNumber of nodes = %d\n", APTERYX_NUM_NODES (root));
    printf ("Number of paths = %d\n", g_node_n_nodes (root, G_TRAVERSE_LEAVES));
    for (GNode *node = g_node_first_child (state); node; node = g_node_next_sibling (node)) {
        char* path = apteryx_node_path (node);
        printf ("%s = %s\n", path, APTERYX_VALUE (node));
        free (path);
    }
    g_node_destroy (root);
}

void
test_set_tree ()
{
    GNode* root;
    const char *value = NULL;

    root = APTERYX_NODE (NULL, TEST_PATH"/interfaces/eth0");
    APTERYX_LEAF (root, "state", "up");
    APTERYX_LEAF (root, "speed", "1000");
    APTERYX_LEAF (root, "duplex", "full");
    CU_ASSERT (apteryx_set_tree (root));
    CU_ASSERT ((value = apteryx_get (TEST_PATH"/interfaces/eth0/speed")) != NULL);
    CU_ASSERT (value && strcmp (value, "1000") == 0);
    free ((void *) value);
    CU_ASSERT (apteryx_prune (TEST_PATH"/interfaces/eth0"));
    g_node_destroy (root);
    CU_ASSERT (assert_apteryx_empty ());
}

void
test_get_tree ()
{
    const char *path = TEST_PATH"/interfaces/eth0";
    GNode *root = NULL;
    GNode *node = NULL;

    CU_ASSERT (apteryx_set_string (path, "state", "up"));
    CU_ASSERT (apteryx_set_string (path, "speed", "1000"));
    CU_ASSERT (apteryx_set_string (path, "duplex", "full"));
    root = apteryx_get_tree (TEST_PATH"/interfaces");
    CU_ASSERT (root != NULL);
    CU_ASSERT (root && strcmp (APTERYX_NAME (root), TEST_PATH"/interfaces") == 0);
    CU_ASSERT (root && g_node_n_children (root) == 1);
    node = root ? g_node_first_child (root) : NULL;
    CU_ASSERT (node && strcmp (APTERYX_NAME (node), "eth0") == 0);
    CU_ASSERT (node && g_node_n_children (node) == 3);
    node = node ? g_node_first_child (node) : NULL;
    while (node)
    {
        if (strcmp (APTERYX_NAME (node), "state") == 0)
        {
            CU_ASSERT (strcmp (APTERYX_VALUE (node), "up") == 0);
        }
        else if (strcmp (APTERYX_NAME (node), "speed") == 0)
        {
            CU_ASSERT (strcmp (APTERYX_VALUE (node), "1000") == 0);
        }
        else if (strcmp (APTERYX_NAME (node), "duplex") == 0)
        {
            CU_ASSERT (strcmp (APTERYX_VALUE (node), "full") == 0);
        }
        else
        {
            CU_ASSERT (node == NULL);
        }
        node = node->next;
    }
    CU_ASSERT (apteryx_prune (path));
    apteryx_free_tree (root);
    CU_ASSERT (assert_apteryx_empty ());
}

void
test_get_tree_single_node ()
{
    const char *path = TEST_PATH"/interfaces/eth0/state";
    GNode *root = NULL;

    CU_ASSERT (apteryx_set (path, "up"));
    root = apteryx_get_tree (path);
    CU_ASSERT (root != NULL);
    CU_ASSERT (root && APTERYX_HAS_VALUE (root));
    CU_ASSERT (root && strcmp (APTERYX_NAME (root), path) == 0);
    if (root && APTERYX_HAS_VALUE (root))
    {
        CU_ASSERT (root && strcmp (APTERYX_VALUE (root), "up") == 0);
    }
    CU_ASSERT (apteryx_set (path, NULL));
    apteryx_free_tree (root);
    CU_ASSERT (assert_apteryx_empty ());
}

void
test_get_tree_null ()
{
    const char *path = TEST_PATH"/interfaces/eth0/state";
    GNode *root = NULL;

    root = apteryx_get_tree (path);
    CU_ASSERT (root == NULL);
    CU_ASSERT (assert_apteryx_empty ());
}

static char*
test_provide_callback_100 (const char *path)
{
    return strdup ("100");
}

static char*
test_provide_callback_1000 (const char *path)
{
    return strdup ("1000");
}

void
test_get_tree_indexed_provided ()
{
    GNode *root, *node, *child;

    CU_ASSERT (apteryx_index (TEST_PATH"/counters", test_index_cb));
    CU_ASSERT (apteryx_provide (TEST_PATH"/counters/rx/pkts", test_provide_callback_100));
    CU_ASSERT (apteryx_provide (TEST_PATH"/counters/rx/bytes", test_provide_callback_1000));
    CU_ASSERT (apteryx_provide (TEST_PATH"/counters/tx/pkts", test_provide_callback_1000));
    CU_ASSERT (apteryx_provide (TEST_PATH"/counters/tx/bytes", test_provide_callback_100));

    root = apteryx_get_tree (TEST_PATH"/counters");
    CU_ASSERT (root && g_node_n_children (root) == 2);
    node = root ? g_node_first_child (root) : NULL;
    while (node)
    {
        if (strcmp (APTERYX_NAME (node), "rx") == 0)
        {
            CU_ASSERT (g_node_n_children (node) == 2);
            child = g_node_first_child (node);
            while (child)
            {
                if (strcmp (APTERYX_NAME (child), "pkts") == 0)
                {
                    CU_ASSERT (strcmp (APTERYX_VALUE (child), "100") == 0);
                }
                else if (strcmp (APTERYX_NAME (child), "bytes") == 0)
                {
                    CU_ASSERT (strcmp (APTERYX_VALUE (child), "1000") == 0);
                }
                else
                {
                    CU_ASSERT (child == NULL);
                }
                child = child->next;
            }
        }
        else if (strcmp (APTERYX_NAME (node), "tx") == 0)
        {
            CU_ASSERT (g_node_n_children (node) == 2);
            child = g_node_first_child (node);
            while (child)
            {
                if (strcmp (APTERYX_NAME (child), "pkts") == 0)
                {
                    CU_ASSERT (strcmp (APTERYX_VALUE (child), "1000") == 0);
                }
                else if (strcmp (APTERYX_NAME (child), "bytes") == 0)
                {
                    CU_ASSERT (strcmp (APTERYX_VALUE (child), "100") == 0);
                }
                else
                {
                    CU_ASSERT (child == NULL);
                }
                child = child->next;
            }
        }
        else
        {
            CU_ASSERT (node == NULL);
        }
        node = node->next;
    }
    apteryx_free_tree (root);

    CU_ASSERT (apteryx_unprovide (TEST_PATH"/counters/rx/pkts", test_provide_callback_100));
    CU_ASSERT (apteryx_unprovide (TEST_PATH"/counters/rx/bytes", test_provide_callback_1000));
    CU_ASSERT (apteryx_unprovide (TEST_PATH"/counters/tx/pkts", test_provide_callback_1000));
    CU_ASSERT (apteryx_unprovide (TEST_PATH"/counters/tx/bytes", test_provide_callback_100));
    CU_ASSERT (apteryx_unindex (TEST_PATH"/counters", test_index_cb));
    CU_ASSERT (assert_apteryx_empty ());
}

void
test_perf_set_tree ()
{
    const char *path = TEST_PATH"/interfaces/eth0";
    char value[32];
    GNode* root;
    uint64_t start, time;
    int count = 50;
    int i;
    bool res;

    root = APTERYX_NODE (NULL, strdup (path));
    for (i=0; i<count; i++)
    {
        sprintf (value, "value%d", i);
        APTERYX_LEAF (root, strdup (value), strdup (value));
    }
    start = get_time_us ();
    for (i = 0; i < TEST_ITERATIONS; i++)
    {
        CU_ASSERT ((res = apteryx_set_tree (root)));
        if (!res)
            goto exit;
    }
    time = ((get_time_us () - start) / TEST_ITERATIONS);
    printf ("%"PRIu64"us(%"PRIu64"us) ... ", time, time/count);
exit:
    apteryx_free_tree (root);
    CU_ASSERT (apteryx_prune (path));
    CU_ASSERT (assert_apteryx_empty ());
}

void
test_perf_set_tree_5000 ()
{
    const char *path = TEST_PATH"/interfaces/eth0";
    char value[32];
    GNode* root;
    uint64_t start, time;
    int count = 5000;
    int i;
    bool res;

    root = APTERYX_NODE (NULL, strdup (path));
    for (i=0; i<count; i++)
    {
        sprintf (value, "value%d", i);
        APTERYX_LEAF (root, strdup (value), strdup (value));
    }
    start = get_time_us ();
    CU_ASSERT ((res = apteryx_set_tree (root)));
    if (!res)
        goto exit;
    time = (get_time_us () - start);
    printf ("%"PRIu64"us(%"PRIu64"us) ... ", time, time/count);
exit:
    apteryx_free_tree (root);
    CU_ASSERT (apteryx_prune (path));
    CU_ASSERT (assert_apteryx_empty ());
}

void
test_perf_get_tree ()
{
    const char *path = TEST_PATH"/interfaces/eth0";
    char value[32];
    GNode* root;
    uint64_t start, time;
    int count = 50;
    int i;

    for (i=0; i<count; i++)
    {
        sprintf (value, "value%d", i);
        CU_ASSERT (apteryx_set_string (path, value, value));
    }
    start = get_time_us ();
    for (i = 0; i < (TEST_ITERATIONS/10); i++)
    {
        root = apteryx_get_tree (path);
        if (!root)
            goto exit;
        apteryx_free_tree (root);
    }
    time = ((get_time_us () - start) / (TEST_ITERATIONS/10));
    printf ("%"PRIu64"us(%"PRIu64"us) ... ", time, time/count);
exit:
    CU_ASSERT (apteryx_prune (path));
    CU_ASSERT (assert_apteryx_empty ());
}

void
test_perf_get_tree_5000 ()
{
    const char *path = TEST_PATH"/interfaces/eth0";
    char value[32];
    GNode* root;
    uint64_t start, time;
    int count = 5000;
    int i;

    for (i=0; i<count; i++)
    {
        sprintf (value, "value%d", i);
        CU_ASSERT (apteryx_set_string (path, value, value));
    }
    start = get_time_us ();
    root = apteryx_get_tree (path);
    if (!root)
        goto exit;
    time = (get_time_us () - start);
    printf ("%"PRIu64"us(%"PRIu64"us) ... ", time, time/count);
    apteryx_free_tree (root);
exit:
    CU_ASSERT (apteryx_prune (path));
    CU_ASSERT (assert_apteryx_empty ());
}

void
test_perf_provide ()
{
    const char *path = TEST_PATH"/entity/zones/private/state";
    const char *value = NULL;
    uint64_t start;
    int i;

    CU_ASSERT (apteryx_provide (path, test_provide_callback_up));
    start = get_time_us ();
    for (i = 0; i < TEST_ITERATIONS; i++)
    {
        CU_ASSERT ((value = apteryx_get (path)) != NULL);
        if (!value)
            goto exit;
        free ((void *) value);
    }
    printf ("%"PRIu64"us ... ", (get_time_us () - start) / TEST_ITERATIONS);
exit:
    apteryx_unprovide (path, test_provide_callback_up);
    CU_ASSERT (assert_apteryx_empty ());
}

void
test_proxy_get ()
{
    const char *value = NULL;

    CU_ASSERT (apteryx_set (TEST_PATH"/local", "test"));
    CU_ASSERT (apteryx_bind (TEST_TCP_URL));
    CU_ASSERT (apteryx_proxy (TEST_PATH"/remote/*", TEST_TCP_URL));
    CU_ASSERT ((value = apteryx_get (TEST_PATH"/remote"TEST_PATH"/local")) != NULL);
    CU_ASSERT (value && strcmp (value, "test") == 0);
    if (value)
        free ((void *) value);
    CU_ASSERT (apteryx_unproxy (TEST_PATH"/remote/*", TEST_TCP_URL));
    CU_ASSERT (apteryx_unbind (TEST_TCP_URL));
    CU_ASSERT (apteryx_set (TEST_PATH"/local", NULL));
    CU_ASSERT (assert_apteryx_empty ());
}

void
test_proxy_set ()
{
    const char *value = NULL;

    CU_ASSERT (apteryx_bind (TEST_TCP_URL));
    CU_ASSERT (apteryx_proxy (TEST_PATH"/remote/*", TEST_TCP_URL));
    CU_ASSERT (apteryx_set (TEST_PATH"/remote/test/local", "test"));
    CU_ASSERT ((value = apteryx_get (TEST_PATH"/local")) != NULL);
    CU_ASSERT (value && strcmp (value, "test") == 0);
    if (value)
        free ((void *) value);
    CU_ASSERT (apteryx_unproxy (TEST_PATH"/remote/*", TEST_TCP_URL));
    CU_ASSERT (apteryx_unbind (TEST_TCP_URL));
    CU_ASSERT (apteryx_set (TEST_PATH"/local", NULL));
    CU_ASSERT (apteryx_set (TEST_PATH"/remote/test/local", NULL));
    CU_ASSERT (assert_apteryx_empty ());
}

void
test_proxy_not_listening ()
{
    CU_ASSERT (apteryx_set (TEST_PATH"/local", "test"));
    CU_ASSERT (apteryx_proxy (TEST_PATH"/remote/*", TEST_TCP_URL));
    CU_ASSERT (apteryx_get (TEST_PATH"/remote/test/local") == NULL);
    CU_ASSERT (apteryx_unproxy (TEST_PATH"/remote/*", TEST_TCP_URL));
    CU_ASSERT (apteryx_set (TEST_PATH"/local", NULL));
    CU_ASSERT (assert_apteryx_empty ());
}

void
test_proxy_before_db_get ()
{
    const char *value = NULL;

    CU_ASSERT (apteryx_set (TEST_PATH"/local", "dog"));
    CU_ASSERT (apteryx_set (TEST_PATH"/remote/test/local", "cat"));
    CU_ASSERT (apteryx_bind (TEST_TCP_URL));
    CU_ASSERT (apteryx_proxy (TEST_PATH"/remote/*", TEST_TCP_URL));
    CU_ASSERT ((value = apteryx_get (TEST_PATH"/remote/test/local")) != NULL);
    CU_ASSERT (value && strcmp (value, "dog") == 0);
    if (value)
        free ((void *) value);
    CU_ASSERT (apteryx_unproxy (TEST_PATH"/remote/*", TEST_TCP_URL));
    CU_ASSERT (apteryx_unbind (TEST_TCP_URL));
    CU_ASSERT (apteryx_set (TEST_PATH"/remote/test/local", NULL));
    CU_ASSERT (apteryx_set (TEST_PATH"/local", NULL));
    CU_ASSERT (assert_apteryx_empty ());
}

void
test_proxy_before_db_set ()
{
    CU_ASSERT (apteryx_bind (TEST_TCP_URL));
    CU_ASSERT (apteryx_proxy (TEST_PATH"/remote/*", TEST_TCP_URL));
    CU_ASSERT (apteryx_set (TEST_PATH"/remote/test/local", "test"));
    CU_ASSERT (apteryx_unproxy (TEST_PATH"/remote/*", TEST_TCP_URL));
    CU_ASSERT (apteryx_unbind (TEST_TCP_URL));
    CU_ASSERT (apteryx_get (TEST_PATH"/remote/test/local") == NULL);
    CU_ASSERT (apteryx_set (TEST_PATH"/remote/test/local", NULL));
    CU_ASSERT (apteryx_set (TEST_PATH"/local", NULL));
    CU_ASSERT (assert_apteryx_empty ());
}

void
test_proxy_set_validated ()
{
    CU_ASSERT (apteryx_validate (TEST_PATH"/local", test_validate_refuse_callback));
    CU_ASSERT (apteryx_bind (TEST_TCP_URL));
    CU_ASSERT (apteryx_proxy (TEST_PATH"/remote/*", TEST_TCP_URL));
    CU_ASSERT (!apteryx_set (TEST_PATH"/remote/test/local", "test"));
    CU_ASSERT (errno == -EPERM);
    CU_ASSERT (apteryx_unvalidate (TEST_PATH"/local", test_validate_refuse_callback));
    CU_ASSERT (apteryx_unproxy (TEST_PATH"/remote/*", TEST_TCP_URL));
    CU_ASSERT (apteryx_unbind (TEST_TCP_URL));
    CU_ASSERT (apteryx_set (TEST_PATH"/local", NULL));
    CU_ASSERT (assert_apteryx_empty ());
}

void
test_proxy_search ()
{
    GList *paths = NULL;

    CU_ASSERT (apteryx_set (TEST_PATH"/local/cat", "felix"));
    CU_ASSERT (apteryx_set (TEST_PATH"/local/dog", "fido"));
    CU_ASSERT (apteryx_bind (TEST_TCP_URL));
    CU_ASSERT (apteryx_proxy (TEST_PATH"/remote/*", TEST_TCP_URL));
    CU_ASSERT ((paths = apteryx_search (TEST_PATH"/remote/test/local/")) != NULL);
    CU_ASSERT (g_list_length (paths) == 2);
    CU_ASSERT (g_list_find_custom (paths, TEST_PATH"/remote"TEST_PATH"/local/cat",
            (GCompareFunc) strcmp) != NULL);
    CU_ASSERT (g_list_find_custom (paths, TEST_PATH"/remote"TEST_PATH"/local/dog",
            (GCompareFunc) strcmp) != NULL);
    g_list_free_full (paths, free);
    CU_ASSERT (apteryx_unproxy (TEST_PATH"/remote/*", TEST_TCP_URL));
    CU_ASSERT (apteryx_unbind (TEST_TCP_URL));
    CU_ASSERT (apteryx_set (TEST_PATH"/local/cat", NULL));
    CU_ASSERT (apteryx_set (TEST_PATH"/local/dog", NULL));
    CU_ASSERT (assert_apteryx_empty ());
}

void
test_proxy_prune ()
{
    GList *paths = NULL;

    CU_ASSERT (apteryx_set_string (TEST_PATH"/interfaces", NULL, "-"));
    CU_ASSERT (apteryx_set_string (TEST_PATH"/interfaces/eth0", NULL, "-"));
    CU_ASSERT (apteryx_set_string (TEST_PATH"/interfaces/eth0/state", NULL, "up"));
    CU_ASSERT (apteryx_set_string (TEST_PATH"/entities", NULL, "-"));
    CU_ASSERT (apteryx_set_string (TEST_PATH"/entities/zones", NULL, "-"));
    CU_ASSERT (apteryx_set_string (TEST_PATH"/entities/zones/public", NULL, "-"));
    CU_ASSERT (apteryx_set_string (TEST_PATH"/entities/zones/private", NULL, "-"));

    CU_ASSERT (apteryx_bind (TEST_TCP_URL));
    CU_ASSERT (apteryx_proxy (TEST_PATH"/remote/*", TEST_TCP_URL));
    CU_ASSERT (apteryx_prune (TEST_PATH"/remote"TEST_PATH"/interfaces"));
    CU_ASSERT ((paths = apteryx_search (TEST_PATH"/interfaces/")) == NULL);
    CU_ASSERT ((paths = apteryx_search (TEST_PATH"/entities/zones/")) != NULL);
    CU_ASSERT (g_list_length (paths) == 2);
    g_list_free_full (paths, free);

    CU_ASSERT (apteryx_prune (TEST_PATH"/entities"));
    CU_ASSERT (apteryx_unproxy (TEST_PATH"/remote/*", TEST_TCP_URL));
    CU_ASSERT (apteryx_unbind (TEST_TCP_URL));
    CU_ASSERT (assert_apteryx_empty ());
}

void
test_proxy_timestamp ()
{
    uint64_t ts = 0;

    CU_ASSERT (apteryx_set (TEST_PATH"/local", "test"));
    CU_ASSERT ((ts = apteryx_timestamp (TEST_PATH"/local")) != 0);
    CU_ASSERT (apteryx_bind (TEST_TCP_URL));
    CU_ASSERT (apteryx_proxy (TEST_PATH"/remote/*", TEST_TCP_URL));
    CU_ASSERT (apteryx_timestamp (TEST_PATH"/remote/test/local") == ts);
    CU_ASSERT (apteryx_unproxy (TEST_PATH"/remote/*", TEST_TCP_URL));
    CU_ASSERT (apteryx_unbind (TEST_TCP_URL));
    CU_ASSERT (apteryx_set (TEST_PATH"/local", NULL));
    CU_ASSERT (assert_apteryx_empty ());
}

static bool
test_deadlock_callback (const char *path, const char *value)
{
    apteryx_set(TEST_PATH"/goes/here", "changed");
    return true;
}

void
test_deadlock ()
{
    int i;

    for (i = 0; i < 1000; i++)
    {
        char *path = NULL;
        CU_ASSERT (asprintf(&path, TEST_PATH"/zones/private/state/%d", i) > 0);
        CU_ASSERT (apteryx_set (path, "set"));
        CU_ASSERT (apteryx_watch (path, test_deadlock_callback));
        free (path);
    }
    CU_ASSERT (apteryx_prune(TEST_PATH));
    usleep(1000);
    apteryx_shutdown();
    apteryx_init(false);

    for (i = 0; i < 1000; i++)
    {
        char *path = NULL;
        CU_ASSERT (asprintf(&path, TEST_PATH"/zones/private/state/%d", i) > 0);
        CU_ASSERT (apteryx_unwatch (path, test_deadlock_callback));
        free (path);
    }
    CU_ASSERT (apteryx_prune(TEST_PATH));
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
        CU_ASSERT (asprintf(&path, TEST_PATH"/zones/private/state/%d", i) > 0);
        CU_ASSERT (apteryx_set (path, "set"));
        CU_ASSERT (apteryx_watch (path, test_deadlock2_callback));
        free (path);
    }
    CU_ASSERT (apteryx_prune (TEST_PATH));
    usleep (200);
    apteryx_shutdown ();
    apteryx_init (false);

    for (i = 0; i < 1000; i++)
    {
        char *path = NULL;
        CU_ASSERT (asprintf (&path, TEST_PATH"/zones/private/state/%d", i) > 0);
        CU_ASSERT (apteryx_unwatch (path, test_deadlock2_callback));
        CU_ASSERT (apteryx_unwatch (path, test_deadlock_callback));
        free (path);
    }
    CU_ASSERT (apteryx_prune (TEST_PATH));
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
    apteryx_set_string (TEST_PATH"/interfaces/eth0", "description", "our lan");
    apteryx_set_string (TEST_PATH"/interfaces/eth0", "state", "up");
    apteryx_set_int (TEST_PATH"/interfaces/eth0/counters", "in_pkts", 10);
    apteryx_set_int (TEST_PATH"/interfaces/eth0/counters/out_pkts", NULL, 20);
    apteryx_set_string (TEST_PATH"/interfaces/eth1/description", NULL, "our wan");
    apteryx_set_string (TEST_PATH"/interfaces/eth1/state", NULL, "down");

    printf ("\nInterfaces:\n");
    GList *paths = apteryx_search (TEST_PATH"/interfaces/");
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

    apteryx_set_string (TEST_PATH"/interfaces/eth0", "description", NULL);
    apteryx_set_string (TEST_PATH"/interfaces/eth0", "state", NULL);
    apteryx_set_string (TEST_PATH"/interfaces/eth0/counters", "in_pkts", NULL);
    apteryx_set_string (TEST_PATH"/interfaces/eth0/counters/out_pkts", NULL, NULL);
    apteryx_set_string (TEST_PATH"/interfaces/eth1/description", NULL, NULL);
    apteryx_set_string (TEST_PATH"/interfaces/eth1/state", NULL, NULL);
    CU_ASSERT (assert_apteryx_empty ());
}

void
test_socket_latency (int family, bool cd, bool req, bool resp)
{
    int iterations = 2 * TEST_ITERATIONS;
    char buf[TEST_MESSAGE_SIZE] = {};
    union
    {
        struct sockaddr_in addr_in;
        struct sockaddr_in6 addr_in6;
        struct sockaddr_un addr_un;
    } server, client;
    socklen_t address_len, len;
    int64_t start, i, s, s2 = -1;
    int on = 1;
    int pid;
    int status;
    int ret;

    if (family == AF_UNIX)
    {
        server.addr_un.sun_family = AF_UNIX;
        strcpy (server.addr_un.sun_path, TEST_RPC_PATH);
        unlink (server.addr_un.sun_path);
        address_len = sizeof (server.addr_un);
    }
    else if (family == AF_INET)
    {
        server.addr_in.sin_family = AF_INET;
        server.addr_in.sin_port = htons (TEST_PORT_NUM);
        server.addr_in.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        address_len = sizeof (server.addr_in);
        client = server;
        client.addr_in.sin_port = htons (TEST_PORT_NUM+1);
    }
    else
    {
        CU_ASSERT (family == AF_UNIX || family == AF_INET);
        return;
    }
    CU_ASSERT ((s = socket (family, SOCK_STREAM, 0)) >= 0);
    CU_ASSERT (setsockopt (s, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on)) >= 0);
    CU_ASSERT ((ret = bind (s, (struct sockaddr *)&server, address_len)) >= 0);
    CU_ASSERT ((ret = listen (s, 5)) >= 0);
    if (ret < 0)
        return;

    CU_ASSERT (system ("sudo sysctl -w net.ipv4.tcp_tw_recycle=1 > /dev/null 2>&1") == 0);
    if ((pid = fork ()) == 0)
    {
        if (!cd)
        {
            len = address_len;
            CU_ASSERT ((s2 = accept (s, (struct sockaddr *)&client, &len)) >= 0);
            if (s2 < 0)
                exit (-1);
        }
        for (i = 0; i < iterations; i++)
        {
            if (cd)
            {
                len = address_len;
                CU_ASSERT ((s2 = accept (s, (struct sockaddr *)&client, &len)) >= 0);
                if (s2 < 0)
                    exit (-1);
            }
            if (req)
                CU_ASSERT (read (s2, buf, TEST_MESSAGE_SIZE) == TEST_MESSAGE_SIZE);
            if (resp)
                CU_ASSERT (write (s2, buf, TEST_MESSAGE_SIZE) == TEST_MESSAGE_SIZE);
            if (cd)
                close (s2);
        }
        if (!cd)
            close (s2);
        close (s);
        exit (0);
    }
    else
    {
        close (s);
        if (!cd)
        {
            CU_ASSERT ((s = socket (family, SOCK_STREAM, 0)) >= 0);
            CU_ASSERT (setsockopt (s, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on)) >= 0);
            CU_ASSERT ((ret = connect (s, (struct sockaddr *)&server, address_len)) == 0);
            if (ret)
                goto exit;
        }
        start = get_time_us ();
        for (i = 0; i < iterations; i++)
        {
            if (cd)
            {
                CU_ASSERT ((s = socket (family, SOCK_STREAM, 0)) >= 0);
                CU_ASSERT (setsockopt (s, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on)) >= 0);
                CU_ASSERT ((ret = connect (s, (struct sockaddr *)&server, address_len)) == 0);
                if (ret)
                    goto exit;
            }
            if (req)
                CU_ASSERT (write (s, buf, TEST_MESSAGE_SIZE) == TEST_MESSAGE_SIZE);
            if (resp)
                CU_ASSERT (read (s, buf, TEST_MESSAGE_SIZE) == TEST_MESSAGE_SIZE);
            if (cd)
                close (s);
        }
        printf ("%"PRIu64"us ... ", (get_time_us () - start) / iterations);
        if (!cd)
            close (s);
    }
exit:
    CU_ASSERT (system ("sudo sysctl -w net.ipv4.tcp_tw_recycle=0 > /dev/null 2>&1") == 0);
    kill (pid, 9);
    waitpid (pid, &status, 0);
}

void
test_unix_req_latency ()
{
    test_socket_latency (AF_UNIX, false, true, false);
}

void
test_unix_req_resp_latency ()
{
    test_socket_latency (AF_UNIX, false, true, true);
}

void
test_unix_con_disc_latency ()
{
    test_socket_latency (AF_UNIX, true, false, false);
}

void
test_unix_con_req_resp_disc_latency ()
{
    test_socket_latency (AF_UNIX, true, true, true);
}

void
test_tcp_req_latency ()
{
    test_socket_latency (AF_INET, false, true, false);
}

void
test_tcp_req_resp_latency ()
{
    test_socket_latency (AF_INET, false, true, true);
}

void
test_tcp_con_disc_latency ()
{
    test_socket_latency (AF_INET, true, false, false);
}

void
test_tcp_con_req_resp_disc_latency ()
{
    test_socket_latency (AF_INET, true, true, true);
}

static int
apteryxd_memory (void)
{
    int memory;
    FILE* file = popen ("ps -C apteryxd -O rss | gawk '{ count ++; sum += $2 }; END {count --; print sum;};'", "r");
    if (!file || fscanf (file, "%d", &memory) != 1)
    {
        memory = 0;
    }
    pclose (file);
    return memory;
}

static struct rusage before;
static long apteryxd_before;

static int
suite_init (void)
{
    getrusage (RUSAGE_SELF, &before);
    apteryxd_before = apteryxd_memory ();
    return 0;
}

static int
suite_clean (void)
{
    struct rusage after;
    getrusage (RUSAGE_SELF, &after);
    printf ("\n[Memory Used: Client:%ldkB Server:%ldkB]",
            after.ru_maxrss - before.ru_maxrss,
            apteryxd_memory () - apteryxd_before);
    return 0;
}

static CU_TestInfo tests_api[] = {
    { "doc example", test_docs },
    { "set and get", test_set_get },
    { "raw byte streams", test_set_get_raw },
    { "long path", test_set_get_long_path },
    { "large value", test_set_get_large_value },
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
    { "index before db", test_index_before_db },
    { "index replace handler", test_index_replace_handler },
    { "index no handler", test_index_no_handler },
    { "index remove handler", test_index_remove_handler },
    { "index x/* with provide x/*", test_index_and_provide },
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
    { "watch wildpath", test_watch_wildpath },
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
    { "provide and db search", test_provide_search_db },
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

static CU_TestInfo tests_api_tree[] = {
    { "doc example", test_tree_docs },
    { "tree nodes", test_tree_nodes },
    { "tree nodes deep", test_tree_nodes_deep },
    { "tree nodes wide", test_tree_nodes_wide },
    { "set tree", test_set_tree },
    { "get tree", test_get_tree },
    { "get tree single node", test_get_tree_single_node },
    { "get tree null", test_get_tree_null },
    { "get tree indexed/provided", test_get_tree_indexed_provided },
    CU_TEST_INFO_NULL,
};

static CU_TestInfo tests_performance[] = {
    { "dummy", test_perf_dummy },
    { "set", test_perf_set },
    { "set(tcp)", test_perf_tcp_set },
    { "set(tcp6)", test_perf_tcp6_set },
    { "set tree 50", test_perf_set_tree },
    { "set tree 5000", test_perf_set_tree_5000 },
    { "get", test_perf_get },
    { "get(tcp)", test_perf_tcp_get },
    { "get(tcp6)", test_perf_tcp6_get },
    { "get tree 50", test_perf_get_tree },
    { "get tree 5000", test_perf_get_tree_5000 },
    { "get null", test_perf_get_null },
    { "search", test_perf_search },
    { "watch", test_perf_watch },
    { "provide", test_perf_provide },
    CU_TEST_INFO_NULL,
};

CU_TestInfo tests_sockets[] = {
    { "unix req", test_unix_req_latency },
    { "unix req/resp", test_unix_req_resp_latency },
    { "unix con/disc", test_unix_con_disc_latency },
    { "unix c/r/r/d", test_unix_con_req_resp_disc_latency},
    { "tcp req", test_tcp_req_latency },
    { "tcp req/resp", test_tcp_req_resp_latency },
    { "tcp con/disc", test_tcp_con_disc_latency },
    { "tcp c/r/r/d", test_tcp_con_req_resp_disc_latency},
    CU_TEST_INFO_NULL,
};

extern CU_TestInfo tests_database_internal[];
extern CU_TestInfo tests_database[];
extern CU_TestInfo tests_callbacks[];

static CU_SuiteInfo suites[] = {
    { "Database Internal", suite_init, suite_clean, tests_database_internal },
    { "Database", suite_init, suite_clean, tests_database },
    { "Callbacks", suite_init, suite_clean, tests_callbacks },
    { "Sockets", suite_init, suite_clean, tests_sockets },
    { "Apteryx API", suite_init, suite_clean, tests_api },
    { "Apteryx API Index", suite_init, suite_clean, tests_api_index },
    { "Apteryx API Tree", suite_init, suite_clean, tests_api_tree },
    { "Apteryx API Watch", suite_init, suite_clean, tests_api_watch },
    { "Apteryx API Validate", suite_init, suite_clean, tests_api_validate },
    { "Apteryx API Provide", suite_init, suite_clean, tests_api_provide },
    { "Apteryx API Proxy", suite_init, suite_clean, tests_api_proxy },
    { "Apteryx Performance", suite_init, suite_clean, tests_performance },
    CU_SUITE_INFO_NULL,
};

void
run_unit_tests (const char *filter)
{
    /* Initialize the CUnit test registry */
    if (CUE_SUCCESS != CU_initialize_registry ())
        return;
    assert (NULL != CU_get_registry ());
    assert (!CU_is_test_running ());

    /* Add tests */
    CU_SuiteInfo *suite = &suites[0];
    while (suite && suite->pName)
    {
        /* Default to running all tests of a suite */
        bool all = true;
        if (filter && strstr (suite->pName, filter) != NULL)
            all = true;
        else if (filter)
            all = false;
        CU_pSuite pSuite = CU_add_suite(suite->pName, suite->pInitFunc, suite->pCleanupFunc);
        if (pSuite == NULL)
        {
            fprintf (stderr, "suite registration failed (%s) - %s\n",
                    suite->pName, CU_get_error_msg ());
            exit (EXIT_FAILURE);
        }
        CU_TestInfo *test = &suite->pTests[0];
        while (test && test->pName)
        {
            if (all || (filter && strstr (test->pName, filter) != NULL))
            {
                if (CU_add_test(pSuite, test->pName, test->pTestFunc) == NULL)
                {
                    fprintf (stderr, "test registration failed (%s) - %s\n",
                            test->pName, CU_get_error_msg ());
                    exit (EXIT_FAILURE);
                }
            }
            test++;
        }
        suite++;
    }

    /* Run all tests using the CUnit Basic interface */
    CU_basic_set_mode (CU_BRM_VERBOSE);
    CU_set_error_action (CUEA_IGNORE);
    CU_basic_run_tests ();
    CU_cleanup_registry ();
    return;
}
