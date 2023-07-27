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
#include <sys/poll.h>
#include <assert.h>
#ifdef HAVE_LUA
#include <lua.h>
#include <lualib.h>
#include <lauxlib.h>
#endif
#include <CUnit/CUnit.h>
#include <CUnit/Basic.h>
#include "apteryx.h"
#include "internal.h"

#define TEST_PATH           "/test"
#define TEST2_PATH          "/test2"
#define TEST_ITERATIONS     1000
#define TEST_SLEEP_TIMEOUT  100000
#define TEST_TCP_URL        "tcp://127.0.0.1:9999"
#define TEST_TCP6_URL       "tcp://[::1]:9999"
#define TEST_RPC_PATH       "/tmp/apteryx.test"
#define TEST_PORT_NUM       9999
#define TEST_MESSAGE_SIZE   100
#define TEST_SCHEMA_PATH    "/etc/apteryx/schema:."
#define TEST_SCHEMA_FILE    "./test.xml"

static int _cb_count = 0;

static bool
assert_apteryx_empty (void)
{
    GNode *tree = apteryx_get_tree (TEST_PATH);
    if (tree)
    {
        fprintf (stderr, "\nERROR: Nodes still set:\n");
        apteryx_print_tree (tree, stdout);
        apteryx_free_tree (tree);
        return false;
    }
    return true;
}

void
test_init ()
{
    const char *path = TEST_PATH"/entity/zones/private/name";
    char *value = NULL;

    apteryx_shutdown_force ();
    CU_ASSERT (apteryx_set (path, "private") == FALSE);
    CU_ASSERT ((value = apteryx_get (path)) == NULL);
    CU_ASSERT (apteryx_set (path, NULL) == FALSE);
    CU_ASSERT (assert_apteryx_empty ());
    apteryx_init (apteryx_debug);
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


static int test_wack_signal = 0;
static bool
test_watch_w_ack_callback (const char *path, const char *value)
{
    usleep (TEST_SLEEP_TIMEOUT);
    test_wack_signal = value ? 2 : 3;
    return true;
}

void
test_set_with_ack ()
{
    const char *path = TEST_PATH"/entity/zones/private/name";

    CU_ASSERT (apteryx_watch(path, test_watch_w_ack_callback));
    CU_ASSERT (test_wack_signal == 0);
    CU_ASSERT (apteryx_set_wait (path, "private"));
    CU_ASSERT (test_wack_signal == 2);
    CU_ASSERT (apteryx_set_wait (path, NULL));
    CU_ASSERT (test_wack_signal == 3);
    test_wack_signal = 0;
    CU_ASSERT (apteryx_unwatch(path, test_watch_w_ack_callback));
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

    svalue = g_malloc0 (len);
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
            apteryx_init (apteryx_debug);
            _multi_write_thread ((void *) i);
            apteryx_shutdown ();
            exit (0);
        }
    }
    apteryx_init (apteryx_debug);

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
test_perf_tcp_set_tree ()
{
    const char *path = TEST_TCP_URL":"TEST_PATH"/entity/zones";
    uint64_t start;
    int i;
    bool res;

    CU_ASSERT (apteryx_bind (TEST_TCP_URL));
    usleep (TEST_SLEEP_TIMEOUT);

    GNode *root = APTERYX_NODE(NULL, (char*)path);
    APTERYX_LEAF (root, "private", "crash");

    start = get_time_us ();
    for (i = 0; i < TEST_ITERATIONS; i++)
    {
        CU_ASSERT ((res = apteryx_set_tree (root)));
        if (!res)
            goto exit;
    }

    printf ("%"PRIu64"us ... ", (get_time_us () - start) / TEST_ITERATIONS);
exit:
    g_node_destroy (root);
    apteryx_prune(path);
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

    /* test correct behavior with strings */
    char *strvalue = "illegal";

    CU_ASSERT (apteryx_set_string (path, "count", strvalue));

    v = 0;

    CU_ASSERT((v = apteryx_get_int (path, "count")) == -1);

    CU_ASSERT((errno == -ERANGE));

    strvalue = "123illegal";

    CU_ASSERT (apteryx_set_string (path, "count", strvalue));

    v = 0;

    CU_ASSERT((v = apteryx_get_int (path, "count")) == -1);

    CU_ASSERT((errno == -ERANGE));

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
test_set_has_value ()
{
    const char *path = TEST_PATH"/entity/zones";
    const char *value = "123456";

    CU_ASSERT (apteryx_set (path, value));

    CU_ASSERT (apteryx_has_value (path) == true);

    CU_ASSERT (apteryx_prune (path));

    CU_ASSERT (apteryx_has_value (path) == false);
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


static char *
_dummy_provide(const char *d)
{
    return NULL;
}

/* Check that we find a provider when have a search that hits it */
void
test_search_of_provide ()
{
    GList *paths = NULL;
    CU_ASSERT (apteryx_provide (TEST_PATH"/interfaces/eth0/status", _dummy_provide));
    CU_ASSERT ((paths = apteryx_search (TEST_PATH"/interfaces/eth0/")) != NULL);
    CU_ASSERT (paths && strcmp(paths->data, TEST_PATH"/interfaces/eth0/status") == 0);
    g_list_free_full(paths, g_free);

    CU_ASSERT (apteryx_unprovide (TEST_PATH"/interfaces/eth0/status", _dummy_provide));
    CU_ASSERT (assert_apteryx_empty ());
}

/* Check search doesn't return a path for a directory level provider */
void
test_search_of_provider_slash ()
{
    GList *paths = NULL;
    CU_ASSERT (apteryx_provide (TEST_PATH"/interfaces/eth0/status/", _dummy_provide));
    CU_ASSERT ((paths = apteryx_search (TEST_PATH"/interfaces/eth0/status/")) == NULL)
    CU_ASSERT (apteryx_unprovide (TEST_PATH"/interfaces/eth0/status/", _dummy_provide));
    CU_ASSERT (assert_apteryx_empty ());
}

/* Check search doesn't return a path for a wildcard provider */
void
test_search_of_provider_wildcard ()
{
    GList *paths = NULL;
    CU_ASSERT (apteryx_provide (TEST_PATH"/interfaces/eth0/status/*", _dummy_provide));
    CU_ASSERT ((paths = apteryx_search (TEST_PATH"/interfaces/eth0/status/")) == NULL)
    CU_ASSERT (apteryx_unprovide (TEST_PATH"/interfaces/eth0/status/*", _dummy_provide));
    CU_ASSERT (assert_apteryx_empty ());
}

/* Check search returns a path when there is a lower level directory provider */
void
test_search_of_lower_directory_provider ()
{
    GList *paths = NULL;
    CU_ASSERT (apteryx_provide (TEST_PATH"/interfaces/eth0/status/lower-directory/", _dummy_provide));
    CU_ASSERT ((paths = apteryx_search (TEST_PATH"/interfaces/eth0/status/")) != NULL);
    CU_ASSERT (paths && strcmp(paths->data, TEST_PATH"/interfaces/eth0/status/lower-directory") == 0);
    CU_ASSERT (apteryx_unprovide (TEST_PATH"/interfaces/eth0/status/lower-directory/", _dummy_provide));
    g_list_free_full(paths, g_free);
    CU_ASSERT (assert_apteryx_empty ());
}

/* Check search returns a path when there is a lower level wildcard provider */
void
test_search_of_lower_wildcard_provider ()
{
    GList *paths = NULL;
    CU_ASSERT (apteryx_provide (TEST_PATH"/interfaces/eth0/status/lower-wildcard/*", _dummy_provide));
    CU_ASSERT ((paths = apteryx_search (TEST_PATH"/interfaces/eth0/status/")) != NULL);
    CU_ASSERT (paths && strcmp(paths->data, TEST_PATH"/interfaces/eth0/status/lower-wildcard") == 0);
    g_list_free_full(paths, g_free);
    CU_ASSERT (apteryx_unprovide (TEST_PATH"/interfaces/eth0/status/lower-wildcard/*", _dummy_provide));
    CU_ASSERT (assert_apteryx_empty ());
}

/* Check search skips wildcard nodes when searching for providers.
 * These wildcard nodes are either filled in with indexers or from the database.
 */
void
test_search_of_intermediate_wildcard()
{
    GList *paths = NULL;
    CU_ASSERT (apteryx_provide (TEST_PATH"/interfaces/eth0/status/lower-wildcard/*/and-below", _dummy_provide));
    CU_ASSERT ((paths = apteryx_search (TEST_PATH"/interfaces/eth0/status/lower-wildcard/")) == NULL);
    CU_ASSERT (paths == NULL);
    CU_ASSERT (apteryx_unprovide (TEST_PATH"/interfaces/eth0/status/lower-wildcard/*/and-below", _dummy_provide));
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

static GList*
test_index_cb_always_slash (const char *path)
{
    GList *paths = NULL;
    if (strcmp (path, TEST_PATH"/ends/with/slash/") == 0)
    {
        paths = g_list_append (paths, strdup (TEST_PATH"/ends/with/slash/yes"));
    }
    return paths;
}

static char*
test_index_cb_always_slash_provide (const char *path)
{
    if (strcmp (path, TEST_PATH"/ends/with/slash/yes") == 0)
    {
        return strdup ("yes");
    }
    return NULL;
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

void
test_index_always_ends_with_slash ()
{
    char *path = TEST_PATH"/ends/with/slash/*";
    GList *paths = NULL;
    GNode *root = NULL;

    CU_ASSERT (apteryx_index (path, test_index_cb_always_slash));
    CU_ASSERT (apteryx_provide (path, test_index_cb_always_slash_provide));

    /* apteryx_search */
    CU_ASSERT ((paths = apteryx_search (TEST_PATH"/ends/with/slash/")) != NULL);
    g_list_free_full (paths, free);

    /* apteryx_get_tree */
    root = apteryx_get_tree (TEST_PATH"/ends/with/slash");
    CU_ASSERT (root != NULL);
    CU_ASSERT (root && strcmp (APTERYX_NAME (root), TEST_PATH"/ends/with/slash") == 0);
    CU_ASSERT (root && g_node_n_children (root) == 1);
    apteryx_free_tree (root);

    CU_ASSERT (apteryx_unindex (path, test_index_cb_always_slash));
    CU_ASSERT (apteryx_unprovide (path, test_index_cb_always_slash_provide));
    CU_ASSERT (assert_apteryx_empty ());
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

static GList *
test_index_get_tree_cb(const char *path)
{
    gchar *tmp = g_strdup(path);
    char *token = NULL;
    char *saveptr = NULL;
    int count = 0;
    GList *paths = NULL;

    token = tmp;
    while ((token = strtok_r(token, "/", &saveptr)) != NULL)
    {
        count++;
        token = NULL;
    }

    switch(count)
    {
        case 2:
            for (int i = 0; i < 3; i++)
                paths = g_list_append(paths, g_strdup_printf(TEST_PATH"/counters/eth%d", i));
            break;
        case 3:
            paths = g_list_append(paths, g_strdup_printf("%s%s", path, "rx"));
            paths = g_list_append(paths, g_strdup_printf("%s%s", path, "tx"));
            break;
        case 4:
            paths = g_list_append(paths, g_strdup_printf("%s%s", path, "pkts"));
            paths = g_list_append(paths, g_strdup_printf("%s%s", path, "bytes"));
        default:
            break;
    }

    g_free(tmp);
    return paths;
}

static char *
test_provide_get_tree_cb(const char *path)
{
    if (strstr(path, "rx/pkts"))
    {
        _cb_count++;
        return strdup("100");
    }
    if (strstr(path, "rx/bytes"))
    {
        _cb_count++;
        return strdup("200");
    }
    if (strstr(path, "tx/pkts"))
    {
        _cb_count++;
        return strdup("300");
    }
    if (strstr(path, "tx/bytes"))
    {
        _cb_count++;
        return strdup("400");
    }
    return NULL;
}

void
test_index_and_provide_get_tree ()
{
    char *path = TEST_PATH"/counters/*";
    GNode *root = NULL;
    _cb_count = 0;
    CU_ASSERT (apteryx_provide (path, test_provide_get_tree_cb));
    CU_ASSERT (apteryx_index (path, test_index_get_tree_cb));
    apteryx_set(TEST_PATH"/counters/eth4/name", "eth3");
    CU_ASSERT ((root = apteryx_get_tree (TEST_PATH"/counters")) != NULL);
    if (root)
        apteryx_free_tree (root);
    /* eth0-3 * rx/tx * bytes/packets = 16 counters */
    CU_ASSERT (_cb_count == 16);
    CU_ASSERT (apteryx_unprovide (path, test_provide_get_tree_cb));
    CU_ASSERT (apteryx_unindex (path, test_index_get_tree_cb));
    apteryx_prune(TEST_PATH"/counters");
    CU_ASSERT (assert_apteryx_empty ());
    _cb_count = 0;
}

static GList *
_indexer_writes (const char *d)
{
    apteryx_set_string (d, "one", "1");
    apteryx_set_string (d, "two", "2");
    return NULL;
}

static char*
_provide_callback (const char *path)
{
    return strdup ("up");
}

void
test_index_writes ()
{
    char *path = TEST_PATH"/counters/*";
    char *provide_path = TEST_PATH"/counters/*/something/else";
    GNode *root;

    CU_ASSERT (apteryx_index (path, _indexer_writes));
    /* There's no reason to call the indexer without a provider behind it. */
    CU_ASSERT (apteryx_provide (provide_path, _provide_callback));
    root = apteryx_get_tree (TEST_PATH"/counters");
    if (root)
        apteryx_free_tree (root);
    CU_ASSERT (apteryx_get_int(TEST_PATH"/counters", "one") == 1);
    CU_ASSERT (apteryx_unindex (path, _indexer_writes));
    CU_ASSERT (apteryx_unprovide (provide_path, _provide_callback));
    apteryx_prune (TEST_PATH"/counters");
    CU_ASSERT (assert_apteryx_empty ());
}

static GList *
_indexer_recurses(const char *path)
{
    GList *paths = g_list_append(NULL, g_strdup_printf(TEST_PATH"/counters/eth0"));
    paths = g_list_append(paths, g_strdup_printf(TEST_PATH"/counters/eth1"));
    paths = g_list_append(paths, g_strdup_printf(TEST_PATH"/counters/eth2"));
    paths = g_list_append(paths, g_strdup_printf(TEST_PATH"/counters/eth2/something/else"));
    return paths;
}

void
test_index_recursive ()
{
    char *path = TEST_PATH"/counters/*";
    char *provide_path = TEST_PATH"/counters/*/something/else";
    GNode *root;

    /* This indexer is poorly behaved - indexers must return paths that
     * extend the search path - this one returns the same set of paths
     * each time it's called. We need code in apteryxd to ignore paths
     * that are obviously wrong.
     */
    CU_ASSERT (apteryx_index (path, _indexer_recurses));
    /* There's no reason to call the indexer without a provider behind it. */
    CU_ASSERT (apteryx_provide (provide_path, _provide_callback));
    root = apteryx_get_tree (TEST_PATH"/counters");
    if (root)
        apteryx_free_tree (root);
    CU_ASSERT (apteryx_unindex (path, _indexer_recurses));
    CU_ASSERT (apteryx_unprovide (provide_path, _provide_callback));
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

void
test_prune_root ()
{
    GList *paths = NULL;

    CU_ASSERT (apteryx_set_string (TEST_PATH"/interfaces", NULL, "-"));
    CU_ASSERT (apteryx_set_string (TEST_PATH"/interfaces/eth0", NULL, "-"));
    CU_ASSERT (apteryx_set_string (TEST_PATH"/interfaces/eth0/state", NULL, "up"));
    CU_ASSERT (apteryx_set_string (TEST_PATH"/entities", NULL, "-"));
    CU_ASSERT (apteryx_set_string (TEST_PATH"/entities/zones", NULL, "-"));
    CU_ASSERT (apteryx_set_string (TEST_PATH"/entities/zones/public", NULL, "-"));
    CU_ASSERT (apteryx_set_string (TEST_PATH"/entities/zones/private", NULL, "-"));
    CU_ASSERT (apteryx_prune ("/"));

    CU_ASSERT ((paths = apteryx_search (TEST_PATH"/interfaces/")) == NULL);
    CU_ASSERT ((paths = apteryx_search (TEST_PATH"/entities/zones/")) == NULL);

    g_list_free_full (paths, free);
    CU_ASSERT (assert_apteryx_empty ());
}

static bool set_prune_running = false;
static GNode *prune_thread_safe_tree_root = NULL;

static int
_set_prune_thread (void *data)
{
    while (set_prune_running)
    {
        CU_ASSERT (apteryx_set_string (TEST_PATH"/platform/pluggables", "port1.1.1", "11"));
        CU_ASSERT (apteryx_prune (TEST_PATH"/platform/pluggables/port1.1.1"));
    }

    return 0;
}

static int
_search_thread (void *data)
{
    int i;
    int iterations = * (int *) data;
    GList *paths;

    for (i=0; i<iterations; i++)
    {
        paths = apteryx_search(TEST_PATH"/platform/pluggables/");
        g_list_free_full (paths, free);
    }

    return 0;
}

void
test_prune_thread_safe ()
{
    char *name, *value;
    int num_boards = 8;
    int num_ports = 12;
    int board, port, i;
    int num_search_threads = 10;
    int num_search_iterations = 100;
    pthread_t set_prune_thread;
    pthread_t search_threads[num_search_threads];

    /* Generate test tree */
    CU_ASSERT ((name = strdup (TEST_PATH"/platform/pluggables")) != NULL);
    CU_ASSERT ((prune_thread_safe_tree_root = APTERYX_NODE (NULL, name)) != NULL);
    for (board=1; board<=num_boards; board++)
    {
        for (port=1; port<=num_ports; port++)
        {
            name = value = NULL;
            CU_ASSERT (asprintf (&name, "port1.%d.%d", board, port));
            CU_ASSERT (asprintf (&value, "%d%d", board, port));
            APTERYX_LEAF (prune_thread_safe_tree_root, name, value);
        }
    }
    CU_ASSERT (apteryx_set_tree (prune_thread_safe_tree_root));

    /* Start set_prune and search threads */
    set_prune_running = true;
    pthread_create (&set_prune_thread, NULL, (void *) &_set_prune_thread, NULL);
    for (i=0; i<num_search_threads; i++)
    {
        pthread_create (&search_threads[i], NULL, (void *) &_search_thread, (void *) &num_search_iterations);
    }

    /* Collect set_prune and search threads */
    for (i=0; i<num_search_threads; i++)
    {
        pthread_join (search_threads[i], NULL);
    }
    set_prune_running = false;
    pthread_join (set_prune_thread, NULL);

    /* Clean up */
    usleep (TEST_SLEEP_TIMEOUT);
    apteryx_prune (TEST_PATH"/platform/pluggables");
    apteryx_free_tree (prune_thread_safe_tree_root);
    CU_ASSERT (assert_apteryx_empty ());
}

void
test_cas ()
{
    const char *path = TEST_PATH"/interfaces/eth0/ifindex";
    char *value;
    uint64_t ts;

    CU_ASSERT (apteryx_cas (path, "1", 0));
    CU_ASSERT (!apteryx_cas (path, "2", 0));
    CU_ASSERT (errno == -EBUSY);
    CU_ASSERT ((ts = apteryx_timestamp (path)) != 0);
    CU_ASSERT (apteryx_cas (path, "3", ts));
    CU_ASSERT (!apteryx_cas (path, "4", ts));
    CU_ASSERT (errno == -EBUSY);
    CU_ASSERT ((value = apteryx_get (path)) != NULL);
    CU_ASSERT (value && strcmp (value, "3") == 0);
    free ((void *) value);

    CU_ASSERT (apteryx_set (path, NULL));
    CU_ASSERT (assert_apteryx_empty ());
}

void
test_cas_string ()
{
    const char *path = TEST_PATH"/interfaces/eth0";
    char *value;
    uint64_t ts;

    CU_ASSERT (apteryx_cas_string (path, "ifindex", "1", 0));
    CU_ASSERT (!apteryx_cas_string (path, "ifindex", "2", 0));
    CU_ASSERT (errno == -EBUSY);
    CU_ASSERT ((ts = apteryx_timestamp (path)) != 0);
    CU_ASSERT (apteryx_cas_string (path, "ifindex", "3", ts));
    CU_ASSERT (!apteryx_cas_string (path, "ifindex", "4", ts));
    CU_ASSERT (errno == -EBUSY);
    CU_ASSERT ((value = apteryx_get_string (path, "ifindex")) != NULL);
    CU_ASSERT (value && strcmp (value, "3") == 0);
    free ((void *) value);

    CU_ASSERT (apteryx_set_string (path, "ifindex", NULL));
    CU_ASSERT (assert_apteryx_empty ());
}

void
test_cas_int ()
{
    const char *path = TEST_PATH"/interfaces/eth0";
    uint64_t ts;

    CU_ASSERT (apteryx_cas_int (path, "ifindex", 1, 0));
    CU_ASSERT (!apteryx_cas_int (path, "ifindex", 2, 0));
    CU_ASSERT (errno == -EBUSY);
    CU_ASSERT ((ts = apteryx_timestamp (path)) != 0);
    CU_ASSERT (apteryx_cas_int (path, "ifindex", 3, ts));
    CU_ASSERT (!apteryx_cas_int (path, "ifindex", 4, ts));
    CU_ASSERT (errno == -EBUSY);
    CU_ASSERT (apteryx_get_int (path, "ifindex") == 3);

    CU_ASSERT (apteryx_set_string (path, "ifindex", NULL));
    CU_ASSERT (assert_apteryx_empty ());
}

#define bitmap_path TEST_PATH"/interfaces/eth0/status"
#define bitmap_bits 32
int
_bitmap_thread (void *data)
{
    int id = (long int) data;
    uint32_t set = (1 << id);
    uint32_t clear = (1 << (bitmap_bits/2 + id));
    const char *path = bitmap_path;

    while (1) {
        uint64_t ts = apteryx_timestamp (path);
        char *value = apteryx_get (path);
        uint32_t bitmap = 0;
        if (value)
        {
            sscanf (value, "%"PRIx32, &bitmap);
            free (value);
        }
        bitmap = (bitmap & ~clear) | set;
        if (asprintf (&value, "%"PRIx32, bitmap) > 0) {
            bool success = apteryx_cas (path, value, ts);
            free (value);
            if (success || errno != -EBUSY)
                break;
        }
    }
    return 0;
}

void
test_bitmap ()
{
    const char *path = bitmap_path;
    char *value = NULL;
    pthread_t writers[bitmap_bits];
    uint32_t bitmap = 0;
    long int i;

    CU_ASSERT (asprintf (&value, "%"PRIx32, (uint32_t)0xFFFF0000) > 0);
    CU_ASSERT (apteryx_set (path, value));
    free (value);
    for (i = 0; i < bitmap_bits/2; i++)
    {
        pthread_create (&writers[i], NULL, (void *) &_bitmap_thread, (void *) i);
    }
    for (i = 0; i < bitmap_bits/2; i++)
    {
        pthread_join (writers[i], NULL);
    }
    CU_ASSERT ((value = apteryx_get (path)) != NULL);
    CU_ASSERT (value && sscanf (value, "%"PRIx32, &bitmap) == 1)
    CU_ASSERT (bitmap == 0x0000FFFF)
    free (value);

    CU_ASSERT (apteryx_set (path, NULL));
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
    _cb_count++;
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
        apteryx_init (apteryx_debug);
        usleep (TEST_SLEEP_TIMEOUT);
        apteryx_set_string (path, NULL, "down");
        apteryx_shutdown ();
        exit (0);
    }
    else if (pid > 0)
    {
        apteryx_init (apteryx_debug);
        CU_ASSERT (apteryx_watch (path, test_watch_callback));
        usleep (TEST_SLEEP_TIMEOUT * 2);
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
test_watch_one_level_miss ()
{
    _path = _value = NULL;
    const char *path = TEST_PATH"/entity/zones/private/state";

    CU_ASSERT (apteryx_set_string (path, NULL, "up"));
    CU_ASSERT (apteryx_watch (TEST_PATH"/entity/zones/", test_watch_callback));
    CU_ASSERT (apteryx_set_string (path, NULL, "down"));
    usleep (TEST_SLEEP_TIMEOUT);
    CU_ASSERT (_path == NULL);
    CU_ASSERT (_value == NULL);
    CU_ASSERT (apteryx_unwatch (TEST_PATH"/entity/zones/", test_watch_callback));
    CU_ASSERT (apteryx_set_string (path, NULL, NULL));
    _watch_cleanup ();
}

void
test_watch_prune ()
{
    _path = _value = NULL;
    _cb_count = 0;
    const char *path = TEST_PATH"/entity/zones/private/state";

    CU_ASSERT (apteryx_set(path, "up"));
    CU_ASSERT (apteryx_watch (TEST_PATH"/entity/*", test_watch_callback));
    CU_ASSERT (apteryx_prune (TEST_PATH"/entity"));
    usleep (TEST_SLEEP_TIMEOUT);
    CU_ASSERT (_cb_count == 1);
    CU_ASSERT (_path && strcmp (_path, path) == 0);
    CU_ASSERT (apteryx_unwatch (TEST_PATH"/entity/*", test_watch_callback));
    _watch_cleanup ();
}

void
test_watch_prune_multiple ()
{
    _path = _value = NULL;
    _cb_count = 0;
    const char *path = TEST_PATH"/entity/zones/private/state";
    const char *path2 = TEST_PATH"/entity/zones/private/state2";

    CU_ASSERT (apteryx_set(path, "up"));
    CU_ASSERT (apteryx_set(path2, "down"));
    CU_ASSERT (apteryx_watch (TEST_PATH"/entity/*", test_watch_callback));
    CU_ASSERT (apteryx_prune (TEST_PATH"/entity"));
    usleep (TEST_SLEEP_TIMEOUT);
    CU_ASSERT (_cb_count == 2);
    CU_ASSERT (_path && (strcmp (_path, path) == 0 || strcmp (_path, path2) == 0));
    CU_ASSERT (apteryx_unwatch (TEST_PATH"/entity/*", test_watch_callback));
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
test_watch_empty_path_prune ()
{
    _path = _value = NULL;
    CU_ASSERT (apteryx_watch
               (TEST_PATH"/entity/*", test_watch_callback));
    CU_ASSERT (apteryx_prune (TEST_PATH"/entity/zones/private/state"));
    usleep (TEST_SLEEP_TIMEOUT);
    CU_ASSERT (_path == NULL);
    CU_ASSERT (apteryx_prune (TEST_PATH"/entity/zones"));
    usleep (TEST_SLEEP_TIMEOUT);
    CU_ASSERT (_path == NULL);
    CU_ASSERT (apteryx_prune (TEST_PATH"/entity"));
    usleep (TEST_SLEEP_TIMEOUT);
    CU_ASSERT (_path == NULL);
    CU_ASSERT (apteryx_unwatch (TEST_PATH"/entity/*", test_watch_callback));
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
test_watch_set_callback_set_recursive_cb (const char *path, const char *value)
{
    apteryx_set_string (path, NULL, "down");
    return true;
}

void
test_watch_set_callback_set_recursive ()
{
    const char *path = TEST_PATH"/entity/zones/private/state";
    CU_ASSERT (apteryx_watch (path, test_watch_set_callback_set_recursive_cb));
    CU_ASSERT (apteryx_set_string (path, NULL, "up"));
    usleep (TEST_SLEEP_TIMEOUT);
    CU_ASSERT (apteryx_unwatch (path, test_watch_set_callback_set_recursive_cb));
    usleep (TEST_SLEEP_TIMEOUT);
    CU_ASSERT (apteryx_set_string (path, NULL, NULL));
    usleep (2*RPC_TIMEOUT_US); /* At least */
    _watch_cleanup ();
}

static bool
test_watch_set_multi_callback_set_cb (const char *path, const char *value)
{
    usleep (TEST_SLEEP_TIMEOUT);
    apteryx_set_string (TEST_PATH"/entity/zones/public", "state", "down");
    return true;
}

void
test_watch_set_multi_callback_set ()
{
    GNode* root;
    CU_ASSERT (apteryx_watch (TEST_PATH"/entity/zones/private/*", test_watch_set_multi_callback_set_cb));
    root = APTERYX_NODE (NULL, TEST_PATH"/entity/zones/private");
    APTERYX_LEAF (root, "1", "1");
    APTERYX_LEAF (root, "2", "2");
    APTERYX_LEAF (root, "3", "3");
    APTERYX_LEAF (root, "4", "4");
    APTERYX_LEAF (root, "5", "5");
    APTERYX_LEAF (root, "6", "6");
    APTERYX_LEAF (root, "7", "7");
    APTERYX_LEAF (root, "8", "8");
    APTERYX_LEAF (root, "9", "9");
    CU_ASSERT (apteryx_set_tree (root));
    usleep (10 * TEST_SLEEP_TIMEOUT);
    CU_ASSERT (apteryx_unwatch (TEST_PATH"/entity/zones/private/*", test_watch_set_multi_callback_set_cb));
    usleep (TEST_SLEEP_TIMEOUT);
    CU_ASSERT (apteryx_prune (TEST_PATH"/entity/zones"));
    apteryx_set_string (TEST_PATH"/entity/zones/public", "state", NULL);
    g_node_destroy (root);
    CU_ASSERT (assert_apteryx_empty ());
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
    _cb_count = 0;

    apteryx_watch (TEST_PATH"/entity/zones/public/*", test_watch_adds_watch_cb);
    apteryx_set_string (TEST_PATH"/entity/zones/public/state", NULL, "new_cb");
    usleep (TEST_SLEEP_TIMEOUT);
    CU_ASSERT (_cb_count == 1);
    apteryx_set_string (TEST_PATH"/entity/zones/public/state", NULL, "new_cb_two");
    usleep (TEST_SLEEP_TIMEOUT);
    CU_ASSERT (_cb_count == 2);
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
    CU_ASSERT (_cb_count == 1);
    apteryx_set_string (path, NULL, "new_cb_two");
    usleep (TEST_SLEEP_TIMEOUT);
    CU_ASSERT (_cb_count == 1);
    apteryx_set_string (path, NULL, NULL);
    _watch_cleanup ();
}

static pthread_mutex_t watch_count_lock = PTHREAD_MUTEX_INITIALIZER;

static bool
test_watch_count_callback (const char *path, const char *value)
{
    char *v;
    pthread_mutex_lock (&watch_count_lock);
    CU_ASSERT ((asprintf ((char **) &v, "%d", _cb_count)+1) != 0);
    CU_ASSERT (value && v && strcmp ((char*)value, v) == 0);
    free (v);
    _cb_count++;
    pthread_mutex_unlock (&watch_count_lock);
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

void
test_watch_order ()
{
    int count = 1000;
    int i;

    _cb_count = 0;
    CU_ASSERT (apteryx_watch (TEST_PATH"/interfaces/eth0/packets", test_watch_count_callback));
    rpc_test_random_watch_delay = true;
    for (i=0; i<count; i++)
    {
        CU_ASSERT (apteryx_set_int (TEST_PATH"/interfaces/eth0/packets", NULL, i));
    }
    usleep (TEST_SLEEP_TIMEOUT + count * RPC_TEST_DELAY_MASK);
    rpc_test_random_watch_delay = false;

    CU_ASSERT (_cb_count == count);
    CU_ASSERT (apteryx_get_int (TEST_PATH"/interfaces/eth0/packets", NULL) == count - 1);
    CU_ASSERT (apteryx_unwatch (TEST_PATH"/interfaces/eth0/packets", test_watch_count_callback));
    apteryx_set (TEST_PATH"/interfaces/eth0/packets", NULL);
    _watch_cleanup ();
}

void
test_watch_rpc_restart ()
{
    _path = _value = NULL;
    const char *path = TEST_PATH"/entity/zones/private/state";

    CU_ASSERT (apteryx_set_string (path, NULL, "up"));
    CU_ASSERT (apteryx_watch (path, test_watch_callback));
    apteryx_shutdown ();
    apteryx_init (apteryx_debug);
    CU_ASSERT (apteryx_set_string (path, NULL, "down"));
    usleep (TEST_SLEEP_TIMEOUT);
    CU_ASSERT (_path && strcmp (_path, path) == 0);
    CU_ASSERT (_value && strcmp (_value, "down") == 0);
    apteryx_shutdown ();
    apteryx_init (apteryx_debug);
    CU_ASSERT (apteryx_set_string (path, NULL, "up"));
    usleep (TEST_SLEEP_TIMEOUT);
    CU_ASSERT (_path && strcmp (_path, path) == 0);
    CU_ASSERT (_value && strcmp (_value, "up") == 0);
    CU_ASSERT (apteryx_unwatch (path, test_watch_callback));
    apteryx_set_string (path, NULL, NULL);
    _watch_cleanup ();
}

static pthread_mutex_t watch_lock;
static int watch_count;

static bool
test_watch_block_callback (const char *path, const char *value)
{
    pthread_mutex_lock (&watch_lock);
    watch_count++;
    pthread_mutex_unlock (&watch_lock);
    return true;
}

void
test_watch_myself_blocked ()
{
    const char *path = TEST_PATH"/entity/zones/private/state";
    int i;

    pthread_mutex_init (&watch_lock, NULL);
    pthread_mutex_lock (&watch_lock);
    watch_count = 0;
    CU_ASSERT (apteryx_watch (path, test_watch_block_callback));
    for (i = 0; i < 30; i++)
    {
        CU_ASSERT (apteryx_set (path, "down"));
    }
    pthread_mutex_unlock (&watch_lock);
    usleep (TEST_SLEEP_TIMEOUT);
    pthread_mutex_lock (&watch_lock);
    pthread_mutex_unlock (&watch_lock);
    usleep (TEST_SLEEP_TIMEOUT);
    CU_ASSERT (watch_count == 30);
    CU_ASSERT (apteryx_unwatch (path, test_watch_block_callback));
    CU_ASSERT (apteryx_set (path, NULL));
    CU_ASSERT (assert_apteryx_empty ());
}


static pthread_t watch_thread_id = -1;
static bool
test_watch_callback_thread_info (const char *path, const char *value)
{
    if (_path)
        free (_path);
    if (_value)
        free (_value);

    usleep(TEST_SLEEP_TIMEOUT / 100);

    if (watch_thread_id == -1)
        watch_thread_id = pthread_self ();
    else
        CU_ASSERT (pthread_self() == watch_thread_id);

    _path = strdup (path);
    if (value)
        _value = strdup (value);
    else
        _value = NULL;
    _cb_count++;
    return true;
}


void
test_watch_ack_thread ()
{
    const char *path = TEST_PATH"/entity/zones/private/state";
    _cb_count = 0;
    watch_thread_id = -1;
    CU_ASSERT (apteryx_watch (path, test_watch_callback_thread_info));
    apteryx_set (path, "1");
    apteryx_set_wait (path, "2");

    /* By the time the apteryx_set_wait finishes we have to have cleared the
     * backlog of watch callbacks.
     */
    CU_ASSERT (_cb_count == 2);
    apteryx_set (path, "3");

    /* The test sleep timeout should be long enough for the callback to be
     * called.
     */
    usleep (TEST_SLEEP_TIMEOUT);
    CU_ASSERT (_cb_count == 3);
    CU_ASSERT (apteryx_unwatch (path, test_watch_callback_thread_info));
    apteryx_prune (TEST_PATH);
    if (_path)
        free(_path);
    if (_value)
        free(_value);
    _path = NULL;
}

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
test_validate_prune()
{
    _path = _value = NULL;
    const char *path = TEST_PATH"/hostname";

    CU_ASSERT (apteryx_validate (path, test_validate_callback));
    CU_ASSERT (apteryx_set_string (path, NULL, "testing"));
    CU_ASSERT (apteryx_prune (path));

    CU_ASSERT (apteryx_set_string (path, NULL, "testing"));
    CU_ASSERT (apteryx_validate (path, test_validate_refuse_callback));
    CU_ASSERT (!apteryx_prune (path));
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
    CU_ASSERT (failed == -EPERM || failed == -ETIMEDOUT);
    usleep (TEST_SLEEP_TIMEOUT);

    CU_ASSERT (apteryx_unvalidate (path, test_validate_conflicting_callback));
    CU_ASSERT (apteryx_unwatch (path, test_validate_test_watch_callback));
    apteryx_set_string (path, NULL, NULL);
    CU_ASSERT (assert_apteryx_empty ());
}

void
test_validate_tree ()
{
    GNode* root;

    CU_ASSERT (apteryx_validate (TEST_PATH"/entity/zones/private/*", test_validate_callback));

    root = APTERYX_NODE (NULL, TEST_PATH"/entity/zones/private");
    APTERYX_LEAF (root, "1", "1");
    APTERYX_LEAF (root, "2", "2");
    APTERYX_LEAF (root, "3", "3");
    APTERYX_LEAF (root, "4", "4");
    APTERYX_LEAF (root, "5", "5");
    APTERYX_LEAF (root, "6", "6");
    APTERYX_LEAF (root, "7", "7");
    APTERYX_LEAF (root, "8", "8");
    APTERYX_LEAF (root, "9", "9");
    CU_ASSERT (apteryx_set_tree (root));
    usleep (TEST_SLEEP_TIMEOUT);
    CU_ASSERT (apteryx_unvalidate (TEST_PATH"/entity/zones/private/*", test_validate_callback));
    CU_ASSERT (apteryx_prune (TEST_PATH"/entity/zones"));
    g_node_destroy (root);
    CU_ASSERT (assert_apteryx_empty ());
}

static bool
test_set_from_watch_cb (const char *path, const char *value)
{
    CU_ASSERT (apteryx_set_string (TEST_PATH"/entity/zones/public", "name", "public") == false);
    CU_ASSERT (errno == -ETIMEDOUT);
    return true;
}

void
test_validate_from_watch_callback ()
{
    CU_ASSERT (apteryx_watch (TEST_PATH"/entity/zones/private/*", test_set_from_watch_cb));
    CU_ASSERT (apteryx_validate (TEST_PATH"/entity/zones/public/*", test_validate_callback));
    CU_ASSERT (apteryx_set_string (TEST_PATH"/entity/zones/private", "link", "up"));
    usleep (1.1 * RPC_TIMEOUT_US);
    CU_ASSERT (apteryx_unvalidate (TEST_PATH"/entity/zones/public/*", test_validate_callback));
    CU_ASSERT (apteryx_unwatch (TEST_PATH"/entity/zones/private/*", test_set_from_watch_cb));
    CU_ASSERT (apteryx_set_string (TEST_PATH"/entity/zones/private", "link", NULL));
    CU_ASSERT (assert_apteryx_empty ());
}

void
test_validate_from_many_watches ()
{
    GNode* root;

    CU_ASSERT (apteryx_watch (TEST_PATH"/entity/zones/private/*", test_set_from_watch_cb));
    CU_ASSERT (apteryx_validate (TEST_PATH"/entity/zones/public/*", test_validate_callback));
    root = APTERYX_NODE (NULL, TEST_PATH"/entity/zones/private");
    APTERYX_LEAF (root, "1", "1");
    APTERYX_LEAF (root, "2", "2");
    APTERYX_LEAF (root, "3", "3");
    APTERYX_LEAF (root, "4", "4");
    CU_ASSERT (apteryx_set_tree (root));
    usleep (5 * RPC_TIMEOUT_US);
    CU_ASSERT (apteryx_unvalidate (TEST_PATH"/entity/zones/public/*", test_validate_callback));
    CU_ASSERT (apteryx_unwatch (TEST_PATH"/entity/zones/private/*", test_set_from_watch_cb));
    CU_ASSERT (apteryx_prune (TEST_PATH"/entity/zones"));
    g_node_destroy (root);
    CU_ASSERT (assert_apteryx_empty ());
}

static int test_validate_order_index;

int
test_validate_order_callback (const char *path, const char *value)
{
    int index;
    CU_ASSERT (sscanf (path, TEST_PATH"/entity/zones/private/%d", &index) == 1);
    CU_ASSERT (index == test_validate_order_index);
    test_validate_order_index++;
    return 0;
}

static bool
test_validate_order_watch_callback (const char *path, const char *value)
{
    int index;
    CU_ASSERT (sscanf (path, TEST_PATH"/entity/zones/private/%d", &index) == 1);
    CU_ASSERT (index <= test_validate_order_index);
    return true;
}

void
test_validate_ordering ()
{
    char *path;
    int i;

    CU_ASSERT (apteryx_watch (TEST_PATH"/entity/zones/private/*", test_validate_order_watch_callback));
    CU_ASSERT (apteryx_validate (TEST_PATH"/entity/zones/private/*", test_validate_order_callback));
    test_validate_order_index = 0;
    for (i=0; i<100; i++)
    {
        CU_ASSERT (asprintf (&path, TEST_PATH"/entity/zones/private/%d", i) > 0);
        CU_ASSERT (apteryx_set_int (path, NULL, i));
        free (path);
    }
    usleep (TEST_SLEEP_TIMEOUT);
    CU_ASSERT (apteryx_unvalidate (TEST_PATH"/entity/zones/private/*", test_validate_order_callback));
    CU_ASSERT (apteryx_unwatch (TEST_PATH"/entity/zones/private/*", test_validate_order_watch_callback));
    CU_ASSERT (apteryx_prune (TEST_PATH"/entity/zones"));
    CU_ASSERT (assert_apteryx_empty ());
}

static int
test_validate_order_tree_callback (const char *path, const char *value)
{
    int index;
    CU_ASSERT (sscanf (path, TEST_PATH"/entity/zones/private/%d", &index) == 1);
    CU_ASSERT (test_validate_order_index < 10);
    test_validate_order_index++;
    return 0;
}

static bool
test_validate_order_tree_watch_callback (const char *path, const char *value)
{
    int index;
    CU_ASSERT (sscanf (path, TEST_PATH"/entity/zones/private/%d", &index) == 1);
    CU_ASSERT (test_validate_order_index >= 10);
    test_validate_order_index++;
    return true;
}

void
test_validate_ordering_tree ()
{
    GNode* root;

    CU_ASSERT (apteryx_watch (TEST_PATH"/entity/zones/private/*", test_validate_order_tree_watch_callback));
    CU_ASSERT (apteryx_validate (TEST_PATH"/entity/zones/private/*", test_validate_order_tree_callback));
    root = APTERYX_NODE (NULL, TEST_PATH"/entity/zones/private");
    APTERYX_LEAF (root, "9", "9");
    APTERYX_LEAF (root, "8", "8");
    APTERYX_LEAF (root, "7", "7");
    APTERYX_LEAF (root, "6", "6");
    APTERYX_LEAF (root, "5", "5");
    APTERYX_LEAF (root, "4", "4");
    APTERYX_LEAF (root, "3", "3");
    APTERYX_LEAF (root, "2", "2");
    APTERYX_LEAF (root, "1", "1");
    APTERYX_LEAF (root, "0", "0");
    test_validate_order_index = 0;
    CU_ASSERT (apteryx_set_tree (root));
    usleep (TEST_SLEEP_TIMEOUT);
    CU_ASSERT (apteryx_unvalidate (TEST_PATH"/entity/zones/private/*", test_validate_order_tree_callback));
    CU_ASSERT (apteryx_unwatch (TEST_PATH"/entity/zones/private/*", test_validate_order_tree_watch_callback));
    CU_ASSERT (apteryx_prune (TEST_PATH"/entity/zones"));
    g_node_destroy (root);
    CU_ASSERT (assert_apteryx_empty ());
}

static int _cb_timeout;
static int _cb_delay = 0;
static uint64_t
test_refresh_callback (const char *path)
{
    char *value = g_strdup_printf ("%d", _cb_count);
    apteryx_set (path, value);
    g_free (value);
    _cb_count++;
    usleep (_cb_delay);
    return _cb_timeout;
}

void
test_refresh ()
{
    const char *path = TEST_PATH"/interfaces/eth0/state";
    const char *value = NULL;

    _cb_count = 0;
    _cb_timeout = 0;
    _cb_delay = 0;
    CU_ASSERT (apteryx_refresh (path, test_refresh_callback));
    CU_ASSERT ((value = apteryx_get (path)) != NULL);
    CU_ASSERT (value && strcmp (value, "0") == 0);
    if (value)
        free ((void *) value);
    apteryx_unrefresh (path, test_refresh_callback);
    CU_ASSERT (apteryx_set (path, NULL));
    CU_ASSERT (assert_apteryx_empty ());
}

void
test_refresh_unneeded ()
{
    const char *path = TEST_PATH"/interfaces/eth0/state";
    const char *value = NULL;

    _cb_count = 0;
    _cb_timeout = 5 * 1000 * 1000;
    _cb_delay = 0;
    CU_ASSERT (apteryx_refresh (path, test_refresh_callback));
    CU_ASSERT ((value = apteryx_get (path)) != NULL);
    CU_ASSERT (value && strcmp (value, "0") == 0);
    if (value)
        free ((void *) value);
    CU_ASSERT ((value = apteryx_get (path)) != NULL);
    CU_ASSERT (value && strcmp (value, "0") == 0);
    if (value)
        free ((void *) value);
    apteryx_unrefresh (path, test_refresh_callback);
    CU_ASSERT (apteryx_set (path, NULL));
    CU_ASSERT (assert_apteryx_empty ());
}

void
test_refresh_timeout ()
{
    const char *path = TEST_PATH"/interfaces/eth0/state";
    const char *value = NULL;

    _cb_count = 0;
    _cb_timeout = 5000;
    _cb_delay = 0;
    CU_ASSERT (apteryx_refresh (path, test_refresh_callback));
    CU_ASSERT ((value = apteryx_get (path)) != NULL);
    CU_ASSERT (value && strcmp (value, "0") == 0);
    if (value)
        free ((void *) value);
    CU_ASSERT ((value = apteryx_get (path)) != NULL);
    CU_ASSERT (value && strcmp (value, "0") == 0);
    if (value)
        free ((void *) value);
    usleep (_cb_timeout);
    CU_ASSERT ((value = apteryx_get (path)) != NULL);
    CU_ASSERT (value && strcmp (value, "1") == 0);
    if (value)
        free ((void *) value);
    apteryx_unrefresh (path, test_refresh_callback);
    CU_ASSERT (apteryx_set (path, NULL));
    CU_ASSERT (assert_apteryx_empty ());
}

static uint64_t
test_refresh_a_callback (const char *path)
{
    _cb_count++;
    apteryx_set_int (TEST_PATH"/interfaces/eth0", "one_hundred", 100);
    return _cb_timeout;
}

static uint64_t
test_refresh_b_callback (const char *path)
{
    _cb_count++;
    apteryx_set_int (TEST_PATH"/interfaces/eth0", "collision", 200);
    return _cb_timeout;
}

static uint64_t
test_refresh_c_callback (const char *path)
{
    _cb_count++;
    apteryx_set_int (TEST_PATH"/interfaces/eth0", "collision", 300);
    return _cb_timeout;
}

void
test_refresh_collision ()
{
    const char *path = TEST_PATH"/interfaces/eth0/*";

    _cb_count = 0;
    _cb_timeout = TEST_SLEEP_TIMEOUT / 2;
    _cb_delay = 0;

    CU_ASSERT (apteryx_refresh (path, test_refresh_a_callback));
    CU_ASSERT (apteryx_refresh (path, test_refresh_b_callback));
    CU_ASSERT (apteryx_refresh (path, test_refresh_c_callback));

    /* Call in order to get times on these fields */
    apteryx_get_int (TEST_PATH"/interfaces/eth0", "one_hundred");
    usleep (TEST_SLEEP_TIMEOUT);
    CU_ASSERT (_cb_count == 3);

    _cb_count = 0;
    /* We should get 3 refreshes, one for each callback above.
     * "one_hundred" is provided by one, and the other two collide
     * trying to set the "collision" field
     */
    CU_ASSERT (100 == apteryx_get_int (TEST_PATH"/interfaces/eth0","one_hundred"));
    CU_ASSERT (_cb_count == 3);
    CU_ASSERT (200 == apteryx_get_int (TEST_PATH"/interfaces/eth0","collision") ||
               300 == apteryx_get_int (TEST_PATH"/interfaces/eth0","collision"));
    CU_ASSERT (_cb_count == 3);

    apteryx_unrefresh (path, test_refresh_a_callback);
    apteryx_unrefresh (path, test_refresh_b_callback);
    apteryx_unrefresh (path, test_refresh_c_callback);

    CU_ASSERT (apteryx_prune (TEST_PATH"/interfaces/eth0"));
    CU_ASSERT (assert_apteryx_empty ());
}

static void *
_state_get_thread (void *priv)
{
    char *value = apteryx_get ((const char *)priv);

    /* These should all get called before the refresh is hit a second time */
    CU_ASSERT (value != NULL);
    if (value)
        CU_ASSERT (strcmp(value, "0") == 0);
    free (value);
    return NULL;
}

void
test_refresh_concurrent ()
{
    const char *path = TEST_PATH"/interfaces/eth0/state";
    int client_count = 7;
    pthread_t clients[client_count];
    int i;

    _cb_count = 0;
    _cb_timeout = TEST_SLEEP_TIMEOUT;
    _cb_delay = TEST_SLEEP_TIMEOUT / 2;

    CU_ASSERT (apteryx_refresh (path, test_refresh_callback));

    /* Reading 7 times within the refresh timeout should cause all
     * reads to get the same value (0)
     * Note that we currenly only support 8 apteryxd threads
     * so we need to leave one free for the refresher to use
     * for the SET operation.
     */
    for (i = 0; i < client_count; i++)
        pthread_create (&clients[i], NULL, _state_get_thread, (void*)path);
    for (i = 0; i < client_count; i++)
        pthread_join (clients[i], NULL);

    apteryx_unrefresh (path, test_refresh_callback);

    CU_ASSERT (apteryx_set (path, NULL));
    CU_ASSERT (assert_apteryx_empty ());
}


static uint64_t
test_refresh_tree_callback (const char *path)
{
    GNode* root = APTERYX_NODE (NULL, TEST_PATH"/interfaces/eth0");
    GNode* state = APTERYX_NODE (root, "state");
    APTERYX_LEAF (state, "state", "up");
    APTERYX_LEAF (state, "speed", "1000");
    APTERYX_LEAF (state, "duplex", "full");
    apteryx_set_tree (root);
    g_node_destroy (root);
    _cb_count++;
    return _cb_timeout;
}


void
test_refresh_wildcards ()
{
    const char *path = TEST_PATH"/interfaces/*/state/*";
    _cb_count = 0;
    _cb_timeout = 0;
    _cb_delay = 0;
    CU_ASSERT (apteryx_refresh (path, test_refresh_tree_callback));

    /* We won't use the wildcard in the refresher path to traverse past
     * interfaces and into state, so this one should not return any
     * data.
     */
    GNode *root = apteryx_get_tree (TEST_PATH"/interfaces");
    CU_ASSERT (root == NULL);
    if (root)
        apteryx_free_tree (root);
    apteryx_prune (TEST_PATH);

    /* Once there is something stored in /interfaces/eth0 we can get past
     * and far enough to call the refresher.
     */
    apteryx_set (TEST_PATH"/interfaces/eth0/name", "eth0");
    _cb_count = 0;
    root = apteryx_get_tree (TEST_PATH"/interfaces");
    CU_ASSERT (root != NULL);
    CU_ASSERT (_cb_count > 0);
    if (root)
        apteryx_free_tree (root);
    apteryx_prune (TEST_PATH);

    /* Even without any data in the tree, if we have no more wildcards
     * in path (on the end is fine) we can traverse down the refresh
     * path to call it (over the state key).
     */
    root = apteryx_get_tree (TEST_PATH"/interfaces/eth0");
    CU_ASSERT (root != NULL);
    if (root)
        apteryx_free_tree (root);
    apteryx_prune (TEST_PATH);

    /* This one is probably the simplest case and tested elsewhere */
    root = apteryx_get_tree (TEST_PATH"/interfaces/eth0/state");
    CU_ASSERT (root != NULL);
    if (root)
        apteryx_free_tree (root);
    apteryx_prune (TEST_PATH);

    apteryx_unrefresh (path, test_refresh_tree_callback);
}

void
test_refresh_trunk ()
{
    const char *path = TEST_PATH"/interfaces/*";
    const char *value = NULL;

    _cb_count = 0;
    _cb_timeout = 5000;
    CU_ASSERT (apteryx_refresh (path, test_refresh_tree_callback));
    CU_ASSERT ((value = apteryx_get (TEST_PATH"/interfaces/eth0/state/state")) != NULL);
    CU_ASSERT (value && strcmp (value, "up") == 0);
    if (value)
        free ((void *) value);
    apteryx_unrefresh (path, test_refresh_tree_callback);
    CU_ASSERT (apteryx_prune (TEST_PATH"/interfaces"));
    CU_ASSERT (_cb_count == 1);
    CU_ASSERT (assert_apteryx_empty ());
}

void
test_refresh_tree ()
{
    const char *path = TEST_PATH"/interfaces/*";
    GNode *value = NULL;

    _cb_count = 0;
    _cb_timeout = 5000;
    CU_ASSERT (apteryx_refresh (path, test_refresh_tree_callback));
    CU_ASSERT ((value = apteryx_get_tree (TEST_PATH"/interfaces/eth0")) != NULL);
    CU_ASSERT (value != NULL);
    if (value)
        apteryx_free_tree (value);
    apteryx_unrefresh (path, test_refresh_tree_callback);
    CU_ASSERT (apteryx_prune (TEST_PATH"/interfaces"));
    CU_ASSERT (_cb_count == 1);
    CU_ASSERT (assert_apteryx_empty ());
}

/* If a refresher is called while traversing the database we can end up
 * with lock contention when the refresher attempts to write to the
 * database. The callback can be expected to be called more than once
 * during the initial path building.
 */
void
test_refresh_during_get_tree ()
{
    const char *path = TEST_PATH"/interfaces/*";
    GNode *value = NULL;

    _cb_count = 0;
    _cb_timeout = 0;
    CU_ASSERT (apteryx_refresh (path, test_refresh_tree_callback));
    CU_ASSERT ((value = apteryx_get_tree (TEST_PATH"/interfaces/eth0")) != NULL);
    CU_ASSERT (value != NULL);
    if (value)
        apteryx_free_tree (value);
    apteryx_unrefresh (path, test_refresh_tree_callback);
    CU_ASSERT (apteryx_prune (TEST_PATH"/interfaces"));
    CU_ASSERT (assert_apteryx_empty ());
}

void
test_refresh_search ()
{
    const char *path = TEST_PATH"/interfaces/*";
    GList *paths = NULL;

    _cb_count = 0;
    _cb_timeout = 0;
    CU_ASSERT (apteryx_refresh (path, test_refresh_tree_callback));

    CU_ASSERT ((paths = apteryx_search (TEST_PATH"/interfaces/")) != NULL);
    CU_ASSERT (g_list_length (paths) == 1);
    CU_ASSERT (g_list_find_custom (paths, TEST_PATH"/interfaces/eth0", (GCompareFunc) strcmp) != NULL);
    g_list_free_full (paths, free);

    apteryx_unrefresh (path, test_refresh_tree_callback);
    CU_ASSERT (apteryx_prune (TEST_PATH"/interfaces"));
    CU_ASSERT (_cb_count == 1);
    CU_ASSERT (assert_apteryx_empty ());
}

static uint64_t
test_refresh_subpath_callback (const char *path)
{
    char *value = g_strdup_printf ("%d", _cb_count);
    apteryx_set (TEST_PATH"/atmf/backups/locations/first", value);
    g_free (value);
    _cb_count++;
    return _cb_timeout;
}

void
test_refresh_subpath_search ()
{
    const char *path = TEST_PATH"/atmf/backups/locations/*";
    GList *paths = NULL;

    _cb_count = 0;
    _cb_timeout = 0;
    CU_ASSERT (apteryx_refresh (path, test_refresh_subpath_callback));
    CU_ASSERT ((paths = apteryx_search (TEST_PATH"/atmf/backups/")) != NULL);
    CU_ASSERT (g_list_length (paths) == 1);
    CU_ASSERT (g_list_find_custom (paths, TEST_PATH"/atmf/backups/locations", (GCompareFunc) strcmp) != NULL);
    g_list_free_full (paths, free);
    CU_ASSERT (_cb_count == 0);

    CU_ASSERT ((paths = apteryx_search (TEST_PATH"/atmf/backups/locations/")) != NULL);
    CU_ASSERT (g_list_length (paths) == 1);
    CU_ASSERT (g_list_find_custom (paths, TEST_PATH"/atmf/backups/locations/first", (GCompareFunc) strcmp) != NULL);
    g_list_free_full (paths, free);
    CU_ASSERT (_cb_count == 1);

    apteryx_unrefresh (path, test_refresh_subpath_callback);
    CU_ASSERT (apteryx_prune (TEST_PATH"/atmf"));
    CU_ASSERT (assert_apteryx_empty ());
}

void
test_refresh_traverse ()
{
    const char *path = TEST_PATH"/interfaces/*";
    GNode *value = NULL;

    _cb_count = 0;
    _cb_timeout = 5000;
    CU_ASSERT (apteryx_refresh (path, test_refresh_tree_callback));
    CU_ASSERT ((value = apteryx_get_tree (TEST_PATH"/interfaces")) != NULL);
    CU_ASSERT (value != NULL);
    if (value)
        apteryx_free_tree (value);
    apteryx_unrefresh (path, test_refresh_tree_callback);
    CU_ASSERT (apteryx_prune (TEST_PATH"/interfaces"));
    CU_ASSERT (_cb_count == 1);
    CU_ASSERT (assert_apteryx_empty ());
}

void
test_refresh_traverse_deeper ()
{
    const char *path = TEST_PATH"/interfaces/eth0/*";
    GNode *value = NULL;

    _cb_count = 0;
    _cb_timeout = 5000;
    CU_ASSERT (apteryx_refresh (path, test_refresh_tree_callback));
    CU_ASSERT ((value = apteryx_get_tree (TEST_PATH"/interfaces")) != NULL);
    CU_ASSERT (value != NULL);
    if (value)
        apteryx_free_tree (value);
    apteryx_unrefresh (path, test_refresh_tree_callback);
    CU_ASSERT (apteryx_prune (TEST_PATH"/interfaces"));
    CU_ASSERT (_cb_count == 1);
    CU_ASSERT (assert_apteryx_empty ());
}

static uint64_t
test_refresh_no_change_callback (const char *path)
{
    _cb_count++;
    return _cb_timeout;
}

void
test_refresh_path_empty ()
{
    const char *path = TEST_PATH"/interfaces/eth0/state";
    const char *value = NULL;

    _cb_count = 0;
    _cb_timeout = 5000;
    CU_ASSERT (apteryx_refresh (path, test_refresh_no_change_callback));
    CU_ASSERT ((value = apteryx_get (path)) == NULL);
    CU_ASSERT ((value = apteryx_get (path)) == NULL);
    apteryx_unrefresh (path, test_refresh_no_change_callback);
    CU_ASSERT (apteryx_set (path, NULL));
    CU_ASSERT (_cb_count == 2);
    CU_ASSERT (assert_apteryx_empty ());
}

void
test_refresh_no_change ()
{
    const char *path = TEST_PATH"/interfaces/eth0/state";
    const char *value = NULL;

    _cb_count = 0;
    _cb_timeout = 5000;
    CU_ASSERT (apteryx_refresh (path, test_refresh_no_change_callback));

    apteryx_set (path, "0");
    usleep (_cb_timeout);
    CU_ASSERT ((value = apteryx_get (path)) != NULL);
    CU_ASSERT (value && strcmp (value, "0") == 0);
    if (value)
        free ((void *) value);
    CU_ASSERT ((value = apteryx_get (path)) != NULL);
    CU_ASSERT (value && strcmp (value, "0") == 0);
    if (value)
        free ((void *) value);

    apteryx_unrefresh (path, test_refresh_no_change_callback);
    CU_ASSERT (apteryx_set (path, NULL));
    CU_ASSERT (_cb_count == 1);
    CU_ASSERT (assert_apteryx_empty ());
}

void
test_refresh_tree_no_change ()
{
    const char *path = TEST_PATH"/zones/private/network/lan/count";
    GList *paths = NULL;
    const char *value = NULL;

    _cb_count = 0;
    _cb_timeout = 5000;
    apteryx_set (path, "0");
    usleep (_cb_timeout);
    CU_ASSERT (apteryx_refresh (TEST_PATH"/zones/*", test_refresh_no_change_callback));

    CU_ASSERT ((value = apteryx_get (path)) != NULL);
    CU_ASSERT (value && strcmp (value, "0") == 0);
    if (value)
        free ((void *) value);
    CU_ASSERT ((value = apteryx_get (path)) != NULL);
    CU_ASSERT (value && strcmp (value, "0") == 0);
    if (value)
        free ((void *) value);
    CU_ASSERT ((paths = apteryx_search (TEST_PATH"/zones/")) != NULL);
    CU_ASSERT (g_list_length (paths) == 1);
    CU_ASSERT (g_list_find_custom (paths, TEST_PATH"/zones/private", (GCompareFunc) strcmp) != NULL);
    g_list_free_full (paths, free);
    CU_ASSERT ((paths = apteryx_search (TEST_PATH"/zones/")) != NULL);
    CU_ASSERT (g_list_length (paths) == 1);
    CU_ASSERT (g_list_find_custom (paths, TEST_PATH"/zones/private", (GCompareFunc) strcmp) != NULL);
    g_list_free_full (paths, free);

    apteryx_unrefresh (TEST_PATH"/zones/*", test_refresh_no_change_callback);
    CU_ASSERT (apteryx_set (path, NULL));
    CU_ASSERT (_cb_count == 2);
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
        apteryx_init (apteryx_debug);
        CU_ASSERT (apteryx_provide (path, test_provide_callback_up));
        usleep (RPC_TIMEOUT_US);
        apteryx_unprovide (path, test_provide_callback_up);
        apteryx_shutdown ();
        exit (0);
    }
    else if (pid > 0)
    {
        apteryx_init (apteryx_debug);
        usleep (RPC_TIMEOUT_US / 2);
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
    return apteryx_get (TEST_PATH"/interfaces/eth0/state_get");
}

void
test_provide_callback_get ()
{
    const char *path1 = TEST_PATH"/interfaces/eth0/state_get";
    const char *path2 = TEST_PATH"/interfaces/eth0/status_get";
    char *value = NULL;

    apteryx_set (path1, "up");
    CU_ASSERT (apteryx_provide (path2, test_provide_callback_get_cb));
    CU_ASSERT ((value = apteryx_get (path2)) != NULL);
    CU_ASSERT (value && strcmp (value, "up") == 0);
    if (value)
        free ((void *) value);
    apteryx_unprovide (path2, test_provide_callback_get_cb);
    CU_ASSERT ((value = apteryx_get (path2)) == NULL);
    apteryx_set (path1, NULL);
    if (value)
        free ((void *) value);
    CU_ASSERT (apteryx_search(TEST_PATH"/interfaces/eth0/") == NULL);
    CU_ASSERT (assert_apteryx_empty ());
}

void
test_provide_callback_get_null ()
{
    const char *path = TEST_PATH"/interfaces/eth0/statii";
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
    CU_ASSERT (apteryx_set (TEST_PATH"/interfaces/eth0/size", "huge"));
    CU_ASSERT ((paths = apteryx_search (TEST_PATH"/interfaces/eth0/")) != NULL);
    CU_ASSERT (g_list_length (paths) == 2);
    CU_ASSERT (g_list_find_custom (paths, path, (GCompareFunc) strcmp) != NULL);
    g_list_free_full (paths, free);

    CU_ASSERT ((paths = apteryx_search (TEST_PATH"/interfaces/")) != NULL);
    CU_ASSERT (g_list_length (paths) == 1);
    CU_ASSERT (g_list_find_custom (paths, TEST_PATH"/interfaces/eth0", (GCompareFunc) strcmp) != NULL);
    g_list_free_full (paths, free);

    apteryx_unprovide (path, test_provide_callback_up);
    CU_ASSERT (apteryx_set (TEST_PATH"/interfaces/eth0/size",NULL));
    CU_ASSERT (assert_apteryx_empty ());
}

void
test_provide_search_root ()
{
    const char *path = TEST_PATH"/interfaces/eth0/state";
    GList *paths = NULL;

    CU_ASSERT (apteryx_provide (path, test_provide_callback_up));
    CU_ASSERT ((paths = apteryx_search ("/")) != NULL);
    CU_ASSERT (g_list_length (paths) == 2);
    CU_ASSERT (g_list_find_custom (paths, TEST_PATH, (GCompareFunc) strcmp) != NULL);
    g_list_free_full (paths, free);

    apteryx_unprovide (path, test_provide_callback_up);
    CU_ASSERT (assert_apteryx_empty ());
}

char *
test_provide_cb(const char *path)
{
    return strdup("provided");
}

void
test_provider_wildcard_search ()
{
    const char *path = TEST_PATH"/atmf/backups/locations/*";
    GList *paths = NULL;

    CU_ASSERT (apteryx_provide (path, test_provide_cb));
    CU_ASSERT ((paths = apteryx_search (TEST_PATH"/atmf/backups/")) != NULL);
    CU_ASSERT (g_list_length (paths) == 1);
    CU_ASSERT (g_list_find_custom (paths, TEST_PATH"/atmf/backups/locations", (GCompareFunc) strcmp) != NULL);
    g_list_free_full (paths, free);

    /* We don't want the * to show up - that should come from the indexer */
    CU_ASSERT ((paths = apteryx_search (TEST_PATH"/atmf/backups/locations/")) == NULL);
    CU_ASSERT (g_list_length (paths) == 0);
    CU_ASSERT (g_list_find_custom (paths, TEST_PATH"/atmf/backups/locations/*", (GCompareFunc) strcmp) == NULL);
    g_list_free_full (paths, free);

    apteryx_unprovide (path, test_provide_cb);
    CU_ASSERT (assert_apteryx_empty ());

}

void
test_provide_search_db ()
{
    const char *path1 = TEST_PATH"/interfaces/eth0/one";
    const char *path2 = TEST_PATH"/interfaces/eth0/two";
    const char *path3 = TEST_PATH"/interfaces/eth0/*";
    GList *paths = NULL;

    CU_ASSERT (apteryx_get (TEST_PATH"/interfaces/eth0/status") == NULL);
    CU_ASSERT (apteryx_provide (path1, test_provide_callback_up));
    CU_ASSERT (apteryx_set (path2, "100"));
    CU_ASSERT (apteryx_provide (path3, test_provide_callback_up));
    CU_ASSERT ((paths = apteryx_search (TEST_PATH"/interfaces/eth0/")) != NULL);
    CU_ASSERT (g_list_length (paths) == 2);
    CU_ASSERT (g_list_find_custom (paths, path1, (GCompareFunc) strcmp) != NULL);
    CU_ASSERT (g_list_find_custom (paths, path2, (GCompareFunc) strcmp) != NULL);
    g_list_free_full (paths, free);
    apteryx_unprovide (path1, test_provide_callback_up);
    CU_ASSERT (apteryx_set (path2, NULL));
    apteryx_unprovide (path3, test_provide_callback_up);
    CU_ASSERT (assert_apteryx_empty ());
}

void
test_provide_before_db ()
{
    const char *path = TEST_PATH"/interfaces/eth0/state";
    const char *value = NULL;

    CU_ASSERT (apteryx_set (path, "down"));
    CU_ASSERT (apteryx_provide (path, test_provide_callback_up));
    CU_ASSERT (( value = apteryx_get (path)) != NULL);
    CU_ASSERT (value && strcmp (value, "up") == 0);
    if (value)
        free ((void *) value);
    apteryx_unprovide (path, test_provide_callback_up);
    CU_ASSERT (apteryx_set (path, NULL));
    CU_ASSERT (assert_apteryx_empty ());
}

static char*
test_provide_wildcard_callback (const char *path)
{
    return strdup ("matching");
}

void
test_provider_wildcard ()
{
    const char *path = TEST_PATH"/interfaces/eth0/*";
    const char *path2 = TEST_PATH"/interfaces/eth0/state";
    const char *path3 = TEST_PATH"/interfaces/eth0";
    char *value = NULL;

    CU_ASSERT (apteryx_provide (path, test_provide_wildcard_callback));
    CU_ASSERT ((value = apteryx_get (path)) != NULL);
    free (value);
    CU_ASSERT ((value = apteryx_get (path2)) != NULL);
    free (value);
    CU_ASSERT ((value = apteryx_get (path3)) == NULL);
    if (value)
        free (value);
    apteryx_unprovide (path, test_provide_wildcard_callback);
}

void
test_provider_wildcard_internal ()
{
    const char *path = TEST_PATH"/a/b/*/f";
    const char *path2 = TEST_PATH"/a/b/e/f";
    const char *path3 = TEST_PATH"/a/bcd/e/f";
    const char *multiple_wildcards = TEST_PATH"/*/double_wildcard/*/f";
    GList *search_result = NULL;
    char *value = NULL;

    CU_ASSERT (apteryx_provide (path, test_provide_wildcard_callback));
    CU_ASSERT (apteryx_provide (multiple_wildcards, test_provide_wildcard_callback));

    /* The provided value should NOT show in search */
    search_result = apteryx_search (TEST_PATH"/a/b/");
    CU_ASSERT (g_list_length (search_result) == 0);
    g_list_free_full (search_result, free);

    CU_ASSERT ((value = apteryx_get (path)) != NULL);
    free (value);
    CU_ASSERT ((value = apteryx_get (path2)) != NULL);
    free (value);
    CU_ASSERT ((value = apteryx_get (path3)) == NULL);
    if (value)
        free (value);
    apteryx_unprovide (path, test_provide_wildcard_callback);

    CU_ASSERT((value=apteryx_get(TEST_PATH"/x/double_wildcard/y/f")) != NULL);
    if (value)
        free(value);
    CU_ASSERT (apteryx_unprovide (multiple_wildcards, test_provide_wildcard_callback));
    CU_ASSERT((value=apteryx_get(TEST_PATH"/x/double_wildcard/y/f")) == NULL);
    CU_ASSERT((search_result = apteryx_search(TEST_PATH"/wildcard/")) == NULL);
};


void
test_tree_nodes ()
{
    GNode* root;
    GNode* node;

    root = APTERYX_NODE (NULL, TEST_PATH"/interfaces/eth0");
    APTERYX_LEAF (root, "state", "up");
    APTERYX_LEAF (root, "speed", "1000");
    APTERYX_LEAF (root, "duplex", "full");
    CU_ASSERT (root != NULL);
    CU_ASSERT (g_node_n_nodes (root, G_TRAVERSE_LEAFS) == 3);
    CU_ASSERT (g_node_n_children (root) == 3);
    CU_ASSERT (!APTERYX_HAS_VALUE(root));
    node = root ? g_node_first_child (root) : NULL;
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
    GNode *root;
    char *name, *value;
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
    CU_ASSERT (APTERYX_NUM_NODES (root) == 1025);
    CU_ASSERT (g_node_n_nodes (root, G_TRAVERSE_ALL) == 2049);
    CU_ASSERT (g_node_n_nodes (root, G_TRAVERSE_LEAVES) == 1024);
    CU_ASSERT (g_node_n_children (root) == 1024);
    CU_ASSERT (!APTERYX_HAS_VALUE(root));
    apteryx_free_tree (root);
    CU_ASSERT (assert_apteryx_empty ());
}

void
test_tree_find_children ()
{
    GNode* root;
    GNode* node;

    root = APTERYX_NODE (NULL, TEST_PATH"/interfaces/eth0");
    APTERYX_LEAF (root, "state", "up");
    APTERYX_LEAF (root, "speed", "1000");
    APTERYX_LEAF (root, "duplex", "full");
    CU_ASSERT ((node = apteryx_find_child (root, "duplex")) != NULL);
    CU_ASSERT ((node = apteryx_find_child (root, "speed")) != NULL);
    CU_ASSERT ((node = apteryx_find_child (root, "state")) != NULL);
    CU_ASSERT (g_strcmp0 (APTERYX_CHILD_VALUE (root, "state"), "up") == 0);
    CU_ASSERT (g_strcmp0 (APTERYX_CHILD_VALUE (root, "speed"), "1000") == 0);
    CU_ASSERT (g_strcmp0 (APTERYX_CHILD_VALUE (root, "duplex"), "full") == 0);
    g_node_destroy (root);
    CU_ASSERT (assert_apteryx_empty ());
}

void
test_tree_path_node ()
{
    GNode *root;
    GNode *first_child;
    GNode *node;

    root = APTERYX_NODE (NULL, TEST_PATH);
    CU_ASSERT (root != NULL);
    first_child = APTERYX_NODE (root, "interfaces");
    CU_ASSERT (first_child != NULL);
    node = APTERYX_NODE (first_child, "eth0");
    CU_ASSERT (node != NULL);
    node = NULL;

    /* Test successful searches
     */
    CU_ASSERT ((node = apteryx_path_node (root, TEST_PATH)) != NULL);
    CU_ASSERT (strcmp (APTERYX_NAME (node), TEST_PATH) == 0);
    CU_ASSERT ((node = apteryx_path_node (root, "/interfaces")) != NULL);
    CU_ASSERT (strcmp (APTERYX_NAME (node), "interfaces") == 0);
    CU_ASSERT ((node = apteryx_path_node (root, "/interfaces/eth0")) != NULL);
    CU_ASSERT (strcmp (APTERYX_NAME (node), "eth0") == 0);
    CU_ASSERT ((node = apteryx_path_node (root, TEST_PATH"/interfaces/eth0")) != NULL);
    CU_ASSERT (strcmp (APTERYX_NAME (node), "eth0") == 0);
    CU_ASSERT ((node = apteryx_path_node (first_child, "/interfaces/eth0")) != NULL);
    CU_ASSERT (strcmp (APTERYX_NAME (node), "eth0") == 0);

    /* Test it fails correctly
     */
    CU_ASSERT ((node = apteryx_path_node (root, "")) == NULL);
    CU_ASSERT ((node = apteryx_path_node (root, "/interface")) == NULL);
    CU_ASSERT ((node = apteryx_path_node (root, "/interfaces/eth1")) == NULL);
    CU_ASSERT ((node = apteryx_path_node (root, TEST_PATH"/interfaces/eth1")) == NULL);
    CU_ASSERT ((node = apteryx_path_node (root, TEST_PATH"ing/interfaces/eth0")) == NULL);
    CU_ASSERT ((node = apteryx_path_node (root, "/tes/interfaces/eth0")) == NULL);

    g_node_destroy (root);
    CU_ASSERT (assert_apteryx_empty ());
}

static int
test_tree_sort (const char *a, const char *b)
{
    unsigned int id1 = atoi (a);
    unsigned int id2 = atoi (b);
    return id1 - id2;
}

static void
test_tree_check_sorted (GNode *node, gpointer data)
{
    unsigned int *max = (unsigned int *) data;
    unsigned int name = atoi (APTERYX_NAME (node));
    unsigned int child = atoi (APTERYX_NAME (node->children));
    unsigned int value = atoi (APTERYX_VALUE (node->children));
    CU_ASSERT ((*max == 0 && node->prev == NULL) || node->prev->next == node);
    CU_ASSERT (node->children->parent == node);
    CU_ASSERT (node->children->children->parent == node->children);
    CU_ASSERT (name == child);
    CU_ASSERT (child == value);
    CU_ASSERT (*max <= value);
    *max = value;
}

void
test_tree_sort_children ()
{
    GNode *root;
    int count = 1024;
    char *name;
    unsigned int i;

    CU_ASSERT ((name = strdup (TEST_PATH"/root")) != NULL);
    CU_ASSERT ((root = APTERYX_NODE (NULL, name)) != NULL);
    for (i=0; i<count; i++)
    {
        name = NULL;
        CU_ASSERT (asprintf (&name, "%d", (unsigned int) rand ()));
        APTERYX_LEAF (APTERYX_NODE (root, name), strdup (name), strdup (name));
    }
    CU_ASSERT (g_node_n_children (root) == count);
    apteryx_sort_children (root, test_tree_sort);
    i = 0;
    g_node_children_foreach (root, G_TRAVERSE_ALL,
            test_tree_check_sorted, (gpointer) &i);
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
test_set_tree_empty ()
{
    GNode *root = g_node_new ("/");
    CU_ASSERT (apteryx_set_tree (root));
    g_node_destroy (root);
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
test_get_tree_value_on_branch ()
{
    const char *path = TEST_PATH"/interfaces/eth0";
    GNode *root = NULL;
    GNode *node = NULL;

    CU_ASSERT (apteryx_set_string (path, "state", "up"));
    CU_ASSERT (apteryx_set_string (path, "duplex", "full"));
    CU_ASSERT (apteryx_set_string (TEST_PATH"/interfaces", "eth0", "eth0"));
    /* get_tree only returns values on leaf nodes */
    root = apteryx_get_tree (TEST_PATH"/interfaces");
    CU_ASSERT (root != NULL);
    CU_ASSERT (root && strcmp (APTERYX_NAME (root), TEST_PATH"/interfaces") == 0);
    CU_ASSERT (root && g_node_n_children (root) == 1);
    node = root ? g_node_first_child (root) : NULL;
    CU_ASSERT (node && strcmp (APTERYX_NAME (node), "eth0") == 0);
    CU_ASSERT (node && g_node_n_children (node) == 2);
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
test_get_tree_provided ()
{
    const char *path = TEST_PATH"/interfaces/eth0/state";
    GNode *root = NULL;
    GNode *node = NULL;

    CU_ASSERT (apteryx_provide (path, test_provide_cb));
    root = apteryx_get_tree (TEST_PATH"/interfaces");
    CU_ASSERT (root != NULL);
    CU_ASSERT (root && !APTERYX_HAS_VALUE (root));
    node = root ? g_node_first_child (root) : NULL;
    CU_ASSERT (node && strcmp (APTERYX_NAME (node), "eth0") == 0);
    CU_ASSERT (node && g_node_n_children (node) == 1);
    node = node ? g_node_first_child (node) : NULL;
    CU_ASSERT (node && strcmp (APTERYX_NAME (node), "state") == 0);
    CU_ASSERT (node && g_node_n_children (node) == 1);

    CU_ASSERT (apteryx_unprovide (path, test_provide_cb));
    apteryx_free_tree (root);
    CU_ASSERT (assert_apteryx_empty ());
}

void
test_get_tree_provided_before_db ()
{
    const char *path = TEST_PATH"/interfaces/eth0/state";
    GNode *root = NULL;
    GNode *node = NULL;

    CU_ASSERT (apteryx_provide (path, test_provide_cb));
    CU_ASSERT (apteryx_set (path, "up"));
    root = apteryx_get_tree (TEST_PATH"/interfaces");
    CU_ASSERT (root != NULL);
    node = root ? g_node_first_child (root) : NULL;
    CU_ASSERT (node && g_node_n_children (node) == 1);
    node = node ? g_node_first_child (node) : NULL;
    CU_ASSERT (node && strcmp (APTERYX_NAME (node), "state") == 0);
    CU_ASSERT (node && strcmp (APTERYX_VALUE (node), "provided") == 0);

    CU_ASSERT (apteryx_set (path, NULL));
    CU_ASSERT (apteryx_unprovide (path, test_provide_cb));
    apteryx_free_tree (root);
    CU_ASSERT (assert_apteryx_empty ());
}

void
test_get_tree_provided_plus_set ()
{
    const char *path = TEST_PATH"/interfaces/eth0/state";
    const char *path2 = TEST_PATH"/interfaces/eth0/admin-status";
    GNode *root = NULL;
    GNode *node = NULL;

    CU_ASSERT (apteryx_provide (path, test_provide_cb));
    CU_ASSERT (apteryx_set (path2, "up"));
    root = apteryx_get_tree (TEST_PATH"/interfaces");
    CU_ASSERT (root != NULL);
    CU_ASSERT (root && !APTERYX_HAS_VALUE (root));
    node = root ? g_node_first_child (root) : NULL;
    CU_ASSERT (node && strcmp (APTERYX_NAME (node), "eth0") == 0);
    CU_ASSERT (node && g_node_n_children (node) == 2);
    node = node ? g_node_first_child (node) : NULL;
    if (node && (strcmp (APTERYX_NAME (node), "state") == 0 || strcmp (APTERYX_NAME (node), "admin-status") == 0))
    {
        CU_ASSERT (node && g_node_n_children (node) == 1);
    }
    else
    {
        CU_ASSERT (false);
    }

    CU_ASSERT (apteryx_unprovide (path, test_provide_cb));
    CU_ASSERT (apteryx_set (path2, NULL));
    apteryx_free_tree (root);
    CU_ASSERT (assert_apteryx_empty ());
}

/* Writing to the database during a provide is a bit cruel and nasty,
 * but we need to be sure that we don't get dead locked while trying
 * to traverse the tree.
 */
char *
test_provide_writes_cb (const char *path)
{
    apteryx_set (TEST_PATH"/unimportant", NULL);
    return strdup ("provided");
}

void
test_get_tree_provider_write ()
{
    const char *path = TEST_PATH"/interfaces/eth0/state";
    GNode *root = NULL;
    GNode *node = NULL;

    CU_ASSERT (apteryx_provide (path, test_provide_writes_cb));
    root = apteryx_get_tree (TEST_PATH"/interfaces");
    CU_ASSERT (root != NULL);
    CU_ASSERT (root && !APTERYX_HAS_VALUE (root));
    node = root ? g_node_first_child (root) : NULL;
    CU_ASSERT (node && strcmp (APTERYX_NAME (node), "eth0") == 0);
    CU_ASSERT (node && g_node_n_children (node) == 1);
    node = node ? g_node_first_child (node) : NULL;
    CU_ASSERT (node && strcmp (APTERYX_NAME (node), "state") == 0);
    CU_ASSERT (node && g_node_n_children (node) == 1);

    CU_ASSERT (apteryx_unprovide (path, test_provide_writes_cb));
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

static bool thrasher_running = false;

static void *
database_thrasher (void *unused)
{
    GNode *root = NULL;
    thrasher_running = true;

    for (int v = 0; thrasher_running; v++)
    {
        root = APTERYX_NODE (NULL, strdup (TEST_PATH"/database/filled/with/nothing"));
        for (int i = 0; i < 50; i++)
        {
            char *k = NULL;
            if(asprintf (&k, "%d", i))
            {
                APTERYX_LEAF_INT (root, k, v);
                free (k);
            }
        }
        apteryx_set_tree (root);
        apteryx_free_tree (root);
    }
    return NULL;
}

void
test_get_tree_while_thrashing ()
{
    pthread_t thrasher_thread;

    pthread_create (&thrasher_thread, NULL, database_thrasher, NULL);

    /* When we read this tree all values should be the same,
     * and there should be about 50 of them */
    usleep (TEST_SLEEP_TIMEOUT);
    GNode *root = apteryx_get_tree (TEST_PATH"/database/filled/with/nothing");

    CU_ASSERT (root != NULL);
    if (root)
    {
        CU_ASSERT (APTERYX_NUM_NODES (root) == 51);
        int found_value = 0;
        for (int i = 0; i < 50; i++)
        {
            char k[10];
            int value;

            sprintf (k, "%d", i);
            GNode *child = apteryx_find_child (root, k);
            CU_ASSERT (child != NULL);
            value = atoi (child ? APTERYX_VALUE (child) : "0");
            if (found_value)
            {
                CU_ASSERT (found_value == value);
            }
            else
            {
                found_value = value;
            }
        }
        apteryx_free_tree (root);
    }

    thrasher_running = false;
    pthread_join (thrasher_thread, NULL);

    apteryx_prune (TEST_PATH"/database/filled/with/nothing");
}

void
test_query2node_invalid ()
{
    char *queries[] = {
        "die",
        "die=",
        "die=now",
        "die=now&=counter",
        "counter&die=now",
        "&",
        "&&,",
    };
    for (int i=0; i < sizeof(queries) / sizeof (const char *); i++)
    {
        GNode *root = g_node_new (g_strdup ("/"));
        CU_ASSERT (apteryx_query_to_node (root, queries[i]));
        apteryx_free_tree (root);
    }
}

void
test_query2node_single_field ()
{
    GNode *root = g_node_new (g_strdup (TEST_PATH"/system"));
    CU_ASSERT (apteryx_query_to_node (root, "time"));
    CU_ASSERT (root && g_node_n_children (root) == 1);
    GNode *node = root ? g_node_first_child (root) : NULL;
    CU_ASSERT (node && strcmp (APTERYX_NAME (node), "time") == 0);
    CU_ASSERT (node && g_node_n_children (node) == 0);
    apteryx_free_tree (root);
}

void
test_query2node_double_field ()
{
    GNode *root = g_node_new (g_strdup (TEST_PATH"/system"));
    CU_ASSERT (apteryx_query_to_node (root, "time;date"));
    CU_ASSERT (root && g_node_n_children (root) == 2);
    GNode *child;
    CU_ASSERT ((child = apteryx_find_child (root, "time")) != NULL);
    CU_ASSERT (child && g_node_n_children (child) == 0);
    CU_ASSERT ((child = apteryx_find_child (root, "date")) != NULL);
    CU_ASSERT (child && g_node_n_children (child) == 0);
    apteryx_free_tree (root);
}

void
test_query2node_single_field_path ()
{
    GNode *root = g_node_new (g_strdup (TEST_PATH"/system"));
    CU_ASSERT (apteryx_query_to_node (root, "time/seconds"));
    CU_ASSERT (root && g_node_n_children (root) == 1);
    GNode *node = root ? g_node_first_child (root) : NULL;
    CU_ASSERT (node && strcmp (APTERYX_NAME (node), "time") == 0);
    CU_ASSERT (node && g_node_n_children (node) == 1);
    node = node ? g_node_first_child (node) : NULL;
    CU_ASSERT (node && strcmp (APTERYX_NAME (node), "seconds") == 0);
    CU_ASSERT (node && g_node_n_children (node) == 0);
    apteryx_free_tree (root);
}

void
test_query2node_double_field_path ()
{
    GNode *root = g_node_new (g_strdup (TEST_PATH"/system"));
    CU_ASSERT (apteryx_query_to_node (root, "time/seconds;date/day"));
    CU_ASSERT (root && g_node_n_children (root) == 2);
    GNode *child;
    CU_ASSERT ((child = apteryx_find_child (root, "time")) != NULL);
    CU_ASSERT (child && g_node_n_children (child) == 1);
    CU_ASSERT ((child = apteryx_find_child (child, "seconds")) != NULL);
    CU_ASSERT (child && g_node_n_children (child) == 0);
    CU_ASSERT ((child = apteryx_find_child (root, "date")) != NULL);
    CU_ASSERT (child && g_node_n_children (child) == 1);
    CU_ASSERT ((child = apteryx_find_child (child, "day")) != NULL);
    CU_ASSERT (child && g_node_n_children (child) == 0);
    apteryx_free_tree (root);
}

void
test_query2node_one_path_two_nodes ()
{
    GNode *root = g_node_new (g_strdup (TEST_PATH"/system"));
    CU_ASSERT (apteryx_query_to_node (root, "time(minutes;seconds)"));
    CU_ASSERT (root && g_node_n_children (root) == 1);
    GNode *node;
    CU_ASSERT ((node = apteryx_find_child (root, "time")) != NULL);
    CU_ASSERT (node && g_node_n_children (node) == 2);
    GNode *child;
    CU_ASSERT ((child = apteryx_find_child (node, "seconds")) != NULL);
    CU_ASSERT (child && g_node_n_children (child) == 0);
    CU_ASSERT ((child = apteryx_find_child (node, "minutes")) != NULL);
    CU_ASSERT (child && g_node_n_children (child) == 0);
    apteryx_free_tree (root);
}

void
test_query2node_two_path_two_nodes ()
{
    GNode *root = g_node_new (g_strdup (TEST_PATH"/system"));
    CU_ASSERT (apteryx_query_to_node (root, "time(minutes;seconds);date(month;day)"));
    CU_ASSERT (root && g_node_n_children (root) == 2);
    GNode *parent, *child;
    CU_ASSERT ((parent = apteryx_find_child (root, "time")) != NULL);
    CU_ASSERT (parent && g_node_n_children (parent) == 2);
    CU_ASSERT ((child = apteryx_find_child (parent, "seconds")) != NULL);
    CU_ASSERT (child && g_node_n_children (child) == 0);
    CU_ASSERT ((child = apteryx_find_child (parent, "minutes")) != NULL);
    CU_ASSERT (child && g_node_n_children (child) == 0);
    CU_ASSERT ((parent = apteryx_find_child (root, "date")) != NULL);
    CU_ASSERT (parent && g_node_n_children (parent) == 2);
    CU_ASSERT ((child = apteryx_find_child (parent, "month")) != NULL);
    CU_ASSERT (child && g_node_n_children (child) == 0);
    CU_ASSERT ((child = apteryx_find_child (parent, "day")) != NULL);
    CU_ASSERT (child && g_node_n_children (child) == 0);
    apteryx_free_tree (root);
}

void
test_query_empty ()
{
    GNode *query = g_node_new ("/");
    CU_ASSERT (apteryx_query (query) == NULL);
    g_node_destroy (query);
}

void
test_query_basic ()
{
    GNode *root = NULL;
    GNode *rroot = NULL;
    GNode *iroot = NULL;
    char *path = NULL;

    root = APTERYX_NODE (NULL, TEST_PATH"/routing/ipv4/rib/1");
    APTERYX_LEAF (root, "proto", "static");
    APTERYX_LEAF (root, "ifname", "eth0");
    APTERYX_LEAF (root, "prefix", "10.0.0.0/8");
    CU_ASSERT (apteryx_set_tree (root));
    g_node_destroy (root);

    root = APTERYX_NODE (NULL, TEST_PATH"/routing/ipv4/rib/2");
    APTERYX_LEAF (root, "proto", "static");
    APTERYX_LEAF (root, "ifname", "eth1");
    APTERYX_LEAF (root, "prefix", "172.16.0.0/16");
    CU_ASSERT (apteryx_set_tree (root));
    g_node_destroy (root);
    root = NULL;

    root = g_node_new (strdup ("/"));
    path = g_strdup (TEST_PATH"/routing/ipv4/rib/1");
    iroot = apteryx_path_to_node (root, path, NULL);
    APTERYX_NODE (iroot, strdup ("proto"));
    APTERYX_NODE (iroot, strdup ("ifname"));
    rroot = apteryx_query (root);
    CU_ASSERT (rroot && g_node_n_nodes (rroot, G_TRAVERSE_LEAVES) == 2);
    CU_ASSERT (rroot && g_node_n_nodes (rroot, G_TRAVERSE_ALL) == 10);

    apteryx_free_tree (rroot);
    apteryx_free_tree (root);

    /* Nothing to be queried from this point */
    root = APTERYX_NODE (NULL, TEST_PATH"/routing");
    rroot = apteryx_query(root);
    CU_ASSERT (rroot == NULL);

    apteryx_query (NULL);

    if (root) g_node_destroy(root);
    if (rroot) g_node_destroy(rroot);

    g_free (path);

    apteryx_prune (TEST_PATH);
}

void
test_query_subtree_root ()
{
    GNode *root = NULL;
    GNode *rroot = NULL;

    root = APTERYX_NODE (NULL, TEST_PATH"/routing/ipv4/rib/1");
    APTERYX_LEAF (root, "proto", "static");
    APTERYX_LEAF (root, "ifname", "eth0");
    APTERYX_LEAF (root, "prefix", "10.0.0.0/8");
    CU_ASSERT (apteryx_set_tree (root));
    g_node_destroy (root);

    root = APTERYX_NODE (NULL, TEST_PATH"/routing/ipv4/rib/2");
    APTERYX_LEAF (root, "proto", "static");
    APTERYX_LEAF (root, "ifname", "eth1");
    APTERYX_LEAF (root, "prefix", "172.16.0.0/16");
    CU_ASSERT (apteryx_set_tree (root));
    g_node_destroy (root);
    root = NULL;

    root = g_node_new (strdup (TEST_PATH"/routing/ipv4/rib/1"));
    APTERYX_NODE (root, strdup ("proto"));
    APTERYX_NODE (root, strdup ("ifname"));
    rroot = apteryx_query (root);
    CU_ASSERT (g_node_n_nodes (rroot, G_TRAVERSE_LEAVES) == 2);
    CU_ASSERT (g_node_n_nodes (rroot, G_TRAVERSE_ALL) == 5);

    apteryx_free_tree (rroot);
    apteryx_free_tree (root);

    apteryx_prune (TEST_PATH);
}

void
test_query_one_level ()
{
    GNode *query = NULL;
    GNode *rroot = NULL;

    apteryx_set_string (TEST_PATH"/interfaces/eth0", "description", "our lan");
    apteryx_set_string (TEST_PATH"/interfaces/eth0", "state", "up");
    apteryx_set_string (TEST_PATH"/interfaces/eth0/counters", "pkts", "10");

    /* Full tree query */
    query = g_node_new (strdup ("/"));
    apteryx_path_to_node (query, TEST_PATH"/interfaces/eth0/", NULL);
    rroot = apteryx_query (query);
    CU_ASSERT (rroot && g_node_n_nodes (rroot, G_TRAVERSE_LEAVES) == 2);
    apteryx_free_tree (rroot);
    apteryx_free_tree (query);

    /* Root node path and empty child node */
    query = g_node_new (strdup (TEST_PATH"/interfaces/eth0"));
    APTERYX_NODE (query, strdup (""));
    rroot = apteryx_query (query);
    CU_ASSERT (rroot && g_node_n_nodes (rroot, G_TRAVERSE_LEAVES) == 2);
    apteryx_free_tree (rroot);
    apteryx_free_tree (query);

    /* Full query in root node */
    query = g_node_new (strdup (TEST_PATH"/interfaces/eth0/"));
    rroot = apteryx_query (query);
    CU_ASSERT (rroot && g_node_n_nodes (rroot, G_TRAVERSE_LEAVES) == 2);
    apteryx_free_tree (rroot);
    apteryx_free_tree (query);

    apteryx_prune (TEST_PATH);
}

void
test_query_one_star ()
{
    GNode *root = NULL;
    GNode *rroot = NULL;
    GNode *iroot = NULL;
    char *path = NULL;

    root = APTERYX_NODE (NULL, TEST_PATH"/routing/ipv4/rib/1");
    APTERYX_LEAF (root, "proto", "static");
    APTERYX_LEAF (root, "ifname", "eth0");
    APTERYX_LEAF (root, "prefix", "10.0.0.0/8");
    CU_ASSERT (apteryx_set_tree (root));
    g_node_destroy (root);

    root = APTERYX_NODE (NULL, TEST_PATH"/routing/ipv4/rib/2");
    APTERYX_LEAF (root, "proto", "static");
    APTERYX_LEAF (root, "ifname", "eth1");
    APTERYX_LEAF (root, "prefix", "172.16.0.0/16");
    CU_ASSERT (apteryx_set_tree (root));
    g_node_destroy (root);
    root = NULL;

    root = g_node_new (strdup ("/"));
    path = strdup (TEST_PATH"/routing/ipv4/rib/*");
    iroot = apteryx_path_to_node (root, path, NULL);
    APTERYX_NODE (iroot, strdup ("proto"));
    APTERYX_NODE (iroot, strdup ("ifname"));
    rroot = apteryx_query (root);
    CU_ASSERT (g_node_n_nodes (rroot, G_TRAVERSE_LEAVES) == 4);

    apteryx_free_tree (rroot);
    apteryx_free_tree (root);
    g_free (path);

    apteryx_prune (TEST_PATH);
}

void
test_query_one_star_traverse ()
{
    GNode *root = NULL;
    GNode *rroot = NULL;
    char *path = NULL;

    root = APTERYX_NODE (NULL, TEST_PATH"/routing/ipv4/rib/1");
    APTERYX_LEAF (root, "proto", "static");
    APTERYX_LEAF (root, "ifname", "eth0");
    APTERYX_LEAF (root, "prefix", "10.0.0.0/8");
    CU_ASSERT (apteryx_set_tree (root));
    g_node_destroy (root);

    root = APTERYX_NODE (NULL, TEST_PATH"/routing/ipv4/rib/2");
    APTERYX_LEAF (root, "proto", "static");
    APTERYX_LEAF (root, "ifname", "eth1");
    APTERYX_LEAF (root, "prefix", "172.16.0.0/16");
    CU_ASSERT (apteryx_set_tree (root));
    g_node_destroy (root);
    root = NULL;

    root = g_node_new (strdup ("/"));
    path = strdup (TEST_PATH"/routing/ipv4/*");
    apteryx_path_to_node (root, path, NULL);
    rroot = apteryx_query (root);
    CU_ASSERT (g_node_n_nodes (rroot, G_TRAVERSE_LEAVES) == 6);

    apteryx_free_tree (rroot);
    apteryx_free_tree (root);
    g_free (path);

    apteryx_prune (TEST_PATH);
}

void
test_query_one_star_match_exact ()
{
    GNode *root = NULL;
    GNode *rroot = NULL;
    GNode *iroot = NULL;
    GNode *child = NULL;
    char *path = NULL;

    root = APTERYX_NODE (NULL, TEST_PATH"/routing/ipv4/rib/1");
    APTERYX_LEAF (root, "proto", "static");
    APTERYX_LEAF (root, "ifname", "eth0");
    APTERYX_LEAF (root, "ipaddr", "10.0.0.1");
    CU_ASSERT (apteryx_set_tree (root));
    g_node_destroy (root);

    root = APTERYX_NODE (NULL, TEST_PATH"/routing/ipv4/rib/2");
    APTERYX_LEAF (root, "proto", "static");
    APTERYX_LEAF (root, "ifname", "eth1");
    APTERYX_LEAF (root, "ipaddr", "172.16.0.1");
    CU_ASSERT (apteryx_set_tree (root));
    g_node_destroy (root);

    root = g_node_new (strdup ("/"));
    path = strdup (TEST_PATH"/routing/ipv4/rib/*");
    iroot = apteryx_path_to_node (root, path, NULL);
    child = APTERYX_NODE (iroot, strdup ("ipaddr"));
    APTERYX_NODE (child, strdup ("172.16.0.1"));

    rroot = apteryx_query (root);
    CU_ASSERT (g_node_n_nodes (rroot, G_TRAVERSE_LEAVES) == 1);

    apteryx_free_tree (rroot);
    apteryx_free_tree (root);
    g_free (path);

    apteryx_prune (TEST_PATH);
}

void
test_query_one_star_no_match_exact ()
{
    GNode *root = NULL;
    GNode *rroot = NULL;
    GNode *iroot = NULL;
    GNode *child = NULL;
    char *path = NULL;

    root = APTERYX_NODE (NULL, TEST_PATH"/routing/ipv4/rib/1");
    APTERYX_LEAF (root, "proto", "static");
    APTERYX_LEAF (root, "ifname", "eth0");
    APTERYX_LEAF (root, "ipaddr", "10.0.0.1");
    CU_ASSERT (apteryx_set_tree (root));
    g_node_destroy (root);

    root = APTERYX_NODE (NULL, TEST_PATH"/routing/ipv4/rib/2");
    APTERYX_LEAF (root, "proto", "static");
    APTERYX_LEAF (root, "ifname", "eth1");
    APTERYX_LEAF (root, "ipaddr", "172.16.0.1");
    CU_ASSERT (apteryx_set_tree (root));
    g_node_destroy (root);

    root = g_node_new (strdup ("/"));
    path = strdup (TEST_PATH"/routing/ipv4/rib/*");
    iroot = apteryx_path_to_node (root, path, NULL);
    child = APTERYX_NODE (iroot, strdup ("ipaddr"));
    APTERYX_NODE (child, strdup ("144.16.0.1"));

    rroot = apteryx_query (root);
    CU_ASSERT (rroot == NULL);

    apteryx_free_tree (rroot);
    apteryx_free_tree (root);
    g_free (path);

    apteryx_prune (TEST_PATH);
}

void
test_query_one_star_match_exact_with_other ()
{
    GNode *root = NULL;
    GNode *rroot = NULL;
    GNode *iroot = NULL;
    GNode *child = NULL;
    char *path = NULL;

    root = APTERYX_NODE (NULL, TEST_PATH"/routing/ipv4/rib/1");
    APTERYX_LEAF (root, "proto", "static");
    APTERYX_LEAF (root, "ifname", "eth0");
    APTERYX_LEAF (root, "ipaddr", "10.0.0.1");
    CU_ASSERT (apteryx_set_tree (root));
    g_node_destroy (root);

    root = APTERYX_NODE (NULL, TEST_PATH"/routing/ipv4/rib/2");
    APTERYX_LEAF (root, "proto", "static");
    APTERYX_LEAF (root, "ifname", "eth1");
    APTERYX_LEAF (root, "ipaddr", "172.16.0.1");
    CU_ASSERT (apteryx_set_tree (root));
    g_node_destroy (root);

    root = g_node_new (strdup ("/"));
    path = strdup (TEST_PATH"/routing/ipv4/rib/*");
    iroot = apteryx_path_to_node (root, path, NULL);
    APTERYX_NODE (iroot, strdup ("ifname"));
    child = APTERYX_NODE (iroot, strdup ("ipaddr"));
    APTERYX_NODE (child, strdup ("172.16.0.1"));

    rroot = apteryx_query (root);
    CU_ASSERT (g_node_n_nodes (rroot, G_TRAVERSE_LEAVES) == 2);

    apteryx_free_tree (rroot);
    apteryx_free_tree (root);
    g_free (path);

    apteryx_prune (TEST_PATH);
}

void
test_query_one_star_match_exact_two_results ()
{
    GNode *root = NULL;
    GNode *rroot = NULL;
    GNode *iroot = NULL;
    GNode *child = NULL;
    char *path = NULL;

    root = APTERYX_NODE (NULL, TEST_PATH"/routing/ipv4/rib/1");
    APTERYX_LEAF (root, "proto", "static");
    APTERYX_LEAF (root, "ifname", "eth0");
    APTERYX_LEAF (root, "ipaddr", "10.0.0.1");
    CU_ASSERT (apteryx_set_tree (root));
    g_node_destroy (root);

    root = APTERYX_NODE (NULL, TEST_PATH"/routing/ipv4/rib/2");
    APTERYX_LEAF (root, "proto", "static");
    APTERYX_LEAF (root, "ifname", "eth1");
    APTERYX_LEAF (root, "ipaddr", "172.16.0.1");
    CU_ASSERT (apteryx_set_tree (root));
    g_node_destroy (root);

    root = g_node_new (strdup ("/"));
    path = strdup (TEST_PATH"/routing/ipv4/rib/*");
    iroot = apteryx_path_to_node (root, path, NULL);
    child = APTERYX_NODE (iroot, strdup ("proto"));
    APTERYX_NODE (child, strdup ("static"));

    rroot = apteryx_query (root);
    CU_ASSERT (g_node_n_nodes (rroot, G_TRAVERSE_LEAVES) == 2);

    apteryx_free_tree (rroot);
    apteryx_free_tree (root);
    g_free (path);

    apteryx_prune (TEST_PATH);
}

void
test_query_one_star_match_exact_two_results_with_other ()
{
    GNode *root = NULL;
    GNode *rroot = NULL;
    GNode *iroot = NULL;
    GNode *child = NULL;
    char *path = NULL;

    root = APTERYX_NODE (NULL, TEST_PATH"/routing/ipv4/rib/1");
    APTERYX_LEAF (root, "proto", "static");
    APTERYX_LEAF (root, "ifname", "eth0");
    APTERYX_LEAF (root, "ipaddr", "10.0.0.1");
    CU_ASSERT (apteryx_set_tree (root));
    g_node_destroy (root);

    root = APTERYX_NODE (NULL, TEST_PATH"/routing/ipv4/rib/2");
    APTERYX_LEAF (root, "proto", "static");
    APTERYX_LEAF (root, "ifname", "eth1");
    APTERYX_LEAF (root, "ipaddr", "172.16.0.1");
    CU_ASSERT (apteryx_set_tree (root));
    g_node_destroy (root);

    root = g_node_new (strdup ("/"));
    path = strdup (TEST_PATH"/routing/ipv4/rib/*");
    iroot = apteryx_path_to_node (root, path, NULL);
    APTERYX_NODE (iroot, strdup ("ifname"));
    child = APTERYX_NODE (iroot, strdup ("proto"));
    APTERYX_NODE (child, strdup ("static"));

    rroot = apteryx_query (root);
    CU_ASSERT (g_node_n_nodes (rroot, G_TRAVERSE_LEAVES) == 4);

    apteryx_free_tree (rroot);
    apteryx_free_tree (root);
    g_free (path);

    apteryx_prune (TEST_PATH);
}

void
test_query_multi_star_traverse ()
{
    GNode *root = NULL;
    GNode *rroot = NULL;

    root = APTERYX_NODE (NULL, TEST_PATH"/routing/ipv4/rib/1");
    APTERYX_LEAF (root, "proto", "static");
    APTERYX_LEAF (root, "ifname", "eth0");
    APTERYX_LEAF (root, "prefix", "10.0.0.0/8");
    CU_ASSERT (apteryx_set_tree (root));
    g_node_destroy (root);

    root = APTERYX_NODE (NULL, TEST_PATH"/routing/ipv4/rib/2");
    APTERYX_LEAF (root, "proto", "static");
    APTERYX_LEAF (root, "ifname", "eth1");
    APTERYX_LEAF (root, "prefix", "172.16.0.0/16");
    CU_ASSERT (apteryx_set_tree (root));
    g_node_destroy (root);
    root = NULL;

    root = g_node_new (strdup ("/"));
    apteryx_path_to_node (root, TEST_PATH"/routing/ipv4/rib/*/ifname", NULL);
    apteryx_path_to_node (root, TEST_PATH"/routing/ipv4/fib/*", NULL);
    rroot = apteryx_query (root);
    CU_ASSERT (g_node_n_nodes (rroot, G_TRAVERSE_LEAVES) == 2);

    apteryx_free_tree (rroot);
    apteryx_free_tree (root);

    apteryx_prune (TEST_PATH);
}

void
test_query_one_star_one_level ()
{
    GNode *root = NULL;
    GNode *rroot = NULL;
    char *path = NULL;

    root = APTERYX_NODE (NULL, TEST_PATH"/routing/ipv4/rib/1");
    APTERYX_LEAF (root, "proto", "static");
    APTERYX_LEAF (root, "ifname", "eth0");
    APTERYX_LEAF (root, "prefix", "10.0.0.0/8");
    CU_ASSERT (apteryx_set_tree (root));
    g_node_destroy (root);

    root = APTERYX_NODE (NULL, TEST_PATH"/routing/ipv4/rib/2");
    APTERYX_LEAF (root, "proto", "static");
    APTERYX_LEAF (root, "ifname", "eth1");
    APTERYX_LEAF (root, "prefix", "172.16.0.0/16");
    CU_ASSERT (apteryx_set_tree (root));
    g_node_destroy (root);
    root = NULL;
    apteryx_set (TEST_PATH"/routing/ipv4/rib/3", "junk");

    root = g_node_new (strdup ("/"));
    path = strdup (TEST_PATH"/routing/ipv4/rib/*/");
    apteryx_path_to_node (root, path, NULL);
    rroot = apteryx_query (root);
    CU_ASSERT (rroot && g_node_n_nodes (rroot, G_TRAVERSE_LEAVES) == 6);

    apteryx_free_tree (rroot);
    apteryx_free_tree (root);
    g_free (path);

    apteryx_prune (TEST_PATH);
}

void
test_query_multi_star_one_level ()
{
    GNode *root = NULL;
    GNode *rroot = NULL;

    root = APTERYX_NODE (NULL, TEST_PATH"/routing/ipv4/rib/1");
    APTERYX_LEAF (root, "proto", "static");
    APTERYX_LEAF (root, "ifname", "eth0");
    APTERYX_LEAF (root, "prefix", "10.0.0.0/8");
    CU_ASSERT (apteryx_set_tree (root));
    g_node_destroy (root);

    root = APTERYX_NODE (NULL, TEST_PATH"/routing/ipv4/rib/2");
    APTERYX_LEAF (root, "proto", "static");
    APTERYX_LEAF (root, "ifname", "eth1");
    APTERYX_LEAF (root, "prefix", "172.16.0.0/16");
    CU_ASSERT (apteryx_set_tree (root));
    g_node_destroy (root);
    root = NULL;
    apteryx_set (TEST_PATH"/routing/ipv4/rib/3", "junk");

    root = g_node_new (strdup ("/"));
    apteryx_path_to_node (root, TEST_PATH"/routing/ipv4/rib/*/", NULL);
    apteryx_path_to_node (root, TEST_PATH"/routing/ipv4/fib/*", NULL);
    rroot = apteryx_query (root);
    CU_ASSERT (rroot && g_node_n_nodes (rroot, G_TRAVERSE_LEAVES) == 6);

    apteryx_free_tree (rroot);
    apteryx_free_tree (root);

    apteryx_prune (TEST_PATH);
}

void
test_query_two_star ()
{
    GNode *root = NULL;
    GNode *rroot = NULL;
    GNode *iroot = NULL;
    char *path = NULL;

    root = APTERYX_NODE (NULL, TEST_PATH"/routing/ipv4/rib/1");
    APTERYX_LEAF (root, "proto", "static");
    APTERYX_LEAF (root, "ifname", "eth0");
    APTERYX_LEAF (root, "prefix", "10.0.0.0/8");
    CU_ASSERT (apteryx_set_tree (root));
    g_node_destroy (root);

    root = APTERYX_NODE (NULL, TEST_PATH"/routing/ipv4/rib/2");
    APTERYX_LEAF (root, "proto", "static");
    APTERYX_LEAF (root, "ifname", "eth1");
    APTERYX_LEAF (root, "prefix", "172.16.0.0/16");
    CU_ASSERT (apteryx_set_tree (root));
    g_node_destroy (root);

    root = APTERYX_NODE (NULL, TEST_PATH"/routing/ipv6/rib/1");
    APTERYX_LEAF (root, "proto", "static");
    APTERYX_LEAF (root, "ifname", "eth0");
    APTERYX_LEAF (root, "prefix", "fc00:1::/64");
    CU_ASSERT (apteryx_set_tree (root));
    g_node_destroy (root);

    root = APTERYX_NODE (NULL, TEST_PATH"/routing/ipv6/rib/2");
    APTERYX_LEAF (root, "proto", "static");
    APTERYX_LEAF (root, "ifname", "eth1");
    APTERYX_LEAF (root, "prefix", "fc00:2::/64");
    CU_ASSERT (apteryx_set_tree (root));
    g_node_destroy (root);
    root = NULL;

    root = g_node_new (strdup ("/"));
    path = strdup (TEST_PATH"/routing/*/rib/*");
    iroot = apteryx_path_to_node (root, path, NULL);
    APTERYX_NODE (iroot, strdup ("proto"));
    APTERYX_NODE (iroot, strdup ("ifname"));
    rroot = apteryx_query (root);
    CU_ASSERT (g_node_n_nodes (rroot, G_TRAVERSE_LEAVES) == 8);

    apteryx_free_tree (rroot);
    apteryx_free_tree (root);
    g_free (path);

    apteryx_prune (TEST_PATH);
}

void
test_query_null_values ()
{
    GNode *root = NULL;
    GNode *rroot = NULL;
    GNode *iroot = NULL;
    char *path = NULL;

    root = APTERYX_NODE (NULL, TEST_PATH"/routing/ipv4/rib/0");
    APTERYX_LEAF (root, "proto", "static");
    APTERYX_LEAF (root, "prefix", "10.0.0.0/8");
    CU_ASSERT (apteryx_set_tree (root));
    g_node_destroy (root);

    root = APTERYX_NODE (NULL, TEST_PATH"/routing/ipv4/rib/1");
    APTERYX_LEAF (root, "proto", "static");
    APTERYX_LEAF (root, "ifname", "");
    APTERYX_LEAF (root, "prefix", "10.0.0.0/8");
    CU_ASSERT (apteryx_set_tree (root));
    g_node_destroy (root);

    root = APTERYX_NODE (NULL, TEST_PATH"/routing/ipv4/rib/2");
    APTERYX_LEAF (root, "proto", "static");
    APTERYX_LEAF (root, "ifname", "eth1");
    APTERYX_LEAF (root, "prefix", "10.0.0.0/8");
    CU_ASSERT (apteryx_set_tree (root));
    g_node_destroy (root);

    root = APTERYX_NODE (NULL, TEST_PATH"/routing/ipv4/rib/3");
    APTERYX_LEAF (root, "proto", "static");
    APTERYX_LEAF (root, "ifname", "eth10");
    APTERYX_LEAF (root, "prefix", "10.0.0.0/8");
    CU_ASSERT (apteryx_set_tree (root));
    g_node_destroy (root);
    root = NULL;

    root = g_node_new (strdup ("/"));
    path = strdup (TEST_PATH"/routing/*/rib/*");
    iroot = apteryx_path_to_node (root, path, NULL);
    APTERYX_NODE (iroot, strdup ("ifname"));
    rroot = apteryx_query (root);
    CU_ASSERT (g_node_n_nodes (rroot, G_TRAVERSE_LEAVES) == 2);

    apteryx_free_tree (rroot);
    apteryx_free_tree (root);
    g_free (path);

    apteryx_prune (TEST_PATH);
}

void
test_query_two_branches ()
{
    GNode *root = NULL;
    GNode *rroot = NULL;
    GNode *iroot = NULL;
    char *path = NULL;
    char *path2 = NULL;

    root = APTERYX_NODE (NULL, TEST_PATH"/routing/ipv4/rib/1");
    APTERYX_LEAF (root, "proto", "static");
    APTERYX_LEAF (root, "ifname", "eth0");
    APTERYX_LEAF (root, "prefix", "10.0.0.0/8");
    CU_ASSERT (apteryx_set_tree (root));
    g_node_destroy (root);

    root = APTERYX_NODE (NULL, TEST_PATH"/routing/ipv4/rib/2");
    APTERYX_LEAF (root, "proto", "static");
    APTERYX_LEAF (root, "ifname", "eth1");
    APTERYX_LEAF (root, "prefix", "172.16.0.0/16");
    CU_ASSERT (apteryx_set_tree (root));
    g_node_destroy (root);

    root = APTERYX_NODE (NULL, TEST2_PATH"/routing/ipv6/rib/0");
    APTERYX_LEAF (root, "proto", "static2");
    APTERYX_LEAF (root, "ifname", "eth2");
    APTERYX_LEAF (root, "prefix", "fc00:2::4/64");
    CU_ASSERT (apteryx_set_tree (root));
    g_node_destroy (root);
    root = NULL;

    root = g_node_new (strdup ("/"));
    path = strdup (TEST_PATH"/routing/ipv4/rib/1");
    path2 = strdup (TEST2_PATH"/routing/ipv6/rib/0");
    iroot = apteryx_path_to_node (root, path, NULL);
    APTERYX_NODE (iroot, strdup ("proto"));
    APTERYX_NODE (iroot, strdup ("ifname"));
    iroot = apteryx_path_to_node (root, path2, NULL);
    APTERYX_NODE (iroot, strdup ("proto"));
    APTERYX_NODE (iroot, strdup ("ifname"));
    rroot = apteryx_query (root);
    CU_ASSERT (rroot && strcmp (APTERYX_NAME (rroot), "/") == 0);
    char *p = apteryx_node_path(rroot);
    CU_ASSERT (strstr(p, "//") == NULL);
    g_free (p);
    CU_ASSERT (g_node_n_nodes (rroot, G_TRAVERSE_LEAVES) == 4);

    apteryx_free_tree (rroot);
    apteryx_free_tree (root);
    g_free (path);
    g_free (path2);

    apteryx_prune (TEST_PATH);
    apteryx_prune (TEST2_PATH);
}

static char *
dont_call_this(const char *_unused) {
    CU_ASSERT_FALSE ("Never call me here!");
    return NULL;
}

void
test_query_provided ()
{
    const char *path = TEST_PATH"/system/state";
    GNode *root = NULL;
    GNode *rroot = NULL;

    CU_ASSERT (apteryx_provide (path, test_provide_cb));

    /* Direct query of provided value */
    root = g_node_new (strdup ("/"));
    apteryx_path_to_node (root, path, NULL);
    rroot = apteryx_query (root);
    CU_ASSERT (rroot && g_node_n_nodes (rroot, G_TRAVERSE_LEAVES) == 1);
    CU_ASSERT (rroot && g_node_max_height (rroot) == 5);
    apteryx_free_tree (rroot);
    apteryx_free_tree (root);

    /* Directory level query of provided value */
    root = g_node_new (strdup ("/"));
    apteryx_path_to_node (root, TEST_PATH"/system/", NULL);
    rroot = apteryx_query (root);
    CU_ASSERT (rroot && g_node_n_nodes (rroot, G_TRAVERSE_LEAVES) == 1);
    CU_ASSERT (rroot && g_node_max_height (rroot) == 5);
    apteryx_free_tree (rroot);
    apteryx_free_tree (root);

    CU_ASSERT (apteryx_unprovide (path, test_provide_cb));
}

void
test_query_provided_before_db ()
{
    const char *path = TEST_PATH"/system/state";
    GNode *root = NULL;
    GNode *rroot = NULL;
    GNode *node;

    CU_ASSERT (apteryx_provide (path, test_provide_cb));
    CU_ASSERT (apteryx_set (path, "up"));

    /* Direct query of provided value */
    root = g_node_new (strdup ("/"));
    apteryx_path_to_node (root, path, NULL);
    rroot = apteryx_query (root);
    node = rroot ? g_node_first_child (rroot) : NULL;
    node = node ? g_node_first_child (node) : NULL;
    CU_ASSERT (node && g_node_n_children (node) == 1);
    node = node ? g_node_first_child (node) : NULL;
    CU_ASSERT (node && strcmp (APTERYX_NAME (node), "state") == 0);
    CU_ASSERT (node && strcmp (APTERYX_VALUE (node), "provided") == 0);
    apteryx_free_tree (rroot);
    apteryx_free_tree (root);

    /* Directory level query of provided value */
    root = g_node_new (strdup ("/"));
    apteryx_path_to_node (root, TEST_PATH"/system/", NULL);
    rroot = apteryx_query (root);
    node = rroot ? g_node_first_child (rroot) : NULL;
    node = node ? g_node_first_child (node) : NULL;
    CU_ASSERT (node && g_node_n_children (node) == 1);
    node = node ? g_node_first_child (node) : NULL;
    CU_ASSERT (node && strcmp (APTERYX_NAME (node), "state") == 0);
    CU_ASSERT (node && strcmp (APTERYX_VALUE (node), "provided") == 0);
    apteryx_free_tree (rroot);
    apteryx_free_tree (root);

    CU_ASSERT (apteryx_set (path, NULL));
    CU_ASSERT (apteryx_unprovide (path, test_provide_cb));
}

static uint64_t
test_refresh_cb(const char *path)
{
    apteryx_set (TEST_PATH"/system/ram/size", "1000");
    return 1000000;
}

void
test_query_provided_refreshed ()
{
    const char *path = TEST_PATH"/system";
    GNode *root = NULL;
    GNode *rroot = NULL;

    CU_ASSERT (apteryx_provide (TEST_PATH"/system/flash/size", test_provide_cb));
    CU_ASSERT (apteryx_refresh (TEST_PATH"/system/ram/size", test_refresh_cb));

    /* Direct query of value on the tree (no value) */
    root = g_node_new (strdup ("/"));
    apteryx_path_to_node (root, path, NULL);
    rroot = apteryx_query (root);
    CU_ASSERT (!rroot);
    apteryx_free_tree (rroot);
    apteryx_free_tree (root);

    /* Full depth query of tree */
    root = g_node_new (strdup ("/"));
    apteryx_path_to_node (root, TEST_PATH"/system/*", NULL);
    rroot = apteryx_query (root);
    CU_ASSERT (rroot && g_node_n_nodes (rroot, G_TRAVERSE_LEAVES) == 2);
    CU_ASSERT (rroot && g_node_max_height (rroot) == 6);
    apteryx_free_tree (rroot);
    apteryx_free_tree (root);

    /* Directory level query of provided + refreshed value */
    root = g_node_new (strdup ("/"));
    apteryx_path_to_node (root, TEST_PATH"/system/ram/", NULL);
    apteryx_path_to_node (root, TEST_PATH"/system/flash/", NULL);
    rroot = apteryx_query (root);
    CU_ASSERT (rroot && g_node_n_nodes (rroot, G_TRAVERSE_LEAVES) == 2);
    CU_ASSERT (rroot && g_node_max_height (rroot) == 6);
    apteryx_free_tree (rroot);
    apteryx_free_tree (root);

    CU_ASSERT (apteryx_unprovide (TEST_PATH"/system/flash/size", test_provide_cb));
    CU_ASSERT (apteryx_unrefresh (TEST_PATH"/system/ram/size", test_refresh_cb));
    apteryx_prune (TEST_PATH);
}

void
test_query_trunk_provided ()
{
    const char *path = TEST_PATH"/system/state";
    GNode *root = NULL;
    GNode *rroot = NULL;

    CU_ASSERT (apteryx_provide (path, test_provide_cb));

    /* Query of an intermediate node should return nothing */
    root = g_node_new (strdup ("/"));
    apteryx_path_to_node (root, TEST_PATH"/system", NULL);
    rroot = apteryx_query (root);
    CU_ASSERT (rroot == NULL);
    apteryx_free_tree (rroot);
    apteryx_free_tree (root);

    CU_ASSERT (apteryx_unprovide (path, test_provide_cb));
}

void
test_query_provided_wildcard ()
{
    const char *path = TEST_PATH"/system/state";
    GNode *root = NULL;
    GNode *rroot = NULL;

    CU_ASSERT (apteryx_provide (path, test_provide_cb));

    root = g_node_new (strdup ("/"));
    apteryx_path_to_node (root, TEST_PATH"/system/*", NULL);
    rroot = apteryx_query (root);
    CU_ASSERT (rroot && g_node_n_nodes (rroot, G_TRAVERSE_LEAVES) == 1);
    CU_ASSERT (rroot && g_node_max_height (rroot) == 5);

    apteryx_free_tree (rroot);
    apteryx_free_tree (root);

    CU_ASSERT (apteryx_unprovide (path, test_provide_cb));
}

void
test_query_provided_wildcards ()
{
    const char *path = TEST_PATH"/devices/*/interfaces/*/state";
    GNode *root = NULL;
    GNode *rroot = NULL;

    CU_ASSERT (apteryx_provide (path, test_provide_cb));
    CU_ASSERT (apteryx_provide (TEST_PATH"/forbidden", dont_call_this));

    root = APTERYX_NODE (NULL, TEST_PATH"/devices/unit1/interfaces/eth0");
    APTERYX_LEAF (root, "ifname", "eth0");
    CU_ASSERT (apteryx_set_tree (root));
    g_node_destroy (root);

    root = APTERYX_NODE (NULL, TEST_PATH"/devices/unit1/interfaces/eth1");
    APTERYX_LEAF (root, "ifname", "eth1");
    CU_ASSERT (apteryx_set_tree (root));
    g_node_destroy (root);

    root = g_node_new (strdup ("/"));
    apteryx_path_to_node (root, TEST_PATH"/devices/*", NULL);
    rroot = apteryx_query (root);
    CU_ASSERT (g_node_n_nodes (rroot, G_TRAVERSE_LEAVES) == 4);

    apteryx_free_tree (rroot);
    apteryx_free_tree (root);

    CU_ASSERT (apteryx_unprovide (TEST_PATH"/forbidden", dont_call_this));
    CU_ASSERT (apteryx_unprovide (path, test_provide_cb));

    CU_ASSERT (apteryx_provide (TEST_PATH"/one/provide/lower", test_provide_cb));
    root = g_node_new(strdup(TEST_PATH"/one/provide/*"));
    rroot = apteryx_query(root);
    CU_ASSERT (rroot && g_strcmp0 (TEST_PATH"/one/provide", APTERYX_NAME(rroot)) == 0);
    CU_ASSERT (g_node_n_nodes (rroot, G_TRAVERSE_LEAVES) == 1);
    apteryx_free_tree (rroot);
    apteryx_free_tree (root);
    CU_ASSERT (apteryx_unprovide (TEST_PATH"/one/provide/lower", test_provide_cb));

    apteryx_prune (TEST_PATH);
}

void
test_query_long_root()
{
    const char *path = TEST_PATH"/devices/dut/interfaces/eth1/state";
    GNode *root = NULL;
    GNode *rroot = NULL;

    apteryx_set(path, "up");

    root = g_node_new(strdup(TEST_PATH"/devices/*"));
    rroot = apteryx_query(root);
    CU_ASSERT (rroot && g_strcmp0 (TEST_PATH"/devices", APTERYX_NAME(rroot)) == 0);
    CU_ASSERT (g_node_n_nodes (rroot, G_TRAVERSE_LEAVES) == 1);
    apteryx_free_tree (rroot);
    apteryx_free_tree (root);

    root = g_node_new(strdup(TEST_PATH"/devices/*/interfaces/*"));
    rroot = apteryx_query(root);
    CU_ASSERT (rroot && g_strcmp0 (TEST_PATH"/devices", APTERYX_NAME(rroot)) == 0);
    CU_ASSERT (g_node_n_nodes (rroot, G_TRAVERSE_LEAVES) == 1);
    apteryx_free_tree (rroot);
    apteryx_free_tree (root);

    apteryx_prune (TEST_PATH);
}

void
test_query_too_long()
{
    GNode *query = NULL;

    apteryx_set (TEST_PATH"/routing/ipv4/rib", "rib");

    query = g_node_new (strdup ("/"));
    apteryx_path_to_node (query, TEST_PATH"/routing/ipv4/rib/1/ifname", NULL);
    CU_ASSERT (apteryx_query (query) == NULL);
    apteryx_free_tree (query);

    apteryx_prune (TEST_PATH);
}

void
test_query_value_on_branch()
{
    GNode *root = NULL;
    GNode *query = NULL;

    root = APTERYX_NODE (NULL, TEST_PATH"/routing/ipv4/rib/1");
    APTERYX_LEAF (root, "proto", "static");
    APTERYX_LEAF (root, "ifname", "eth0");
    APTERYX_LEAF (root, "prefix", "10.0.0.0/8");
    CU_ASSERT (apteryx_set_tree (root));
    g_node_destroy (root);

    root = APTERYX_NODE (NULL, TEST_PATH"/routing/ipv4/rib/2");
    APTERYX_LEAF (root, "proto", "static");
    APTERYX_LEAF (root, "ifname", "eth1");
    APTERYX_LEAF (root, "prefix", "172.16.0.0/16");
    CU_ASSERT (apteryx_set_tree (root));
    g_node_destroy (root);

    apteryx_set (TEST_PATH"/routing/ipv4/rib", "rib");

    query = g_node_new (strdup (TEST_PATH"/routing/ipv4/rib/*"));
    root = apteryx_query (query);
    CU_ASSERT (root && g_node_n_children (root) == 2);
    CU_ASSERT (g_node_n_nodes (root, G_TRAVERSE_LEAVES) == 6);
    apteryx_free_tree (query);
    apteryx_free_tree (root);

    query = g_node_new (strdup (TEST_PATH"/routing/ipv4/rib/1/ifname"));
    root = apteryx_query (query);
    CU_ASSERT (root && APTERYX_HAS_VALUE (root));
    CU_ASSERT (root && strcmp (APTERYX_VALUE (root), "eth0") == 0);
    apteryx_free_tree (query);
    apteryx_free_tree (root);

    apteryx_prune (TEST_PATH);
}

static uint64_t
refresh_state_callback (const char *path)
{
    apteryx_set (TEST_PATH"/devices/dut/interfaces/eth1/state", "up");
    _cb_count++;
    return _cb_timeout;
}

void
test_query_refreshed_simple()
{
    const char *path = TEST_PATH"/devices/dut/interfaces/eth1/state";
    GNode *root = NULL;
    GNode *rroot = NULL;

    _cb_count = 0;
    _cb_timeout = 0;
    apteryx_refresh (path, refresh_state_callback);

    root = g_node_new (strdup(TEST_PATH"/devices/*"));
    rroot = apteryx_query (root);
    CU_ASSERT (rroot && g_strcmp0 (TEST_PATH"/devices", APTERYX_NAME(rroot)) == 0);
    CU_ASSERT (g_node_n_nodes (rroot, G_TRAVERSE_LEAVES) == 1);
    apteryx_free_tree (rroot);
    apteryx_free_tree (root);
    CU_ASSERT (_cb_count == 1);

    apteryx_unrefresh (path, refresh_state_callback);
    apteryx_set (TEST_PATH"/devices/dut/interfaces/eth1/state", NULL);
    apteryx_prune (TEST_PATH);
}

void
test_query_refreshed_mid_wildcard()
{
    const char *path = TEST_PATH"/devices/dut/interfaces/eth1/state";
    GNode *root = NULL;
    GNode *rroot = NULL;

    _cb_count = 0;
    _cb_timeout = 0;
    apteryx_refresh (path, refresh_state_callback);

    root = g_node_new (strdup(TEST_PATH"/devices/*/interfaces/eth1/state"));
    rroot = apteryx_query (root);
    CU_ASSERT (rroot && g_strcmp0 (TEST_PATH"/devices", APTERYX_NAME(rroot)) == 0);
    CU_ASSERT (rroot && g_node_n_nodes (rroot, G_TRAVERSE_LEAVES) == 1);
    apteryx_free_tree (rroot);
    apteryx_free_tree (root);
    CU_ASSERT (_cb_count == 1);

    apteryx_unrefresh (path, refresh_state_callback);
    apteryx_set (TEST_PATH"/devices/dut/interfaces/eth1/state", NULL);
    apteryx_prune (TEST_PATH);
}

void
test_query_refreshed_multi_wildcard()
{
    const char *path = TEST_PATH"/devices/dut/interfaces/eth1/state";
    GNode *root = NULL;
    GNode *rroot = NULL;

    _cb_count = 0;
    _cb_timeout = 0;
    apteryx_refresh (path, refresh_state_callback);

    root = g_node_new (strdup(TEST_PATH"/devices/*/interfaces/*"));
    rroot = apteryx_query (root);
    CU_ASSERT (rroot && g_strcmp0 (TEST_PATH"/devices", APTERYX_NAME(rroot)) == 0);
    CU_ASSERT (rroot && g_node_n_nodes (rroot, G_TRAVERSE_LEAVES) == 1);
    apteryx_free_tree (rroot);
    apteryx_free_tree (root);
    CU_ASSERT (_cb_count == 1);

    apteryx_unrefresh (path, refresh_state_callback);
    apteryx_set (TEST_PATH"/devices/dut/interfaces/eth1/state", NULL);
    apteryx_prune (TEST_PATH);
}

void
test_query_refreshed_once()
{
    const char *path = TEST_PATH"/devices/dut/interfaces/eth1/state";
    GNode *root = NULL;
    GNode *rroot = NULL;

    _cb_count = 0;
    _cb_timeout = 5000;
    apteryx_refresh (path, refresh_state_callback);

    root = g_node_new (strdup(TEST_PATH"/devices/*"));
    CU_ASSERT ((rroot = apteryx_query (root)) != NULL);
    apteryx_free_tree (rroot);
    CU_ASSERT (_cb_count == 1);
    usleep (_cb_timeout);
    CU_ASSERT ((rroot = apteryx_query (root)) != NULL);
    apteryx_free_tree (rroot);
    CU_ASSERT (_cb_count == 2);
    apteryx_free_tree (root);

    apteryx_unrefresh (path, refresh_state_callback);
    apteryx_prune (TEST_PATH);
}

void
test_query_not_refreshed_one_path()
{
    const char *path = "/cars/suv/*";
    GNode *root;
    GNode *node;

    _cb_count = 0;
    _cb_timeout = 5000;
    apteryx_refresh (path, refresh_state_callback);

    /* Collapsed path */
    root = g_node_new (strdup("/cars/sedan/*"));
    CU_ASSERT (apteryx_query (root) == NULL);
    CU_ASSERT (_cb_count == 0);
    apteryx_free_tree (root);

    /* Expanded path */
    root = g_node_new (strdup("/"));
    node = APTERYX_NODE (root, strdup ("cars"));
    node = APTERYX_NODE (node, strdup ("sedan"));
    APTERYX_NODE (node, strdup ("*"));
    CU_ASSERT (apteryx_query (root) == NULL);
    CU_ASSERT (_cb_count == 0);
    apteryx_free_tree (root);

    apteryx_unrefresh (path, refresh_state_callback);
    apteryx_prune (TEST_PATH);
}

void
test_query_not_refreshed_two_paths()
{
    const char *path = "/cars/suv/*";
    GNode *root;
    GNode *node;

    _cb_count = 0;
    _cb_timeout = 5000;
    apteryx_refresh (path, refresh_state_callback);

    root = g_node_new (strdup("/cars"));
    node = APTERYX_NODE (root, strdup ("sedan"));
    APTERYX_NODE (node, strdup ("*"));
    node = APTERYX_NODE (root, strdup ("hatchback"));
    APTERYX_NODE (node, strdup ("*"));
    CU_ASSERT (apteryx_query (root) == NULL);
    CU_ASSERT (_cb_count == 0);
    apteryx_free_tree (root);

    apteryx_unrefresh (path, refresh_state_callback);
    apteryx_prune (TEST_PATH);
}

void
test_query_not_refreshed_different_roots()
{
    const char *path = "/cars/suv/*";
    GNode *root;

    _cb_count = 0;
    _cb_timeout = 5000;
    apteryx_refresh (path, refresh_state_callback);

    root = g_node_new (strdup("/"));
    apteryx_path_to_node (root, "/cars/sedan/*", NULL);
    apteryx_path_to_node (root, "/houses/*", NULL);
    CU_ASSERT (apteryx_query (root) == NULL);
    CU_ASSERT (_cb_count == 0);
    apteryx_free_tree (root);

    apteryx_unrefresh (path, refresh_state_callback);
    apteryx_prune (TEST_PATH);
}

// TODO current behaviour is to refresh from the first wildcard
// void
// test_query_not_refreshed_mid_wildcard()
// {
//     const char *path = TEST_PATH"/devices/dut/interfaces/eth1/state";
//     GNode *root = NULL;

//     _cb_count = 0;
//     _cb_timeout = 5000;
//     apteryx_refresh (path, refresh_state_callback);

//     root = g_node_new (strdup(TEST_PATH"/devices/*/interfaces/eth2/state"));
//     CU_ASSERT (apteryx_query (root) == NULL);
//     CU_ASSERT (_cb_count == 0);
//     apteryx_free_tree (root);

//     apteryx_unrefresh (path, refresh_state_callback);
//     apteryx_set (TEST_PATH"/devices/dut/interfaces/eth1/state", NULL);
//     apteryx_prune (TEST_PATH);
// }

static uint64_t
refresh_timeout_callback (const char *path)
{
    usleep (1.1 * RPC_TIMEOUT_US);
    return 100000;
}

void
test_query_refresh_timeout()
{
    const char *path = TEST_PATH"/devices/dut/interfaces/eth1/state";
    GNode *root;

    _cb_count = 0;
    apteryx_refresh (path, refresh_timeout_callback);

    root = g_node_new (strdup(TEST_PATH"/devices/*"));
    CU_ASSERT (apteryx_query (root) == NULL);
    usleep (0.1 * RPC_TIMEOUT_US);
    apteryx_free_tree (root);

    root = g_node_new (strdup("/"));
    apteryx_path_to_node (root, TEST_PATH"/devices/*", NULL);
    CU_ASSERT (apteryx_query (root) == NULL);
    usleep (0.1 * RPC_TIMEOUT_US);
    apteryx_free_tree (root);

    apteryx_unrefresh (path, refresh_timeout_callback);
}

void
test_cas_tree ()
{
    const char *path = TEST_PATH"/interfaces/eth0";
    GNode* root;
    uint64_t ts;

    root = APTERYX_NODE (NULL, (char*)path);
    APTERYX_LEAF (root, "state", "up");
    APTERYX_LEAF (root, "speed", "1000");
    APTERYX_LEAF (root, "duplex", "full");

    CU_ASSERT (apteryx_cas_tree (root, 0));
    CU_ASSERT (!apteryx_cas_tree (root, 0));
    CU_ASSERT (errno == -EBUSY);
    CU_ASSERT ((ts = apteryx_timestamp (path)) != 0);
    CU_ASSERT (apteryx_cas_tree (root, ts));
    CU_ASSERT (!apteryx_cas_tree (root, ts));
    CU_ASSERT (errno == -EBUSY);

    CU_ASSERT (apteryx_prune (path));
    g_node_destroy (root);
    CU_ASSERT (assert_apteryx_empty ());
}


void
test_cas_tree_detailed ()
{
    const char *path = TEST_PATH"/team";
    GNode *root, *node;
    uint64_t ts;

    /* Do a set into an empty place in the database */
    root = APTERYX_NODE (NULL, (char*)path);
    node = APTERYX_NODE (root, "blue");
    APTERYX_LEAF (node, "first", "who");
    APTERYX_LEAF (node, "second", "i don't know");
    APTERYX_LEAF (node, "third", "why");
    CU_ASSERT (apteryx_cas_tree (root, 0));
    CU_ASSERT (!apteryx_cas_tree (root, 0));
    CU_ASSERT (errno == -EBUSY);
    CU_ASSERT ((ts = apteryx_timestamp (path)) != 0);
    g_node_destroy (root);

    /* Make sure we can set data that doesn't collide with previous */
    root = APTERYX_NODE (NULL, (char*)path);
    node = APTERYX_NODE (root, "numbers");
    APTERYX_LEAF (node, "one", "1");
    APTERYX_LEAF (node, "two", "2");
    APTERYX_LEAF (node, "three", "3");
    node = APTERYX_NODE (root, "colors");
    APTERYX_LEAF (node, "red", "pink");
    APTERYX_LEAF (node, "blue", "green");
    APTERYX_LEAF (node, "black", "white");
    CU_ASSERT (apteryx_cas_tree (root, 0));
    CU_ASSERT (!apteryx_cas_tree (root, 0));
    CU_ASSERT (errno == -EBUSY);
    g_node_destroy (root);

    /* Make sure that, in the case of a collision, none of the data
     * is set.
     */
    root = APTERYX_NODE (NULL, (char*)path);
    node = APTERYX_NODE (root, "animals");
    APTERYX_LEAF (node, "pig", "piglet");
    APTERYX_LEAF (node, "duck", "duckling");
    APTERYX_LEAF (node, "cow", "veal");
    node = APTERYX_NODE (root, "colors");
    APTERYX_LEAF (node, "red", "pink");
    APTERYX_LEAF (node, "blue", "green");
    APTERYX_LEAF (node, "black", "white");
    CU_ASSERT (!apteryx_cas_tree (root, 0));
    CU_ASSERT (errno == -EBUSY);
    g_node_destroy (root);

    char *value = apteryx_get (TEST_PATH"/team/animals/pig");
    CU_ASSERT (value == NULL);
    if (value)
        free (value);

    CU_ASSERT (apteryx_prune (path));
    CU_ASSERT (assert_apteryx_empty ());
}

static bool atomic_tree_running = true;
static pthread_mutex_t atomic_tree_set_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t atomic_tree_prune_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t atomic_tree_set_cond = PTHREAD_COND_INITIALIZER;
static pthread_cond_t atomic_tree_prune_cond = PTHREAD_COND_INITIALIZER;
static GNode *atomic_tree_root = NULL;

static int
tree_atomic_set (void *data)
{
    while (atomic_tree_running)
    {
        pthread_cond_wait (&atomic_tree_set_cond, &atomic_tree_set_lock);
        //printf ("prune ");
        CU_ASSERT (apteryx_set_tree (atomic_tree_root));
        pthread_mutex_unlock (&atomic_tree_set_lock);
    }
    return 0;
}

static int
tree_atomic_prune (void *data)
{
    uint64_t time = (int) (size_t) data;
    while (atomic_tree_running)
    {
        pthread_cond_wait (&atomic_tree_prune_cond, &atomic_tree_prune_lock);
        uint64_t wait = (time / 2) + (rand () & (time / 2));
        //printf ("wait:%zd ", wait);
        usleep (wait);
        apteryx_prune (TEST_PATH"/interfaces/eth0");
        pthread_mutex_unlock (&atomic_tree_prune_lock);
    }
    return 0;
}

void
test_tree_atomic ()
{
    uint64_t start, time = 1;
    char *name, *value;
    int count = 1000;
    uint64_t iterations;
    pthread_t prune_thread, set_thread;
    GList *paths;
    int i;

    /* Generate test tree */
    CU_ASSERT ((name = strdup (TEST_PATH"/interfaces/eth0")) != NULL);
    CU_ASSERT ((atomic_tree_root = APTERYX_NODE (NULL, name)) != NULL);
    for (i=0; i<count; i++)
    {
        name = value = NULL;
        CU_ASSERT (asprintf (&name, "%d", i));
        CU_ASSERT (asprintf (&value, "%d", i));
        APTERYX_LEAF (atomic_tree_root, name, value);
    }

    /* Calculate time to set tree */
    start = get_time_us ();
    CU_ASSERT (apteryx_set_tree (atomic_tree_root));
    time = (get_time_us () - start);
    //printf ("\nTime: %"PRIu64"us ...\n", time);
    apteryx_prune (TEST_PATH"/interfaces/eth0");
    iterations = 1000000 / time;
    if (iterations < 50)
        iterations = 50;
    if (iterations > 200)
        iterations = 200;
    //printf ("Iterations: %"PRIu64"\n", iterations);

    /* Start the set/prune threads */
    atomic_tree_running = true;
    pthread_create (&set_thread, NULL, (void *) &tree_atomic_set, (void *) (size_t) time);
    pthread_create (&prune_thread, NULL, (void *) &tree_atomic_prune, (void *) (size_t) time);
    usleep (TEST_SLEEP_TIMEOUT);

    for (i=0; i<iterations;i++)
    {
        pthread_cond_signal (&atomic_tree_prune_cond);
        pthread_cond_signal (&atomic_tree_set_cond);
        usleep (100);
        pthread_mutex_lock (&atomic_tree_prune_lock);
        pthread_mutex_lock (&atomic_tree_set_lock);
        usleep (2 * time);
        paths = apteryx_search (TEST_PATH"/interfaces/eth0/");
        CU_ASSERT (g_list_length (paths) == 0 || g_list_length (paths) == count);
        //printf("len:%d\n", g_list_length (paths));
        g_list_free_full (paths, free);
        apteryx_prune (TEST_PATH"/interfaces/eth0");
        pthread_mutex_unlock (&atomic_tree_prune_lock);
        pthread_mutex_unlock (&atomic_tree_set_lock);
    }

    atomic_tree_running = false;
    pthread_cond_signal (&atomic_tree_set_cond);
    pthread_cond_signal (&atomic_tree_prune_cond);
    pthread_join (set_thread, NULL);
    pthread_join (prune_thread, NULL);
    usleep (TEST_SLEEP_TIMEOUT);
    apteryx_prune (TEST_PATH"/interfaces/eth0");
    apteryx_free_tree (atomic_tree_root);
    CU_ASSERT (assert_apteryx_empty ());
}

static GNode *watch_tree_root = NULL;
static bool
test_watch_tree_callback (GNode *root)
{
    if (watch_tree_root)
        apteryx_free_tree (watch_tree_root);
    watch_tree_root = root;
    _cb_count++;
    return true;
}

void
_watch_tree_cleanup ()
{
    _cb_count = 0;
    if (watch_tree_root)
        apteryx_free_tree (watch_tree_root);
    watch_tree_root = NULL;
    CU_ASSERT (assert_apteryx_empty ());
}

void
test_watch_tree ()
{
    const char *path = TEST_PATH"/entity/zones/private/state";
    GNode* node;

    CU_ASSERT (apteryx_set_string (path, NULL, "up"));
    CU_ASSERT (apteryx_watch_tree (path, test_watch_tree_callback));
    CU_ASSERT (apteryx_set_string (path, NULL, "down"));
    usleep (TEST_SLEEP_TIMEOUT);
    CU_ASSERT (watch_tree_root != NULL);
    CU_ASSERT (_cb_count == 1);
    CU_ASSERT (g_node_n_nodes (watch_tree_root, G_TRAVERSE_NON_LEAVES) == 6);
    CU_ASSERT (g_node_n_nodes (watch_tree_root, G_TRAVERSE_LEAVES) == 1);
    CU_ASSERT ((node = apteryx_path_node (watch_tree_root, path)) != NULL);
    CU_ASSERT (node && strcmp (APTERYX_VALUE (node), "down") == 0);
    CU_ASSERT (apteryx_unwatch_tree (path, test_watch_tree_callback));
    apteryx_set_string (path, NULL, NULL);
    _watch_tree_cleanup ();
}

void
test_watch_tree_wildcard ()
{
    const char *path = TEST_PATH"/interfaces/*";
    GNode* node;

    CU_ASSERT (apteryx_watch_tree (path, test_watch_tree_callback));
    node = APTERYX_NODE (NULL, TEST_PATH"/interfaces/eth0");
    APTERYX_LEAF (node, "state", "up");
    APTERYX_LEAF (node, "speed", "1000");
    APTERYX_LEAF (node, "duplex", "full");
    CU_ASSERT (apteryx_set_tree (node));
    g_node_destroy (node);
    usleep (TEST_SLEEP_TIMEOUT);
    CU_ASSERT (watch_tree_root != NULL);
    CU_ASSERT (_cb_count == 1);
    CU_ASSERT (g_node_n_nodes (watch_tree_root, G_TRAVERSE_NON_LEAVES) == 7);
    CU_ASSERT (g_node_n_nodes (watch_tree_root, G_TRAVERSE_LEAVES) == 3);
    CU_ASSERT ((node = apteryx_path_node (watch_tree_root, TEST_PATH"/interfaces/eth0")) != NULL);
    CU_ASSERT (strcmp (APTERYX_CHILD_VALUE (node, "state") ?: "", "up") == 0);
    CU_ASSERT (strcmp (APTERYX_CHILD_VALUE (node, "speed") ?: "", "1000") == 0);
    CU_ASSERT (strcmp (APTERYX_CHILD_VALUE (node, "duplex") ?: "", "full") == 0);
    CU_ASSERT (apteryx_unwatch_tree (path, test_watch_tree_callback));
    CU_ASSERT (apteryx_prune (TEST_PATH"/interfaces/eth0"));
    _watch_tree_cleanup ();
}

void
test_watch_tree_no_match ()
{
    const char *path1 = TEST_PATH"/entity/zones/private/state";
    const char *path2 = TEST_PATH"/entity/zones/private/active";

    CU_ASSERT (apteryx_set_string (path1, NULL, "up"));
    usleep (TEST_SLEEP_TIMEOUT);
    CU_ASSERT (apteryx_watch_tree (path1, test_watch_tree_callback));
    CU_ASSERT (apteryx_set_string (path2, NULL, "true"));
    CU_ASSERT (watch_tree_root == NULL);
    CU_ASSERT (_cb_count == 0);
    CU_ASSERT (apteryx_unwatch_tree (path1, test_watch_tree_callback));
    CU_ASSERT (apteryx_set_string (path1, NULL, NULL));
    CU_ASSERT (apteryx_set_string (path2, NULL, NULL));
    _watch_tree_cleanup ();
}

void
test_watch_tree_remove ()
{
    const char *path = TEST_PATH"/entity/zones/private/state";

    CU_ASSERT (apteryx_set_string (path, NULL, "up"));
    usleep (TEST_SLEEP_TIMEOUT);
    CU_ASSERT (apteryx_watch_tree (path, test_watch_tree_callback));
    CU_ASSERT (apteryx_unwatch_tree (path, test_watch_tree_callback));
    usleep (TEST_SLEEP_TIMEOUT);
    CU_ASSERT (apteryx_set_string (path, NULL, "down"));
    CU_ASSERT (watch_tree_root == NULL);
    CU_ASSERT (_cb_count == 0);
    CU_ASSERT (apteryx_set_string (path, NULL, NULL));
    _watch_tree_cleanup ();
}

void
test_watch_tree_prune ()
{
    const char *path = TEST_PATH"/entity/zones/private/state";
    GNode *node;

    CU_ASSERT (apteryx_set(path, "up"));
    CU_ASSERT (apteryx_watch_tree (TEST_PATH"/entity/*", test_watch_tree_callback));
    CU_ASSERT (apteryx_prune (TEST_PATH"/entity"));
    usleep (TEST_SLEEP_TIMEOUT);
    CU_ASSERT (watch_tree_root != NULL);
    CU_ASSERT ((node = apteryx_path_node (watch_tree_root, TEST_PATH"/entity/zones/private")) != NULL);
    CU_ASSERT (g_strcmp0 (APTERYX_CHILD_VALUE (node, "state"), "") == 0);
    CU_ASSERT (_cb_count == 1);
    CU_ASSERT (apteryx_unwatch_tree (TEST_PATH"/entity/*", test_watch_tree_callback));
    _watch_tree_cleanup ();
}

void
test_watch_tree_prune_tree ()
{
    const char *path = TEST_PATH"/interfaces/eth0";
    GNode *node;

    node = APTERYX_NODE (NULL, (gpointer) path);
    APTERYX_LEAF (node, "state", "up");
    APTERYX_LEAF (node, "speed", "1000");
    APTERYX_LEAF (node, "duplex", "full");
    CU_ASSERT (apteryx_set_tree (node));
    g_node_destroy (node);
    CU_ASSERT (apteryx_watch_tree (TEST_PATH"/interfaces/eth0/", test_watch_tree_callback));
    CU_ASSERT (apteryx_prune (path));
    usleep (TEST_SLEEP_TIMEOUT);
    CU_ASSERT (_cb_count == 1);
    CU_ASSERT (watch_tree_root != NULL);
    CU_ASSERT ((node = apteryx_path_node (watch_tree_root, path)) != NULL);
    CU_ASSERT (strcmp (APTERYX_CHILD_VALUE (node, "state") ?: "x", "") == 0);
    CU_ASSERT (strcmp (APTERYX_CHILD_VALUE (node, "speed") ?: "x", "") == 0);
    CU_ASSERT (strcmp (APTERYX_CHILD_VALUE (node, "duplex") ?: "x", "") == 0);
    CU_ASSERT (apteryx_unwatch_tree (TEST_PATH"/interfaces/eth0/", test_watch_tree_callback));
    _watch_tree_cleanup ();
}

void
test_watch_tree_one_level ()
{
    const char *path = TEST_PATH"/entity/zones/private/state";
    GNode *node;

    CU_ASSERT (apteryx_set_string (path, NULL, "up"));
    CU_ASSERT (apteryx_watch_tree (TEST_PATH"/entity/zones/private/", test_watch_tree_callback));
    CU_ASSERT (apteryx_set_string (path, NULL, "down"));
    usleep (TEST_SLEEP_TIMEOUT);
    CU_ASSERT (_cb_count == 1);
    CU_ASSERT ((node = apteryx_path_node (watch_tree_root, path)) != NULL);
    CU_ASSERT (node && strcmp (APTERYX_VALUE (node) ?: "", "down") == 0);
    CU_ASSERT (apteryx_unwatch_tree (TEST_PATH"/entity/zones/private/", test_watch_tree_callback));
    CU_ASSERT (apteryx_set_string (path, NULL, NULL));
    _watch_tree_cleanup ();
}

void
test_watch_tree_one_level_multi ()
{
    const char *path = TEST_PATH"/interfaces/eth0";
    GNode *node;

    CU_ASSERT (apteryx_watch_tree (TEST_PATH"/interfaces/eth0/", test_watch_tree_callback));
    node = APTERYX_NODE (NULL, (gpointer) path);
    APTERYX_LEAF (node, "state", "up");
    APTERYX_LEAF (node, "speed", "1000");
    APTERYX_LEAF (node, "duplex", "full");
    CU_ASSERT (apteryx_set_tree (node));
    g_node_destroy (node);
    usleep (TEST_SLEEP_TIMEOUT);
    CU_ASSERT (_cb_count == 1);
    CU_ASSERT ((node = apteryx_path_node (watch_tree_root, path)) != NULL);
    CU_ASSERT (strcmp (APTERYX_CHILD_VALUE (node, "state") ?: "", "up") == 0);
    CU_ASSERT (strcmp (APTERYX_CHILD_VALUE (node, "speed") ?: "", "1000") == 0);
    CU_ASSERT (strcmp (APTERYX_CHILD_VALUE (node, "duplex") ?: "", "full") == 0);
    CU_ASSERT (apteryx_unwatch_tree (TEST_PATH"/interfaces/eth0/", test_watch_tree_callback));
    CU_ASSERT (apteryx_prune (path));
    _watch_tree_cleanup ();
}

void
test_watch_tree_one_level_miss ()
{
    _path = _value = NULL;
    const char *path = TEST_PATH"/entity/zones/private/state";

    CU_ASSERT (apteryx_set_string (path, NULL, "up"));
    CU_ASSERT (apteryx_watch_tree (TEST_PATH"/entity/zones/", test_watch_tree_callback));
    CU_ASSERT (apteryx_set_string (path, NULL, "down"));
    usleep (TEST_SLEEP_TIMEOUT);
    CU_ASSERT (watch_tree_root == NULL);
    CU_ASSERT (_cb_count == 0);
    CU_ASSERT (apteryx_unwatch_tree (TEST_PATH"/entity/zones/", test_watch_tree_callback));
    CU_ASSERT (apteryx_set_string (path, NULL, NULL));
    _watch_tree_cleanup ();
}

void
test_find_one_star ()
{
    GNode* root = NULL;

    root = APTERYX_NODE (NULL, TEST_PATH"/routing/ipv4/rib/1");
    APTERYX_LEAF (root, "proto", "static");
    APTERYX_LEAF (root, "ifname", "eth0");
    APTERYX_LEAF (root, "prefix", "10.0.0.0/8");
    CU_ASSERT(apteryx_set_tree(root));
    g_node_destroy (root);

    root = APTERYX_NODE (NULL, TEST_PATH"/routing/ipv4/rib/2");
    APTERYX_LEAF (root, "proto", "static");
    APTERYX_LEAF (root, "ifname", "eth1");
    APTERYX_LEAF (root, "prefix", "172.16.0.0/16");
    CU_ASSERT(apteryx_set_tree(root));
    g_node_destroy (root);

    GList *paths = apteryx_find (TEST_PATH"/routing/ipv4/rib/*/ifname", "eth0");
    CU_ASSERT (g_list_length (paths) == 1);
    g_list_free_full (paths, free);

    apteryx_prune (TEST_PATH);
}


void
test_find_two_star ()
{
    GNode* root = NULL;

    root = APTERYX_NODE (NULL, TEST_PATH"/routing/ipv4/rib/1");
    APTERYX_LEAF (root, "proto", "static");
    APTERYX_LEAF (root, "ifname", "eth0");
    APTERYX_LEAF (root, "prefix", "10.0.0.0/8");
    CU_ASSERT (apteryx_set_tree (root));
    g_node_destroy (root);

    root = APTERYX_NODE (NULL, TEST_PATH"/routing/ipv4/rib/2");
    APTERYX_LEAF (root, "proto", "static");
    APTERYX_LEAF (root, "ifname", "eth1");
    APTERYX_LEAF (root, "prefix", "172.16.0.0/16");
    CU_ASSERT (apteryx_set_tree (root));
    g_node_destroy (root);

    root = APTERYX_NODE (NULL, TEST_PATH"/routing/ipv6/rib/1");
    APTERYX_LEAF (root, "proto", "static");
    APTERYX_LEAF (root, "ifname", "eth0");
    APTERYX_LEAF (root, "prefix", "fc00:1::/64");
    CU_ASSERT (apteryx_set_tree (root));
    g_node_destroy (root);

    root = APTERYX_NODE (NULL, TEST_PATH"/routing/ipv6/rib/2");
    APTERYX_LEAF (root, "proto", "static");
    APTERYX_LEAF (root, "ifname", "eth1");
    APTERYX_LEAF (root, "prefix", "fc00:2::/64");
    CU_ASSERT (apteryx_set_tree (root));
    g_node_destroy (root);

    GList *paths = apteryx_find (TEST_PATH"/routing/*/rib/*/ifname", "eth1");
    CU_ASSERT (g_list_length (paths) == 2);
    g_list_free_full (paths, free);

    apteryx_prune(TEST_PATH);
}

void
test_find_tree_one_star()
{
    GNode* root = NULL;

    root = APTERYX_NODE (NULL, TEST_PATH"/routing/ipv4/rib/1");
    APTERYX_LEAF (root, "proto", "static");
    APTERYX_LEAF (root, "ifname", "eth0");
    APTERYX_LEAF (root, "prefix", "10.0.0.0/8");
    CU_ASSERT (apteryx_set_tree (root));
    g_node_destroy (root);

    root = APTERYX_NODE (NULL, TEST_PATH"/routing/ipv4/rib/2");
    APTERYX_LEAF (root, "proto", "static");
    APTERYX_LEAF (root, "ifname", "eth1");
    APTERYX_LEAF (root, "prefix", "172.16.0.0/16");
    CU_ASSERT (apteryx_set_tree (root));
    g_node_destroy (root);

    root = APTERYX_NODE (NULL, TEST_PATH"/routing/ipv4/rib/*");
    APTERYX_LEAF (root, "proto", "static");
    APTERYX_LEAF (root, "ifname", "eth1");

    GList *paths = apteryx_find_tree (root);
    CU_ASSERT (g_list_length (paths) == 1);
    g_list_free_full (paths, free);
    g_node_destroy (root);

    apteryx_prune (TEST_PATH);
}

void
test_find_empty ()
{
    GNode* root = APTERYX_NODE (NULL, "/");
    CU_ASSERT (apteryx_find_tree (root) == NULL);
    g_node_destroy (root);
}

void
test_find_tree_two_star()
{
    GNode* root = NULL;

    root = APTERYX_NODE (NULL, TEST_PATH"/routing/ipv4/rib/1");
    APTERYX_LEAF (root, "proto", "static");
    APTERYX_LEAF (root, "ifname", "eth0");
    APTERYX_LEAF (root, "prefix", "10.0.0.0/8");
    CU_ASSERT (apteryx_set_tree (root));
    g_node_destroy (root);

    root = APTERYX_NODE (NULL, TEST_PATH"/routing/ipv4/rib/2");
    APTERYX_LEAF (root, "proto", "static");
    APTERYX_LEAF (root, "ifname", "eth1");
    APTERYX_LEAF (root, "prefix", "172.16.0.0/16");
    CU_ASSERT (apteryx_set_tree (root));
    g_node_destroy (root);

    root = APTERYX_NODE (NULL, TEST_PATH"/routing/ipv6/rib/1");
    APTERYX_LEAF (root, "proto", "static");
    APTERYX_LEAF (root, "ifname", "eth0");
    APTERYX_LEAF (root, "prefix", "fc00:1::/64");
    CU_ASSERT (apteryx_set_tree (root));
    g_node_destroy (root);

    root = APTERYX_NODE (NULL, TEST_PATH"/routing/ipv6/rib/2");
    APTERYX_LEAF (root, "proto", "static");
    APTERYX_LEAF (root, "ifname", "eth1");
    APTERYX_LEAF (root, "prefix", "fc00:2::/64");
    CU_ASSERT (apteryx_set_tree (root));
    g_node_destroy (root);

    root = APTERYX_NODE (NULL, TEST_PATH"/routing/*/rib/*");
    APTERYX_LEAF (root, "proto", "static");
    APTERYX_LEAF (root, "ifname", "eth1");

    GList *paths = apteryx_find_tree (root);
    CU_ASSERT (g_list_length (paths) == 2);
    g_list_free_full (paths, free);
    g_node_destroy (root);

    apteryx_prune (TEST_PATH);
}


void
test_find_tree_null_values()
{
    GNode* root = NULL;
    GList *paths = NULL;

    root = APTERYX_NODE (NULL, TEST_PATH"/routing/ipv4/rib/0");
    APTERYX_LEAF (root, "proto", "static");
    APTERYX_LEAF (root, "prefix", "10.0.0.0/8");
    CU_ASSERT (apteryx_set_tree (root));
    g_node_destroy (root);

    root = APTERYX_NODE (NULL, TEST_PATH"/routing/ipv4/rib/1");
    APTERYX_LEAF (root, "proto", "static");
    APTERYX_LEAF (root, "ifname", "");
    APTERYX_LEAF (root, "prefix", "10.0.0.0/8");
    CU_ASSERT (apteryx_set_tree (root));
    g_node_destroy (root);

    root = APTERYX_NODE (NULL, TEST_PATH"/routing/ipv4/rib/2");
    APTERYX_LEAF (root, "proto", "static");
    APTERYX_LEAF (root, "ifname", "eth1");
    APTERYX_LEAF (root, "prefix", "10.0.0.0/8");
    CU_ASSERT (apteryx_set_tree (root));
    g_node_destroy (root);

    root = APTERYX_NODE (NULL, TEST_PATH"/routing/ipv4/rib/3");
    APTERYX_LEAF (root, "proto", "static");
    APTERYX_LEAF (root, "ifname", "eth10");
    APTERYX_LEAF (root, "prefix", "10.0.0.0/8");
    CU_ASSERT (apteryx_set_tree (root));
    g_node_destroy (root);

    /* Find the entry with a NULL ifname */
    root = APTERYX_NODE (NULL, TEST_PATH"/routing/*/rib/*");
    APTERYX_LEAF (root, "proto", "static");
    APTERYX_LEAF (root, "ifname", "");
    paths = apteryx_find_tree (root);
    CU_ASSERT (g_list_length (paths) == 2);
    g_list_free_full (paths, free);
    g_node_destroy (root);

    /* Find the entry the eth1 entry (miss eth10) */
    root = APTERYX_NODE (NULL, TEST_PATH"/routing/*/rib/*");
    APTERYX_LEAF (root, "proto", "static");
    APTERYX_LEAF (root, "ifname", "eth1");
    paths = apteryx_find_tree (root);
    CU_ASSERT (g_list_length (paths) == 1);
    g_list_free_full (paths, free);
    g_node_destroy (root);

    /* No entries exist with bpg as proto */
    root = APTERYX_NODE (NULL, TEST_PATH"/routing/*/rib/*");
    APTERYX_LEAF (root, "proto", "bgp");
    paths = apteryx_find_tree (root);
    CU_ASSERT (g_list_length (paths) == 0);
    g_list_free_full (paths, free);
    g_node_destroy (root);

    apteryx_prune (TEST_PATH);
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

    CU_ASSERT (apteryx_index (TEST_PATH"/counters/", test_index_cb));
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
    CU_ASSERT (apteryx_unindex (TEST_PATH"/counters/", test_index_cb));
    CU_ASSERT (assert_apteryx_empty ());
}


static char*
test_provide_callback_counters(const char *path)
{
    if (strstr(path, "rx/pkts"))
        return strdup ("100");
    if (strstr(path, "rx/bytes"))
        return strdup ("1000");
    if (strstr(path, "tx/pkts"))
        return strdup ("1000");
    if (strstr(path, "tx/bytes"))
        return strdup ("100");
    return strdup("");
}

void
test_get_tree_indexed_provided_wildcards ()
{
    GNode *root, *node, *child;

    CU_ASSERT (apteryx_index (TEST_PATH"/counters/", test_index_cb));
    CU_ASSERT (apteryx_provide (TEST_PATH"/counters/*/pkts", test_provide_callback_counters));
    CU_ASSERT (apteryx_provide (TEST_PATH"/counters/*/bytes", test_provide_callback_counters));

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

    CU_ASSERT (apteryx_unprovide (TEST_PATH"/counters/*/pkts", test_provide_callback_counters));
    CU_ASSERT (apteryx_unprovide (TEST_PATH"/counters/*/bytes", test_provide_callback_counters));
    CU_ASSERT (apteryx_unindex (TEST_PATH"/counters/", test_index_cb));
    CU_ASSERT (assert_apteryx_empty ());
}

static GList *
test_stack_index_cb(const char *path)
{
    GList *stack_members = NULL;
    stack_members = g_list_prepend(stack_members, g_strdup_printf("%sstack1", path));
    stack_members = g_list_prepend(stack_members, g_strdup_printf("%sstack2", path));
    stack_members = g_list_prepend(stack_members, g_strdup_printf("%sstack3", path));
    stack_members = g_list_prepend(stack_members, g_strdup_printf("%sstack4", path));
    return stack_members;
}

static GList *
test_stack_interfaces_index_cb(const char *path)
{
    GList *interfaces = NULL;
    interfaces = g_list_prepend(interfaces, g_strdup_printf("%seth0", path));
    interfaces = g_list_prepend(interfaces, g_strdup_printf("%seth1", path));
    interfaces = g_list_prepend(interfaces, g_strdup_printf("%seth2", path));
    interfaces = g_list_prepend(interfaces, g_strdup_printf("%seth3", path));
    return interfaces;
}

static gchar *
test_provide_callback_stack_interface_ifname(const char *path)
{
    const char *key[] = {"eth0", "eth1", "eth2", "eth3"};
    for (int i = 0; i < 4; i++)
        if (strstr(path, key[i]))
            return strdup(key[i]);
    return NULL;
}

static gchar *
test_provide_callback_stack_interface_flags(const char *path)
{
    return strdup("0");
}

void
test_get_tree_indexed_provided_two_levels ()
{
    GNode *root;

    /* This should fill in /test/stack/ */
    CU_ASSERT (apteryx_index (TEST_PATH"/stack/", test_stack_index_cb));
    /* The above callback should get us past this star into calling indexer for
     * /test/stack/stack[1|2|3|4]/interfaces/blarg
     */
    CU_ASSERT (apteryx_index (TEST_PATH"/stack/*/interfaces/", test_stack_interfaces_index_cb));
    /* The above callback should fill in /test/stack/stack[1|2|3|4]/interfaces/eth[0|1|2|3]
     * and get us all the way down to these ifname / flags callbacks
     */
    CU_ASSERT (apteryx_provide (TEST_PATH"/stack/*/*/*/ifname", test_provide_callback_stack_interface_ifname));
    CU_ASSERT (apteryx_provide (TEST_PATH"/stack/*/*/*/flags", test_provide_callback_stack_interface_flags));

    root = apteryx_get_tree (TEST_PATH"/stack");
    CU_ASSERT (root && g_node_n_nodes (root, G_TRAVERSE_LEAFS) == 32);
    if (root)
        apteryx_free_tree (root);

    CU_ASSERT (apteryx_unindex (TEST_PATH"/stack/", test_stack_index_cb));
    CU_ASSERT (apteryx_unindex (TEST_PATH"/stack/*/interfaces/", test_stack_interfaces_index_cb));
    CU_ASSERT (apteryx_unprovide (TEST_PATH"/stack/*/*/*/ifname", test_provide_callback_stack_interface_ifname));
    CU_ASSERT (apteryx_unprovide (TEST_PATH"/stack/*/*/*/flags", test_provide_callback_stack_interface_flags));
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
    GNode *root, *node;
    uint64_t start, time, start2, time2;
    int count = 5000;
    int i;
    bool res;

    time = time2 = 0;
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

    /* Do the same test, but with an exploded root path */
    root = APTERYX_NODE (NULL, strdup (TEST_PATH));
    node = APTERYX_NODE (root, strdup ("interfaces"));
    node = APTERYX_NODE (node, strdup ("eth0"));
    for (i=0; i<count; i++)
    {
        sprintf (value, "value%d", i);
        APTERYX_LEAF (node, strdup (value), strdup (value));
    }
    start2 = get_time_us ();
    CU_ASSERT ((res = apteryx_set_tree (root)));
    if (!res)
        goto exit2;
    time2 = (get_time_us () - start2);
    printf ("%"PRIu64"us(%"PRIu64"us) ... ", time2, time2/count);

    /* These two sets really ought to be within 5% of each other,
     * but there's a lot of variablity. I'll leave both runs here
     * so we can inspect the output, but I don't want them failing.
     */
    // CU_ASSERT (abs(time - time2) / (time * 1.0) < 0.05);

exit2:
    apteryx_free_tree (root);
    CU_ASSERT (apteryx_prune (path));

    CU_ASSERT (assert_apteryx_empty ());
}


void
test_perf_set_tree_50000 ()
{
    const char *path = TEST_PATH"/interfaces/eth0";
    char value[32];
    GNode *root, *node;
    uint64_t start, time;
    int count = 50000;
    int i;
    bool res;

    root = APTERYX_NODE (NULL, strdup (TEST_PATH));
    node = APTERYX_NODE (root, strdup ("interfaces"));
    node = APTERYX_NODE (node, strdup ("eth0"));
    for (i=0; i<count; i++)
    {
        sprintf (value, "value%d", i);
        APTERYX_LEAF (node, strdup (value), strdup (value));
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
test_perf_set_tree_real ()
{
    const char *path = TEST_PATH"/interfaces";
    GNode *root, *node1, *node2;
    uint64_t start, time;
    int i, j, k;
    bool res;

    root = APTERYX_NODE (NULL, strdup (path));
    for (i = 0; i < 250; i++)
    {
        node1 = APTERYX_NODE (root, g_strdup_printf ("eth%d", i));
        node1 = APTERYX_NODE (node1, g_strdup_printf ("statistics"));
        for (j = 0; j < 50; j++)
        {
            node2 = APTERYX_NODE (node1, g_strdup_printf ("statistic%d", j));
            for (k = 0; k < 4; k++)
            {
                APTERYX_LEAF (node2, g_strdup_printf ("counter%d", k), g_strdup_printf ("%d", i*j*k));
            }
        }
    }

    start = get_time_us ();
    CU_ASSERT ((res = apteryx_set_tree (root)));
    if (!res)
        goto exit;
    time = (get_time_us () - start);
    printf ("%"PRIu64"us ... ", time);
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
        CU_ASSERT ((root = apteryx_get_tree (path)) != NULL);
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
    CU_ASSERT ((root = apteryx_get_tree (path)) != NULL)
    if (!root)
        goto exit;
    time = (get_time_us () - start);
    printf ("%"PRIu64"us ... ", time);
    apteryx_free_tree (root);
exit:
    CU_ASSERT (apteryx_prune (path));
    CU_ASSERT (assert_apteryx_empty ());
}

/* This test is an attempt to reproduce the performance of a
 * moderately large tree with realistic branch layouts.
 */
void
test_perf_get_tree_real ()
{
    const char *path = TEST_PATH"/interfaces";
    GNode *root, *node1, *node2;
    uint64_t start, time;
    int i, j, k;
    bool res;

    root = APTERYX_NODE (NULL, strdup (path));
    for (i = 0; i < 250; i++)
    {
        node1 = APTERYX_NODE (root, g_strdup_printf ("eth%d", i));
        node1 = APTERYX_NODE (node1, g_strdup_printf ("statistics"));
        for (j = 0; j < 50; j++)
        {
            node2 = APTERYX_NODE (node1, g_strdup_printf ("statistic%d", j));
            for (k = 0; k < 4; k++)
            {
                APTERYX_LEAF (node2, g_strdup_printf ("counter%d", k), g_strdup_printf ("%d", i*j*k));
            }
        }
    }
    CU_ASSERT ((res = apteryx_set_tree (root)));
    if (!res)
        goto exit;
    apteryx_free_tree (root);

    start = get_time_us ();
    CU_ASSERT ((root = apteryx_get_tree (path)) != NULL);
    if (!root)
        goto exit;
    apteryx_free_tree (root);
    time = (get_time_us () - start);
    printf ("%"PRIu64"us ... ", time);

exit:
    CU_ASSERT (apteryx_prune (path));
    CU_ASSERT (assert_apteryx_empty ());
}

void
test_perf_get_tree_n (int n)
{
     const char *path = TEST_PATH"/interfaces/eth0";
    char value[32];
    GNode* root;
    uint64_t start, time;
    int count = n/5;
    int i;

    for (i=0; i<count; i++)
    {
        for (int j =0; j < 5; j++)
        {
            sprintf (value, "node%d/value%d", i,j);
            CU_ASSERT (apteryx_set_string (path, value, value));
        }
    }
    start = get_time_us ();
    CU_ASSERT ((root = apteryx_get_tree (path)) != NULL)
    if (!root)
        goto exit;
    time = (get_time_us () - start);
    printf ("%"PRIu64"us(%"PRIu64"us) ... ", time, time/(n));
    apteryx_free_tree (root);
exit:
    CU_ASSERT (apteryx_prune (path));
    CU_ASSERT (assert_apteryx_empty ());
}

void
test_perf_get_tree_10000 ()
{
    test_perf_get_tree_n(10000);
}
void
test_perf_get_tree_20000 ()
{
    test_perf_get_tree_n(20000);
}
void
test_perf_get_tree_30000 ()
{
    test_perf_get_tree_n(30000);
}
void
test_perf_get_tree_40000 ()
{
    test_perf_get_tree_n(40000);
}
void
test_perf_get_tree_50000 ()
{
    test_perf_get_tree_n(50000);
}
void
test_perf_get_tree_60000 ()
{
    test_perf_get_tree_n(60000);
}
void
test_perf_get_tree_70000 ()
{
    test_perf_get_tree_n(70000);
}
void
test_perf_get_tree_80000 ()
{
    test_perf_get_tree_n(80000);
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
test_perf_prune ()
{
    const char *path = TEST_PATH"/neighbour/";
    uint64_t start, time;
    int count = 10000;
    int i;

    for (i=0; i<count; i++)
    {
        char p2[128];
        sprintf (p2, "%svalue%d", path,i);
        CU_ASSERT (apteryx_set_int (p2, "data_point_1", 1));
        CU_ASSERT (apteryx_set_int (p2, "data_point_2", 1));
    }
    start = get_time_us ();
    CU_ASSERT (apteryx_prune(TEST_PATH));
    time = (get_time_us () - start);
    printf ("%"PRIu64"us(%"PRIu64"us) ... ", time, time/count);

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
test_proxy_tree_get ()
{
    const char *value = NULL;
    GNode *root = NULL;

    CU_ASSERT (apteryx_set (TEST_PATH"/local/foo/menu1", "spam"));
    CU_ASSERT (apteryx_set (TEST_PATH"/local/foo/menu2", "eggsandspam"));
    CU_ASSERT (apteryx_set (TEST_PATH"/local/bar/menu3", "eggspamspamandeggs"))
    CU_ASSERT (apteryx_set (TEST_PATH"/local/bar/menu4", "spamspameggsspamspamspameggsandspam"));
    CU_ASSERT (apteryx_bind (TEST_TCP_URL));
    CU_ASSERT (apteryx_proxy (TEST_PATH"/remote/*", TEST_TCP_URL));

    /* Get menu item 1 via proxy */
    CU_ASSERT ((value = apteryx_get (TEST_PATH"/remote"TEST_PATH"/local/foo/menu1")) != NULL);
    CU_ASSERT (value && strcmp (value, "spam") == 0);
    if (value)
        free ((void *) value);

    /* Test local tree */
    root = apteryx_get_tree (TEST_PATH"/local");
    CU_ASSERT (root && APTERYX_NUM_NODES (root) == 7);
    if (root)
        apteryx_free_tree (root);

    /* Test same tree via proxy */
    root = apteryx_get_tree (TEST_PATH"/remote"TEST_PATH"/local");
    CU_ASSERT (root && APTERYX_NUM_NODES (root) == 7);
    if (root)
        apteryx_free_tree (root);
    else
        printf("No tree in result\n");

    CU_ASSERT (apteryx_unproxy (TEST_PATH"/remote/*", TEST_TCP_URL));
    CU_ASSERT (apteryx_unbind (TEST_TCP_URL));
    CU_ASSERT (apteryx_prune (TEST_PATH"/local"));
    CU_ASSERT (assert_apteryx_empty ());

    apteryx_debug = false;
}

void
test_proxy_tree_query ()
{
    GNode *query = NULL;
    GNode *root = NULL;

    /* Query should ignore non-leaf values */
    CU_ASSERT (apteryx_set (TEST_PATH"/local/foo", "dog"));
    CU_ASSERT (apteryx_set (TEST_PATH"/local/foo/menu1", "spam"));
    CU_ASSERT (apteryx_set (TEST_PATH"/local/foo/menu2", "eggsandspam"));
    CU_ASSERT (apteryx_set (TEST_PATH"/local/bar/menu3", "eggspamspamandeggs"))
    CU_ASSERT (apteryx_set (TEST_PATH"/local/bar/menu4", "spamspameggsspamspamspameggsandspam"));
    CU_ASSERT (apteryx_set (TEST_PATH"/local/foo/menu5/part1", "part1"));
    CU_ASSERT (apteryx_set (TEST_PATH"/local/foo/menu5/part2", "part2"));
    CU_ASSERT (apteryx_bind (TEST_TCP_URL));
    CU_ASSERT (apteryx_proxy (TEST_PATH"/remote/*", TEST_TCP_URL));

    /* Test local tree */
    query = g_node_new (strdup (TEST_PATH"/local/*"));
    root = apteryx_query (query);
    CU_ASSERT (root && g_node_n_nodes (root, G_TRAVERSE_NON_LEAVES) == 10);
    CU_ASSERT (root && g_node_n_nodes (root, G_TRAVERSE_LEAFS) == 6);
    apteryx_free_tree (root);
    apteryx_free_tree (query);

    /* Test same tree via proxy */
    query = g_node_new (strdup (TEST_PATH"/remote"TEST_PATH"/local/*"));
    root = apteryx_query (query);
    CU_ASSERT (root && strcmp (root->data, TEST_PATH"/remote"TEST_PATH"/local") == 0);
    CU_ASSERT (root && g_node_n_nodes (root, G_TRAVERSE_NON_LEAVES) == 10);
    CU_ASSERT (root && g_node_n_nodes (root, G_TRAVERSE_LEAFS) == 6);
    apteryx_free_tree (root);
    apteryx_free_tree (query);

    /* Query tree */
    query = g_node_new (strdup ("/"));
    apteryx_path_to_node (query, TEST_PATH"/remote"TEST_PATH"/local/*", NULL);
    root = apteryx_query (query);
    CU_ASSERT (root && strcmp (root->data, "/") == 0);
    CU_ASSERT (root && g_node_n_nodes (root, G_TRAVERSE_NON_LEAVES) == 14);
    CU_ASSERT (root && g_node_n_nodes (root, G_TRAVERSE_LEAFS) == 6);
    apteryx_free_tree (root);
    apteryx_free_tree (query);

    /* Sub-tree */
    query = g_node_new (strdup (TEST_PATH"/remote"TEST_PATH"/local/foo/*"));
    root = apteryx_query (query);
    CU_ASSERT (root && strcmp (root->data, TEST_PATH"/remote"TEST_PATH"/local/foo") == 0);
    CU_ASSERT (root && g_node_n_nodes (root, G_TRAVERSE_NON_LEAVES) == 6);
    CU_ASSERT (root && g_node_n_nodes (root, G_TRAVERSE_LEAFS) == 4);
    apteryx_free_tree (root);
    apteryx_free_tree (query);

    /* Sub-tree - one level */
    query = g_node_new (strdup (TEST_PATH"/remote"TEST_PATH"/local/foo/"));
    root = apteryx_query (query);
    CU_ASSERT (root && strcmp (root->data, TEST_PATH"/remote"TEST_PATH"/local/foo") == 0);
    CU_ASSERT (root && g_node_n_nodes (root, G_TRAVERSE_NON_LEAVES) == 3);
    CU_ASSERT (root && g_node_n_nodes (root, G_TRAVERSE_LEAFS) == 2);
    apteryx_free_tree (root);
    apteryx_free_tree (query);

    /* Non-leaf value */
    query = g_node_new (strdup (TEST_PATH"/remote"TEST_PATH"/local/foo"));
    root = apteryx_query (query);
    CU_ASSERT (root && strcmp (root->data, TEST_PATH"/remote"TEST_PATH"/local/foo") == 0);
    CU_ASSERT (root && g_node_n_nodes (root, G_TRAVERSE_NON_LEAVES) == 1);
    CU_ASSERT (root && g_node_n_nodes (root, G_TRAVERSE_LEAFS) == 1);
    CU_ASSERT (root && strcmp (g_node_first_child (root)->data, "dog") == 0);
    apteryx_free_tree (root);
    apteryx_free_tree (query);

    /* Miss */
    query = g_node_new (strdup (TEST_PATH"/remote"TEST_PATH"/local/cat"));
    root = apteryx_query (query);
    CU_ASSERT (root == NULL);
    apteryx_free_tree (query);

    /* End node */
    query = g_node_new (strdup (TEST_PATH"/remote"TEST_PATH"/local/foo/menu1"));
    root = apteryx_query (query);
    CU_ASSERT (root && strcmp (root->data, TEST_PATH"/remote"TEST_PATH"/local/foo/menu1") == 0);
    CU_ASSERT (root && g_node_n_nodes (root, G_TRAVERSE_NON_LEAVES) == 1);
    CU_ASSERT (root && g_node_n_nodes (root, G_TRAVERSE_LEAFS) == 1);
    apteryx_free_tree (root);
    apteryx_free_tree (query);

    CU_ASSERT (apteryx_unproxy (TEST_PATH"/remote/*", TEST_TCP_URL));
    CU_ASSERT (apteryx_unbind (TEST_TCP_URL));
    CU_ASSERT (apteryx_prune (TEST_PATH"/local"));
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
    CU_ASSERT (apteryx_prune (TEST_PATH));
    CU_ASSERT (assert_apteryx_empty ());
}

void
test_proxy_not_listening ()
{
    CU_ASSERT (apteryx_set (TEST_PATH"/local", "test"));
    CU_ASSERT (apteryx_proxy (TEST_PATH"/remote/*", TEST_TCP_URL));
    CU_ASSERT (apteryx_get (TEST_PATH"/remote/test/local") == NULL);
    CU_ASSERT (apteryx_unproxy (TEST_PATH"/remote/*", TEST_TCP_URL));
    CU_ASSERT (apteryx_prune (TEST_PATH));
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
    CU_ASSERT (apteryx_prune (TEST_PATH));
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
    CU_ASSERT (apteryx_prune (TEST_PATH));
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
    CU_ASSERT (apteryx_prune (TEST_PATH));
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
    CU_ASSERT (apteryx_prune (TEST_PATH));
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

void
test_proxy_cas ()
{
    const char *path = TEST_PATH"/remote/test/local";
    char *value = NULL;
    uint64_t ts;

    CU_ASSERT (apteryx_bind (TEST_TCP_URL));
    CU_ASSERT (apteryx_proxy (TEST_PATH"/remote/*", TEST_TCP_URL));

    value = g_strdup_printf ("%d", 1);
    CU_ASSERT (apteryx_cas (path, value, 0));
    CU_ASSERT (!apteryx_cas (path, value, 0));
    CU_ASSERT (errno == -EBUSY);
    CU_ASSERT ((ts = apteryx_timestamp (path)) != 0);
    CU_ASSERT (apteryx_cas (path, value, ts));
    CU_ASSERT (!apteryx_cas (path, value, ts));
    CU_ASSERT (errno == -EBUSY);
    g_free (value);

    CU_ASSERT (apteryx_set (path, NULL));
    CU_ASSERT (apteryx_unproxy (TEST_PATH"/remote/*", TEST_TCP_URL));
    CU_ASSERT (apteryx_unbind (TEST_TCP_URL));
    CU_ASSERT (assert_apteryx_empty ());
}

void
test_timestamp ()
{
    const char *path = TEST_PATH"/timestamp";
    uint64_t ts;

    CU_ASSERT (apteryx_set_int (path, "value", 10));
    CU_ASSERT (apteryx_set_int (path, "value2", 11));
    ts = apteryx_timestamp (path);
    CU_ASSERT (ts != 0);
    CU_ASSERT (apteryx_prune (TEST_PATH"/timestamp/value"));
    CU_ASSERT (ts != apteryx_timestamp (path));
    CU_ASSERT (apteryx_prune (TEST_PATH));
}

void
test_timestamp_refreshed ()
{
    const char *path = TEST_PATH"/timestamp/refreshed";
    uint64_t ts, ts1;
    char *value;

    _cb_timeout = 1000000;
    apteryx_refresh(path, test_refresh_callback);

    ts = apteryx_timestamp (path);
    CU_ASSERT (ts != 0);

    value = apteryx_get(path);
    ts1 = apteryx_timestamp (path);

    CU_ASSERT(ts1 != 0);
    CU_ASSERT(ts != ts1);

    ts = apteryx_timestamp (path);
    CU_ASSERT(ts == ts1);

    free (value);
    apteryx_unrefresh(path, test_refresh_callback);
    apteryx_prune(path);
    _cb_count = 0;
}

static char*
test_provide_timestamp (const char *path)
{
    return strdup ("timestamp");
}

void
test_timestamp_provider ()
{
    const char *path = TEST_PATH"/timestamp";
    uint64_t ts;

    CU_ASSERT (apteryx_provide (path, test_provide_timestamp));
    ts = apteryx_timestamp (path);
    CU_ASSERT(ts != 0);

    apteryx_prune(path);
    apteryx_unprovide (path, test_provide_timestamp);
    CU_ASSERT (assert_apteryx_empty ());
}

void
test_memuse ()
{
    const char *path = TEST_PATH"/memuse";
    uint64_t memuse;

    CU_ASSERT (apteryx_memuse (path) == 0);
    CU_ASSERT (apteryx_set_int (path, "value", 10));
    CU_ASSERT (apteryx_set_int (path, "value2", 11));
    CU_ASSERT ((memuse = apteryx_memuse (path)) != 0);
    CU_ASSERT (apteryx_prune (TEST_PATH"/memuse/value"));
    CU_ASSERT (apteryx_memuse (path) != 0);
    CU_ASSERT (apteryx_memuse (path) < memuse);
    CU_ASSERT (apteryx_prune (TEST_PATH));
}

void
test_path_to_node ()
{
    char *path;
    GNode *root;
    GNode *node;

    path = TEST_PATH"/path/to/node";
    root = APTERYX_NODE (NULL, strdup (path));
    node = apteryx_path_to_node (root, path, "test");
    CU_ASSERT (root != NULL);
    CU_ASSERT (node != NULL);
    CU_ASSERT (node && g_strcmp0(node->data, "test") == 0);
    apteryx_free_tree (root);

    /* Multiple roots */
    root = g_node_new (strdup ("/"));
    apteryx_path_to_node (root, "/system/time/01:23:45", NULL);
    apteryx_path_to_node (root, "/boot/time", "12:23:45");
    CU_ASSERT (root && strcmp(APTERYX_NAME(root), "/") == 0);
    CU_ASSERT (root->next == NULL);
    CU_ASSERT (g_node_n_children (root) == 2);
    apteryx_free_tree (root);

    root = APTERYX_NODE (NULL, strdup ("/system"));
    apteryx_path_to_node (root, "/system/system-name", "awplus");
    node = root->children;
    CU_ASSERT (node && strcmp(APTERYX_NAME(node), "system-name") == 0);
    apteryx_free_tree (root);

    root = APTERYX_NODE (NULL, strdup ("/"));
    apteryx_path_to_node (root, "/system/system-name", "awplus");
    node = root->children;
    path = apteryx_node_path(node);
    CU_ASSERT (path && strcmp (path, "/system") == 0);
    g_free (path);
    CU_ASSERT (node && strcmp(APTERYX_NAME(node), "system") == 0);
    node = node->children;
    path = apteryx_node_path(node);
    CU_ASSERT (path && strcmp (path, "/system/system-name") == 0);
    g_free (path);
    CU_ASSERT (node && strcmp(APTERYX_NAME(node), "system-name") == 0);
    node = node->children;
    CU_ASSERT (node && strcmp(APTERYX_NAME(node), "awplus") == 0);
    apteryx_free_tree (root);

    root = APTERYX_NODE (NULL, strdup ("/system"));
    apteryx_path_to_node (root, "/system/system-name", "awplus");
    node = root->children;
    path = apteryx_node_path(node);
    CU_ASSERT (path && strcmp (path, "/system/system-name") == 0);
    g_free (path);
    CU_ASSERT (node && strcmp(APTERYX_NAME(node), "system-name") == 0);
    node = node->children;
    CU_ASSERT (node && strcmp(APTERYX_NAME(node), "awplus") == 0);
    apteryx_free_tree (root);
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
    usleep (1000);
    apteryx_shutdown ();
    apteryx_init (false);

    usleep (5 * 1000 * 1000);
    for (i = 0; i < 1000; i++)
    {
        char *path = NULL;
        CU_ASSERT (asprintf (&path, TEST_PATH"/zones/private/state/%d", i) > 0);
        CU_ASSERT (apteryx_unwatch (path, test_deadlock_callback));
        free (path);
    }
    CU_ASSERT (apteryx_prune (TEST_PATH));
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

    usleep (5 * 1000 * 1000);
    for (i = 0; i < 1000; i++)
    {
        char *path = NULL;
        CU_ASSERT (asprintf (&path, TEST_PATH"/zones/private/state/%d", i) > 0);
        apteryx_unwatch (path, test_deadlock2_callback);
        apteryx_unwatch (path, test_deadlock_callback);
        free (path);
    }
    CU_ASSERT (apteryx_prune (TEST_PATH));
    usleep (TEST_SLEEP_TIMEOUT);
    CU_ASSERT (assert_apteryx_empty ());
}

void
test_double_fork ()
{
    const char *path = TEST_PATH"/entity/zones/private/age";
    int status;
    int pid;

    CU_ASSERT (apteryx_set_int (path, NULL, 1));
    if ((pid = fork ()) == 0)
    {
        /* Child */
        apteryx_set_int (path, NULL, apteryx_get_int (path, NULL) + 1);
        if ((pid = fork ()) == 0)
        {
            /* Grandchild */
            apteryx_set_int (path, NULL, apteryx_get_int (path, NULL) + 1);
            exit (0);
        }
        waitpid (pid, &status, 0);
        exit (0);
    }
    waitpid (pid, &status, 0);
    CU_ASSERT (WEXITSTATUS (status) == 0);
    CU_ASSERT ((apteryx_get_int (path, NULL)) == 3);

    CU_ASSERT (apteryx_set (path, NULL));
    CU_ASSERT (assert_apteryx_empty ());
}

void
test_remote_path_colon ()
{
    char *path = TEST_TCP_URL":"TEST_PATH "/2001:db8::1/test";
    char *value = NULL;
    CU_ASSERT (apteryx_bind (TEST_TCP_URL));
    usleep (TEST_SLEEP_TIMEOUT);
    CU_ASSERT (apteryx_set (path, "hello"));
    CU_ASSERT ((value = apteryx_get (path)) != NULL && strcmp (value, "hello") == 0);
    free (value);
    CU_ASSERT (apteryx_set (path, NULL));
    CU_ASSERT (apteryx_unbind (TEST_TCP_URL));
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

    CU_ASSERT (system ("sudo sysctl -w net.ipv4.tcp_tw_recycle=1 > /dev/null 2>&1 || true") == 0);
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
    CU_ASSERT (system ("sudo sysctl -w net.ipv4.tcp_tw_recycle=0 > /dev/null 2>&1 || true") == 0);
    kill (pid, 9);
    waitpid (pid, &status, 0);
    if (family == AF_UNIX)
        unlink (TEST_RPC_PATH);
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

static bool
test_handler (rpc_message msg)
{
    APTERYX_MODE mode = rpc_msg_decode_uint8 (msg);
    CU_ASSERT (mode == MODE_TEST);
    char *ping = rpc_msg_decode_string (msg);
    char *pong = g_strdup (ping);
    rpc_msg_reset (msg);
    rpc_msg_encode_string (msg, pong);
    g_free (pong);
    return true;
}

void
test_rpc_init ()
{
    rpc_instance rpc;
    CU_ASSERT ((rpc = rpc_init (RPC_TIMEOUT_US, test_handler)) != NULL);
    rpc_shutdown (rpc);
}

void
test_rpc_bind ()
{
    char *url = APTERYX_SERVER".test";
    rpc_instance rpc;
    CU_ASSERT ((rpc = rpc_init (RPC_TIMEOUT_US, test_handler)) != NULL);
    CU_ASSERT (rpc_server_bind (rpc,  url, url));
    CU_ASSERT (rpc_server_release (rpc, url));
    rpc_shutdown (rpc);
}

void
test_rpc_connect ()
{
    char *url = APTERYX_SERVER".test";
    rpc_client rpc_client;
    rpc_instance rpc;

    CU_ASSERT ((rpc = rpc_init (RPC_TIMEOUT_US, test_handler)) != NULL);
    CU_ASSERT (rpc_server_bind (rpc,  url, url));
    CU_ASSERT ((rpc_client = rpc_client_connect (rpc, url)) != NULL);
    rpc_client_release (rpc, rpc_client, false);
    CU_ASSERT (rpc_server_release (rpc, url));
    rpc_shutdown (rpc);
}

void
test_rpc_ping ()
{
    rpc_message_t msg = {};
    char *test_string = "testing123...";
    char *url = APTERYX_SERVER".test";
    rpc_client rpc_client;
    rpc_instance rpc;
    char *value;

    CU_ASSERT ((rpc = rpc_init (RPC_TIMEOUT_US, test_handler)) != NULL);
    CU_ASSERT (rpc_server_bind (rpc,  url, url));
    CU_ASSERT ((rpc_client = rpc_client_connect (rpc, url)) != NULL);
    rpc_msg_encode_uint8 (&msg, MODE_TEST);
    rpc_msg_encode_string (&msg, test_string);
    CU_ASSERT (rpc_msg_send (rpc_client, &msg));
    value = rpc_msg_decode_string (&msg);
    CU_ASSERT (value && strcmp (value, test_string) == 0);
    rpc_msg_reset (&msg);
    rpc_client_release (rpc, rpc_client, false);
    CU_ASSERT (rpc_server_release (rpc, url));
    rpc_shutdown (rpc);
}

void
test_rpc_double_bind ()
{
    char *url = APTERYX_SERVER".test";
    rpc_instance rpc;
    CU_ASSERT ((rpc = rpc_init (RPC_TIMEOUT_US, test_handler)) != NULL);
    CU_ASSERT (rpc_server_bind (rpc,  url, url));
    CU_ASSERT (!rpc_server_bind (rpc,  url, url));
    CU_ASSERT (rpc_server_release (rpc, url));
    rpc_shutdown (rpc);
}

void
test_rpc_perf ()
{
    rpc_message_t msg = {};
    char *test_string = "testing123...";
    char *url = APTERYX_SERVER".test";
    rpc_client rpc_client;
    rpc_instance rpc;
    uint64_t start;
    char *value;
    int i;

    CU_ASSERT ((rpc = rpc_init (RPC_TIMEOUT_US, test_handler)) != NULL);
    CU_ASSERT (rpc_server_bind (rpc,  url, url));
    CU_ASSERT ((rpc_client = rpc_client_connect (rpc, url)) != NULL);

    start = get_time_us ();
    for (i = 0; i < TEST_ITERATIONS; i++)
    {
        rpc_msg_encode_uint8 (&msg, MODE_TEST);
        rpc_msg_encode_string (&msg, test_string);
        CU_ASSERT (rpc_msg_send (rpc_client, &msg));
        value = rpc_msg_decode_string (&msg);
        CU_ASSERT (value && strcmp (value, test_string) == 0);
        rpc_msg_reset (&msg);
        if (!value)
            goto exit;
    }
    printf ("%"PRIu64"us ... ", (get_time_us () - start) / TEST_ITERATIONS);
exit:
    rpc_client_release (rpc, rpc_client, false);
    rpc_shutdown (rpc);
}

static pthread_t single_thread = -1;
static int
_single_thread (void *data)
{
    int fd = 0;
    struct pollfd pfd;
    uint8_t dummy = 0;

    while (fd >= 0)
    {
        fd = apteryx_process (true);
        CU_ASSERT (fd >= 0);
        pfd.fd = fd;
        pfd.events = POLLIN;
        poll (&pfd, 1, 0);
        if (read (fd, &dummy, 1) == 0)
        {
            ERROR ("Poll/Read error: %s\n", strerror (errno));
        }
    }
    return 0;
}

static void
start_single_threading ()
{
    CU_ASSERT (pthread_create (&single_thread, NULL, (void *) &_single_thread, (void *) NULL) == 0);
}

static void
stop_single_threading ()
{
    pthread_cancel (single_thread);
    pthread_join (single_thread, NULL);
    CU_ASSERT (apteryx_process (false) == -1);
}

void
test_single_index()
{
    start_single_threading ();
    test_index ();
    stop_single_threading ();
}

void
test_single_index_no_polling ()
{
    char *path = TEST_PATH"/counters/";
    GList *paths = NULL;

    apteryx_process (true);
    CU_ASSERT (apteryx_index (path, test_index_cb));
    CU_ASSERT ((paths = apteryx_search (path)) == NULL);
    CU_ASSERT (apteryx_unindex (path, test_index_cb));
    CU_ASSERT (assert_apteryx_empty ());
    apteryx_process (false);
    usleep (1.1 * RPC_TIMEOUT_US);
}

void
test_single_watch ()
{
    start_single_threading ();
    test_watch ();
    stop_single_threading ();
}

void
test_single_watch_no_polling ()
{
    _path = _value = NULL;
    const char *path = TEST_PATH"/entity/zones/private/state";
    apteryx_process (true);
    CU_ASSERT (apteryx_set_string (path, NULL, "up"));
    CU_ASSERT (apteryx_watch (path, test_watch_callback));
    CU_ASSERT (apteryx_set_string (path, NULL, "down"));
    usleep (TEST_SLEEP_TIMEOUT);
    CU_ASSERT (_path == NULL);
    CU_ASSERT (_value  == NULL);
    CU_ASSERT (apteryx_unwatch (path, test_watch_callback));
    apteryx_set_string (path, NULL, NULL);
    _watch_cleanup ();
    apteryx_process (false);
    usleep (1.1 * RPC_TIMEOUT_US);
}

void
test_single_validate()
{
    start_single_threading ();
    test_validate ();
    stop_single_threading ();
}

void
test_single_validate_no_polling ()
{
    _path = _value = NULL;
    const char *path = TEST_PATH"/entity/zones/private/state";
    apteryx_process (true);
    CU_ASSERT (apteryx_validate (path, test_validate_callback));
    CU_ASSERT (!apteryx_set_string (path, NULL, "down"));
    CU_ASSERT (apteryx_validate (path, test_validate_refuse_callback));
    CU_ASSERT (!apteryx_set_string (path, NULL, "up"));
    usleep (TEST_SLEEP_TIMEOUT);
    CU_ASSERT (apteryx_unvalidate (path, test_validate_callback));
    CU_ASSERT (apteryx_unvalidate (path, test_validate_refuse_callback));
    apteryx_set_string (path, NULL, NULL);
    apteryx_process (false);
    usleep (1.1 * RPC_TIMEOUT_US);
}

void
test_single_provide()
{
    start_single_threading ();
    test_provide ();
    stop_single_threading ();
}

void
test_single_provide_no_polling ()
{
    const char *path = TEST_PATH"/interfaces/eth0/state";
    const char *value = NULL;
    apteryx_process (true);
    CU_ASSERT (apteryx_provide (path, test_provide_callback_up));
    CU_ASSERT ((value = apteryx_get (path)) == NULL);
    apteryx_unprovide (path, test_provide_callback_up);
    CU_ASSERT (assert_apteryx_empty ());
    apteryx_process (false);
    usleep (1.1 * RPC_TIMEOUT_US);
}

static bool
test_single_watch_myself_callback (const char *path, const char *value)
{
    watch_count++;
    return true;
}

void
test_single_watch_myself ()
{
    const char *path = TEST_PATH"/entity/zones/private/state";
    int count = 64;
    int i;

    apteryx_process (true);
    watch_count = 0;
    CU_ASSERT (apteryx_watch (path, test_single_watch_myself_callback));
    for (i = 0; i < count; i++)
    {
        CU_ASSERT (apteryx_set (path, "down"));
    }
    for (i = 0; i < count; i++)
    {
        apteryx_process (true);
    }
    usleep (TEST_SLEEP_TIMEOUT);
    CU_ASSERT (watch_count == count);
    CU_ASSERT (apteryx_unwatch (path, test_single_watch_myself_callback));
    CU_ASSERT (apteryx_set (path, NULL));
    CU_ASSERT (assert_apteryx_empty ());
    apteryx_process (false);
}

void
test_single_watch_myself_blocked ()
{
    const char *path = TEST_PATH"/entity/zones/private/state";
    int fd = apteryx_process (true);
    long pipe_size = (long)fcntl(fd, F_GETPIPE_SZ);
    int count = pipe_size + 50;
    char dummy;
    int i;

    watch_count = 0;
    CU_ASSERT (apteryx_watch (path, test_single_watch_myself_callback));
    for (i = 0; i < count; i++)
    {
        CU_ASSERT (apteryx_set (path, "down"));
    }
    usleep (TEST_SLEEP_TIMEOUT);
    CU_ASSERT (fcntl (fd, F_SETFL, fcntl (fd, F_GETFL, 0) | O_NONBLOCK) == 0);
    for (i = 0; i <= count; i++)
    {
        struct pollfd poll_fd = {
            .fd = fd,
            .events = POLLIN | POLLERR | POLLHUP,
        };
        if (i == count) {
            CU_ASSERT (poll (&poll_fd, 1, 1) == 0);
            CU_ASSERT (read (fd, &dummy, 1) < 0);
        }
        else {
            CU_ASSERT (poll (&poll_fd, 1, 1) == 1 && read (fd, &dummy, 1) == 1);
            apteryx_process (true);
        }
    }
    CU_ASSERT (watch_count == count);
    CU_ASSERT (apteryx_unwatch (path, test_single_watch_myself_callback));
    CU_ASSERT (apteryx_set (path, NULL));
    CU_ASSERT (assert_apteryx_empty ());
    apteryx_process (false);
}

#ifdef HAVE_LUA
static bool
_run_lua (char *script)
{
    char *buffer = strdup (script);
    lua_State *L;
    char *line;
    int res = -1;

    L = luaL_newstate ();
    luaL_openlibs (L);
    line = strtok (buffer, "\n");
    while (line != NULL)
    {
        res = luaL_loadstring (L, line);
        if (res == 0)
            res = lua_pcall (L, 0, 0, 0);
        if (res != 0)
            fprintf (stderr, "%s\n", lua_tostring(L, -1));
        CU_ASSERT (res == 0);
        line = strtok (NULL,"\n");
    }
    CU_ASSERT (lua_gettop (L) == 0);
    lua_close (L);
    free (buffer);
    return res == 0;
}

void
test_lua_load (void)
{
    CU_ASSERT (_run_lua ("apteryx = require('apteryx')"));
    CU_ASSERT (assert_apteryx_empty ());
}

void
test_lua_basic_set_get (void)
{
    CU_ASSERT (_run_lua (
        "apteryx = require('apteryx')                                 \n"
        "apteryx.set('"TEST_PATH"/debug', '1')                        \n"
        "assert(apteryx.get('"TEST_PATH"/debug') == '1')              \n"
        "apteryx.set('"TEST_PATH"/debug')                             \n"
        "assert(apteryx.get('"TEST_PATH"/debug') == nil)              \n"
    ));
    CU_ASSERT (assert_apteryx_empty ());
}

void
test_lua_basic_search (void)
{
    CU_ASSERT (_run_lua (
        "apteryx = require('apteryx')                                 \n"
        "apteryx.set('"TEST_PATH"/list/eth0/name', 'eth0')            \n"
        "apteryx.set('"TEST_PATH"/list/eth1/name', 'eth1')            \n"
        "assert(next(apteryx.search('"TEST_PATH"/list')) == nil)      \n"
        "paths = apteryx.search('"TEST_PATH"/list/')                  \n"
        "assert(#paths == 2)                                          \n"
        "apteryx.set('"TEST_PATH"/list/eth0/name')                    \n"
        "apteryx.set('"TEST_PATH"/list/eth1/name')                    \n"
    ));
    CU_ASSERT (assert_apteryx_empty ());
}

void
test_lua_basic_prune (void)
{
    CU_ASSERT (_run_lua (
        "apteryx = require('apteryx')                                 \n"
        "apteryx.set('"TEST_PATH"/list/eth0/name', 'eth0')            \n"
        "apteryx.set('"TEST_PATH"/list/eth1/name', 'eth1')            \n"
        "assert(apteryx.prune('"TEST_PATH"/list'))                    \n"
        "paths = apteryx.search('"TEST_PATH"/')                       \n"
        "assert(next(paths) == nil)                                   \n"
    ));
    CU_ASSERT (assert_apteryx_empty ());
}

void
test_lua_basic_set_tree_get_tree (void)
{
    CU_ASSERT (_run_lua (
        "apteryx = require('apteryx')                                 \n"
        "t={a='a', b={a='ba', b='bb'}, c = 'c'}                       \n"
        "apteryx.set_tree('"TEST_PATH"/t', t);                        \n"
        "t2 = apteryx.get_tree('"TEST_PATH"/t')                       \n"
        "assert (t2 and t2.a and t2.b.a)                              \n"
        "assert (#t2 == #t and #t2.b == #t.b)                         \n"
        "assert (t.a == t2.a and t.b.a == t2.b.a and t.c == t2.c)     \n"
        "apteryx.prune('"TEST_PATH"/t')                               \n"
    ));
    CU_ASSERT (assert_apteryx_empty ());
}

void
test_lua_basic_query (void)
{
    CU_ASSERT (_run_lua (
        "apteryx = require('apteryx')                                 \n"
        "t={a='a', b={a='ba', b='bb'}, c = 'c'}                       \n"
        "apteryx.set_tree('"TEST_PATH"/t', t);                        \n"
        "t1={test={t={a={}, b={a={}, b={}}, c={}}}}                   \n"
        "t2 = apteryx.query(t1)                                       \n"
        "assert (t2 and t2.test.t.a and t2.test.t.b.a                   "
        "    and t2.test.t.b.b)                                       \n"
        "assert (#t2 == #t1 and #t2.test.t.b == #t1.test.t.b)         \n"
        "assert (t2.test.t.a == t.a and t2.test.t.b.a == t.b.a          "
        "    and t2.test.t.b.b == t.b.b and t2.test.t.c == t.c)       \n"
        "apteryx.prune('"TEST_PATH"/t')                               \n"
    ));
    CU_ASSERT (assert_apteryx_empty ());
}

void
test_lua_basic_timestamp (void)
{
    CU_ASSERT (_run_lua (
        "apteryx = require('apteryx')                                 \n"
        "assert(apteryx.timestamp ('/nonex') == 0)                    \n"
        "apteryx.set('"TEST_PATH"/list/eth0/name', 'eth0')            \n"
        "assert(apteryx.timestamp('"TEST_PATH"/list') ~= 0)           \n"
        "apteryx.set('"TEST_PATH"/list/eth1/name', 'eth1')            \n"
        "t1 = apteryx.timestamp('"TEST_PATH"/list/eth0')              \n"
        "t2 = apteryx.timestamp('"TEST_PATH"/list/eth1')              \n"
        "assert(t2 > t1)                                              \n"
        "t1, t2 = nil, nil                                            \n"
        "assert(apteryx.prune('"TEST_PATH"/list'))                    \n"
        "assert(apteryx.timestamp ('/list') == 0)                     \n"
    ));
    CU_ASSERT (assert_apteryx_empty ());
}

void
test_lua_basic_watch (void)
{
    CU_ASSERT (_run_lua (
            "apteryx = require('apteryx')                                 \n"
            "local v = nil                                                \n"
            "function test_watch (path, value)                              "
            "    assert (path == '"TEST_PATH"/watch')                       "
            "    assert (value == 'me')                                     "
            "    v = value                                                  "
            "end                                                          \n"
            "apteryx.watch('"TEST_PATH"/watch', test_watch)               \n"
            "apteryx.process()                                            \n"
            "apteryx.set('"TEST_PATH"/watch', 'me')                       \n"
            "apteryx.process()                                            \n"
            "assert(v == 'me')                                            \n"
            "apteryx.unwatch('"TEST_PATH"/watch', test_watch)             \n"
            "apteryx.set('"TEST_PATH"/watch')                             \n"
            "apteryx.process(false)                                       \n"
    ));
    CU_ASSERT (assert_apteryx_empty ());
}

void
test_lua_multiple_watchers ()
{
        CU_ASSERT (_run_lua (
            "apteryx = require('apteryx')                                 \n"
            "local v1 = nil                                               \n"
            "local v2 = nil                                               \n"
            "local v3 = nil                                               \n"
            "function test_watch1 (path, value)                             "
            "    assert (path == '"TEST_PATH"/watch')                       "
            "    v1 = value                                                 "
            "end                                                          \n"
            "function test_watch2 (path, value)                             "
            "    assert (path == '"TEST_PATH"/watch')                       "
            "    v2 = value                                                 "
            "end                                                          \n"
            "function test_watch3 (path, value)                             "
            "    assert (path == '"TEST_PATH"/watch')                       "
            "    v3 = value                                                 "
            "end                                                          \n"
            "apteryx.watch('"TEST_PATH"/watch', test_watch1)              \n"
            "apteryx.process()                                            \n"
            "apteryx.watch('"TEST_PATH"/watch', test_watch2)              \n"
            "apteryx.process()                                            \n"
            "apteryx.watch('"TEST_PATH"/watch', test_watch3)              \n"
            "apteryx.process()                                            \n"
            "apteryx.set('"TEST_PATH"/watch', 'me')                       \n"
            "apteryx.process()                                            \n"
            "apteryx.process()                                            \n"
            "apteryx.process()                                            \n"
            "assert(v1 == 'me')                                           \n"
            "assert(v2 == 'me')                                           \n"
            "assert(v3 == 'me')                                           \n"
            "apteryx.unwatch('"TEST_PATH"/watch', test_watch1)            \n"
            "apteryx.process()                                            \n"
            "apteryx.set('"TEST_PATH"/watch', 'too')                      \n"
            "apteryx.process()                                            \n"
            "apteryx.process()                                            \n"
            "apteryx.process()                                            \n"
            "assert(v1 == 'me')                                           \n"
            "assert(v2 == 'too')                                          \n"
            "assert(v3 == 'too')                                          \n"
            "apteryx.unwatch('"TEST_PATH"/watch', test_watch3)            \n"
            "apteryx.process()                                            \n"
            "apteryx.set('"TEST_PATH"/watch', 'again')                    \n"
            "apteryx.process()                                            \n"
            "apteryx.process()                                            \n"
            "apteryx.process()                                            \n"
            "assert(v1 == 'me')                                           \n"
            "assert(v2 == 'again')                                        \n"
            "assert(v3 == 'too')                                          \n"
            "apteryx.unwatch('"TEST_PATH"/watch', test_watch2)            \n"
            "apteryx.set('"TEST_PATH"/watch')                             \n"
            "apteryx.process(false)                                       \n"
    ));
    CU_ASSERT (assert_apteryx_empty ());
}

static int
test_lua_refresh_thread (void *data)
{
    CU_ASSERT (_run_lua (
            "apteryx = require('apteryx')                                 \n"
            "function test_refresh (path)                                   "
            "    assert (path == '"TEST_PATH"/refresh')                     "
            "    apteryx.set('"TEST_PATH"/refresh', 'me')                   "
            "    return 0                                                   "
            "end                                                          \n"
            "apteryx.refresh('"TEST_PATH"/refresh', test_refresh)         \n"
            "for i=1,5 do                                                  "
            "    apteryx.process()                                          "
            "    os.execute('sleep 0.1')                                    "
            "end                                                          \n"
            "apteryx.unrefresh('"TEST_PATH"/refresh', test_refresh)       \n"
            "apteryx.set('"TEST_PATH"/refresh')                           \n"
            "apteryx.process(false)                                       \n"
    ));
    return 0;
}

void
test_lua_basic_refresh (void)
{
    pthread_t client;
    char *value = NULL;

    pthread_create (&client, NULL, (void *) &test_lua_refresh_thread, (void *) NULL);
    usleep (TEST_SLEEP_TIMEOUT);
    CU_ASSERT ((value = apteryx_get (TEST_PATH"/refresh")) != NULL);
    CU_ASSERT (value && strcmp (value, "me") == 0);
    if (value)
        free ((void *) value);
    pthread_join (client, NULL);
    usleep (TEST_SLEEP_TIMEOUT);
    CU_ASSERT (assert_apteryx_empty ());
}

static int
test_lua_provide_thread (void *data)
{
    CU_ASSERT (_run_lua (
            "apteryx = require('apteryx')                                 \n"
            "function test_provide (path)                                   "
            "    assert (path == '"TEST_PATH"/provide')                     "
            "    return 'me'                                                "
            "end                                                          \n"
            "apteryx.provide('"TEST_PATH"/provide', test_provide)         \n"
            "for i=1,5 do                                                  "
            "    apteryx.process()                                          "
            "    os.execute('sleep 0.1')                                    "
            "end                                                          \n"
            "apteryx.unprovide('"TEST_PATH"/provide', test_provide)       \n"
            "apteryx.process(false)                                       \n"
    ));
    return 0;
}

void
test_lua_basic_provide (void)
{
    pthread_t client;
    char *value = NULL;

    pthread_create (&client, NULL, (void *) &test_lua_provide_thread, (void *) NULL);
    usleep (TEST_SLEEP_TIMEOUT);
    CU_ASSERT ((value = apteryx_get (TEST_PATH"/provide")) != NULL);
    CU_ASSERT (value && strcmp (value, "me") == 0);
    if (value)
        free ((void *) value);
    pthread_join (client, NULL);
    usleep (TEST_SLEEP_TIMEOUT);
    CU_ASSERT (assert_apteryx_empty ());
}

static int
test_lua_index_thread (void *data)
{
    CU_ASSERT (_run_lua (
            "apteryx = require('apteryx')                                 \n"
            "function test_index (path)                                   "
            "    assert (path == '"TEST_PATH"/index/')                     "
            "    return {'"TEST_PATH"/index/dog','"TEST_PATH"/index/cat'}  "
            "end                                                          \n"
            "apteryx.index('"TEST_PATH"/index/', test_index)              \n"
            "for i=1,5 do                                                  "
            "    apteryx.process()                                          "
            "    os.execute('sleep 0.1')                                    "
            "end                                                          \n"
            "apteryx.unindex('"TEST_PATH"/index/', test_index)            \n"
            "apteryx.process(false)                                       \n"
    ));
    return 0;
}

void
test_lua_basic_index (void)
{
    pthread_t client;
    GList *paths = NULL;

    pthread_create (&client, NULL, (void *) &test_lua_index_thread, (void *) NULL);
    usleep (TEST_SLEEP_TIMEOUT);
    CU_ASSERT ((paths = apteryx_search (TEST_PATH"/index/")) != NULL);
    CU_ASSERT (g_list_length (paths) == 2);
    CU_ASSERT (g_list_find_custom (paths, TEST_PATH"/index/dog", (GCompareFunc) strcmp) != NULL);
    CU_ASSERT (g_list_find_custom (paths, TEST_PATH"/index/cat", (GCompareFunc) strcmp) != NULL);
    g_list_free_full (paths, free);
    pthread_join (client, NULL);
    usleep (TEST_SLEEP_TIMEOUT);
    CU_ASSERT (assert_apteryx_empty ());
}

static int
test_lua_validate_thread (void *data)
{
    CU_ASSERT (_run_lua (
            "apteryx = require('apteryx')                                 \n"
            "function test_validate (path, value)                           "
            "    assert (path == '"TEST_PATH"/validate')                    "
            "    return value == 'cat' and -22 or 0                          "
            "end                                                          \n"
            "apteryx.validate('"TEST_PATH"/validate', test_validate)      \n"
            "for i=1,5 do                                                  "
            "    apteryx.process()                                          "
            "    os.execute('sleep 0.1')                                    "
            "end                                                          \n"
            "apteryx.unvalidate('"TEST_PATH"/validate', test_validate)    \n"
            "apteryx.process(false)                                       \n"
    ));
    return 0;
}

void
test_lua_basic_validate (void)
{
    pthread_t client;

    pthread_create (&client, NULL, (void *) &test_lua_validate_thread, (void *) NULL);
    usleep (TEST_SLEEP_TIMEOUT);
    CU_ASSERT (apteryx_set (TEST_PATH"/validate", "dog"));
    CU_ASSERT (!apteryx_set (TEST_PATH"/validate", "cat") && errno == -EINVAL);
    CU_ASSERT (apteryx_set (TEST_PATH"/validate", NULL));
    pthread_join (client, NULL);
    usleep (TEST_SLEEP_TIMEOUT);
    CU_ASSERT (assert_apteryx_empty ());
}

static inline unsigned long
_memory_usage (void)
{
    unsigned long memory;
    FILE *f = fopen ("/proc/self/statm","r");
    CU_ASSERT (1 == fscanf (f, "%*d %ld %*d %*d %*d %*d %*d", &memory))
    fclose (f);
    return memory * getpagesize () / 1024;
}

void
test_lua_load_memory (void)
{
    lua_State *L;
    unsigned long before;
    unsigned long after;
    int res = -1;

    before = _memory_usage ();
    L = luaL_newstate ();
    luaL_openlibs (L);
    res = luaL_loadstring (L, "apteryx = require('apteryx')");
    if (res == 0)
        res = lua_pcall (L, 0, 0, 0);
    if (res != 0)
        fprintf (stderr, "%s\n", lua_tostring(L, -1));
    after = _memory_usage ();
    lua_close (L);
    printf ("%ldkb ... ", (after - before));
    CU_ASSERT (res == 0);
}

void
test_lua_load_performance (void)
{
    uint64_t start;
    int i;

    start = get_time_us ();
    for (i = 0; i < TEST_ITERATIONS; i++)
    {
        CU_ASSERT (_run_lua ("apteryx = require('apteryx')"));
    }
    printf ("%"PRIu64"us ... ", (get_time_us () - start) / TEST_ITERATIONS);
    CU_ASSERT (assert_apteryx_empty ());
}

void
test_lua_perf_get ()
{
    lua_State *L;
    uint64_t start;
    int i;

    for (i = 0; i < TEST_ITERATIONS; i++)
    {
        char *path = NULL;
        CU_ASSERT (asprintf(&path, TEST_PATH"/list/%d/name", i) > 0);
        apteryx_set (path, "private");
        free (path);
    }
    L = luaL_newstate ();
    luaL_openlibs (L);
    CU_ASSERT (luaL_loadstring (L, "apteryx = require('apteryx')") == 0);
    CU_ASSERT(lua_pcall (L, 0, 0, 0) == 0);
    start = get_time_us ();
    for (i = 0; i < TEST_ITERATIONS; i++)
    {
        char *cmd = NULL;
        int res;
        CU_ASSERT (asprintf(&cmd, "assert(apteryx.get('"TEST_PATH"/list/%d/name') ~= nil)", i) > 0);
        res = luaL_loadstring (L, cmd);
        if (res == 0)
            res = lua_pcall (L, 0, 0, 0);
        if (res != 0)
            fprintf (stderr, "%s\n", lua_tostring(L, -1));
        if (res != 0)
            goto exit;
        free (cmd);
    }
    printf ("%"PRIu64"us ... ", (get_time_us () - start) / TEST_ITERATIONS);
exit:
    lua_close (L);
    for (i = 0; i < TEST_ITERATIONS; i++)
    {
        char *path = NULL;
        CU_ASSERT (asprintf(&path, TEST_PATH"/list/%d/name", i) > 0);
        CU_ASSERT (apteryx_set (path, NULL));
        free (path);
    }
    CU_ASSERT (assert_apteryx_empty ());
}

void
test_lua_perf_set ()
{
    lua_State *L;
    uint64_t start;
    int i;

    L = luaL_newstate ();
    luaL_openlibs (L);
    CU_ASSERT (luaL_loadstring (L, "apteryx = require('apteryx')") == 0);
    CU_ASSERT(lua_pcall (L, 0, 0, 0) == 0);
    start = get_time_us ();
    for (i = 0; i < TEST_ITERATIONS; i++)
    {
        char *cmd = NULL;
        int res;
        CU_ASSERT (asprintf(&cmd, "assert(apteryx.set('"TEST_PATH"/list/%d/name', 'private'))", i) > 0);
        res = luaL_loadstring (L, cmd);
        if (res == 0)
            res = lua_pcall (L, 0, 0, 0);
        if (res != 0)
            fprintf (stderr, "%s\n", lua_tostring(L, -1));
        if (res != 0)
            goto exit;
        free (cmd);
    }
    printf ("%"PRIu64"us ... ", (get_time_us () - start) / TEST_ITERATIONS);
exit:
    lua_close (L);
    for (i = 0; i < TEST_ITERATIONS; i++)
    {
        char *path = NULL;
        CU_ASSERT (asprintf(&path, TEST_PATH"/list/%d/name", i) > 0);
        CU_ASSERT (apteryx_set (path, NULL));
        free (path);
    }
    CU_ASSERT (assert_apteryx_empty ());
}
#endif

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
    { "initialisation", test_init },
    { "set and get", test_set_get },
    { "set with ack", test_set_with_ack },
    { "raw byte streams", test_set_get_raw },
    { "long path", test_set_get_long_path },
    { "large value", test_set_get_large_value },
    { "multiple leaves", test_multiple_leaves },
    { "set/get string", test_set_get_string },
    { "set/get int", test_set_get_int },
    { "has_value", test_set_has_value },
    { "get no value", test_get_no_value },
    { "overwrite", test_overwrite },
    { "delete", test_delete },
    { "search paths", test_search_paths },
    { "search root path", test_search_paths_root },
    { "multi threads writing to same table", test_thread_multi_write },
    { "multi processes writing to same table", test_process_multi_write },
    { "prune", test_prune },
    { "prune root", test_prune_root },
    { "prune thread-safe", test_prune_thread_safe},
    { "cas", test_cas },
    { "cas string", test_cas_string },
    { "cas int", test_cas_int },
    { "bitmap", test_bitmap },
    { "shutdown deadlock", test_deadlock },
    { "shutdown deadlock 2", test_deadlock2 },
    { "remote path contains colon", test_remote_path_colon },
    { "double fork", test_double_fork },
    { "timestamp", test_timestamp },
    { "timestamp refreshed", test_timestamp_refreshed },
    { "timestamp provider", test_timestamp_provider },
    { "memuse", test_memuse },
    { "path to node", test_path_to_node },
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
    { "index x/* with provide x/* and get tree", test_index_and_provide_get_tree },
    { "indexer writes to database", test_index_writes },
    { "index path ends with /", test_index_always_ends_with_slash },
    { "index returns earlier path", test_index_recursive },
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
    { "watch one level miss", test_watch_one_level_miss },
    { "watch prune", test_watch_prune },
    { "watch prune multiple", test_watch_prune_multiple },
    { "watch one level path prune", test_watch_one_level_path_prune },
    { "watch empty path prune", test_watch_empty_path_prune },
    { "watch wildpath", test_watch_wildpath },
    { "watch wildcard", test_watch_wildcard },
    { "watch wildcard not last", test_watch_wildcard_not_last },
    { "watch wildcard miss", test_watch_wildcard_miss },
    { "watch set callback get", test_watch_set_callback_get },
    { "watch set callback unwatch", test_watch_set_callback_unwatch },
    { "watch set callback set recursive", test_watch_set_callback_set_recursive },
    { "watch set multi callback set", test_watch_set_multi_callback_set },
    { "watch and set from another thread", test_watch_set_thread },
    { "watch adds / removes watches", test_watch_adds_watch },
    { "watch removes multiple watches", test_watch_removes_all_watches },
    { "watch when busy", test_watch_when_busy },
    { "watch order", test_watch_order },
    { "watch rpc restart", test_watch_rpc_restart },
    { "watch myself blocked", test_watch_myself_blocked },
    { "watch and watch_with_ack in same thread", test_watch_ack_thread },
    CU_TEST_INFO_NULL,
};

static CU_TestInfo tests_api_validate[] = {
    { "validate", test_validate },
    { "validate one level", test_validate_one_level },
    { "validate wildcard", test_validate_wildcard },
    { "validate wildcard internal", test_validate_wildcard_internal },
    { "validate conflicting", test_validate_conflicting },
    { "validate tree", test_validate_tree },
    { "validate from watch callback", test_validate_from_watch_callback },
    { "validate from many watches", test_validate_from_many_watches },
    { "validate set order", test_validate_ordering },
    { "validate tree order", test_validate_ordering_tree },
    { "validate prune", test_validate_prune },
    CU_TEST_INFO_NULL,
};

static CU_TestInfo tests_api_refresh[] = {
    { "refresh", test_refresh },
    { "refresh unneeded", test_refresh_unneeded },
    { "refresh timeout", test_refresh_timeout },
    { "refresh trunk", test_refresh_trunk },
    { "refresh tree", test_refresh_tree },
    { "refresh during get_tree", test_refresh_during_get_tree },
    { "refresh search", test_refresh_search },
    { "refresh subpath search", test_refresh_subpath_search },
    { "refresh traverse", test_refresh_traverse },
    { "refresh traverse deeper", test_refresh_traverse_deeper },
    { "refresh path empty", test_refresh_path_empty },
    { "refresh no change", test_refresh_no_change },
    { "refresh tree no change", test_refresh_tree_no_change },
    { "refresh collision", test_refresh_collision },
    { "refresh concurrent", test_refresh_concurrent },
    { "refresh various wildcards", test_refresh_wildcards },
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
    { "provide search root", test_provide_search_root },
    { "provide wildcard + search", test_provider_wildcard_search },
    { "provide and db search", test_provide_search_db },
    { "provide before db", test_provide_before_db },
    { "provider wildcard", test_provider_wildcard },
    { "provider wildcard internal", test_provider_wildcard_internal },
    { "provider search exact provide", test_search_of_provide },
    { "provider directory search", test_search_of_provider_slash },
    { "provider wildcard search", test_search_of_provider_wildcard },
    { "provider lower directory search", test_search_of_lower_directory_provider },
    { "provider lower wildcard search", test_search_of_lower_wildcard_provider },
    { "provider intermediate wildcard search", test_search_of_intermediate_wildcard },
    CU_TEST_INFO_NULL,
};

static CU_TestInfo tests_api_proxy[] = {
    { "proxy get", test_proxy_get },
    { "proxy tree get", test_proxy_tree_get },
    { "proxy tree query", test_proxy_tree_query },
    { "proxy set", test_proxy_set },
    { "proxy not listening", test_proxy_not_listening },
    { "proxy before db get", test_proxy_before_db_get },
    { "proxy before db set", test_proxy_before_db_set },
    { "proxy set validated", test_proxy_set_validated },
    { "proxy search", test_proxy_search },
    { "proxy prune", test_proxy_prune },
    { "proxy timestamp", test_proxy_timestamp },
    { "proxy cas", test_proxy_cas },
    CU_TEST_INFO_NULL,
};

static CU_TestInfo tests_api_tree[] = {
    { "doc example", test_tree_docs },
    { "tree nodes", test_tree_nodes },
    { "tree nodes deep", test_tree_nodes_deep },
    { "tree nodes wide", test_tree_nodes_wide },
    { "tree find children", test_tree_find_children },
    { "tree find node", test_tree_path_node },
    { "tree sort children", test_tree_sort_children },
    { "set tree", test_set_tree },
    { "set tree empty", test_set_tree_empty },
    { "get tree", test_get_tree },
    { "get tree single node", test_get_tree_single_node },
    { "get tree value on_branch", test_get_tree_value_on_branch },
    { "get tree null", test_get_tree_null },
    { "get tree indexed/provided", test_get_tree_indexed_provided },
    { "get tree indexed/provided wildcards", test_get_tree_indexed_provided_wildcards },
    { "get tree indexed/provided deeper", test_get_tree_indexed_provided_two_levels },
    { "get tree provided", test_get_tree_provided },
    { "get tree provided before db", test_get_tree_provided_before_db },
    { "get tree provided + set", test_get_tree_provided_plus_set },
    { "get tree provider writes", test_get_tree_provider_write },
    { "get tree thrashing" , test_get_tree_while_thrashing },
    { "query2node invalid" , test_query2node_invalid },
    { "query2node single field", test_query2node_single_field },
    { "query2node double field", test_query2node_double_field },
    { "query2node single field path", test_query2node_single_field_path },
    { "query2node double field path", test_query2node_double_field_path },
    { "query2node one path two nodes", test_query2node_one_path_two_nodes },
    { "query2node two paths two nodes", test_query2node_two_path_two_nodes },
    { "query empty", test_query_empty },
    { "query basic", test_query_basic},
    { "query subtree root", test_query_subtree_root},
    { "query one level", test_query_one_level},
    { "query one star", test_query_one_star},
    { "query one star traverse", test_query_one_star_traverse},
    { "query one star match exact", test_query_one_star_match_exact},
    { "query one star no match exact", test_query_one_star_no_match_exact},
    { "query one star match exact with other", test_query_one_star_match_exact_with_other},
    { "query one star match exact two results", test_query_one_star_match_exact_two_results},    
    { "query one star match exact two results with other", test_query_one_star_match_exact_two_results_with_other},    
    { "query multi star traverse", test_query_multi_star_traverse},
    { "query one star one level", test_query_one_star_one_level},
    { "query multi star one level", test_query_multi_star_one_level},
    { "query two star", test_query_two_star},
    { "query null values", test_query_null_values},
    { "query two branches", test_query_two_branches},
    { "query provided", test_query_provided},
    { "query provided before db", test_query_provided_before_db},
    { "query provided and refreshed", test_query_provided_refreshed},
    { "query provided trunk request", test_query_trunk_provided},
    { "query provided wildcard",  test_query_provided_wildcard},
    { "query provided wildcards", test_query_provided_wildcards},
    { "query refreshed simple", test_query_refreshed_simple},
    { "query refreshed mid wildcard", test_query_refreshed_mid_wildcard},
    { "query refreshed multi wildcard", test_query_refreshed_multi_wildcard},
    { "query refreshed once", test_query_refreshed_once},
    { "query not refreshed one path", test_query_not_refreshed_one_path},
    { "query not refreshed two paths", test_query_not_refreshed_two_paths},
    { "query not refreshed different root", test_query_not_refreshed_different_roots},
    // { "query not refreshed mid wildcard", test_query_not_refreshed_mid_wildcard},
    { "query refresh timeout", test_query_refresh_timeout},
    { "query root length", test_query_long_root},
    { "query too long", test_query_too_long},
    { "query value on branch", test_query_value_on_branch},
    { "cas tree", test_cas_tree},
    { "cas tree detailed", test_cas_tree_detailed},
    { "tree atomic", test_tree_atomic},
    { "watch tree", test_watch_tree },
    { "watch tree wildcard", test_watch_tree_wildcard },
    { "watch tree no match", test_watch_tree_no_match },
    { "watch tree remove", test_watch_tree_remove },
    { "watch tree prune", test_watch_tree_prune },
    { "watch tree prune tree", test_watch_tree_prune_tree },
    { "watch tree one level", test_watch_tree_one_level },
    { "watch tree one level multi", test_watch_tree_one_level_multi },
    { "watch tree one level miss", test_watch_tree_one_level_miss },
    CU_TEST_INFO_NULL,
};

static CU_TestInfo tests_find[] = {
    { "find simple", test_find_one_star },
    { "find multi *", test_find_two_star },
    { "find simple tree", test_find_tree_one_star },
    { "find empty tree", test_find_empty },
    { "find multi * tree", test_find_tree_two_star },
    { "find with null entry", test_find_tree_null_values },
    CU_TEST_INFO_NULL,
};

static CU_TestInfo tests_single_threaded[] = {
    { "single-threaded index", test_single_index },
    { "single-threaded index no polling", test_single_index_no_polling },
    { "single-threaded watch", test_single_watch },
    { "single-threaded watch no polling", test_single_watch_no_polling },
    { "single-threaded validate", test_single_validate },
    { "single-threaded validate no polling", test_single_validate_no_polling },
    { "single-threaded provide", test_single_provide },
    { "single-threaded provide no polling", test_single_provide_no_polling },
    { "single-threaded watch myself", test_single_watch_myself },
    { "single-threaded watch myself blocked", test_single_watch_myself_blocked },
    CU_TEST_INFO_NULL,
};

static CU_TestInfo tests_performance[] = {
    { "performance: dummy", test_perf_dummy },
    { "performance: set", test_perf_set },
    { "performance: set(tcp)", test_perf_tcp_set },
    { "performance: set tree (tcp)", test_perf_tcp_set_tree },
    { "performance: set(tcp6)", test_perf_tcp6_set },
    { "performance: set tree 50", test_perf_set_tree },
    { "performance: set tree 5000", test_perf_set_tree_5000 },
    { "performance: set tree 50000", test_perf_set_tree_50000 },
    { "performance: set tree real", test_perf_set_tree_real },
    { "performance: get", test_perf_get },
    { "performance: get(tcp)", test_perf_tcp_get },
    { "performance: get(tcp6)", test_perf_tcp6_get },
    { "performance: get tree 50", test_perf_get_tree },
    { "performance: get tree 10000", test_perf_get_tree_10000 },
    { "performance: get tree 20000", test_perf_get_tree_20000 },
    { "performance: get tree 30000", test_perf_get_tree_30000 },
    { "performance: get tree 40000", test_perf_get_tree_40000 },
    { "performance: get tree 50000", test_perf_get_tree_50000 },
    { "performance: get tree 60000", test_perf_get_tree_60000 },
    { "performance: get tree 70000", test_perf_get_tree_70000 },
    { "performance: get tree 80000", test_perf_get_tree_80000 },
    { "performance: get tree real", test_perf_get_tree_real },
    { "performance: get null", test_perf_get_null },
    { "performance: search", test_perf_search },
    { "performance: watch", test_perf_watch },
    { "performance: provide", test_perf_provide },
    { "performance: large prune (10000 level 1 nodes, 20000 level 2 nodes)", test_perf_prune },
    CU_TEST_INFO_NULL,
};

CU_TestInfo tests_rpc[] = {
    { "unix req", test_unix_req_latency },
    { "unix req/resp", test_unix_req_resp_latency },
    { "unix con/disc", test_unix_con_disc_latency },
    { "unix c/r/r/d", test_unix_con_req_resp_disc_latency},
    { "tcp req", test_tcp_req_latency },
    { "tcp req/resp", test_tcp_req_resp_latency },
    { "tcp con/disc", test_tcp_con_disc_latency },
    { "tcp c/r/r/d", test_tcp_con_req_resp_disc_latency},
    { "rpc init", test_rpc_init },
    { "rpc bind", test_rpc_bind },
    { "rpc connect", test_rpc_connect },
    { "rpc ping", test_rpc_ping },
    { "rpc double bind", test_rpc_double_bind },
    { "rpc perf", test_rpc_perf },
    CU_TEST_INFO_NULL,
};

#ifdef HAVE_LUA
CU_TestInfo tests_lua[] = {
    { "lua load module",test_lua_load },
    { "lua basic set get", test_lua_basic_set_get },
    { "lua basic search", test_lua_basic_search },
    { "lua basic prune", test_lua_basic_prune },
    { "lua basic set_tree get_tree", test_lua_basic_set_tree_get_tree},
    { "lua basic query", test_lua_basic_query},
    { "lua basic timestamp", test_lua_basic_timestamp },
    { "lua basic watch", test_lua_basic_watch },
    { "lua multiple watchers", test_lua_multiple_watchers },
    { "lua basic refresh", test_lua_basic_refresh },
    { "lua basic provide", test_lua_basic_provide },
    { "lua basic index", test_lua_basic_index },
    { "lua basic validate", test_lua_basic_validate },
    { "lua load memory usage", test_lua_load_memory },
    { "lua load performance", test_lua_load_performance },
    { "lua get performance", test_lua_perf_get },
    { "lua set performance", test_lua_perf_set },
    CU_TEST_INFO_NULL,
};
#endif

extern CU_TestInfo tests_database[];
extern CU_TestInfo tests_callbacks[];

static CU_SuiteInfo suites[] = {
    {
        .pName = "Database",
        .pInitFunc = suite_init,
        .pCleanupFunc = suite_clean,
        .pTests = tests_database
    },
    {
        .pName = "Callbacks",
        .pInitFunc = suite_init,
        .pCleanupFunc = suite_clean,
        .pTests = tests_callbacks
    },
    {
        .pName = "RPC",
        .pInitFunc = suite_init,
        .pCleanupFunc = suite_clean,
        .pTests = tests_rpc
    },
    #ifdef HAVE_LUA
    {
        .pName = "LUA",
        .pInitFunc = suite_init,
        .pCleanupFunc = suite_clean,
        .pTests = tests_lua
    },
    #endif
    {
        .pName = "Apteryx API",
        .pInitFunc = suite_init,
        .pCleanupFunc = suite_clean,
        .pTests = tests_api
    },
    {
        .pName = "Apteryx API Index",
        .pInitFunc = suite_init,
        .pCleanupFunc = suite_clean,
        .pTests = tests_api_index
    },
    {
        .pName = "Apteryx API Tree",
        .pInitFunc = suite_init,
        .pCleanupFunc = suite_clean,
        .pTests = tests_api_tree
    },
    {
        .pName = "Apteryx API Watch",
        .pInitFunc = suite_init,
        .pCleanupFunc = suite_clean,
        .pTests = tests_api_watch
    },
    {
        .pName = "Apteryx API Validate",
        .pInitFunc = suite_init,
        .pCleanupFunc = suite_clean,
        .pTests = tests_api_validate
    },
    {
        .pName = "Apteryx API Refresh",
        .pInitFunc = suite_init,
        .pCleanupFunc = suite_clean,
        .pTests = tests_api_refresh
    },
    {
        .pName = "Apteryx API Provide",
        .pInitFunc = suite_init,
        .pCleanupFunc = suite_clean,
        .pTests = tests_api_provide
    },
    {
        .pName = "Apteryx API Proxy",
        .pInitFunc = suite_init,
        .pCleanupFunc = suite_clean,
        .pTests = tests_api_proxy
    },
    {
        .pName = "Apteryx API Find",
        .pInitFunc = suite_init,
        .pCleanupFunc = suite_clean,
        .pTests = tests_find
    },
    {
        .pName = "Apteryx API Single Threaded",
        .pInitFunc = suite_init,
        .pCleanupFunc = suite_clean,
        .pTests = tests_single_threaded
    },
    {
        .pName = "Apteryx Performance",
        .pInitFunc = suite_init,
        .pCleanupFunc = suite_clean,
        .pTests = tests_performance
    },
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

    /* Make some random numbers */
    srand (time (NULL));

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
            fprintf (stderr, "suite registration failed - %s\n", CU_get_error_msg ());
            exit (EXIT_FAILURE);
        }
        CU_TestInfo *test = &suite->pTests[0];
        while (test && test->pName)
        {
            if (all || (filter && strstr (test->pName, filter) != NULL))
            {
                if (CU_add_test(pSuite, test->pName, test->pTestFunc) == NULL)
                {
                    fprintf (stderr, "test registration failed - %s\n", CU_get_error_msg ());
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
