/**
 * @file database.c
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
#include <stdlib.h>
#include <stdio.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include <glib.h>
#include <inttypes.h>
#include "internal.h"
#ifdef TEST
#include <CUnit/CUnit.h>
#include <CUnit/Basic.h>
#endif

#include "hashtree.h"

struct database_node
{
    struct hashtree_node hashtree_node;
    uint64_t timestamp;
    size_t length;
    unsigned char *value;
};

struct hashtree_node *root = NULL;  /* The database root */

pthread_rwlock_t db_lock = PTHREAD_RWLOCK_INITIALIZER;

static uint64_t
db_calculate_timestamp (void)
{
    struct timespec tms;
    uint64_t micros = 0;
    if (clock_gettime(CLOCK_REALTIME, &tms)) {
        return 0;
    }

    micros = ((uint64_t)tms.tv_sec) * 1000000;
    micros += tms.tv_nsec/1000;
    return micros;
}


static uint64_t
db_timestamp_no_lock (const char *path)
{
    uint64_t timestamp = 0;
    struct database_node *new_value =
        (struct database_node *) hashtree_path_to_node (root, path);
    if (new_value)
    {
        timestamp = new_value->timestamp;
    }
    return timestamp;
}

uint64_t
db_timestamp (const char *path)
{
    uint64_t timestamp = 0;
    pthread_rwlock_rdlock (&db_lock);
    timestamp = db_timestamp_no_lock (path);
    pthread_rwlock_unlock (&db_lock);
    return timestamp;
}

bool
db_add_no_lock (const char *path, const unsigned char *value, size_t length, uint64_t ts)
{
    uint64_t timestamp = db_calculate_timestamp();

    if (ts != UINT64_MAX && ts < db_timestamp_no_lock (path))
        return false;

    struct database_node *new_value =
        (struct database_node *) hashtree_path_to_node (root, path);
    if (!new_value)
    {
        new_value =
            (struct database_node *) hashtree_node_add (root, sizeof (*new_value), path);
    }
    g_free (new_value->value);
    new_value->value = NULL;
    if (length > 0)
    {
        new_value->value = g_malloc (length);
        memcpy (new_value->value, value, length);
    }
    new_value->length = length;

    /* This node is in a path that is being updated */
    do
    {
        new_value->timestamp = timestamp;
    }
    while ((new_value =
            (struct database_node *) hashtree_parent_get ((struct hashtree_node *)
                                                          new_value)) != NULL);

    return true;
}

bool
db_add (const char *path, const unsigned char *value, size_t length, uint64_t ts)
{
    bool ret = false;
    pthread_rwlock_wrlock (&db_lock);
    ret = db_add_no_lock (path, value, length, ts);
    pthread_rwlock_unlock (&db_lock);
    return ret;
}

bool
db_delete_no_lock (const char *path, uint64_t ts)
{
    bool ret = false;
    if (ts == UINT64_MAX || ts >= db_timestamp_no_lock (path))
    {

        struct hashtree_node *node = hashtree_path_to_node (root, path);
        if (node && node != root)
        {
            uint64_t now = db_calculate_timestamp ();
            struct hashtree_node *iter = node;
            struct hashtree_node *parent = hashtree_parent_get (node);
            while ((iter = hashtree_parent_get (iter)) != NULL)
            {
                ((struct database_node *) iter)->timestamp = now;
            }

            if (((struct database_node *) node)->value != NULL)
            {
                g_free (((struct database_node *) node)->value);
                ((struct database_node *) node)->value = NULL;
                ((struct database_node *) node)->length = 0;
            }

            if (hashtree_empty (node))
            {
                hashtree_node_delete (root, node);
            }

            if (parent)
            {
                /* This is now a hanging node, remove it */
                if (hashtree_empty (parent) &&
                    ((struct database_node *) parent)->length == 0)
                {
                    char *parent_path = strdup (path);
                    if (strchr (parent_path, '/'))
                    {
                        *strrchr (parent_path, '/') = '\0';
                    }
                    db_delete_no_lock (parent_path, UINT64_MAX);
                    free (parent_path);
                }
            }
        }
        ret = true;
    }
    return ret;
}

bool
db_delete (const char *path, uint64_t ts)
{
    bool ret = false;
    pthread_rwlock_wrlock (&db_lock);
    ret = db_delete_no_lock (path, ts);
    pthread_rwlock_unlock (&db_lock);
    return ret;
}

bool
db_get (const char *path, unsigned char **value, size_t *length)
{
    pthread_rwlock_rdlock (&db_lock);
    struct database_node *node =
        (struct database_node *) hashtree_path_to_node (root, path);
    if (!node || !node->value)
    {
        pthread_rwlock_unlock (&db_lock);
        return false;
    }
    *value = g_malloc (node->length);
    memcpy (*value, node->value, node->length);
    *length = node->length;
    pthread_rwlock_unlock (&db_lock);
    return true;
}

GList *
db_search (const char *path)
{
    bool end_with_slash = strlen (path) > 0 ? path[strlen (path) - 1] == '/' : false;

    pthread_rwlock_rdlock (&db_lock);
    GList *children, *iter, *paths = NULL;
    struct hashtree_node *node = hashtree_path_to_node (root, path);

    if (node == NULL)
    {
        pthread_rwlock_unlock (&db_lock);
        return NULL;
    }

    children = hashtree_children_get (node);
    if (children == NULL)
    {
        pthread_rwlock_unlock (&db_lock);
        return NULL;
    }

    for (iter = children; iter; iter = g_list_next (iter))
    {
        char *child_path = NULL;
        struct hashtree_node *node = iter->data;
        if (asprintf (&child_path, "%s%s%s", path, end_with_slash ? "" : "/", node->key) >
            0)
        {
            paths = g_list_prepend (paths, child_path);
        }
    }
    g_list_free (children);
    pthread_rwlock_unlock (&db_lock);
    return paths;
}

void
db_init ()
{
    pthread_rwlock_wrlock (&db_lock);
    if (!root)
    {
        root = hashtree_init (sizeof (struct database_node));
    }
    pthread_rwlock_unlock (&db_lock);
}

static void
db_purge (struct database_node *node)
{
    GList *children = hashtree_children_get (&node->hashtree_node);
    for (GList * iter = children; iter; iter = iter->next)
    {
        db_purge ((struct database_node *) iter->data);
    }
    g_list_free (children);

    if (node->value)
    {
        g_free (node->value);
    }
    node->value = NULL;
    node->length = 0;
}

static void
db_evaporate (struct database_node *node)
{
    struct database_node *parent =
      (struct database_node *) hashtree_parent_get (&node->hashtree_node);

    hashtree_node_delete (&parent->hashtree_node, &node->hashtree_node);
    if ((void*)parent != (void*)root && parent
        && hashtree_empty (&parent->hashtree_node) && parent->length == 0)
        db_evaporate (parent);
}

void
db_prune (const char *path)
{
    pthread_rwlock_wrlock (&db_lock);

    struct database_node *node =
        (struct database_node *) hashtree_path_to_node (root, path);

    if (node)
    {
        db_purge (node);
        db_evaporate (node);
    }

    pthread_rwlock_unlock (&db_lock);
}

void
db_shutdown ()
{
    GList *paths = db_search ("");
    if (paths)
    {
        GList *iter;
        for (iter = paths; iter; iter = g_list_next (iter))
            printf ("DB ERROR: path still set %s\n", (char *) iter->data);
        g_list_free_full (paths, g_free);
    }
    pthread_rwlock_wrlock (&db_lock);

    db_purge ((struct database_node *) root);

    hashtree_shutdown (root);
    root = NULL;
    pthread_rwlock_unlock (&db_lock);
}

#ifdef TEST
#define TEST_DB_MAX_ENTRIES 10000
#define TEST_DB_MAX_ITERATIONS 1000

void
test_db_add_delete ()
{
    const char *path = "/database/test";
    db_init ();
    CU_ASSERT (db_add (path, (const unsigned char *) "test", strlen ("test") + 1, UINT64_MAX));
    CU_ASSERT (db_delete (path, UINT64_MAX));
    db_shutdown ();
}

void
test_db_add_delete_perf ()
{
    char *path = NULL;
    uint64_t start;
    int i;

    db_init ();

    for (i = 0; i < TEST_DB_MAX_ENTRIES; i++)
    {
        path = g_strdup_printf ("/database/test%d/test%d", i, i);
        CU_ASSERT (db_add (path, (const unsigned char *) "test", strlen ("test") + 1, UINT64_MAX));
        g_free (path);
    }

    start = get_time_us ();
    path = g_strdup_printf ("/database/test%d/test%d",
            TEST_DB_MAX_ENTRIES - 1, TEST_DB_MAX_ENTRIES - 1);
    for (i = 0; i < TEST_DB_MAX_ITERATIONS; i++)
    {
        CU_ASSERT (db_add (path, (const unsigned char *) "test", strlen ("test") + 1, UINT64_MAX));
        CU_ASSERT (db_delete (path, UINT64_MAX));
    }
    printf ("%"PRIu64"us ... ", (get_time_us () - start) / 1000);

    g_free (path);
    for (i = 0; i < TEST_DB_MAX_ENTRIES; i++)
    {
        path = g_strdup_printf ("/database/test%d/test%d", i, i);
        CU_ASSERT (db_delete (path, UINT64_MAX));
        g_free (path);
    }
    db_delete ("", UINT64_MAX);
}

void
test_db_long_path ()
{
    char *path = NULL;
    char *value = NULL;
    size_t length;
    int i;

    path = g_strdup_printf ("%s", "/database/test");
    for (i=0; i<1024; i++)
    {
        char *old = path;
        path = g_strdup_printf ("%s/%08x", old, rand ());
        g_free (old);
    }
    db_init ();
    CU_ASSERT (db_get (path, (unsigned char **) &value, &length) != true);
    CU_ASSERT (db_add (path, (const unsigned char *) "test", strlen ("test") + 1, UINT64_MAX));
    CU_ASSERT (db_get (path, (unsigned char **) &value, &length) == true);
    CU_ASSERT (value != NULL);
    CU_ASSERT (length == (strlen ("test") + 1));
    CU_ASSERT (value && strcmp (value, "test") == 0);
    g_free ((void *) value);
    CU_ASSERT (db_delete (path, UINT64_MAX));
    g_free ((void *) path);
    db_shutdown ();
}

void
_path_perf (int path_length, bool full)
{
    char *path = NULL;
    int count = TEST_DB_MAX_ITERATIONS / path_length;
    uint64_t start;
    int i;

    path = g_strdup_printf ("%s", "/database");
    for (i=0; i<(path_length - 1); i++)
    {
        char *old = path;
        path = g_strdup_printf ("%s/%08x", old, rand ());
        g_free (old);
    }
    db_init ();
    if (!full)
    {
        db_add (path, (const unsigned char *) "placeholder", strlen ("placeholder") + 1, UINT64_MAX);
        path[strlen (path) - 1]++;
    }
    start = get_time_us ();
    for (i = 0; i < count; i++)
    {
        CU_ASSERT (db_add (path, (const unsigned char *) "test", strlen ("test") + 1, UINT64_MAX));
        CU_ASSERT (db_delete (path, UINT64_MAX));
    }
    printf ("%d=%"PRIu64"us ", path_length, (get_time_us () - start) / count);
    if (!full)
    {
        path[strlen (path) - 1]--;
        db_delete (path, UINT64_MAX);
    }
    g_free (path);
    db_shutdown ();
}

void test_db_path_perf ()
{
    _path_perf (5, true);
    _path_perf (10, true);
    _path_perf (100, true);
    _path_perf (1000, true);
    printf ("... ");
}

void test_db_path_exists_perf ()
{
    _path_perf (5, false);
    _path_perf (10, false);
    _path_perf (100, false);
    _path_perf (1000, false);
    printf (" ... ");
}

void
test_db_large_value ()
{
    const char *path = "/database/test";
    char *large;
    int len = 1024*1024;
    char *value = NULL;
    size_t length;

    large = g_malloc0 (len);
    memset (large, 'a', len-1);
    db_init ();
    CU_ASSERT (db_get (path, (unsigned char **) &value, &length) != true);
    CU_ASSERT (db_add (path, (const unsigned char *) large, len, UINT64_MAX));
    CU_ASSERT (db_get (path, (unsigned char **) &value, &length) == true);
    CU_ASSERT (value != NULL);
    CU_ASSERT (length == len);
    CU_ASSERT (value && strcmp (value, large) == 0);
    g_free ((void *) value);
    CU_ASSERT (db_delete (path, UINT64_MAX));
    g_free ((void *) large);
    db_shutdown ();
}

void
test_db_get ()
{
    const char *path = "/database/test";
    char *value;
    size_t length;
    db_init ();
    CU_ASSERT (db_get (path, (unsigned char **) &value, &length) != true);
    CU_ASSERT (db_add (path, (const unsigned char *) "test", strlen ("test") + 1, UINT64_MAX));
    CU_ASSERT (db_get (path, (unsigned char **) &value, &length) == true);
    CU_ASSERT (value != NULL);
    CU_ASSERT (length == (strlen ("test") + 1));
    CU_ASSERT (value && strcmp (value, "test") == 0);
    g_free ((void *) value);
    CU_ASSERT (db_delete (path, UINT64_MAX));
    db_shutdown ();
}

void
test_db_get_perf ()
{
    char *path = NULL;
    char *value = NULL;
    size_t length;
    uint64_t start;
    int i;
    bool res;

    db_init ();
    for (i = 0; i < TEST_DB_MAX_ENTRIES; i++)
    {
        path = g_strdup_printf ("/database/test%d/test%d", i, i);
        CU_ASSERT (db_add (path, (const unsigned char *) "test", strlen ("test") + 1, UINT64_MAX));
        g_free (path);
    }

    start = get_time_us ();
    path = g_strdup_printf ("/database/test%d/test%d",
            TEST_DB_MAX_ENTRIES - 1, TEST_DB_MAX_ENTRIES - 1);
    for (i = 0; i < TEST_DB_MAX_ITERATIONS; i++)
    {
        CU_ASSERT ((res = db_get (path, (unsigned char **) &value, &length)) == true);
        CU_ASSERT (value != NULL);
        if (!res || !value)
            goto exit;
        g_free ((void *) value);
    }
    printf ("%"PRIu64"us ... ", (get_time_us () - start) / 1000);
  exit:
    g_free (path);
    for (i = 0; i < TEST_DB_MAX_ENTRIES; i++)
    {
        path = g_strdup_printf ("/database/test%d/test%d", i, i);
        CU_ASSERT (db_delete (path, UINT64_MAX));
        g_free (path);
    }
    db_shutdown ();
}

void
test_db_replace ()
{
    const char *path = "/database/test";
    char *value;
    size_t length;
    int i;
    db_init ();
    for (i=0; i<10; i++)
    {
        char value[64];
        sprintf (value, "test%d", i);
        CU_ASSERT (db_add (path, (const unsigned char *) value, strlen (value) + 1, UINT64_MAX));
    }
    CU_ASSERT (db_get (path, (unsigned char **) &value, &length) == true);
    CU_ASSERT (value != NULL);
    CU_ASSERT (length == (strlen ("test9") + 1));
    CU_ASSERT (value && strcmp (value, "test9") == 0);
    g_free ((void *) value);
    CU_ASSERT (db_delete (path, UINT64_MAX));
    db_shutdown ();
}

void
test_db_search ()
{
    const char *path = "/database/test";
    GList *paths = NULL;
    db_init ();
    CU_ASSERT (db_add (path, (const unsigned char *) "test", strlen ("test") + 1, UINT64_MAX));
    CU_ASSERT ((paths = db_search ("/database/")) != NULL);
    CU_ASSERT (g_list_length (paths) == 1);
    CU_ASSERT (g_list_find_custom (paths, "/database/test", (GCompareFunc) strcmp) != NULL);
    g_list_free_full (paths, g_free);

    CU_ASSERT ((paths = db_search ("/database")) != NULL);
    CU_ASSERT (g_list_length (paths) == 1);
    CU_ASSERT (g_list_find_custom (paths, "/database/test", (GCompareFunc) strcmp) != NULL);
    g_list_free_full (paths, g_free);

    CU_ASSERT (db_delete (path, UINT64_MAX));
    db_shutdown ();
}

void
test_db_search_perf ()
{
    char *path = NULL;
    GList *paths = NULL;
    uint64_t start;
    int i;
    db_init ();

    for (i = 0; i < TEST_DB_MAX_ENTRIES; i++)
    {
        path = g_strdup_printf ("/database/test%d/test%d", i, i);
        CU_ASSERT (db_add (path, (const unsigned char *) "test", strlen ("test") + 1, UINT64_MAX));
        g_free (path);
    }

    start = get_time_us ();
    path = g_strdup_printf ("/database/test%d/", TEST_DB_MAX_ENTRIES - 1);
    for (i = 0; i < TEST_DB_MAX_ITERATIONS; i++)
    {
        CU_ASSERT ((paths = db_search (path)) != NULL);
        CU_ASSERT (g_list_length (paths) == 1);
        if (g_list_length (paths) != 1)
            goto exit;
        g_list_free_full (paths, g_free);
    }
    printf ("%"PRIu64"us ... ", (get_time_us () - start) / 1000);
  exit:
  g_free (path);
    for (i = 0; i < TEST_DB_MAX_ENTRIES; i++)
    {
        path = g_strdup_printf ("/database/test%d/test%d", i, i);
        CU_ASSERT (db_delete (path, UINT64_MAX));
        g_free (path);
    }
    db_shutdown ();
}

void
test_db_timestamping ()
{
    char *path = "/test/timestamps";
    char *path2 = "/test/timestamp2";
    char *ppath = "/test";

    uint64_t last_ts;

    db_init ();

    CU_ASSERT (db_add (path, (const unsigned char *) "test", 5, UINT64_MAX));
    last_ts = db_timestamp (path);
    sleep (1);
    CU_ASSERT (db_add (path2, (const unsigned char *) "test", 5, UINT64_MAX));
    CU_ASSERT (db_timestamp (path2) > last_ts);
    last_ts = db_timestamp (path2);
    CU_ASSERT (db_timestamp (path) < db_timestamp (path2));
    CU_ASSERT (db_timestamp (ppath) >= db_timestamp (path2));
    CU_ASSERT (db_timestamp ("/") >= db_timestamp (ppath));

    CU_ASSERT (db_delete (path2, UINT64_MAX));
    CU_ASSERT (db_timestamp (ppath) > last_ts);
    CU_ASSERT (db_timestamp ("/") >= db_timestamp (ppath));

    CU_ASSERT (db_delete (path, UINT64_MAX));

    db_shutdown ();
}


CU_TestInfo tests_database[] = {
    { "add/delete", test_db_add_delete },
    { "add/delete performance", test_db_add_delete_perf },
    { "large value", test_db_large_value },
    { "long path", test_db_long_path },
    { "path performance", test_db_path_perf },
    { "path exists perf", test_db_path_exists_perf },
    { "get", test_db_get },
    { "get performance", test_db_get_perf },
    { "replace", test_db_replace },
    { "search", test_db_search },
    { "search performance", test_db_search_perf },
    { "timestamping", test_db_timestamping },
    CU_TEST_INFO_NULL,
};
#endif
