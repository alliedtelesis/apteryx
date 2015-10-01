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

struct database_node
{
    char *key;
    unsigned char *value;
    size_t length;
    struct database_node *parent;
    GHashTable *children;
    unsigned int removing;
    uint64_t timestamp;
};
struct database_node *root = NULL;  /* The database root */

static pthread_rwlock_t db_lock = PTHREAD_RWLOCK_INITIALIZER;

/* This function needs to be forward declared - it is used in a recursive loop. It needs
 * to be called with db_lock (above) held for writing */
static bool db_add_no_lock (const char *path, const unsigned char *value, size_t length);

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

static char *
db_node_to_path (struct database_node *node, char **buf)
{
    /* don't put a trailing / on */
    char end = 0;
    if (!*buf)
    {
        *buf = g_strdup ("");
        end = 1;
    }

    if (node && node->parent)
        db_node_to_path (node->parent, buf);

    char *tmp = g_strdup_printf ("%s%s%s",
            *buf ? : "", node ? node->key : "/", end ? "" : "/");
    g_free (*buf);
    *buf = tmp;

    return tmp;
}

static struct database_node *
db_path_to_node (const char *path, uint64_t timestamp)
{
    char *key = g_strdup (path);
    char *start = key;
    int path_length;
    struct database_node *node = NULL;
    struct database_node *current = root;

    /* Trim trailing '/' */
    if (strlen (key) && key[strlen (key) - 1] == '/')
        key[strlen (key) - 1] = '\0';
    path_length = strlen (key);

    if (strchr (key, '/'))
        *strchr (key, '/') = '\0';

    while (current)
    {
        if (key + strlen (key) == start + path_length)
        {
            if (strcmp (key, current->key) == 0)
            {
                node = current;
                break;
            }
        }

        /* look down a level */
        if (current->children == NULL)
        {
            node = NULL;
            break;
        }

        key += strlen (key) + 1;
        if (strchr (key, '/'))
            *strchr (key, '/') = '\0';

        /* This node is in a path that is being updated */
        if (timestamp)
            current->timestamp = timestamp;

        if ((current = g_hash_table_lookup (current->children, key)) == NULL)
            break;
    }

    /* This node is in a path that is being updated */
    if (node && timestamp)
        node->timestamp = timestamp;

    g_free (start);
    return node;
}

static void
db_node_delete (struct database_node *node)
{
    if (!node)
        return;

    node->removing++;

    if (node->removing <= 1 && node->parent && node->parent->children)
    {
        g_hash_table_remove (node->parent->children, node->key);
        if (g_hash_table_size (node->parent->children) == 0 && node->parent->length == 0)
        {
            db_node_delete (node->parent);
        }
    }

    if (node->removing == 1)
    {
        if (node->children)
        {
            GList *children = g_hash_table_get_values (node->children);
            GList *iter;
            for (iter = children; iter; iter = g_list_next (iter))
            {
                struct database_node *child = iter->data;
                db_node_delete (child);
            }
            g_hash_table_destroy (node->children);
            node->children = NULL;
            g_list_free (children);
        }
        g_free (node->value);
        node->value = NULL;
        g_free (node->key);
        node->key = NULL;
        if (node == root)
            root = NULL;
        g_free (node);
    }
    else
    {
        node->removing--;
    }

}

static struct database_node *
db_node_add (struct database_node *parent, const char *key)
{
    struct database_node *new_node = g_malloc0 (sizeof (struct database_node));
    new_node->key = g_strdup (key);
    new_node->parent = parent;
    if (parent)
    {
        if (!parent->children)
        {
            parent->children = g_hash_table_new (g_str_hash, g_str_equal);
        }
        g_hash_table_insert (parent->children, new_node->key, new_node);
    }
    else if (strcmp(key, "") == 0) /* This is a candidate "root" node */
    {
        if (root)
        {
            db_node_delete(new_node);
            new_node = root;
        }
        else
        {
            root = new_node;
        }
    }
    return new_node;
}

void
db_init (void)
{
    pthread_rwlock_wrlock (&db_lock);
    if (!root)
        root = db_node_add (NULL, "");
    pthread_rwlock_unlock (&db_lock);
}

void
db_shutdown (void)
{
    GList *paths = db_search ("");
    if (paths)
    {
        GList *iter;
        for (iter = paths; iter; iter = g_list_next (iter))
            printf ("DB ERROR: path still set %s\n", (char*)iter->data);
        g_list_free_full (paths, g_free);
    }

    pthread_rwlock_wrlock (&db_lock);
    if (root)
        db_node_delete (root);
    pthread_rwlock_unlock (&db_lock);
    root = NULL;
}

static struct database_node *
db_parent_get (const char *path)
{
    struct database_node *node = NULL;
    char *parent = g_strdup (path);

    if (strlen (parent) == 0)
    {
        /* found the root node */
        root = db_node_add (NULL, "");
        g_free (parent);
        return NULL;
    }
    if (strchr (parent, '/') != NULL)
        *strrchr (parent, '/') = '\0';

    if ((node = db_path_to_node (parent, 0)) == NULL)
    {
        db_add_no_lock (parent, NULL, 0);
        node = db_path_to_node (parent, 0);
    }
    g_free (parent);
    return node;
}

uint64_t
db_timestamp (const char *path)
{
    uint64_t timestamp = 0;
    pthread_rwlock_rdlock (&db_lock);
    struct database_node *new_value = db_path_to_node (path, 0);
    if (new_value)
    {
        timestamp = new_value->timestamp;
    }
    pthread_rwlock_unlock (&db_lock);
    return timestamp;
}

static bool
db_add_no_lock (const char *path, const unsigned char *value, size_t length)
{
    uint64_t timestamp = db_calculate_timestamp();

    struct database_node *new_value = db_path_to_node (path, timestamp);
    if (!new_value)
    {
        struct database_node *parent = db_parent_get (path);
        const char *key = NULL;

        if (strchr (path, '/') != NULL)
            key = strrchr (path, '/') + 1;
        else
            key = path;
        new_value = db_node_add (parent, key);
        new_value->timestamp = timestamp;
    }
    g_free (new_value->value);
    new_value->value = NULL;
    if (length > 0)
    {
        new_value->value = g_malloc (length);
        memcpy (new_value->value, value, length);
    }
    new_value->length = length;

    return true;
}

bool
db_add (const char *path, const unsigned char *value, size_t length)
{
    bool ret = false;
    pthread_rwlock_wrlock (&db_lock);
    ret = db_add_no_lock (path, value, length);
    pthread_rwlock_unlock (&db_lock);
    return ret;
}

bool
db_delete (const char *path)
{
    pthread_rwlock_wrlock (&db_lock);
    struct database_node *node = db_path_to_node (path, db_calculate_timestamp ());
    if (node)
        db_node_delete (node);
    pthread_rwlock_unlock (&db_lock);
    return true;
}

bool
db_get (const char *path, unsigned char **value, size_t *length)
{
    pthread_rwlock_rdlock (&db_lock);
    struct database_node *node = db_path_to_node (path, 0);
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
    pthread_rwlock_rdlock (&db_lock);
    GList *children, *iter, *values = NULL;
    struct database_node *node = db_path_to_node (path, 0);
    if (node == NULL || node->children == NULL)
    {
        pthread_rwlock_unlock (&db_lock);
        return NULL;
    }
    children = g_hash_table_get_values (node->children);
    for (iter = children; iter; iter = g_list_next (iter))
    {
        char *value = NULL;
        struct database_node *node = iter->data;
        db_node_to_path (node, &value);
        values = g_list_append (values, value);
    }
    g_list_free (children);
    pthread_rwlock_unlock (&db_lock);
    return values;
}

#ifdef TEST
#define TEST_DB_MAX_ENTRIES 10000
#define TEST_DB_MAX_ITERATIONS 1000

void
test_db_internal_init ()
{
    db_init ();
    CU_ASSERT (root != NULL);
    db_shutdown ();
}

void
test_db_internal_delete ()
{
    struct database_node *node = db_node_add (NULL, "test_node");
    db_node_delete (node);
}

void
test_db_node_to_path ()
{
    db_init ();
    struct database_node *node = db_node_add (NULL, "test_node");
    struct database_node *one = db_node_add (root, "one");
    struct database_node *two = db_node_add (one, "two");
    struct database_node *three = db_node_add (two, "three");
    char *path = NULL;
    db_node_to_path (node, &path);
    CU_ASSERT (strcmp (path, "test_node") == 0);
    g_free (path);
    path = NULL;
    db_node_to_path (three, &path);
    CU_ASSERT (strcmp (path, "/one/two/three") == 0);
    g_free (path);
    db_node_delete (three);
    db_node_delete (node);
}

void
test_db_path_to_node ()
{
    db_init ();
    pthread_rwlock_wrlock (&db_lock);
    struct database_node *one = db_node_add (root, "one");
    struct database_node *two = db_node_add (one, "two");
    struct database_node *rua = db_node_add (one, "rua");
    struct database_node *three = db_node_add (two, "three");
    struct database_node *dos = db_node_add (two, "dos");
    struct database_node *toru = db_node_add (two, "toru");

    CU_ASSERT (db_path_to_node ("", 0) == root);
    CU_ASSERT (db_path_to_node ("/", 0) == root);
    CU_ASSERT (db_path_to_node ("/one", 0) == one);
    CU_ASSERT (db_path_to_node ("/one/two", 0) == two);
    CU_ASSERT (db_path_to_node ("/one/rua", 0) == rua);
    CU_ASSERT (db_path_to_node ("/one/two/three", 0) == three);
    CU_ASSERT (db_path_to_node ("/one/two/dos", 0) == dos);
    CU_ASSERT (db_path_to_node ("/one/two/toru", 0) == toru);
    CU_ASSERT (db_path_to_node ("/uno", 0) == NULL);
    CU_ASSERT (db_path_to_node ("/uno/two", 0) == NULL);
    CU_ASSERT (db_path_to_node ("/one/", 0) == one);

    // nodes not in this list get destroyed as their children are deleted
    db_node_delete (three);
    db_node_delete (dos);
    db_node_delete (toru);
    db_node_delete (rua);

    pthread_rwlock_unlock (&db_lock);
}

void
test_db_init_shutdown ()
{
    db_init ();
    db_shutdown ();
}

void
test_db_add_delete ()
{
    const char *path = "/database/test";
    db_init ();
    CU_ASSERT (db_add (path, (const unsigned char *) "test", strlen ("test") + 1));
    CU_ASSERT (db_delete (path));
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
        CU_ASSERT (db_add (path, (const unsigned char *) "test", strlen ("test") + 1));
        g_free (path);
    }

    start = get_time_us ();
    path = g_strdup_printf ("/database/test%d/test%d",
            TEST_DB_MAX_ENTRIES - 1, TEST_DB_MAX_ENTRIES - 1);
    for (i = 0; i < TEST_DB_MAX_ITERATIONS; i++)
    {
        CU_ASSERT (db_add (path, (const unsigned char *) "test", strlen ("test") + 1));
        CU_ASSERT (db_delete (path));
    }
    printf ("%"PRIu64"us ... ", (get_time_us () - start) / 1000);

    g_free (path);
    for (i = 0; i < TEST_DB_MAX_ENTRIES; i++)
    {
        path = g_strdup_printf ("/database/test%d/test%d", i, i);
        CU_ASSERT (db_delete (path));
        g_free (path);
    }
    db_delete ("");
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
    CU_ASSERT (db_add (path, (const unsigned char *) "test", strlen ("test") + 1));
    CU_ASSERT (db_get (path, (unsigned char **) &value, &length) == true);
    CU_ASSERT (value != NULL);
    CU_ASSERT (length == (strlen ("test") + 1));
    CU_ASSERT (value && strcmp (value, "test") == 0);
    g_free ((void *) value);
    CU_ASSERT (db_delete (path));
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
        db_add (path, (const unsigned char *) "placeholder", strlen ("placeholder") + 1);
        path[strlen (path) - 1]++;
    }
    start = get_time_us ();
    for (i = 0; i < count; i++)
    {
        CU_ASSERT (db_add (path, (const unsigned char *) "test", strlen ("test") + 1));
        CU_ASSERT (db_delete (path));
    }
    printf ("%d=%"PRIu64"us ", path_length, (get_time_us () - start) / count);
    if (!full)
    {
        path[strlen (path) - 1]--;
        db_delete (path);
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
    CU_ASSERT (db_add (path, (const unsigned char *) large, len));
    CU_ASSERT (db_get (path, (unsigned char **) &value, &length) == true);
    CU_ASSERT (value != NULL);
    CU_ASSERT (length == len);
    CU_ASSERT (value && strcmp (value, large) == 0);
    g_free ((void *) value);
    CU_ASSERT (db_delete (path));
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
    CU_ASSERT (db_add (path, (const unsigned char *) "test", strlen ("test") + 1));
    CU_ASSERT (db_get (path, (unsigned char **) &value, &length) == true);
    CU_ASSERT (value != NULL);
    CU_ASSERT (length == (strlen ("test") + 1));
    CU_ASSERT (value && strcmp (value, "test") == 0);
    g_free ((void *) value);
    CU_ASSERT (db_delete (path));
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
        CU_ASSERT (db_add (path, (const unsigned char *) "test", strlen ("test") + 1));
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
        CU_ASSERT (db_delete (path));
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
        CU_ASSERT (db_add (path, (const unsigned char *) value, strlen (value) + 1));
    }
    CU_ASSERT (db_get (path, (unsigned char **) &value, &length) == true);
    CU_ASSERT (value != NULL);
    CU_ASSERT (length == (strlen ("test9") + 1));
    CU_ASSERT (value && strcmp (value, "test9") == 0);
    g_free ((void *) value);
    CU_ASSERT (db_delete (path));
    db_shutdown ();
}

void
test_db_search ()
{
    const char *path = "/database/test";
    GList *paths = NULL;
    db_init ();
    CU_ASSERT (db_add (path, (const unsigned char *) "test", strlen ("test") + 1));
    CU_ASSERT ((paths = db_search ("/database/")) != NULL);
    CU_ASSERT (g_list_length (paths) == 1);
    CU_ASSERT (g_list_find_custom (paths, "/database/test", (GCompareFunc) strcmp) != NULL);
    g_list_free_full (paths, g_free);
    CU_ASSERT (db_delete (path));
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
        CU_ASSERT (db_add (path, (const unsigned char *) "test", strlen ("test") + 1));
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
        CU_ASSERT (db_delete (path));
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

    CU_ASSERT (db_add (path, (const unsigned char *) "test", 5));
    last_ts = db_timestamp (path);
    sleep (1);
    CU_ASSERT (db_add (path2, (const unsigned char *) "test", 5));
    CU_ASSERT (db_timestamp (path2) > last_ts);
    last_ts = db_timestamp (path2);
    CU_ASSERT (db_timestamp (path) < db_timestamp (path2));
    CU_ASSERT (db_timestamp (ppath) >= db_timestamp (path2));
    CU_ASSERT (db_timestamp ("/") >= db_timestamp (ppath));

    CU_ASSERT (db_delete (path2));
    CU_ASSERT (db_timestamp (ppath) > last_ts);
    CU_ASSERT (db_timestamp ("/") >= db_timestamp (ppath));

    CU_ASSERT (db_delete (path));

    db_shutdown ();
}

CU_TestInfo tests_database_internal[] = {
    { "delete", test_db_internal_delete },
    { "node_to_path", test_db_node_to_path },
    { "path_to_node", test_db_path_to_node },
    { "init", test_db_internal_init },
    CU_TEST_INFO_NULL,
};

CU_TestInfo tests_database[] = {
    { "init/shutdown", test_db_init_shutdown },
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
