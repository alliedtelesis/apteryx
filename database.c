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

static uint64_t
db_calculate_timestamp (void)
{
    struct timespec tms;
    uint64_t micros = 0;
    if (clock_gettime(CLOCK_REALTIME,&tms)) {
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
        *buf = strdup ("");
        end = 1;
    }

    if (node && node->parent)
        db_node_to_path (node->parent, buf);

    char *tmp = NULL;
    if (asprintf (&tmp, "%s%s%s", *buf ? : "", node ? node->key : "/", end ? "" : "/") > 0)
    {
        free (*buf);
        *buf = tmp;
    }
    return tmp;
}

static struct database_node *
db_path_to_node (const char *path)
{
    char *key = strdup (path);
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

        if ((current = g_hash_table_lookup (current->children, key)) == NULL)
            break;
    }

    free (start);
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
        free (node->value);
        free (node->key);
        if (node == root)
            root = NULL;
        free (node);
    }
    else
    {
        node->removing--;
    }

}

struct database_node *
db_node_add (struct database_node *parent, const char *key)
{
    struct database_node *new_node = calloc (1, sizeof (struct database_node));
    new_node->key = strdup (key);
    new_node->parent = parent;
    pthread_rwlock_wrlock (&db_lock);
    if (parent)
    {
        if (!parent->children)
        {
            parent->children = g_hash_table_new (g_str_hash, g_str_equal);
        }
        g_hash_table_insert (parent->children, new_node->key, new_node);
    }
    pthread_rwlock_unlock (&db_lock);
    return new_node;
}

void
db_init (void)
{
    if (!root)
        root = db_node_add (NULL, "");
}

void
db_shutdown (void)
{
    GList *iter, *paths = db_search ("");
    for (iter = paths; iter; iter = g_list_next (iter))
        printf ("DB ERROR: path still set %s\n", (char*)iter->data);
    g_list_free_full (paths, free);

    if (root)
        db_node_delete (root);
    root = NULL;
}

static struct database_node *
db_parent_get (const char *path)
{
    struct database_node *node = NULL;
    char *parent = strdup (path);

    if (strlen (parent) == 0)
    {
        /* found the root node */
        root = db_node_add (NULL, "");
        free (parent);
        return NULL;
    }
    if (strchr (parent, '/') != NULL)
        *strrchr (parent, '/') = '\0';

    if ((node = db_path_to_node (parent)) == NULL)
    {
        db_add (parent, NULL, 0);
        node = db_path_to_node (parent);
    }
    free (parent);
    return node;
}

static void
db_update_parent_timestamp (const char *path, uint64_t timestamp)
{
    struct database_node *node = NULL;
    char *parent = strdup (path);
    if (strlen (parent) == 0)
    {
        /* found the root node */
        node = root;
    }
    else
    {
        if (strchr (parent, '/') != NULL)
            *strrchr (parent, '/') = '\0';

        node = db_path_to_node (parent);
    }
    if (node)
    {
        node->timestamp = timestamp;
        if (node != root)
        {
            db_update_parent_timestamp (parent, timestamp);
        }
    }
    free (parent);
}

uint64_t
db_timestamp (const char *path)
{
    struct database_node *new_value = db_path_to_node (path);
    if (new_value)
        return new_value->timestamp;
    return 0;
}

bool
db_add (const char *path, const unsigned char *value, size_t length)
{
    struct database_node *new_value = db_path_to_node (path);
    if (!new_value)
    {
        struct database_node *parent = db_parent_get (path);
        const char *key = NULL;

        if (strchr (path, '/') != NULL)
            key = strrchr (path, '/') + 1;
        else
            key = path;
        new_value = db_node_add (parent, key);
    }
    pthread_rwlock_wrlock (&db_lock);
    free (new_value->value);
    if (length == 0)
    {
        new_value->value = NULL;
    }
    else
    {
        new_value->value = malloc (length);
        memcpy (new_value->value, value, length);
    }
    new_value->length = length;
    new_value->timestamp = db_calculate_timestamp ();
    db_update_parent_timestamp (path, new_value->timestamp);
    pthread_rwlock_unlock (&db_lock);
    return true;
}

bool
db_delete (const char *path)
{
    pthread_rwlock_wrlock (&db_lock);
    db_update_parent_timestamp (path, db_calculate_timestamp ());
    struct database_node *node = db_path_to_node (path);
    if (node)
        db_node_delete (node);
    pthread_rwlock_unlock (&db_lock);
    return true;
}

bool
db_get (const char *path, unsigned char **value, size_t *length)
{
    pthread_rwlock_rdlock (&db_lock);
    struct database_node *node = db_path_to_node (path);
    if (!node || !node->value)
    {
        pthread_rwlock_unlock (&db_lock);
        return false;
    }
    *value = malloc (node->length);
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
    struct database_node *node = db_path_to_node (path);
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
    free (path);
    path = NULL;
    db_node_to_path (three, &path);
    CU_ASSERT (strcmp (path, "/one/two/three") == 0);
    free (path);
    db_node_delete (three);
    db_node_delete (node);
}

void
test_db_path_to_node ()
{
    db_init ();
    struct database_node *one = db_node_add (root, "one");
    struct database_node *two = db_node_add (one, "two");
    struct database_node *rua = db_node_add (one, "rua");
    struct database_node *three = db_node_add (two, "three");
    struct database_node *dos = db_node_add (two, "dos");
    struct database_node *toru = db_node_add (two, "toru");


    CU_ASSERT (db_path_to_node ("") == root);
    CU_ASSERT (db_path_to_node ("/") == root);
    CU_ASSERT (db_path_to_node ("/one") == one);
    CU_ASSERT (db_path_to_node ("/one/two") == two);
    CU_ASSERT (db_path_to_node ("/one/rua") == rua);
    CU_ASSERT (db_path_to_node ("/one/two/three") == three);
    CU_ASSERT (db_path_to_node ("/one/two/dos") == dos);
    CU_ASSERT (db_path_to_node ("/one/two/toru") == toru);
    CU_ASSERT (db_path_to_node ("/uno") == NULL);
    CU_ASSERT (db_path_to_node ("/uno/two") == NULL);
    CU_ASSERT (db_path_to_node ("/one/") == one);

    // nodes not in this list get destroyed as their children are deleted
    db_node_delete (three);
    db_node_delete (dos);
    db_node_delete (toru);
    db_node_delete (rua);
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
        CU_ASSERT (asprintf (&path, "/database/test%d/test%d", i, i) > 0);
        CU_ASSERT (db_add (path, (const unsigned char *) "test", strlen ("test") + 1));
        free (path);
    }

    start = get_time_us ();
    CU_ASSERT (asprintf
               (&path, "/database/test%d/test%d", TEST_DB_MAX_ENTRIES - 1,
                TEST_DB_MAX_ENTRIES - 1) > 0);
    for (i = 0; i < TEST_DB_MAX_ITERATIONS; i++)
    {
        CU_ASSERT (db_add (path, (const unsigned char *) "test", strlen ("test") + 1));
        CU_ASSERT (db_delete (path));
    }
    printf ("%ldus ... ", (get_time_us () - start) / 1000);

    free (path);
    for (i = 0; i < TEST_DB_MAX_ENTRIES; i++)
    {
        CU_ASSERT (asprintf (&path, "/database/test%d/test%d", i, i) > 0);
        CU_ASSERT (db_delete (path));
        free (path);
    }
    db_delete ("");
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
    free ((void *) value);
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
        CU_ASSERT (asprintf (&path, "/database/test%d/test%d", i, i) > 0);
        CU_ASSERT (db_add (path, (const unsigned char *) "test", strlen ("test") + 1));
        free (path);
    }

    start = get_time_us ();
    CU_ASSERT (asprintf
               (&path, "/database/test%d/test%d", TEST_DB_MAX_ENTRIES - 1,
                TEST_DB_MAX_ENTRIES - 1) > 0);
    for (i = 0; i < TEST_DB_MAX_ITERATIONS; i++)
    {
        CU_ASSERT ((res = db_get (path, (unsigned char **) &value, &length)) == true);
        CU_ASSERT (value != NULL);
        if (!res || !value)
            goto exit;
        free ((void *) value);
    }
    printf ("%ldus ... ", (get_time_us () - start) / 1000);
  exit:
    free (path);
    for (i = 0; i < TEST_DB_MAX_ENTRIES; i++)
    {
        CU_ASSERT (asprintf (&path, "/database/test%d/test%d", i, i) > 0);
        CU_ASSERT (db_delete (path));
        free (path);
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
    free ((void *) value);
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
    g_list_free_full (paths, free);
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
        CU_ASSERT (asprintf (&path, "/database/test%d/test%d", i, i) > 0);
        CU_ASSERT (db_add (path, (const unsigned char *) "test", strlen ("test") + 1));
        free (path);
    }

    start = get_time_us ();
    CU_ASSERT (asprintf (&path, "/database/test%d/", TEST_DB_MAX_ENTRIES - 1) > 0);
    for (i = 0; i < TEST_DB_MAX_ITERATIONS; i++)
    {
        CU_ASSERT ((paths = db_search (path)) != NULL);
        CU_ASSERT (g_list_length (paths) == 1);
        if (g_list_length (paths) != 1)
            goto exit;
        g_list_free_full (paths, free);
    }
    printf ("%ldus ... ", (get_time_us () - start) / 1000);
  exit:
    free (path);
    for (i = 0; i < TEST_DB_MAX_ENTRIES; i++)
    {
        CU_ASSERT (asprintf (&path, "/database/test%d/test%d", i, i) > 0);
        CU_ASSERT (db_delete (path));
        free (path);
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
    CU_ASSERT (db_timestamp (ppath) == db_timestamp (path2));
    CU_ASSERT (db_timestamp ("/") == db_timestamp (ppath));

    CU_ASSERT (db_delete (path2));
    CU_ASSERT (db_timestamp (ppath) > last_ts);

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
    { "get", test_db_get },
    { "get performance", test_db_get_perf },
    { "replace", test_db_replace },
    { "search", test_db_search },
    { "search performance", test_db_search_perf },
    { "timestamping", test_db_timestamping },
    CU_TEST_INFO_NULL,
};
#endif
