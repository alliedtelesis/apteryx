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
#include <malloc.h>
#include "internal.h"
#include <apteryx.h>
#ifdef TEST
#include <CUnit/CUnit.h>
#include <CUnit/Basic.h>
#endif

#include "hashtree.h"
#include "string-cache.h"

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

static uint64_t
db_memuse_no_lock (struct database_node *node)
{
    uint64_t memuse = 0;
    if (node)
    {
        /* Malloc header + actual size of the database_node */
        memuse = (8 + malloc_usable_size (node));
        /* Size of the value (our share if used by others) */
        memuse += (node->length ? string_cache_memuse ((const char *) node->value, true) : 0);
        /* Size of the key and hash-tree */
        memuse += hashtree_node_memuse (&node->hashtree_node);
        /* Add in the children if any */
        GList *children = hashtree_children_get (&node->hashtree_node);
        for (GList *iter = children; iter; iter = g_list_next (iter))
        {
            memuse += db_memuse_no_lock ((struct database_node *) iter->data);
        }
        g_list_free (children);
    }
    return memuse;
}

uint64_t
db_memuse (const char *path)
{
    struct database_node *node;
    uint64_t memuse = 0;

    pthread_rwlock_rdlock (&db_lock);
    node = (struct database_node *) hashtree_path_to_node (root, path);
    if (node)
    {
        memuse = db_memuse_no_lock (node);
    }
    pthread_rwlock_unlock (&db_lock);
    return memuse;
}

/* Search for or create a node for node under db_node. node
 * may have a name with slashes in it - we will need to set up the chain
 * of database_nodes to reach the end value.
 */
static struct database_node *
_db_align_nodes(struct database_node *db_node, GNode *node, bool create)
{
    if (APTERYX_NAME(node)[0] == '\0')
    {
        return db_node;
    }

    char *name = g_strdup(APTERYX_NAME(node));

    char *tok = NULL;
    char *chunk = strtok_r(name, "/", &tok);

    if (!chunk)
    {
        goto exit;
    }

    do
    {
        /* Find / create the next node down. */
        struct database_node *next_db_node = db_node->hashtree_node.children ?
                                             g_hash_table_lookup (db_node->hashtree_node.children, chunk) :
                                             NULL;

        /* Some callers to this function will require the nodes to be created,
         * others will be happy to know there's nothing here.
         */
        if (!create && !next_db_node)
        {
            db_node = NULL;
            goto exit;
        }
        if (!next_db_node)
        {
            db_node = (struct database_node *) hashtree_node_add (&db_node->hashtree_node,
                                                                  sizeof(struct database_node),
                                                                  chunk);
        }
        else
        {
            db_node = next_db_node;
        }
    } while ((chunk = strtok_r (NULL, "/", &tok)) != NULL);

exit:
    g_free (name);

    return db_node;
}


/* Execute a depth-first update of the database. As nodes are removed
 * we will clean up the parent database node as we head back up the tree.
 *
 * The GNode passed in has a list of children, the database node has a
 * hashtable of children, so there is some mapping to be done between
 * the two.
 */
static bool
_db_update (struct database_node *parent_node, GNode *new_node, uint64_t ts)
{
    struct database_node *db_node;

    if (!parent_node)
     {
         return false;
     }

    if (!new_node)
     {
         return true;
     }

    /* Move db_node along to match this new_node */
    db_node = _db_align_nodes(parent_node, new_node, true);

    /* Got to a leaf node - update / remove values as required */
    if (APTERYX_HAS_VALUE(new_node))
    {
        const char *value = APTERYX_VALUE(new_node);

        string_cache_release ((char *)db_node->value);

        /* We interpret an empty string as removal, so anything else
         * is a value to set. NULL values can be in the tree when
         * doing a query.
         */
        if (value && value[0])
        {
            db_node->value = (unsigned char *) string_cache_get (value);
            db_node->length = strlen(value) + 1;
        }
        else
        {
            db_node->value = NULL;
            db_node->length = 0;
        }

        /* Update times up this tree */
        uint64_t set_time = get_time_us();
        for (struct database_node *ts_update = db_node; ts_update; ts_update = (struct database_node *)ts_update->hashtree_node.parent)
        {
            ts_update->timestamp = set_time;
        }
    }
    else
    {
        /* Non-leaf nodes have children, iterate down them. */
        for (GNode *node = g_node_first_child (new_node); node; node = g_node_next_sibling (node)) {
            if (!_db_update(db_node, node, ts))
            {
                return false;
            }
        }
    }

    /* Having updated both this node and its children, iterate up the tree until we
     * reach either the root passed in, a node with children, or a node with a value.
     */
    while (db_node &&
           db_node != parent_node &&
           db_node->length == 0 &&
           hashtree_empty(&db_node->hashtree_node))
    {
        struct database_node *parent = (struct database_node *)db_node->hashtree_node.parent;
        hashtree_node_delete (root, &db_node->hashtree_node);
        db_node = parent;
    }

    return true;
}

static bool
_db_timestamp_ok (struct database_node *parent_node, GNode *new_node, uint64_t ts)
{
    struct database_node *db_node;
    if (ts == UINT64_MAX)
    {
        return true;
    }

    if (!parent_node)
    {
        return false;
    }

    if (!new_node)
    {
        return true;
    }

    /* Move db_node along to match this new_node - not being able to find
     * one means this node is empty, and we needn't check the timestamp
     */
    db_node = _db_align_nodes(parent_node, new_node, false);

    /* Nothing below here means anything is fine. */
    if (!db_node)
    {
        return true;
    }

    /* Got to a leaf node - check the timestamp. */
    if (APTERYX_HAS_VALUE(new_node))
    {
        if (db_node->timestamp > ts)
        {
            return false;
        }
    }
    else
    {
        /* Non-leaf nodes have children, iterate down them. */
        for (GNode *node = g_node_first_child (new_node); node; node = g_node_next_sibling (node)) {
            if (!_db_timestamp_ok(db_node, node, ts))
            {
                return false;
            }
        }
    }

    return true;

}

bool
db_update_no_lock (GNode *new_data, uint64_t ts)
{
    if (!new_data)
        return true;

    if (!_db_timestamp_ok ((struct database_node*)root, new_data, ts))
    {
        return false;
    }
    return _db_update ((struct database_node*)root, new_data, ts);
}

bool
db_add_no_lock (const char *path, const unsigned char *value, size_t length, uint64_t ts)
{
    uint64_t timestamp = get_time_us();

    if (ts != UINT64_MAX && ts < db_timestamp_no_lock (path))
        return false;

    struct database_node *new_value =
        (struct database_node *) hashtree_path_to_node (root, path);
    if (!new_value)
    {
        new_value =
            (struct database_node *) hashtree_node_add (root, sizeof (*new_value), path);
    }
    string_cache_release ((char *)new_value->value);
    new_value->value = NULL;
    if (length > 0)
    {
        new_value->value = (unsigned char *)string_cache_get ((char *)value);
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
            uint64_t now = get_time_us ();
            struct hashtree_node *iter = node;
            struct hashtree_node *parent = hashtree_parent_get (node);
            while ((iter = hashtree_parent_get (iter)) != NULL)
            {
                ((struct database_node *) iter)->timestamp = now;
            }

            if (((struct database_node *) node)->value != NULL)
            {
                string_cache_release ((char *)((struct database_node *) node)->value);
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
                    char *parent_path = g_strdup (path);
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
        *value = NULL;
        *length = 0;
        return false;
    }
    *value = g_malloc (node->length);
    memcpy (*value, node->value, node->length);
    *length = node->length;
    pthread_rwlock_unlock (&db_lock);
    return true;
}

/* Add depth (-1 for all) layers of children from the database into the node n. */
static void
_db_add_children (GNode *n, struct database_node *parent, int depth)
{
    if (depth > 0)
    {
        if (--depth == 0)
        {
            return;
        }
    }

    GList *children = hashtree_children_get (&parent->hashtree_node);
    if (children)
    {
        for (GList *iter = children; iter; iter = iter->next)
        {
            struct database_node *child = iter->data;
            GNode *next = g_node_new(g_strdup((gchar*)child->hashtree_node.key));
            g_node_prepend(n, next);
            _db_add_children(next, child, depth);
        }
        g_list_free (children);
    }
    else if (parent->length)
    {
        GNode *next = g_node_new(g_strdup((gchar*)parent->value));
        g_node_prepend(n, next);
    }
}

GNode *
db_get_all (const char *path)
{
    /* Move db_node along to match this new_node */
    GNode *new_node = g_node_new(g_strdup(path));
    pthread_rwlock_rdlock (&db_lock);
    struct database_node *db_node = _db_align_nodes((struct database_node*)root, new_node, false);
    if (!db_node)
    {
        pthread_rwlock_unlock (&db_lock);
        return new_node;
    }
    _db_add_children(new_node, db_node, -1);
    pthread_rwlock_unlock (&db_lock);
    return new_node;
}

static GNode *
_db_query_children (GNode *n, struct database_node *parent, GNode *query)
{
    /* We only need to look for values on leaves of a query */
    if (!g_node_first_child (query) || !g_node_first_child (query)->data)
    {
        /* This check doesn't need a * match - they get picked up with the
         * _db_add_children below.
         */
        if (parent->length &&
            (((char*)query->data)[0] == '\0' || strcmp (query->data, parent->hashtree_node.key) == 0))
        {
            g_node_prepend_data(n, g_strdup((char*)parent->value));
            return n;
        }
    }

    for (GNode *query_element = g_node_first_child(query); query_element;
         query_element = g_node_next_sibling(query_element))
    {
        if (query_element->data == NULL)
            continue;
        if (strcmp(query_element->data, "*") == 0)
        {
            if (g_node_first_child(query_element) && g_node_first_child(query_element)->data)
            {
                /* This needs to continue matching down all children. */
                GList *children = hashtree_children_get(&parent->hashtree_node);
                for (GList *iter = children; iter; iter = g_list_next (iter))
                {
                    struct database_node *child = iter->data;
                    _db_query_children (APTERYX_NODE(n, g_strdup(child->hashtree_node.key)), child, query_element);
                }
                g_list_free (children);
            }
            else
            {
                /* This is a terminating * and needs to catch everything (db_get_all) */
                _db_add_children(n, parent, -1);
            }
        }
        else if (strcmp(query_element->data, "") == 0)
        {
            /* Got to a directory match */
            GList *children = hashtree_children_get(&parent->hashtree_node);
            for (GList *iter = children; iter; iter = g_list_next (iter))
            {
                struct database_node *child = iter->data;
                _db_query_children (APTERYX_NODE(n, g_strdup(child->hashtree_node.key)), child, query_element);
            }
            g_list_free (children);
        }
        /* The incoming query is a string - parent length includes the null terminator */
        else if ((strlen(query_element->data)+1) == parent->length &&
                 (memcmp(query_element->data, parent->value, parent->length) == 0))
        {
            /* Got a direct value match */
            g_node_prepend_data(n, g_strdup ((char*)parent->value));
            return n;
        }
        else
        {
            struct database_node *child = parent->hashtree_node.children ?
                                          g_hash_table_lookup(parent->hashtree_node.children, query_element->data) :
                                          NULL;
            if (child)
            {
                _db_query_children (APTERYX_NODE(n, g_strdup(child->hashtree_node.key)), child, query_element);
            }
        }
    }

    if (g_node_first_child(n) == NULL)
    {
        g_free(n->data);
        g_node_destroy(n);
        return NULL;
    }
    return n;
}

GNode *
db_query (GNode *query)
{
    /* Move db_node along as far as we can to match this new_node */
    GNode *new_node = g_node_new(g_strdup(APTERYX_NAME(query)));

    pthread_rwlock_rdlock (&db_lock);
    struct database_node *db_node = _db_align_nodes((struct database_node*)root, new_node, false);
    if (!db_node)
    {
        pthread_rwlock_unlock (&db_lock);
        return new_node;
    }
    new_node = _db_query_children(new_node, db_node, query);
    pthread_rwlock_unlock (&db_lock);
    return new_node;
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
    string_cache_init ();
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
        string_cache_release ((char *)node->value);
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
        uint64_t now = get_time_us ();
        struct hashtree_node *iter = &node->hashtree_node;
        while ((iter = hashtree_parent_get (iter)) != NULL)
        {
            ((struct database_node *) iter)->timestamp = now;
        }
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

void
test_db_update ()
{
    size_t length = 0;
    char *value = NULL;
    GNode *root_node = APTERYX_NODE (NULL, "");
    GNode *node = APTERYX_NODE (root_node, "test");
    node = APTERYX_NODE (node, "eth0");
    GNode *node2 = APTERYX_NODE (node, "statistics");
    node = APTERYX_LEAF (node2, "rx_count", "10");
    node = APTERYX_LEAF (node2, "tx_count", "20");
    node = APTERYX_LEAF (node2, "removed", "");
    node = APTERYX_LEAF (node2, "changed", "changed");

    db_init ();

    /* Install a value to remove with the update */
    CU_ASSERT (db_add ("/test/eth0/statistics/removed", (const unsigned char *) "dummy", strlen ("dummy") + 1, UINT64_MAX));
    /* Install a value to change with the update */
    CU_ASSERT (db_add ("/test/eth0/statistics/changed", (const unsigned char *) "unchanged", strlen ("unchanged") + 1, UINT64_MAX));

    pthread_rwlock_rdlock (&db_lock);
    CU_ASSERT (db_update_no_lock (root_node, UINT64_MAX));

    CU_ASSERT (db_get ("/test/eth0/statistics/rx_count", (unsigned char**)&value, &length) == true);
    CU_ASSERT (value != NULL);
    CU_ASSERT (length == (strlen ("10") + 1));
    CU_ASSERT (value && strcmp (value, "10") == 0);
    g_free ((void *) value);

    db_get ("/test/eth0/statistics/removed", (unsigned char**)&value, &length);
    CU_ASSERT (value == NULL);

    CU_ASSERT (db_get ("/test/eth0/statistics/changed", (unsigned char**)&value, &length) == true);
    CU_ASSERT (value != NULL);
    CU_ASSERT (length == (strlen ("changed") + 1));
    CU_ASSERT (value && strcmp (value, "changed") == 0);
    g_free ((void *) value);

    pthread_rwlock_unlock (&db_lock);

    g_node_destroy(root_node);

    db_prune ("/test");

    db_shutdown ();
}

void
test_db_get_all ()
{
    GNode *root, *node, *child;

    db_init ();

    /* NOTE: GNode does not support values on non-leaf nodes */
    CU_ASSERT (db_add ("/database/test", (const unsigned char *) "test", 5, UINT64_MAX));
    CU_ASSERT (db_add ("/database/test/a", (const unsigned char *) "a", 2, UINT64_MAX));
    CU_ASSERT (db_add ("/database/test/b", (const unsigned char *) "b", 2, UINT64_MAX));
    CU_ASSERT (db_add ("/database/test/c/d", (const unsigned char *) "d", 2, UINT64_MAX));

    CU_ASSERT ((root = db_get_all ("/database/test/a")) != NULL);
    CU_ASSERT (root && APTERYX_HAS_VALUE (root) && strcmp (APTERYX_VALUE (root), "a") == 0);
    apteryx_free_tree (root);

    CU_ASSERT ((root = db_get_all ("/database/test/c")) != NULL);
    CU_ASSERT (root && g_node_n_children (root) == 1);
    child = root ? g_node_first_child (root) : NULL;
    CU_ASSERT (child && strcmp (APTERYX_NAME (child), "d") == 0);
    CU_ASSERT (child && APTERYX_HAS_VALUE (child) && strcmp (APTERYX_VALUE (child), "d") == 0);
    apteryx_free_tree (root);

    CU_ASSERT ((root = db_get_all ("/database")) != NULL);
    CU_ASSERT (root && g_node_n_children (root) == 1);
    node = root ? g_node_first_child (root) : NULL;
    CU_ASSERT (node && strcmp (APTERYX_NAME (node), "test") == 0);
    CU_ASSERT (node && g_node_n_children (node) == 3);
    CU_ASSERT ((child = apteryx_find_child (node, "a")) != NULL);
    CU_ASSERT (child && APTERYX_HAS_VALUE (child) && strcmp (APTERYX_VALUE (child), "a") == 0);
    CU_ASSERT ((child = apteryx_find_child (node, "b")) != NULL);
    CU_ASSERT (child && APTERYX_HAS_VALUE (child) && strcmp (APTERYX_VALUE (child), "b") == 0);
    CU_ASSERT ((child = apteryx_find_child (node, "c")) != NULL);
    CU_ASSERT (child && g_node_n_children (child) == 1);
    child = child ? g_node_first_child (child) : NULL;
    CU_ASSERT (child && APTERYX_HAS_VALUE (child) && strcmp (APTERYX_VALUE (child), "d") == 0);
    apteryx_free_tree (root);

    db_prune ("/database");
    db_shutdown ();
}

void
test_db_query ()
{
    GNode *query, *root, *node, *child;

    db_init ();

    /* NOTE: GNode does not support values on non-leaf nodes */
    CU_ASSERT (db_add ("/database/test", (const unsigned char *) "test", 5, UINT64_MAX));
    CU_ASSERT (db_add ("/database/test/a", (const unsigned char *) "a", 2, UINT64_MAX));
    CU_ASSERT (db_add ("/database/test/b", (const unsigned char *) "b", 2, UINT64_MAX));
    CU_ASSERT (db_add ("/database/test/c/d", (const unsigned char *) "d", 2, UINT64_MAX));

    query = g_node_new (strdup ("/"));
    apteryx_path_to_node (query, "/database/test/a", NULL);
    CU_ASSERT ((root = db_query (query)) != NULL);
    CU_ASSERT (root && g_node_n_children (root) == 1);
    node = root ? g_node_first_child (root) : NULL;
    CU_ASSERT (node && strcmp (APTERYX_NAME (node), "database") == 0);
    CU_ASSERT (node && g_node_n_children (node) == 1);
    node = node ? g_node_first_child (node) : NULL;
    CU_ASSERT (node && strcmp (APTERYX_NAME (node), "test") == 0);
    CU_ASSERT (node && g_node_n_children (node) == 1);
    node = node ? g_node_first_child (node) : NULL;
    CU_ASSERT (node && strcmp (APTERYX_NAME (node), "a") == 0);
    CU_ASSERT (node && APTERYX_HAS_VALUE (node) && strcmp (APTERYX_VALUE (node), "a") == 0);
    apteryx_free_tree (query);
    apteryx_free_tree (root);

    query = g_node_new (strdup ("/"));
    apteryx_path_to_node (query, "/database/*", NULL);
    CU_ASSERT ((root = db_query (query)) != NULL);
    CU_ASSERT (root && g_node_n_children (root) == 1);
    node = root ? g_node_first_child (root) : NULL;
    CU_ASSERT (node && strcmp (APTERYX_NAME (node), "database") == 0);
    CU_ASSERT (node && g_node_n_children (node) == 1);
    node = node ? g_node_first_child (node) : NULL;
    CU_ASSERT (node && strcmp (APTERYX_NAME (node), "test") == 0);
    CU_ASSERT (node && g_node_n_children (node) == 3);
    CU_ASSERT ((child = apteryx_find_child (node, "a")) != NULL);
    CU_ASSERT (child && APTERYX_HAS_VALUE (child) && strcmp (APTERYX_VALUE (child), "a") == 0);
    CU_ASSERT ((child = apteryx_find_child (node, "b")) != NULL);
    CU_ASSERT (child && APTERYX_HAS_VALUE (child) && strcmp (APTERYX_VALUE (child), "b") == 0);
    CU_ASSERT ((child = apteryx_find_child (node, "c")) != NULL);
    CU_ASSERT (child && g_node_n_children (child) == 1);
    child = child ? g_node_first_child (child) : NULL;
    CU_ASSERT (child && APTERYX_HAS_VALUE (child) && strcmp (APTERYX_VALUE (child), "d") == 0);
    apteryx_free_tree (query);
    apteryx_free_tree (root);

    query = g_node_new (strdup ("/"));
    apteryx_path_to_node (query, "/database/*/a", NULL);
    CU_ASSERT ((root = db_query (query)) != NULL);
    CU_ASSERT (root && g_node_n_children (root) == 1);
    node = root ? g_node_first_child (root) : NULL;
    CU_ASSERT (node && strcmp (APTERYX_NAME (node), "database") == 0);
    CU_ASSERT (node && g_node_n_children (node) == 1);
    node = node ? g_node_first_child (node) : NULL;
    CU_ASSERT (node && strcmp (APTERYX_NAME (node), "test") == 0);
    CU_ASSERT (node && g_node_n_children (node) == 1);
    node = node ? g_node_first_child (node) : NULL;
    CU_ASSERT (node && strcmp (APTERYX_NAME (node), "a") == 0);
    CU_ASSERT (node && APTERYX_HAS_VALUE (node) && strcmp (APTERYX_VALUE (node), "a") == 0);
    apteryx_free_tree (query);
    apteryx_free_tree (root);

    db_prune ("/database");
    db_shutdown ();
}

CU_TestInfo tests_database[] = {
    { "database: add/delete", test_db_add_delete },
    { "database: add/delete performance", test_db_add_delete_perf },
    { "database: large value", test_db_large_value },
    { "database: long path", test_db_long_path },
    { "database: path performance", test_db_path_perf },
    { "database: path exists perf", test_db_path_exists_perf },
    { "database: get", test_db_get },
    { "database: get performance", test_db_get_perf },
    { "database: replace", test_db_replace },
    { "database: search", test_db_search },
    { "database: search performance", test_db_search_perf },
    { "database: timestamping", test_db_timestamping },
    { "database: update simple", test_db_update },
    { "database: get_all", test_db_get_all },
    { "database: db_query", test_db_query },
    CU_TEST_INFO_NULL,
};
#endif
