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
#include "hashtree.h"

struct callback_node
{
    struct hashtree_node hashtree_node;
    GList *exact;
    GList *directory;
    GList *following;
};

struct callback_node *watch_list = NULL;
struct callback_node *validation_list = NULL;
struct callback_node *refresh_list = NULL;
struct callback_node *provide_list = NULL;
struct callback_node *index_list = NULL;
struct callback_node *proxy_list = NULL;

static pthread_mutex_t tree_lock = PTHREAD_MUTEX_INITIALIZER;

cb_info_t *
cb_create (struct callback_node *tree_root, const char *guid, const char *path,
        uint64_t id, uint64_t callback)
{
    cb_info_t *cb = (cb_info_t *) g_malloc0 (sizeof (cb_info_t));
    cb->active = true;
    cb->guid = g_strdup (guid);
    cb->path = g_strdup (path);
    cb->id = id;
    cb->uri = g_strdup_printf (APTERYX_SERVER ".%" PRIu64, cb->id);
    cb->ref = callback;
    g_atomic_int_set (&cb->refcnt, 1);

    g_atomic_int_inc (&cb->refcnt);
    cb->type = cb->path[strlen (cb->path) - 1];

    char *tmp = strdup (path);

    pthread_mutex_lock (&tree_lock);
    if (cb->type == '/')
    {
        tmp[strlen (tmp) - 1] = '\0';
    }

    struct callback_node *node =
        (struct callback_node *) hashtree_path_to_node ((struct hashtree_node *) tree_root,
                                                        tmp);
    if (!node)
    {
        node =
            (struct callback_node *) hashtree_node_add ((struct hashtree_node *) tree_root,
                                                        sizeof (struct callback_node), tmp);
    }
    free (tmp);

    switch (cb->type)
    {
    case '*':
        /* ... and following match */
        node->following = g_list_prepend (node->following, cb);
        break;
    case '/':
        /* directory level match */
        node->directory = g_list_prepend (node->directory, cb);
        break;
    default:
        /* exact match */
        node->exact = g_list_prepend (node->exact, cb);
        break;
    }

    cb->node = node;
    pthread_mutex_unlock (&tree_lock);
    return cb;
}

static void
cb_node_remove (struct callback_node *node)
{
    if (!node)
    {
        return;
    }
    if (node->directory == NULL && node->following == NULL && node->exact == NULL)
    {
        struct callback_node *parent =
            (struct callback_node *) hashtree_parent_get (&node->hashtree_node);

        /* Remove this node from the tree, if it has no children */
        if (parent && hashtree_empty (&node->hashtree_node))
        {
            hashtree_node_delete (&parent->hashtree_node, &node->hashtree_node);
        }

        cb_node_remove (parent);
    }
}

static void
cb_ref (cb_info_t *cb, void *unused)
{
    g_atomic_int_inc (&cb->refcnt);
    return;
}

void
cb_take (cb_info_t *cb)
{
    cb_ref (cb, NULL);
}

static void
cb_free (gpointer data, void *param)
{
    cb_info_t *cb = (cb_info_t *) data;
    DEBUG ("freeing callback for %s / %s\n", cb->path, cb->uri);
    if (cb->node)
    {
        switch (cb->type)
        {
        case '/':
            cb->node->directory = g_list_remove (cb->node->directory, cb);
            break;
        case '*':
            cb->node->following = g_list_remove (cb->node->following, cb);
            break;
        default:
            cb->node->exact = g_list_remove (cb->node->exact, cb);
            break;
        }

        /* Node may need removing from the tree... */
        cb_node_remove (cb->node);
        cb->node = NULL;
    }


    if (cb->guid)
    {
        g_free ((void *) cb->guid);
    }
    if (cb->path)
    {
        g_free ((void *) cb->path);
    }
    if (cb->uri)
    {
        g_free ((void *) cb->uri);
    }
    g_free (cb);
}

void
cb_disable (cb_info_t *cb)
{
    cb->active = false;
}

void
cb_release_no_lock (cb_info_t *cb)
{
    if (!cb)
    {
        return;
    }

    if (g_atomic_int_dec_and_test (&cb->refcnt))
    {
        cb_free (cb, NULL);
    }
}


void
cb_release (cb_info_t *cb)
{
    pthread_mutex_lock (&tree_lock);
    cb_release_no_lock (cb);
    pthread_mutex_unlock (&tree_lock);
}


static GList *
cb_gather_search (struct callback_node *node, GList *callbacks_so_far, const char *path)
{
    /* Terminating condition */
    if (strlen (path) == 0 || strcmp (path, "/") == 0)
    {
        GList *children = hashtree_children_get (&node->hashtree_node);
        for (GList *iter = children; iter; iter = iter->next)
        {
            struct callback_node *child = iter->data;
            if (g_list_length (child->exact) > 0 || !hashtree_empty (&child->hashtree_node))
            {
                callbacks_so_far =
                    g_list_prepend (callbacks_so_far, g_strdup (child->hashtree_node.key));
            }
        }
        g_list_free (children);
        return callbacks_so_far;
    }

    char *tmp = strdup (path + 1);
    if (strchr (tmp, '/'))
    {
        *strchr (tmp, '/') = '\0';
    }

    struct hashtree_node *next_stage = hashtree_path_to_node (&node->hashtree_node, "/*");
    if (next_stage)
    {
        callbacks_so_far =
            cb_gather_search ((struct callback_node *) next_stage, callbacks_so_far,
                              path + strlen (tmp) + 1);
    }

    char *with_leading_slash = NULL;
    if (asprintf (&with_leading_slash, "/%s", tmp) < 0)
        return callbacks_so_far;

    next_stage = hashtree_path_to_node (&node->hashtree_node, with_leading_slash);
    if (next_stage)
    {
        callbacks_so_far =
            cb_gather_search ((struct callback_node *) next_stage, callbacks_so_far,
                              path + strlen (with_leading_slash));
    }
    free (with_leading_slash);

    free (tmp);

    return callbacks_so_far;
}

GList *
cb_search (struct callback_node *node, const char *path)
{
    GList *matches = NULL;
    GList *full = NULL;

    pthread_mutex_lock (&tree_lock);
    matches = cb_gather_search (node, matches, path);
    pthread_mutex_unlock (&tree_lock);
    for (GList *iter = matches; iter; iter = iter->next)
    {
        if (strcmp ((char *) iter->data, "*") != 0)
        {
            full =
                g_list_prepend (full, g_strdup_printf ("%s%s", path, (char *) iter->data));
        }
    }
    g_list_free_full (matches, g_free);
    return full;
}

static GList *
cb_gather (struct callback_node *node, GList *callbacks_so_far, const char *path)
{
    callbacks_so_far = g_list_concat (g_list_copy (node->following), callbacks_so_far);

    /* Terminating condition */
    if (strlen (path) == 0 || !strchr (path + 1, '/'))
    {
        callbacks_so_far = g_list_concat (g_list_copy (node->directory), callbacks_so_far);

        struct hashtree_node *next_stage =
            hashtree_path_to_node (&node->hashtree_node, "/*");
        if (next_stage)
        {
            callbacks_so_far =
                g_list_concat (g_list_copy
                               (((struct callback_node *) next_stage)->following),
                               callbacks_so_far);
        }

        node = (struct callback_node *) hashtree_path_to_node (&node->hashtree_node, path);
        if (node)
        {
            callbacks_so_far = g_list_concat (g_list_copy (node->exact), callbacks_so_far);
        }

        return callbacks_so_far;
    }

    char *tmp = strdup (path + 1);
    if (strchr (tmp, '/'))
    {
        *strchr (tmp, '/') = '\0';
    }

    struct hashtree_node *next_stage = hashtree_path_to_node (&node->hashtree_node, "/*");
    if (next_stage)
    {
        callbacks_so_far = cb_gather ((struct callback_node *) next_stage,
                                      callbacks_so_far, path + strlen (tmp) + 1);
    }

    if (strlen (tmp) > 0)
    {
        char *with_leading_slash = NULL;
        if (asprintf (&with_leading_slash, "/%s", tmp) < 0)
            return callbacks_so_far;

        next_stage = hashtree_path_to_node (&node->hashtree_node, with_leading_slash);
        if (next_stage)
        {
            callbacks_so_far = cb_gather ((struct callback_node *) next_stage,
                                          callbacks_so_far,
                                          path + strlen (with_leading_slash));
        }
        free (with_leading_slash);
    }

    free (tmp);

    return callbacks_so_far;
}

GList *
cb_match (struct callback_node *list, const char *path)
{
    GList *matches = NULL;
    GList *next = NULL;
    pthread_mutex_lock (&tree_lock);
    matches = cb_gather (list, matches, path);

    next = matches;

    /* Remove inactive callbacks (without copying list) */
    while (next)
    {
        GList *spot = next;
        cb_info_t *cb = next->data;
        next = g_list_next (next);
        if (!cb)
        {
            break;
        }

        if (!cb->active)
        {
            if (spot->prev)
            {
                spot->prev->next = spot->next;
            }
            else
            {
                matches = spot->next;
            }

            if (spot->next)
            {
                spot->next->prev = spot->prev;
            }

            spot->next = NULL;

            g_list_free (spot);
        }

    }

    g_list_foreach (matches, (GFunc) cb_ref, NULL);
    pthread_mutex_unlock (&tree_lock);
    return matches;
}

struct callback_node *
cb_init (void)
{
    return (struct callback_node *) hashtree_init (sizeof (struct callback_node));
}

static void
cb_detach (void *data, void *unused)
{
    cb_info_t *cb = data;
    cb->node = NULL;
}

static void
cb_tree_destroy (struct callback_node *node)
{
    if (!node)
    {
        return;
    }

    GList *list = hashtree_children_get (&node->hashtree_node);

    g_list_foreach (node->directory, cb_detach, NULL);
    g_list_foreach (node->exact, cb_detach, NULL);
    g_list_foreach (node->following, cb_detach, NULL);

    /* Calling cb_release will alter these lists (and free them) - so we need
     * to pass a copy.
     */
    g_list_free_full (g_list_copy (node->directory), (GDestroyNotify) cb_release_no_lock);
    g_list_free_full (g_list_copy (node->exact), (GDestroyNotify) cb_release_no_lock);
    g_list_free_full (g_list_copy (node->following), (GDestroyNotify) cb_release_no_lock);

    /* This must be called before hashtree_node_delete */
    g_list_free_full (list, (GDestroyNotify) cb_tree_destroy);

    g_list_free (node->directory);
    g_list_free (node->exact);
    g_list_free (node->following);

    hashtree_node_delete (NULL, &node->hashtree_node);
}

void
cb_shutdown (struct callback_node *node)
{
    /* Cleanup callback sets */
    pthread_mutex_lock (&tree_lock);
    cb_tree_destroy (node);
    pthread_mutex_unlock (&tree_lock);
    return;
}

#ifdef TEST
#define TEST_CB_MAX_ENTRIES 100000
#define TEST_CB_MAX_ITERATIONS 100

void
test_cb_init ()
{
    struct callback_node *root = cb_init ();
    cb_shutdown (root);
}

void
test_cb_match ()
{
    GList *matches = NULL;
    cb_info_t *cb = NULL;
    /* Wildcard in path */
    struct callback_node *watch_list = cb_init ();
    cb = cb_create (watch_list, "tester", "/firewall/rules/*/app", 1, 0);
    cb_release (cb);
    matches = cb_match (watch_list, "/firewall/rules/10/app");
    CU_ASSERT (matches != NULL);
    g_list_foreach (matches, (GFunc) cb_disable, NULL);
    g_list_free_full (matches, (GDestroyNotify) cb_release);

    matches = cb_match (watch_list, "/firewall/rules/10");
    CU_ASSERT (matches == NULL);
    g_list_foreach (matches, (GFunc) cb_disable, NULL);
    g_list_free_full (matches, (GDestroyNotify) cb_release);
    cb_shutdown (watch_list);

    /* directory */
    watch_list = cb_init ();
    cb = cb_create (watch_list, "tester", "/firewall/rules/10/", 2, 0);
    cb_release (cb);

    matches = cb_match (watch_list, "/firewall/rules/10/app");
    CU_ASSERT (matches != NULL);
    g_list_foreach (matches, (GFunc) cb_disable, NULL);
    g_list_free_full (matches, (GDestroyNotify) cb_release);

    matches = cb_match (watch_list, "/firewall/rules/10");
    CU_ASSERT (matches == NULL);
    g_list_foreach (matches, (GFunc) cb_disable, NULL);
    g_list_free_full (matches, (GDestroyNotify) cb_release);
    cb_shutdown (watch_list);

    watch_list = cb_init ();
    cb = cb_create (watch_list, "tester", "/firewall/rules/10/app", 3, 0);
    cb_release (cb);
    matches = cb_match (watch_list, "/firewall/rules/10/app");
    CU_ASSERT (matches != NULL);
    g_list_foreach (matches, (GFunc) cb_disable, NULL);
    g_list_free_full (matches, (GDestroyNotify) cb_release);

    matches = cb_match (watch_list, "/firewall/rules/10");
    CU_ASSERT (matches == NULL);
    g_list_foreach (matches, (GFunc) cb_disable, NULL);
    g_list_free_full (matches, (GDestroyNotify) cb_release);
    cb_shutdown (watch_list);

    watch_list = cb_init ();
    cb = cb_create (watch_list, "tester", "/firewall/rules/10", 4, 0);
    cb_release (cb);

    matches = cb_match (watch_list, "/firewall/rules/10/app");
    CU_ASSERT (matches == NULL);
    g_list_foreach (matches, (GFunc) cb_disable, NULL);
    g_list_free_full (matches, (GDestroyNotify) cb_release);
    matches = cb_match (watch_list, "/firewall/rules/10");
    CU_ASSERT (matches != NULL);
    g_list_foreach (matches, (GFunc) cb_disable, NULL);
    g_list_free_full (matches, (GDestroyNotify) cb_release);
    cb_shutdown (watch_list);

    watch_list = cb_init ();
    cb = cb_create (watch_list, "tester", "/firewall/rules/*", 5, 0);
    cb_release (cb);

    matches = cb_match (watch_list, "/firewall/rules/10/app");
    CU_ASSERT (matches != NULL);
    g_list_free_full (matches, (GDestroyNotify) cb_release);

    matches = cb_match (watch_list, "/firewall/rules/10");
    CU_ASSERT (matches != NULL);
    g_list_free_full (matches, (GDestroyNotify) cb_release);

    matches = cb_match (watch_list, "/firewall/rules");
    CU_ASSERT (matches == NULL);
    g_list_foreach (matches, (GFunc) cb_disable, NULL);
    g_list_free_full (matches, (GDestroyNotify) cb_release);

    cb_shutdown (watch_list);
}

void
test_cb_release ()
{
    cb_info_t *cb;
    struct callback_node *watch_list = cb_init ();
    cb = cb_create (watch_list, "abc", "/test", 1, 0);
    cb_release (cb);
    CU_ASSERT (g_atomic_int_get (&cb->refcnt) == 1);
    cb_release (cb);
    CU_ASSERT (hashtree_empty (&watch_list->hashtree_node));
    cb_shutdown (watch_list);
}

void
test_cb_disable ()
{
    cb_info_t *cb;
    struct callback_node *watch_list = cb_init ();
    cb = cb_create (watch_list, "abc", "/test", 1, 0);

    cb_disable (cb);
    CU_ASSERT (!hashtree_empty (&watch_list->hashtree_node));
    cb_release (cb);
    cb_release (cb);

    CU_ASSERT (hashtree_empty (&watch_list->hashtree_node));
    cb_shutdown (watch_list);
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

    struct callback_node *watch_list = cb_init ();
    for (i = 0; i < TEST_CB_MAX_ENTRIES; i++)
    {
        sprintf (path, "/database/test%d/test%d", i, i);
        sprintf (guid, "%zX", (size_t) g_str_hash (path));
        cb = cb_create (watch_list, guid, path, 1, 0);
        cb_release (cb);
    }
    CU_ASSERT (!hashtree_empty (&watch_list->hashtree_node));

    start = get_time_us ();
    for (i = 0; i < TEST_CB_MAX_ITERATIONS; i++)
    {
        GList *matches;
        int test = index == INDEX_FIRST ? 0 :
            (index == INDEX_LAST ? (TEST_CB_MAX_ENTRIES - 1) :
             random () % TEST_CB_MAX_ENTRIES);
        sprintf (path, "/database/test%d/test%d", test, test);
        matches = cb_match (watch_list, path);
        if (g_list_length (matches) != 1)
            goto exit;
        g_list_free_full (matches, (GDestroyNotify) cb_release);
    }
    printf ("%" PRIu64 "us ... ", (get_time_us () - start) / TEST_CB_MAX_ITERATIONS);
    ret = true;
  exit:
    cb_shutdown (watch_list);
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
    { "match", test_cb_match },
    { "release", test_cb_release },
    { "disable", test_cb_disable },
    { "match performance random", test_cb_match_perf_random },
    { "match performance first", test_cb_match_perf_first },
    { "match performance last", test_cb_match_perf_last },
    CU_TEST_INFO_NULL,
};
#endif
