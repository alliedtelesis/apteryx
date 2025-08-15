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
#include "apteryx.h"

struct callback_node
{
    struct hashtree_node hashtree_node;
    GList *exact;
    GList *directory;
    GList *following;
};

static pthread_mutex_t tree_lock = PTHREAD_MUTEX_INITIALIZER;

cb_info_t *
cb_create (struct callback_node *tree_root, const char *guid, const char *path,
           uint64_t id, uint64_t callback, uint64_t ns, uint64_t flags)
{
    cb_info_t *cb = (cb_info_t *) g_malloc0 (sizeof (cb_info_t));
    cb->active = true;
    cb->guid = g_strdup (guid);
    cb->path = g_strdup (path);
    cb->ns = ns ?: getns ();
    cb->id = id;
    cb->uri = g_strdup_printf (APTERYX_CLIENT, cb->ns, cb->id);
    cb->ref = callback;
    cb->flags = flags;
    g_atomic_int_set (&cb->refcnt, 1);

    g_atomic_int_inc (&cb->refcnt);
    cb->type = cb->path[strlen (cb->path) - 1];

    char *tmp = g_strdup (path);

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
    pthread_mutex_init (&cb->lock, NULL);
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
    if (cb->last_path)
    {
        g_free ((void *) cb->last_path);
    }
    pthread_mutex_destroy (&cb->lock);
    g_free (cb);
}

void
cb_disable (cb_info_t *cb)
{
    cb->active = false;
}

void
cb_tree_disable (struct cb_tree_info *cb)
{
    cb_disable(cb->cb);
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

void
cb_tree_release (struct cb_tree_info *cb)
{
    pthread_mutex_lock (&tree_lock);
    cb_release_no_lock (cb->cb);
    pthread_mutex_unlock (&tree_lock);
    if (cb->data)
    {
        apteryx_free_tree(cb->data);
    }
    g_free (cb);
}

static GList *
cb_gather_search (struct callback_node *node, GList *callbacks_so_far, const char *path)
{
    /* If we have got to the end of the search path then exact matches,
     * or nodes with children with directory / lower matches need to
     * be returned.
     */
    if (strlen (path) == 0)
    {
        if (node->exact || node->following)
        {
            callbacks_so_far = g_list_prepend (callbacks_so_far, g_strdup (""));
        }

        GList *children = hashtree_children_get (&node->hashtree_node);
        for (GList *iter = children; iter; iter = iter->next)
        {
            struct callback_node *child = iter->data;
            if (child->directory ||
                !hashtree_empty (&child->hashtree_node))
            {
                callbacks_so_far =
                    g_list_prepend (callbacks_so_far, g_strdup (child->hashtree_node.key));
            }
        }
        g_list_free (children);
        return callbacks_so_far;
    }

    /* If we get down to a trailing slash we need the children of this node,
     * but not the node itself.
     */
    if (strcmp (path, "/") == 0)
    {
        GList *children = hashtree_children_get (&node->hashtree_node);
        for (GList *iter = children; iter; iter = iter->next)
        {
            struct callback_node *child = iter->data;
            callbacks_so_far =
                g_list_prepend (callbacks_so_far, g_strdup (child->hashtree_node.key));
        }
        g_list_free (children);
        return callbacks_so_far;
    }

    char *tmp = strdup (path + 1);
    if (strchr (tmp, '/'))
    {
        *strchr (tmp, '/') = '\0';
    }

    /* If this callback tree has a wildcard node we need to follow down that branch. */
    struct hashtree_node *next_stage = hashtree_path_to_node (&node->hashtree_node, "/*");
    if (next_stage)
    {
        callbacks_so_far =
            cb_gather_search ((struct callback_node *) next_stage, callbacks_so_far,
                              path + strlen (tmp) + 1);
    }
    /* Directory match and we are matching to this node */
    if (node->directory && strlen(path + strlen (tmp) + 1) == 0)
    {
        callbacks_so_far = g_list_prepend (callbacks_so_far, g_strdup (""));
    }

    char *with_leading_slash = NULL;
    if (asprintf (&with_leading_slash, "/%s", tmp) < 0)
        return callbacks_so_far;

    /* Find the next piece and move down. */
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
            char *npath = g_strdup_printf ("%s%s",
                                           strlen (path) > 0 ? path : "/",
                                           (char *) iter->data);
            full = g_list_prepend (full, npath);
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

        /* End of path wildcard - collect everything from here down */
        if (g_strcmp0 (path, "/*") == 0 && node->hashtree_node.children)
        {
            GList *values = g_hash_table_get_values (node->hashtree_node.children);
            for (GList *iter = values; iter; iter = g_list_next (iter))
            {
                struct callback_node *cb = (struct callback_node *) iter->data;
                if (g_strcmp0 (cb->hashtree_node.key, "*") != 0)
                {
                    char *_path;
                    if (cb->hashtree_node.children)
                        _path = g_strdup_printf ("/%s/*", cb->hashtree_node.key);
                    else
                        _path = g_strdup_printf ("/%s", cb->hashtree_node.key);
                    callbacks_so_far = cb_gather (node, callbacks_so_far, _path);
                    free (_path);
                }
            }
            g_list_free (values);
        }

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

    char *tmp = g_strdup (path + 1);
    if (strchr (tmp, '/'))
    {
        *strchr (tmp, '/') = '\0';
    }

    /* Match wildcard path element */
    if (g_strcmp0 (tmp, "*") == 0 && node->hashtree_node.children)
    {
        /* Match next stage callbacks that have non wildcard path elements */
        GList *values = g_hash_table_get_values (node->hashtree_node.children);
        for (GList *iter = values; iter; iter = g_list_next (iter))
        {
            char *key = ((struct hashtree_node *)iter->data)->key;
            if (g_strcmp0 (key, "*") != 0)
            {
                char *npath = g_strdup_printf ("/%s%s", key, path + strlen (tmp) + 1);
                callbacks_so_far = cb_gather (node, callbacks_so_far, npath);
                free (npath);
            }
        }
        g_list_free (values);
        free (tmp);
        return callbacks_so_far;
    }

    /* Match non-wildcard to all wildcard callbacks */
    struct hashtree_node *next_stage = hashtree_path_to_node (&node->hashtree_node, "/*");
    if (next_stage)
    {
        callbacks_so_far = cb_gather ((struct callback_node *) next_stage,
                                    callbacks_so_far, path + strlen (tmp) + 1);
    }

    /* Exact match for non wildcards */
    if (tmp && strlen (tmp) > 0)
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

static gpointer
node_copy (gconstpointer data, gpointer _unused)
{
    return data ? g_strdup ((char*)data) : NULL;
}

static GNode *
deep_copy (GNode *node, bool non_leaves)
{
    /* First copy down*/
    GNode *root;

    if (non_leaves)
    {
        root = g_node_copy_deep (node, node_copy, NULL);
    }
    else
    {
        root = g_node_new ((char*) g_strdup (node->data));
        for (GNode *child = node->children; child; child = child->next)
        {
            if (APTERYX_HAS_VALUE(child))
                g_node_prepend (root, g_node_copy_deep (child, node_copy, NULL));
        }
    }

    /* Then the single path back to the root */
    while (node->parent)
    {
        GNode *next_ancestor = g_node_new (g_strdup ((char*)node->parent->data));
        g_node_prepend (next_ancestor, root);
        root = next_ancestor;
        node = node->parent;
    }
    return root;
}

static struct cb_tree_info *
alloc_cb_tree (cb_info_t *cb, GNode *data, bool non_leaves)
{
    struct cb_tree_info *c = g_malloc0 (sizeof(*c));
    cb_take(cb);
    c->cb = cb;
    c->data = deep_copy(data, non_leaves);
    return c;
}

static GList *
_cb_match_tree_no_lock (struct callback_node *callbacks, GNode *root)
{
    GList *callbacks_to_call = NULL;
    struct callback_node *next_level;

    if (callbacks == NULL || root == NULL)
    {
        return NULL;
    }

    /* We need to break a compound root up to match nicely. */
    if (root->data && strchr ((char*)root->data, '/'))
    {
        void *old_root_data = root->data;
        GNode *new_root = APTERYX_NODE(NULL, g_strdup (""));

        GNode *last_bit = apteryx_path_to_node (new_root, root->data, NULL);

        assert (last_bit);

        last_bit->children = root->children;
        root->data = last_bit->data;
        root->parent = last_bit->parent;

        callbacks_to_call = _cb_match_tree_no_lock (callbacks, new_root);

        last_bit->children = NULL;
        root->data = old_root_data;
        root->parent = NULL;

        apteryx_free_tree (new_root);
        return callbacks_to_call;
    }

    /* Find a wildcard match for matching a whole tree */
    struct callback_node *wildcard_match = (struct callback_node*) hashtree_path_to_node (&callbacks->hashtree_node, "*");
    for (GList *iter = wildcard_match ? wildcard_match->following : NULL;
         iter; iter = iter->next)
    {
        struct cb_tree_info *c = alloc_cb_tree (iter->data, root, true);
        callbacks_to_call = g_list_prepend (callbacks_to_call, c);
    }

    /* Get the next step down the tree */
    for (GNode *child = root->children; child; child = child->next)
    {
        if (G_NODE_IS_LEAF(child))
        {
            for (GList *iter = callbacks->exact; iter; iter = iter->next)
            {
                struct cb_tree_info *c = alloc_cb_tree (iter->data, root, true);
                callbacks_to_call = g_list_prepend (callbacks_to_call, c);
            }
        }
        else
        {
            /* Follow down a key match */
            next_level = (struct callback_node*) hashtree_path_to_node (&callbacks->hashtree_node, child->data);
            if (next_level)
                callbacks_to_call = g_list_concat (_cb_match_tree_no_lock (next_level, child), callbacks_to_call);

            /* Follow down a wildcard match */
            next_level = (struct callback_node*) hashtree_path_to_node (&callbacks->hashtree_node, "*");
            if (next_level)
            {
                callbacks_to_call = g_list_concat (_cb_match_tree_no_lock (next_level, child), callbacks_to_call);
            }
        }
    }

    /* Check to see if there are any directory level values in this tree
     */
    if (callbacks->directory)
    {
        /* Add all directory matches for this tree */
        bool has_leaf_child = false;
        for (GNode *key = root->children; key && !has_leaf_child; key = key->next)
        {
            for (GNode *value = key->children; value && !has_leaf_child; value = value->next)
            {
                if (G_NODE_IS_LEAF(value))
                {
                    has_leaf_child = true;
                }
            }
        }
        if (has_leaf_child)
        {
            for (GList *iter = callbacks->directory; iter; iter = iter->next)
            {
                struct cb_tree_info *c = alloc_cb_tree (iter->data, root, false);
                callbacks_to_call = g_list_prepend (callbacks_to_call, c);
            }
        }
    }

    return callbacks_to_call;
}

GList *
cb_match_tree (struct callback_node *callbacks, GNode *root)
{
    GList *matches = NULL;

    pthread_mutex_lock (&tree_lock);
    matches = _cb_match_tree_no_lock (callbacks, root);
    pthread_mutex_unlock (&tree_lock);

    return matches;
}

/* Finds if a given path has any callbacks from this tree under it */
static bool
_cb_exists (struct callback_node *node, const char *path)
{
    bool found = false;
    if (node->following)
    {
        return true;
    }

    /* Got only one node left, check here for directory and terminal wildcard */
    if (path[0] != '\0' && !strchr (path + 1, '/'))
    {
        if (node->directory)
        {
            return true;
        }

        struct hashtree_node *next_stage =
            hashtree_path_to_node (&node->hashtree_node, "/*");
        if (next_stage)
        {
            return true;
        }
    }

    /* Down to the final possible node */
    if (path[0] == '\0')
    {
        /* We got to the end of the path, but it has something else below it. */
        if(!hashtree_empty (&node->hashtree_node))
        {
            return true;
        }

        /* Got an exact match */
        if (node->exact || node->directory)
        {
            return true;
        }

        return false;
    }

    char *tmp = g_strdup (path + 1);
    if (strchr (tmp, '/'))
    {
        *strchr (tmp, '/') = '\0';
    }

    struct hashtree_node *next_stage = hashtree_path_to_node (&node->hashtree_node, "/*");
    if (next_stage)
    {
        found = _cb_exists ((struct callback_node *) next_stage, path + strlen (tmp) + 1);
    }

    if (!found && strlen (tmp) > 0)
    {
        char *with_leading_slash = NULL;
        if (asprintf (&with_leading_slash, "/%s", tmp) < 0)
            goto exit;

        next_stage = hashtree_path_to_node (&node->hashtree_node, with_leading_slash);
        if (next_stage)
        {
            found = _cb_exists ((struct callback_node *) next_stage,
                                path + strlen (with_leading_slash));
        }
        free (with_leading_slash);
    }
  exit:
    free (tmp);

    return found;
}

bool
cb_exists (struct callback_node *node, const char *path)
{
    bool result = false;
    pthread_mutex_lock (&tree_lock);
    result = _cb_exists (node, path);
    pthread_mutex_unlock (&tree_lock);
    return result;
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

struct _cb_foreach_t
{
    GFunc func;
    gpointer user_data;
};

static void
_cb_foreach (gpointer key, gpointer value, gpointer user_data)
{
    struct callback_node *list = (struct callback_node *) value;
    struct _cb_foreach_t *cbt = (struct _cb_foreach_t *) user_data;
    cb_foreach (list, cbt->func, cbt->user_data);
    return;
}

void
cb_foreach (struct callback_node *list, GFunc func, gpointer user_data)
{
    struct _cb_foreach_t cbt = {func, user_data};
    g_list_foreach (list->exact, func, user_data);
    g_list_foreach (list->directory, func, user_data);
    g_list_foreach (list->following, func, user_data);
    if (list->hashtree_node.children)
        g_hash_table_foreach (list->hashtree_node.children, _cb_foreach, (gpointer) &cbt);
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
    struct callback_node *watches_list = cb_init ();
    cb = cb_create (watches_list, "tester", "/firewall/rules/*/app", 1, 0, 0, 0);
    cb_release (cb);
    matches = cb_match (watches_list, "/firewall/rules/10/app");
    CU_ASSERT (matches != NULL);
    g_list_foreach (matches, (GFunc) cb_disable, NULL);
    g_list_free_full (matches, (GDestroyNotify) cb_release);

    matches = cb_match (watches_list, "/firewall/rules/10");
    CU_ASSERT (matches == NULL);
    g_list_foreach (matches, (GFunc) cb_disable, NULL);
    g_list_free_full (matches, (GDestroyNotify) cb_release);
    cb_shutdown (watches_list);

    /* directory */
    watches_list = cb_init ();
    cb = cb_create (watches_list, "tester", "/firewall/rules/10/", 2, 0, 0, 0);
    cb_release (cb);

    matches = cb_match (watches_list, "/firewall/rules/10/app");
    CU_ASSERT (matches != NULL);
    g_list_foreach (matches, (GFunc) cb_disable, NULL);
    g_list_free_full (matches, (GDestroyNotify) cb_release);

    matches = cb_match (watches_list, "/firewall/rules/10");
    CU_ASSERT (matches == NULL);
    g_list_foreach (matches, (GFunc) cb_disable, NULL);
    g_list_free_full (matches, (GDestroyNotify) cb_release);
    cb_shutdown (watches_list);

    watches_list = cb_init ();
    cb = cb_create (watches_list, "tester", "/firewall/rules/10/app", 3, 0, 0, 0);
    cb_release (cb);
    matches = cb_match (watches_list, "/firewall/rules/10/app");
    CU_ASSERT (matches != NULL);
    g_list_foreach (matches, (GFunc) cb_disable, NULL);
    g_list_free_full (matches, (GDestroyNotify) cb_release);

    matches = cb_match (watches_list, "/firewall/rules/10");
    CU_ASSERT (matches == NULL);
    g_list_foreach (matches, (GFunc) cb_disable, NULL);
    g_list_free_full (matches, (GDestroyNotify) cb_release);
    cb_shutdown (watches_list);

    watches_list = cb_init ();
    cb = cb_create (watches_list, "tester", "/firewall/rules/10", 4, 0, 0, 0);
    cb_release (cb);

    matches = cb_match (watches_list, "/firewall/rules/10/app");
    CU_ASSERT (matches == NULL);
    g_list_foreach (matches, (GFunc) cb_disable, NULL);
    g_list_free_full (matches, (GDestroyNotify) cb_release);
    matches = cb_match (watches_list, "/firewall/rules/10");
    CU_ASSERT (matches != NULL);
    g_list_foreach (matches, (GFunc) cb_disable, NULL);
    g_list_free_full (matches, (GDestroyNotify) cb_release);
    cb_shutdown (watches_list);

    watches_list = cb_init ();
    cb = cb_create (watches_list, "tester", "/firewall/rules/*", 5, 0, 0, 0);
    cb_release (cb);

    matches = cb_match (watches_list, "/firewall/rules/10/app");
    CU_ASSERT (matches != NULL);
    g_list_free_full (matches, (GDestroyNotify) cb_release);

    matches = cb_match (watches_list, "/firewall/rules/10");
    CU_ASSERT (matches != NULL);
    g_list_free_full (matches, (GDestroyNotify) cb_release);

    matches = cb_match (watches_list, "/firewall/rules");
    CU_ASSERT (matches == NULL);
    g_list_foreach (matches, (GFunc) cb_disable, NULL);
    g_list_free_full (matches, (GDestroyNotify) cb_release);

    cb_shutdown (watches_list);
}

void
test_cb_release ()
{
    cb_info_t *cb;
    struct callback_node *watches_list = cb_init ();
    cb = cb_create (watches_list, "abc", "/test", 1, 0, 0, 0);
    cb_release (cb);
    CU_ASSERT (g_atomic_int_get (&cb->refcnt) == 1);
    cb_release (cb);
    CU_ASSERT (hashtree_empty (&watches_list->hashtree_node));
    cb_shutdown (watches_list);
}

void
test_cb_disable ()
{
    cb_info_t *cb;
    struct callback_node *watches_list = cb_init ();
    cb = cb_create (watches_list, "abc", "/test", 1, 0, 0, 0);

    cb_disable (cb);
    CU_ASSERT (!hashtree_empty (&watches_list->hashtree_node));
    cb_release (cb);
    cb_release (cb);

    CU_ASSERT (hashtree_empty (&watches_list->hashtree_node));
    cb_shutdown (watches_list);
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

    struct callback_node *watches_list = cb_init ();
    for (i = 0; i < TEST_CB_MAX_ENTRIES; i++)
    {
        sprintf (path, "/database/test%d/test%d", i, i);
        sprintf (guid, "%zX", (size_t) g_str_hash (path));
        cb = cb_create (watches_list, guid, path, 1, 0, 0, 0);
        cb_release (cb);
    }
    CU_ASSERT (!hashtree_empty (&watches_list->hashtree_node));

    start = get_time_us ();
    for (i = 0; i < TEST_CB_MAX_ITERATIONS; i++)
    {
        GList *matches;
        int test = index == INDEX_FIRST ? 0 :
            (index == INDEX_LAST ? (TEST_CB_MAX_ENTRIES - 1) :
             random () % TEST_CB_MAX_ENTRIES);
        sprintf (path, "/database/test%d/test%d", test, test);
        matches = cb_match (watches_list, path);
        if (g_list_length (matches) != 1)
            goto exit;
        g_list_free_full (matches, (GDestroyNotify) cb_release);
    }
    printf ("%" PRIu64 "us ... ", (get_time_us () - start) / TEST_CB_MAX_ITERATIONS);
    ret = true;
  exit:
    cb_shutdown (watches_list);
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

static bool test_running = false;
static void *
_cb_exist_locking_thrasher (void *list)
{
    struct callback_node *test_list = list;
    while (test_running)
    {
        cb_info_t *cb =
            cb_create (test_list, "tester", "/test/callback/path/down/*/someplace", 1, 0, 0, 0);
        cb_release (cb);
        /* remove this callback */
        cb_release (cb);
    }

    return NULL;
}

void
test_cb_exist_locking ()
{
    pthread_t thrasher;
    struct callback_node *test_list = cb_init ();

    test_running = true;
    pthread_create (&thrasher, NULL, _cb_exist_locking_thrasher, test_list);
    usleep (1000);
    for (int i = 0; i < TEST_CB_MAX_ITERATIONS * 100; i++)
    {
        cb_exists (test_list, "/test/callback/path/down/here/someplace");
    }
    test_running = false;
    pthread_join (thrasher, NULL);
    cb_shutdown (test_list);
}

void
test_cb_match_tree ()
{
    GList *matches = NULL;
    cb_info_t *cb = NULL;
    GNode *root;
    struct callback_node *watches_list = NULL;

    /* Wildcard in path */
    watches_list = cb_init ();
    cb = cb_create (watches_list, "tester", "/firewall/rules/*/app", 1, 0, 0, 0);
    cb_release (cb);

    /* Simple match on single value*/
    root = APTERYX_NODE(NULL, g_strdup(""));
    apteryx_path_to_node (root, "/firewall/rules/10/app", "google");

    matches = cb_match_tree (watches_list, root);
    CU_ASSERT (g_list_length (matches) == 1);
    for (GList *iter = matches; iter; iter = iter->next)
    {
        struct cb_tree_info *c = iter->data;
        CU_ASSERT(g_node_n_nodes (c->data, G_TRAVERSE_LEAFS) == 1);
    }
    g_list_foreach (matches, (GFunc) cb_tree_disable, NULL);
    g_list_free_full (matches, (GDestroyNotify) cb_tree_release);

    /* Add another 2 nodes, should have three callbacks */
    apteryx_path_to_node (root, "/firewall/rules/20/app", "facebook");
    apteryx_path_to_node (root, "/firewall/rules/30/app", "football");

    matches = cb_match_tree (watches_list, root);
    CU_ASSERT (g_list_length (matches) == 3);
    for (GList *iter = matches; iter; iter = iter->next)
    {
        struct cb_tree_info *c = iter->data;
        CU_ASSERT(g_node_n_nodes (c->data, G_TRAVERSE_LEAFS) == 1);
    }
    g_list_foreach (matches, (GFunc) cb_tree_disable, NULL);
    g_list_free_full (matches, (GDestroyNotify) cb_tree_release);

    /* Add another 2 nodes that should not match, should have three callbacks */
    apteryx_path_to_node (root, "/firewall/rules/20/zone", "united-states");
    apteryx_path_to_node (root, "/firewall/settings/protect", "1");

    matches = cb_match_tree (watches_list, root);
    CU_ASSERT (g_list_length (matches) == 3);

    g_list_foreach (matches, (GFunc) cb_tree_disable, NULL);
    g_list_free_full (matches, (GDestroyNotify) cb_tree_release);
    cb_shutdown (watches_list);
    watches_list = NULL;

    apteryx_free_tree (root);
    root = APTERYX_NODE(NULL, g_strdup ("/firewall"));
    apteryx_path_to_node (root, "/firewall/rule", "10");

    /* Should miss */
    matches = cb_match_tree (watches_list, root);
    CU_ASSERT (matches == NULL);
    g_list_foreach (matches, (GFunc) cb_tree_disable, NULL);
    g_list_free_full (matches, (GDestroyNotify) cb_tree_release);

    watches_list = cb_init ();
    cb = cb_create (watches_list, "tester", "/firewall/rules/*/app", 1, 0, 0, 0);
    cb_release (cb);
    matches = cb_match_tree (watches_list, root);
    CU_ASSERT (matches == NULL);
    g_list_foreach (matches, (GFunc) cb_tree_disable, NULL);
    g_list_free_full (matches, (GDestroyNotify) cb_tree_release);
    cb_shutdown (watches_list);

    /* directory */
    watches_list = cb_init ();
    cb = cb_create (watches_list, "tester", "/firewall/rules/10/", 2, 0, 0, 0);
    cb_release (cb);
    apteryx_free_tree (root);

     /* Simple match on single value*/
    root = APTERYX_NODE(NULL, g_strdup (""));
    apteryx_path_to_node (root, "/firewall/rules/10/app", "google");

    matches = cb_match_tree (watches_list, root);
    CU_ASSERT (matches != NULL);

    for (GList *iter = matches; iter; iter = iter->next)
    {
        struct cb_tree_info *c = iter->data;
        CU_ASSERT(g_node_n_nodes (c->data, G_TRAVERSE_LEAFS) == 1);
    }

    g_list_foreach (matches, (GFunc) cb_tree_disable, NULL);
    g_list_free_full (matches, (GDestroyNotify) cb_tree_release);

    apteryx_path_to_node (root, "/firewall/rules/10/zone", "united-states");
    matches = cb_match_tree (watches_list, root);
    CU_ASSERT (g_list_length (matches) == 1);

    for (GList *iter = matches; iter; iter = iter->next)
    {
        struct cb_tree_info *c = iter->data;
        CU_ASSERT(g_node_n_nodes (c->data, G_TRAVERSE_LEAFS) == 2);
    }

    g_list_foreach (matches, (GFunc) cb_tree_disable, NULL);
    g_list_free_full (matches, (GDestroyNotify) cb_tree_release);

    /* Data on other node should not be picked up */
    apteryx_path_to_node (root, "/firewall/rules/20/zone", "new-zealand");
    apteryx_path_to_node (root, "/firewall/rules/20/app", "zoom");
    matches = cb_match_tree (watches_list, root);
    CU_ASSERT (g_list_length (matches) == 1);
    for (GList *iter = matches; iter; iter = iter->next)
    {
        struct cb_tree_info *c = iter->data;
        CU_ASSERT(g_node_n_nodes (c->data, G_TRAVERSE_LEAFS) == 2);
    }

    g_list_foreach (matches, (GFunc) cb_tree_disable, NULL);
    g_list_free_full (matches, (GDestroyNotify) cb_tree_release);

    /* Data lower in the tree should not be picked up */
    apteryx_path_to_node (root, "/firewall/rules/10/counters/rx", "10");
    apteryx_path_to_node (root, "/firewall/rules/10/counters/tx", "11");

    matches = cb_match_tree (watches_list, root);
    CU_ASSERT (g_list_length (matches) == 1);
    for (GList *iter = matches; iter; iter = iter->next)
    {
        struct cb_tree_info *c = iter->data;
        CU_ASSERT(g_node_n_nodes (c->data, G_TRAVERSE_LEAFS) == 2);
    }

    g_list_foreach (matches, (GFunc) cb_tree_disable, NULL);
    g_list_free_full (matches, (GDestroyNotify) cb_tree_release);
    cb_shutdown (watches_list);
    apteryx_free_tree (root);

    /* wildcard / watch */
    watches_list = cb_init ();
    cb = cb_create (watches_list, "tester", "/firewall/*", 3, 0, 0, 0);
    cb_release (cb);

    /* Simple match on single value*/
    root = APTERYX_NODE(NULL, g_strdup(""));
    apteryx_path_to_node (root, "/firewall/rules/10/app", "google");

    matches = cb_match_tree (watches_list, root);
    CU_ASSERT (g_list_length (matches) == 1);
    for (GList *iter = matches; iter; iter = iter->next)
    {
        struct cb_tree_info *c = iter->data;
        CU_ASSERT(g_node_n_nodes (c->data, G_TRAVERSE_LEAFS) == 1);
    }
    g_list_foreach (matches, (GFunc) cb_tree_disable, NULL);
    g_list_free_full (matches, (GDestroyNotify) cb_tree_release);
    apteryx_free_tree (root);

    /* Put up 2 sub trees*/
    cb = cb_create (watches_list, "tester", "/entities/*", 3, 0, 0, 0);
    cb_release (cb);
    cb = cb_create (watches_list, "tester2", "/entities/*/children/*/subnets/", 3, 0, 0, 0);
    cb_release (cb);
    root = APTERYX_NODE(NULL, g_strdup ("/entities/united-states"));
    apteryx_path_to_node (root, "/entities/united-states/name", "united-states");
    apteryx_path_to_node (root, "/entities/united-states/children/geoip/name", "geoip");
    apteryx_path_to_node (root, "/entities/united-states/children/geoip/subnets/10.0.0.0_8", "10.0.0.0/8");
    apteryx_path_to_node (root, "/entities/united-states/children/geoip/subnets/20.0.0.0_8", "20.0.0.0/8");

    matches = cb_match_tree (watches_list, root);
    CU_ASSERT (g_list_length (matches) == 2);
    for (GList *iter = matches; iter; iter = iter->next)
    {
        struct cb_tree_info *c = iter->data;
        CU_ASSERT(g_node_n_nodes (c->data, G_TRAVERSE_LEAFS) == 4 ||
                  g_node_n_nodes (c->data, G_TRAVERSE_LEAFS) == 2);
    }
    g_list_foreach (matches, (GFunc) cb_tree_disable, NULL);
    g_list_free_full (matches, (GDestroyNotify) cb_tree_release);
    apteryx_free_tree (root);

    root = APTERYX_NODE(NULL, g_strdup("/entities/united-states"));
    apteryx_path_to_node (root, "/entities/united-states/name", NULL);
    apteryx_path_to_node (root, "/entities/united-states/children/geoip/name", NULL);
    apteryx_path_to_node (root, "/entities/united-states/children/geoip/subnets/10.0.0.0_8", NULL);
    apteryx_path_to_node (root, "/entities/united-states/children/geoip/subnets/20.0.0.0_8", NULL);

    matches = cb_match_tree (watches_list, root);
    CU_ASSERT (g_list_length (matches) == 1);
    for (GList *iter = matches; iter; iter = iter->next)
    {
        struct cb_tree_info *c = iter->data;
        CU_ASSERT(g_node_n_nodes (c->data, G_TRAVERSE_LEAFS) == 4);
    }
    g_list_foreach (matches, (GFunc) cb_tree_disable, NULL);
    g_list_free_full (matches, (GDestroyNotify) cb_tree_release);

    apteryx_free_tree (root);
    cb_shutdown (watches_list);
}

void
test_cb_match_tree_compound_root ()
{
    GList *matches = NULL;
    cb_info_t *cb = NULL;
    GNode *root;
    struct callback_node *watches_list = NULL;

    /* Wildcard in path */
    watches_list = cb_init ();
    cb = cb_create (watches_list, "tester", "/firewall/rules/*/app", 1, 0, 0, 0);
    cb_release (cb);

    /* Simple match on single value*/
    root = APTERYX_NODE(NULL, g_strdup ("/firewall/rules/10"));
    apteryx_path_to_node (root, "/firewall/rules/10/app", "google");

    matches = cb_match_tree (watches_list, root);
    CU_ASSERT (g_list_length (matches) == 1);
    for (GList *iter = matches; iter; iter = iter->next)
    {
        struct cb_tree_info *c = iter->data;
        CU_ASSERT(g_node_n_nodes (c->data, G_TRAVERSE_LEAFS) == 1);
    }
    g_list_foreach (matches, (GFunc) cb_tree_disable, NULL);
    g_list_free_full (matches, (GDestroyNotify) cb_tree_release);
    apteryx_free_tree (root);
    cb_shutdown (watches_list);
}


void
test_cb_match_tree_locking ()
{
    pthread_t thrasher;
    struct callback_node *test_list = cb_init ();

    test_running = true;
    pthread_create (&thrasher, NULL, _cb_exist_locking_thrasher, test_list);
    usleep (1000);
    /* Simple match on single value*/
    GNode *root = APTERYX_NODE(NULL, g_strdup ("/test/callback/path/down/here/someplace"));
    apteryx_path_to_node (root, "/test/callback/path/down/here/someplace", "test value");

    for (int i = 0; i < TEST_CB_MAX_ITERATIONS * 100; i++)
    {
        GList *matches = cb_match_tree (test_list, root);
        g_list_foreach (matches, (GFunc) cb_tree_disable, NULL);
        g_list_free_full (matches, (GDestroyNotify) cb_tree_release);
    }
    test_running = false;
    pthread_join (thrasher, NULL);
    cb_shutdown (test_list);
    apteryx_free_tree (root);
}

CU_TestInfo tests_callbacks[] = {
    { "init", test_cb_init },
    { "match", test_cb_match },
    { "release", test_cb_release },
    { "disable", test_cb_disable },
    { "match performance random", test_cb_match_perf_random },
    { "match performance first", test_cb_match_perf_first },
    { "match performance last", test_cb_match_perf_last },
    { "cb_exist locking", test_cb_exist_locking },
    { "match tree", test_cb_match_tree },
    { "match tree compound root", test_cb_match_tree_compound_root },
    { "match tree locking", test_cb_match_tree_locking },
    CU_TEST_INFO_NULL,
};
#endif
