/**
 * @file apteryx.c
 * API for configuration and state shared between Apteryx processes.
 * Features:
 * - A simple path:value database.
 * - Tree like structure with each node being a value.
 * - Path specified in directory format (e.g. /root/node1/node2).
 * - Searching for nodes children requires substring search of the path.
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
#include <unistd.h>
#include <pthread.h>
#include <poll.h>
#include <semaphore.h>
#include <errno.h>
#include "internal.h"
#include "apteryx.h"
#include <glib.h>

/* Configuration */
bool apteryx_debug = false;                      /* Debug enabled */
static int ref_count = 0;               /* Library reference count */
static pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER; /* Protect globals */

bool
apteryx_init (bool debug_enabled)
{
    /* Increment refcount */
    pthread_mutex_lock (&lock);
    ref_count++;
    apteryx_debug |= debug_enabled;
    if (ref_count == 1)
    {
        /* Initialise the database */
        db_init ();
        /* Initialise the inter-client rpc */
        rpc_init ();
        /* Initialise callbacks to clients */
        cb_init ();
        /* Configuration Set/Get */
        config_init ();
    }
    pthread_mutex_unlock (&lock);

    /* Ready to go */
    if (ref_count == 1)
        DEBUG ("Init: Initialised\n");
    return true;
}

bool
apteryx_shutdown (void)
{
    ASSERT ((ref_count > 0), return false, "SHUTDOWN: Not initialised\n");

    /* Decrement ref count */
    pthread_mutex_lock (&lock);
    ref_count--;
    pthread_mutex_unlock (&lock);

    /* Check if there are still other users */
    if (ref_count > 0)
    {
        DEBUG ("SHUTDOWN: More users (refcount=%d)\n", ref_count);
        return true;
    }

    /* Shutdown */
    DEBUG ("SHUTDOWN: Shutting down\n");
    rpc_shutdown (false);
    db_shutdown (false);
    DEBUG ("SHUTDOWN: Shutdown\n");
    return true;
}


bool
apteryx_shutdown_force (void)
{
    while (ref_count > 0)
        apteryx_shutdown ();
    return true;
}

int
apteryx_process (bool poll)
{
    ASSERT ((ref_count > 0), return false, "PROCESS: Not initialised\n");
//    return rpc_server_process (rpc, poll);
    return 0;
}

bool
apteryx_prune (const char *path)
{
    ASSERT ((ref_count > 0), return false, "PRUNE: Not initialised\n");
    ASSERT (path, return false, "PRUNE: Invalid parameters\n");

    // TODO: notify watchers

    /* Prune from database */
    db_prune (path);

    /* Success */
    return true;
}

bool
apteryx_dump (const char *path, FILE *fp)
{
    char *value = NULL;

    ASSERT ((ref_count > 0), return false, "DUMP: Not initialised\n");
    ASSERT (path, return false, "DUMP: Invalid parameters\n");
    ASSERT (fp, return false, "DUMP: Invalid parameters\n");

    DEBUG ("DUMP: %s\n", path);

    /* Check initialised */
    if (ref_count <= 0)
    {
        ERROR ("DUMP: not initialised!\n");
        assert(ref_count > 0);
        return false;
    }

    if (strlen (path) > 0 && (value = apteryx_get (path)))
    {
        fprintf (fp, "%-64s%s\n", path, value);
        free (value);
    }

    char *_path = NULL;
    int len = asprintf (&_path, "%s/", path);
    if (len >= 0)
    {
        GList *children, *iter;
        children = apteryx_search (_path);
        for (iter = children; iter; iter = g_list_next (iter))
        {
            apteryx_dump ((const char *) iter->data, fp);
        }
        g_list_free_full (children, free);
        free (_path);
    }
    return true;
}

bool
apteryx_cas (const char *path, const char *value, uint64_t ts)
{
    bool db_result = false;
    int validation_result = false;

    ASSERT ((ref_count > 0), return false, "SET: Not initialised\n");
    ASSERT (path, return false, "SET: Invalid parameters\n");

    DEBUG ("SET: %s = %s\n", path, value);

    if (value && value[0] == '\0')
        value = NULL;

    /* Validate first */
    validation_result = rpc_validate_set (path, value);
    if (validation_result < 0)
    {
        DEBUG ("SET: %s = %s refused by validate\n", path, value);
        errno = validation_result;
        return false;
    }

    /* Add/Delete to/from database */
    if (value)
        db_result = db_add_no_lock (path, (unsigned char*)value, strlen (value) + 1, ts);
    else
        db_result = db_delete_no_lock (path, ts);
    if (!db_result)
    {
        DEBUG ("SET: %s = %s refused by DB\n", path, value);
        errno = -EBUSY;
    }

    /* Notify watchers */
    rpc_notify_watchers (path, value);

    return db_result;
}

bool
apteryx_set (const char *path, const char *value)
{
    return apteryx_cas (path, value, UINT64_MAX);
}

bool
apteryx_cas_string (const char *path, const char *key, const char *value, uint64_t ts)
{
    char *full_path;
    size_t len;
    bool res = false;

    /* Create full path */
    if (key)
        len = asprintf (&full_path, "%s/%s", path, key);
    else
        len = asprintf (&full_path, "%s", path);
    if (len)
    {
        res = apteryx_cas (full_path, value, ts);
        free (full_path);
    }
    return res;
}

bool
apteryx_set_string (const char *path, const char *key, const char *value)
{
    return apteryx_cas_string (path, key, value, UINT64_MAX);
}

bool
apteryx_cas_int (const char *path, const char *key, int32_t value, uint64_t ts)
{
    char *full_path;
    size_t len;
    char *v;
    bool res = false;

    /* Create full path */
    if (key)
        len = asprintf (&full_path, "%s/%s", path, key);
    else
        len = asprintf (&full_path, "%s", path);
    if (len)
    {
        /* Store as a string at the moment */
        len = asprintf ((char **) &v, "%d", value);
        if (len)
        {
            res = apteryx_cas (full_path, v, ts);
            free ((void *) v);
        }
        free (full_path);
    }
    return res;
}

bool
apteryx_set_int (const char *path, const char *key, int32_t value)
{
    return apteryx_cas_int (path, key, value, UINT64_MAX);
}

char *
apteryx_get (const char *path)
{
    char *value = NULL;
    size_t vsize = 0;

    ASSERT ((ref_count > 0), return NULL, "GET: Not initialised\n");
    ASSERT (path, return NULL, "GET: Invalid parameters\n");

    DEBUG ("GET: %s\n", path);

    /* Check path */
    if (!path || path[strlen(path)-1] == '/')
    {
        ERROR ("GET: invalid path (%s)!\n", path);
        assert (!apteryx_debug || path);
        return NULL;
    }

    /* Database first */
    if (!db_get (path, (unsigned char**)&value, &vsize))
    {
        /* Provide second */
        if ((value = rpc_provide_get (path)) == NULL)
        {
            DEBUG ("GET: not in database or provided or proxied\n");
        }
    }

    DEBUG ("    = %s\n", value);
    return value;
}

char *
apteryx_get_string (const char *path, const char *key)
{
    char *full_path;
    size_t len;
    char *value = NULL;
    char *str = NULL;

    /* Create full path */
    if (key)
        len = asprintf (&full_path, "%s/%s", path, key);
    else
        len = asprintf (&full_path, "%s", path);
    if (len)
    {
        if ((value = apteryx_get ((const char *) full_path)))
        {
            str = (char *) value;
        }
        free (full_path);
    }
    return str;
}

int32_t
apteryx_get_int (const char *path, const char *key)
{
    char *full_path;
    size_t len;
    char *v = NULL;
    char *rem = NULL;
    int32_t value = -1;

    /* Create full path */
    if (key)
        len = asprintf (&full_path, "%s/%s", path, key);
    else
        len = asprintf (&full_path, "%s", path);
    if (len)
    {
        if (apteryx_debug)
        {
            errno = 0;
        }

        if ((v = apteryx_get (full_path)))
        {
            value = strtol ((char *) v, &rem, 0);

            if (*rem != '\0')
            {
                errno = -ERANGE;
                value = -1;
            }

            free (v);
        }
        else
        {
            errno = -ERANGE;
        }

        if (apteryx_debug && errno == -ERANGE)
        {
            DEBUG ("Cannot represent value as int: %s\n", v);
        }

        free (full_path);
    }
    return value;
}

bool
apteryx_has_value (const char *path)
{
    char *value = NULL;
    value = apteryx_get (path);
    if (value)
    {
        free (value);
        return true;
    }
    return false;
}

GNode *
apteryx_find_child (GNode *parent, const char *name)
{
    GNode *node;

    for (node = g_node_first_child (parent); node; node = node->next)
    {
        if (strcmp (APTERYX_NAME (node), name) == 0)
        {
            return node;
        }
    }
    return NULL;
}

static inline gboolean
_node_free (GNode *node, gpointer data)
{
    free ((void *)node->data);
    return FALSE;
}

void
apteryx_free_tree (GNode* root)
{
    if (root)
    {
        g_node_traverse (root, G_PRE_ORDER, G_TRAVERSE_ALL, -1, _node_free, NULL);
        g_node_destroy (root);
    }
}

static GNode *
merge (GNode *left, GNode *right, int (*cmp) (const char *a, const char *b))
{
    if (!left)
        return right;
    if (!right)
        return left;
    if (cmp (left->data, right->data) < 0)
    {
        left->next = merge (left->next, right, cmp);
        left->next->prev = left;
        left->prev = NULL;
        return left;
    }
    else
    {
        right->next = merge (left, right->next, cmp );
        right->next->prev = right;
        right->prev = NULL;
        return right;
    }
}

static GNode *
split (GNode *head)
{
    GNode *left, *right;
    left = right = head;
    while (right->next && right->next->next)
    {
        right = right->next->next;
        left = left->next;
    }
    right = left->next;
    left->next = NULL;
    return right;
}

static GNode *
merge_sort (GNode *head, int (*cmp) (const char *a, const char *b))
{
    GNode *left, *right;
    if (!head || !head->next)
        return head;
    left = head;
    right = split (left);
    left = merge_sort (left, cmp);
    right = merge_sort (right, cmp);
    return merge (left, right, cmp);
}

void
apteryx_sort_children (GNode *parent, int (*cmp) (const char *a, const char *b))
{
    if (parent)
        parent->children = merge_sort (parent->children, cmp);
}

static char *
_node_to_path (GNode *node, char **buf)
{
    /* don't put a trailing / on */
    char end = 0;
    if (!*buf)
    {
        *buf = strdup ("");
        end = 1;
    }

    if (node && node->parent)
        _node_to_path (node->parent, buf);

    char *tmp = NULL;
    if (asprintf (&tmp, "%s%s%s", *buf ? : "",
            node ? (char*)node->data : "/",
            end ? "" : "/") > 0)
    {
        free (*buf);
        *buf = tmp;
    }
    return tmp;
}

char *
apteryx_node_path (GNode* node)
{
    char *path = NULL;
    _node_to_path (node, &path);
    return path;
}

typedef struct _set_multi_data_t
{
    uint64_t ts;
    bool rc;
} set_multi_data_t;

static gboolean
_set_multi (GNode *node, gpointer data)
{
    set_multi_data_t *smd = (set_multi_data_t *)data;

    if (APTERYX_HAS_VALUE(node))
    {
        char *path = apteryx_node_path (node);
        DEBUG ("SET_TREE: %s = %s\n", path, APTERYX_VALUE (node));
        smd->rc = apteryx_cas (path, APTERYX_VALUE (node), smd->ts);
        if (!smd->rc)
            return true;
    }
    return false;
}

bool
apteryx_cas_tree (GNode* root, uint64_t ts)
{
    set_multi_data_t smd = {};
    const char *path = NULL;
    char *url = NULL;

    ASSERT ((ref_count > 0), return false, "SET_TREE: Not initialised\n");
    ASSERT (root, return false, "SET_TREE: Invalid parameters\n");

    DEBUG ("SET_TREE: %d paths\n", g_node_n_nodes (root, G_TRAVERSE_LEAVES));

    /* Check path */
    path = APTERYX_NAME (root);
    if (path && strcmp (path, "/") == 0)
    {
        path = "";
    }

    if (!path || (strlen (path) > 0 && path[strlen(path) - 1] == '/'))
    {
        ERROR ("SET_TREE: invalid path (%s)!\n", path);
        assert (!apteryx_debug || path);
        free (url);
        return false;
    }

    // TODO - atomic set_tree
    smd.ts = ts;
    smd.rc = true;
    g_node_traverse (root, G_PRE_ORDER, G_TRAVERSE_NON_LEAFS, -1, _set_multi, &smd);
    /* Return result */
    return smd.rc;
}

bool
apteryx_set_tree (GNode* root)
{
    return apteryx_cas_tree (root, UINT64_MAX);
}

typedef struct _traverse_data_t
{
    GNode* root;
    bool done;
} traverse_data_t;

static void
path_to_node (GNode* root, const char *path, const char *value)
{
    const char *next;
    GNode *node;

    if (path && path[0] == '/')
    {
        path++;
        next = strchr (path, '/');
        if (!next)
        {
            APTERYX_LEAF (root, strdup (path), strdup (value));
        }
        else
        {
            char *name = strndup (path, next - path);
            for (node = g_node_first_child (root); node;
                    node = g_node_next_sibling (node))
            {
                if (strcmp (APTERYX_NAME (node), name) == 0)
                {
                    root = node;
                    free (name);
                    break;
                }
            }
            if (!node)
            {
                root = APTERYX_NODE (root, name);
            }
            path_to_node (root, next, value);
        }
    }
    return;
}

static void
_traverse_paths (GNode* root, const char *path)
{
    GList *children, *iter;
    char *value = NULL;
    size_t vsize;

    /* Look for a value - db first */
    if (!db_get (path, (unsigned char**)&value, &vsize))
    {
        /* Provide next */
        value = rpc_provide_get (path);
    }
    if (value)
    {
        if (strcmp (path, root->data) == 0)
        {
            DEBUG ("  %s = %s\n", path, value);
            g_node_append_data (root, (gpointer)strdup (value));
        }
        else
        {
            int slen = strlen (root->data);
            DEBUG ("  %s = %s\n", path + slen, value);
            path_to_node (root, path + slen, value);
        }
    }

    /* Check for children - index first */
    char *path_s = g_strdup_printf ("%s/", path);
    children = rpc_index_search (path_s);
    if (!children)
    {
        /* Search database next */
        children = db_search (path_s);

        /* Append any provided paths */
        GList *providers = NULL;
        providers = cb_match (&provide_list, path_s, CB_MATCH_PART);
        for (iter = providers; iter; iter = g_list_next (iter))
        {
            cb_info_t *provider = iter->data;
            char *ptr, *ppath;
            int len = strlen (path_s);

            if (strcmp (provider->path, path_s) == 0)
                continue;

            ppath = g_strdup (provider->path);
            if ((ptr = strchr (&ppath[len+1], '/')) != 0)
                   *ptr = '\0';
            if (!g_list_find_custom (children, ppath, (GCompareFunc) strcmp))
                children = g_list_prepend (children, ppath);
            else
                g_free (ppath);
        }
        g_list_free_full (providers, (GDestroyNotify) cb_release);
    }
    for (iter = children; iter; iter = g_list_next (iter))
    {
        _traverse_paths (root, (const char *) iter->data);
    }
    g_list_free_full (children, g_free);
    g_free (path_s);
}

GNode*
apteryx_get_tree (const char *path)
{
    char *url = NULL;
    GNode* root = NULL;

    ASSERT ((ref_count > 0), return NULL, "GET_TREE: Not initialised\n");
    ASSERT (path, return NULL, "GET_TREE: Invalid parameters\n");

    DEBUG ("GET_TREE: %s\n", path);

    /* Check path */
    if (!path || path[strlen(path) - 1] == '/')
    {
        ERROR ("GET_TREE: invalid path (%s)!\n", path);
        assert (!apteryx_debug || path);
        return false;
    }

    root = g_node_new (strdup (path));

    /* Traverse paths */
     _traverse_paths (root, path);
    if (!root->children)
    {
        apteryx_free_tree (root);
        root = NULL;
    }

    free (url);
    return root;
}

GList *
apteryx_search (const char *path)
{
    char *url = NULL;
    GList *results = NULL;
    GList *iter = NULL;

    ASSERT ((ref_count > 0), return NULL, "SEARCH: Not initialised\n");
    ASSERT (path, return NULL, "SEARCH: Invalid parameters\n");

    DEBUG ("SEARCH: %s\n", path);

    /* Validate path */
    if (!path ||
        strcmp (path, "/") == 0 ||
        strcmp (path, "/*") == 0 ||
        strcmp (path, "*") == 0 ||
        strlen (path) == 0)
    {
        path = "";
    }
    else if (path[0] != '/' ||
             path[strlen (path) - 1] != '/' ||
             strstr (path, "//") != NULL)
    {
        free (url);
        ERROR ("SEARCH: invalid root (%s)!\n", path);
        assert(!apteryx_debug || path[0] == '/');
        assert(!apteryx_debug || path[strlen (path) - 1] == '/');
        assert(!apteryx_debug || strstr (path, "//") == NULL);
        return NULL;
    }

    /* Indexers first */
    results = rpc_index_search (path);
    if (results)
    {
        DEBUG (" (index result:)\n");
    }
    else
    {
        /* Search database next */
        results = db_search (path);

        /* Append any provided paths */
        GList *providers = NULL;
        providers = cb_match (&provide_list, path, CB_MATCH_PART);
        for (iter = providers; iter; iter = g_list_next (iter))
        {
            cb_info_t *provider = iter->data;
            int len = strlen (path);
            /* If there is a provider for a single node below here it may
             * show as a "*" entry in this list, which is not desirable */
            if (strlen (provider->path) > strlen (path) &&
                provider->path[strlen (path)] == '*')
            {
                continue;
            }
            char *ptr, *provider_path = g_strdup (provider->path);
            if ((ptr = strchr (&provider_path[len ? len : len+1], '/')) != 0)
                *ptr = '\0';
            if (!g_list_find_custom (results, provider_path, (GCompareFunc) strcmp))
                results = g_list_prepend (results, provider_path);
            else
                g_free (provider_path);
        }
        g_list_free_full (providers, (GDestroyNotify) cb_release);
    }

    free (url);
    return results;
}

char *
apteryx_search_simple (const char *path)
{
    GList *paths = apteryx_search (path);
    char *tmp = NULL, *result = NULL;
    GList *iter;

    if (!paths)
    {
        return NULL;
    }
    for (iter = g_list_first (paths); iter; iter = g_list_next (iter))
    {
        if (result)
        {
            ASSERT (asprintf (&tmp, "%s\n%s", result, (char *) iter->data) > 0,
                    tmp = NULL, "SEARCH: Memory allocation failure\n");
        }
        else
        {
            ASSERT (asprintf (&tmp, "%s", (char *) iter->data) > 0, tmp = NULL,
                    tmp = NULL, "SEARCH: Memory allocation failure\n");
        }
        if (result)
            free (result);
        result = tmp;
        tmp = NULL;
    }
    g_list_free_full (paths, free);

    return result;
}

static GList *
search_path (const char *path)
{
    GList *results = NULL;
    GList *iter = NULL;

    /* Indexers first */
    results = rpc_index_search (path);
    if (results)
    {
        DEBUG (" (index result:)\n");
    }
    else
    {
        /* Search database next */
        results = db_search (path);

        /* Append any provided paths */
        GList *providers = NULL;
        providers = cb_match (&provide_list, path, CB_MATCH_PART);
        for (iter = providers; iter; iter = g_list_next (iter))
        {
            cb_info_t *provider = iter->data;
            int len = strlen (path);
            /* If there is a provider for a single node below here it may
             * show as a "*" entry in this list, which is not desirable */
            if (strlen (provider->path) > strlen (path) &&
                provider->path[strlen (path)] == '*')
            {
                continue;
            }
            char *ptr, *provider_path = g_strdup (provider->path);
            if ((ptr = strchr (&provider_path[len ? len : len+1], '/')) != 0)
                *ptr = '\0';
            if (!g_list_find_custom (results, provider_path, (GCompareFunc) strcmp))
                results = g_list_prepend (results, provider_path);
            else
                g_free (provider_path);
        }
        g_list_free_full (providers, (GDestroyNotify) cb_release);
    }
    return results;
}

static char *
get_value (const char *path)
{
    char *value = NULL;
    size_t vsize = 0;

    /* Database first */
    if (!db_get (path, (unsigned char**)&value, &vsize))
    {
        /* Provide second */
        if ((value = rpc_provide_get (path)) == NULL)
        {
            DEBUG ("GET: not in database or provided or proxied\n");
        }
    }

    return value;
}

GList *
apteryx_find (const char *path, const char *value)
{
    GList *possible_matches = NULL;
    GList *iter = NULL;
    char *tmp = NULL;
    char *ptr = NULL;
    char *chunk;
    GList *matches = NULL;

    DEBUG ("FIND: %s = %s\n", path, value);

    /* Remove the trailing key */
    tmp = g_strdup (path);
    if (strrchr (tmp, '*'))
        *strrchr (tmp, '*') = '\0';

    /* Grab first level (from root) */
    chunk = strtok_r( tmp, "*", &ptr);
    if (chunk)
    {
        possible_matches = search_path (chunk);
    }

    /* For each * do a search + add keys, then re-search */
    while ((chunk = strtok_r (NULL, "*", &ptr)) != NULL)
    {
        GList *last_round = possible_matches;
        possible_matches = NULL;
        for (iter = g_list_first (last_round); iter; iter = g_list_next (iter))
        {
            char *next_level = NULL;
            next_level = g_strdup_printf("%s%s", (char*) iter->data, chunk);
            possible_matches = g_list_concat (search_path (next_level), possible_matches);
            g_free (next_level);
        }
        g_list_free_full (last_round, g_free);
    }

    /* Go through each path match and see if all keys match */
    for (iter = g_list_first (possible_matches); iter; iter = g_list_next (iter))
    {
        bool possible_match = true;
        char *key = NULL;
        char *val = NULL;

        key = g_strdup_printf("%s%s", (char*)iter->data,
                          strrchr (path, '*') + 1);
        val = get_value (key);

        /* A "" value on a match maps to no return value from provider / database */
        if (strlen (value) == 0 && val == NULL)
        {
            possible_match = true;
        }
        else if ((strlen (value) == 0 && val != NULL) ||
                (val == NULL && strlen (value) > 0))
        {
            /* Match miss - we can stop checking */
            possible_match = false;
        }
        else if (strcmp (val, value) != 0)
        {
            /* Match miss - we can stop checking */
            possible_match = false;
        }
        g_free (key);
        g_free (val);

        /* All keys match, so this is a good path */
        if (possible_match)
        {
            matches = g_list_prepend (matches, g_strdup ((char*)iter->data));
        }
    }
    g_list_free_full (possible_matches, g_free);
    return matches;
}

//static gboolean
//_find_multi (GNode *node, gpointer data)
//{
//    Apteryx__Find *find = (Apteryx__Find *)data;
//
//    if (APTERYX_HAS_VALUE(node))
//    {
//        char *path = apteryx_node_path (node);
//        Apteryx__PathValue *pv = calloc (1, sizeof (Apteryx__PathValue));
//        DEBUG ("FIND_TREE: %s = %s\n", path, APTERYX_VALUE (node));
//        pv->base.descriptor = &apteryx__path_value__descriptor;
//        pv->path = (char *) path;
//        pv->value = (char *) APTERYX_VALUE (node);
//        find->matches[find->n_matches++] = pv;
//    }
//    return FALSE;
//}

GList *
apteryx_find_tree (GNode *root)
{
//    char *url = NULL;
//    ProtobufCService *rpc_client;
//    Apteryx__Find find = APTERYX__FIND__INIT;
//    search_data_t data = {0};
//    const char *path = APTERYX_NAME(root);
//    int i;
//
//    ASSERT ((ref_count > 0), return NULL, "FIND: Not initialised\n");
//    ASSERT (path, return NULL, "FIND: Invalid parameters\n");
//
//    DEBUG ("FIND_TREE: %s\n", path);
//
//    /* Check path */
//    if (!path ||
//        strcmp (path, "/") == 0 ||
//        strcmp (path, "/*") == 0 ||
//        strcmp (path, "*") == 0 ||
//        strlen (path) == 0)
//    {
//        path = "";
//    }
//    else if (path[0] != '/' ||
//             strstr (path, "//") != NULL)
//    {
//        free (url);
//        ERROR ("FIND: invalid root (%s)!\n", path);
//        assert(!apteryx_debug || path[0] == '/');
//        assert(!apteryx_debug || strstr (path, "//") == NULL);
//        return NULL;
//    }
//
//    /* IPC */
//    rpc_client = rpc_client_connect (rpc, url);
//    if (!rpc_client)
//    {
//        ERROR ("FIND: Path(%s) Failed to connect to server: %s\n", path, strerror (errno));
//        free (url);
//        return false;
//    }
//
//    find.path = (char *) path;
//    find.n_matches = g_node_n_nodes (root, G_TRAVERSE_LEAVES);
//    find.matches = malloc (find.n_matches * sizeof (Apteryx__PathValue *));
//    find.n_matches = 0;
//    g_node_traverse (root, G_PRE_ORDER, G_TRAVERSE_NON_LEAFS, -1, _find_multi, &find);
//
//    apteryx__server__find (rpc_client, &find, handle_search_response, &data);
//    if (!data.done)
//    {
//        ERROR ("FIND: No response\n");
//        rpc_client_release (rpc, rpc_client, false);
//        free (url);
//        return NULL;
//    }
//    rpc_client_release (rpc, rpc_client, true);
//    free (url);
//
//    /* Cleanup message */
//    for (i = 0; i < find.n_matches; i++)
//    {
//        Apteryx__PathValue *pv = find.matches[i];
//        free (pv->path);
//        free (pv);
//    }
//    free (find.matches);
//
//    /* Result */
//    return data.paths;
    return NULL;
}

bool
apteryx_index (const char *path, apteryx_index_callback cb)
{
    return rpc_add_callback (APTERYX_INDEXERS_PATH, path, (void *)cb);
}

bool
apteryx_unindex (const char *path, apteryx_index_callback cb)
{
    return rpc_delete_callback (APTERYX_INDEXERS_PATH, path, (void *)cb);
}

bool
apteryx_watch (const char *path, apteryx_watch_callback cb)
{
    return rpc_add_callback (APTERYX_WATCHERS_PATH, path, (void *)cb);
}

bool
apteryx_unwatch (const char *path, apteryx_watch_callback cb)
{
    return rpc_delete_callback (APTERYX_WATCHERS_PATH, path, (void *)cb);
}

bool
apteryx_validate (const char *path, apteryx_validate_callback cb)
{
    return rpc_add_callback (APTERYX_VALIDATORS_PATH, path, (void *)cb);
}

bool
apteryx_unvalidate (const char *path, apteryx_validate_callback cb)
{
    return rpc_delete_callback (APTERYX_VALIDATORS_PATH, path, (void *)cb);
}

bool
apteryx_provide (const char *path, apteryx_provide_callback cb)
{
    return rpc_add_callback (APTERYX_PROVIDERS_PATH, path, (void *)cb);
}

bool
apteryx_unprovide (const char *path, apteryx_provide_callback cb)
{
    return rpc_delete_callback (APTERYX_PROVIDERS_PATH, path, (void *)cb);
}

uint64_t
apteryx_timestamp (const char *path)
{
    uint64_t value = 0;

    ASSERT ((ref_count > 0), return 0, "TIMESTAMP: Not initialised\n");
    ASSERT (path, return 0, "TIMESTAMP: Invalid parameters\n");

    DEBUG ("TIMESTAMP: %s\n", path);

    /* Lookup value */
    value = db_timestamp (path);

    DEBUG ("    = %"PRIu64"\n", value);
    return value;
}
