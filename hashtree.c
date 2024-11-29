
#include <assert.h>
#include "hashtree.h"
#include "string-cache.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

struct hashtree_node *
hashtree_path_to_node (struct hashtree_node *root, const char *path)
{
    char *ptr = NULL;
    char *key = NULL;
    struct hashtree_node *next = root;
    struct hashtree_node *ret = root;

    char *p = g_strdup (path);

    key = strtok_r (p, "/", &ptr);

    while (key)
    {
        ret = next;

        if (next->children)
        {
            next = g_hash_table_lookup (next->children, key);
            ret = next;
        }
        else
        {
            next = NULL;
        }

        if (next == NULL)
        {
            ret = NULL;
            break;
        }

        key = strtok_r (NULL, "/", &ptr);
    }

    g_free (p);
    return ret;
}

struct hashtree_node *
hashtree_node_add (struct hashtree_node *root, size_t size, const char *path)
{
    char *p = g_strdup (path);
    char *ptr = NULL;
    char *key;
    struct hashtree_node *next_node = NULL;
    struct hashtree_node *parent = root;

    key = strtok_r (p, "/", &ptr);

    while (key)
    {
        if (parent->children &&
            (next_node = g_hash_table_lookup (parent->children, key)) != NULL)
        {
            parent = next_node;
        }
        else
        {
            next_node = g_malloc0 (size);
            next_node->parent = parent;
            next_node->key = (char *) string_cache_get (key);
            if (parent->children == NULL)
            {
                parent->children = g_hash_table_new (g_str_hash, g_str_equal);
            }
            g_hash_table_replace (parent->children, next_node->key, next_node);
            parent = next_node;
        }
        key = strtok_r (NULL, "/", &ptr);
    }
    g_free (p);
    return parent;
}

struct hashtree_node *
hashtree_parent_get (struct hashtree_node *node)
{
    return node->parent;
}

void
hashtree_node_delete (struct hashtree_node *root, struct hashtree_node *node)
{
    struct hashtree_node *parent = hashtree_parent_get (node);

    if (parent && parent->children)
    {
        g_hash_table_remove (parent->children, node->key);
    }

    node->parent = NULL;

    if (node->children)
    {
        GList *children = hashtree_children_get (node);
        for (GList * iter = children; iter; iter = g_list_next (iter))
            hashtree_node_delete (node, iter->data);
        g_list_free (children);
        g_hash_table_destroy (node->children);
    }

    string_cache_release (node->key);
    g_free (node);
}

GList *
hashtree_children_get (struct hashtree_node *node)
{
    GList *children = node->children ? g_hash_table_get_values (node->children) : NULL;
    return children;
}

uint64_t
hashtree_node_memuse (struct hashtree_node *node)
{
    /* Exclude the sizeof hashtree_node as that is already accounted for */
    uint64_t memuse = node->key ? string_cache_memuse (node->key, true) : 0;
    if (node->children)
    {
        /* We can't use malloc_usable_size as the hash table is
           alloced in GLIB by who knows what and we can't use
           sizeof as GLIB is hiding the structure. So we guess. */
        memuse += (16 * sizeof (uint64_t));
        /* Each entry uses pointers to a key and value plus a hash */
        guint num_entries = MAX (8, g_hash_table_size (node->children));
        memuse += ((sizeof (gpointer) + sizeof (gpointer) + sizeof (guint)) * num_entries);
    }
    return memuse;
}

bool
hashtree_empty (struct hashtree_node *node)
{
    return node->children == NULL || (g_hash_table_size (node->children) == 0);
}

void *
hashtree_init (size_t element_size)
{
    assert (element_size >= sizeof (struct hashtree_node));
    struct hashtree_node *root = g_malloc0 (element_size);
    return root;
}

void
hashtree_shutdown (struct hashtree_node *root)
{
    hashtree_node_delete (root, root);
}
