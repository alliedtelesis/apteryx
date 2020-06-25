

#ifndef _HASHTREE_H_
#define _HASHTREE_H_H

#include <glib.h>
#include <stdbool.h>
#include <stdint.h>
#include <glib.h>
#include <inttypes.h>

struct hashtree_node
{
    char *key;
    struct hashtree_node *parent;
    GHashTable *children;
    unsigned int removing;
};

struct hashtree_node *hashtree_node_add (struct hashtree_node *root, size_t size,
                                         const char *path);
struct hashtree_node *hashtree_parent_get (struct hashtree_node *node);
struct hashtree_node *hashtree_path_to_node (struct hashtree_node *root, const char *path);
void hashtree_node_delete (struct hashtree_node *root, struct hashtree_node *node);
GList *hashtree_children_get (struct hashtree_node *node);
uint64_t hashtree_node_memuse (struct hashtree_node *node);
bool hashtree_empty (struct hashtree_node *node);
void *hashtree_init (size_t element_size);
void hashtree_shutdown (struct hashtree_node *root);

#endif
