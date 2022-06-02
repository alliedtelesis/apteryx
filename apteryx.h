/**
 * @file apteryx.h
 * API for configuration and state shared between Apteryx processes
 *
 * Stores data in a tree like structure with nodes referenced by
 * "paths" that have a file system-like format.
 *   i.e. /root/node1/node2/node3 = value
 *
 * Copyright 2014, Allied Telesis Labs New Zealand, Ltd
 *
 * API:
 *     SET - set the value for the specified path
 *     VALIDATE - accept / deny sets that match the specified path
 *     WATCH - watch for changes in the specified path
 *     GET - get the value stored at the specified path
 *     REFRESH - refresh the value stored at the specified path when required
 *     PROVIDE - provide the value stored at the specified path
 *     SEARCH - look for sub-paths that match the requested root path
 *     INDEX - provide search results for the specified root path
 *     PRUNE - from a requested root path, set values for all sub-paths to NULL
 *     PROXY - proxy gets and sets to the requested path via the specified URL
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
#ifndef _APTERYX_H_
#define _APTERYX_H_
#include <stdio.h>
#include <stdbool.h>
#include <stdint.h>
#include <errno.h>
#include <glib.h>

/** Apteryx configuration
  /apteryx
  /apteryx/debug                           - Apteryx debug
  /apteryx/sockets                         - List of sockets (urls) that apteryxd will accept connections on.
  /apteryx/sockets/-                       - Unique identifier based on HASH(url). Value is the url to listen on.
  /apteryx/watchers                        - List of watched paths and registered callbacks for those watches.
  /apteryx/watchers/-                      - Unique identifier based on PID-CALLBACK-HASH(path). Value is the path.
  /apteryx/refreshers                      - List of refreshed paths and registered callbacks for those refreshers.
  /apteryx/refreshers/-                    - Unique identifier based on PID-CALLBACK-HASH(path). Value is the path.
  /apteryx/providers                       - List of provided paths and registered callbacks for providing gets to that path.
  /apteryx/providers/-                     - Unique identifier based on PID-CALLBACK-HASH(path). Value is the path.
  /apteryx/validators                      - List of validated paths and registered callbacks for validating sets to that path.
  /apteryx/validators/-                    - Unique identifier based on PID-CALLBACK-HASH(path). Value is the path.
  /apteryx/indexers                        - List of indexed paths and registered callbacks for providing search results for that path.
  /apteryx/indexers/-                      - Unique identifier based on PID-CALLBACK-HASH(path). Value is the path.
  /apteryx/proxies                         - List of proxied paths and remote url to proxy gets and sets to.
  /apteryx/proxies/-                       - Unique identifier based on PID-HASH(path)-HASH(url). Value is the full url for the path.
  /apteryx/counters                        - Formatted list of counters and values for Apteryx usage
  /apteryx/statistics                      - Statistics for callback usage
 */
#define APTERYX_PATH                             "/apteryx"
#define APTERYX_DEBUG_PATH                       "/apteryx/debug"
#define APTERYX_DEBUG_DEFAULT                        0
#define APTERYX_DEBUG_DISABLE                        0
#define APTERYX_DEBUG_ENABLE                         1
#define APTERYX_SOCKETS_PATH                     "/apteryx/sockets"
#define APTERYX_WATCHERS_PATH                    "/apteryx/watchers"
#define APTERYX_REFRESHERS_PATH                  "/apteryx/refreshers"
#define APTERYX_PROVIDERS_PATH                   "/apteryx/providers"
#define APTERYX_VALIDATORS_PATH                  "/apteryx/validators"
#define APTERYX_INDEXERS_PATH                    "/apteryx/indexers"
#define APTERYX_PROXIES_PATH                     "/apteryx/proxies"
#define APTERYX_COUNTERS                         "/apteryx/counters"
#define APTERYX_STATISTICS                       "/apteryx/statistics"

/** Initialise this instance of the Apteryx library.
 * @param debug verbose debug to stdout
 * @return true on success
 */
bool apteryx_init (bool debug);

/**
 * Shutdown this instance of the Apteryx library.
 * @return true on success
 */
bool apteryx_shutdown (void);

/**
 * Shutdown all instances of the Apteryx library.
 * NOTE: This function should only be called as a process exits,
 *       as subsequent library calls will fail.
 * @return true on success
 */
bool apteryx_shutdown_force (void);

/**
 * Process callback requests in client thread context.
 * Example:
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
 * @param poll enable polling and disable multi-threaded callbacks
 * @return fd for using select for detecting there is work to process
 */
int apteryx_process (bool poll);

/**
 * Bind the Apteryx server to accepts connections on the specified URL.
 * Can be used to enable remote access to Apteryx (e.g. for proxy).
 * @param url path to bind to
 * @return true on successful (un)binding
 * @return false if the (un)bind fails
 */
bool apteryx_bind (const char *url);
/** Stop accepting connections on the specified URL. */
bool apteryx_unbind (const char *url);

/**
 * Remove a path and all reachable children
 * @param path path to remove
 * @return true on successful removal
 * @return false if the removal fails
 */
bool apteryx_prune (const char *path);

/**
 * Print a path and all reachable children
 * @param path path to print
 * @param fd open file descriptor to print to
 * @return true on successful removal
 * @return false if the removal fails
 */
bool apteryx_dump (const char *path, FILE *fp);

/**
 * Set a path/value in Apteryx with full options
 * @param path path to the value to set
 * @param value value to set at the specified path
 * @param ts monotonic timestamp to be compared to the paths last change time
 * @param wait_for_completion flag that indicates blocking / non-blocking
 *                            watch callbacks from this set
 * @return true on a successful set
 * @return false if the path is invalid
 */
bool apteryx_set_full (const char *path, const char *value, uint64_t ts,
                       bool wait_for_completion);

/**
 * Set a tree of multiple values in Apteryx, with full options
 * @param root pointer to the N-ary tree of nodes.
 * @param ts monotonic timestamp to be compared to the paths last change time
 * @param wait_for_completion flag that indicates blocking / non-blocking
 *                            watch callbacks from this tree set
 * @return true on a successful set
 * @return false if the path is invalid
 */
bool apteryx_set_tree_full (GNode *root, uint64_t ts, bool wait_for_completion);

/**
 * Set a path/value in Apteryx
 * @param path path to the value to set
 * @param value value to set at the specified path
 * @return true on a successful set
 * @return false if the path is invalid
 */
#define apteryx_set(path,value) apteryx_set_full((path), (value), UINT64_MAX, false)

/**
 * Set a path/value in Apteryx and wait for all watches to complete.
 * @param path path to the value to set
 * @param value value to set at the specified path
 * @return true on a successful set after watches are complete
 * @return false if the path is invalid
 */
#define apteryx_set_wait(path,value) apteryx_set_full((path), (value), UINT64_MAX, true)

/** Helper to extend the path with the specified key */
bool apteryx_set_string (const char *path, const char *key, const char *value);
/** Helper to store a simple int at an extended path */
bool apteryx_set_int (const char *path, const char *key, int32_t value);

/**
 * Get a path/value from Apteryx
 * @param path path to the value to get
 * @return value on success
 * @return NULL if the path is invalid
 */
char *apteryx_get (const char *path);
/** Helper to retrieve the value using an extended path based on the specified key */
char *apteryx_get_string (const char *path, const char *key);
char *apteryx_get_string_default (const char *path, const char *key, const char *deflt);
/**
 * Helper to retrieve a simple integer from an extended path
 * @return -1 if the value cannot be represented as an int (and set errno to -ERANGE)
 */
int32_t apteryx_get_int (const char *path, const char *key);
int32_t apteryx_get_int_default (const char *path, const char *key, int32_t deflt);

/**
 * Check if a path has a value in Apteryx
 * @param path path to check that it exists and has a value
 * @return true if the path exists and has a value
 * @return false if the path is invalid or has no value
 */
bool apteryx_has_value (const char *path);

/**
 * Get the last change timestamp in monotonic time of a given path
 * @param path path to get the timestamp for
 * @return 0 if the path doesn't exist, last change timestamp in monotonic time otherwise
 */
uint64_t apteryx_timestamp (const char *path);

/**
 * Get the memory usage in bytes of a given path
 * @param path path to get the memory usage for
 * @return 0 if the path doesn't exist, memory usage in bytes otherwise
 */
uint64_t apteryx_memuse (const char *path);

/**
 * Set a path/value in Apteryx, but only if the existing
 * value has not changed since the specified monotonic timestamp.
 * Can be used for a Compare-And-Swap operation.
 * Example: Safely reserve the next free row in a table
    uint32_t index = 1;
    while (index > 0) {
        if (apteryx_cas_int (path, key, index, 0))
            break;
        index++;
    }
 * Example: Safely updating a 32-bit bitmap
    while (1) {
        uint64_t ts = apteryx_timestamp (path);
        uint32_t bitmap = 0;
        char *value = apteryx_get (path);
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
                return success;
        }
    }
 * @param path path to the value to set
 * @param value value to set at the specified path
 * @param ts monotonic timestamp to be compared to the paths last change time
 * @return true on a successful set
 * @return false if the set failed (errno == -EBUSY if timestamp comparison failed)
 */
#define apteryx_cas(path, value, ts) apteryx_set_full((path), (value), (ts), false)

/**
 * Set a path/value in Apteryx, but only if the existing
 * value has not changed since the specified monotonic timestamp and
 * wait for watch execution to complete.
 * Can be used for a Compare-And-Swap operation.
 * Example: Safely reserve the next free row in a table
    uint32_t index = 1;
    while (index > 0) {
        if (apteryx_cas_int (path, key, index, 0))
            break;
        index++;
    }
 * Example: Safely updating a 32-bit bitmap
    while (1) {
        uint64_t ts = apteryx_timestamp (path);
        uint32_t bitmap = 0;
        char *value = apteryx_get (path);
        if (value)
        {
            sscanf (value, "%"PRIx32, &bitmap);
            free (value);
        }
        bitmap = (bitmap & ~clear) | set;
        if (asprintf (&value, "%"PRIx32, bitmap) > 0) {
            bool success = apteryx_cas_wait (path, value, ts);
            free (value);
            if (success || errno != -EBUSY)
            {
                // If success is true here, watches have completed
                return success;
            }
        }
    }
 * @param path path to the value to set
 * @param value value to set at the specified path
 * @param ts monotonic timestamp to be compared to the paths last change time
 * @return true on a successful set after watches have completed
 * @return false if the set failed (errno == -EBUSY if timestamp comparison failed)
 */
#define apteryx_cas_wait(path, value, ts) apteryx_set_full((path), (value), (ts), true)

/** Helper to extend the path with the specified key */
bool apteryx_cas_string (const char *path, const char *key, const char *value, uint64_t ts);
/** Helper to store a simple int at an extended path */
bool apteryx_cas_int (const char *path, const char *key, int32_t value, uint64_t ts);

/**
 * Helpers for generating and parsing an Apteryx tree.
 * Can be used to set/get multiple values at once.
 * Uses GLIB's GNode based N-ary trees.
 * - Long paths can be concatenated in a single node.
 * - Leaf nodes are values for the leaves parent
 *   e.g. a->b->c->d == /a/b/c = d.
 * - Creator owns the GNode data (names and values).
 * Example:
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
 */
#define APTERYX_NODE(p,n) \
    (p ? (g_node_prepend_data (p, (gpointer)n)) : (g_node_new (n)))
#define APTERYX_LEAF(p,n,v) \
    (g_node_prepend_data (g_node_prepend_data (p, (gpointer)n), (gpointer)v))
#define APTERYX_LEAF_INT(ROOT,KEY,VALUE) \
  do { \
    char *__value = NULL; \
    if (asprintf (&__value, "%i", (VALUE)) >= 0) \
      { \
        APTERYX_LEAF ((ROOT), strdup ((KEY)), __value); \
      } \
  } while (0)
#define APTERYX_LEAF_STRING(ROOT,KEY,VALUE) \
  APTERYX_LEAF ((ROOT), strdup ((KEY)), (VALUE) ? strdup ((VALUE)) : NULL)
#define APTERYX_NUM_NODES(p) \
    (g_node_n_nodes (p, G_TRAVERSE_NON_LEAVES))
#define APTERYX_NAME(n) \
    ((char*)(n)->data)
#define APTERYX_HAS_VALUE(n) \
    (g_node_first_child (n) && G_NODE_IS_LEAF (g_node_first_child (n)))
#define APTERYX_VALUE(n) \
    ((char*)g_node_first_child (n)->data)
#define APTERYX_CHILD_VALUE(n,k) ({ \
    char *__ret = NULL;\
    GNode *__c = apteryx_find_child (n,k);\
    if (__c) { __ret = APTERYX_VALUE (__c); }\
    __ret;\
})

/** Free an N-ary tree of nodes when the data need freeing (e.g. from apteryx_get_tree) */
void apteryx_free_tree (GNode *root);
/** Find the child of the node with the specified name */
GNode *apteryx_find_child (GNode *parent, const char *name);
/** Sort the children of a node using the supplied compare function */
void apteryx_sort_children (GNode *parent, int (*cmp) (const char *a, const char *b));
/** Get the full path of an Apteryx node in an N-ary tree */
char *apteryx_node_path (GNode *node);
/** Descend down the given N-ary tree to find the child at the end of the given path */
GNode *apteryx_path_node (GNode *node, const char *path);
/** Print a tree to fp */
void apteryx_print_tree (GNode *root, FILE *fp);

/**
 * Convert a path into a full N-ary tree. Each node is separated by a slash.
 * @param root Pointer to the existing N-ary tree of nodes
 * @param path Path to convert into the tree
 * @param value Value which the leaf node is set to
 * @return GNode of the last leaf which was added to the tree
 * Example: Create a tree with the ifname set to "eth1"
     GNode *root = g_node_new ("/");
     apteryx_path_to_node (root, "/routing/ipv4/rib/1/ifname", "eth1");
 */
GNode *apteryx_path_to_node (GNode *root, const char *path, const char *value);

/**
 * Convert a query into a full N-ary tree.
 * Supports RFC8040 like query fields.
 * @param parent Pointer to an existing node to attach to
 * @param query query to convert into the tree
 * @return true on a successful conversion
 * @return false on failure
 * Example:
     GNode *root = g_node_new ("/system/time");
     apteryx_query_to_node (root, "time(minutes;seconds);date(month;day)");
     system
       time
         minutes
         seconds
       date
         month
         day
 */
bool apteryx_query_to_node (GNode *parent, const char *query);

/**
 * Find a list of paths that match this tree below the root path given
 * @param root pointer to the N-ary tree of nodes with a wildcard root path
 * @return GList of paths where this tree can be found
 */
GList *apteryx_find_tree (GNode *root);

/**
 * Find a list of paths that match this wildcard path + value
 * @param path Path to match (with one or more * wildcard)
 * @param value Value to match path against
 * @return GList of paths where this value can be found
 */
GList *apteryx_find (const char *path, const char *value);

/**
 * Set a tree of multiple values in Apteryx.
 * @param root pointer to the N-ary tree of nodes.
 * @return true on a successful set.
 * @return false on failure.
 */
#define apteryx_set_tree(root) apteryx_set_tree_full((root), UINT64_MAX, false)

/**
 * Set a tree of multiple values in Apteryx and wait for watch execution
 * @param root pointer to the N-ary tree of nodes.
 * @return true on a successful set.
 * @return false on failure.
 */
#define apteryx_set_tree_wait(root) apteryx_set_tree_full((root), UINT64_MAX, true)

/**
 * Get a tree of multiple values from Apteryx.
 * @param path path to the root of the tree to return.
 * @return N-ary tree of nodes.
 */
GNode *apteryx_get_tree (const char *path);

/**
 * Get a tree of multiple values from Apteryx that match this tree below the root path given.
 * @param root pointer to the N-ary tree of nodes.
 * @return N-ary tree of nodes.
 * Example: Create a tree and get the n-ary tree with the values for the given nodes
     GNode *root = g_node_new ("/");
     apteryx_path_to_node (root, "/routing/ipv4/rib/1/ifname", NULL);
     GNode *rroot = apteryx_query (root);
 */
GNode *apteryx_query (GNode *root);

/**
 * Set a tree of multiple values in Apteryx, but only if
 * the existing value has not changed since the specified monotonic timestamp.
 * @param root pointer to the N-ary tree of nodes.
 * @param ts monotonic timestamp to be compared to the paths last change time
 * @return true on a successful set.
 * @return false on failure.
 */
#define apteryx_cas_tree(root, ts) apteryx_set_tree_full((root), (ts), false)

/**
 * Set a tree of multiple values in Apteryx, but only if
 * the existing value has not changed since the specified monotonic timestamp.
 * Wait for watches to be executed before returning.
 * @param root pointer to the N-ary tree of nodes.
 * @param ts monotonic timestamp to be compared to the paths last change time
 * @return true on a successful set.
 * @return false on failure.
 */
#define apteryx_cas_tree_wait(root, ts) apteryx_set_tree_full((root), (ts), true)

/**
 * Search for all children that start with the root path.
 * Does not go further than one level down.
 * example:
    "/entity/zones/private/description" = "lan"
    "/entity/zones/private/networks/description" = "engineers"
    "/entity/zones/public/description" = "wan"
 *  apteryx_search ("/entity/zones/") = {"/entity/zones/private", "/entity/zones/public"}
 * @param root root path to search on
 * @return GList of full paths
 */
GList *apteryx_search (const char *root);

/**
 * Search for all children that start with the root path.
 * Does not go further than one level down.
 * example:
    "/entity/zones/private/description" = "lan"
    "/entity/zones/private/networks/description" = "engineers"
    "/entity/zones/public/description" = "wan"
 *  apteryx_search_simple ("/entity/zones/") = "/entity/zones/private\n/entity/zones/public"
 * @param root root path to search on
 * @return newline separated full paths
 */
char *apteryx_search_simple (const char *root);

/**
 * Callback function to be called when a
 * path is searched.
 * @param root root of the searched path
 * @return GList of full paths
 */
typedef GList *(*apteryx_index_callback) (const char *path);

/**
 * Provide search results for a root path
 * Supports *(wildcard) at the end of path for all children under this path
 * Supports /(level) at the end of path for children only under this current path (one level down)
 * Whenever a search occurs for the indexed path, cb is called with requested path
 * example:
 * - apteryx_index ("/counters/", search_counters)
 * - apteryx_search ("/counters/") = {"/counters/tx", "/counters/rx"}
 * @param path path to the value to be indexed
 * @param cb function to call when the path is searched
 * @return true on successful registration
 */
bool apteryx_index (const char *path, apteryx_index_callback cb);
/** No longer provide search results for a root path */
bool apteryx_unindex (const char *path, apteryx_index_callback cb);

/**
 * Callback function to be called when a
 * watched value changes.
 * @param path path to the watched value
 * @param value new value of the watched path
 * @return true on success
 */
typedef bool (*apteryx_watch_callback) (const char *path, const char *value);

/**
 * Watch for changes in the path
 * Supports *(wildcard) at the end of path for all children under this path
 * Supports /(level) at the end of path for children only under this current path (one level down)
 * Whenever a change occurs in a watched path, cb is called with the changed
 * path and new value
 * examples: (using libentity usage example (Don't escape *))
 * - apteryx_watch("/entity/zones/red/networks/\*", network_updated, "red")
 * @param path path to the value to be watched
 * @param cb function to call when the value changes
 * @return true on successful registration
 */
bool apteryx_watch (const char *path, apteryx_watch_callback cb);
/** UnWatch for changes in the path */
bool apteryx_unwatch (const char *path, apteryx_watch_callback cb);

/**
 * Callback function to be called when a watched tree changes.
 * @param root pointer to the N-ary tree of nodes representing the changed data
 * @return true on success
 */
typedef bool (*apteryx_watch_tree_callback) (GNode *root);

/**
 * Watch for changes in the path
 * Supports *(wildcard) at the end of path for all children under this path
 * Supports /(level) at the end of path for children only under this current path (one level down)
 * Whenever a change occurs in a watched path, cb is called with the changed
 * tree of changes that occurred in one transaction (e.g. an apteryx_set_tree)
 * @param path path to the value to be watched
 * @param cb function to call when the value changes
 * @return true on successful registration
 */
bool apteryx_watch_tree (const char *path, apteryx_watch_tree_callback cb);
/** UnWatch for changes in the path */
bool apteryx_unwatch_tree (const char *path, apteryx_watch_tree_callback cb);

/**
 * Callback function to be called to validate a new value
 * @param path path for the proposed value
 * @param value new proposed value
 * @return 0 on success, error code on failure. The error code must be a negative number.
 */
typedef int (*apteryx_validate_callback) (const char *path, const char *value);

/**
 * Validate changes in the path
 * Supports *(wildcard) at the end of path for all children under this path
 * Supports /(level) at the end of path for children only under this current path (one level down)
 * Whenever a change occurs on the path, cb is called with the changed
 * path and new value
 * examples: (using imaginary usage example (Don't escape *))
 * - apteryx_validate("/entity/zones/red/networks/\*", network_validate);
 * WARNING: The validate callback is not processed until all watch callbacks have
 * completed. This is to ensure local state is correct when doing the validation
 * operation. The side effect of this is that if the validation callback is
 * called due to a set operation from a watch callback in the same process, then
 * the validation callback will be blocked and time out.
 * @param path path to the value to be validated
 * @param cb function to call when the value changes
 * @return true on successful registration
 */
bool apteryx_validate (const char *path, apteryx_validate_callback cb);
/** UnValidate changes in the path */
bool apteryx_unvalidate (const char *path, apteryx_validate_callback cb);

/**
 * Callback function to be called when a library user
 * makes a get to a "refreshed" path.
 * @param path path to the value to be refreshed
 * @return timeout in microseconds to next refresh
 */
typedef uint64_t (*apteryx_refresh_callback) (const char *path);

/**
 * Refresh values when required
 * Whenever a get is performed on the given path, callback is
 * called to refresh the values of the tree.
 * examples: (using contrived usage example)
 * - apteryx_refresh ("/hw/interfaces/\*\/counters/\*", refresh_intf_tx_counters, 50);
 * @param path path to the value that others will request
 * @param cb function to be called if others request the path
 * @param timeout time after refresh is requred
 * @return true on successful registration
 */
bool apteryx_refresh (const char *path, apteryx_refresh_callback cb);
/** Remove refresher for this path */
bool apteryx_unrefresh (const char *path, apteryx_refresh_callback cb);

/**
 * Callback function to be called when a library users
 * requests a value for a "provided" path.
 * @param path path to the requested value
 * @return the provided value on success, otherwise NULL
 */
typedef char *(*apteryx_provide_callback) (const char *path);

/**
 * Provide a value that can be read on demand
 * Whenever a get is performed on the given path/key, callback is called to get the value
 * No *(wildcard)s are supported
 * examples: (using contrived usage example)
 * - apteryx_provide ("/hw/interfaces/port1.0.1/counters/tx", port_tx_counters, "port1.0.1")
 * @param path path to the value that others will request
 * @param cb function to be called if others request the value
 * @return true on successful registration
 */
bool apteryx_provide (const char *path, apteryx_provide_callback cb);
/** UnProvide a value that can be read on demand */
bool apteryx_unprovide (const char *path, apteryx_provide_callback cb);

/**
 * Proxy get and sets for the requested path to the specified remote url.
 * Whenever a get is performed on the given path/key, callback is called to get the value
 * Path must include wildcard. (Don't escape *)
 * - apteryx_proxy ("/remote/host1/\*", "tcp://192.168.1.1:9999")
 * @param path path to the value that others will set/get
 * @param url url to the remote apteryx instance
 * @return true on successful registration
 */
bool apteryx_proxy (const char *path, const char *url);
/** Remove the proxy for this path */
bool apteryx_unproxy (const char *path, const char *url);

#endif /* _APTERYX_H_ */
