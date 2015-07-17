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
#include <glib.h>

/** Apteryx configuration
  /apteryx
  /apteryx/debug                           - Apteryx debug
  /apteryx/sockets                         - List of sockets (urls) that apteryxd will accept connections on.
  /apteryx/sockets/-                       - Unique identifier based on HASH(url). Value is the url to listen on.
  /apteryx/watchers                        - List of watched paths and registered callbacks for those watches.
  /apteryx/watchers/-                      - Unique identifier based on PID-CALLBACK-HASH(path). Value is the path.
  /apteryx/providers                       - List of provided paths and registered callbacks for providing gets to that path.
  /apteryx/providers/-                     - Unique identifier based on PID-CALLBACK-HASH(path). Value is the path.
  /apteryx/validators                      - List of validated paths and registered callbacks for validating sets to that path.
  /apteryx/validators/-                    - Unique identifier based on PID-CALLBACK-HASH(path). Value is the path.
  /apteryx/indexers                        - List of indexed paths and registered callbacks for providing search results for that path.
  /apteryx/indexers/-                      - Unique identifier based on PID-CALLBACK-HASH(path). Value is the path.
  /apteryx/proxies                         - List of proxied paths and remote url to proxy gets and sets to.
  /apteryx/proxies/-                       - Unique identifier based on PID-HASH(path)-HASH(url). Value is the full url for the path.
  /apteryx/cache                           - Formatted dump of the Apteryx cache
  /apteryx/counters                        - Formatted list of counters and values for Apteryx usage
 */
#define APTERYX_PATH                             "/apteryx"
#define APTERYX_DEBUG_PATH                       "/apteryx/debug"
#define APTERYX_DEBUG_DEFAULT                        0
#define APTERYX_DEBUG_DISABLE                        0
#define APTERYX_DEBUG_ENABLE                         1
#define APTERYX_SOCKETS_PATH                     "/apteryx/sockets"
#define APTERYX_WATCHERS_PATH                    "/apteryx/watchers"
#define APTERYX_PROVIDERS_PATH                   "/apteryx/providers"
#define APTERYX_VALIDATORS_PATH                  "/apteryx/validators"
#define APTERYX_INDEXERS_PATH                    "/apteryx/indexers"
#define APTERYX_PROXIES_PATH                     "/apteryx/proxies"
#define APTERYX_CACHE                            "/apteryx/cache"
#define APTERYX_COUNTERS                         "/apteryx/counters"

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
 * Set a path/value in Apteryx
 * @param path path to the value to set
 * @param value value to set at the specified path
 * @return true on a successful set
 * @return false if the path is invalid
 */
bool apteryx_set (const char *path, const char *value);
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
/** Helper to retrieve a simple integer from an extended path */
int32_t apteryx_get_int (const char *path, const char *key);

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
    APTERYX_LEAF (root, "state", "up");
    APTERYX_LEAF (root, "speed", "1000");
    APTERYX_LEAF (root, "duplex", "full");
    printf (Number of nodes = %d\n, APTERYX_NUM_NODES (root));
    printf (Number of paths = %d\n, g_node_n_nodes (root, G_TRAVERSE_LEAVES));
    for (GNode *node = g_node_first_child (root); node; node = g_node_next_sibling (node)) {
        printf ("%s = %s", APTERYX_NAME (node), APTERYX_VALUE (node));
    }
    g_node_destroy (root);
 */
#define APTERYX_NODE(p,n) \
    (p ? (g_node_append_data (p, (gpointer)n)) : (g_node_new (n)))
#define APTERYX_LEAF(p,n,v) \
    (g_node_append_data (g_node_append_data (p, (gpointer)n), (gpointer)v))
#define APTERYX_NUM_NODES(p) \
    (g_node_n_nodes (p, G_TRAVERSE_ALL) - g_node_n_nodes (p, G_TRAVERSE_LEAVES))
#define APTERYX_NAME(n) \
    ((char*)(n)->data)
#define APTERYX_HAS_VALUE(n) \
    (g_node_first_child (n) && G_NODE_IS_LEAF (g_node_first_child (n)))
#define APTERYX_VALUE(n) \
    ((char*)g_node_first_child (n)->data)
/** Free an N-ary tree of nodes when the data need freeing (e.g. from apteryx_get_tree) */
void apteryx_free_tree (GNode* root);
/** Get the full path of an Apteryx node in an N-ary tree */
char* apteryx_node_path (GNode* node);

/**
 * Set a tree of multiple values in Apteryx.
 * @param root pointer to the N-ary tree of nodes.
 * @return true on a successful set.
 * @return false on failure.
 */
bool apteryx_set_tree (GNode* root);

/**
 * Get a tree of multiple values from Apteryx.
 * @param path path to the root of the tree to return.
 * @param depth depth of the tree to traverse (-1 means keep going).
 * @return N-ary tree of nodes.
 */
GNode* apteryx_get_tree (const char *path, int depth);

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
 * Callback function to be called when a
 * path is searched.
 * @param root root of the searched path
 * @return GList of full paths
 */
typedef GList* (*apteryx_index_callback) (const char *path);

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
 * examples: (using libentity usage example)
 * - apteryx_watch("/entity/zones/red/networks/*", network_updated, "red")
 * @param path path to the value to be watched
 * @param cb function to call when the value changes
 * @return true on successful registration
 */
bool apteryx_watch (const char *path, apteryx_watch_callback cb);
/** UnWatch for changes in the path */
bool apteryx_unwatch (const char *path, apteryx_watch_callback cb);

/**
 * Callback function to be called to validate a new value
 * @param path path for the proposed value
 * @param value new proposed value
 * @return 0 on success, error code on failure
 */
typedef int (*apteryx_validate_callback) (const char *path, const char *value);

/**
 * Validate changes in the path
 * Supports *(wildcard) at the end of path for all children under this path
 * Supports /(level) at the end of path for children only under this current path (one level down)
 * Whenever a change occurs on the path, cb is called with the changed
 * path and new value
 * examples: (using imaginary usage example)
 * - apteryx_validate("/entity/zones/red/networks/*", network_validate);
 * @param path path to the value to be validated
 * @param cb function to call when the value changes
 * @return true on successful registration
 */
bool apteryx_validate (const char *path, apteryx_validate_callback cb);
/** UnValidate changes in the path */
bool apteryx_unvalidate (const char *path, apteryx_validate_callback cb);

/**
 * Callback function to be called when a library users
 * requests a value for a "provided" path.
 * @param path path to the requested value
 * @return the provided value on success, otherwise NULL
 */
typedef char* (*apteryx_provide_callback) (const char *path);

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
 * Path must include wildcard.
 * - apteryx_proxy ("/remote/host1/*", "tcp://192.168.1.1:9999")
 * @param path path to the value that others will set/get
 * @param url url to the remote apteryx instance
 * @return true on successful registration
 */
bool apteryx_proxy (const char *path, const char *url);
/** Remove the proxy for this path */
bool apteryx_unproxy (const char *path, const char *url);

/**
 * Get the last change timestamp of a given path
 * @param path path to get the timestamp for
 * @return 0 if the path doesn't exist, last change timestamp otherwise
 */
uint64_t apteryx_timestamp (const char *path);

#endif /* _APTERYX_H_ */
