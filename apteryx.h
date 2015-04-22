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
 *     WATCH - watch for changes in the specified path
 *     GET - get the value stored at the specified path
 *     PROVIDE - provide the value stored at the specified path
 *     SEARCH - look for sub-paths that match the requested root path
 *
 * Example Usage:
 *
 *   apteryx_set ("/interfaces/eth0/description", "our lan");
 *   apteryx_set ("/interfaces/eth0/state", "up");
 *   apteryx_set ("/interfaces/eth1/description", "our wan");
 *   apteryx_set ("/interfaces/eth1/state", "down");
 *
 *   printf ("\nInterfaces:\n");
 *   GList* paths = apteryx_search ("/interfaces/");
 *   for (GList* _iter= paths; _iter; _iter = _iter->next)
 *   {
 *       char *path, *value;
 *       path = (char *)_iter->data;
 *       printf ("  %s\n", strrchr (path, '/') + 1);
 *       value = apteryx_get_string (path, "description");
 *       printf ("    description     %s\n", value);
 *       free ((void*)value);
 *       value = apteryx_get_string (path, "state");
 *       printf ("    state           %s\n", value);
 *       free ((void*)value);
 *   }
 *   g_list_free_full (paths, free);
 *
 * Output:
 *
 * Interfaces:
 *   eth0
 *     description      our lan
 *     state            up
 *   eth1
 *     description      our wan
 *     state            down
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
 * Search for all children that start with the root path.
 * Does not go further than one level down.
 * example:
    "/entity/zones/private/description" = "lan"
    "/entity/zones/private/networks/description" = "engineers"
    "/entity/zones/public/description" = "wan"
 *  apteryx_search ("/entity/zones") = {"/entity/zones/private", "/entity/zones/public"}
 * @param root root path to search on
 * @return GList of full paths
 */
GList *apteryx_search (const char *root);

/**
 * Callback function to be called when a
 * watched value changes.
 * @param path path to the watched value
 * @param priv something I passed to apteryx_watch to be passed back to me
 * @param value new value of the watched path
 * @return true on success
 */
typedef bool (*apteryx_watch_callback) (const char *path, void *priv, const char *value);

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
 * @param priv something I want to be passed to my callback
 * @return true on successful registration
 */
bool apteryx_watch (const char *path, apteryx_watch_callback cb, void *priv);

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

/**
 * Callback function to be called when a library users
 * requests a value for a "provided" path.
 * @param path path to the requested value
 * @param priv something I passed to apteryx_provide to be passed back to me
 * @return the provided value on success, otherwise NULL
 */
typedef char* (*apteryx_provide_callback) (const char *path, void *priv);

/**
 * Provide a value that can be read on demand
 * Whenever a get is performed on the given path/key, callback is called to get the value
 * No *(wildcard)s are supported
 * examples: (using contrived usage example)
 * - apteryx_provide ("/hw/interfaces/port1.0.1/counters/tx", port_tx_counters, "port1.0.1")
 * @param path path to the value that others will request
 * @param cb function to be called if others request the value
 * @param priv something I want to be passed to my callback
 * @return true on successful registration
 */
bool apteryx_provide (const char *path, apteryx_provide_callback cb, void *priv);

#endif /* _APTERYX_H_ */
