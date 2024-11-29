/**
 * @file string-cache.c
 * Provide a cache of strings to reduce memory allocations
 *
 * Copyright 2024, Allied Telesis Labs New Zealand, Ltd
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
#include <stdint.h>
#include <stdbool.h>
#include <malloc.h>
#include <assert.h>
#include "hashtree.h"
#include "string-cache.h"

/* Structure with a flexible array member for the string.
 * When we allocate this it will be done with space for the string. */
typedef struct
{
    uint64_t refcount;
    char str[0];
} StringCacheEntry;

static GHashTable *string_cache = NULL;

/* Function to create a new cache entry. */
static StringCacheEntry *
string_cache_entry_new (const char *str)
{
    /* Include space for null terminator. */
    size_t len = strlen (str) + 1;
    StringCacheEntry *entry = g_malloc (sizeof (StringCacheEntry) + len);
    entry->refcount = 1;
    /* Copy the string into the allocated memory (including null terminator). */
    memcpy (entry->str, str, len);
    return entry;
}

/* Function to free a cache entry. */
static void
string_cache_entry_free (StringCacheEntry *entry)
{
    assert (entry->refcount == 0);
    if (entry)
    {
        g_free (entry);
    }
}

/* Retrieve a string from the cache or add it if it doesn't exist */
const char *
string_cache_get (const char *str)
{
    if (!str)
    {
        return NULL;
    }

    StringCacheEntry *entry = g_hash_table_lookup (string_cache, str);
    if (entry)
    {
        entry->refcount++;
        return entry->str;
    }
    else
    {
        entry = string_cache_entry_new (str);
        /* Use entry->str as the key to ensure hash/equal functions operate on the string */
        g_hash_table_insert (string_cache, entry->str, entry);
        return entry->str;
    }
}

/* Decrease the reference count of a string and remove it if refcount reaches 0 */
void
string_cache_release (const char *str)
{
    if (!str)
    {
        return;
    }

    StringCacheEntry *entry = g_hash_table_lookup (string_cache, str);
    if (entry)
    {
        entry->refcount--;
        if (entry->refcount == 0)
        {
            g_hash_table_remove (string_cache, str);
        }
    }
}

/* Amount of actual memory used to store this string */
uint64_t
string_cache_memuse (const char *str, bool pss)
{
    StringCacheEntry *entry;
    uint64_t size = 0;

    if (str && (entry = g_hash_table_lookup (string_cache, str)))
    {
        /* Ignore the string-cache hashtable structure but
           include the pointers to key and value and the hash */
        size = (sizeof (gpointer) + sizeof (gpointer) + sizeof (guint));
        /* 8 bytes malloc header + actual malloced size */
        size += 8 + malloc_usable_size (entry);
        /* Proportional size is one references share of the total */
        if (pss)
            size /= entry->refcount;
    }

    return size;
}

void
string_cache_init ()
{
    if (!string_cache)
    {
        string_cache =
            g_hash_table_new_full (g_str_hash, g_str_equal, NULL,
                                   (GDestroyNotify) string_cache_entry_free);
    }
}

/* This function should only be called when *all* strings have been released. */
void
string_cache_deinit ()
{
    g_hash_table_destroy (string_cache);
    string_cache = NULL;
}
