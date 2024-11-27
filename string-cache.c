#include "string-cache.h"
#include <assert.h>
#include "hashtree.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>


// Structure with a flexible array member for the string
typedef struct {
    uint64_t refcount;
    char str[0]; // Flexible array member for the string
} StringCacheEntry;
typedef struct {
    GHashTable *table;
} StringCache;
static StringCache *string_cache = NULL;

// Function to create a new cache entry
static StringCacheEntry *string_cache_entry_new(const char *str) {
    size_t len = strlen(str) + 1; // Include space for null terminator
    StringCacheEntry *entry = g_malloc(sizeof(StringCacheEntry) + len);
    entry->refcount = 1;
    memcpy(entry->str, str, len); // Copy the string into the allocated memory
    return entry;
}

// Function to free a cache entry
static void string_cache_entry_free(StringCacheEntry *entry) {
    assert (entry->refcount == 0);
    if (entry) {
        g_free(entry);
    }
}

// Hash and equality functions for strings (keys are the `str` field)
static guint string_hash(gconstpointer key) {
    return g_str_hash(key);
}

static gboolean string_equal(gconstpointer a, gconstpointer b) {
    return g_str_equal(a, b);
}

// Retrieve a string from the cache or add it if it doesn't exist
const char *string_cache_get(const char *str) {
    StringCacheEntry *entry = g_hash_table_lookup(string_cache->table, str);
    if (entry) {
        entry->refcount++;
        return entry->str;
    } else {
        entry = string_cache_entry_new(str);
        // Use entry->str as the key to ensure hash/equal functions operate on the string
        g_hash_table_insert(string_cache->table, entry->str, entry);
        return entry->str;
    }
}

// Decrease the reference count of a string and remove it if refcount reaches 0
void string_cache_release(const char *str) {
    if (!str)
        return;
    StringCacheEntry *entry = g_hash_table_lookup(string_cache->table, str);
    if (entry) {
        entry->refcount--;
        if (entry->refcount == 0) {
            g_hash_table_remove(string_cache->table, str);
        }
    }
}

// Create a new string cache
static StringCache *string_cache_new() {
    string_cache = g_new(StringCache, 1);
    // The keys are pointers to `str` in StringCacheEntry, no need for g_free on keys
    string_cache->table = g_hash_table_new_full(string_hash, string_equal, NULL, (GDestroyNotify)string_cache_entry_free);
    return string_cache;
}

// Destroy the cache
static void string_cache_free(StringCache *cache) {
    if (cache) {
        g_hash_table_destroy(cache->table);
        g_free(cache);
    }
}

void string_cache_init ()
{
    if (!string_cache)
        string_cache = string_cache_new();
}

void string_cache_deinit()
{
    if (string_cache)
        string_cache_free(string_cache);
    string_cache = NULL;
}