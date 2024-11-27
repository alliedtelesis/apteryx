#ifndef _STRING_CACHE_H_
#define _STRING_CACHE_H_

#include <glib.h>

/* Prepare string cache */
void string_cache_init();

// Retrieve a string from the cache or add it if it doesn't exist
const char *string_cache_get (const char *str) ;
void string_cache_release (const char *str);

#endif