#ifndef _STRING_CACHE_H_
#define _STRING_CACHE_H_

/**
 * @file string-cache.h
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


#include <glib.h>

/* Prepare string cache */
void string_cache_init();

/* Retrieve a string from the cache or add it if it doesn't exist */
const char *string_cache_get (const char *str) ;
void string_cache_release (const char *str);
/* Retrieve the memory used to store this string */
uint64_t string_cache_memuse (const char *str, bool pss);

#endif