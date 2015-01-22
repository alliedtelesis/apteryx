/**
 * @file imexport
 * Used for import/export.
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
#include "internal.h"

bool
export_raw (const char *path, char **data)
{
    GList *children, *iter;
    unsigned char *value = NULL;
    size_t size;

    if (db_get (path, &value, &size) /*||
        provide_get (path, &value, &size)*/)
    {
        char *d = *data;
        if (d == NULL)
            d = calloc (1, 64 + 2*size + 1);
        else
            d = realloc (d, strlen (d) + 64 + 2*size + 1);
        sprintf (d+strlen(d), "%-64s%.*s\n", path, (int) size, value);
        free (value);
        *data = d;
    }

    children = db_search (path);
    for (iter = children; iter; iter = g_list_next (iter))
    {
        char *_path = NULL;
        int len = asprintf (&_path, "%s/", (const char *) iter->data);
        if (len)
        {
            export_raw ((const char *) _path, data);
            free (_path);
        }
    }
    g_list_free_full (children, free);
    return true;
}
