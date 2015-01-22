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
    char *_path = NULL;
    unsigned char *value = NULL;
    size_t size;
    int len;

    if (strlen (path) > 0 && db_get (path, &value, &size) && value)
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
    else if (path[strlen (path)-1] != '/')
        return true;

    len = asprintf (&_path, "%s/", path);
    if (len >= 0)
    {
        GList *children, *iter;
        children = db_search (_path);
        for (iter = children; iter; iter = g_list_next (iter))
        {
            export_raw ((const char *) iter->data, data);
        }
        g_list_free_full (children, free);
        free (_path);
    }

    return true;
}

static bool
export_json_recursive (const char *path, char **data, int tab)
{
    int len = strlen (path);
    char *_path = strndup (path, len-1);
    char *key = "";
    GList *children = NULL, *iter;
    unsigned char *value = NULL;
    size_t size;

    /* Get the key */
    if (strrchr(_path, '/'))
        key = strrchr(_path, '/') + 1;

    /* Get value and/or children */
    children = db_search (path);

    /* Value or children */
    if (children == NULL && db_get (_path, &value, &size) && value && size) {
        char *d = *data;
        int len = tab + strlen (key) + 2*size + 7;
        if (d == NULL)
            d = calloc (1, len);
        else
            d = realloc (d, strlen (d) + len);
        sprintf (d+strlen(d), "%*s\"%s\": \"%s\"",
                tab, "", key, bytes_to_string(value, size));
        free (value);
        *data = d;
    }
    else if (children) {
        char *d = *data;
        int len = tab + strlen (key) + 1024;
        if (d == NULL)
            d = calloc (1, len);
        else
            d = realloc (d, strlen (d) + len);
        if (tab == 0)
            sprintf (d+strlen(d), "{");
        sprintf (d+strlen(d), "%*s\"%s\": {\n", tab, "", key);
        free (_path);
        for (iter = children; iter; iter = g_list_next (iter))
        {
            if (asprintf(&_path, "%s/", (const char *) iter->data))
            {
                *data = d;
                export_json_recursive ((const char *)_path, data, tab+4);
                free(_path);
            }
            d = *data;
            sprintf (d+strlen(d), "%s\n", g_list_next(iter) ? "," : "");
        }
        g_list_free_full(children, free);
        sprintf (d+strlen(d), "%*s}", tab, "");
        if (tab == 0)
            sprintf (d+strlen(d), "}\n");
        *data = d;
    }
    else
    {
        free (_path);
    }

    return true;
}

bool
export_json (const char *path, char **data)
{
    int len = path ? strlen (path) : 0;
    unsigned char *value = NULL;
    size_t size;

    if (!path || len == 0 || path[0] != '/')
        return false;

    if (path[len-1] == '/')
        return export_json_recursive (path, data, 0);

    if (!db_get (path, &value, &size))
        return false;

    if (!asprintf (data, "{\"%s\": \"%s\"}\n",
            strrchr(path, '/') + 1,
            bytes_to_string(value, size))) {
        free (value);
        return false;
    }
    free (value);
    return true;
}
