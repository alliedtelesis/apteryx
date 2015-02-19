/**
 * @file example
 * Example application for Apteryx.
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
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <apteryx.h>

int
main (int argc, char **argv)
{
    apteryx_set ("/interfaces/eth0/description", "our lan");
    apteryx_set ("/interfaces/eth0/state", "up");
    apteryx_set ("/interfaces/eth1/description", "our wan");
    apteryx_set ("/interfaces/eth1/state", "down");

    printf ("\nInterfaces:\n");
    GList* paths = apteryx_search ("/interfaces/");
    for (GList* _iter= paths; _iter; _iter = _iter->next)
    {
        char *path, *value;
        path = (char *)_iter->data;
        printf ("  %s\n", strrchr (path, '/') + 1);
        value = apteryx_get_string (path, "description");
        printf ("    description     %s\n", value);
        free ((void*)value);
        value = apteryx_get_string (path, "state");
        printf ("    state           %s\n", value);
        free ((void*)value);
    }
    g_list_free_full (paths, free);

    return 0;
}
