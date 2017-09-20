/**
 * @file apteryxc.c
 * Client application for Apteryx.
 * Used for accessing the database from the command line.
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
#include <unistd.h>
#include <ctype.h>
#include "internal.h"
#include "apteryx.h"

/* Debug enabled */
bool apteryx_debug = false;

/* Run while true */
static bool running = true;

/* Trap signals to exit cleanly */
void
termination_handler (void)
{
    running = false;
}

/* Display application usage */
void
usage ()
{
#ifdef TEST
    printf ("Usage: apteryx [-h] [-s|-g|-f|-t|-w|-p|-x|-l|-u<filter>] [<path>] [<value>]\n"
#else
    printf ("Usage: apteryx [-h] [-s|-g|-f|-t|-w|-p|-x|-l] [<path>] [<value>]\n"
#endif
            "  -h   show this help\n"
            "  -d   debug\n"
            "  -s   set <path> to <value>\n"
            "  -g   get <path>\n"
            "  -f   find <path>\n"
            "  -t   traverse database from <path>\n"
            "  -w   watch changes to the path <path>\n"
            "  -p   provide <value> for <path>\n"
            "  -x   proxy <path> via url <value>\n"
            "  -l   last change <path>\n"
#ifdef TEST
            "  -u   run unit tests (optionally match only tests with <filter>)\n"
#endif
            );
    printf ("\n");
    printf ("  Internal settings\n");
    printf ("    %s\n", APTERYX_DEBUG_PATH);
    printf ("    %s\n", APTERYX_SOCKETS_PATH);
    printf ("    %s\n", APTERYX_WATCHERS_PATH);
    printf ("    %s\n", APTERYX_PROVIDERS_PATH);
    printf ("    %s\n", APTERYX_VALIDATORS_PATH);
    printf ("    %s\n", APTERYX_PROXIES_PATH);
    printf ("    %s\n", APTERYX_COUNTERS);
    printf ("\n");
}

static bool
watch_callback (const char *path, const char *value)
{
    printf ("%s = %s\n", path, value);
    return true;
}

static char *provide_value = NULL;

static char*
provide_callback (const char *path)
{
    return strdup ((char *) provide_value);
}

/* Application entry point */
int
main (int argc, char **argv)
{
#ifdef TEST
    const char *filter = NULL;
#endif
    APTERYX_MODE mode = -1;
    char *path = NULL;
    char *param = NULL;
    GList * _iter;
    int c;
    uint64_t value;

    /* Parse options */
    while ((c = getopt (argc, argv, "hdsgftwpxlu::")) != -1)
    {
        switch (c)
        {
        case 'd':
            apteryx_debug = true;
            break;
        case 's':
            mode = MODE_SET;
            break;
        case 'g':
            mode = MODE_GET;
            break;
        case 'f':
            mode = MODE_FIND;
            break;
        case 't':
            mode = MODE_TRAVERSE;
            break;
        case 'w':
            mode = MODE_WATCH;
            break;
        case 'p':
            mode = MODE_PROVIDE;
            break;
        case 'x':
            mode = MODE_PROXY;
            break;
        case 'l':
            mode = MODE_TIMESTAMP;
            break;
#ifdef TEST
        case 'u':
            mode = MODE_TEST;
            if (optarg && optarg[0] == '=')
                memmove(optarg, optarg+1, strlen(optarg));
            filter = optarg;
            break;
#endif
        case '?':
        case 'h':
        default:
            usage ();
            return 0;
        }
    }

    for (c = optind; c < argc; c++)
    {
        if (path == NULL)
            path = argv[c];
        else if (param == NULL)
            param = argv[c];
        else
        {
            usage ();
            return 0;
        }
    }

    /* Handle SIGTERM/SIGINT/SIGPIPE gracefully */
    if (mode != MODE_TEST)
    {
        signal (SIGTERM, (__sighandler_t) termination_handler);
        signal (SIGINT, (__sighandler_t) termination_handler);
    }

    switch (mode)
    {
    case MODE_GET:
        if (!path || param)
        {
            usage ();
            return 0;
        }
        apteryx_init (apteryx_debug);
        if ((param = apteryx_get (path)))
        {
            printf ("%s\n", param);
            free (param);
        }
        else
            fprintf (stderr, "Not found\n");
        apteryx_shutdown ();
        break;
    case MODE_SET:
        if (!path)
        {
            usage ();
            return 0;
        }
        apteryx_init (apteryx_debug);
        if (!apteryx_set (path, param))
            fprintf (stderr, "Failed\n");
        apteryx_shutdown ();
        break;
    case MODE_FIND:
        if (!path || param)
        {
            usage ();
            return 0;
        }
        apteryx_init (apteryx_debug);
        GList *paths = apteryx_search (path);
        for (_iter = paths; _iter; _iter = _iter->next)
            printf ("  %s\n", (char *) _iter->data);
        g_list_free_full (paths, free);
        apteryx_shutdown ();
        break;
    case MODE_TRAVERSE:
        if (param)
        {
            usage ();
            return 0;
        }
        if (!path)
        {
            path = "";
        }
        apteryx_init (apteryx_debug);
        apteryx_dump (path, stdout);
        apteryx_shutdown ();
        break;
    case MODE_WATCH:
        if (param)
        {
            usage ();
            return 0;
        }
        if (!path)
        {
            path = "/";
        }
        apteryx_init (apteryx_debug);
        apteryx_watch (path, watch_callback);
        while (running)
            pause ();
        apteryx_unwatch (path, watch_callback);
        apteryx_shutdown ();
        break;
    case MODE_PROVIDE:
        if (!path || !param)
        {
            usage ();
            return 0;
        }
        apteryx_init (apteryx_debug);
        provide_value = param;
        apteryx_provide (path, provide_callback);
        while (running)
            pause ();
        apteryx_unprovide (path, provide_callback);
        apteryx_shutdown ();
        break;
    case MODE_PROXY:
        if (!path || !param)
        {
            usage ();
            return 0;
        }
        apteryx_init (apteryx_debug);
        apteryx_proxy (path, param);
        apteryx_shutdown ();
        break;
    case MODE_TIMESTAMP:
        if (param)
        {
            usage ();
            return 0;
        }
        if (!path)
        {
            path = "";
        }
        apteryx_init (apteryx_debug);
        value = apteryx_timestamp (path);
        printf ("%"PRIu64"\n", value);
        apteryx_shutdown ();
        break;
#ifdef TEST
    case MODE_TEST:
        if (path || param)
        {
            usage ();
            return 0;
        }
        apteryx_init (apteryx_debug);

        run_unit_tests (filter);
        usleep (100000);

        apteryx_shutdown ();
        break;
#endif
    default:
        usage ();
        return 0;
    }

    return 0;
}
