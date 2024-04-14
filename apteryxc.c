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
    printf ("Usage: apteryx [-h] [-s|-g|-f|-q|-t|-r|-w|-p|-x|-l|-m|-c|-u<filter>] [<path>] [<value>]\n"
#else
    printf ("Usage: apteryx [-h] [-s|-g|-f|-q|-t|-r|-w|-p|-x|-l|-m|-c] [<path>] [<value>]\n"
#endif
            "  -h   show this help\n"
            "  -d   debug\n"
            "  -s   set <path> to <value>\n"
            "  -g   get <path>\n"
            "  -f   find <path>\n"
            "  -q   query <path>?<query>\n"
            "  -t   traverse database from <path>\n"
            "  -r   prune <path>\n"
            "  -w   watch changes to the path <path>\n"
            "  -p   provide <value> for <path>\n"
            "  -x   proxy <path> via url <value>\n"
            "  -l   last change <path>\n"
            "  -m   display memory usage for <path>\n"
            "  -c   display counters and statistics\n"
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

struct stat_t
{
    char *guid;
    uint64_t pid;
    uint64_t callback;
    uint64_t ns;
    uint64_t flags;
    uint64_t hash;
    uint64_t count;
    uint64_t min;
    uint64_t avg;
    uint64_t max;
};

static int
_sort_stats (struct stat_t *a, struct stat_t *b)
{
    return b->count - a->count;
}

static void
_free_stats (struct stat_t *stat)
{
    g_free (stat->guid);
    g_free (stat);
}

static inline gboolean
_parse_stats (GNode *node, gpointer data)
{
    GList **stats = (GList **) data;
    if (APTERYX_HAS_VALUE (node))
    {
        struct stat_t *stat = g_malloc0 (sizeof (struct stat_t));
        stat->guid = g_strdup (APTERYX_NAME (node));
        if (sscanf (APTERYX_NAME (node), APTERYX_GUID_FORMAT,
                    &stat->ns, &stat->pid, &stat->callback, &stat->flags, &stat->hash) != 5 ||
            sscanf (APTERYX_VALUE (node), "%" PRIu64 ",%" PRIu64 ",%" PRIu64 ",%" PRIu64 "",
                    &stat->count, &stat->min, &stat->avg, &stat->max) != 4 ||
            stat->count == 0)
        {
            g_free (stat->guid);
            g_free (stat);
            return false;
        }
        *stats = g_list_insert_sorted (*stats, (gpointer) stat, (GCompareFunc) _sort_stats);
    }
    return false;
}

static const char*
procname (const uint64_t ns, const uint64_t pid)
{
    static char name[1024];
    name[0] = '\0';
    if (ns != getns ())
    {
        sprintf (name, APTERYX_CLIENT_ID, ns, pid);
        return name;
    }
    sprintf (name, "/proc/%"PRIu64"/cmdline", pid);
    FILE* f = fopen (name,"r");
    if (f)
    {
        size_t size;
        size = fread (name, sizeof(char), 1024, f);
        if (size > 0)
        {
            if ('\n' == name[size-1])
                name[size-1]='\0';
        }
        fclose(f);
    }
    if (strrchr (name, '/'))
        return strrchr (name, '/') + 1;
    return name;
}

static void
_print_stats (struct stat_t *stat, char *rpath)
{
    char *cpath = g_strdup_printf ("%s/%s", rpath, stat->guid);
    char *path = apteryx_get (cpath);
    g_free (cpath);
    printf (" %-*s %-*s%*" PRIu64 " %" PRIu64 "/%" PRIu64 "/%" PRIu64 "\n",
            15, procname(stat->ns, stat->pid), 64, path, 8, stat->count, stat->min, stat->avg, stat->max);
    g_free (path);
    return;
}

static void
print_stats (void)
{
    char *paths[] = { APTERYX_WATCHERS_PATH, APTERYX_REFRESHERS_PATH, APTERYX_PROVIDERS_PATH,
                      APTERYX_VALIDATORS_PATH, APTERYX_INDEXERS_PATH, APTERYX_PROXIES_PATH };
    int i;

    printf (" %-*s %-*s%*s%s\n", 15, "process", 64, "path", 8, "count", " min/avg/max");
    for (i = 0; i < (sizeof(paths)/sizeof(char *)); i++)
    {
        char *operation = strrchr (paths[i], '/') + 1;
        char *path = g_strdup_printf (APTERYX_STATISTICS "/%s", operation);
        GNode *tree = apteryx_get_tree (path);
        g_free (path);
        if (tree)
        {
            GList *stats = NULL;
            g_node_traverse (tree, G_PRE_ORDER, G_TRAVERSE_NON_LEAFS, -1, _parse_stats, (gpointer) &stats);
            if (stats)
            {
                char *header = g_ascii_strup (operation, -1);
                printf ("%s:\n", header);
                g_free (header);
                g_list_foreach (stats, (GFunc) _print_stats, (gpointer) paths[i]);
                g_list_free_full (stats, (GDestroyNotify)_free_stats);
            }
            apteryx_free_tree (tree);
        }
    }
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
    while ((c = getopt (argc, argv, "hdsgfqtrwpxlmcu::")) != -1)
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
        case 'q':
            mode = MODE_QUERY;
            break;
        case 't':
            mode = MODE_TRAVERSE;
            break;
        case 'r':
            mode = MODE_PRUNE;
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
        case 'm':
            mode = MODE_MEMUSE;
            break;
        case 'c':
            mode = MODE_COUNTERS;
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
            printf ("Not found\n");
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
            printf ("Failed\n");
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
    case MODE_QUERY:
    {
        if (!path || param)
        {
            usage ();
            return 0;
        }
        apteryx_init (apteryx_debug);
        char *fields = strchr (path, '?');
        if (fields)
        {
            *fields = '\0';
            fields++;
        }
        GNode *query = g_node_new (g_strdup (path));
        if (fields && !apteryx_query_to_node (query, fields))
        {
            printf ("Invalid query \"%s\"\n", fields);
            apteryx_free_tree (query);
            return 0;
        }
        GNode *tree = apteryx_query (query);
        if (tree)
        {
            apteryx_print_tree (tree, stdout);
            apteryx_free_tree (tree);
        }
        apteryx_free_tree (query);
        apteryx_shutdown ();
        break;
    }
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
    case MODE_PRUNE:
        if (!path || param)
        {
            usage ();
            return 0;
        }
        apteryx_init (apteryx_debug);
        if (!apteryx_prune (path))
            printf ("Failed\n");
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
    case MODE_MEMUSE:
    {
        if (!path || param)
        {
            usage ();
            return 0;
        }
        apteryx_init (apteryx_debug);
        if (path[strlen(path) - 1] != '/')
            path = g_strdup_printf ("%s/", path);
        else
            path = g_strdup (path);
        GList *paths = apteryx_search (path);
        for (_iter = paths; _iter; _iter = _iter->next)
        {
            uint64_t size = apteryx_memuse ((char *) _iter->data);
            if (size != 0)
                printf ("%10"PRIu64" %s\n", size, (char *) _iter->data);
        }
        g_list_free_full (paths, free);
        apteryx_shutdown ();
        g_free (path);
        break;
    }
    case MODE_COUNTERS:
    {
        if (path || param)
        {
            usage ();
            return 0;
        }
        apteryx_init (apteryx_debug);
        print_stats ();
        apteryx_shutdown ();
        break;
    }
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
