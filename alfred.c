/**
 * @file alfred.c
 *
 * Copyright 2015, Allied Telesis Labs New Zealand, Ltd
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
#include "common.h"
#include "apteryx.h"
#include <assert.h>
#include <dirent.h>
#include <libxml/parser.h>
#include <libxml/tree.h>
#include <libxml/xmlschemas.h>
#include <lua.h>
#include <lualib.h>
#include <lauxlib.h>
#include <pthread.h>
#include <time.h>
#include <glib.h>
#include <lua.h>

/* Change the following to alfred*/
#define APTERYX_ALFRED_PID "/var/run/apteryx-alfred.pid"
#define APTERYX_CONFIG_DIR "/etc/apteryx/schema/"
#define SECONDS_TO_MILLI 1000

/* Debug */
bool debug = false;
/* Run while true */
static bool running = true;

/* Alfred object */
typedef struct alfred_t
{
    /* Watched path */
    char *path;
    /* Script to action when the path changes */
    char *script;
    /* TODO */
    bool leaf;
} alfred_t;

/* An Alfred instance. */
struct alfred_instance_t
{
    /* Hash table of actions based on path */
    GHashTable *actions;
    /* Lua state */
    lua_State *ls;
    /* Lock for Lua state */
    pthread_mutex_t ls_lock;
} alfred_instance_t;
typedef struct alfred_instance_t *alfred_instance;

/* The one and only instance */
alfred_instance alfred_inst = NULL;

static void
alfred_error (lua_State *ls, int res)
{
    switch (res)
    {
    case LUA_ERRRUN:
        ERROR ("LUA: %s\n", lua_tostring (ls, -1));
        break;
    case LUA_ERRSYNTAX:
        ERROR ("LUA: %s\n", lua_tostring (ls, -1));
        break;
    case LUA_ERRMEM:
        ERROR ("LUA: Memory allocation error\n");
        break;
    case LUA_ERRERR:
        ERROR ("LUA: Error handler error\n");
        break;
    case LUA_ERRFILE:
        ERROR ("LUA: Couldn't open file\n");
        break;
    default:
        ERROR ("LUA: Unknown error\n");
        break;
    }
}

static bool
alfred_exec (lua_State *ls, const char *script)
{
    int res = 0;

    res = luaL_loadstring (ls, script);
    if (res == 0)
        res = lua_pcall (ls, 0, 0, 0);
    if (res != 0)
        alfred_error (ls, res);

    lua_gc (ls, LUA_GCCOLLECT, 0);

    return (res == 0);
}

static bool
node_changed (const char *path, const char *value)
{
    char *_path = NULL;
    alfred_t *alfred = NULL;
    bool ret = false;

    assert (path);
    assert (alfred_inst);

    /* Find a matching action */
    _path = g_strdup (path);
    alfred = g_hash_table_lookup (alfred_inst->actions, _path);
    while (alfred == NULL && strlen (_path) > 1)
    {
        *(strrchr (_path, '/')) = '\0';
        alfred = g_hash_table_lookup (alfred_inst->actions, _path);
    }
    g_free (_path);
    if (alfred == NULL)
    {
        ERROR ("ALFRED: No Alfred action for %s\n", path);
        return false;
    }

    DEBUG ("ALFRED: %s = %s\n", path, value);

    pthread_mutex_lock (&alfred_inst->ls_lock);
    lua_pushstring (alfred_inst->ls, path);
    lua_setglobal (alfred_inst->ls, "_path");
    lua_pushstring (alfred_inst->ls, value);
    lua_setglobal (alfred_inst->ls, "_value");
    ret = alfred_exec (alfred_inst->ls, alfred->script);
    pthread_mutex_unlock (&alfred_inst->ls_lock);
    return ret;
}

static void
alfred_register (gpointer key, gpointer value, gpointer user_data)
{
    alfred_t *alfred = (alfred_t *) value;
    int install = GPOINTER_TO_INT (user_data);
    char *path;

    if (!alfred->leaf)
        path = g_strdup_printf ("%s/*", alfred->path);
    else
        path = g_strdup (alfred->path);

    if ((install && !apteryx_watch (path, node_changed)) ||
        (!install && !apteryx_unwatch (path, node_changed)))
    {
        ERROR ("Failed to (un)register watch for path %s\n", alfred->path);
    }

    g_free (path);
}

static alfred_t *
create_alfred (const char *path, const char *script, bool leaf)
{
    alfred_t *alfred;

    alfred = g_malloc0 (sizeof (alfred_t));
    if (!alfred)
    {
        ERROR ("XML: Failed to allocate memory for alfred\n");
        return NULL;
    }
    alfred->path = g_strdup (path);
    alfred->script = g_strdup (script);
    alfred->leaf = leaf;
    return alfred;
}

static bool
destroy_alfred (gpointer key, gpointer value, gpointer rpc)
{
    alfred_t *alfred = (alfred_t *) value;

    DEBUG ("XML: Destroy alfred for path %s\n", alfred->path);

    /* Free the alfred */
    g_free (alfred->path);
    g_free (alfred->script);
    g_free (alfred);

    return true;
}

static bool
node_is_leaf (xmlNode *node)
{
    for (xmlNode *n = node->children; n; n = n->next)
    {
        if (n->type == XML_ELEMENT_NODE && strcmp ((const char *) n->name, "NODE") == 0)
            return false;
    }
    return true;
}

static bool
process_node (alfred_instance alfred, xmlNode *node, char *parent)
{
    xmlChar *name = NULL;
    xmlChar *content = NULL;
    char *path = NULL;
    bool res = true;

    assert (alfred);

    /* Ignore fluff */
    if (!node || node->type != XML_ELEMENT_NODE)
        return true;

    /* Process this node */
    if (strcmp ((const char *) node->name, "NODE") == 0)
    {
        /* Find node name and path */
        name = xmlGetProp (node, (xmlChar *) "name");
        if (parent)
            path = g_strdup_printf ("%s/%s", parent, name);
        else
            path = g_strdup_printf ("/%s", name);

        DEBUG ("XML: %s: %s (%s)\n", node->name, name, path);
    }
    else if (strcmp ((const char *) node->name, "ALFRED") == 0)
    {
        content = xmlNodeGetContent (node);
        alfred_t *act = create_alfred (parent, (char *) content, node_is_leaf (node->parent));
        if (!act)
        {
            res = false;
            goto exit;
        }
        g_hash_table_insert (alfred->actions, act->path, act);

        DEBUG ("XML: %s: (%s) %s\n", node->name, act->path, act->script);
    }
    else if (strcmp ((const char *) node->name, "SCRIPT") == 0)
    {
        bool ret = false;
        content = xmlNodeGetContent (node);
        DEBUG ("XML: %s: %s\n", node->name, content);
        pthread_mutex_lock (&alfred->ls_lock);
        ret = alfred_exec (alfred->ls, (char *) content);
        pthread_mutex_unlock (&alfred->ls_lock);
        if (!ret)
        {
            res = false;
            goto exit;
        }
    }

    /* Process children */
    for (xmlNode *n = node->children; n; n = n->next)
    {
        if (!process_node (alfred, n, path))
        {
            res = false;
            goto exit;
        }
    }

  exit:
    if (path)
        g_free (path);
    if (name)
        xmlFree (name);
    if (content)
        xmlFree (content);
    return res;
}

static bool
load_config_files (alfred_instance alfred, const char *path)
{
    struct dirent *entry;
    DIR *dir;
    bool res = true;

    /* Find all the XML files in this folder */
    dir = opendir (path);
    if (dir == NULL)
    {
        DEBUG ("XML: Failed to open \"%s\"", path);
        return false;
    }

    /* Load all libraries first */
    for (entry = readdir (dir); entry; entry = readdir (dir))
    {
        const char *ext = strrchr (entry->d_name, '.');
        if (ext && strcmp (".lua", ext) == 0)
        {
            char *filename = g_strdup_printf ("%s/%s", path, entry->d_name);
            int error;

            DEBUG ("ALFRED: Load Lua file \"%s\"\n", filename);

            /* Execute the script */
            pthread_mutex_lock (&alfred->ls_lock);
            lua_getglobal (alfred->ls, "debug");
            lua_getfield (alfred->ls, -1, "traceback");
            error = luaL_loadfile (alfred->ls, filename);
            if (error == 0)
                error = lua_pcall (alfred->ls, 0, 0, 0);
            if (error != 0)
                alfred_error (alfred->ls, error);
            g_free (filename);

            while (lua_gettop (alfred->ls))
                lua_pop (alfred->ls, 1);

            pthread_mutex_unlock (&alfred->ls_lock);

            /* Stop processing files if there has been an error */
            if (error != 0)
            {
                res = false;
                goto exit;
            }
        }
    }
    rewinddir (dir);

    /* Load all XML files */
    for (entry = readdir (dir); entry; entry = readdir (dir))
    {
        const char *ext = strrchr (entry->d_name, '.');
        if (ext && strcmp (".xml", ext) == 0)
        {
            /* Full path */
            char *filename = g_strdup_printf ("%s%s%s", path,
                path[strlen (path) - 1] == '/' ? "" : "/", entry->d_name);

            DEBUG ("ALFRED: Parse XML file \"%s\"\n", filename);

            /* Parse the file */
            xmlDoc *doc = xmlReadFile (filename, NULL, 0);
            if (doc == NULL)
            {
                ERROR ("ALFRED: Invalid file \"%s\"\n", filename);
                g_free (filename);
                res = false;
                goto exit;
            }
            res = process_node (alfred, xmlDocGetRootElement (doc), NULL);
            xmlFreeDoc (doc);
            g_free (filename);

            /* Stop processing files if there has been an error */
            if (!res)
                goto exit;
        }
    }

  exit:
    closedir (dir);
    return res;
}

typedef struct delayed_execute_s
{
    char *script;
} delayed_execute;

GList *delayed_work = NULL;
pthread_mutex_t delayed_work_lock = PTHREAD_MUTEX_INITIALIZER;

static gboolean
delayed_work_process (gpointer script)
{
    pthread_mutex_lock (&delayed_work_lock);

    /* Remove the script to be run */
    delayed_work = g_list_remove (delayed_work, script);
    pthread_mutex_unlock (&delayed_work_lock);

    /* Execute the script */
    pthread_mutex_lock (&alfred_inst->ls_lock);
    alfred_exec (alfred_inst->ls, script);
    pthread_mutex_unlock (&alfred_inst->ls_lock);

    return true;
}

static void
delayed_work_add (int delay, const char *script)
{
    bool found = false;
    delayed_execute *de = g_malloc0 (sizeof (delayed_execute));

    de->script = g_strdup (script);
    pthread_mutex_lock (&delayed_work_lock);
    for (GList * iter = delayed_work; iter; iter = g_list_next (iter))
    {
        delayed_execute *de_list = (delayed_execute *) script;
        if (strcmp (de_list->script, de->script) == 0)
        {
            found = true;
            break;
        }
    }
    if (found)
    {
        g_free (de->script);
        g_free (de);
    }
    else
    {
        delayed_work = g_list_append (delayed_work, de);
        g_timeout_add (delay * SECONDS_TO_MILLI, delayed_work_process, &script);
    }
    pthread_mutex_unlock (&delayed_work_lock);
}

static int
rate_limit (lua_State *ls)
{
    bool failure = false;
    if (lua_gettop (ls) != 2)
    {
        ERROR ("Alfred.rate_limit() takes 2 arguements\n");
        failure = true;
    }
    if (!lua_isnumber (ls, 1))
    {
        ERROR ("First argument to Alfred.rate_limit() must be a number");
        failure = true;
    }
    if (!lua_isstring (ls, 2))
    {
        ERROR ("Second argument to Alfred.rate_limit() must be a string");
        failure = true;
    }

    if (failure)
    {
        return 0;
    }

    delayed_work_add (lua_tonumber (ls, 1), lua_tostring (ls, 2));

    return 0;
}

alfred_instance
alfred_init (const char *path)
{
    alfred_instance alfred = NULL;

    assert (path);

    /* Malloc memory for the new service */
    alfred = (alfred_instance) g_malloc0 (sizeof (*alfred));
    if (!alfred)
    {
        ERROR ("ALFRED: No memory for alfred instance\n");
        goto error;
    }

    /* Create the hash table for alfreds */
    alfred->actions = g_hash_table_new (g_str_hash, g_str_equal);
    if (!alfred->actions)
    {
        ERROR ("ALFRED: Failed to allocate hash table\n");
        goto error;
    }

    /* Initialise the Lua state */
    alfred->ls = luaL_newstate ();
    if (!alfred->ls)
    {
        ERROR ("XML: Failed to instantiate Lua interpreter\n");
        goto error;
    }
    luaL_openlibs (alfred->ls);
    lua_setglobal (alfred->ls, "Apteryx");
    if (luaL_dostring (alfred->ls, "require('api')") != 0)
    {
        ERROR ("Lua: Failed to require('api')\n");
    }

    /* Add the rate_limit function to a Lua table so it can be called using Lua */
    lua_newtable(alfred->ls);
    lua_pushstring(alfred->ls, "alfred");
    lua_pushcfunction(alfred->ls, rate_limit);
    lua_setfield(alfred->ls, -3, "rate_limit");

    pthread_mutex_init (&alfred->ls_lock, NULL);

    /* Parse files in the config path */
    if (!load_config_files (alfred, path))
    {
        goto error;
    }

    /* Register actions */
    g_hash_table_foreach (alfred->actions, (GHFunc) alfred_register, GINT_TO_POINTER (1));

    return alfred;

  error:
    if (alfred)
    {
        if (alfred->ls)
            lua_close (alfred->ls);
        if (alfred->actions)
            g_hash_table_destroy (alfred->actions);
        g_free (alfred);
    }
    return NULL;
}

static void
alfred_shutdown (alfred_instance alfred)
{
    assert (alfred);

    if (alfred->ls)
        lua_close (alfred->ls);
    if (alfred->actions)
    {
        g_hash_table_foreach (alfred->actions, (GHFunc) alfred_register,
                              GINT_TO_POINTER (0));
        g_hash_table_foreach (alfred->actions, (GHFunc) destroy_alfred, NULL);
        g_hash_table_destroy (alfred->actions);
    }
    g_free (alfred);

    return;
}

void
termination_handler (void)
{
    running = false;
}

void
help (char *app_name)
{
    printf ("Usage: %s [-h] [-b] [-d] [-p <pidfile>] [-c <configdir>]\n"
            "  -h   show this help\n"
            "  -b   background mode\n"
            "  -d   enable verbose debug\n"
            "  -m   memory profiling\n"
            "  -p   use <pidfile> (defaults to "APTERYX_ALFRED_PID")\n"
            "  -c   use <configdir> (defaults to "APTERYX_CONFIG_DIR")\n",
            app_name);
}

int
main (int argc, char *argv[])
{
    const char *pid_file = APTERYX_ALFRED_PID;
    const char *config_dir = APTERYX_CONFIG_DIR;
    int i = 0;
    bool background = false;
    FILE *fp = NULL;

    /* Parse options */
    while ((i = getopt (argc, argv, "hdbp:c:m")) != -1)
    {
        switch (i)
        {
        case 'd':
            debug = true;
            background = false;
            break;
        case 'b':
            background = true;
            break;
        case 'p':
            pid_file = optarg;
            break;
        case 'c':
            config_dir = optarg;
            break;
        case 'm':
            g_mem_set_vtable (glib_mem_profiler_table);
            break;
        case '?':
        case 'h':
        default:
            help (argv[0]);
            return 0;
        }
    }

    /* Handle SIGTERM/SIGINT/SIGPIPE gracefully */
    signal (SIGTERM, (__sighandler_t) termination_handler);
    signal (SIGINT, (__sighandler_t) termination_handler);
    signal (SIGPIPE, SIG_IGN);

    /* Daemonize */
    if (background && fork () != 0)
    {
        /* Parent */
        return 0;
    }

    /* Initialise Apteryx client library */
    apteryx_init (debug);

    /* Create the alfred hash table */
    alfred_inst = alfred_init (config_dir);
    if (!alfred_inst)
        goto exit;

    /* Create pid file */
    if (background)
    {
        fp = fopen (pid_file, "w");
        if (!fp)
        {
            ERROR ("Failed to create PID file %s\n", pid_file);
            goto exit;
        }
        fprintf (fp, "%d\n", getpid ());
        fclose (fp);
    }

    /* Loop while not terminated */
    while (running)
    {
        sleep (1);
    }

  exit:
    /* Clean alfreds */
    if (alfred_inst)
        alfred_shutdown (alfred_inst);

    /* Cleanup client library */
    apteryx_shutdown ();

    /* Remove the pid file */
    if (background)
        unlink (pid_file);

    return 0;
}
