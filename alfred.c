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
#include "internal.h"
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
#include <glib-unix.h>
#include <lua.h>

/* Change the following to alfred*/
#define APTERYX_ALFRED_PID "/var/run/apteryx-alfred.pid"
#define APTERYX_CONFIG_DIR "/etc/apteryx/schema/"
#define SECONDS_TO_MILLI 1000

/* Debug */
bool debug = false;

/* An Alfred instance. */
struct alfred_instance_t
{
    /* Lua state */
    lua_State *ls;
    /* Lock for Lua state */
    pthread_mutex_t ls_lock;
    /* List of watches based on path */
    GList *watches;
    /* List of provides based on path */
    GList *provides;
    /* List of provides based on path */
    GList *indexes;
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
watch_node_changed (const char *path, const char *value)
{
    GList *matches = NULL;
    GList *node = NULL;
    GList *script = NULL;
    GList *scripts = NULL;
    bool ret = false;
    cb_info_t *cb = NULL;

    assert (path);
    assert (alfred_inst);

    matches = cb_match (&alfred_inst->watches, path, CB_MATCH_EXACT |
                        CB_PATH_MATCH_PART | CB_MATCH_WILD_PATH);
    if (matches == NULL)
    {
        ERROR ("ALFRED: No Alfred watch for %s\n", path);
        return false;
    }

    pthread_mutex_lock (&alfred_inst->ls_lock);
    for (node = g_list_first (matches); node != NULL; node = g_list_next (node))
    {
        cb = node->data;
        scripts = (GList *) (long) cb->cb;
        for (script = g_list_first (scripts); script != NULL; script = g_list_next (script))
        {
            lua_pushstring (alfred_inst->ls, path);
            lua_setglobal (alfred_inst->ls, "_path");
            lua_pushstring (alfred_inst->ls, value);
            lua_setglobal (alfred_inst->ls, "_value");
            ret = alfred_exec (alfred_inst->ls, script->data);
        }
        cb_release (cb);
    }
    g_list_free (matches);
    pthread_mutex_unlock (&alfred_inst->ls_lock);
    DEBUG ("ALFRED WATCH: %s = %s\n", path, value);

    return ret;
}

char *
provide_node_changed (const char *path)
{
    const char *const_value = NULL;
    char *ret = NULL;
    GList *matches = NULL;
    GList *node = NULL;
    char *script = NULL;
    cb_info_t *cb = NULL;

    matches = cb_match (&alfred_inst->provides, path, CB_MATCH_EXACT | CB_MATCH_WILD_PATH);
    if (matches == NULL)
    {
        ERROR ("ALFRED: No Alfred provide for %s\n", path);
        return NULL;
    }

    pthread_mutex_lock (&alfred_inst->ls_lock);
    cb = matches->data;
    script = (char *) (long) cb->cb;
    lua_pushstring (alfred_inst->ls, path);
    lua_setglobal (alfred_inst->ls, "_path");
    if ((luaL_dostring (alfred_inst->ls, script)) != 0)
    {
        ERROR ("Lua: Failed to execute script\n");
    }
    for (node = g_list_first (matches); node != NULL; node = g_list_next (node))
    {
        cb = node->data;
        cb_release (cb);
    }
    g_list_free (matches);
    /* The return value of luaL_dostring is the top value of the stack */
    const_value = lua_tostring (alfred_inst->ls, -1);
    lua_pop (alfred_inst->ls, 1);
    ret = g_strdup (const_value);
    pthread_mutex_unlock (&alfred_inst->ls_lock);
    return ret;
}

static GList *
index_node_changed (const char *path)
{
    char *script = NULL;
    const char *tmp_path = NULL;
    char *tmp_path2 = NULL;
    GList *ret = NULL;
    GList *matches = NULL;
    GList *node = NULL;
    cb_info_t *cb = NULL;

    matches = cb_match (&alfred_inst->indexes, path, CB_MATCH_EXACT | CB_MATCH_WILD_PATH);
    if (matches == NULL)
    {
        ERROR ("ALFRED: No Alfred index for %s\n", path);
        return NULL;
    }
    cb = matches->data;
    script = (char *) (long) cb->cb;
    pthread_mutex_lock (&alfred_inst->ls_lock);
    lua_pushstring (alfred_inst->ls, path);
    lua_setglobal (alfred_inst->ls, "_path");
    if ((luaL_dostring (alfred_inst->ls, script)) != 0)
    {
        ERROR ("Lua: Failed to execute script\n");
    }
    for (node = g_list_first (matches); node != NULL; node = g_list_next (node))
    {
        cb = node->data;
        cb_release (cb);
    }
    g_list_free (matches);
    while (lua_gettop (alfred_inst->ls) && lua_isstring (alfred_inst->ls, -1))
    {
        tmp_path = lua_tostring (alfred_inst->ls, -1);
        tmp_path2 = strdup (tmp_path);
        lua_pop (alfred_inst->ls, 1);
        ret = g_list_append (ret, tmp_path2);
    }
    pthread_mutex_unlock (&alfred_inst->ls_lock);
    return ret;
}

static void
alfred_register_watches (gpointer value, gpointer user_data)
{
    cb_info_t *cb = (cb_info_t *) value;
    int install = GPOINTER_TO_INT (user_data);

    if ((install && !apteryx_watch (cb->path, watch_node_changed)) ||
        (!install && !apteryx_unwatch (cb->path, watch_node_changed)))
    {
        ERROR ("Failed to (un)register watch for path %s\n", cb->path);
    }
}

static void
alfred_register_provide (gpointer value, gpointer user_data)
{
    cb_info_t *cb = (cb_info_t *) value;
    int install = GPOINTER_TO_INT (user_data);

    if ((install && !apteryx_provide (cb->path, provide_node_changed)) ||
        (!install && !apteryx_unprovide (cb->path, provide_node_changed)))
    {
        ERROR ("Failed to (un)register provide for path %s\n", cb->path);
    }
}

static void
alfred_register_index (gpointer value, gpointer user_data)
{
    cb_info_t *cb = (cb_info_t *) value;
    int install = GPOINTER_TO_INT (user_data);

    if ((install && !apteryx_index (cb->path, index_node_changed)) ||
        (!install && !apteryx_unindex (cb->path, index_node_changed)))
    {
        ERROR ("Failed to (un)register provide for path %s\n", cb->path);
    }
}

static bool
destroy_watches (gpointer value, gpointer rpc)
{
    cb_info_t *cb = (cb_info_t *) value;
    GList *scripts = (GList *) (long) cb->cb;
    DEBUG ("XML: Destroy watches for path %s\n", cb->path);

    g_list_free_full (scripts, g_free);
    cb_release (cb);

    return true;
}

static bool
destroy_provides (gpointer value, gpointer rpc)
{
    cb_info_t *cb = (cb_info_t *) value;
    char *script = (char *) (long) cb->cb;
    DEBUG ("XML: Destroy provides for path %s\n", cb->path);

    g_free (script);
    cb_release (cb);

    return true;
}

static bool
destroy_indexes (gpointer value, gpointer rpc)
{
    cb_info_t *cb = (cb_info_t *) value;
    char *script = (char *) (long) cb->cb;
    DEBUG ("XML: Destroy indexes for path %s\n", cb->path);

    g_free (script);
    cb_release (cb);
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
    char *tmp_content = NULL;
    GList *matches = NULL;
    GList *scripts = NULL;
    cb_info_t *cb;
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
    else if (strcmp ((const char *) node->name, "WATCH") == 0)
    {
        content = xmlNodeGetContent (node);
        tmp_content = g_strdup ((char *) content);
        /* If the node is a leaf or ends in a '*' don't add another '*' */
        if (node_is_leaf (node->parent) || parent[strlen (parent) - 1] == '*')
        {
            path = g_strdup (parent);
        }
        else
        {
            path = g_strdup_printf ("%s/*", parent);
        }

        if (alfred->watches)
        {
            matches = cb_match (&alfred->watches, path, CB_MATCH_EXACT);
        }
        if (matches == NULL)
        {
            scripts = g_list_append (scripts, tmp_content);
            cb = cb_create (&alfred->watches, "", (const char *) path, 0,
                            (uint64_t) (long) scripts);
        }
        else
        {
            /* A watch already exists on that exact path */
            cb = matches->data;
            scripts = (GList *) (long) cb->cb;
            scripts = g_list_append (scripts, tmp_content);
            g_list_free (matches);
        }
        DEBUG ("XML: %s: (%s)\n", node->name, cb->path);
        cb_release (cb);
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
    else if (strcmp ((const char *) node->name, "PROVIDE") == 0)
    {
        content = xmlNodeGetContent (node);
        tmp_content = g_strdup ((char *) content);
        cb = cb_create (&alfred->provides, "", (const char *) parent, 0,
                        (uint64_t) (long) tmp_content);
        cb_release (cb);
        DEBUG ("PROVIDE: %s, XML STR: %s\n", parent, content);
    }

    else if (strcmp ((const char *) node->name, "INDEX") == 0)
    {
        content = xmlNodeGetContent (node);
        tmp_content = g_strdup ((char *) content);
        DEBUG ("INDEX: XML STR: %s\n", content);

        /* If the node is a leaf or ends in a '*' don't add another '*' */
        if (node_is_leaf (node->parent) || parent[strlen (parent) - 1] == '*')
        {
            path = g_strdup (parent);
        }
        else
        {
            path = g_strdup_printf ("%s/*", parent);
        }

        if (path)
        {
            cb = cb_create (&alfred->indexes, "", (const char *) path, 0,
                            (uint64_t) (long) tmp_content);
            cb_release (cb);
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

GList *delayed_work = NULL;
pthread_mutex_t delayed_work_lock = PTHREAD_MUTEX_INITIALIZER;

static gboolean
delayed_work_process (gpointer arg1)
{
    char *script = (char *) arg1;
    pthread_mutex_lock (&delayed_work_lock);

    /* Remove the script to be run */
    delayed_work = g_list_remove (delayed_work, script);
    pthread_mutex_unlock (&delayed_work_lock);

    /* Execute the script */
    pthread_mutex_lock (&alfred_inst->ls_lock);
    alfred_exec (alfred_inst->ls, script);
    pthread_mutex_unlock (&alfred_inst->ls_lock);
    g_free (script);
    return false;
}

static void
delayed_work_add (int delay, const char *script)
{
    bool found = false;
    char *delay_script = NULL;

    delay_script = g_strdup (script);
    pthread_mutex_lock (&delayed_work_lock);
    for (GList * iter = delayed_work; iter; iter = g_list_next (iter))
    {
        char *script_list = (char *) iter->data;
        if (strcmp (delay_script, script_list) == 0)
        {
            found = true;
            break;
        }
    }
    if (found)
    {
        g_free (delay_script);
    }
    else
    {
        delayed_work = g_list_append (delayed_work, delay_script);
        g_timeout_add (delay * SECONDS_TO_MILLI, delayed_work_process, (gpointer) delay_script);
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
        ERROR ("First argument to Alfred.rate_limit() must be a number\n");
        failure = true;
    }
    if (!lua_isstring (ls, 2))
    {
        ERROR ("Second argument to Alfred.rate_limit() must be a string\n");
        failure = true;
    }

    if (failure)
    {
        return 0;
    }

    delayed_work_add (lua_tonumber (ls, 1), lua_tostring (ls, 2));

    return 0;
}

static void
alfred_shutdown (alfred_instance alfred)
{
    assert (alfred);

    if (alfred->ls)
        lua_close (alfred->ls);
    if (alfred->watches)
    {
        g_list_foreach (alfred->watches, (GFunc) alfred_register_watches,
                        GINT_TO_POINTER (0));
        g_list_foreach (alfred->watches, (GFunc) destroy_watches, NULL);
        g_list_free (alfred->watches);
    }
    if (alfred->provides)
    {
        g_list_foreach (alfred->provides, (GFunc) alfred_register_provide,
                        GINT_TO_POINTER (0));
        g_list_foreach (alfred->provides, (GFunc) destroy_provides, NULL);
        g_list_free (alfred->provides);
    }
    if (alfred->indexes)
    {
        g_list_foreach (alfred->indexes, (GFunc) alfred_register_index,
                        GINT_TO_POINTER (0));
        g_list_foreach (alfred->indexes, (GFunc) destroy_indexes, NULL);
        g_list_free (alfred->indexes);
    }
    g_free (alfred);

    return;
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

    /* Initialise the Lua state */
    alfred->ls = luaL_newstate ();
    if (!alfred->ls)
    {
        ERROR ("XML: Failed to instantiate Lua interpreter\n");
        goto error;
    }
    luaL_openlibs (alfred->ls);
    if (luaL_dostring (alfred->ls, "require('api')") != 0)
    {
        ERROR ("Lua: Failed to require('api')\n");
    }

    /* Add the rate_limit function to a Lua table so it can be called using Lua */
    lua_newtable (alfred->ls);
    lua_pushcfunction (alfred->ls, rate_limit);
    lua_setfield (alfred->ls, -2, "rate_limit");
    lua_setglobal (alfred->ls, "Alfred");

    pthread_mutex_init (&alfred->ls_lock, NULL);

    /* Parse files in the config path */
    if (!load_config_files (alfred, path))
    {
        goto error;
    }

    /* Register watches */
    g_list_foreach (alfred->watches, (GFunc) alfred_register_watches, GINT_TO_POINTER (1));

    /* Register provides */
    g_list_foreach (alfred->provides, (GFunc) alfred_register_provide, GINT_TO_POINTER (1));

    /* Register indexes */
    g_list_foreach (alfred->indexes, (GFunc) alfred_register_index, GINT_TO_POINTER (1));

    return alfred;

  error:
    if (alfred)
    {
        alfred_shutdown (alfred);
    }
    return NULL;
}

static gboolean
termination_handler (gpointer arg1)
{
    GMainLoop *loop = (GMainLoop *) arg1;
    g_main_loop_quit (loop);
    return false;
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
    GMainLoop *loop = NULL;

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

    /* Daemonize */
    if (background && fork () != 0)
    {
        /* Parent */
        return 0;
    }

    /* Initialise Apteryx client library */
    apteryx_init (debug);

    cb_init ();

    /* Create the alfred glists */
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

    loop = g_main_loop_new (NULL, true);

    /* Handle SIGTERM/SIGINT/SIGPIPE gracefully */
    g_unix_signal_add (SIGINT, termination_handler, loop);
    g_unix_signal_add (SIGTERM, termination_handler, loop);
    signal (SIGPIPE, SIG_IGN);

    /* Loop while not terminated */
    g_main_loop_run (loop);

  exit:
    /* Free the glib main loop */
    g_main_loop_unref (loop);

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
