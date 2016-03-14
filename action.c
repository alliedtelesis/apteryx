/**
 * @file action.c
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

#define APTERYX_DO_PID "/var/run/apteryx-do.pid"
#define APTERYX_CONFIG_DIR "/etc/apteryx/schema/"

/* Debug */
bool debug = false;
/* Run while true */
static bool running = true;


/* Action object */
typedef struct action_t
{
    /* Watched path */
    char *path;
    /* Script to action when the path changes */
    char *script;
    /* TODO */
    bool leaf;
} action_t;

/* An Action instance. */
struct action_instance_t {
    /* Hash table of actions based on path */
    GHashTable *actions;
    /* Lua state */
    lua_State *ls;
    /* Lock for Lua state */
    pthread_mutex_t ls_lock;
} action_instance_t;
typedef struct action_instance_t *action_instance;

/* The one and only instance */
action_instance action_inst = NULL;

static void
action_error (lua_State *ls, int res)
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
action_exec (lua_State *ls, const char *script)
{
    int res = 0;

    res = luaL_loadstring (ls, script);
    if (res == 0)
        res = lua_pcall (ls, 0, 0, 0);
    if (res != 0)
        action_error (ls, res);

    lua_gc (ls, LUA_GCCOLLECT, 0);

    return (res == 0);
}

static bool
node_changed (const char *path, const char *value)
{
    char *_path = NULL;
    action_t *action = NULL;
    bool ret = false;

    assert (path);
    assert (action_inst);

    /* Find a matching action */
    _path = g_strdup (path);
    action = g_hash_table_lookup (action_inst->actions, _path);
    while (action == NULL && strlen (_path) > 1)
    {
        *(strrchr (_path, '/')) = '\0';
        action = g_hash_table_lookup (action_inst->actions, _path);
    }
    g_free (_path);
    if (action == NULL)
    {
        ERROR ("ACTION: No action for %s\n", path);
        return false;
    }

    DEBUG ("ACTION: %s = %s\n", path, value);

    pthread_mutex_lock (&action_inst->ls_lock);
    lua_pushstring (action_inst->ls, path);
    lua_setglobal (action_inst->ls, "_path");
    lua_pushstring (action_inst->ls, value);
    lua_setglobal (action_inst->ls, "_value");
    ret = action_exec (action_inst->ls, action->script);
    pthread_mutex_unlock (&action_inst->ls_lock);
    return ret;
}

static void
action_register (gpointer key, gpointer value, gpointer user_data)
{
    action_t *action = (action_t *) value;
    int install = GPOINTER_TO_INT (user_data);
    char *path;

    if (!action->leaf)
        path = g_strdup_printf ("%s/*", action->path);
    else
        path = g_strdup (action->path);

    if ((install && !apteryx_watch (path, node_changed)) ||
        (!install && !apteryx_unwatch (path, node_changed)))
    {
        ERROR ("Failed to (un)register watch for path %s\n", action->path);
    }

    g_free (path);
}

static action_t*
create_action (const char *path, const char *script, bool leaf)
{
    action_t * action;

    action = g_malloc0 (sizeof (action_t));
    if (!action)
    {
        ERROR ("XML: Failed to allocate memory for action\n");
        return NULL;
    }
    action->path = g_strdup (path);
    action->script = g_strdup (script);
    action->leaf = leaf;
    return action;
}

static bool
destroy_action (gpointer key, gpointer value, gpointer rpc)
{
    action_t *action = (action_t *) value;

    DEBUG ("XML: Destroy action for path %s\n", action->path);

    /* Free the action */
    g_free (action->path);
    g_free (action->script);
    g_free (action);

    return true;
}

static bool
node_is_leaf (xmlNode *node)
{
    for (xmlNode *n = node->children; n; n = n->next)
    {
        if (n->type == XML_ELEMENT_NODE &&
            strcmp ((const char *) n->name, "NODE") == 0)
            return false;
    }
    return true;
}

static bool
process_node (action_instance action, xmlNode *node, char *parent)
{
    xmlChar *name = NULL;
    xmlChar *content = NULL;
    char *path = NULL;
    bool res = true;

    assert (action);

    /* Ignore fluff */
    if (!node || node->type != XML_ELEMENT_NODE)
        return true;

    /* Process this node */
    if (strcmp ((const char *) node->name, "NODE") == 0)
    {
        /* Find node name and path */
        name = xmlGetProp (node, (xmlChar*)"name");
        if (parent)
            path = g_strdup_printf ("%s/%s", parent, name);
        else
            path = g_strdup_printf ("/%s", name);

        DEBUG ("XML: %s: %s (%s)\n", node->name, name, path);
    }
    else if (strcmp ((const char *) node->name, "ACTION") == 0)
    {
        content = xmlNodeGetContent (node);
        action_t *act = create_action (parent, (char *) content, node_is_leaf (node->parent));
        if (!act)
        {
            res = false;
            goto exit;
        }
        g_hash_table_insert (action->actions, act->path, act);

        DEBUG ("XML: %s: (%s) %s\n", node->name, act->path, act->script);
    }
    else if (strcmp ((const char *) node->name, "SCRIPT") == 0)
    {
        bool ret = false;
        content = xmlNodeGetContent (node);
        DEBUG ("XML: %s: %s\n", node->name, content);
        pthread_mutex_lock (&action->ls_lock);
        ret = action_exec (action->ls, (char *) content);
        pthread_mutex_unlock (&action->ls_lock);
        if (!ret)
        {
            res = false;
            goto exit;
        }
    }

    /* Process children */
    for (xmlNode *n = node->children; n; n = n->next)
    {
        if (!process_node (action, n, path))
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
load_config_files (action_instance action, const char *path)
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

            DEBUG ("ACTION: Load Lua file \"%s\"\n", filename);

            /* Execute the script */
            pthread_mutex_lock (&action->ls_lock);
            lua_getglobal (action->ls, "debug");
            lua_getfield (action->ls, -1, "traceback");
            error = luaL_loadfile (action->ls, filename);
            if (error == 0)
                error = lua_pcall (action->ls, 0, 0, 0);
            if (error != 0)
                action_error (action->ls, error);
            g_free (filename);

            while (lua_gettop (action->ls))
                lua_pop (action->ls, 1);

            pthread_mutex_unlock (&action->ls_lock);

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

            DEBUG ("ACTION: Parse XML file \"%s\"\n", filename);

            /* Parse the file */
            xmlDoc *doc = xmlReadFile (filename, NULL, 0);
            if (doc == NULL)
            {
                ERROR ("ACTION: Invalid file \"%s\"\n", filename);
                g_free (filename);
                res = false;
                goto exit;
            }
            res = process_node (action, xmlDocGetRootElement(doc), NULL);
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

typedef struct delayed_execute_s {
    time_t run_at;
    char *script;
    bool once;
} delayed_execute;

GList *delayed_work = NULL;
pthread_mutex_t delayed_work_lock = PTHREAD_MUTEX_INITIALIZER;

static void
delayed_work_add (int delay, const char *script, bool once)
{
    bool found = false;
    delayed_execute *de = g_malloc0(sizeof (delayed_execute));

    de->run_at = time(NULL) + delay;
    de->script = g_strdup (script);
    de->once = once;

    pthread_mutex_lock (&delayed_work_lock);
    for (GList *iter = delayed_work; iter; iter = g_list_next (iter))
    {
        delayed_execute *de_list = (delayed_execute *)iter->data;
        if (once && strcmp (de_list->script, de->script) == 0)
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
    }
    pthread_mutex_unlock (&delayed_work_lock);
}

static void
delayed_work_process ()
{
    GList *removals = NULL;
    time_t now = time (NULL);

    pthread_mutex_lock (&delayed_work_lock);
    for (GList *iter = delayed_work; iter; iter = g_list_next (iter))
    {
        delayed_execute *de = (delayed_execute *)iter->data;
        if (de->run_at <= now)
        {
            removals = g_list_append (removals, de);
        }
    }
    /* Remove all of the found entries */
    for (GList *iter = removals; iter; iter = g_list_next (iter))
    {
        delayed_work = g_list_remove (delayed_work, iter->data);
    }
    pthread_mutex_unlock (&delayed_work_lock);

    /* Execute (and free) all the found entries */
    for (GList *iter = removals; iter; iter = g_list_next (iter))
    {
        delayed_execute *de = (delayed_execute *)iter->data;
        pthread_mutex_lock (&action_inst->ls_lock);
        action_exec (action_inst->ls, de->script);
        pthread_mutex_unlock (&action_inst->ls_lock);
        g_free (de->script);
    }
    g_list_free_full (removals, g_free);
}

static int
once_every (lua_State *ls)
{
    bool failure = false;
    if(lua_gettop(ls) != 2)
    {
        ERROR("once_every() takes 2 arguements\n");
        failure = true;
    }
    if(!lua_isnumber(ls, 1))
    {
        ERROR("First argument to once_every() must be a number");
        failure = true;
    }
    if(!lua_isstring(ls, 2))
    {
        ERROR("Second argument to once_every() must be a string");
        failure = true;
    }

    if (failure)
    {
        return 0;
    }

    delayed_work_add (lua_tonumber(ls, 1), lua_tostring(ls, 2), true);

    return 0;
}

static int
defer (lua_State *ls)
{
    bool failure = false;
    if(lua_gettop(ls) != 2)
    {
        ERROR("defer takes 2 arguements\n");
        failure = true;
    }
    if(!lua_isnumber(ls, 1))
    {
        ERROR("First argument to defer() must be a number");
        failure = true;
    }
    if(!lua_isstring(ls, 2))
    {
        ERROR("Second argument to defer() must be a string");
        failure = true;
    }

    if (failure)
    {
        return 0;
    }

    delayed_work_add (lua_tonumber(ls, 1), lua_tostring(ls, 2), false);

    return 0;
}

action_instance
action_init (const char *path)
{
    action_instance action = NULL;

    assert (path);

    /* Malloc memory for the new service */
    action = (action_instance) g_malloc0 (sizeof (*action));
    if (!action)
    {
        ERROR("ACTION: No memory for action instance\n");
        goto error;
    }

    /* Create the hash table for actions */
    action->actions = g_hash_table_new (g_str_hash, g_str_equal);
    if (!action->actions)
    {
        ERROR("ACTION: Failed to allocate hash table\n");
        goto error;
    }

    /* Initialise the Lua state */
    action->ls = luaL_newstate ();
    if (!action->ls)
    {
        ERROR("XML: Failed to instantiate Lua interpreter\n");
        goto error;
    }
    luaL_openlibs(action->ls);
    lua_setglobal (action->ls, "Apteryx");
    if(luaL_dostring(action->ls, "require('api')") != 0)
    {
        ERROR("Lua: Failed to require('api')\n");
    }
    lua_register(action->ls, "once_every", once_every);
    lua_register(action->ls, "defer", defer);

    pthread_mutex_init (&action->ls_lock, NULL);

    /* Parse files in the config path */
    if (!load_config_files (action, path))
    {
        goto error;
    }

    /* Register actions */
    g_hash_table_foreach (action->actions, (GHFunc) action_register, GINT_TO_POINTER(1));

    return action;

error:
    if (action)
    {
        if (action->ls)
            lua_close (action->ls);
        if (action->actions)
            g_hash_table_destroy (action->actions);
        g_free (action);
    }
    return NULL;
}

static void
action_shutdown (action_instance action)
{
    assert (action);

    if (action->ls)
        lua_close (action->ls);
    if (action->actions)
    {
        g_hash_table_foreach (action->actions, (GHFunc) action_register, GINT_TO_POINTER(0));
        g_hash_table_foreach (action->actions, (GHFunc) destroy_action, NULL);
        g_hash_table_destroy (action->actions);
    }
    g_free (action);

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
            "  -p   use <pidfile> (defaults to "APTERYX_DO_PID")\n"
            "  -c   use <configdir> (defaults to "APTERYX_CONFIG_DIR")\n",
            app_name);
}

int
main (int argc, char *argv[])
{
    const char *pid_file = APTERYX_DO_PID;
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

    /* Create the action hash table */
    action_inst = action_init (config_dir);
    if (!action_inst)
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
        delayed_work_process ();
        sleep (1);
    }

exit:
    /* Clean actions */
    if (action_inst)
        action_shutdown (action_inst);

    /* Cleanup client library */
    apteryx_shutdown ();

    /* Remove the pid file */
    if (background)
        unlink (pid_file);

    /* Memory profiling */
    g_mem_profile ();

    return 0;
}
