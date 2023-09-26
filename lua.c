/**
 * @file lua.c
 * Lua bindings for Apteryx.
 *
 * Copyright 2014, Allied Telesis Labs New Zealand, Ltd
 *
 * Basic API Example:
 * > apteryx = require("apteryx")
 * > apteryx.set("/interfaces/eth0/state", "up")
 * > apteryx.set("/interfaces/eth1/state", "down")
 * > print(apteryx.get("/interfaces/eth0/state"))
 * up
 * > paths = apteryx.search("/interfaces/")
 * > print(unpack(paths))
 * /interfaces/eth0        /interfaces/eth1
 *
 * Schema based API example:
 * > api = require("apteryx").api("/etc/apteryx")
 * > api.interfaces("eth0").state = "up"
 * > api.interfaces("eth1").state = "down"
 * > print(api.interaces("eth0").state)
 * up
 * > paths = api.interaces()
 * > print(unpack(paths))
 * eth0    eth1
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
#ifdef HAVE_LUA
#include <sys/poll.h>
#include <lua.h>
#include <lauxlib.h>
#include "apteryx.h"
#include "internal.h"

#define lua_absindex(L, i) ((i) > 0 || (i) <= LUA_REGISTRYINDEX ? (i) : \
                                        lua_gettop(L) + (i) + 1)

static lua_State *g_L = NULL;

typedef enum {
    LUA_CALLBACK_WATCH,
    LUA_CALLBACK_REFRESH,
    LUA_CALLBACK_PROVIDE,
    LUA_CALLBACK_INDEX,
    LUA_CALLBACK_VALIDATE,
} lua_callback_type;

typedef struct lua_callback_info {
    lua_State *instance;
    int ref;
    lua_callback_type type;
    char *path;
} lua_callback_info;

static GList *callbacks = NULL;
static GHashTable *locks = NULL;
static pthread_rwlock_t lock_lock = PTHREAD_RWLOCK_INITIALIZER;

int luaopen_apteryx (lua_State *L);
static bool lua_apteryx_register_lock (lua_State *L);
static void lua_apteryx_unregister_lock (lua_State *L);
bool lua_apteryx_instance_lock (lua_State *L);
void lua_apteryx_instance_unlock (lua_State *L);

static lua_callback_info *
remove_callback_info (lua_State *L, size_t ref, lua_callback_type type)
{
    GList *iter;
    for (iter = callbacks; iter; iter = iter->next)
    {
        lua_callback_info *cb_info = iter->data;
        if (cb_info->instance == L && cb_info->ref == ref && cb_info->type == type)
        {
            callbacks = g_list_delete_link (callbacks, iter);
            return cb_info;
        }
    }
    return NULL;
}

static void
destroy_cb_info(lua_callback_info *cb_info)
{
    g_free(cb_info->path);
    g_free(cb_info);
}

static lua_callback_info *
new_lua_callback(lua_State *L, lua_callback_type type, const char *path, size_t ref)
{
    lua_callback_info *cb_info = g_malloc0 (sizeof (lua_callback_info));
    cb_info->instance = L;
    cb_info->ref = ref;
    cb_info->type = type;
    cb_info->path = g_strdup (path);

    callbacks = g_list_prepend (callbacks, cb_info);
    return cb_info;
}

static void
lua_apteryx_error (lua_State *ls, int res)
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

static const char *
lua_apteryx_tostring (lua_State *L, int i)
{
    const char *ret = NULL;
    int abs_index = lua_absindex (L, i);

    switch (lua_type (L, i))
    {
    case LUA_TNIL:
        return NULL;
    case LUA_TBOOLEAN:
        return lua_toboolean (L, i) ? "1" : "0";
    default:
        lua_getglobal (L, "tostring");
        lua_pushvalue (L, abs_index);
        lua_call (L, 1, 1);
        ret = lua_tostring (L, -1);
        lua_pop (L, 1);
    }

    return ret;
}

static void
_lua_apteryx_tree2dict (lua_State *L, GNode *this)
{
    GNode *child = NULL;

    if (!(this->children))
    {
        /* Something is wrong, either a value has been stored on a trunk
         * or get_tree was called on a leaf node. Both we do not support */
        return;
    }

    lua_pushstring (L, APTERYX_NAME (this));
    /* is this a leaf? */
    if (APTERYX_HAS_VALUE (this))
    {
        lua_pushstring (L, APTERYX_VALUE (this));
    }
    else
    {
        lua_newtable (L);
        for (child = g_node_first_child (this); child; child = g_node_next_sibling (child))
        {
            _lua_apteryx_tree2dict (L, child);
        }
    }

    lua_settable (L, -3);
}

static inline void
lua_apteryx_tree2dict (lua_State *L, GNode *this)
{
    GNode *child = NULL;
    lua_newtable (L);
    if (this)
    {
        for (child = g_node_first_child (this); child; child = g_node_next_sibling (child))
        {
            _lua_apteryx_tree2dict (L, child);
        }
    }
}

static bool
_lua_apteryx_dict2tree (lua_State *L, GNode *n, bool leaves)
{
    bool ret = false;
    GNode *c = NULL;
    const char *value = NULL;

    lua_pushnil (L);
    while (lua_next (L, -2))
    {
        if (lua_type (L, -1) == LUA_TTABLE)
        {
            lua_pushvalue (L, -2);
            c = APTERYX_NODE (n, strdup ((char *) lua_tostring (L, -1)));
            lua_pop (L, 1);
            if ((_lua_apteryx_dict2tree (L, c, leaves)) || !leaves)
            {
                ret = true;
            }
            else
            { /* destroy leafless sub-trees */
                apteryx_free_tree (c);
            }
        }
        else
        {
            value = lua_apteryx_tostring (L, -1);
            if (value)
            {
                lua_pushvalue (L, -2);
                APTERYX_LEAF (n, strdup ((char *) lua_tostring (L, -1)), strdup (value));
                lua_pop (L, 1);
                ret = true;
            }
        }
        lua_pop (L, 1);
    }
    return ret;
}

static inline GNode *
lua_apteryx_dict2tree (lua_State *L)
{
    GNode *root = NULL;
    root = APTERYX_NODE (NULL, (char *) strdup (lua_tostring (L, 1)));
    if (!_lua_apteryx_dict2tree (L, root, true))
    {
        apteryx_free_tree (root);
        root = NULL;
    }
    return root;
}

static inline GNode *
lua_apteryx_dict2tree_paths (lua_State *L)
{
    GNode *root = g_node_new (strdup ("/"));
    if (!_lua_apteryx_dict2tree (L, root, false))
    {
        apteryx_free_tree (root);
        root = NULL;
    }
    return root;
}

static int
lua_apteryx_debug (lua_State *L)
{
    if (lua_gettop (L) < 1 || !lua_isboolean (L, 1))
    {
        luaL_error (L, "Invalid arguments: requires boolean");
        return 0;
    }
    apteryx_debug = lua_toboolean (L, 1);
    return 0;
}

static int
lua_apteryx_set (lua_State *L)
{
    if (lua_gettop (L) < 1 || !lua_isstring (L, 1))
    {
        luaL_error (L, "Invalid arguments: requires path");
        return 0;
    }
    if (lua_gettop (L) < 2)
    {
        lua_pushnil (L);
    }
    lua_pushboolean (L, apteryx_set (lua_tostring (L, 1), lua_apteryx_tostring (L, 2)));
    return 1;
}

static int
lua_apteryx_get (lua_State *L)
{
    char *value = NULL;
    if (lua_gettop (L) != 1 || !lua_isstring (L, 1))
    {
        luaL_error (L, "Invalid arguments: requires path");
        return 0;
    }
    value = apteryx_get (lua_tostring (L, 1));
    if (value)
    {
        lua_pushstring (L, value);
        free (value);
        return 1;
    }
    return 0;
}

static int
lua_apteryx_search (lua_State *L)
{
    GList *paths;
    int num;
    if (lua_gettop (L) != 1 || !lua_isstring (L, 1))
    {
        luaL_error (L, "Invalid arguments: requires path");
        return 0;
    }
    paths = apteryx_search (lua_tostring (L, 1));
    num = g_list_length (paths);
    GList *_iter = paths;
    lua_createtable (L, num, 0);
    for (int i = 1; i <= num; i++)
    {
        const char *path = (char *) _iter->data;
        lua_pushstring (L, path);
        lua_rawseti (L, -2, i);
        _iter = _iter->next;
    }
    g_list_free_full (paths, free);
    return 1;
}

static int
lua_apteryx_find (lua_State *L)
{
    GList *paths;
    int num;
    if (lua_gettop (L) != 2 || !lua_isstring (L, 1) || !lua_isstring (L, 2))
    {
        luaL_error (L, "Invalid arguments: requires path and value");
        return 0;
    }
    paths = apteryx_find (lua_tostring (L, 1), lua_tostring (L, 2));
    num = g_list_length (paths);
    GList *_iter = paths;
    lua_createtable (L, num, 0);
    for (int i = 1; i <= num; i++)
    {
        const char *path = (char *) _iter->data;
        lua_pushstring (L, path);
        lua_rawseti (L, -2, i);
        _iter = _iter->next;
    }
    g_list_free_full (paths, free);
    return 1;
}

static int
lua_apteryx_prune (lua_State *L)
{
    if (lua_gettop (L) != 1 || !lua_isstring (L, 1))
    {
        luaL_error (L, "Invalid arguments: requires path");
        return 0;
    }
    lua_pushboolean (L, apteryx_prune (lua_tostring (L, 1)));
    return 1;
}

static int
lua_apteryx_set_tree (lua_State *L)
{
    GNode *root = NULL;

    if (lua_gettop (L) < 1 || !lua_isstring (L, 1))
    {
        luaL_error (L, "Invalid arguments: requires path");
        return 0;
    }
    if (lua_gettop (L) < 2 || !lua_istable (L, 2))
    {
        luaL_error (L, "Invalid arguments: requires table");
        return 0;
    }

    root = lua_apteryx_dict2tree (L);
    if (root)
    {
        lua_pushboolean (L, apteryx_set_tree (root));
        apteryx_free_tree (root);
    }

    return 1;
}

static int
lua_apteryx_get_tree (lua_State *L)
{
    GNode *tree = NULL;

    if (lua_gettop (L) != 1 || !lua_isstring (L, 1))
    {
        luaL_error (L, "Invalid arguments: requires path");
        return 0;
    }
    tree = apteryx_get_tree (lua_tostring (L, 1));
    lua_apteryx_tree2dict (L, tree);
    apteryx_free_tree (tree);
    return 1;
}

static int
lua_apteryx_query (lua_State *L)
{
    GNode *root = NULL;
    GNode *out_root = NULL;

    if (lua_gettop (L) != 1 || (!lua_istable (L, 1) && !lua_isstring (L, 1)))
    {
        luaL_error (L, "Invalid arguments: requires table or query string");
        return 0;
    }

    if (lua_istable (L, 1))
    {
        root = lua_apteryx_dict2tree_paths (L);
    }
    else
    {
        root = g_node_new (g_strdup ("/"));
        if (!apteryx_query_to_node (root, lua_tostring (L, 1)))
        {
            free ((void *)root->data);
            g_node_destroy (root);
            luaL_error (L, "Invalid arguments: query format invalid");
            return 0;
        }
    }

    if (root)
    {
        out_root = apteryx_query (root);
        lua_apteryx_tree2dict (L, out_root);
        apteryx_free_tree (root);
        apteryx_free_tree (out_root);
    }
    else
    {
        luaL_error (L, "Invalid arguments: no query paths specified");
        return 0;
    }
    return 1;
}

#define APTERYX_CB_TABLE_REGISTRY_INDEX "apteryx_cb_table"

static int
find_callback (lua_State *L, int index)
{
    int ref = 0;
    luaL_checktype (L, -1, LUA_TTABLE);
    /* lua_next pops requested key and pushes next key and value */
    lua_pushnil (L); /* push nil key to get first table entry */
    while (lua_next (L, -2))
    {
        if (lua_rawequal (L, index, -1))
        {
            ref = lua_tonumber (L, -2);
            lua_pop (L, 2); /* pop key and value */
            break;
        }
        lua_pop(L, 1); /* pop value but leave key on stack for lua_next */
    }
    return ref;
}

static int
ref_callback (lua_State* L, int index)
{
    luaL_checktype (L, index, LUA_TFUNCTION);
    lua_pushlightuserdata (L, APTERYX_CB_TABLE_REGISTRY_INDEX);
    lua_gettable (L, LUA_REGISTRYINDEX);
    if (lua_isnil (L, -1))
    {
        lua_pop (L, 1); /* pop nil */
        lua_pushlightuserdata (L, APTERYX_CB_TABLE_REGISTRY_INDEX);
        lua_newtable (L);
        lua_settable (L, LUA_REGISTRYINDEX);
        lua_pushlightuserdata (L, APTERYX_CB_TABLE_REGISTRY_INDEX);
        lua_gettable (L, LUA_REGISTRYINDEX);
    }
    int ref = find_callback (L, index);
    if (ref == 0)
    {
        lua_pushvalue (L, index);
        ref = luaL_ref (L, -2);
    }
    lua_pop (L, 1); /* pop table */
    return ref;
}

static bool
push_callback (lua_State* L, size_t ref)
{
    if (L == NULL)
        return false;
    lua_pushlightuserdata (L, APTERYX_CB_TABLE_REGISTRY_INDEX);
    lua_gettable (L, LUA_REGISTRYINDEX);
    if (lua_isnil (L, -1))
    {
        ERROR ("LUA: Callback not found\n");
        lua_pop (L, 1); /* pop nil */
        return false;
    }
    lua_rawgeti (L, -1, ref);
    if (!lua_isfunction (L, -1))
    {
        ERROR ("LUA: Callback not a function\n");
        lua_pop (L, 1);
        return false;
    }
    return true;
}

static GList*
lua_do_index (const char *path, lua_callback_info *cb_info)
{
    int res = 0;
    lua_State* L = cb_info->instance;
    size_t ref = cb_info->ref;
    GList *paths = NULL;

    ASSERT (L, return NULL, "Index: LUA is not multi-threaded (use apteryx.process)\n");
    if (lua_apteryx_instance_lock (L)) {
        int ssize = lua_gettop (L);
        if (!push_callback (L, ref))
        {
             lua_apteryx_instance_unlock (L);
             return NULL;
        }
        lua_pushstring (L, path);
        res = lua_pcall (L, 1, 1, 0);
        if (res != 0)
            lua_apteryx_error (L, res);
        if (lua_gettop (L))
        {
            if (lua_istable (L, -1))
            {
                lua_pushnil (L);
                while (lua_next(L, -2) != 0)
                {
                    paths = g_list_append (paths, strdup (lua_tostring (L, -1)));
                    lua_pop (L, 1);
                }
                lua_pop (L, 1);
            }
            else
            {
                ERROR ("LUA: Index did not return a table\n");
                lua_pop (L, 1);
            }
        }
        lua_pop (L, 1); /* pop fn */
        if (lua_gettop (L) != ssize)
        {
           ERROR ("Index: Stack changed\n");
        }
        lua_apteryx_instance_unlock(L);
    }
    return paths;
}

static int
lua_apteryx_index (lua_State *L)
{
    luaL_checktype (L, 1, LUA_TSTRING);
    luaL_checktype (L, 2, LUA_TFUNCTION);
    const char *path = lua_tostring (L, 1);
    size_t ref = ref_callback (L, 2);

    lua_callback_info *cb_info = new_lua_callback (L, LUA_CALLBACK_INDEX, path, ref);

    if (!add_callback (APTERYX_INDEXERS_PATH, path, (void *)lua_do_index, false, cb_info, 0))
    {
        luaL_error (L, "Failed to register callback\n");
        lua_pushboolean (L, false);
        return 1;
    }

    lua_pushboolean (L, true);
    return 1;
}

static int
lua_apteryx_unindex (lua_State *L)
{
    luaL_checktype(L, 1, LUA_TSTRING);
    luaL_checktype(L, 2, LUA_TFUNCTION);
    const char *path = lua_tostring (L, 1);
    size_t ref = ref_callback (L, 2);

    lua_callback_info *cb_info = remove_callback_info (L, ref, LUA_CALLBACK_INDEX);

    if (!delete_callback (APTERYX_INDEXERS_PATH, path, (void *)lua_do_index, cb_info))
    {
        luaL_error (L, "Failed to unregister callback\n");
        lua_pushboolean (L, false);
    }
    else
    {
        lua_pushboolean (L, true);
    }

    destroy_cb_info(cb_info);

    return 1;
}

static bool
lua_do_watch (const char *path, const char *value, lua_callback_info *cb_info)
{
    int res = 0;
    lua_State* L = cb_info->instance;
    size_t ref = cb_info->ref;

    ASSERT (L, return false, "Watch: LUA is not multi-threaded (use apteryx.process)\n");

    if (lua_apteryx_instance_lock (L))
    {
        int ssize = lua_gettop (L);
        if (!push_callback (L, ref))
        {
            lua_apteryx_instance_unlock (L);
            return false;
        }
        lua_pushstring (L, path);
        lua_pushstring (L, value);
        res = lua_pcall (L, 2, 0, 0);
        if (res != 0)
        {
            lua_apteryx_error (L, res);
        }
        lua_pop (L, 1); /* pop fn */

        if (lua_gettop (L) != ssize)
        {
            ERROR ("Watch: Stack changed\n");
        }
        lua_apteryx_instance_unlock (L);
    }

    return true;
}

static bool
lua_do_watch_tree (GNode *tree, size_t ref)
{
    int res = 0;
    lua_State* L = g_L;

    ASSERT (L, return false, "Watch: LUA is not multi-threaded (use apteryx.process)\n");
    int ssize = lua_gettop (L);
    if (!push_callback (L, ref))
        return false;
    lua_apteryx_tree2dict (L, tree);
    apteryx_free_tree (tree);
    res = lua_pcall (L, 1, 0, 0);
    if (res != 0)
        lua_apteryx_error (L, res);
    lua_pop (L, 1); /* pop fn */
    ASSERT (lua_gettop (L) == ssize, return true, "Watch: Stack changed\n");
    return true;
}

static int
lua_apteryx_watch (lua_State *L)
{
    luaL_checktype (L, 1, LUA_TSTRING);
    luaL_checktype (L, 2, LUA_TFUNCTION);
    const char *path = lua_tostring (L, 1);
    size_t ref = ref_callback (L, 2);

    if (!add_callback (APTERYX_WATCHERS_PATH, path, (void *)lua_do_watch, true, (void *) ref, 0, 0))
    {
        luaL_error (L, "Failed to register watch\n");
        lua_pushboolean (L, false);
        return 1;
    }

    lua_pushboolean (L, true);
    return 1;
}

static int
lua_apteryx_watch_tree (lua_State *L)
{
    luaL_checktype (L, 1, LUA_TSTRING);
    luaL_checktype (L, 2, LUA_TFUNCTION);
    const char *path = lua_tostring (L, 1);
    size_t ref = ref_callback (L, 2);
    lua_Integer timeout_ms = 0;
    if (lua_gettop (L) == 3 && lua_isinteger (L, 3))
        timeout_ms = lua_tointeger (L, 3);

    if (!add_callback (APTERYX_WATCHERS_PATH, path, (void *)lua_do_watch_tree, true, (void *) ref, 1, (uint64_t) timeout_ms))
    {
        luaL_error (L, "Failed to register watch\n");
        lua_pushboolean (L, false);
        return 1;
    }

    lua_pushboolean (L, true);
    return 1;
}

static int
lua_apteryx_unwatch (lua_State *L)
{
    luaL_checktype(L, 1, LUA_TSTRING);
    luaL_checktype(L, 2, LUA_TFUNCTION);
    const char *path = lua_tostring (L, 1);
    size_t ref = ref_callback (L, 2);

    lua_callback_info *cb_info = remove_callback_info (L, ref, LUA_CALLBACK_WATCH);

    if (!delete_callback (APTERYX_WATCHERS_PATH, path, (void *)lua_do_watch, cb_info))
    {
        luaL_error (L, "Failed to unregister callback\n");
        lua_pushboolean (L, false);
    }
    else
    {
        lua_pushboolean (L, true);
    }

    destroy_cb_info (cb_info);
    return 1;
}

static uint64_t
lua_do_refresh (const char *path, lua_callback_info *cb_info)
{
    int res = 0;
    lua_State* L = cb_info->instance;
    size_t ref = cb_info->ref;
    uint64_t timeout = 0;

    ASSERT (L, return 0, "Refresh: LUA is not multi-threaded (use apteryx.process)\n");
    if (lua_apteryx_instance_lock (L))
    {
        int ssize = lua_gettop (L);
        if (!push_callback (L, ref))
        {
            lua_apteryx_instance_unlock (L);
            return 0;
        }
        lua_pushstring (L, path);
        res = lua_pcall (L, 1, 1, 0);
        if (res != 0)
            lua_apteryx_error (L, res);
        if (lua_gettop (L))
        {
            timeout = lua_tonumber (L, -1);
            lua_pop (L, 1);
        }
        lua_pop (L, 1); /* pop fn */

        if (lua_gettop (L) != ssize)
        {
            ERROR("Refresh: Stack changed\n");
        }
        lua_apteryx_instance_unlock (L);
    }
    return timeout;
}

static int
lua_apteryx_refresh (lua_State *L)
{
    luaL_checktype (L, 1, LUA_TSTRING);
    luaL_checktype (L, 2, LUA_TFUNCTION);
    const char *path = lua_tostring (L, 1);
    size_t ref = ref_callback (L, 2);

    lua_callback_info *cb_info = new_lua_callback(L, LUA_CALLBACK_REFRESH, path, ref);

    if (!add_callback (APTERYX_REFRESHERS_PATH, path, (void *)lua_do_refresh, false, cb_info, 0))
    {
        luaL_error (L, "Failed to register refresh\n");
        lua_pushboolean (L, false);
        return 1;
    }

    lua_pushboolean (L, true);
    return 1;
}

static int
lua_apteryx_unrefresh (lua_State *L)
{
    luaL_checktype(L, 1, LUA_TSTRING);
    luaL_checktype(L, 2, LUA_TFUNCTION);
    const char *path = lua_tostring (L, 1);
    size_t ref = ref_callback (L, 2);
    lua_callback_info *cb_info = remove_callback_info (L, ref, LUA_CALLBACK_REFRESH);
    if (!delete_callback (APTERYX_REFRESHERS_PATH, path, (void *)lua_do_refresh, cb_info))
    {
        luaL_error (L, "Failed to unregister callback\n");
        lua_pushboolean (L, false);
    }
    else
    {
        lua_pushboolean (L, true);
    }
    destroy_cb_info (cb_info);
    return 1;
}

static int
lua_do_validate (const char *path, const char *value, lua_callback_info *cb_info)
{
    int res = 0;
    lua_State* L = cb_info->instance;
    size_t ref = cb_info->ref;
    int rc = 0;

    ASSERT (L, return -1, "Validate: LUA is not multi-threaded (use apteryx.process)\n");
    if(lua_apteryx_instance_lock (L))
    {
        int ssize = lua_gettop (L);
        if (!push_callback (L, ref))
        {
            lua_apteryx_instance_unlock (L);
            return -1;
        }
        lua_pushstring (L, path);
        lua_pushstring (L, value);
        res = lua_pcall (L, 2, 1, 0);
        if (res != 0)
            lua_apteryx_error (L, res);
        if (lua_gettop (L))
        {
            rc = lua_tonumber (L, -1);
            lua_pop (L, 1);
        }
        lua_pop (L, 1); /* pop fn */
        if (lua_gettop (L) != ssize)
        {
            ERROR ("Validate: Stack changed\n");
        }
        lua_apteryx_instance_unlock (L);
    }
    return rc;
}

static int
lua_apteryx_validate (lua_State *L)
{
    luaL_checktype (L, 1, LUA_TSTRING);
    luaL_checktype (L, 2, LUA_TFUNCTION);
    const char *path = lua_tostring (L, 1);
    size_t ref = ref_callback (L, 2);

    lua_callback_info *cb_info = new_lua_callback (L, LUA_CALLBACK_VALIDATE, path, ref);

    if (!add_callback (APTERYX_VALIDATORS_PATH, path, (void *)lua_do_validate, true, cb_info, 0))
    {
        luaL_error (L, "Failed to register callback\n");
        lua_pushboolean (L, false);
        return 1;
    }

    lua_pushboolean (L, true);
    return 1;
}

static int
lua_apteryx_unvalidate (lua_State *L)
{
    luaL_checktype(L, 1, LUA_TSTRING);
    luaL_checktype(L, 2, LUA_TFUNCTION);
    const char *path = lua_tostring (L, 1);
    size_t ref = ref_callback (L, 2);

    lua_callback_info *cb_info = remove_callback_info (L, ref, LUA_CALLBACK_VALIDATE);
    if (!delete_callback (APTERYX_VALIDATORS_PATH, path, (void *)lua_do_validate, cb_info))
    {
        luaL_error (L, "Failed to unregister callback\n");
        lua_pushboolean (L, false);
    }
    else
    {
        lua_pushboolean (L, true);
    }
    destroy_cb_info (cb_info);
    return 1;
}

static char*
lua_do_provide (const char *path, lua_callback_info *cb_info)
{
    int res = 0;
    lua_State* L = cb_info->instance;
    size_t ref = cb_info->ref;
    char *value = NULL;

    ASSERT (L, return NULL, "Provide: LUA is not multi-threaded (use apteryx.process)\n");
    if (lua_apteryx_instance_lock (L))
    {
        int ssize = lua_gettop (L);
        if (!push_callback (L, ref))
        {
            lua_apteryx_instance_unlock (L);
            return NULL;
        }
        lua_pushstring (L, path);
        res = lua_pcall (L, 1, 1, 0);
        if (res != 0)
            lua_apteryx_error (L, res);
        if (lua_gettop (L))
        {
            value = strdup (lua_apteryx_tostring (L, -1));
            lua_pop (L, 1);
        }
        lua_pop (L, 1); /* pop fn */
        if (lua_gettop (L) != ssize)
        {
            ERROR("Provide: Stack changed\n");
        }
        lua_apteryx_instance_unlock (L);
    }
    return value;
}

static int
lua_apteryx_provide (lua_State *L)
{
    luaL_checktype (L, 1, LUA_TSTRING);
    luaL_checktype (L, 2, LUA_TFUNCTION);
    const char *path = lua_tostring (L, 1);
    size_t ref = ref_callback (L, 2);

    lua_callback_info *cb_info = new_lua_callback(L, LUA_CALLBACK_PROVIDE, path, ref);

    if (!add_callback (APTERYX_PROVIDERS_PATH, path, (void *)lua_do_provide, false, cb_info, 0))
    {
        luaL_error (L, "Failed to register callback\n");
        lua_pushboolean (L, false);
        return 1;
    }

    lua_pushboolean (L, true);
    return 1;
}

static int
lua_apteryx_unprovide (lua_State *L)
{
    luaL_checktype(L, 1, LUA_TSTRING);
    luaL_checktype(L, 2, LUA_TFUNCTION);
    const char *path = lua_tostring (L, 1);
    size_t ref = ref_callback (L, 2);

    lua_callback_info *cb_info = remove_callback_info (L, ref, LUA_CALLBACK_PROVIDE);
    if (!delete_callback (APTERYX_PROVIDERS_PATH, path, (void *)lua_do_provide, cb_info))
    {
        luaL_error (L, "Failed to unregister callback\n");
        lua_pushboolean (L, false);
    }
    else
    {
        lua_pushboolean (L, true);
    }
    destroy_cb_info(cb_info);
    return 1;
}

static int
lua_apteryx_process (lua_State *L)
{
    if (lua_gettop (L) == 1 && !lua_isboolean (L, 1))
    {
        luaL_error (L, "Invalid arguments: process(bool poll)");
        return 0;
    }
    bool poll = lua_gettop (L) == 1 ? lua_toboolean (L, 1) : true;
    g_L = L;
    /* The lua stack calling in to this function will hold the lock -
     * release it at the callbacks processed with apteryx_process will
     * all require the lua instance lock.
     */
    lua_apteryx_instance_unlock (L);
    int fd = apteryx_process (poll);
    lua_apteryx_instance_lock (L);
    lua_pushnumber (L, fd);
    g_L = NULL;
    return 1;
}

static bool running = false;
static void
termination_handler (void)
{
    running = false;
}

static int
lua_apteryx_timestamp (lua_State *L)
{
    uint64_t ret;

    if (lua_gettop (L) != 1 || !lua_isstring (L, 1))
    {
        luaL_error (L, "Invalid arguments: requires path");
        return 0;
    }

    ret = apteryx_timestamp (lua_tostring (L, 1));
    lua_pop (L, 1);
    lua_pushinteger (L, ret);

    return 1;
}

static int
lua_apteryx_mainloop (lua_State *L)
{
    int fd = 0;
    struct pollfd pfd;
    uint8_t dummy = 0;

    if (lua_gettop (L) > 1 ||
        (lua_gettop (L) == 1 && !lua_isboolean (L, 1)))
    {
        luaL_error (L, "Invalid arguments: mainloop(bool catch_sig)");
        return 0;
    }
    if (lua_gettop (L) == 1 && lua_toboolean (L, 1))
    {
        signal (SIGTERM, (__sighandler_t) termination_handler);
        signal (SIGINT, (__sighandler_t) termination_handler);
    }

    running = true;
    while (running && fd >= 0)
    {
        g_L = L;
        fd = apteryx_process (true);
        g_L = NULL;
        pfd.fd = fd;
        pfd.events = POLLIN;
        poll (&pfd, 1, -1);
        if (running && (!(pfd.revents & POLLIN) || read (fd, &dummy, 1) == 0))
        {
            luaL_error (L, "Poll/Read error: %s\n", strerror (errno));
        }
    }
    return 0;
}


bool
lua_apteryx_instance_lock (lua_State *L)
{
    bool lock_present = false;
    pthread_rwlock_rdlock(&lock_lock);
    pthread_mutex_t *lock = g_hash_table_lookup(locks, L);
    if (lock)
    {
        pthread_mutex_lock(lock);
        lock_present = true;
    }
    pthread_rwlock_unlock(&lock_lock);
    return lock_present;
}

void
lua_apteryx_instance_unlock (lua_State *L)
{
    pthread_rwlock_rdlock (&lock_lock);
    pthread_mutex_t *lock = g_hash_table_lookup (locks, L);
    if (lock)
    {
        pthread_mutex_unlock (lock);
    }
    pthread_rwlock_unlock (&lock_lock);
}

static bool
lua_apteryx_register_lock (lua_State *L)
{
    bool created = false;
    pthread_rwlock_wrlock (&lock_lock);
    if (locks && g_hash_table_lookup (locks, L) == NULL)
    {
        pthread_mutex_t *new_lock = g_malloc0 (sizeof (pthread_mutex_t));
        pthread_mutex_init (new_lock, NULL);
        g_hash_table_insert (locks, L, new_lock);
        created = true;
    }
    pthread_rwlock_unlock (&lock_lock);
    return created;
}

static void
lua_apteryx_unregister_lock (lua_State *L)
{
    pthread_rwlock_wrlock (&lock_lock);
    if (locks)
    {
        g_hash_table_remove (locks, L);
    }
    pthread_rwlock_unlock (&lock_lock);
}

int
lua_apteryx_run (lua_State *L)
{
    lua_apteryx_instance_unlock (L);
    lua_pushboolean (L, true);
    return 1;
}

int
luaopen_libapteryx (lua_State *L)
{
    /* Standard functions */
    static const luaL_Reg _apteryx_fns[] = {
        { "debug", lua_apteryx_debug },
        { "set", lua_apteryx_set },
        { "get", lua_apteryx_get },
        { "search", lua_apteryx_search },
        { "find", lua_apteryx_find},
        { "prune", lua_apteryx_prune },
        { "get_tree", lua_apteryx_get_tree },
        { "set_tree", lua_apteryx_set_tree },
        { "query", lua_apteryx_query },
        { "timestamp", lua_apteryx_timestamp },
        { "index", lua_apteryx_index },
        { "unindex", lua_apteryx_unindex },
        { "watch", lua_apteryx_watch },
        { "watch_tree", lua_apteryx_watch_tree },
        { "unwatch", lua_apteryx_unwatch },
        { "refresh", lua_apteryx_refresh },
        { "unrefresh", lua_apteryx_unrefresh },
        { "validate", lua_apteryx_validate },
        { "unvalidate", lua_apteryx_unvalidate },
        { "provide", lua_apteryx_provide },
        { "unprovide", lua_apteryx_unprovide },
        { "process", lua_apteryx_process },
        { "mainloop", lua_apteryx_mainloop },
        { "run", lua_apteryx_run },
        { NULL, NULL }
    };

    /* Initialise Apteryx */
    if (!apteryx_init (false))
    {
        return 0;
    }

    /* Create a lock for this lua instance */
    if (lua_apteryx_register_lock(L))
    {
        lua_apteryx_instance_lock(L);
    }

    /* Return the Apteryx object on the stack */
    luaL_newmetatable (L, "apteryx");
    luaL_setfuncs (L, _apteryx_fns, 0);
    return 1;
}

static void
removing_state(lua_State *L)
{
    GList *next;
    /* Strip out all the callbacks related to this lua_State that is shutting down*/
    for (GList *iter = callbacks; iter; iter = next)
    {
        next = iter->next;
        lua_callback_info *cb_info = iter->data;
        if (cb_info->instance == L)
        {
            switch (cb_info->type)
            {
                case LUA_CALLBACK_WATCH:
                    delete_callback (APTERYX_WATCHERS_PATH, cb_info->path, (void *)lua_do_watch, cb_info);
                    break;
                case LUA_CALLBACK_VALIDATE:
                    delete_callback (APTERYX_VALIDATORS_PATH, cb_info->path, (void *)lua_do_validate, cb_info);
                    break;
                case LUA_CALLBACK_REFRESH:
                    delete_callback (APTERYX_REFRESHERS_PATH, cb_info->path, (void *)lua_do_refresh, cb_info);
                    break;
                case LUA_CALLBACK_INDEX:
                    delete_callback (APTERYX_INDEXERS_PATH, cb_info->path, (void *)lua_do_index, cb_info);
                    break;
                case LUA_CALLBACK_PROVIDE:
                    delete_callback (APTERYX_PROVIDERS_PATH, cb_info->path, (void *)lua_do_provide, cb_info);
                    break;
                default:
                    continue;
            }
        }
        destroy_cb_info (cb_info);
        callbacks = g_list_delete_link (callbacks, iter);
    }
}

static void
release_lock (pthread_mutex_t *lock)
{
    pthread_mutex_destroy (lock);
    g_free (lock);
}

int
luaopen_apteryx (lua_State *L)
{
    pthread_rwlock_wrlock(&lock_lock);
    if (!locks)
    {
        locks = g_hash_table_new_full (g_direct_hash,
                                       g_direct_equal,
                                       (GDestroyNotify)removing_state,
                                       (GDestroyNotify)release_lock);
    }
    pthread_rwlock_unlock (&lock_lock);
    return luaopen_libapteryx (L);
}

void
lua_apteryx_close (lua_State *L)
{
    lua_apteryx_unregister_lock (L);
}

#endif /* HAVE_LUA */
