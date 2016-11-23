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
#include <lua.h>
#include <lauxlib.h>
#include "apteryx.h"
#include "internal.h"
#include <pthread.h>

static lua_State *gL = NULL;
pthread_mutex_t gL_lock;

#define lua_absindex(L, i) ((i) > 0 || (i) <= LUA_REGISTRYINDEX ? (i) : \
                                        lua_gettop(L) + (i) + 1)

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
_lua_apteryx_dict2tree (lua_State *L, GNode *n)
{
    bool ret = false;
    GNode *c = NULL;
    const char *value = NULL;

    lua_pushnil (L);
    while (lua_next (L, -2))
    {
        if (lua_type (L, -1) == LUA_TTABLE)
        {
            c = APTERYX_NODE (n, (char *) lua_tostring (L, -2));
            if (_lua_apteryx_dict2tree (L, c))
            {
                ret = true;
            }
            else
            { /* destroy leafless sub-trees */
                g_node_destroy (c);
            }
            break;
        }
        else
        {
            value = lua_apteryx_tostring (L, -1);
            if (value)
            {
                APTERYX_LEAF (n, (char *) lua_tostring (L, -2), value);
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
    root = APTERYX_NODE (NULL, (char *) lua_tostring (L, 1));
    if (!_lua_apteryx_dict2tree (L, root))
    {
        g_node_destroy (root);
        root = NULL;
    }
    return root;
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
        g_node_destroy (root);
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
    g_node_destroy (tree);
    return 1;
}

bool
lua_watch_mux (int n, const char *path, const char *value)
{
    bool ret;

    pthread_mutex_lock (&gL_lock);

    if (!gL)
    { /* must have exclusive access to the global lua state */
        ERROR ("LUA cb: Lua state is NULL");
        pthread_mutex_unlock (&gL_lock);
        return false;
    }

    lua_pushinteger (gL, lua_watch_fn_table[n]);
    lua_gettable (gL, LUA_REGISTRYINDEX);
    if (!lua_isfunction (gL, -1))
    {
        luaL_error (gL, "lua function expected");
    }
    lua_pushstring (gL, path);
    lua_pushstring (gL, value);
    lua_call (gL, 2, 1);
    /* boolean return type is not enforced */
    ret = !(lua_toboolean (gL, -1) == 0);
    lua_pop (gL, 1);    /* Remove the result to clean up */

    pthread_mutex_unlock (&gL_lock);
    return ret;
}

static int
lua_apteryx_watch (lua_State *L)
{
    int cb_table_index;

    if ((cb_table_index = lua_cb_register (L, lua_watch_fn_table)) < 0)
    {
        return 0;
    }

    if (!apteryx_watch (lua_tostring (L, 1), lua_watch_cb_table[cb_table_index]))
    {
        ERROR ("Could not register watch at index %d\n", cb_table_index);
        return 0;
    }

    DEBUG ("Registered watch with index %d\n", cb_table_index);
    return 1;
}

static int
lua_apteryx_unwatch (lua_State *L)
{
    int cb_table_index;

    if ((cb_table_index = lua_cb_unregister (L, lua_watch_fn_table)) < 0)
    {
        return 0;
    }

    if (!apteryx_unwatch (lua_tostring (L, 1), lua_watch_cb_table[cb_table_index]))
    {
        ERROR ("Could not unregister watch at index %d\n", cb_table_index);
    }

    DEBUG ("Unregistered watch index %d\n", cb_table_index);
    return 1;
}

int
lua_apteryx_mainloop (lua_State *L)
{
    gL = L;
    pthread_mutex_unlock (&gL_lock);
    pause ();
    exit (0);
}

int
luaopen_libapteryx (lua_State *L)
{
    /* Standard functions */
    static const luaL_Reg _apteryx_fns[] = {
        { "set", lua_apteryx_set },
        { "get", lua_apteryx_get },
        { "search", lua_apteryx_search },
        { "prune", lua_apteryx_prune },
        { "get_tree", lua_apteryx_get_tree },
        { "set_tree", lua_apteryx_set_tree },
        { "watch", lua_apteryx_watch },
        { "unwatch", lua_apteryx_unwatch },
        { "mainloop", lua_apteryx_mainloop },
        { NULL, NULL }
    };

    if (pthread_mutex_init (&gL_lock, NULL) != 0)
    {
        luaL_error (L, "Initialization failed");
        return 0;
    }

    pthread_mutex_lock (&gL_lock);

    /* Initialise Apteryx */
    if (!apteryx_init (false))
    {
        luaL_error (L, "Initialization failed");
        return 0;
    }

    /* Return the Apteryx object on the stack */
    luaL_newmetatable (L, "apteryx");
    luaL_setfuncs (L, _apteryx_fns, 0);
    return 1;
}

int
luaopen_apteryx (lua_State *L)
{
    return luaopen_libapteryx (L);
}

#endif /* HAVE_LUA */
