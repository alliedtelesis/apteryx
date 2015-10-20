/**
 * @file lua.c
 * Lua bindings for Apteryx.
 *
 * Copyright 2014, Allied Telesis Labs New Zealand, Ltd
 *
 * Example:
 * > require "libapteryx"
 * > apteryx_init(false)
 * > apteryx_set("/interfaces/eth0/state", "up")
 * > apteryx_set("/interfaces/eth1/state", "down")
 * > print(apteryx_get("/interfaces/eth0/state"))
 * up
 * > paths = {apteryx_search("/interfaces")}
 * > print(unpack(paths))
 * /interfaces/eth0        /interfaces/eth1
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
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <glib.h>
#include <lua.h>
#include <lualib.h>
#include <lauxlib.h>
#include "apteryx.h"
#include "internal.h"

lua_State *g_L = NULL;

#if 0
static void
_dump_stack (lua_State *L)
{
    int n = lua_gettop (L);
    for (int i=1; i <= n; i++)
    {
        const char *type = lua_typename (L, lua_type (L, i));
        const char *value = lua_tostring (L, i);
        printf ("%d: [%s] %s\n", i, type, value ? value : "");
    }
    return;
}

static void
_dump_table (lua_State *L, int index)
{
    lua_pushvalue (L, index);
    lua_pushnil (L);
    while (lua_next(L, -2))
    {
        lua_pushvalue(L, -2);
        const char *key = lua_tostring(L, -1);
        const char *type = lua_typename (L, lua_type (L, -2));
        const char *value = lua_tostring(L, -2);
        printf("%s => [%s] %s\n", key, type, value ? value : "");
        lua_pop(L, 2);
    }
    lua_pop(L, 1);
}
#endif

static int
lua_apteryx_init (lua_State *L)
{
    if (lua_gettop (L) != 1 || !lua_isboolean (L, 1))
    {
        ERROR ("invalid arguments\n");
        lua_pushboolean (L, false);
        return 1;
    }
    lua_pushboolean (L, apteryx_init (lua_toboolean (L, 1)));
    return 1;
}

static int
lua_apteryx_shutdown (lua_State *L)
{
    if (lua_gettop (L) != 0)
    {
        ERROR ("invalid arguments\n");
        lua_pushboolean (L, false);
        return 1;
    }
    lua_pushboolean (L, apteryx_shutdown ());
    return 1;
}

static int
lua_apteryx_prune (lua_State *L)
{
    if (lua_gettop (L) != 1 || !lua_isstring (L, 1))
    {
        ERROR ("invalid arguments\n");
        lua_pushboolean (L, false);
        return 1;
    }
    lua_pushboolean (L, apteryx_prune (lua_tostring (L, 1)));
    return 1;
}

static int
lua_apteryx_set (lua_State *L)
{
    const char *path = lua_tostring (L, 1);
    const char *value = lua_tostring (L,2);
    lua_pushboolean (L, apteryx_set (path, value));
    return 1;
}

static int
lua_apteryx_get (lua_State *L)
{
    char *value = NULL;
    if (lua_gettop (L) != 1 || !lua_isstring (L, 1))
    {
        ERROR ("invalid arguments\n");
        lua_pushboolean (L, false);
        return 1;
    }
    value = apteryx_get (lua_tostring (L, 1));
    if (value)
        lua_pushstring (L, value);
    else
        lua_pushboolean (L, false);
    return 1;
}

static int
lua_apteryx_get_int (lua_State *L)
{
    int res;
    if (lua_gettop (L) != 1 || !lua_isstring (L, 1))
    {
        ERROR ("invalid arguments\n");
        lua_pushboolean (L, false);
        return 1;
    }
    res = apteryx_get_int (lua_tostring (L, 1), NULL);
    if (res != -1)
        lua_pushnumber (L, res);
    else
        lua_pushboolean (L, false);
    return 1;
}

static int
lua_apteryx_search (lua_State *L)
{
    GList *paths;
    int num;
    if (lua_gettop (L) != 1 || !lua_isstring (L, 1))
    {
        ERROR ("invalid arguments\n");
        lua_pushboolean (L, false);
        return 1;
    }
    paths = apteryx_search (lua_tostring (L, 1));
    num = g_list_length (paths);
    for (GList* _iter= paths; _iter; _iter = _iter->next)
    {
        const char *path = (char *)_iter->data;
        lua_pushstring (L, path);
    }
    g_list_free_full (paths, free);
    return num;
}

#define APTERYX_CB_TABLE_REGISTRY_INDEX "apteryx_cb_table"

static int
find_callback (lua_State *L, int index)
{
    int ref = 0;
    luaL_checktype (L, -1, LUA_TTABLE);
    lua_pushvalue (L, -1);
    lua_pushnil (L);
    while (lua_next (L, -2))
    {
        lua_pushvalue (L, -2);
        if (lua_rawequal (L, index, -2))
        {
            ref = lua_tonumber (L, -1);
            lua_pop (L, 2);
            break;
        }
        lua_pop(L, 2);
    }
    lua_pop(L, 1);
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

bool
lua_do_watch (size_t cb, const char *path, const char *value)
{
    lua_State* L = g_L;
    if (L == NULL)
        return false;
    lua_pushlightuserdata (L, APTERYX_CB_TABLE_REGISTRY_INDEX);
    lua_gettable (L, LUA_REGISTRYINDEX);
    if (lua_isnil (L, -1))
    {
        lua_pop (L, 1); /* pop nil */
        return false;
    }
    lua_rawgeti (L, -1, cb);
    if (!lua_isfunction (L, -1))
    {
        lua_pop (L, 1);
        return false;
    }
    lua_pushstring (L, path);
    lua_pushstring (L, value);
    lua_pcall (L, 2, 0, 0);
    lua_pop (L, 1); /* pop table */
    return true;
}

static int
lua_apteryx_watch (lua_State *L)
{
    luaL_checktype (L, 1, LUA_TSTRING);
    luaL_checktype (L, 2, LUA_TFUNCTION);
    const char *path = lua_tostring (L, 1);
    int cb = ref_callback (L, 2);
    if (!apteryx_watch (path, (apteryx_watch_callback) (size_t) cb))
    {
        ERROR ("Failed to register watch\n");
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
    int cb = ref_callback (L, 2);
    if (!apteryx_unwatch (path, (apteryx_watch_callback) (size_t) cb))
    {
        ERROR ("Failed to unregister watch\n");
        lua_pushboolean (L, false);
        return 1;
    }
    lua_pushboolean (L, true);
    return 1;
}

int
luaopen_libapteryx(lua_State *L)
{
    g_L = L;
    lua_register (L, "apteryx_init", lua_apteryx_init);
    lua_register (L, "apteryx_shutdown", lua_apteryx_shutdown);
    lua_register (L, "apteryx_prune", lua_apteryx_prune);
    lua_register (L, "apteryx_set", lua_apteryx_set);
    lua_register (L, "apteryx_get", lua_apteryx_get);
    lua_register (L, "apteryx_get_int", lua_apteryx_get_int);
    lua_register (L, "apteryx_search", lua_apteryx_search);
    lua_register (L, "apteryx_watch", lua_apteryx_watch);
    lua_register (L, "apteryx_unwatch", lua_apteryx_unwatch);
    return 0;
}

int
luaopen_apteryx(lua_State *L)
{
    return luaopen_libapteryx(L);
}
#endif
