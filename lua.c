/**
 * @file lua.c
 * Lua bindings for Apteryx.
 *
 * Copyright 2014, Allied Telesis Labs New Zealand, Ltd
 *
 * Example:
 * > require "libapteryx"
 * > apteryx_init(false)
 * > apteryx_set("/interfaces/eth0/state", "up", 3)
 * > apteryx_set("/interfaces/eth1/state", "down", 5)
 * > print(apteryx_get("/interfaces/eth0/state"))
 * up
 * > paths = {apteryx_search("/interfaces/")}
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
#include "apteryx.h"
#include "internal.h"

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
    unsigned char *value = (unsigned char *)lua_tostring (L,2);
    size_t size = lua_tonumber (L, 3);
    lua_pushboolean (L, apteryx_set (path, value, size));
    return 1;
}

static int
lua_apteryx_get (lua_State *L)
{
    unsigned char *value = NULL;
    size_t size;
    bool res;
    if (lua_gettop (L) != 1 || !lua_isstring (L, 1))
    {
        ERROR ("invalid arguments\n");
        lua_pushboolean (L, false);
        return 1;
    }
    res = apteryx_get (lua_tostring (L, 1), &value, &size);
    if (res)
        lua_pushlstring (L, (char*)value, size);
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

int
luaopen_libapteryx(lua_State *L)
{
    lua_register (L, "apteryx_init", lua_apteryx_init);
    lua_register (L, "apteryx_shutdown", lua_apteryx_shutdown);
    lua_register (L, "apteryx_prune", lua_apteryx_prune);
    lua_register (L, "apteryx_set", lua_apteryx_set);
    lua_register (L, "apteryx_get", lua_apteryx_get);
    lua_register (L, "apteryx_search", lua_apteryx_search);
    return 0;
}
#endif
