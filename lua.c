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

static int
lua_apteryx_set (lua_State *L)
{
    if (lua_gettop (L) < 1 || !lua_isstring (L, 1))
    {
        luaL_error (L, "Invalid arguments: requires path");
        return 0;
    }
    const char *path = lua_tostring (L, 1);
    const char *value = lua_tostring (L, 2);
    lua_pushboolean (L, apteryx_set (path, value));
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

int
luaopen_libapteryx (lua_State *L)
{
    /* Standard functions */
    static const luaL_Reg _apteryx_fns[] = {
        { "set", lua_apteryx_set },
        { "get", lua_apteryx_get },
        { "search", lua_apteryx_search },
        { "prune", lua_apteryx_prune },
        { NULL, NULL }
    };

    /* Initialise Apteryx */
    if (!apteryx_init (false))
    {
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
