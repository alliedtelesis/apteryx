/**
 * @file lua.c
 * Callback tables for Apteryx lua bindings.
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
#ifdef HAVE_LUA
#include <lua.h>
#include <lauxlib.h>
#include "apteryx.h"
#include "internal.h"

#define N_OF(this, ...) \
this(0, __VA_ARGS__)    \
this(1, __VA_ARGS__)    \
this(2, __VA_ARGS__)    \
this(3, __VA_ARGS__)    \
this(4, __VA_ARGS__)    \
this(5, __VA_ARGS__)    \
this(6, __VA_ARGS__)    \
this(7, __VA_ARGS__)    \
this(8, __VA_ARGS__)    \
this(9, __VA_ARGS__)    \
this(10, __VA_ARGS__)   \
this(11, __VA_ARGS__)   \
this(12, __VA_ARGS__)   \
this(13, __VA_ARGS__)   \
this(14, __VA_ARGS__)   \
this(15, __VA_ARGS__)   \
this(16, __VA_ARGS__)   \
this(17, __VA_ARGS__)   \
this(18, __VA_ARGS__)   \
this(19, __VA_ARGS__)   \
this(20, __VA_ARGS__)   \
this(21, __VA_ARGS__)   \
this(22, __VA_ARGS__)   \
this(23, __VA_ARGS__)   \
this(24, __VA_ARGS__)   \
this(25, __VA_ARGS__)   \
this(26, __VA_ARGS__)   \
this(27, __VA_ARGS__)   \
this(28, __VA_ARGS__)   \
this(29, __VA_ARGS__)   \
this(30, __VA_ARGS__)   \
this(31, __VA_ARGS__)   \
this(32, __VA_ARGS__)   \
this(33, __VA_ARGS__)   \
this(34, __VA_ARGS__)   \
this(35, __VA_ARGS__)   \
this(36, __VA_ARGS__)   \
this(37, __VA_ARGS__)   \
this(38, __VA_ARGS__)   \
this(39, __VA_ARGS__)   \
this(41, __VA_ARGS__)   \
this(42, __VA_ARGS__)   \
this(43, __VA_ARGS__)   \
this(44, __VA_ARGS__)   \
this(45, __VA_ARGS__)   \
this(46, __VA_ARGS__)   \
this(47, __VA_ARGS__)   \
this(48, __VA_ARGS__)   \
this(49, __VA_ARGS__)

#define LUA_CB_TABLE_LEN 50

#define CB_FUNC(n, ret, func, args, mux, ...) static ret func##_##n args { return mux (n, __VA_ARGS__); }
#define CB_FUNC_GEN(ret, func, args, mux, ...) N_OF (CB_FUNC, ret, func, args, mux, __VA_ARGS__)

#define CB_TABLE_ENTRY(n, func) func##_##n,
#define CB_TABLE_GEN(cb_type, table_name) \
cb_type table_name[LUA_CB_TABLE_LEN] = { N_OF (CB_TABLE_ENTRY, table_name) };

#define LUA_CB_TABLE(cb_type, table_name, ret, args, mux, ...) \
CB_FUNC_GEN (ret, table_name, args, mux, __VA_ARGS__) \
CB_TABLE_GEN (cb_type, table_name)

int lua_watch_fn_table[LUA_CB_TABLE_LEN] = { 0 };

LUA_CB_TABLE (apteryx_watch_callback, lua_watch_cb_table, bool,
              (const char *path, const char *value), lua_watch_mux, path, value);

static inline int
lua_fn_table_next_free_index (int lua_fn_table[LUA_CB_TABLE_LEN])
{
    int i;
    for (i = 0; i < LUA_CB_TABLE_LEN && lua_watch_fn_table[i]; i++);

    if (i == LUA_CB_TABLE_LEN)
    {
        i = -1;
    }
    return i;
}

bool
lua_cb_stack_check (lua_State *L)
{
    if (lua_gettop (L) == 2)
    {
        if (!lua_isstring (L, 1))
        {
            luaL_error (L, "Argument one: requires path");
            return false;
        }
        if (!lua_isfunction (L, 2))
        {
            luaL_error (L, "Argument two: requires function");
            return false;
        }
    }
    else
    {
        luaL_error (L, "Two arguments required");
        return false;
    }
    return true;
}

int
lua_cb_register (lua_State *L, int fn_table[LUA_CB_TABLE_LEN])
{
    int cb_table_index = 0;

    if (!lua_cb_stack_check (L))
    {
        return -1;
    }

    if ((cb_table_index = lua_fn_table_next_free_index (fn_table)) < 0)
    {
        luaL_error (L, "Unable to allocate callback resource");
        return -1;
    }

    /* push the lua function to the registry and register a watch with it's associated callback */
    lua_pushvalue (L, -1);  /* duplicate the lua function */
    /* Register the lua function to the registry for the callback mux */
    fn_table[cb_table_index] = luaL_ref (L, LUA_REGISTRYINDEX);

    /* Store the reverse mapping so we can unwatch (registry[function] = cb_table_index) */
    lua_pushinteger (L, cb_table_index);
    lua_settable (L, LUA_REGISTRYINDEX);
    return cb_table_index;
}

int
lua_cb_unregister (lua_State *L, int fn_table[LUA_CB_TABLE_LEN])
{
    int cb_table_index;

    if (!lua_cb_stack_check (L))
    {
        return -1;
    }

    lua_pushvalue (L, -1);                  /* duplicate the lua function */
    lua_gettable (L, LUA_REGISTRYINDEX);    /* cb_table_index = registry[function] */
    if (lua_isnil (L, -1))
    {
        luaL_error (L, "Cannot find registered callback");
        return -1;
    }
    cb_table_index = lua_tointeger (L, -1);
    if (!lua_watch_fn_table[cb_table_index])
    {
        luaL_error (L, "Empty callback table entry");
        return -1;
    }
    lua_pop (L, 1);
    /* Remove registry entries for this cb */
    lua_pushnil (L);
    lua_settable (L, LUA_REGISTRYINDEX);
    lua_pushinteger (L, lua_watch_fn_table[cb_table_index]);
    lua_pushnil (L);
    lua_settable (L, LUA_REGISTRYINDEX);

    fn_table[cb_table_index] = 0;

    return cb_table_index;
}

#endif /* HAVE_LUA */
