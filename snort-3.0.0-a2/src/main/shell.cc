//--------------------------------------------------------------------------
// Copyright (C) 2014-2015 Cisco and/or its affiliates. All rights reserved.
//
// This program is free software; you can redistribute it and/or modify it
// under the terms of the GNU General Public License Version 2 as published
// by the Free Software Foundation.  You may not use, modify or distribute
// this program under any other version of the GNU General Public License.
//
// This program is distributed in the hope that it will be useful, but
// WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
// General Public License for more details.
//
// You should have received a copy of the GNU General Public License along
// with this program; if not, write to the Free Software Foundation, Inc.,
// 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
//--------------------------------------------------------------------------
// shell.cc author Russ Combs <rucombs@cisco.com>

#include "shell.h"

#include <assert.h>
#include <string.h>
#include <string>
#include <luajit-2.0/lua.hpp>
#include <stdexcept>

#include "framework/module.h"
#include "lua/lua.h"
#include "managers/module_manager.h"
#include "parser/parser.h"
#include "log/messages.h"

using namespace std;

#define required "require('snort_config'); "

//-------------------------------------------------------------------------
// helper functions
//-------------------------------------------------------------------------

// FIXIT-M Shell::panic() works on Linux but on OSX we can't throw from lua
// to C++.  unprotected lua calls could be wrapped in a pcall to ensure lua
// panics don't kill the process.  or we can not use lua for the shell.  :(

string Shell::fatal;

int Shell::panic(lua_State* L)
{
    fatal = lua_tostring(L, -1);
    throw runtime_error(fatal);
    return -1;
}

// FIXIT-L --shell --pause should stop before loading config so Lua state
// can be examined and modified.

#if 0
// :( it does not look possible to get file and line after load
static int get_line_number(lua_State* L)
{
    lua_Debug ar;
    lua_getstack(L, 1, &ar);
    lua_getinfo(L, "nSl", &ar);
    return ar.currentline;
}

#endif

static void load_config(lua_State* L, const char* file)
{
    Lua::ManageStack ms(L);

    if ( luaL_loadfile(L, file) )
    {
        FatalError("can't load %s: %s\n", file, lua_tostring(L, -1));
        return;
    }

    if ( lua_pcall(L, 0, 0, 0) )
        FatalError("can't init %s: %s\n", file, lua_tostring(L, -1));
}

static void load_overrides(lua_State* L, string& s)
{
    Lua::ManageStack ms(L);

    if ( luaL_loadstring(L, s.c_str()) )
    {
        const char* err = lua_tostring(L, -1);
        if ( strstr(err, "near '#'") )
            ParseError("this doesn't look like Lua.  Comments start with --, not #.");
        FatalError("can't load overrides: %s\n", err);
        return;
    }

    if ( lua_pcall(L, 0, 0, 0) )
        FatalError("can't init overrides: %s\n", lua_tostring(L, -1));
}

static void run_config(lua_State* L, const char* t)
{
    Lua::ManageStack ms(L);

    lua_getglobal(L, "snort_config");
    lua_getglobal(L, t);

    if ( !lua_isfunction(L, -2) )
        FatalError("%s\n", "snort_config is required");

    else if ( lua_pcall(L, 1, 1, 0) )
    {
        const char* err = lua_tostring(L, -1);
        FatalError("%s\n", err);
    }
}

static void config_lua(
    lua_State* L, const char* file, string& s)
{
    if ( file && *file )
        load_config(L, file);

    if ( s.size() )
        load_overrides(L, s);

    run_config(L, "_G");
}

//-------------------------------------------------------------------------
// public methods
//-------------------------------------------------------------------------

Shell::Shell(const char* s)
{
    // FIXIT-M: Should wrap in Lua::State
    lua = luaL_newstate();

    if ( !lua )
        FatalError("lua state instantiation failed\n");

    lua_atpanic(lua, Shell::panic);
    luaL_openlibs(lua);

    if ( s )
        file = s;

    loaded = false;
}

Shell::~Shell()
{
    lua_close(lua);
}

void Shell::set_file(const char* s)
{
    assert(!file.size());
    file = s;
}

void Shell::set_overrides(const char* s)
{
    if ( overrides.empty() )
        overrides = required;

    overrides += s;
}

void Shell::set_overrides(Shell* sh)
{
    overrides += sh->overrides;
}

void Shell::configure(SnortConfig* sc)
{
    assert(file.size());
    ModuleManager::set_config(sc);
    config_lua(lua, file.c_str(), overrides);
    ModuleManager::set_config(nullptr);
    loaded = true;
}

void Shell::install(const char* name, const luaL_Reg* reg)
{
    if ( !strcmp(name, "snort") )
        luaL_register(lua, "_G", reg);

    luaL_register(lua, name, reg);
}

void Shell::execute(const char* cmd, string& rsp)
{
    int err = 0;
    Lua::ManageStack ms(lua);

    try
    {
        // FIXIT-L: Shares logic with chunk
        err = luaL_loadbuffer(lua, cmd, strlen(cmd), "shell");

        if ( !err )
            err = lua_pcall(lua, 0, 0, 0);
    }
    catch (...)
    {
        rsp = fatal.c_str();
    }

    if (err)
    {
        rsp = lua_tostring(lua, -1);
        lua_pop(lua, 1);
    }
}

