//--------------------------------------------------------------------------
// Copyright (C) 2015-2015 Cisco and/or its affiliates. All rights reserved.
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
// pp_ips_option.cc author Joel Cornett <jocornet@cisco.com>

#include "piglet_plugins.h"

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <string>

#include "detection/treenodes.h"
#include "lua/lua_iface.h"
#include "managers/ips_manager.h"
#include "piglet/piglet_api.h"

#include "pp_cursor_iface.h"
#include "pp_packet_iface.h"
#include "pp_raw_buffer_iface.h"

#include "pp_ips_option_iface.h"

class IpsOptionPiglet : public Piglet::BasePlugin
{
public:
    IpsOptionPiglet(Lua::State&, std::string, Module*);
    virtual ~IpsOptionPiglet() override;
    virtual bool setup() override;

private:
    IpsOptionWrapper* wrapper;
    struct OptTreeNode* otn;
};

IpsOptionPiglet::IpsOptionPiglet(
    Lua::State& state, std::string target, Module* m) :
    BasePlugin(state, target, m)
{
    if ( !module )
        return;

    otn = new struct OptTreeNode;

    if ( !otn )
        return;

    wrapper = IpsManager::instantiate(target.c_str(), m, otn);
}

IpsOptionPiglet::~IpsOptionPiglet()
{
    if ( wrapper )
        delete wrapper;

    // FIXIT-M: Is it okay for OTN to be arbitrary?
    if ( otn )
        delete otn;
}

bool IpsOptionPiglet::setup()
{
    if ( !wrapper )
        return true;

    install(L, RawBufferIface);
    install(L, PacketIface);
    install(L, CursorIface);

    install(L, IpsOptionIface, wrapper->instance);

    return false;
}

// -----------------------------------------------------------------------------
// API foo
// -----------------------------------------------------------------------------
static Piglet::BasePlugin* ctor(
    Lua::State& state, std::string target, Module* m, SnortConfig*)
{ return new IpsOptionPiglet(state, target, m); }

static void dtor(Piglet::BasePlugin* p)
{ delete p; }

static const struct Piglet::Api piglet_api =
{
    {
        PT_PIGLET,
        sizeof(Piglet::Api),
        PIGLET_API_VERSION,
        0,
        API_RESERVED,
        API_OPTIONS,
        "pp_ips_option",
        "Ips option piglet",
        nullptr,
        nullptr
    },
    ctor,
    dtor,
    PT_IPS_OPTION
};

const BaseApi* pp_ips_option = &piglet_api.base;
