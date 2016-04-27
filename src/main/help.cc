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
// help.cc author Russ Combs <rucombs@cisco.com>

#include "help.h"

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <syslog.h>
#include <iostream>
#include <string>
using namespace std;

#include "main.h"
#include "main/snort_config.h"
#include "main/snort_module.h"
#include "framework/module.h"
#include "framework/parameter.h"
#include "managers/event_manager.h"
#include "managers/so_manager.h"
#include "managers/inspector_manager.h"
#include "managers/module_manager.h"
#include "managers/plugin_manager.h"
#include "managers/script_manager.h"
#include "packet_io/sfdaq.h"
#include "packet_io/intf.h"
#include "parser/config_file.h"
#include "helpers/process.h"
#include "utils/util.h"
#include "helpers/markup.h"

#define snort_help \
    "\n" \
    "Snort has several options to get more help:\n" \
    "\n" \
    "-? list command line options (same as --help)\n" \
    "--help this overview of help\n" \
    "--help-commands [<module prefix>] output matching commands\n" \
    "--help-config [<module prefix>] output matching config options\n" \
    "--help-counts [<module prefix>] output matching peg counts\n" \
    "--help-module <module> output description of given module\n" \
    "--help-modules list all available modules with brief help\n" \
    "--help-plugins list all available plugins with brief help\n" \
    "--help-options [<option prefix>] output matching command line options\n" \
    "--help-signals dump available control signals\n" \
    "--list-buffers output available inspection buffers\n" \
    "--list-builtin [<module prefix>] output matching builtin rules\n" \
    "--list-gids [<module prefix>] output matching generators\n" \
    "--list-modules [<module type>] list all known modules\n" \
    "--list-plugins list all known modules\n" \
    "--show-plugins list module and plugin versions\n" \
    "\n" \
    "--help* and --list* options preempt other processing so should be last on the\n" \
    "command line since any following options are ignored.  To ensure options like\n" \
    "--markup and --plugin-path take effect, place them ahead of the help or list\n" \
    "options.\n" \
    "\n" \
    "Options that filter output based on a matching prefix, such as --help-config\n" \
    "won't output anything if there is no match.  If no prefix is given, everything\n" \
    "matches.\n" \
    "\n" \
    "Report bugs to bugs@snort.org.\n"

//-------------------------------------------------------------------------

void help_args(const char* pfx)
{
    Module* m = get_snort_module();
    const Parameter* p = m->get_parameters();
    unsigned n = pfx ? strlen(pfx) : 0;

    while ( p->name )
    {
        const char* name = p->name;
        while ( *name == '-' )
            name++;

        if ( p->help && (!n || !strncasecmp(name, pfx, n)) )
        {
            cout << Markup::item();

            cout << Markup::emphasis_on();
            cout << Markup::escape(p->name);
            cout << Markup::emphasis_off();

            cout << " " << Markup::escape(p->help);

            if ( const char* r = p->get_range() )
            {
                if ( *r == '(' )
                    cout << " " << r;
                else
                    cout << " (" << r << ")";
            }
            cout << endl;
        }
        ++p;
    }
}

void help_basic(SnortConfig*, const char*)
{
    fprintf(stdout, "%s\n", snort_help);
    exit(0);
}

void help_usage(SnortConfig*, const char* s)
{
    fprintf(stdout, "usage:\n");
    fprintf(stdout, "    %s -?: list options\n", s);
    fprintf(stdout, "    %s -V: output version\n", s);
    fprintf(stdout, "    %s --help: help summary\n", s);
    fprintf(stdout, "    %s [-options] -c conf [-T]: validate conf\n", s);
    fprintf(stdout, "    %s [-options] -c conf -i iface: process live\n", s);
    fprintf(stdout, "    %s [-options] -c conf -r pcap: process readback\n", s);
    exit(1);
}

void help_options(SnortConfig*, const char* val)
{
    help_args(val);
    exit(0);
}

void help_signals(SnortConfig*, const char*)
{
    help_signals();
    exit(0);
}

enum HelpType
{
    HT_CFG, HT_CMD, HT_GID, HT_IPS, HT_MOD,
    HT_BUF, HT_LST, HT_PLG, HT_DDR, HT_DBR,
    HT_HMO, HT_HPL, HT_DFL, HT_PEG
};

static void show_help(SnortConfig* sc, const char* val, HelpType ht)
{
    snort_conf = new SnortConfig;
    ScriptManager::load_scripts(sc->script_paths);
    PluginManager::load_plugins(sc->plugin_path);
    ModuleManager::init();

    switch ( ht )
    {
    case HT_CFG:
        ModuleManager::show_configs(val);
        break;
    case HT_CMD:
        ModuleManager::show_commands(val);
        break;
    case HT_GID:
        ModuleManager::show_gids(val);
        break;
    case HT_IPS:
        ModuleManager::show_rules(val);
        break;
    case HT_MOD:
        ModuleManager::show_module(val);
        break;
    case HT_BUF:
        InspectorManager::dump_buffers();
        break;
    case HT_LST:
        ModuleManager::list_modules(val);
        break;
    case HT_PLG:
        PluginManager::list_plugins();
        break;
    case HT_DDR:
        SoManager::dump_rule_stubs(val);
        break;
    case HT_DBR:
        ModuleManager::dump_rules(val);
        break;
    case HT_HMO:
        ModuleManager::show_modules();
        break;
    case HT_HPL:
        PluginManager::show_plugins();
        break;
    case HT_DFL:
        ModuleManager::dump_defaults(val);
        break;
    case HT_PEG:
        ModuleManager::show_pegs(val);
        break;
    }
    ModuleManager::term();
    PluginManager::release_plugins();
    delete snort_conf;
    exit(0);
}

void help_config(SnortConfig* sc, const char* val)
{
    show_help(sc, val, HT_CFG);
}

void help_commands(SnortConfig* sc, const char* val)
{
    show_help(sc, val, HT_CMD);
}

void config_markup(SnortConfig*, const char*)
{
    Markup::enable();
}

void help_gids(SnortConfig* sc, const char* val)
{
    show_help(sc, val, HT_GID);
}

void help_buffers(SnortConfig* sc, const char* val)
{
    show_help(sc, val, HT_BUF);
}

void help_builtin(SnortConfig* sc, const char* val)
{
    show_help(sc, val, HT_IPS);
}

void help_module(SnortConfig* sc, const char* val)
{
    show_help(sc, val, HT_MOD);
}

void help_modules(SnortConfig* sc, const char* val)
{
    show_help(sc, val, HT_HMO);
}

void help_plugins(SnortConfig* sc, const char* val)
{
    show_help(sc, val, HT_HPL);
}

void list_modules(SnortConfig* sc, const char* val)
{
    show_help(sc, val, HT_LST);
}

void list_plugins(SnortConfig* sc, const char* val)
{
    show_help(sc, val, HT_PLG);
}

void dump_defaults(SnortConfig* sc, const char* val)
{
    show_help(sc, val, HT_DFL);
}

void dump_builtin_rules(SnortConfig* sc, const char* val)
{
    show_help(sc, val, HT_DBR);
}

void dump_dynamic_rules(SnortConfig* sc, const char* val)
{
    show_help(sc, val, HT_DDR);
}

void help_counts(SnortConfig* sc, const char* val)
{
    show_help(sc, val, HT_PEG);
}

void dump_rule_hex(SnortConfig*, const char* val)
{
    SoManager::rule_to_hex(val);
    exit(0);
}

void dump_rule_text(SnortConfig*, const char* val)
{
    SoManager::rule_to_text(val);
    exit(0);
}

void dump_version(SnortConfig*, const char*)
{
    cout << VERSION << endl;
    exit(0);
}

void help_version(SnortConfig*, const char*)
{
    DisplayBanner();
    exit(0);
}

void list_interfaces(SnortConfig*, const char*)
{
    PrintAllInterfaces();
    exit(0);
}

void list_daqs(SnortConfig* sc, const char* val)
{
    if ( val )
        ConfigDaqDir(sc, val);

    DAQ_Load(sc);
    DAQ_PrintTypes(stdout);
    DAQ_Unload();
    exit(0);
}

