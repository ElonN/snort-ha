//--------------------------------------------------------------------------
// Copyright (C) 2014-2015 Cisco and/or its affiliates. All rights reserved.
// Copyright (C) 2002-2013 Sourcefire, Inc.
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
// dt_table_api.h author Josh Rosenbaum <jrosenba@cisco.com>

#ifndef DATA_DT_TABLE_API_H
#define DATA_DT_TABLE_API_H

#include <string>
#include <iostream>
#include <vector>
#include <stack>

/*
*
* As a heads up to whoever reads this file.  This one API is
* really three distinct API's rolled into one.  One API for rules,
* one api for misc data (variables, includes, etcs), one api
* for creating tables. Hoever, the reason they are
* together is becasue this class is not static, and I did not
* want to be pass three pointers to the three API's when
* creating new convesion states.  There are comments in
* in all caps which show the seperate the sections.
*
* The first section of this file is really DataApi creation
* and initialization, and adding miscelaneous objects
* to the DataApi data.  The second section is for creating
* tables and their options.  The third section is for
* creating rules.
*/
// dt_table_api.h author Josh Rosenbaum <jrosenba@cisco.com>

class Table;
class TableApi;

class TableApi
{
public:
    TableApi();
    virtual ~TableApi();

    void reset_state();
    friend std::ostream& operator<<(std::ostream& out, const TableApi& table);
    void print_tables(std::ostream& out);

    inline bool empty()
    { return tables.empty(); }

/*
 * Accessing and choosing specific tables.
 */

// open a table at the topmost layer. i.e., the table will not be nested inside any other table.
    void open_top_level_table(std::string name);
// open a nested named table --> 'name = {...}')
    void open_table(std::string name);
// open a nested table that does not contain a name --> {...})
    void open_table();
// close the nested table.  go to previous table level
    void close_table();

    void swap_tables(std::vector<Table*>& new_tables);

/*
 * Adding/accessing data to the specific table chosen above!!
 * These methods will all throw a developer warning if called without
 * selecting a table!
 */

/*
 * add a string, bool, or int option to the table. --> table = { name = var |'var'};
 * NOTE:  if val is a string/char* and starts with a '$', Snort2lua assumes that val
 *        is a Snort/Lua variable. Therefore, if val starts with $, Snort2Lua will not
 *        place quotes around the string
 */
    bool add_option(const std::string opt_name, const std::string val);
    bool add_option(const std::string opt_name, const int val);
    bool add_option(const std::string opt_name, const bool val);
    bool add_option(const std::string opt_name, const char* const v);

// sometimes, you may need to create a default option, before overwriting that
// option later. For instance, if you have a default table, and then you
// need to overwrite a single option in that default table, you can use these
// methods to overwrite that option.
    void append_option(const std::string opt_name, const std::string val);
    void append_option(const std::string opt_name, const int val);
    void append_option(const std::string opt_name, const bool val);
    void append_option(const std::string opt_name, const char* const v);

// add an option with a list of variables -->  table = { name = 'elem1 elem2 ...' }
// corresponds to Parameter::PT_MULTI
    bool add_list(std::string list_name, std::string next_elem);
// add a commment to be printed in the table --> table = { -- comment \n ... }
    bool add_comment(std::string comment);
// add a comment about an option change to the table
    bool add_diff_option_comment(std::string orig_var, std::string new_var);
// attach a deprecated option comment to the current table
    bool add_deleted_comment(std::string dep_var);
// attach an unsupported option comment to the current table
    bool add_unsupported_comment(std::string unsupported_var);

// return true if this name exists as an option name for the selected table
    bool option_exists(const std::string name);

private:
    void create_append_data(std::string& fqn, Table*& t);

// Data
    std::vector<Table*> tables;
    std::stack<Table*> open_tables;
    std::stack<unsigned> top_level_tables;
    bool curr_data_bad;
};

#endif

