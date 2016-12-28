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
// dt_data.h author Josh Rosenbaum <jrosenba@cisco.com>

#ifndef DATA_DT_DATA_H
#define DATA_DT_DATA_H

#include <string>
#include <iostream>
#include <vector>
#include <stack>

#include "data/dt_table_api.h"
#include "data/dt_rule_api.h"

// FIXIT:  Change name to data_api
// FIXIT:  Remove all unecessary includes
// FIXIT:  set_default_print name should be change to print_all

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

class Include;
class Variable;
class Comments;
class DataApi;

class DataApi
{
public:
    DataApi();
    virtual ~DataApi();

    // set and retrieve various pieces of information from this Data object
    // getters are for other data classes.
    inline static void set_default_print() { mode = PrintMode::DEFAULT; }
    inline static bool is_default_mode() { return mode == PrintMode::DEFAULT; }
    inline static void set_quiet_print() { mode = PrintMode::QUIET; }
    inline static bool is_quiet_mode() { return mode == PrintMode::QUIET; }
    inline static void set_difference_print() { mode = PrintMode::DIFFERENCES; }
    inline static bool is_difference_mode() { return mode == PrintMode::DIFFERENCES; }

    // For problems with the Snort2Lua code, NOT with the snort configuration
    static void developer_error(std::string comment);

    // given a Snort-style string, replace all of the variables with their values.
    std::string expand_vars(const std::string&);
    // translate a given variable into a string
    // spaces will appear if multiple values added to variable
    std::string translate_variable(const std::string&);

    // reset any open tables.
    void reset_state();

    // Output Functions
    void print_errors(std::ostream&);
    void print_data(std::ostream&);
    void print_comments(std::ostream& out);

    // have there been any failed conversion?
    bool failed_conversions() const;
    std::size_t num_errors() const;
    // is there any actual data to print?
    bool empty() const
    { return vars.empty() && includes.empty(); }

    // functions specifically usefull when parsing includes.
    // allows for easy swapping of data.  These two functions
    // swap data which will be printed in 'print_rules()' and
    // 'print_conf_options()'
    void swap_conf_data(std::vector<Variable*>&,
        std::vector<Include*>&,
        Comments*&);

    // FILE CREATION AND ADDITIONS

    // add a variable to this file
    bool add_variable(std::string name, std::string value);
    // add a Snort style include file
    bool add_include_file(std::string name);
    // add a 'comment' to the Lua file. shoudl ONLY be used when
    // adding a comment from the original Snort file.
    void add_comment(std::string);
    // Call when failed to convert a line.
    // stream == the stringstream object which failed to convert
    void failed_conversion(const std::istringstream& stream);
    // same as above. unknown_option is the specific option which
    // caused the failure.
    void failed_conversion(const std::istringstream& stream, const std::string unkown_option);

private:

    enum class PrintMode
    {
        DEFAULT,
        DIFFERENCES,
        QUIET,
    };

    // actual configuration information
    static PrintMode mode;
    static std::size_t dev_warnings;
    static std::size_t errors_count;

    std::vector<Variable*> vars;
    std::vector<Include*> includes;
    Comments* comments;
    Comments* errors;

    bool curr_data_bad;  // keep track whether current 'conversion' is already bad
};

#endif

