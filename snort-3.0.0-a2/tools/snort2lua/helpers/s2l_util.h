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
// s2l_util.h author Josh Rosenbaum <jrosenba@cisco.com>

#ifndef HELPERS_UTIL_H
#define HELPERS_UTIL_H

#include <string>
#include <vector>
#include <algorithm>
#include <functional>
#include <cctype>
#include <locale>
#include <sstream>
#include <memory>

struct ConvertMap;
class Table;

namespace util
{
std::vector<std::string>& split(const std::string& s, char delim, std::vector<std::string>& elems);

// Search through the vector for the map which matches keyword

Table* find_table(const std::vector<Table*>& vec, const std::string& name);
const ConvertMap* find_map(const std::vector<const ConvertMap*>&, const std::string& keyword);
const std::unique_ptr<const ConvertMap>& find_map(
    const std::vector<std::unique_ptr<const ConvertMap> >&, const std::string& keyword);

// trim from begining
std::string& ltrim(std::string& s);

// trim from end
std::string& rtrim(std::string& s);

// trim from both ends
std::string& trim(std::string& s);

// return true if this file exists. False otherwise.
bool file_exists(const std::string& name);

/*
 * Takes in a stream and a string of delimeters. The function will extract the charachters
 * from the stream until it hits one of the delimeters.  The substring will be set to the
 * third parameter.  The stream itself will point to the chrachter after the first delim.
 *
 * PARAMS:
 *          data_stream - the data stream from which to find a substring.
 *          delimeters - The string of delimeters.
 *          options - The found substring will be place in this parameter.  If the
 *                     stream is empty or no charachters have been extracted, then
 *                     this parameter wil be set to an empty string.
 * RETURNS:
 *          True - when the string is found.
 *          False - whenma substing was unable to be extracted.
 */
bool get_string(std::istringstream& data_stream,
    std::string& option,
    const std::string delimeters);

/*
 * Returns the rest of the data_streams data as one argument.
 * Usefule when parsing filenames with spaces or other
 * characters which can get removed by c++ libraries
 *
 * NO SIDE EFFECTS
 */
std::string get_remain_data(std::istringstream& data_stream);

std::string get_rule_option_args(std::istringstream& data_stream);

/*
 * When converting rules, some options require information from
 * a different options.  For instance, the rule options 'threshold'
 * needs to know both the rule's gid and sid.  This function
 * provides a simple way to get those values.
 *
 * PARAMS:
 *          data_stream - the rule's data stream
 *          opt_name - the option name for which to seach.
 * RETURN:
 *          the opt_names value or an empty string if the opt_name
 *          is not found.
 *
 */
std::string rule_option_find_val(std::istringstream& data_stream,
    std::string opt_name);

// remove any ']]' and double spaces from this string.
std::string& sanitize_lua_string(std::string& s);

// find the location of the first space before max_str_lenght.
// if no space exists before max_str_length, return the first space
// after max_length. Otherwise, return std::string::npos
std::size_t get_substr_length(std::string s, std::size_t max_length);

bool case_compare(std::string, std::string);
}  // namespace util

#endif

