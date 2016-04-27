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
// pps_sfportscan.cc author Josh Rosenbaum <jrosenba@cisco.com>

#include <sstream>
#include <vector>

#include "conversion_state.h"
#include "helpers/converter.h"
#include "helpers/s2l_util.h"

namespace preprocessors
{
namespace
{
class PortScan : public ConversionState
{
public:
    PortScan(Converter& c) : ConversionState(c) { }
    virtual ~PortScan() { }
    virtual bool convert(std::istringstream& data_stream);

private:
    bool parse_list(std::string table_name, std::istringstream& data_stream);
    bool parse_option(std::string table_name, std::istringstream& data_stream);
    bool add_portscan_global_option(std::string name, std::istringstream& data_stream);
    // a wrapper for parse_list.  adds an addition '[..]' around the string
    bool parse_ip_list(std::string table_name, std::istringstream& data_stream);
};
} // namespace

bool PortScan::parse_ip_list(std::string list_name, std::istringstream& data_stream)
{
    std::string prev;
    std::string elem;

    if (!(data_stream >> elem) || (elem != "{"))
        return false;

    if (!(data_stream >> elem))
        return false;

    // there can be no spaces between the square bracket and string
    prev = "[" + elem;

    while (data_stream >> elem && elem != "}")
        prev = prev + ' ' + elem;

    prev = prev + "]";
    return table_api.add_option(list_name, prev);
}

bool PortScan::parse_list(std::string list_name, std::istringstream& data_stream)
{
    std::string elem;
    bool retval = true;

    if (!(data_stream >> elem) || (elem != "{"))
        return false;

    while (data_stream >> elem && elem != "}")
        retval && table_api.add_list(list_name, elem) && retval;

    return retval;
}

bool PortScan::parse_option(std::string list_name, std::istringstream& data_stream)
{
    std::string elem;
    bool retval = true;

    if (!(data_stream >> elem) || (elem != "{"))
        return false;

    while (data_stream >> elem && elem != "}")
        retval && table_api.add_option(list_name, elem) && retval;

    return retval;
}

bool PortScan::add_portscan_global_option(std::string name, std::istringstream& data_stream)
{
    int val;
    std::string garbage;

    if (!(data_stream >> garbage) || (garbage != "{"))
        return false;

    if (!(data_stream >> val))
        return false;

    table_api.close_table();
    table_api.open_table("port_scan_global");
    bool retval = table_api.add_option(name, val);
    table_api.close_table();
    table_api.open_table("port_scan");

    if (!(data_stream >> garbage) || (garbage != "}"))
        return false;

    return retval;
}

bool PortScan::convert(std::istringstream& data_stream)
{
    std::string keyword;
    bool retval = true;
    table_api.open_table("port_scan");

    while (data_stream >> keyword)
    {
        bool tmpval = true;

        if (!keyword.compare("sense_level"))
            tmpval = parse_option("sense_level", data_stream);

        else if (!keyword.compare("watch_ip"))
            tmpval = parse_ip_list("watch_ip", data_stream);

        else if (!keyword.compare("ignore_scanned"))
            tmpval = parse_ip_list("ignore_scanners", data_stream);

        else if (!keyword.compare("ignore_scanners"))
            tmpval = parse_ip_list("ignore_scanned", data_stream);

        else if (!keyword.compare("include_midstream"))
            tmpval = table_api.add_option("include_midstream", true);

        else if (!keyword.compare("disabled"))
            table_api.add_deleted_comment("disabled");

        else if (!keyword.compare("detect_ack_scans"))
            table_api.add_deleted_comment("detect_ack_scans");

        else if (!keyword.compare("logfile"))
        {
            if (!util::get_string(data_stream, keyword, "}"))
                tmpval = false;
            table_api.add_deleted_comment("logfile");
        }
        else if (!keyword.compare("memcap"))
            tmpval = add_portscan_global_option("memcap", data_stream);

        else if (!keyword.compare("proto"))
        {
            table_api.add_diff_option_comment("proto", "protos");
            retval = parse_curly_bracket_list("protos", data_stream) && retval;
        }
        else if (!keyword.compare("scan_type"))
        {
            table_api.add_diff_option_comment("scan_type", "scan_types");
            tmpval = parse_curly_bracket_list("scan_types", data_stream) && retval;
        }
        else
            tmpval = false;

        if (retval)
            retval = tmpval;
    }

    table_api.close_table(); // unecessary since the state will be reset
    return retval;
}

/**************************
 *******  A P I ***********
 **************************/

static ConversionState* ctor(Converter& c)
{
    return new PortScan(c);
}

static const ConvertMap preprocessor_sfportscan =
{
    "sfportscan",
    ctor,
};

const ConvertMap* sfportscan_map = &preprocessor_sfportscan;
} // namespace preprocessors

