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
// rule_threshold.cc author Josh Rosenbaum <jrosenba@cisco.com>

#include <sstream>
#include <vector>

#include "conversion_state.h"
#include "helpers/converter.h"
#include "rule_states/rule_api.h"
#include "helpers/s2l_util.h"

namespace rules
{
namespace
{
class Resp : public ConversionState
{
public:
    Resp(Converter& c) : ConversionState(c) { }
    virtual ~Resp() { }
    virtual bool convert(std::istringstream& data);

private:
    void add_diff_comment(std::string, std::string);
};
} // namespace

void Resp::add_diff_comment(std::string old_v, std::string new_v)
{
    table_api.add_diff_option_comment("rule_type - resp:" + old_v,
        "reject - " + new_v);
}

bool Resp::convert(std::istringstream& data_stream)
{
    std::string args;
    std::string tmp;
    std::streamoff pos = data_stream.tellg();

    args = util::get_rule_option_args(data_stream);

    // if there are no arguments, the option had a colon before a semicolon.
    // we are therefore done with this rule.
    if (!args.empty())
    {
        // a colon will have been parsed when retrieving the keyword.
        // Therefore, if a colon is present, we are in the next rule option.
        if (args.find(":") != std::string::npos)
        {
            data_stream.seekg(pos);
        }
        else
        {
            // since we still can't be sure if we passed the resp buffer,
            // check the next option and ensure it matches
            std::istringstream arg_stream(args);
            util::get_string(arg_stream, tmp, ",");

            if (!tmp.compare("reset_dest") ||
                !tmp.compare("reset_both") ||
                !tmp.compare("rst_snd") ||
                !tmp.compare("rst_rcv") ||
                !tmp.compare("rst_all") ||
                !tmp.compare("icmp_net") ||
                !tmp.compare("icmp_host") ||
                !tmp.compare("icmp_all") ||
                !tmp.compare("reset_source") ||
                !tmp.compare("icmp_port"))
            {
                // Now that we have confirmed this is a vlid option, parse it!!
                table_api.open_table("reject");

                do
                {
                    // FIXIT-L Once bindings added for reject, this MUST change!

                    if (!tmp.compare("reset_dest"))
                    {
                        add_diff_comment("reset_dest", "reset: dest");
                        table_api.add_option("reset", "dest");
                    }
                    else if (!tmp.compare("rst_rcv"))
                    {
                        add_diff_comment("rst_rcv", "reset: dest");
                        table_api.add_option("reset", "dest");
                    }
                    else if (!tmp.compare("reset_both"))
                    {
                        add_diff_comment("reset_both", "reset: both");
                        table_api.add_option("reset", "both");
                    }
                    else if (!tmp.compare("rst_all"))
                    {
                        add_diff_comment("rst_all", "reset: both");
                        table_api.add_option("reset", "both");
                    }
                    else if (!tmp.compare("rst_snd"))
                    {
                        add_diff_comment("rst_snd", "reset: source");
                        table_api.add_option("reset", "source");
                    }
                    else if (!tmp.compare("reset_source"))
                    {
                        add_diff_comment("reset_source", "reset: source");
                        table_api.add_option("reset", "source");
                    }
                    else if (!tmp.compare("icmp_net"))
                    {
                        add_diff_comment("icmp_net", "control: network");
                        table_api.add_option("control", "network");
                    }
                    else if (!tmp.compare("icmp_host"))
                    {
                        add_diff_comment("icmp_host", "control: host");
                        table_api.add_option("control", "host");
                    }
                    else if (!tmp.compare("icmp_all"))
                    {
                        add_diff_comment("icmp_all", "control: all");
                        table_api.add_option("control", "all");
                    }
                    else if (!tmp.compare("icmp_port"))
                    {
                        add_diff_comment("icmp_port", "control: port");
                        table_api.add_option("control", "port");
                    }
                    else
                    {
                        rule_api.bad_rule(data_stream, "resp: " + tmp);
                    }
                }
                while (util::get_string(arg_stream, tmp, ","));

                table_api.close_table(); // "reject"
            }
            else
            {
                data_stream.seekg(pos);
            }
        }
    }

    return set_next_rule_state(data_stream);
}

/**************************
 *******  A P I ***********
 **************************/

static ConversionState* ctor(Converter& c)
{
    // reject may not have arguments. So, set this information now.

    // create this table to ensure reject is instatiated
    c.get_table_api().open_table("reject");
    c.get_table_api().close_table();

    // update the rule type
    c.get_rule_api().update_rule_action("reject");

    return new Resp(c);
}

static const ConvertMap rule_resp =
{
    "resp",
    ctor,
};

const ConvertMap* resp_map = &rule_resp;
} // namespace rules

