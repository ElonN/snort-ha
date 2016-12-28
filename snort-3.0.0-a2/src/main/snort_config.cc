//--------------------------------------------------------------------------
// Copyright (C) 2014-2015 Cisco and/or its affiliates. All rights reserved.
// Copyright (C) 2013-2013 Sourcefire, Inc.
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

#include "snort_config.h"

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#ifdef HAVE_MALLOC_TRIM
#include <malloc.h>
#endif

#include "snort_types.h"
#include "thread.h"
#include "detection/treenodes.h"
#include "events/event_queue.h"
#include "stream/stream_api.h"
#include "port_scan/ps_detect.h"  // FIXIT-L for PS_PROTO_*
#include "utils/strvec.h"
#include "file_api/file_service.h"
#include "file_api/libs/file_config.h"
#include "target_based/sftarget_reader.h"
#include "parser/parser.h"
#include "parser/config_file.h"
#include "parser/vars.h"
#include "helpers/process.h"
#include "filters/rate_filter.h"
#include "filters/sfrf.h"
#include "managers/ips_manager.h"
#include "managers/module_manager.h"
#include "managers/mpse_manager.h"
#include "managers/inspector_manager.h"
#include "filters/sfthreshold.h"
#include "filters/detection_filter.h"
#include "detection/fp_config.h"
#include "detection/fp_create.h"
#include "ips_options/ips_pcre.h"
#include "protocols/udp.h"
#include "time/ppm.h"
#include "time/profiler.h"
#include "sfip/sf_ip.h"

THREAD_LOCAL SnortConfig* snort_conf = nullptr;

//-------------------------------------------------------------------------
// private implementation
//-------------------------------------------------------------------------

static void FreeRuleStateList(RuleState* head)
{
    while ( head )
    {
        RuleState* tmp = head;
        head = head->next;
        free(tmp);
    }
}

static void FreeClassifications(ClassType* head)
{
    while ( head )
    {
        ClassType* tmp = head;
        head = head->next;

        if ( tmp->name )
            free(tmp->name);

        if ( tmp->type )
            free(tmp->type);

        free(tmp);
    }
}

static void FreeReferences(ReferenceSystemNode* head)
{
    while ( head )
    {
        ReferenceSystemNode* tmp = head;
        head = head->next;

        if ( tmp->name )
            free(tmp->name);

        if ( tmp->url )
            free(tmp->url);

        free(tmp);
    }
}

static void init_policy_mode(IpsPolicy* p)
{
    switch ( p->policy_mode )
    {
    case POLICY_MODE__PASSIVE:
        if ( SnortConfig::adaptor_inline_test_mode() )
            p->policy_mode = POLICY_MODE__INLINE_TEST;
        break;

    case POLICY_MODE__INLINE:
        if ( SnortConfig::adaptor_inline_test_mode() )
            p->policy_mode = POLICY_MODE__INLINE_TEST;

        else if (!SnortConfig::adaptor_inline_mode())
        {
            ParseWarning(WARN_DAQ, "adapter is in passive mode; switching policy mode to tap.");
            p->policy_mode = POLICY_MODE__PASSIVE;
        }
        break;

    case POLICY_MODE__INLINE_TEST:
        break;

    case POLICY_MODE__MAX:
        if ( SnortConfig::adaptor_inline_mode() )
            p->policy_mode = POLICY_MODE__INLINE;
        else
            p->policy_mode = POLICY_MODE__PASSIVE;
        break;
    }
}

static void init_policies(SnortConfig* sc)
{
    for ( auto p : sc->policy_map->ips_policy )
        init_policy_mode(p);
}

//-------------------------------------------------------------------------
// public methods
//-------------------------------------------------------------------------

/* A lot of this initialization can be skipped if not running in IDS mode
 * but the goal is to minimize config checks at run time when running in
 * IDS mode so we keep things simple and enforce that the only difference
 * among run_modes is how we handle packets via the log_func. */
SnortConfig::SnortConfig()
{
    num_layers = DEFAULT_LAYERMAX;

    max_attribute_hosts = DEFAULT_MAX_ATTRIBUTE_HOSTS;
    max_attribute_services_per_host = DEFAULT_MAX_ATTRIBUTE_SERVICES_PER_HOST;

    max_metadata_services = DEFAULT_MAX_METADATA_SERVICES;
    mpls_stack_depth = DEFAULT_LABELCHAIN_LENGTH;

    InspectorManager::new_config(this);

    num_slots = get_instance_max();
    state = (SnortState*)SnortAlloc(sizeof(SnortState)*num_slots);

#ifdef PERF_PROFILING
    profile_rules = (ProfileConfig*)SnortAlloc(sizeof(*profile_rules));
    profile_modules = (ProfileConfig*)SnortAlloc(sizeof(*profile_modules));
#endif

#ifdef PPM_MGR
    ppm_cfg = (ppm_cfg_t*)SnortAlloc(sizeof(*ppm_cfg));
#endif

    policy_map = new PolicyMap;

    set_inspection_policy(get_inspection_policy());
    set_ips_policy(get_ips_policy());
    set_network_policy(get_network_policy());

    source_affinity = new std::map<const std::string, int>;
    thread_affinity = new std::vector<int>(32, -1);

    sfip_clear(homenet);
    sfip_clear(obfuscation_net);

    memset(evalOrder, 0, sizeof(evalOrder));
}

SnortConfig::~SnortConfig()
{
    FreeRuleStateList(rule_state_list);
    FreeClassifications(classifications);
    FreeReferences(references);

    pcre_cleanup(this);

    FreeRuleLists(this);
    OtnLookupFree(otn_map);
    PortTablesFree(port_tables);

    ThresholdConfigFree(threshold_config);
    RateFilter_ConfigFree(rate_filter_config);
    DetectionFilterConfigFree(detection_filter_config);

    if ( event_queue_config )
        EventQueueConfigFree(event_queue_config);

    fpDeleteFastPacketDetection(this);

    if ( daq_vars )
        StringVector_Delete(daq_vars);

    if ( daq_dirs )
        StringVector_Delete(daq_dirs);

    if (eth_dst )
        free(eth_dst);

    delete file_config;

    if ( var_list )
        FreeVarList(var_list);

    if ( fast_pattern_config &&
        (!snort_conf || this == snort_conf ||
        (fast_pattern_config->get_search_api() !=
        snort_conf->fast_pattern_config->get_search_api())) )
    {
        MpseManager::stop_search_engine(fast_pattern_config->get_search_api());
        delete fast_pattern_config;
    }

    delete policy_map;
    InspectorManager::delete_config(this);

    free(state);

    if (source_affinity)
        delete source_affinity;

    if (thread_affinity)
        delete thread_affinity;

    if (gtp_ports)
        delete gtp_ports;

    free(profile_rules);
    free(profile_modules);
    free(ppm_cfg);

#ifdef INTEL_SOFT_CPM
    IntelPmRelease(ipm_handles);
#endif

    trim_heap();
}

void SnortConfig::setup()
{
    if ( output_use_utc() )
        thiszone = 0;

#ifndef VALGRIND_TESTING
    else
        thiszone = gmt2local(0);
#endif

    init_policies(this);
    ParseRules(this);

    // FIXIT-L see SnortInit() on config printing
    //detection_filter_print_config(detection_filter_config);
    //RateFilter_PrintConfig(rate_filter_config);
    //print_thresholding(threshold_config, 0);
    //PrintRuleOrder(rule_lists);

    SetRuleStates(this);

    /* Need to do this after dynamic detection stuff is initialized, too */
    IpsManager::verify(this);
    ModuleManager::load_commands(this);

    fpCreateFastPacketDetection(this);
    pcre_setup(this);

#ifdef PPM_MGR
    //PPM_PRINT_CFG(ppm_cfg);
#endif
}

// merge in everything from the command line config
void SnortConfig::merge(SnortConfig* cmd_line)
{
    if ( !cmd_line->log_dir.empty() )
        log_dir = cmd_line->log_dir;

    if ( log_dir.empty() )
        log_dir = DEFAULT_LOG_DIR;

    run_prefix = cmd_line->run_prefix;
    id_subdir = cmd_line->id_subdir;
    id_zero = cmd_line->id_zero;

    /* Used because of a potential chroot */
    orig_log_dir = log_dir;
    event_log_id = cmd_line->event_log_id;

    run_flags |= cmd_line->run_flags;
    output_flags |= cmd_line->output_flags;
    logging_flags |= cmd_line->logging_flags;

    if ((cmd_line->run_flags & RUN_FLAG__TEST) &&
        (run_flags & RUN_FLAG__DAEMON))
    {
        /* Just ignore deamon setting in conf file */
        run_flags &= ~RUN_FLAG__DAEMON;
    }

    stdin_rules = cmd_line->stdin_rules;

    // only set by cmd_line to override other conf output settings
    output = cmd_line->output;

    /* Merge checksum flags.  If command line modified them, use from the
     * command line, else just use from config_file. */

    int cl_chk = cmd_line->get_network_policy()->checksum_eval;
    int cl_drop = cmd_line->get_network_policy()->checksum_drop;

    for ( auto p : policy_map->network_policy )
    {
        if ( !(cl_chk & CHECKSUM_FLAG__DEF) )
            p->checksum_eval = cl_chk;

        if ( !(cl_drop & CHECKSUM_FLAG__DEF) )
            p->checksum_drop = cl_drop;
    }

    /* FIXIT-L do these belong in network policy? */
    if (cmd_line->num_layers != 0)
        num_layers = cmd_line->num_layers;

    if (cmd_line->max_ip6_extensions != 0)
        max_ip6_extensions = cmd_line->max_ip6_extensions;

    if (cmd_line->max_ip_layers != 0)
        max_ip_layers = cmd_line->max_ip_layers;

    if (cmd_line->obfuscation_net.family != 0)
        memcpy(&obfuscation_net, &cmd_line->obfuscation_net, sizeof(sfip_t));

    if (cmd_line->homenet.family != 0)
        memcpy(&homenet, &cmd_line->homenet, sizeof(sfip_t));

    if ( !cmd_line->bpf_file.empty() )
        bpf_file = cmd_line->bpf_file;

    if ( !cmd_line->bpf_filter.empty() )
        bpf_filter = cmd_line->bpf_filter;

    if (cmd_line->pkt_snaplen != -1)
        pkt_snaplen = cmd_line->pkt_snaplen;

    if (cmd_line->pkt_cnt != 0)
        pkt_cnt = cmd_line->pkt_cnt;

    if (cmd_line->pkt_skip != 0)
        pkt_skip = cmd_line->pkt_skip;

    if (cmd_line->group_id != -1)
        group_id = cmd_line->group_id;

    if (cmd_line->user_id != -1)
        user_id = cmd_line->user_id;

    /* Only configurable on command line */
    if (cmd_line->file_mask != 0)
        file_mask = cmd_line->file_mask;

    if ( !cmd_line->chroot_dir.empty() )
    {
        chroot_dir = cmd_line->chroot_dir;
    }

    if ( cmd_line->daq_type.size() )
        daq_type = cmd_line->daq_type;

    if ( cmd_line->daq_mode.size() )
        daq_mode = cmd_line->daq_mode;

    if ( cmd_line->dirty_pig )
        dirty_pig = cmd_line->dirty_pig;

    if ( cmd_line->daq_vars )
    {
        /* Command line overwrites daq_vars */
        if (daq_vars)
            StringVector_Delete(daq_vars);

        daq_vars = StringVector_New();
        StringVector_AddVector(daq_vars, cmd_line->daq_vars);
    }
    if ( cmd_line->daq_dirs )
    {
        /* Command line overwrites daq_dirs */
        if (daq_dirs)
            StringVector_Delete(daq_dirs);

        daq_dirs = StringVector_New();
        StringVector_AddVector(daq_dirs, cmd_line->daq_dirs);
    }
    if (cmd_line->mpls_stack_depth != DEFAULT_LABELCHAIN_LENGTH)
        mpls_stack_depth = cmd_line->mpls_stack_depth;

    /* Set MPLS payload type here if it hasn't been defined */
    if ((cmd_line->mpls_payload_type == 0) &&
        (mpls_payload_type == 0))
    {
        mpls_payload_type = DEFAULT_MPLS_PAYLOADTYPE;
    }
    else if (cmd_line->mpls_payload_type != 0)
    {
        mpls_payload_type = cmd_line->mpls_payload_type;
    }

    if (cmd_line->run_flags & RUN_FLAG__PROCESS_ALL_EVENTS)
        event_queue_config->process_all_events = 1;

#ifdef BUILD_SHELL
    if ( cmd_line->remote_control )
        remote_control = cmd_line->remote_control;
#endif

    // config file vars are stored differently
    // FIXIT-M should cmd_line use the same var list / table?
    var_list = NULL;

    free(state);
    num_slots = get_instance_max();
    state = (SnortState*)SnortAlloc(sizeof(SnortState)*num_slots);
}

bool SnortConfig::verify()
{
    if (snort_conf->asn1_mem != asn1_mem)
    {
        ErrorMessage("Snort Reload: Changing the asn1 memory configuration "
            "requires a restart.\n");
        return false;
    }

    if ( bpf_filter != snort_conf->bpf_filter )
    {
        ErrorMessage("Snort Reload: Changing the bpf filter configuration "
            "requires a restart.\n");
        return false;
    }

    if ( respond_attempts != snort_conf->respond_attempts ||
        respond_device != snort_conf->respond_device )
    {
        ErrorMessage("Snort Reload: Changing config response "
            "requires a restart.\n");
        return false;
    }

    if (snort_conf->chroot_dir != chroot_dir)
    {
        ErrorMessage("Snort Reload: Changing the chroot directory "
            "configuration requires a restart.\n");
        return false;
    }

    if ((snort_conf->run_flags & RUN_FLAG__DAEMON) !=
        (run_flags & RUN_FLAG__DAEMON))
    {
        ErrorMessage("Snort Reload: Changing to or from daemon mode "
            "requires a restart.\n");
        return false;
    }

    /* Orig log dir because a chroot might have changed it */
    if (snort_conf->orig_log_dir != orig_log_dir)
    {
        ErrorMessage("Snort Reload: Changing the log directory "
            "configuration requires a restart.\n");
        return false;
    }

    if (snort_conf->max_attribute_hosts != max_attribute_hosts)
    {
        ErrorMessage("Snort Reload: Changing max_attribute_hosts "
            "configuration requires a restart.\n");
        return false;
    }
    if (snort_conf->max_attribute_services_per_host != max_attribute_services_per_host)
    {
        ErrorMessage("Snort Reload: Changing max_attribute_services_per_host "
            "configuration requires a restart.\n");
        return false;
    }

    if ((snort_conf->run_flags & RUN_FLAG__NO_PROMISCUOUS) !=
        (run_flags & RUN_FLAG__NO_PROMISCUOUS))
    {
        ErrorMessage("Snort Reload: Changing to or from promiscuous mode "
            "requires a restart.\n");
        return false;
    }

#ifdef PPM_MGR
    /* XXX XXX Not really sure we need to disallow this */
    if (snort_conf->ppm_cfg->rule_log != ppm_cfg->rule_log)
    {
        ErrorMessage("Snort Reload: Changing the ppm rule_log "
            "configuration requires a restart.\n");
        return false;
    }
#endif

    if (snort_conf->group_id != group_id)
    {
        ErrorMessage("Snort Reload: Changing the group id "
            "configuration requires a restart.\n");
        return false;
    }

    if (snort_conf->user_id != user_id)
    {
        ErrorMessage("Snort Reload: Changing the user id "
            "configuration requires a restart.\n");
        return false;
    }

    if (snort_conf->pkt_snaplen != pkt_snaplen)
    {
        ErrorMessage("Snort Reload: Changing the packet snaplen "
            "configuration requires a restart.\n");
        return false;
    }

    if (snort_conf->threshold_config->memcap !=
        threshold_config->memcap)
    {
        ErrorMessage("Snort Reload: Changing the threshold memcap "
            "configuration requires a restart.\n");
        return false;
    }

    if (snort_conf->rate_filter_config->memcap !=
        rate_filter_config->memcap)
    {
        ErrorMessage("Snort Reload: Changing the rate filter memcap "
            "configuration requires a restart.\n");
        return false;
    }

    if (snort_conf->detection_filter_config->memcap !=
        detection_filter_config->memcap)
    {
        ErrorMessage("Snort Reload: Changing the detection filter memcap "
            "configuration requires a restart.\n");
        return false;
    }

    return true;
}

