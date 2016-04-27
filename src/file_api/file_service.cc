//--------------------------------------------------------------------------
// Copyright (C) 2014-2015 Cisco and/or its affiliates. All rights reserved.
// Copyright (C) 2012-2013 Sourcefire, Inc.
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
/*
 ** Author(s):  Hui Cao <huica@cisco.com>
 **
 ** NOTES
 ** 5.25.12 - Initial Source Code. Hui Cao
 */

#include "file_service.h"

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <sys/types.h>
#include <stdio.h>
#include <stdlib.h>

#include "file_api.h"
#include "file_stats.h"
#include "file_capture.h"
#include "file_flows.h"
#include "file_resume_block.h"
#include "libs/file_lib.h"
#include "libs/file_config.h"

#include "mime/file_mime_config.h"
#include "mime/file_mime_process.h"
#include "main/snort_types.h"
#include "managers/action_manager.h"
#include "stream/stream_api.h"
#include "detection/detect.h"
#include "detection/detection_util.h"
#include "packet_io/active.h"
#include "framework/inspector.h"

bool FileService::file_type_id_enabled = false;
bool FileService::file_signature_enabled = false;
bool FileService::file_capture_enabled = false;
bool FileService::file_processing_initiated = false;

void FileService::init(void)
{
    MimeSession::init();
    FileFlows::init();
}

void FileService::post_init(void)
{
    FileConfig* file_config = (FileConfig*)(snort_conf->file_config);

    if (file_type_id_enabled or file_signature_enabled or file_capture_enabled)
    {
        if (!file_config)
        {
            file_config =  new FileConfig;
            snort_conf->file_config = file_config;
        }
    }

    if ( file_capture_enabled)
        FileCapture::init_mempool(file_config->file_capture_memcap,
            file_config->file_capture_block_size);
}

void FileService::close(void)
{
    file_resume_block_cleanup();
    MimeSession::exit();
    FileCapture::exit();
}

void FileService::start_file_processing(void)
{
    if (!file_processing_initiated)
    {
        file_resume_block_init();
        //RegisterProfileStats("file", print_file_stats);  FIXIT-M put in module
        file_processing_initiated = true;
    }
}

/*
 * - Only accepts 1 (ONE) callback being registered.
 *
 * - Call with NULL callback to "force" (guarantee) file type identification.
 *
 * TBD: Remove per-context "file_type_enabled" checking to simplify implementation.
 *
 */
void FileService::enable_file_type()
{
    if (!file_type_id_enabled)
    {
        file_type_id_enabled = true;
        start_file_processing();
    }
}

void FileService::enable_file_signature()
{

    if (!file_signature_enabled)
    {
        file_signature_enabled = true;
        start_file_processing();
    }
}

/* Enable file capture, also enable file signature */
void FileService::enable_file_capture()
{
    if (!file_capture_enabled)
    {
        file_capture_enabled = true;
        enable_file_signature();
    }
}

bool FileService::is_file_service_enabled()
{
    return (file_type_id_enabled or file_signature_enabled);
}


/* Get maximal file depth based on configuration
 * This function must be called after all file services are configured/enabled.
 */
int64_t FileService::get_max_file_depth(void)
{
    FileConfig* file_config =  (FileConfig*)(snort_conf->file_config);

    if (!file_config)
        return -1;

    if (file_config->file_depth)
        return file_config->file_depth;

    file_config->file_depth = -1;

    if (file_type_id_enabled)
    {
        file_config->file_depth = file_config->file_type_depth;
    }

    if (file_signature_enabled)
    {
        if (file_config->file_signature_depth > file_config->file_depth)
            file_config->file_depth = file_config->file_signature_depth;
    }

    if (file_config->file_depth > 0)
    {
        /*Extra byte for deciding whether file data will be over limit*/
        file_config->file_depth++;
        return (file_config->file_depth);
    }
    else
    {
        return -1;
    }
}

uint64_t get_file_processed_size(Flow* flow)
{
    FileFlows* file_flows = FileFlows::get_file_flows(flow);

    if (!file_flows)
        return 0;

    FileContext* context = file_flows->get_current_file_context();

    if ( !context )
        return 0;

    return context->get_processed_bytes();
}
