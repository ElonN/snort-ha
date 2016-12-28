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
// wizard.cc author Russ Combs <rucombs@cisco.com>

#include <vector>
using namespace std;

#include "flow/flow.h"
#include "framework/inspector.h"
#include "managers/inspector_manager.h"
#include "protocols/packet.h"
#include "stream/stream_splitter.h"
#include "time/profiler.h"
#include "utils/stats.h"
#include "log/messages.h"

#include "magic.h"
#include "wiz_module.h"

THREAD_LOCAL ProfileStats wizPerfStats;

struct WizStats
{
    PegCount tcp_scans;
    PegCount tcp_hits;
    PegCount udp_scans;
    PegCount udp_hits;
    PegCount user_scans;
    PegCount user_hits;
};

const PegInfo wiz_pegs[] =
{
    { "tcp scans", "tcp payload scans" },
    { "tcp hits", "tcp identifications" },
    { "udp scans", "udp payload scans" },
    { "udp hits", "udp identifications" },
    { "user scans", "user payload scans" },
    { "user hits", "user identifications" },
    { nullptr, nullptr }
};

THREAD_LOCAL WizStats tstats;

//-------------------------------------------------------------------------
// configuration
//-------------------------------------------------------------------------

struct Wand
{
    const MagicPage* hex;
    const MagicPage* spell;
};

class Wizard;

class MagicSplitter : public StreamSplitter
{
public:
    MagicSplitter(bool, class Wizard*);
    ~MagicSplitter();

    Status scan(Flow*, const uint8_t* data, uint32_t len,
        uint32_t flags, uint32_t* fp) override;

    bool is_paf() override { return true; }

private:
    Wizard* wizard;
    Wand wand;
};

class Wizard : public Inspector
{
public:
    Wizard(WizardModule*);
    ~Wizard();

    void show(SnortConfig*) override
    { LogMessage("Wizard\n"); }

    void eval(Packet*) override;

    StreamSplitter* get_splitter(bool) override;

    void reset(Wand&, bool tcp, bool c2s);
    bool cast_spell(Wand&, Flow*, const uint8_t*, unsigned);
    bool spellbind(const MagicPage*&, Flow*, const uint8_t*, unsigned);

public:
    MagicBook* c2s_hexes;
    MagicBook* s2c_hexes;

    MagicBook* c2s_spells;
    MagicBook* s2c_spells;
};

//-------------------------------------------------------------------------
// splitter - this doesn't actually split the stream but it applies
// basic magic type logic to determine the appropriate inspector that
// will split the stream.
//-------------------------------------------------------------------------

MagicSplitter::MagicSplitter(bool c2s, class Wizard* w) :
    StreamSplitter(c2s)
{
    wizard = w;
    w->add_ref();
    w->reset(wand, true, c2s);
}

MagicSplitter::~MagicSplitter()
{
    wizard->rem_ref();
}

StreamSplitter::Status MagicSplitter::scan(
    Flow* f, const uint8_t* data, uint32_t len,
    uint32_t, uint32_t*)
{
    ++tstats.tcp_scans;

    if ( wizard->cast_spell(wand, f, data, len) )
        ++tstats.tcp_hits;

    return SEARCH;
}

//-------------------------------------------------------------------------
// class stuff
//-------------------------------------------------------------------------

Wizard::Wizard(WizardModule* m)
{
    c2s_hexes = m->get_book(true, true);
    s2c_hexes = m->get_book(false, true);

    c2s_spells = m->get_book(true, false);
    s2c_spells = m->get_book(false, false);
}

Wizard::~Wizard()
{
    delete c2s_hexes;
    delete s2c_hexes;

    delete c2s_spells;
    delete s2c_spells;
}

void Wizard::reset(Wand& w, bool /*tcp*/, bool c2s)
{
    if ( c2s )
    {
        w.hex = c2s_hexes->page1();
        w.spell = c2s_spells->page1();
    }
    else
    {
        w.hex = s2c_hexes->page1();
        w.spell = s2c_spells->page1();
    }
}

void Wizard::eval(Packet* p)
{
    if ( !p->is_udp() )
        return;

    if ( !p->data || !p->dsize )
        return;

    Wand wand;
    reset(wand, false, p->packet_flags & PKT_FROM_CLIENT);

    if ( cast_spell(wand, p->flow, p->data, p->dsize) )
        ++tstats.udp_hits;

    ++tstats.udp_scans;
}

StreamSplitter* Wizard::get_splitter(bool c2s)
{
    return new MagicSplitter(c2s, this);
}

bool Wizard::spellbind(
    const MagicPage*& m, Flow* f, const uint8_t* data, unsigned len)
{
    f->service = m->book.find_spell(data, len, m);
    return f->service != nullptr;
}

bool Wizard::cast_spell(
    Wand& w, Flow* f, const uint8_t* data, unsigned len)
{
    if ( w.hex && spellbind(w.hex, f, data, len) )
        return true;

    if ( w.spell && spellbind(w.spell, f, data, len) )
        return true;

    return false;
}

//-------------------------------------------------------------------------
// api stuff
//-------------------------------------------------------------------------

static Module* mod_ctor()
{ return new WizardModule; }

static void mod_dtor(Module* m)
{ delete m; }

static Inspector* wiz_ctor(Module* m)
{
    WizardModule* mod = (WizardModule*)m;
    assert(mod);
    return new Wizard(mod);
}

static void wiz_dtor(Inspector* p)
{
    delete p;
}

static const InspectApi wiz_api =
{
    {
        PT_INSPECTOR,
        sizeof(InspectApi),
        INSAPI_VERSION,
        0,
        API_RESERVED,
        API_OPTIONS,
        WIZ_NAME,
        WIZ_HELP,
        mod_ctor,
        mod_dtor
    },
    IT_WIZARD,
    (uint16_t)PktType::TCP | (uint16_t)PktType::UDP | (uint16_t)PktType::PDU,
    nullptr, // buffers
    nullptr, // service
    nullptr, // init
    nullptr, // term
    nullptr, // tinit
    nullptr, // tterm
    wiz_ctor,
    wiz_dtor,
    nullptr, // ssn
    nullptr  // reset
};

#ifdef BUILDING_SO
SO_PUBLIC const BaseApi* snort_plugins[] =
{
    &wiz_api.base,
    nullptr
};
#else
const BaseApi* sin_wizard = &wiz_api.base;
#endif

