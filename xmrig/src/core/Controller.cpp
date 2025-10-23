/* XMRig
 * Copyright (c) 2018-2021 SChernykh   <https://github.com/SChernykh>
 * Copyright (c) 2016-2021 XMRig       <https://github.com/xmrig>, <support@xmrig.com>
 *
 *   This program is free software: you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation, either version 3 of the License, or
 *   (at your option) any later version.
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with this program. If not, see <http://www.gnu.org/licenses/>.
 */

#include "core/Controller.h"
#include "backend/cpu/Cpu.h"
#include "core/config/Config.h"
#include "base/io/log/Log.h"
#include "base/io/log/Tags.h"
#ifdef XMRIG_FEATURE_PEER
#   include "peer/PeerServer.h"
#endif
#include "core/Miner.h"
#include "crypto/common/VirtualMemory.h"
#include "net/Network.h"


#ifdef XMRIG_FEATURE_API
#   include "base/api/Api.h"
#   include "hw/api/HwApi.h"
#endif


#include <cassert>


xmrig::Controller::Controller(Process *process) :
    Base(process)
{
}


xmrig::Controller::~Controller()
{
    VirtualMemory::destroy();
}


int xmrig::Controller::init()
{
    Base::init();

    VirtualMemory::init(config()->cpu().memPoolSize(), config()->cpu().hugePageSize());

    m_network = std::make_shared<Network>(this);

#   ifdef XMRIG_FEATURE_API
    m_hwApi = std::make_shared<HwApi>();
    api()->addListener(m_hwApi.get());
#   endif

    return 0;
}


void xmrig::Controller::start()
{
    Base::start();

    m_miner = std::make_shared<Miner>(this);

#ifdef XMRIG_FEATURE_PEER
    if (config()->peerEnabled()) {
        peer::PeerServerConfig pcfg;
        pcfg.bindAddress = config()->peerBind();
        pcfg.port        = config()->peerPort();
        pcfg.token       = config()->peerToken() ? config()->peerToken() : "";
        pcfg.tls         = false;

        m_peerServer.reset(new peer::PeerServer(m_miner.get()));
        if (m_peerServer->start(pcfg)) {
            LOG_INFO("%s peer server listening on %s:%u", Tags::network(), pcfg.bindAddress.c_str(), static_cast<unsigned>(pcfg.port));
        }
        else {
            LOG_ERR("%s failed to start peer server on %s:%u", Tags::network(), pcfg.bindAddress.c_str(), static_cast<unsigned>(pcfg.port));
            m_peerServer.reset();
        }
    }
#endif

    network()->connect();
}


void xmrig::Controller::stop()
{
    Base::stop();

#ifdef XMRIG_FEATURE_PEER
    m_peerServer.reset();
#endif

    m_network.reset();

    m_miner->stop();
    m_miner.reset();
}


xmrig::Miner *xmrig::Controller::miner() const
{
    assert(m_miner);

    return m_miner.get();
}


xmrig::Network *xmrig::Controller::network() const
{
    assert(m_network);

    return m_network.get();
}

#ifdef XMRIG_FEATURE_PEER
xmrig::peer::PeerServer* xmrig::Controller::peerServer() const
{
    return m_peerServer.get();
}
#endif


void xmrig::Controller::execCommand(char command) const
{
    miner()->execCommand(command);
    network()->execCommand(command);
}
