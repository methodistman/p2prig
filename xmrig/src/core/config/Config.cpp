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

#include <algorithm>
#include <cinttypes>
#include <cstring>
#include <uv.h>


#include "core/config/Config.h"
#include "3rdparty/rapidjson/document.h"
#include "backend/cpu/Cpu.h"
#include "base/io/log/Log.h"
#include "base/kernel/interfaces/IJsonReader.h"
#include "base/net/dns/Dns.h"
#include "crypto/common/Assembly.h"


#ifdef XMRIG_ALGO_RANDOMX
#   include "crypto/rx/RxConfig.h"
#endif


#ifdef XMRIG_FEATURE_OPENCL
#   include "backend/opencl/OclConfig.h"
#endif


#ifdef XMRIG_FEATURE_CUDA
#   include "backend/cuda/CudaConfig.h"
#endif


namespace xmrig {


constexpr static uint32_t kIdleTime     = 60U;


const char *Config::kPauseOnBattery     = "pause-on-battery";
const char *Config::kPauseOnActive      = "pause-on-active";
const char *Config::kPeer               = "peer";
const char *Config::kPeerEnabled        = "enabled";
const char *Config::kPeerBind           = "bind";
const char *Config::kPeerPort           = "port";
const char *Config::kPeerToken          = "token";
#ifdef XMRIG_FEATURE_MARKET
const char *Config::kMarket                     = "market";
const char *Config::kMarketEnabled              = "enabled";
const char *Config::kMarketRole                 = "role";
const char *Config::kMarketPricePerKhash        = "price_per_khash";
const char *Config::kMarketCapacityKhash        = "capacity_khash";
const char *Config::kMarketLeaseMs              = "lease_ms";
const char *Config::kMarketFeeBps               = "fee_bps";
const char *Config::kMarketAuctionIntervalMs    = "auction_interval_ms";
#endif


#ifdef XMRIG_FEATURE_OPENCL
const char *Config::kOcl                = "opencl";
#endif

#ifdef XMRIG_FEATURE_CUDA
const char *Config::kCuda               = "cuda";
#endif

#if defined(XMRIG_FEATURE_NVML) || defined (XMRIG_FEATURE_ADL)
const char *Config::kHealthPrintTime    = "health-print-time";
#endif

#ifdef XMRIG_FEATURE_DMI
const char *Config::kDMI                = "dmi";
#endif


class ConfigPrivate
{
public:
    bool pauseOnBattery = false;
    CpuConfig cpu;
    uint32_t idleTime   = 0;

    // peer
    bool peerEnabled = false;
    String peerBind = String("127.0.0.1");
    uint16_t peerPort = 9000;
    String peerToken;
#   ifdef XMRIG_FEATURE_MARKET
    bool marketEnabled = false;
    String marketRole = String("auto");
    uint32_t marketPricePerKhash = 0;
    uint32_t marketCapacityKhash = 0;
    uint32_t marketLeaseMs = 2000;
    uint16_t marketFeeBps = 0;
    uint32_t marketAuctionIntervalMs = 2000;
#   endif

#   ifdef XMRIG_ALGO_RANDOMX
    RxConfig rx;
#   endif

#   ifdef XMRIG_FEATURE_OPENCL
    OclConfig cl;
#   endif

#   ifdef XMRIG_FEATURE_CUDA
    CudaConfig cuda;
#   endif

#   if defined(XMRIG_FEATURE_NVML) || defined (XMRIG_FEATURE_ADL)
    uint32_t healthPrintTime = 60U;
#   endif

#   ifdef XMRIG_FEATURE_DMI
    bool dmi = true;
#   endif

    void setIdleTime(const rapidjson::Value &value)
    {
        if (value.IsBool()) {
            idleTime = value.GetBool() ? kIdleTime : 0U;
        }
        else if (value.IsUint()) {
            idleTime = value.GetUint();
        }
    }
};

} // namespace xmrig


xmrig::Config::Config() :
    d_ptr(new ConfigPrivate())
{
}


xmrig::Config::~Config()
{
    delete d_ptr;
}


bool xmrig::Config::isPauseOnBattery() const
{
    return d_ptr->pauseOnBattery;
}


const xmrig::CpuConfig &xmrig::Config::cpu() const
{
    return d_ptr->cpu;
}


uint32_t xmrig::Config::idleTime() const
{
    return d_ptr->idleTime * 1000U;
}


bool xmrig::Config::peerEnabled() const
{
    return d_ptr->peerEnabled;
}


const char *xmrig::Config::peerBind() const
{
    return d_ptr->peerBind.isNull() ? "127.0.0.1" : d_ptr->peerBind.data();
}


uint16_t xmrig::Config::peerPort() const
{
    return d_ptr->peerPort;
}


const char *xmrig::Config::peerToken() const
{
    return d_ptr->peerToken.isNull() ? nullptr : d_ptr->peerToken.data();
}
#ifdef XMRIG_FEATURE_MARKET
bool xmrig::Config::marketEnabled() const { return d_ptr->marketEnabled; }
const char *xmrig::Config::marketRole() const { return d_ptr->marketRole.isNull() ? "auto" : d_ptr->marketRole.data(); }
uint32_t xmrig::Config::marketPricePerKhash() const { return d_ptr->marketPricePerKhash; }
uint32_t xmrig::Config::marketCapacityKhash() const { return d_ptr->marketCapacityKhash; }
uint32_t xmrig::Config::marketLeaseMs() const { return d_ptr->marketLeaseMs; }
uint16_t xmrig::Config::marketFeeBps() const { return d_ptr->marketFeeBps; }
uint32_t xmrig::Config::marketAuctionIntervalMs() const { return d_ptr->marketAuctionIntervalMs; }
#endif


#ifdef XMRIG_FEATURE_OPENCL
const xmrig::OclConfig &xmrig::Config::cl() const
{
    return d_ptr->cl;
}
#endif


#ifdef XMRIG_FEATURE_CUDA
const xmrig::CudaConfig &xmrig::Config::cuda() const
{
    return d_ptr->cuda;
}
#endif


#ifdef XMRIG_ALGO_RANDOMX
const xmrig::RxConfig &xmrig::Config::rx() const
{
    return d_ptr->rx;
}
#endif


#if defined(XMRIG_FEATURE_NVML) || defined (XMRIG_FEATURE_ADL)
uint32_t xmrig::Config::healthPrintTime() const
{
    return d_ptr->healthPrintTime;
}
#endif


#ifdef XMRIG_FEATURE_DMI
bool xmrig::Config::isDMI() const
{
    return d_ptr->dmi;
}
#endif


bool xmrig::Config::isShouldSave() const
{
    if (!isAutoSave()) {
        return false;
    }

#   ifdef XMRIG_FEATURE_OPENCL
    if (cl().isShouldSave()) {
        return true;
    }
#   endif

#   ifdef XMRIG_FEATURE_CUDA
    if (cuda().isShouldSave()) {
        return true;
    }
#   endif

    return (m_upgrade || cpu().isShouldSave());
}


bool xmrig::Config::read(const IJsonReader &reader, const char *fileName)
{
    if (!BaseConfig::read(reader, fileName)) {
        return false;
    }

    d_ptr->pauseOnBattery = reader.getBool(kPauseOnBattery, d_ptr->pauseOnBattery);
    d_ptr->setIdleTime(reader.getValue(kPauseOnActive));

    d_ptr->cpu.read(reader.getValue(CpuConfig::kField));

#   ifdef XMRIG_ALGO_RANDOMX
    if (!d_ptr->rx.read(reader.getValue(RxConfig::kField))) {
        m_upgrade = true;
    }
#   endif

#   ifdef XMRIG_FEATURE_OPENCL
    if (!pools().isBenchmark()) {
        d_ptr->cl.read(reader.getValue(kOcl));
    }
#   endif

#   ifdef XMRIG_FEATURE_CUDA
    if (!pools().isBenchmark()) {
        d_ptr->cuda.read(reader.getValue(kCuda));
    }
#   endif

#   if defined(XMRIG_FEATURE_NVML) || defined (XMRIG_FEATURE_ADL)
    d_ptr->healthPrintTime = reader.getUint(kHealthPrintTime, d_ptr->healthPrintTime);
#   endif

#   ifdef XMRIG_FEATURE_DMI
    d_ptr->dmi = reader.getBool(kDMI, d_ptr->dmi);
#   endif

    // peer section (optional)
    const auto &peer = reader.getValue(kPeer);
    if (peer.IsObject()) {
        if (peer.HasMember(kPeerEnabled) && peer[kPeerEnabled].IsBool()) {
            d_ptr->peerEnabled = peer[kPeerEnabled].GetBool();
        }
        if (peer.HasMember(kPeerBind) && peer[kPeerBind].IsString()) {
            d_ptr->peerBind = String(peer[kPeerBind]);
        }
        if (peer.HasMember(kPeerPort) && peer[kPeerPort].IsUint()) {
            d_ptr->peerPort = static_cast<uint16_t>(peer[kPeerPort].GetUint());
        }
        if (peer.HasMember(kPeerToken) && peer[kPeerToken].IsString()) {
            d_ptr->peerToken = String(peer[kPeerToken]);
        }
    }
#   ifdef XMRIG_FEATURE_MARKET
    const auto &market = reader.getValue(kMarket);
    if (market.IsObject()) {
        if (market.HasMember(kMarketEnabled) && market[kMarketEnabled].IsBool()) {
            d_ptr->marketEnabled = market[kMarketEnabled].GetBool();
        }
        if (market.HasMember(kMarketRole) && market[kMarketRole].IsString()) {
            d_ptr->marketRole = String(market[kMarketRole]);
        }
        if (market.HasMember(kMarketPricePerKhash) && market[kMarketPricePerKhash].IsUint()) {
            d_ptr->marketPricePerKhash = market[kMarketPricePerKhash].GetUint();
        }
        if (market.HasMember(kMarketCapacityKhash) && market[kMarketCapacityKhash].IsUint()) {
            d_ptr->marketCapacityKhash = market[kMarketCapacityKhash].GetUint();
        }
        if (market.HasMember(kMarketLeaseMs) && market[kMarketLeaseMs].IsUint()) {
            d_ptr->marketLeaseMs = market[kMarketLeaseMs].GetUint();
        }
        if (market.HasMember(kMarketFeeBps) && market[kMarketFeeBps].IsUint()) {
            d_ptr->marketFeeBps = static_cast<uint16_t>(market[kMarketFeeBps].GetUint());
        }
        if (market.HasMember(kMarketAuctionIntervalMs) && market[kMarketAuctionIntervalMs].IsUint()) {
            d_ptr->marketAuctionIntervalMs = market[kMarketAuctionIntervalMs].GetUint();
        }
    }
#   endif

    return true;
}


void xmrig::Config::getJSON(rapidjson::Document &doc) const
{
    using namespace rapidjson;

    doc.SetObject();

    auto &allocator = doc.GetAllocator();

    Value api(kObjectType);
    api.AddMember(StringRef(kApiId),                    m_apiId.toJSON(), allocator);
    api.AddMember(StringRef(kApiWorkerId),              m_apiWorkerId.toJSON(), allocator);

    doc.AddMember(StringRef(kApi),                      api, allocator);
    doc.AddMember(StringRef(kHttp),                     m_http.toJSON(doc), allocator);
    doc.AddMember(StringRef(kAutosave),                 isAutoSave(), allocator);
    doc.AddMember(StringRef(kBackground),               isBackground(), allocator);
    doc.AddMember(StringRef(kColors),                   Log::isColors(), allocator);
    doc.AddMember(StringRef(kTitle),                    title().toJSON(), allocator);

#   ifdef XMRIG_ALGO_RANDOMX
    doc.AddMember(StringRef(RxConfig::kField),          rx().toJSON(doc), allocator);
#   endif

    doc.AddMember(StringRef(CpuConfig::kField),         cpu().toJSON(doc), allocator);

#   ifdef XMRIG_FEATURE_OPENCL
    doc.AddMember(StringRef(kOcl),                      cl().toJSON(doc), allocator);
#   endif

#   ifdef XMRIG_FEATURE_CUDA
    doc.AddMember(StringRef(kCuda),                     cuda().toJSON(doc), allocator);
#   endif

    doc.AddMember(StringRef(kLogFile),                  m_logFile.toJSON(), allocator);

    m_pools.toJSON(doc, doc);

    doc.AddMember(StringRef(kPrintTime),                printTime(), allocator);
#   if defined(XMRIG_FEATURE_NVML) || defined (XMRIG_FEATURE_ADL)
    doc.AddMember(StringRef(kHealthPrintTime),          healthPrintTime(), allocator);
#   endif

#   ifdef XMRIG_FEATURE_DMI
    doc.AddMember(StringRef(kDMI),                      isDMI(), allocator);
#   endif

    doc.AddMember(StringRef(kSyslog),                   isSyslog(), allocator);

#   ifdef XMRIG_FEATURE_TLS
    doc.AddMember(StringRef(kTls),                      m_tls.toJSON(doc), allocator);
#   endif

    doc.AddMember(StringRef(DnsConfig::kField),         Dns::config().toJSON(doc), allocator);
    doc.AddMember(StringRef(kUserAgent),                m_userAgent.toJSON(), allocator);
    doc.AddMember(StringRef(kVerbose),                  Log::verbose(), allocator);
    doc.AddMember(StringRef(kWatch),                    m_watch, allocator);
    doc.AddMember(StringRef(kPauseOnBattery),           isPauseOnBattery(), allocator);
    doc.AddMember(StringRef(kPauseOnActive),            (d_ptr->idleTime == 0U || d_ptr->idleTime == kIdleTime) ? Value(isPauseOnActive()) : Value(d_ptr->idleTime), allocator);

    // peer
    {
        Value peer(kObjectType);
        peer.AddMember(StringRef(kPeerEnabled), Value(peerEnabled()), allocator);
        peer.AddMember(StringRef(kPeerBind),    StringRef(peerBind()), allocator);
        peer.AddMember(StringRef(kPeerPort),    Value(peerPort()), allocator);
        if (peerToken() != nullptr) {
            peer.AddMember(StringRef(kPeerToken), StringRef(peerToken()), allocator);
        }
        doc.AddMember(StringRef(kPeer), peer, allocator);
#   ifdef XMRIG_FEATURE_MARKET
        Value market(kObjectType);
        market.AddMember(StringRef(kMarketEnabled), Value(marketEnabled()), allocator);
        market.AddMember(StringRef(kMarketRole), StringRef(marketRole()), allocator);
        market.AddMember(StringRef(kMarketPricePerKhash), Value(marketPricePerKhash()), allocator);
        market.AddMember(StringRef(kMarketCapacityKhash), Value(marketCapacityKhash()), allocator);
        market.AddMember(StringRef(kMarketLeaseMs), Value(marketLeaseMs()), allocator);
        market.AddMember(StringRef(kMarketFeeBps), Value(marketFeeBps()), allocator);
        market.AddMember(StringRef(kMarketAuctionIntervalMs), Value(marketAuctionIntervalMs()), allocator);
        doc.AddMember(StringRef(kMarket), market, allocator);
#   endif
    }
}
