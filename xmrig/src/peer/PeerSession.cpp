#include "peer/PeerSession.h"
#include "base/net/tools/NetBuffer.h"
#include "backend/cpu/Cpu.h"
#include "crypto/common/Assembly.h"
#include "crypto/rx/RxVm.h"
#include "crypto/rx/RxCache.h"
#include "crypto/rx/RxDataset.h"
#include "crypto/randomx/randomx.h"
#include "peer/ScratchpadAllocator.h"

#include <uv.h>
#include <cstring>
#include <new>
#include <cstdlib>
#include <chrono>

#include "core/Controller.h"
#include "core/config/Config.h"

namespace xmrig::peer {

namespace {
static inline void be_write_u64(uint8_t* out, uint64_t v) {
    for (int i = 7; i >= 0; --i) { out[i] = static_cast<uint8_t>(v & 0xFF); v >>= 8; }
}

static inline uint64_t be_to_u64(const uint8_t* p) {
    uint64_t v = 0; for (int i = 0; i < 8; ++i) { v = (v << 8) | p[i]; } return v;
}

static inline uint32_t be_to_u32(const uint8_t* p) {
    return (static_cast<uint32_t>(p[0]) << 24) | (static_cast<uint32_t>(p[1]) << 16) | (static_cast<uint32_t>(p[2]) << 8) | static_cast<uint32_t>(p[3]);
}

static inline void be_write_u32(uint8_t* out, uint32_t v) {
    out[0] = static_cast<uint8_t>((v >> 24) & 0xFF);
    out[1] = static_cast<uint8_t>((v >> 16) & 0xFF);
    out[2] = static_cast<uint8_t>((v >> 8) & 0xFF);
    out[3] = static_cast<uint8_t>(v & 0xFF);
}

static inline void be_write_u16(uint8_t* out, uint16_t v) {
    out[0] = static_cast<uint8_t>((v >> 8) & 0xFF);
    out[1] = static_cast<uint8_t>(v & 0xFF);
}

static inline void write_nonce_le(uint8_t* dst, uint64_t nonce, uint8_t nsize) {
    if (nsize == 8) {
        for (int i = 0; i < 8; ++i) { dst[i] = static_cast<uint8_t>((nonce >> (8 * i)) & 0xFF); }
    } else {
        const uint32_t n32 = static_cast<uint32_t>(nonce);
        for (int i = 0; i < 4; ++i) { dst[i] = static_cast<uint8_t>((n32 >> (8 * i)) & 0xFF); }
    }
}

static inline uint64_t read_le_u64(const uint8_t* p) {
    return (static_cast<uint64_t>(p[0]))
        | (static_cast<uint64_t>(p[1]) << 8)
        | (static_cast<uint64_t>(p[2]) << 16)
        | (static_cast<uint64_t>(p[3]) << 24)
        | (static_cast<uint64_t>(p[4]) << 32)
        | (static_cast<uint64_t>(p[5]) << 40)
        | (static_cast<uint64_t>(p[6]) << 48)
        | (static_cast<uint64_t>(p[7]) << 56);
}

static ScratchpadAllocator g_salloc;
}

PeerSession::PeerSession(xmrig::Miner* miner, struct uv_tcp_s* client, const std::string& token)
    : miner_(miner), token_(token), client_(client)
{
    client_->data = this;
    // Start handshake timeout timer (10s)
    timer_ = new (std::nothrow) uv_timer_t;
    if (timer_) {
        uv_timer_init(uv_default_loop(), timer_);
        timer_->data = this;
        uv_timer_start(timer_, PeerSession::onTimeout, 10000, 0);
    }
    uv_read_start(reinterpret_cast<uv_stream_t*>(client_), NetBuffer::onAlloc, PeerSession::onRead);
}

PeerSession::~PeerSession() = default;

void PeerSession::onRead(uv_stream_t* stream, ssize_t nread, const uv_buf_t* buf)
{
    auto* self = static_cast<PeerSession*>(stream->data);
    if (nread > 0) {
        self->handleRead(buf->base, static_cast<size_t>(nread));
    }
    else if (nread < 0) {
        self->close();
    }
    NetBuffer::release(buf);
}

void PeerSession::handleRead(const char* data, size_t len)
{
    rbuf_.insert(rbuf_.end(), reinterpret_cast<const uint8_t*>(data), reinterpret_cast<const uint8_t*>(data) + len);
    parseFrames();
}

bool PeerSession::parseFrames()
{
    for (;;) {
        if (rbuf_.size() < 9) {
            return true;
        }

        uint64_t l = 0; for (int i = 0; i < 8; ++i) { l = (l << 8) | rbuf_[i]; }
        // Cap frame length to ~4MB to avoid abuse
        if (l < 1 || l > ((1ULL << 22) + 1)) {
            return false;
        }

        if (rbuf_.size() < 8 + l) {
            return true; // wait more
        }

        uint8_t op = rbuf_[8];
        size_t plen = static_cast<size_t>(l - 1);
        const uint8_t* pld = plen ? (&rbuf_[9]) : nullptr;
        if (!processFrame(op, pld, plen)) {
            return false;
        }

        rbuf_.erase(rbuf_.begin(), rbuf_.begin() + 8 + static_cast<size_t>(l));
    }
}

bool PeerSession::processFrame(uint8_t opcode, const uint8_t* payload, size_t len)
{
    // CLIENT_HELLO (0x30)
    if (opcode == 0x30) {
        if (len < 8) {
            return false;
        }

        // version (2), caps (4), token_len (2), token
        uint16_t tlen = static_cast<uint16_t>((static_cast<uint16_t>(payload[6]) << 8) | payload[7]);
        if (8u + static_cast<uint32_t>(tlen) != len) {
            return false;
        }
        if (!token_.empty()) {
            std::string ctok(reinterpret_cast<const char*>(payload + 8), tlen);
            if (ctok != token_) {
                return false;
            }
        }

        // SERVER_HELLO (0x31): ver(2)=1, caps(4)=0x00000003 (lease support), lease(1)=1
        uint8_t sh[7];
        sh[0] = 0; sh[1] = 1;
        sh[2] = 0; sh[3] = 0; sh[4] = 0; sh[5] = 3;
        sh[6] = 1;
        if (!sendFrame(0x31, sh, sizeof(sh))) {
            return false;
        }

        // META_RESP (0x02): JSON with cpu_count and max_batch
        size_t cpu_count = 0;
        if (auto* info = Cpu::info()) {
            cpu_count = info->threads();
        }
        const char* maxb = ::getenv("P2PRIG_MAX_BATCH");
        unsigned mb = maxb ? static_cast<unsigned>(::strtoul(maxb, nullptr, 10)) : 0;
        char json[128];
        const int n = std::snprintf(json, sizeof(json), "{\"cpu_count\":%zu,\"max_batch\":%u}", cpu_count, mb);
        if (n > 0) {
            sendFrame(0x02 /*META_RESP*/, reinterpret_cast<const uint8_t*>(json), static_cast<size_t>(n));
        }

        helloDone_ = true;
        if (timer_) { uv_timer_stop(timer_); }
        // Start market offer timer if enabled and acting as seller
#ifdef XMRIG_FEATURE_MARKET
        if (miner_ && miner_->controller() && miner_->controller()->config()->marketEnabled()) {
            const char* role = miner_->controller()->config()->marketRole();
            if (!(role && std::strcmp(role, "buyer") == 0)) {
                leaseMsCfg_   = miner_->controller()->config()->marketLeaseMs();
                pricePerKhash_ = miner_->controller()->config()->marketPricePerKhash();
                capacityKhash_ = miner_->controller()->config()->marketCapacityKhash();
                feeBps_        = miner_->controller()->config()->marketFeeBps();
                if (!offerTimer_) {
                    offerTimer_ = new (std::nothrow) uv_timer_t;
                    if (offerTimer_) {
                        uv_timer_init(uv_default_loop(), offerTimer_);
                        offerTimer_->data = this;
                        uint64_t interval = miner_->controller()->config()->marketAuctionIntervalMs();
                        if (interval == 0) interval = 2000;
                        uv_timer_start(offerTimer_, PeerSession::onOfferTimer, interval, interval);
                    }
                }
            }
        }
#endif

 
        return true;
    }

    // JOB_SUBMIT (0x10) - parse and start compute
    if (opcode == 0x10) {
        if (!payload || len < 3 + 8) {
            return false;
        }
        if (!(payload[0] == 'X' && payload[1] == 'J')) {
            return true; // ignore unknown variant
        }
        XJTask t;
        if (!parseXJBinary(payload, len, t)) {
            return false;
        }
        if (busy_.load()) {
            uint8_t done[16];
            be_write_u64(done, t.jobId);
            be_write_u64(done + 8, 0);
            return sendFrame(0x13 /*DONE*/, done, sizeof(done));
        }
        return startXJ(t);
    }

    // SLICE_LEASE_REQ (0x40) - parse, ACK, and start compute
    if (opcode == 0x40) {
        if (!payload || len < 3 + 8 + 8) { // 'X''L' ver + slice_id + job_id
            return false;
        }
        if (!(payload[0] == 'X' && payload[1] == 'L')) {
            return true; // ignore unknown variant
        }
        XJTask t; t.xl = true;
        if (!parseXJBinary(payload, len, t)) {
            return false;
        }
        // Send ACK immediately
        sendFrame(0x41 /*SLICE_ACK*/, nullptr, 0);
        if (busy_.load()) {
            uint8_t done[16];
            be_write_u64(done, t.jobId);
            be_write_u64(done + 8, 0);
            return sendFrame(0x13 /*DONE*/, done, sizeof(done));
        }
        return startXJ(t);
    }

#ifdef XMRIG_FEATURE_MARKET
    // MARKET_BID (0x72): ver(1), desired_cap_khash(4), max_price_per_khash(4), lease_ms(4)
    if (opcode == 0x72) {
        if (!miner_ || !miner_->controller() || !miner_->controller()->config()->marketEnabled()) {
            return true;
        }
        if (!payload || len < 1 + 4 + 4 + 4) {
            return false;
        }
        size_t pos = 0; (void)payload[pos++];
        const uint32_t desiredCap = be_to_u32(payload + pos); pos += 4;
        const uint32_t maxPrice   = be_to_u32(payload + pos); pos += 4;
        const uint32_t reqLeaseMs = be_to_u32(payload + pos); pos += 4;
        const uint32_t ask = pricePerKhash_ ? pricePerKhash_ : miner_->controller()->config()->marketPricePerKhash();
        const uint32_t cap = capacityKhash_ ? capacityKhash_ : miner_->controller()->config()->marketCapacityKhash();
        const uint32_t confLease = leaseMsCfg_ ? leaseMsCfg_ : miner_->controller()->config()->marketLeaseMs();
        const uint32_t leaseMs = reqLeaseMs > 0 ? (reqLeaseMs < confLease ? reqLeaseMs : confLease) : confLease;
        const uint32_t grantCap = (desiredCap < cap ? desiredCap : cap);
        if (leaseActive_ || grantCap == 0 || leaseMs == 0 || maxPrice < ask) {
            uint8_t nack[4]; be_write_u16(nack, 1); be_write_u16(nack + 2, 0);
            sendFrame(0x74 /*MARKET_LEASE_NACK*/, nack, sizeof(nack));
            return true;
        }
        // Accept bid and start lease window
        lastLeaseId_ = lastLeaseId_ ? (lastLeaseId_ + 1) : 1;
        ackPricePerKhash_ = ask;
        ackCapacityKhash_ = grantCap;
        usedKhashAccum_ = 0; msAccum_ = 0; resultsAccum_ = 0;
        const uint64_t nowMs = static_cast<uint64_t>(std::chrono::duration_cast<std::chrono::milliseconds>(
                                 std::chrono::steady_clock::now().time_since_epoch()).count());
        leaseEndMs_ = nowMs + static_cast<uint64_t>(leaseMs);
        leaseActive_ = true;
        // ack payload: lease_id(8) price(4) cap(4) lease_ms(4) fee_bps(2)
        uint8_t ack[8 + 4 + 4 + 4 + 2];
        be_write_u64(ack, lastLeaseId_);
        be_write_u32(ack + 8, ackPricePerKhash_);
        be_write_u32(ack + 12, ackCapacityKhash_);
        be_write_u32(ack + 16, leaseMs);
        be_write_u16(ack + 20, feeBps_);
        sendFrame(0x73 /*MARKET_LEASE_ACK*/, ack, sizeof(ack));
        return true;
    }
#endif

#ifdef XMRIG_FEATURE_MARKET
    // MARKET_SETTLE_ACK (0x76): lease_id(8)
    if (opcode == 0x76) {
        if (!payload || len < 8) {
            return false;
        }
        const uint64_t ackLease = be_to_u64(payload);
        (void)ackLease; // For MVP we just accept and ignore mismatches
        return true;
    }
#endif

    // PING (0x03) -> PONG (0x04)
    if (opcode == 0x03) {
        return sendFrame(0x04, payload, len);
    }

    // JOB_ABORT (0x11) - cancel current compute if jobId matches
    if (opcode == 0x11) {
        if (!payload || len < 8) {
            return false;
        }
        uint64_t jid = be_to_u64(payload);
        if (busy_.load() && jid == xj_.jobId) {
            cancel_.store(true);
        }
        return true;
    }

    // Unknown opcodes are ignored for now
    return true;
}

bool PeerSession::sendFrame(uint8_t opcode, const uint8_t* payload, size_t len)
{
    const size_t total = 8 + 1 + len;
    char* buf = new (std::nothrow) char[total];
    if (!buf) {
        return false;
    }

    be_write_u64(reinterpret_cast<uint8_t*>(buf), static_cast<uint64_t>(1 + len));
    buf[8] = static_cast<char>(opcode);
    if (len) {
        std::memcpy(buf + 9, payload, len);
    }

    uv_write_t* req = new (std::nothrow) uv_write_t;
    if (!req) {
        delete[] buf;
        return false;
    }

    uv_buf_t uvb = uv_buf_init(buf, static_cast<unsigned int>(total));
    req->data = buf;
    const int rc = uv_write(req, reinterpret_cast<uv_stream_t*>(client_), &uvb, 1, PeerSession::onWrite);
    if (rc != 0) {
        delete[] buf;
        delete req;
        return false;
    }
    return true;
}

void PeerSession::onWrite(uv_write_t* req, int)
{
    char* buf = static_cast<char*>(req->data);
    delete[] buf;
    delete req;
}

void PeerSession::close()
{
    if (closing_) {
        return;
    }
    closing_ = true;
    if (timer_) {
        uv_timer_stop(timer_);
        uv_close(reinterpret_cast<uv_handle_t*>(timer_), nullptr);
        timer_ = nullptr;
    }
#ifdef XMRIG_FEATURE_MARKET
    if (offerTimer_) {
        uv_timer_stop(offerTimer_);
        uv_close(reinterpret_cast<uv_handle_t*>(offerTimer_), nullptr);
        offerTimer_ = nullptr;
    }
#endif
    uv_read_stop(reinterpret_cast<uv_stream_t*>(client_));
    uv_close(reinterpret_cast<uv_handle_t*>(client_), PeerSession::onClosed);
}

void PeerSession::onClosed(uv_handle_t* h)
{
    auto* self = static_cast<PeerSession*>(h->data);
    delete reinterpret_cast<uv_tcp_t*>(h);
    delete self;
}

void PeerSession::onTimeout(uv_timer_t* t)
{
    auto* self = static_cast<PeerSession*>(t->data);
    if (!self) return;
    if (!self->helloDone_) {
        self->close();
    }
}

void PeerSession::onOfferTimer(uv_timer_t* t)
{
#ifdef XMRIG_FEATURE_MARKET
    auto* self = static_cast<PeerSession*>(t->data);
    if (!self) return;
    if (!self->leaseActive_) {
        self->sendMarketOffer();
    }
#else
    (void)t;
#endif
}

void PeerSession::sendMarketOffer()
{
#ifdef XMRIG_FEATURE_MARKET
    // Build a simple OFFER: ver(1), price_per_khash(4), capacity_khash(4), lease_ms(4), fee_bps(2)
    uint32_t price = pricePerKhash_;
    uint32_t cap = capacityKhash_;
    uint32_t leaseMs = leaseMsCfg_;
    uint16_t fee = feeBps_;
    if (miner_ && miner_->controller()) {
        auto cfg = miner_->controller()->config();
        if (price == 0) price = cfg->marketPricePerKhash();
        if (cap == 0) cap = cfg->marketCapacityKhash();
        if (leaseMs == 0) leaseMs = cfg->marketLeaseMs();
        if (fee == 0) fee = cfg->marketFeeBps();
    }
    if (price == 0 || cap == 0 || leaseMs == 0) {
        return;
    }
    uint8_t pl[1 + 4 + 4 + 4 + 2];
    pl[0] = 1;
    be_write_u32(pl + 1, price);
    be_write_u32(pl + 5, cap);
    be_write_u32(pl + 9, leaseMs);
    be_write_u16(pl + 13, fee);
    sendFrame(0x71 /*MARKET_OFFER*/, pl, sizeof(pl));
#endif
}

bool PeerSession::parseXJBinary(const uint8_t* payload, size_t len, XJTask& out)
{
    if (!payload || len < 3 + 8) return false;
    const bool xl = (payload[1] == 'L');
    size_t pos = 3; // skip 'X', type, ver
    if (xl) {
        if (pos + 8 > len) return false;
        out.sliceId = be_to_u64(payload + pos); pos += 8;
    }
    if (pos + 8 > len) return false; out.jobId = be_to_u64(payload + pos); pos += 8;
    if (pos + 1 + 1 + 4 + 4 > len) return false;
    out.rx = payload[pos++] != 0;
    out.nonceSize = payload[pos++];
    out.nonceOffset = static_cast<uint16_t>(be_to_u32(payload + pos)); pos += 4;
    out.blobLen = static_cast<uint16_t>(be_to_u32(payload + pos)); pos += 4;
    if (pos + out.blobLen > len) return false;
    out.blob.assign(payload + pos, payload + pos + out.blobLen); pos += out.blobLen;
    if (pos + 8 + 4 + 32 + 8 > len) return false;
    out.nonceBegin = be_to_u64(payload + pos); pos += 8;
    out.nonceCount = be_to_u32(payload + pos); pos += 4;
    pos += 32; // skip target32 (compat)
    out.target = be_to_u64(payload + pos); pos += 8;
    out.hasSeed = false; out.height = 0;
    if (out.rx) {
        if (pos + 32 + 4 > len) return false;
        memcpy(out.seed, payload + pos, 32); pos += 32;
        out.height = be_to_u32(payload + pos); pos += 4;
        out.hasSeed = true;
    }
    if (out.nonceSize != 4 && out.nonceSize != 8) return false;
    if (out.blobLen == 0 || (static_cast<size_t>(out.nonceOffset) + out.nonceSize) > out.blobLen) return false;
    const uint32_t kMaxCount = (1u << 22);
    if (out.nonceCount == 0 || out.nonceCount > kMaxCount) out.nonceCount = kMaxCount;
    out.xl = xl;
    return true;
}

bool PeerSession::startXJ(const XJTask& t)
{
    if (closing_) return false;
    busy_.store(true);
    xj_ = t;
    xjResults_.clear();
    workDurMs_ = 0;
    work_ = new (std::nothrow) uv_work_t;
    if (!work_) { busy_.store(false); return false; }
    work_->data = this;
    return uv_queue_work(uv_default_loop(), work_, PeerSession::onWork, PeerSession::onWorkAfter) == 0;
}

void PeerSession::onWork(uv_work_t* req)
{
    auto* self = static_cast<PeerSession*>(req->data);
    if (!self) return;
    self->computeXJ();
}

void PeerSession::onWorkAfter(uv_work_t* req, int)
{
    auto* self = static_cast<PeerSession*>(req->data);
    if (!self) { delete req; return; }
    const bool wasCanceled = self->cancel_.exchange(false);
    
    if (wasCanceled) {
        // Do not send any frames for the aborted job
        self->busy_.store(false);
        delete req;
        self->work_ = nullptr;
        return;
    }
    // Send RESULT frames
    for (const auto& r : self->xjResults_) {
        uint8_t pl[8 + 8 + 32];
        be_write_u64(pl, self->xj_.jobId);
        be_write_u64(pl + 8, r.nonce);
        std::memcpy(pl + 16, r.hash, 32);
        self->sendFrame(0x12 /*RESULT*/, pl, sizeof(pl));
    }
    // Send DONE or SLICE_DONE_EXT
    if (self->xj_.xl) {
        uint8_t pl[8 + 8 + 8 + 8 + 4];
        be_write_u64(pl, self->xj_.sliceId);
        be_write_u64(pl + 8, self->xj_.jobId);
        be_write_u64(pl + 16, self->xj_.nonceBegin);
        be_write_u64(pl + 24, self->workDurMs_);
        uint32_t zero = 0; pl[32] = static_cast<uint8_t>((zero >> 24) & 0xFF); pl[33] = static_cast<uint8_t>((zero >> 16) & 0xFF); pl[34] = static_cast<uint8_t>((zero >> 8) & 0xFF); pl[35] = static_cast<uint8_t>(zero & 0xFF);
        self->sendFrame(0x43 /*SLICE_DONE_EXT*/, pl, sizeof(pl));
    } else {
        uint8_t done[16];
        be_write_u64(done, self->xj_.jobId);
        be_write_u64(done + 8, self->workDurMs_);
        self->sendFrame(0x13 /*DONE*/, done, sizeof(done));
    }
    
#ifdef XMRIG_FEATURE_MARKET
    // Accumulate usage and settle if lease expired
    if (self->leaseActive_) {
        self->msAccum_ += self->workDurMs_;
        self->resultsAccum_ += static_cast<uint32_t>(self->xjResults_.size());
        // approximate consumed hashes as nonceCount; convert to kH
        self->usedKhashAccum_ += static_cast<uint64_t>(self->xj_.nonceCount / 1000);
        const uint64_t nowMs = static_cast<uint64_t>(std::chrono::duration_cast<std::chrono::milliseconds>(
                                  std::chrono::steady_clock::now().time_since_epoch()).count());
        if (nowMs >= self->leaseEndMs_) {
            uint8_t stl[8 + 8 + 8 + 4 + 2];
            be_write_u64(stl, self->lastLeaseId_);
            be_write_u64(stl + 8, self->usedKhashAccum_);
            be_write_u64(stl + 16, self->msAccum_);
            be_write_u32(stl + 24, self->ackPricePerKhash_);
            be_write_u16(stl + 28, self->feeBps_);
            self->sendFrame(0x75 /*MARKET_SETTLE*/, stl, sizeof(stl));
            self->leaseActive_ = false;
            self->usedKhashAccum_ = 0;
            self->msAccum_ = 0;
            self->resultsAccum_ = 0;
        }
    }
#endif
    self->busy_.store(false);
    delete req;
    self->work_ = nullptr;
}

void PeerSession::computeXJ()
{
    const auto t0 = std::chrono::steady_clock::now();
    // Hybrid path: build a cache-backed dataset instance and VM; skip global Rx::init, avoid sharing miner threads.
    xmrig::RxCache cache(/*hugePages*/false, /*nodeId*/0);
    if (xj_.hasSeed) {
        xmrig::Buffer seedBuf; seedBuf.assign(xj_.seed, xj_.seed + 32);
        cache.init(seedBuf);
    }
    xmrig::RxDataset dataset(&cache);
    uint8_t* scratch = g_salloc.acquire(&dataset, RANDOMX_SCRATCHPAD_L3_MAX_SIZE);
    auto* info = Cpu::info();
    const bool softAes = info ? !info->hasAES() : true;
    xmrig::Assembly asmHint = info ? xmrig::Assembly(info->assembly()) : xmrig::Assembly(xmrig::Assembly::AUTO);
    auto vm = xmrig::RxVm::create(&dataset, scratch, softAes, asmHint, /*node*/0);
    if (!vm) {
        g_salloc.release(scratch, RANDOMX_SCRATCHPAD_L3_MAX_SIZE);
        workDurMs_ = 0;
        return;
    }

    std::vector<uint8_t> buf = xj_.blob; // working blob copy
    const uint8_t nsize = xj_.nonceSize;
    const size_t off = xj_.nonceOffset;
    const uint64_t target = xj_.target;

    uint8_t hash[32];
    for (uint64_t i = 0; i < static_cast<uint64_t>(xj_.nonceCount); ++i) {
        if (cancel_.load()) {
            break;
        }
        const uint64_t nonce = xj_.nonceBegin + i;
        write_nonce_le(buf.data() + off, nonce, nsize);
        randomx_calculate_hash(vm, buf.data(), buf.size(), hash);
        // Compare low 64 bits little-endian with target64
        const uint64_t h64 = read_le_u64(hash);
        if (h64 <= target) {
            XJResult r{}; r.nonce = nonce; std::memcpy(r.hash, hash, 32); xjResults_.push_back(r);
        }
    }

    xmrig::RxVm::destroy(vm);
    g_salloc.release(scratch, RANDOMX_SCRATCHPAD_L3_MAX_SIZE);

    const auto t1 = std::chrono::steady_clock::now();
    workDurMs_ = static_cast<uint64_t>(std::chrono::duration_cast<std::chrono::milliseconds>(t1 - t0).count());
}

} // namespace xmrig::peer
