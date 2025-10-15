/* XMRig Remote Backend (experimental) - Phase 1/2 handshake */
#include "backend/remote/RemoteBackend.h"
#include "backend/common/Hashrate.h"
#include "backend/common/Tags.h"
#include "base/io/log/Log.h"
#include "core/Controller.h"
#include "core/config/Config.h"
#include "3rdparty/rapidjson/document.h"

// POSIX networking (Linux only for now)
#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>
#include <cstring>
#include <cstdlib>
#include <string>
#include <vector>
#include <thread>
#include <atomic>
#include <mutex>
#include <fcntl.h>
#include <chrono>
#include <errno.h>
#include <memory>

#include "base/net/stratum/Job.h"
#include "net/JobResults.h"
#include "base/io/log/Tags.h"

namespace xmrig {

static const String kType = "remote";

class RemoteBackendPrivate {
public:
    explicit RemoteBackendPrivate(Controller *controller) : controller(controller) {}

    Controller *controller;
    std::shared_ptr<Hashrate> hashrate;
    String profileName;
    bool enabled = false;
    // Phase 1/2: simple env-configured connection & handshake
    int sock = -1;
    std::string host;
    int port = 0;
    std::string token;
    bool handshakeDone = false;
    // Mining state
    std::thread rxThread;
    std::atomic<bool> stopRx{false};
    std::mutex sendMtx;
    Job jobCopy;
    std::atomic<uint64_t> nextJobId{1};
    uint64_t jobId = 0;
    uint64_t nonceNext = 0;
    uint32_t batchSize = 1u<<20; // default 1M
    // Device metadata from META_RESP
    int deviceCpuCount = -1;
    uint32_t deviceMaxBatch = 0;
    std::atomic<uint64_t> lastRxMs{0};
    std::atomic<uint64_t> lastPingMs{0};

    // Multi-remote support (experimental v0)
    struct RemoteConn {
        // endpoint
        std::string host;
        int port{0};
        std::string token; // global token for now
        int weight{1};
        // connection
        int sock{-1};
        bool handshakeDone{false};
        std::thread rxThread;
        std::mutex sendMtx;
        std::atomic<bool> stop{false};
        // per-remote job state
        uint64_t jobId{0};
        uint64_t nextNonce{0};
        uint32_t effectiveBatch{0};
        uint64_t lastSubmitMs{0};
        double doneEwmaMs{0.0};
        uint32_t reconnects{0};
        uint32_t consecutiveFails{0};
        // meta
        int deviceCpuCount{-1};
        uint32_t deviceMaxBatch{0};
        std::atomic<uint64_t> lastRxMs{0};
        std::atomic<uint64_t> lastPingMs{0};
    };
    std::vector<std::unique_ptr<RemoteConn>> remotes;
    bool multi{false};
    // global nonce allocator for static weight-based splitting
    std::mutex allocMtx;
    uint64_t globalNonceNext{0};
};

RemoteBackend::RemoteBackend(Controller *controller) : d_ptr(new RemoteBackendPrivate(controller)) {}
RemoteBackend::~RemoteBackend() { delete d_ptr; }

bool RemoteBackend::isEnabled() const { return d_ptr->enabled; }

bool RemoteBackend::isEnabled(const Algorithm &) const { return d_ptr->enabled; }

bool RemoteBackend::tick(uint64_t) { return true; }

const Hashrate *RemoteBackend::hashrate() const { return d_ptr->hashrate.get(); }

const String &RemoteBackend::profileName() const { return d_ptr->profileName; }

const String &RemoteBackend::type() const { return kType; }

static bool send_all(int fd, const void *buf, size_t len) {
    const uint8_t *p = static_cast<const uint8_t*>(buf);
    size_t off = 0;
    while (off < len) {
        ssize_t w = ::write(fd, p + off, len - off);
        if (w < 0) return false;
        off += static_cast<size_t>(w);
    }
    return true;
}

static bool send_frame(int fd, uint8_t opcode, const uint8_t *payload, uint64_t plen) {
    uint64_t total = plen + 1;
    uint8_t hdr[8];
    for (int i = 7; i >= 0; --i) { hdr[i] = static_cast<uint8_t>(total & 0xFF); total >>= 8; }
    if (!send_all(fd, hdr, 8)) return false;
    if (!send_all(fd, &opcode, 1)) return false;
    if (plen) return send_all(fd, payload, static_cast<size_t>(plen));
    return true;
}

static bool read_full(int fd, void *buf, size_t len) {
    uint8_t *p = static_cast<uint8_t*>(buf);
    size_t off = 0;
    while (off < len) {
        ssize_t r = ::read(fd, p + off, len - off);
        if (r <= 0) return false;
        off += static_cast<size_t>(r);
    }
    return true;
}

static bool recv_frame(int fd, uint8_t &opcode, std::vector<uint8_t> &payload) {
    uint8_t hdr[8];
    if (!read_full(fd, hdr, 8)) return false;
    uint64_t len = 0; for (int i=0;i<8;i++){ len = (len<<8) | hdr[i]; }
    if (len < 1 || len > ((1ULL<<22)+1)) return false; // cap ~4MB
    if (!read_full(fd, &opcode, 1)) return false;
    payload.clear();
    if (len > 1) {
        payload.resize(static_cast<size_t>(len-1));
        if (!read_full(fd, payload.data(), payload.size())) return false;
    }
    return true;
}

void RemoteBackend::prepare(const Job &) {}

void RemoteBackend::printHashrate(bool) {}

void RemoteBackend::printHealth() {}

void RemoteBackend::setJob(const Job &job) {
    auto d = d_ptr;
    d->jobCopy = job;
    d->nonceNext = 0;
    // Multi-remote path
    if (!d->remotes.empty()) {
        d->globalNonceNext = 0;
        for (auto &rp : d->remotes) {
            auto r = rp.get();
            if (!r->handshakeDone || r->sock < 0) { r->jobId = 0; continue; }
            if (r->jobId != 0) {
                uint8_t abortp[8]; uint64_t x = r->jobId; for (int i=7;i>=0;--i){ abortp[i]=static_cast<uint8_t>(x&0xFF); x>>=8; }
                std::lock_guard<std::mutex> lk(r->sendMtx);
                send_frame(r->sock, 0x11 /*JOB_ABORT*/, abortp, 8);
            }
            uint32_t base = d->batchSize;
            if (const char *bs = ::getenv("P2PRIG_BATCH")) { uint32_t v = static_cast<uint32_t>(::strtoul(bs, nullptr, 10)); if (v > 0) base = v; }
            uint32_t eff = base * (r->weight > 0 ? r->weight : 1);
            if (r->deviceMaxBatch > 0 && eff > r->deviceMaxBatch) eff = r->deviceMaxBatch;
            r->effectiveBatch = eff > 0 ? eff : base;
            uint64_t start; { std::lock_guard<std::mutex> lk(d->allocMtx); start = d->globalNonceNext; d->globalNonceNext += r->effectiveBatch; }
            r->nextNonce = start;
            r->jobId = d->nextJobId.fetch_add(1);
            const bool rx = (job.algorithm().family() == Algorithm::RANDOM_X);
            const uint8_t *blob = job.blob(); size_t blen = job.size();
            const uint32_t off = static_cast<uint32_t>(job.nonceOffset());
            const uint8_t nsize = static_cast<uint8_t>(job.nonceSize());
            std::vector<uint8_t> pl; pl.reserve(2+1+8+1+4+4 + blen + 8 + 4 + 32 + 8 + (rx?32+4:0));
            pl.push_back('X'); pl.push_back('J'); pl.push_back(1);
            uint64_t jidbe = r->jobId; uint8_t tmp8[8]; for (int i=7;i>=0;--i){ tmp8[i]=static_cast<uint8_t>(jidbe & 0xFF); jidbe >>=8; }
            pl.insert(pl.end(), tmp8, tmp8+8);
            pl.push_back(rx ? 0x01 : 0x00);
            pl.push_back(nsize);
            uint32_t offbe = htonl(off); pl.insert(pl.end(), (uint8_t*)&offbe, (uint8_t*)&offbe+4);
            uint32_t blbe = htonl(static_cast<uint32_t>(blen)); pl.insert(pl.end(), (uint8_t*)&blbe, (uint8_t*)&blbe+4);
            pl.insert(pl.end(), blob, blob + blen);
            uint64_t ns = r->nextNonce; uint8_t ns8[8]; for (int i=7;i>=0;--i){ ns8[i]=static_cast<uint8_t>(ns&0xFF); ns>>=8; }
            pl.insert(pl.end(), ns8, ns8+8);
            uint32_t ncbe = htonl(r->effectiveBatch); pl.insert(pl.end(), (uint8_t*)&ncbe, (uint8_t*)&ncbe+4);
            pl.insert(pl.end(), 32, 0);
            uint64_t t64 = job.target(); uint8_t t8[8]; for (int i=7;i>=0;--i){ t8[i]=static_cast<uint8_t>(t64&0xFF); t64>>=8; }
            pl.insert(pl.end(), t8, t8+8);
            if (rx) { const auto &seed = job.seed(); pl.insert(pl.end(), seed.data(), seed.data()+32); uint32_t hbe = htonl(static_cast<uint32_t>(job.height())); pl.insert(pl.end(), (uint8_t*)&hbe, (uint8_t*)&hbe+4); }
            {
                std::lock_guard<std::mutex> lk(r->sendMtx);
                send_frame(r->sock, 0x10 /*JOB_SUBMIT*/, pl.data(), pl.size());
            }
            r->lastSubmitMs = static_cast<uint64_t>(std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now().time_since_epoch()).count());
        }
        return;
    }
    // Single-remote path
    if (!d->handshakeDone || d->sock < 0) { d->jobId = 0; return; }
    // Abort previous job on device
    if (d->jobId != 0) {
        uint8_t abortp[8]; uint64_t x = d->jobId; for (int i=7;i>=0;--i){ abortp[i]=static_cast<uint8_t>(x&0xFF); x>>=8; }
        std::lock_guard<std::mutex> lk(d->sendMtx);
        send_frame(d->sock, 0x11 /*JOB_ABORT*/, abortp, 8);
    }
    d->jobId = d->nextJobId.fetch_add(1);

    // Build and send initial JOB_SUBMIT (extended XJ)
    const bool rx = (job.algorithm().family() == Algorithm::RANDOM_X);
    const uint8_t *blob = job.blob(); size_t blen = job.size();
    const uint32_t off = static_cast<uint32_t>(job.nonceOffset());
    const uint8_t nsize = static_cast<uint8_t>(job.nonceSize());
    std::vector<uint8_t> pl; pl.reserve(2+1+8+1+4+4 + blen + 8 + 4 + 32 + 8 + (rx?32+4:0));
    pl.push_back('X'); pl.push_back('J');
    pl.push_back(1);
    uint64_t jidbe = d->jobId; uint8_t tmp8[8]; for (int i=7;i>=0;--i){ tmp8[i]=static_cast<uint8_t>(jidbe & 0xFF); jidbe >>=8; }
    pl.insert(pl.end(), tmp8, tmp8+8);
    pl.push_back(rx ? 0x01 : 0x00);
    pl.push_back(nsize);
    uint32_t offbe = htonl(off); pl.insert(pl.end(), (uint8_t*)&offbe, (uint8_t*)&offbe+4);
    uint32_t blbe = htonl(static_cast<uint32_t>(blen)); pl.insert(pl.end(), (uint8_t*)&blbe, (uint8_t*)&blbe+4);
    pl.insert(pl.end(), blob, blob + blen);
    // nonce_start
    uint64_t ns = d->nonceNext; uint8_t ns8[8]; for (int i=7;i>=0;--i){ ns8[i]=static_cast<uint8_t>(ns&0xFF); ns>>=8; }
    pl.insert(pl.end(), ns8, ns8+8);
    uint32_t ncbe = htonl(d->batchSize); pl.insert(pl.end(), (uint8_t*)&ncbe, (uint8_t*)&ncbe+4);
    // target32 (unused if target64 provided)
    pl.insert(pl.end(), 32, 0);
    // target64
    uint64_t t64 = job.target(); uint8_t t8[8]; for (int i=7;i>=0;--i){ t8[i]=static_cast<uint8_t>(t64&0xFF); t64>>=8; }
    pl.insert(pl.end(), t8, t8+8);
    if (rx) {
        const auto &seed = job.seed(); pl.insert(pl.end(), seed.data(), seed.data()+32);
        uint32_t hbe = htonl(static_cast<uint32_t>(job.height())); pl.insert(pl.end(), (uint8_t*)&hbe, (uint8_t*)&hbe+4);
    }
    {
        std::lock_guard<std::mutex> lk(d->sendMtx);
        send_frame(d->sock, 0x10 /*JOB_SUBMIT*/, pl.data(), pl.size());
    }
}

void RemoteBackend::start(IWorker *, bool) {
    auto d = d_ptr;
    if (d->enabled) return;
    // Env-only config for now
    const char *h = ::getenv("P2PRIG_HOST");
    const char *p = ::getenv("P2PRIG_PORT");
    const char *t = ::getenv("P2PRIG_TOKEN");
    const char *eps = ::getenv("P2PRIG_ENDPOINTS");

    // Multi-remote mode if endpoints provided: host:port[:weight], comma-separated
    if (eps && *eps) {
        d->profileName = String("remote");
        d->enabled = true;
        d->multi = true;
        d->remotes.clear();
        std::string s(eps);
        size_t pos = 0;
        while (pos < s.size()) {
            size_t comma = s.find(',', pos);
            std::string item = s.substr(pos, comma == std::string::npos ? std::string::npos : comma - pos);
            if (!item.empty()) {
                size_t c1 = item.find(':');
                size_t c2 = item.rfind(':');
                if (c1 != std::string::npos) {
                    std::string hh = item.substr(0, c1);
                    int pp = 0; int ww = 1;
                    try { pp = std::stoi(item.substr(c1+1, (c2==c1?std::string::npos:c2-(c1+1)))); } catch(...) { pp = 0; }
                    if (c2 != std::string::npos && c2 != c1) { try { ww = std::stoi(item.substr(c2+1)); } catch(...) { ww = 1; } }
                    if (!hh.empty() && pp > 0) {
                        auto rc = std::unique_ptr<RemoteBackendPrivate::RemoteConn>(new RemoteBackendPrivate::RemoteConn());
                        rc->host = hh; rc->port = pp; rc->weight = ww; rc->token = t ? std::string(t) : std::string();
                        d->remotes.emplace_back(std::move(rc));
                    }
                }
            }
            if (comma == std::string::npos) break; else pos = comma + 1;
        }
        if (d->remotes.empty()) { d->enabled = false; d->multi = false; return; }
        d->stopRx = false;
        d->globalNonceNext = 0;
        for (auto &rp : d->remotes) {
            auto r = rp.get();
            r->stop = false;
            r->rxThread = std::thread([d, r]() {
                int backoff = 1;
                for (;;) {
                    if (r->stop) return;
                    // Resolve and connect
                    struct addrinfo hints{}; memset(&hints, 0, sizeof(hints));
                    hints.ai_socktype = SOCK_STREAM; hints.ai_family = AF_UNSPEC;
                    struct addrinfo *res = nullptr;
                    char portbuf[16]; std::snprintf(portbuf, sizeof(portbuf), "%d", r->port);
                    int rc = ::getaddrinfo(r->host.c_str(), portbuf, &hints, &res);
                    if (rc != 0) { std::this_thread::sleep_for(std::chrono::seconds(backoff)); backoff = backoff < 30 ? (backoff * 2) : 30; continue; }
                    int fd2 = -1;
                    for (auto it = res; it; it = it->ai_next) {
                        fd2 = ::socket(it->ai_family, it->ai_socktype, it->ai_protocol);
                        if (fd2 < 0) continue;
                        if (::connect(fd2, it->ai_addr, it->ai_addrlen) == 0) break;
                        ::close(fd2); fd2 = -1;
                    }
                    ::freeaddrinfo(res);
                    if (fd2 < 0) { std::this_thread::sleep_for(std::chrono::seconds(backoff)); backoff = backoff < 30 ? (backoff * 2) : 30; continue; }
                    // HELLO
                    uint16_t ver = htons(1);
                    uint32_t caps = htonl(0x00000001u);
                    uint16_t tlen = htons(static_cast<uint16_t>(r->token.size()));
                    std::vector<uint8_t> hello; hello.reserve(2+4+2 + r->token.size());
                    hello.insert(hello.end(), reinterpret_cast<uint8_t*>(&ver), reinterpret_cast<uint8_t*>(&ver)+2);
                    hello.insert(hello.end(), reinterpret_cast<uint8_t*>(&caps), reinterpret_cast<uint8_t*>(&caps)+4);
                    hello.insert(hello.end(), reinterpret_cast<uint8_t*>(&tlen), reinterpret_cast<uint8_t*>(&tlen)+2);
                    if (!r->token.empty()) hello.insert(hello.end(), r->token.begin(), r->token.end());
                    if (!send_frame(fd2, 0x30 /*CLIENT_HELLO*/, hello.data(), hello.size())) { ::close(fd2); std::this_thread::sleep_for(std::chrono::seconds(backoff)); backoff = backoff < 30 ? (backoff * 2) : 30; continue; }
                    uint8_t hdr2[8]; ssize_t r2 = ::read(fd2, hdr2, 8);
                    if (r2 != 8) { ::close(fd2); std::this_thread::sleep_for(std::chrono::seconds(backoff)); backoff = backoff < 30 ? (backoff * 2) : 30; continue; }
                    uint64_t len2 = 0; for (int i=0;i<8;i++){ len2 = (len2<<8) | hdr2[i]; }
                    uint8_t op2 = 0; if (::read(fd2, &op2, 1) != 1) { ::close(fd2); std::this_thread::sleep_for(std::chrono::seconds(backoff)); backoff = backoff < 30 ? (backoff * 2) : 30; continue; }
                    std::vector<uint8_t> pl2; if (len2 > 1) { pl2.resize(static_cast<size_t>(len2-1)); if (::read(fd2, pl2.data(), pl2.size()) != static_cast<ssize_t>(pl2.size())) { ::close(fd2); std::this_thread::sleep_for(std::chrono::seconds(backoff)); backoff = backoff < 30 ? (backoff * 2) : 30; continue; } }
                    if (op2 != 0x31 /*SERVER_HELLO*/ || pl2.size() < 2+4+1) { ::close(fd2); std::this_thread::sleep_for(std::chrono::seconds(backoff)); backoff = backoff < 30 ? (backoff * 2) : 30; continue; }

                    // Connected
                    r->sock = fd2; r->handshakeDone = true; backoff = 1;
                    r->lastRxMs.store(static_cast<uint64_t>(
                        std::chrono::duration_cast<std::chrono::milliseconds>(
                            std::chrono::steady_clock::now().time_since_epoch()).count()));

                    // Optional META peek
                    ::fcntl(r->sock, F_SETFL, O_NONBLOCK);
                    uint8_t pop2; std::vector<uint8_t> ppl2;
                    if (recv_frame(r->sock, pop2, ppl2)) {
                        if (pop2 == 0x02 /*META_RESP*/ && !ppl2.empty()) {
                            std::string json(reinterpret_cast<const char*>(ppl2.data()), ppl2.size());
                            rapidjson::Document md; md.Parse(json.c_str());
                            if (md.IsObject()) {
                                if (md.HasMember("cpu_count") && md["cpu_count"].IsInt()) r->deviceCpuCount = md["cpu_count"].GetInt();
                                if (md.HasMember("max_batch") && md["max_batch"].IsUint()) r->deviceMaxBatch = md["max_batch"].GetUint();
                            }
                        }
                    }
                    ::fcntl(r->sock, F_SETFL, 0);

                    // Submit current job slice if any
                    if (d->jobCopy.size() > 0) {
                        const Job saved = d->jobCopy;
                        r->jobId = d->nextJobId.fetch_add(1);
                        const bool rx = (saved.algorithm().family() == Algorithm::RANDOM_X);
                        const uint8_t *blob = saved.blob(); size_t blen = saved.size();
                        const uint32_t off = static_cast<uint32_t>(saved.nonceOffset());
                        const uint8_t nsize = static_cast<uint8_t>(saved.nonceSize());
                        uint32_t base = d->batchSize; if (const char *bs = ::getenv("P2PRIG_BATCH")) { uint32_t v = static_cast<uint32_t>(::strtoul(bs, nullptr, 10)); if (v > 0) base = v; }
                        uint32_t eff = base * (r->weight > 0 ? r->weight : 1);
                        if (r->deviceMaxBatch > 0 && eff > r->deviceMaxBatch) eff = r->deviceMaxBatch;
                        r->effectiveBatch = eff > 0 ? eff : base;
                        uint64_t start; { std::lock_guard<std::mutex> lk(d->allocMtx); start = d->globalNonceNext; d->globalNonceNext += r->effectiveBatch; }
                        r->nextNonce = start;
                        std::vector<uint8_t> pl; pl.reserve(2+1+8+1+4+4 + blen + 8 + 4 + 32 + 8 + (rx?32+4:0));
                        pl.push_back('X'); pl.push_back('J'); pl.push_back(1);
                        uint64_t jidbe = r->jobId; uint8_t tmp8[8]; for (int i=7;i>=0;--i){ tmp8[i]=static_cast<uint8_t>(jidbe & 0xFF); jidbe >>=8; }
                        pl.insert(pl.end(), tmp8, tmp8+8);
                        pl.push_back(rx ? 0x01 : 0x00);
                        pl.push_back(nsize);
                        uint32_t offbe = htonl(off); pl.insert(pl.end(), (uint8_t*)&offbe, (uint8_t*)&offbe+4);
                        uint32_t blbe = htonl(static_cast<uint32_t>(blen)); pl.insert(pl.end(), (uint8_t*)&blbe, (uint8_t*)&blbe+4);
                        pl.insert(pl.end(), blob, blob + blen);
                        uint64_t ns = r->nextNonce; uint8_t ns8[8]; for (int i=7;i>=0;--i){ ns8[i]=static_cast<uint8_t>(ns&0xFF); ns>>=8; }
                        pl.insert(pl.end(), ns8, ns8+8);
                        uint32_t ncbe = htonl(r->effectiveBatch); pl.insert(pl.end(), (uint8_t*)&ncbe, (uint8_t*)&ncbe+4);
                        pl.insert(pl.end(), 32, 0);
                        uint64_t t64 = saved.target(); uint8_t t8[8]; for (int i=7;i>=0;--i){ t8[i]=static_cast<uint8_t>(t64&0xFF); t64>>=8; }
                        pl.insert(pl.end(), t8, t8+8);
                        if (rx) { const auto &seed = saved.seed(); pl.insert(pl.end(), seed.data(), seed.data()+32); uint32_t hbe = htonl(static_cast<uint32_t>(saved.height())); pl.insert(pl.end(), (uint8_t*)&hbe, (uint8_t*)&hbe+4); }
                        {
                            std::lock_guard<std::mutex> lk(r->sendMtx);
                            send_frame(r->sock, 0x10 /*JOB_SUBMIT*/, pl.data(), pl.size());
                        }
                        r->lastSubmitMs = static_cast<uint64_t>(std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now().time_since_epoch()).count());
                    }

                    // Per-remote read loop
                    for (;;) {
                        if (r->stop) { if (r->sock>=0) { ::close(r->sock); r->sock=-1; } return; }
                        uint8_t op; std::vector<uint8_t> pay;
                        if (!recv_frame(r->sock, op, pay)) { if (r->sock>=0) { ::close(r->sock); r->sock=-1; } r->handshakeDone=false; break; }
                        r->lastRxMs.store(static_cast<uint64_t>(
                            std::chrono::duration_cast<std::chrono::milliseconds>(
                                std::chrono::steady_clock::now().time_since_epoch()).count()));
                        if (op == 0x12 /*RESULT*/) {
                            if (pay.size() >= 8+8+32) {
                                uint64_t jid = 0; for (int i=0;i<8;i++) jid = (jid<<8) | pay[i];
                                uint64_t nbe = 0; for (int i=0;i<8;i++) nbe = (nbe<<8) | pay[8+i];
                                uint32_t nonce = static_cast<uint32_t>(nbe);
                                if (jid == r->jobId) { JobResults::submit(d->jobCopy, nonce, pay.data()+16); }
                            }
                        } else if (op == 0x13 /*DONE*/) {
                            if (pay.size() >= 8+8) {
                                uint64_t jid = 0; for (int i=0;i<8;i++) jid = (jid<<8) | pay[i];
                                if (jid == r->jobId) {
                                    uint64_t nowMs = static_cast<uint64_t>(
                                        std::chrono::duration_cast<std::chrono::milliseconds>(
                                            std::chrono::steady_clock::now().time_since_epoch()).count());
                                    uint64_t dtMs = (r->lastSubmitMs > 0 && nowMs > r->lastSubmitMs) ? (nowMs - r->lastSubmitMs) : 0;
                                    if (dtMs > 0) {
                                        const char *tgtEnv = ::getenv("P2PRIG_TUNE_TARGET_MS");
                                        const char *pctEnv = ::getenv("P2PRIG_TUNE_STEP_PCT");
                                        double target = tgtEnv ? static_cast<double>(::strtoul(tgtEnv, nullptr, 10)) : 800.0;
                                        double stepPct = pctEnv ? static_cast<double>(::strtoul(pctEnv, nullptr, 10)) : 10.0;
                                        double alpha = 0.2;
                                        double dt = static_cast<double>(dtMs);
                                        r->doneEwmaMs = (r->doneEwmaMs <= 0.0) ? dt : (alpha * dt + (1.0 - alpha) * r->doneEwmaMs);
                                        double lo = 0.9 * target;
                                        double hi = 1.1 * target;
                                        uint64_t newBatch = r->effectiveBatch;
                                        if (r->doneEwmaMs < lo) {
                                            newBatch = static_cast<uint64_t>(static_cast<double>(r->effectiveBatch) * (1.0 + (stepPct / 100.0)));
                                        } else if (r->doneEwmaMs > hi) {
                                            newBatch = static_cast<uint64_t>(static_cast<double>(r->effectiveBatch) * (1.0 - (stepPct / 100.0)));
                                        }
                                        if (newBatch < 1) newBatch = 1;
                                        if (r->deviceMaxBatch > 0 && newBatch > r->deviceMaxBatch) newBatch = r->deviceMaxBatch;
                                        r->effectiveBatch = static_cast<uint32_t>(newBatch);
                                    }
                                    uint64_t start;
                                    { std::lock_guard<std::mutex> lk(d->allocMtx); start = d->globalNonceNext; d->globalNonceNext += r->effectiveBatch; }
                                    r->nextNonce = start;
                                    const Job &job = d->jobCopy; const bool rx = (job.algorithm().family() == Algorithm::RANDOM_X);
                                    const uint8_t *blob = job.blob(); size_t blen = job.size();
                                    const uint32_t off = static_cast<uint32_t>(job.nonceOffset());
                                    const uint8_t nsize = static_cast<uint8_t>(job.nonceSize());
                                    std::vector<uint8_t> pl2; pl2.reserve(2+1+8+1+4+4 + blen + 8 + 4 + 32 + 8 + (rx?32+4:0));
                                    pl2.push_back('X'); pl2.push_back('J'); pl2.push_back(1);
                                    uint64_t jidbe = r->jobId; uint8_t tmp8[8]; for (int i=7;i>=0;--i){ tmp8[i]=static_cast<uint8_t>(jidbe & 0xFF); jidbe >>=8; }
                                    pl2.insert(pl2.end(), tmp8, tmp8+8);
                                    pl2.push_back(rx ? 0x01 : 0x00);
                                    pl2.push_back(nsize);
                                    uint32_t offbe = htonl(off); pl2.insert(pl2.end(), (uint8_t*)&offbe, (uint8_t*)&offbe+4);
                                    uint32_t blbe = htonl(static_cast<uint32_t>(blen)); pl2.insert(pl2.end(), (uint8_t*)&blbe, (uint8_t*)&blbe+4);
                                    pl2.insert(pl2.end(), blob, blob + blen);
                                    uint64_t ns = r->nextNonce; uint8_t ns8[8]; for (int i=7;i>=0;--i){ ns8[i]=static_cast<uint8_t>(ns&0xFF); ns>>=8; }
                                    pl2.insert(pl2.end(), ns8, ns8+8);
                                    uint32_t ncbe = htonl(r->effectiveBatch); pl2.insert(pl2.end(), (uint8_t*)&ncbe, (uint8_t*)&ncbe+4);
                                    pl2.insert(pl2.end(), 32, 0);
                                    uint64_t t64 = job.target(); uint8_t t8[8]; for (int i=7;i>=0;--i){ t8[i]=static_cast<uint8_t>(t64&0xFF); t64>>=8; }
                                    pl2.insert(pl2.end(), t8, t8+8);
                                    if (rx) { const auto &seed = job.seed(); pl2.insert(pl2.end(), seed.data(), seed.data()+32); uint32_t hbe = htonl(static_cast<uint32_t>(job.height())); pl2.insert(pl2.end(), (uint8_t*)&hbe, (uint8_t*)&hbe+4); }
                                    std::lock_guard<std::mutex> lk(r->sendMtx);
                                    send_frame(r->sock, 0x10 /*JOB_SUBMIT*/, pl2.data(), pl2.size());
                                    r->lastSubmitMs = nowMs;
                                }
                            }
                        } else if (op == 0x20 /*PING*/) {
                            r->lastPingMs.store(static_cast<uint64_t>(
                                std::chrono::duration_cast<std::chrono::milliseconds>(
                                    std::chrono::steady_clock::now().time_since_epoch()).count()));
                            std::lock_guard<std::mutex> lk(r->sendMtx);
                            send_frame(r->sock, 0x21 /*PONG*/, nullptr, 0);
                        } else {
                            // ignore other frames
                        }
                    }
                    // reconnect with backoff
                    std::this_thread::sleep_for(std::chrono::seconds(backoff));
                    backoff = backoff < 30 ? (backoff * 2) : 30;
                }
            });
        }
        return;
    }

    if (!h || !p) {
        // remote disabled if host/port not provided
        return;
    }
    d->host = h;
    d->port = std::atoi(p);
    if (t) d->token = t;
    d->profileName = String("remote");
    d->enabled = true;
    d->handshakeDone = false;
    d->sock = -1;

    // Start reader thread
    d->stopRx = false;
    d->rxThread = std::thread([d]() {
        // Initial connect with backoff if not connected yet
        if (!d->handshakeDone || d->sock < 0) {
            int backoff = 1;
            while (!d->stopRx && (!d->handshakeDone || d->sock < 0)) {
                struct addrinfo hints{}; memset(&hints, 0, sizeof(hints));
                hints.ai_socktype = SOCK_STREAM; hints.ai_family = AF_UNSPEC;
                struct addrinfo *res = nullptr;
                char portbuf[16]; std::snprintf(portbuf, sizeof(portbuf), "%d", d->port);
                int rc = ::getaddrinfo(d->host.c_str(), portbuf, &hints, &res);
                if (rc != 0) {
                    LOG_ERR("remote: resolve %s:%d failed: %s", d->host.c_str(), d->port, gai_strerror(rc));
                    std::this_thread::sleep_for(std::chrono::seconds(backoff));
                    backoff = backoff < 30 ? (backoff * 2) : 30;
                    continue;
                }
                int fd2 = -1;
                for (auto it = res; it; it = it->ai_next) {
                    fd2 = ::socket(it->ai_family, it->ai_socktype, it->ai_protocol);
                    if (fd2 < 0) continue;
                    if (::connect(fd2, it->ai_addr, it->ai_addrlen) == 0) break;
                    ::close(fd2); fd2 = -1;
                }
                ::freeaddrinfo(res);
                if (fd2 < 0) {
                    LOG_ERR("remote: connect %s:%d failed: %s", d->host.c_str(), d->port, strerror(errno));
                    std::this_thread::sleep_for(std::chrono::seconds(backoff));
                    backoff = backoff < 30 ? (backoff * 2) : 30;
                    continue;
                }
                uint16_t ver = htons(1);
                uint32_t caps = htonl(0x00000001u);
                uint16_t tlen = htons(static_cast<uint16_t>(d->token.size()));
                std::vector<uint8_t> hello; hello.reserve(2+4+2 + d->token.size());
                hello.insert(hello.end(), reinterpret_cast<uint8_t*>(&ver), reinterpret_cast<uint8_t*>(&ver)+2);
                hello.insert(hello.end(), reinterpret_cast<uint8_t*>(&caps), reinterpret_cast<uint8_t*>(&caps)+4);
                hello.insert(hello.end(), reinterpret_cast<uint8_t*>(&tlen), reinterpret_cast<uint8_t*>(&tlen)+2);
                if (!d->token.empty()) hello.insert(hello.end(), d->token.begin(), d->token.end());
                if (!send_frame(fd2, 0x30 /*CLIENT_HELLO*/, hello.data(), hello.size())) {
                    LOG_ERR("remote: send CLIENT_HELLO failed: %s", strerror(errno));
                    ::close(fd2);
                    std::this_thread::sleep_for(std::chrono::seconds(backoff));
                    backoff = backoff < 30 ? (backoff * 2) : 30;
                    continue;
                }
                uint8_t hdr2[8]; ssize_t r2 = ::read(fd2, hdr2, 8);
                if (r2 != 8) { ::close(fd2); std::this_thread::sleep_for(std::chrono::seconds(backoff)); backoff = backoff < 30 ? (backoff * 2) : 30; continue; }
                uint64_t len2 = 0; for (int i=0;i<8;i++){ len2 = (len2<<8) | hdr2[i]; }
                uint8_t op2 = 0; if (::read(fd2, &op2, 1) != 1) { ::close(fd2); std::this_thread::sleep_for(std::chrono::seconds(backoff)); backoff = backoff < 30 ? (backoff * 2) : 30; continue; }
                std::vector<uint8_t> pl2;
                if (len2 > 1) {
                    pl2.resize(static_cast<size_t>(len2-1));
                    if (::read(fd2, pl2.data(), pl2.size()) != static_cast<ssize_t>(pl2.size())) { ::close(fd2); std::this_thread::sleep_for(std::chrono::seconds(backoff)); backoff = backoff < 30 ? (backoff * 2) : 30; continue; }
                }
                if (op2 == 0x7F /*ERROR*/ || op2 != 0x31 /*SERVER_HELLO*/ || pl2.size() < 2+4+1) {
                    ::close(fd2);
                    std::this_thread::sleep_for(std::chrono::seconds(backoff));
                    backoff = backoff < 30 ? (backoff * 2) : 30;
                    continue;
                }
                d->sock = fd2;
                d->handshakeDone = true;
                LOG_INFO("%s remote connected to %s:%d", Tags::miner(), d->host.c_str(), d->port);
                d->lastRxMs.store(static_cast<uint64_t>(
                    std::chrono::duration_cast<std::chrono::milliseconds>(
                        std::chrono::steady_clock::now().time_since_epoch()).count()));
                // Optional META peek
                ::fcntl(d->sock, F_SETFL, O_NONBLOCK);
                uint8_t pop2; std::vector<uint8_t> ppl2;
                if (recv_frame(d->sock, pop2, ppl2)) {
                    if (pop2 == 0x02 /*META_RESP*/ && !ppl2.empty()) {
                        std::string json(reinterpret_cast<const char*>(ppl2.data()), ppl2.size());
                        rapidjson::Document md; md.Parse(json.c_str());
                        if (md.IsObject()) {
                            if (md.HasMember("cpu_count") && md["cpu_count"].IsInt()) d->deviceCpuCount = md["cpu_count"].GetInt();
                            if (md.HasMember("max_batch") && md["max_batch"].IsUint()) {
                                d->deviceMaxBatch = md["max_batch"].GetUint();
                                if (d->deviceMaxBatch > 0) d->batchSize = d->deviceMaxBatch;
                            }
                        }
                    }
                }
                ::fcntl(d->sock, F_SETFL, 0);
                if (const char *bs = ::getenv("P2PRIG_BATCH")) {
                    uint32_t v = static_cast<uint32_t>(::strtoul(bs, nullptr, 10));
                    if (v > 0) d->batchSize = v;
                }
                if (d->deviceCpuCount >= 0 || d->deviceMaxBatch > 0) {
                    LOG_INFO("%s remote device: %s:%d cpu=%d max_batch=%u batch=%u", Tags::miner(), d->host.c_str(), d->port,
                             d->deviceCpuCount, d->deviceMaxBatch, d->batchSize);
                } else {
                    LOG_INFO("%s remote device: %s:%d (details pending)", Tags::miner(), d->host.c_str(), d->port);
                }
                // Resubmit saved job if any
                if (d->jobCopy.size() > 0) {
                    const Job saved = d->jobCopy;
                    d->nonceNext = 0;
                    const bool rx = (saved.algorithm().family() == Algorithm::RANDOM_X);
                    d->jobId = d->nextJobId.fetch_add(1);
                    const uint8_t *blob = saved.blob(); size_t blen = saved.size();
                    const uint32_t off = static_cast<uint32_t>(saved.nonceOffset());
                    const uint8_t nsize = static_cast<uint8_t>(saved.nonceSize());
                    std::vector<uint8_t> pl; pl.reserve(2+1+8+1+4+4 + blen + 8 + 4 + 32 + 8 + (rx?32+4:0));
                    pl.push_back('X'); pl.push_back('J'); pl.push_back(1);
                    uint64_t jidbe = d->jobId; uint8_t tmp8[8]; for (int i=7;i>=0;--i){ tmp8[i]=static_cast<uint8_t>(jidbe & 0xFF); jidbe >>=8; }
                    pl.insert(pl.end(), tmp8, tmp8+8);
                    pl.push_back(rx ? 0x01 : 0x00);
                    pl.push_back(nsize);
                    uint32_t offbe = htonl(off); pl.insert(pl.end(), (uint8_t*)&offbe, (uint8_t*)&offbe+4);
                    uint32_t blbe = htonl(static_cast<uint32_t>(blen)); pl.insert(pl.end(), (uint8_t*)&blbe, (uint8_t*)&blbe+4);
                    pl.insert(pl.end(), blob, blob + blen);
                    uint64_t ns = d->nonceNext; uint8_t ns8[8]; for (int i=7;i>=0;--i){ ns8[i]=static_cast<uint8_t>(ns&0xFF); ns>>=8; }
                    pl.insert(pl.end(), ns8, ns8+8);
                    uint32_t ncbe = htonl(d->batchSize); pl.insert(pl.end(), (uint8_t*)&ncbe, (uint8_t*)&ncbe+4);
                    pl.insert(pl.end(), 32, 0);
                    uint64_t t64 = saved.target(); uint8_t t8[8]; for (int i=7;i>=0;--i){ t8[i]=static_cast<uint8_t>(t64&0xFF); t64>>=8; }
                    pl.insert(pl.end(), t8, t8+8);
                    if (rx) { const auto &seed = saved.seed(); pl.insert(pl.end(), seed.data(), seed.data()+32); uint32_t hbe = htonl(static_cast<uint32_t>(saved.height())); pl.insert(pl.end(), (uint8_t*)&hbe, (uint8_t*)&hbe+4); }
                    {
                        std::lock_guard<std::mutex> lk(d->sendMtx);
                        send_frame(d->sock, 0x10 /*JOB_SUBMIT*/, pl.data(), pl.size());
                    }
                }
                backoff = 1;
            }
        }
        for (;;) {
            if (d->stopRx) break;
            uint8_t op; std::vector<uint8_t> pay;
            if (!recv_frame(d->sock, op, pay)) {
                LOG_ERR("%s remote connection lost: %s:%d (%s)", Tags::miner(), d->host.c_str(), d->port, strerror(errno));
                if (d->sock >= 0) { ::close(d->sock); d->sock = -1; }
                d->handshakeDone = false;
                // Reconnect with backoff
                int backoff = 1;
                while (!d->stopRx) {
                    // Resolve
                    struct addrinfo hints{}; memset(&hints, 0, sizeof(hints));
                    hints.ai_socktype = SOCK_STREAM; hints.ai_family = AF_UNSPEC;
                    struct addrinfo *res = nullptr;
                    char portbuf[16]; std::snprintf(portbuf, sizeof(portbuf), "%d", d->port);
                    int rc = ::getaddrinfo(d->host.c_str(), portbuf, &hints, &res);
                    if (rc != 0) {
                        LOG_ERR("remote: resolve %s:%d failed: %s", d->host.c_str(), d->port, gai_strerror(rc));
                        goto sleep_and_retry;
                    }
                    // Connect
                    int fd2 = -1;
                    for (auto it = res; it; it = it->ai_next) {
                        fd2 = ::socket(it->ai_family, it->ai_socktype, it->ai_protocol);
                        if (fd2 < 0) continue;
                        if (::connect(fd2, it->ai_addr, it->ai_addrlen) == 0) break;
                        ::close(fd2); fd2 = -1;
                    }
                    ::freeaddrinfo(res);
                    if (fd2 < 0) {
                        LOG_ERR("remote: connect %s:%d failed: %s", d->host.c_str(), d->port, strerror(errno));
                        goto sleep_and_retry;
                    }
                    // HELLO
                    uint16_t ver = htons(1);
                    uint32_t caps = htonl(0x00000001u);
                    uint16_t tlen = htons(static_cast<uint16_t>(d->token.size()));
                    std::vector<uint8_t> hello; hello.reserve(2+4+2 + d->token.size());
                    hello.insert(hello.end(), reinterpret_cast<uint8_t*>(&ver), reinterpret_cast<uint8_t*>(&ver)+2);
                    hello.insert(hello.end(), reinterpret_cast<uint8_t*>(&caps), reinterpret_cast<uint8_t*>(&caps)+4);
                    hello.insert(hello.end(), reinterpret_cast<uint8_t*>(&tlen), reinterpret_cast<uint8_t*>(&tlen)+2);
                    if (!d->token.empty()) hello.insert(hello.end(), d->token.begin(), d->token.end());
                    if (!send_frame(fd2, 0x30 /*CLIENT_HELLO*/, hello.data(), hello.size())) {
                        LOG_ERR("remote: send CLIENT_HELLO failed: %s", strerror(errno));
                        ::close(fd2);
                        goto sleep_and_retry;
                    }
                    // Read SERVER_HELLO
                    uint8_t hdr2[8]; ssize_t r2 = ::read(fd2, hdr2, 8);
                    if (r2 != 8) { ::close(fd2); goto sleep_and_retry; }
                    uint64_t len2 = 0; for (int i=0;i<8;i++){ len2 = (len2<<8) | hdr2[i]; }
                    uint8_t op2 = 0; if (::read(fd2, &op2, 1) != 1) { ::close(fd2); goto sleep_and_retry; }
                    std::vector<uint8_t> pl2;
                    if (len2 > 1) {
                        pl2.resize(static_cast<size_t>(len2-1));
                        if (::read(fd2, pl2.data(), pl2.size()) != static_cast<ssize_t>(pl2.size())) { ::close(fd2); goto sleep_and_retry; }
                    }
                    if (op2 == 0x7F /*ERROR*/ || op2 != 0x31 /*SERVER_HELLO*/ || pl2.size() < 2+4+1) {
                        ::close(fd2);
                        goto sleep_and_retry;
                    }
                    d->sock = fd2;
                    d->handshakeDone = true;
                    LOG_INFO("%s remote reconnected to %s:%d", Tags::miner(), d->host.c_str(), d->port);
                    d->lastRxMs.store(static_cast<uint64_t>(
                        std::chrono::duration_cast<std::chrono::milliseconds>(
                            std::chrono::steady_clock::now().time_since_epoch()).count()));
                    // Non-blocking quick META peek
                    ::fcntl(d->sock, F_SETFL, O_NONBLOCK);
                    uint8_t pop2; std::vector<uint8_t> ppl2;
                    if (recv_frame(d->sock, pop2, ppl2)) {
                        if (pop2 == 0x02 /*META_RESP*/ && !ppl2.empty()) {
                            std::string json(reinterpret_cast<const char*>(ppl2.data()), ppl2.size());
                            rapidjson::Document md; md.Parse(json.c_str());
                            if (md.IsObject()) {
                                if (md.HasMember("cpu_count") && md["cpu_count"].IsInt()) d->deviceCpuCount = md["cpu_count"].GetInt();
                                if (md.HasMember("max_batch") && md["max_batch"].IsUint()) {
                                    d->deviceMaxBatch = md["max_batch"].GetUint();
                                    if (d->deviceMaxBatch > 0) d->batchSize = d->deviceMaxBatch;
                                }
                            }
                        }
                    }
                    ::fcntl(d->sock, F_SETFL, 0);
                    if (const char *bs = ::getenv("P2PRIG_BATCH")) {
                        uint32_t v = static_cast<uint32_t>(::strtoul(bs, nullptr, 10));
                        if (v > 0) d->batchSize = v;
                    }
                    if (d->deviceCpuCount >= 0 || d->deviceMaxBatch > 0) {
                        LOG_INFO("%s remote device: %s:%d cpu=%d max_batch=%u batch=%u", Tags::miner(), d->host.c_str(), d->port,
                                 d->deviceCpuCount, d->deviceMaxBatch, d->batchSize);
                    } else {
                        LOG_INFO("%s remote device: %s:%d (details pending)", Tags::miner(), d->host.c_str(), d->port);
                    }
                    // Resubmit latest job if available
                    if (d->jobCopy.size() > 0) {
                        const Job saved = d->jobCopy;
                        // setJob will abort previous if any and send new
                        // Note: setJob checks handshakeDone and sock
                        // so it's safe to call here
                        d->nonceNext = 0;
                        // simulate setJob flow inline to avoid locking issues
                        const bool rx = (saved.algorithm().family() == Algorithm::RANDOM_X);
                        d->jobId = d->nextJobId.fetch_add(1);
                        const uint8_t *blob = saved.blob(); size_t blen = saved.size();
                        const uint32_t off = static_cast<uint32_t>(saved.nonceOffset());
                        const uint8_t nsize = static_cast<uint8_t>(saved.nonceSize());
                        std::vector<uint8_t> pl; pl.reserve(2+1+8+1+4+4 + blen + 8 + 4 + 32 + 8 + (rx?32+4:0));
                        pl.push_back('X'); pl.push_back('J'); pl.push_back(1);
                        uint64_t jidbe = d->jobId; uint8_t tmp8[8]; for (int i=7;i>=0;--i){ tmp8[i]=static_cast<uint8_t>(jidbe & 0xFF); jidbe >>=8; }
                        pl.insert(pl.end(), tmp8, tmp8+8);
                        pl.push_back(rx ? 0x01 : 0x00);
                        pl.push_back(nsize);
                        uint32_t offbe = htonl(off); pl.insert(pl.end(), (uint8_t*)&offbe, (uint8_t*)&offbe+4);
                        uint32_t blbe = htonl(static_cast<uint32_t>(blen)); pl.insert(pl.end(), (uint8_t*)&blbe, (uint8_t*)&blbe+4);
                        pl.insert(pl.end(), blob, blob + blen);
                        uint64_t ns = d->nonceNext; uint8_t ns8[8]; for (int i=7;i>=0;--i){ ns8[i]=static_cast<uint8_t>(ns&0xFF); ns>>=8; }
                        pl.insert(pl.end(), ns8, ns8+8);
                        uint32_t ncbe = htonl(d->batchSize); pl.insert(pl.end(), (uint8_t*)&ncbe, (uint8_t*)&ncbe+4);
                        pl.insert(pl.end(), 32, 0);
                        uint64_t t64 = saved.target(); uint8_t t8[8]; for (int i=7;i>=0;--i){ t8[i]=static_cast<uint8_t>(t64&0xFF); t64>>=8; }
                        pl.insert(pl.end(), t8, t8+8);
                        if (rx) { const auto &seed = saved.seed(); pl.insert(pl.end(), seed.data(), seed.data()+32); uint32_t hbe = htonl(static_cast<uint32_t>(saved.height())); pl.insert(pl.end(), (uint8_t*)&hbe, (uint8_t*)&hbe+4); }
                        {
                            std::lock_guard<std::mutex> lk(d->sendMtx);
                            send_frame(d->sock, 0x10 /*JOB_SUBMIT*/, pl.data(), pl.size());
                        }
                    }
                    // reset backoff
                    backoff = 1;
                    break; // re-enter read loop

                sleep_and_retry:
                    std::this_thread::sleep_for(std::chrono::seconds(backoff));
                    backoff = backoff < 30 ? (backoff * 2) : 30;
                    if (res) { ::freeaddrinfo(res); res = nullptr; }
                }
                if (d->stopRx) break; // stop requested
                continue;
            }
            d->lastRxMs.store(static_cast<uint64_t>(
                std::chrono::duration_cast<std::chrono::milliseconds>(
                    std::chrono::steady_clock::now().time_since_epoch()).count()));
            if (op == 0x12 /*RESULT*/) {
                if (pay.size() >= 8+8+32) {
                    uint64_t jid = 0; for (int i=0;i<8;i++) jid = (jid<<8) | pay[i];
                    uint64_t nbe = 0; for (int i=0;i<8;i++) nbe = (nbe<<8) | pay[8+i];
                    uint32_t nonce = static_cast<uint32_t>(nbe);
                    if (jid == d->jobId) {
                        JobResults::submit(d->jobCopy, nonce, pay.data()+16);
                    }
                }
            } else if (op == 0x13 /*DONE*/) {
                if (pay.size() >= 8+8) {
                    uint64_t jid = 0; for (int i=0;i<8;i++) jid = (jid<<8) | pay[i];
                    uint64_t processed = 0; for (int i=0;i<8;i++) processed = (processed<<8) | pay[8+i];
                    (void)processed;
                    if (jid == d->jobId) {
                        // Submit next batch automatically
                        // Reuse current job and increment nonceNext
                        // Build and send XJ frame
                        const Job &job = d->jobCopy;
                        const bool rx = (job.algorithm().family() == Algorithm::RANDOM_X);
                        const uint8_t *blob = job.blob(); size_t blen = job.size();
                        const uint32_t off = static_cast<uint32_t>(job.nonceOffset());
                        const uint8_t nsize = static_cast<uint8_t>(job.nonceSize());
                        std::vector<uint8_t> pl2; pl2.reserve(2+1+8+1+4+4 + blen + 8 + 4 + 32 + 8 + (rx?32+4:0));
                        pl2.push_back('X'); pl2.push_back('J');
                        pl2.push_back(1);
                        uint64_t jidbe = d->jobId; uint8_t tmp8[8];
                        for (int i=7;i>=0;--i){ tmp8[i]=static_cast<uint8_t>(jidbe & 0xFF); jidbe >>=8; }
                        pl2.insert(pl2.end(), tmp8, tmp8+8);
                        pl2.push_back(rx ? 0x01 : 0x00);
                        pl2.push_back(nsize);
                        uint32_t offbe = htonl(off); pl2.insert(pl2.end(), (uint8_t*)&offbe, (uint8_t*)&offbe+4);
                        uint32_t blbe = htonl(static_cast<uint32_t>(blen)); pl2.insert(pl2.end(), (uint8_t*)&blbe, (uint8_t*)&blbe+4);
                        pl2.insert(pl2.end(), blob, blob + blen);
                        // nonce_start
                        d->nonceNext += d->batchSize;
                        uint64_t ns = d->nonceNext; uint8_t ns8[8]; for (int i=7;i>=0;--i){ ns8[i]=static_cast<uint8_t>(ns&0xFF); ns>>=8; }
                        pl2.insert(pl2.end(), ns8, ns8+8);
                        uint32_t ncbe = htonl(d->batchSize); pl2.insert(pl2.end(), (uint8_t*)&ncbe, (uint8_t*)&ncbe+4);
                        // target32 (unused if target64 provided)
                        pl2.insert(pl2.end(), 32, 0);
                        // target64
                        uint64_t t64 = job.target(); uint8_t t8[8]; for (int i=7;i>=0;--i){ t8[i]=static_cast<uint8_t>(t64&0xFF); t64>>=8; }
                        pl2.insert(pl2.end(), t8, t8+8);
                        if (rx) {
                            const auto &seed = job.seed(); pl2.insert(pl2.end(), seed.data(), seed.data()+32);
                            uint32_t hbe = htonl(static_cast<uint32_t>(job.height())); pl2.insert(pl2.end(), (uint8_t*)&hbe, (uint8_t*)&hbe+4);
                        }
                        std::lock_guard<std::mutex> lk(d->sendMtx);
                        send_frame(d->sock, 0x10 /*JOB_SUBMIT*/, pl2.data(), pl2.size());
                    }
                }
            } else if (op == 0x20 /*PING*/) {
                d->lastPingMs.store(static_cast<uint64_t>(
                    std::chrono::duration_cast<std::chrono::milliseconds>(
                        std::chrono::steady_clock::now().time_since_epoch()).count()));
                std::lock_guard<std::mutex> lk(d->sendMtx);
                send_frame(d->sock, 0x21 /*PONG*/, nullptr, 0);
            } else {
                // ignore other frames
            }
        }
    });
}

void RemoteBackend::stop() {
    auto d = d_ptr;
    d->stopRx = true;
    if (d->rxThread.joinable()) d->rxThread.join();
    if (d->sock >= 0) { ::close(d->sock); d->sock = -1; }
    // Multi-remote cleanup
    for (auto &rp : d->remotes) {
        auto r = rp.get();
        r->stop = true;
        if (r->sock >= 0) { ::close(r->sock); r->sock = -1; }
        if (r->rxThread.joinable()) r->rxThread.join();
        r->handshakeDone = false;
    }
    d->remotes.clear();
    d->enabled = false;
    d->handshakeDone = false;
}

#ifdef XMRIG_FEATURE_API
rapidjson::Value RemoteBackend::toJSON(rapidjson::Document &doc) const {
    using namespace rapidjson;
    auto &allocator = doc.GetAllocator();
    Value out(kObjectType);
    out.AddMember("type", type().toJSON(), allocator);
    out.AddMember("enabled", isEnabled(), allocator);
    out.AddMember("profile", profileName().toJSON(), allocator);
    // Extra fields for remote device visibility
    auto d = d_ptr;
    Value host;
    host.SetString(d->host.c_str(), static_cast<SizeType>(d->host.size()), allocator);
    out.AddMember("host", host, allocator);
    out.AddMember("port", d->port, allocator);
    out.AddMember("batch", d->batchSize, allocator);
    out.AddMember("handshake", d->handshakeDone, allocator);
    out.AddMember("device_cpu_count", d->deviceCpuCount, allocator);
    out.AddMember("device_max_batch", d->deviceMaxBatch, allocator);
    // derived status and activity age
    const char *st = d->handshakeDone ? "connected" : (d->enabled ? "connecting" : "disconnected");
    rapidjson::Value status;
    status.SetString(st, static_cast<rapidjson::SizeType>(std::strlen(st)), allocator);
    out.AddMember("status", status, allocator);
    uint64_t nowMs = static_cast<uint64_t>(
        std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now().time_since_epoch()).count());
    uint64_t lastMs = d->lastRxMs.load();
    uint64_t ageMs = (lastMs > 0 && nowMs > lastMs) ? (nowMs - lastMs) : 0;
    out.AddMember("last_rx_ms_ago", ageMs, allocator);
    uint64_t lastPing = d->lastPingMs.load();
    uint64_t pingAge = (lastPing > 0 && nowMs > lastPing) ? (nowMs - lastPing) : 0;
    out.AddMember("last_ping_ms_ago", pingAge, allocator);

    // Multi-remote detailed view
    if (!d->remotes.empty()) {
        rapidjson::Value arr(rapidjson::kArrayType);
        for (const auto &rp : d->remotes) {
            const auto r = rp.get();
            rapidjson::Value ro(rapidjson::kObjectType);
            rapidjson::Value h; h.SetString(r->host.c_str(), static_cast<rapidjson::SizeType>(r->host.size()), allocator);
            ro.AddMember("host", h, allocator);
            ro.AddMember("port", r->port, allocator);
            ro.AddMember("weight", r->weight, allocator);
            ro.AddMember("connected", r->handshakeDone, allocator);
            ro.AddMember("effective_batch", r->effectiveBatch, allocator);
            ro.AddMember("device_cpu_count", r->deviceCpuCount, allocator);
            ro.AddMember("device_max_batch", r->deviceMaxBatch, allocator);
            ro.AddMember("job_id", r->jobId, allocator);
            uint64_t lrx = r->lastRxMs.load();
            uint64_t lage = (lrx > 0 && nowMs > lrx) ? (nowMs - lrx) : 0;
            ro.AddMember("last_rx_ms_ago", lage, allocator);
            uint64_t lpg = r->lastPingMs.load();
            uint64_t page = (lpg > 0 && nowMs > lpg) ? (nowMs - lpg) : 0;
            ro.AddMember("last_ping_ms_ago", page, allocator);
            arr.PushBack(ro, allocator);
        }
        out.AddMember("remotes", arr, allocator);
    }
    return out;
}

void RemoteBackend::handleRequest(IApiRequest &) {}
#endif

} // namespace xmrig
