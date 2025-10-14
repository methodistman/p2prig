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
    if (!d->handshakeDone || d->sock < 0) return;
    d->jobCopy = job;
    d->nonceNext = 0;
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
    if (d->handshakeDone) return;
    // Env-only config for now
    const char *h = ::getenv("P2PRIG_HOST");
    const char *p = ::getenv("P2PRIG_PORT");
    const char *t = ::getenv("P2PRIG_TOKEN");
    if (!h || !p) {
        // remote disabled if host/port not provided
        return;
    }
    d->host = h;
    d->port = std::atoi(p);
    if (t) d->token = t;

    // Resolve and connect
    struct addrinfo hints{}; memset(&hints, 0, sizeof(hints));
    hints.ai_socktype = SOCK_STREAM; hints.ai_family = AF_UNSPEC;
    struct addrinfo *res = nullptr;
    char portbuf[16]; std::snprintf(portbuf, sizeof(portbuf), "%d", d->port);
    int rc = ::getaddrinfo(d->host.c_str(), portbuf, &hints, &res);
    if (rc != 0) {
        LOG_ERR("remote: resolve %s:%d failed: %s", d->host.c_str(), d->port, gai_strerror(rc));
        return;
    }
    int fd = -1;
    for (auto it = res; it; it = it->ai_next) {
        fd = ::socket(it->ai_family, it->ai_socktype, it->ai_protocol);
        if (fd < 0) continue;
        if (::connect(fd, it->ai_addr, it->ai_addrlen) == 0) break;
        ::close(fd); fd = -1;
    }
    ::freeaddrinfo(res);
    if (fd < 0) {
        LOG_ERR("remote: connect %s:%d failed", d->host.c_str(), d->port);
        return;
    }

    // Build CLIENT_HELLO: ver(be16)=1 | caps(be32) | tlen(be16) | token
    uint16_t ver = htons(1);
    uint32_t caps = htonl(0x00000001u); // bit0: RANDOMX support expected from device
    uint16_t tlen = htons(static_cast<uint16_t>(d->token.size()));
    std::vector<uint8_t> hello; hello.reserve(2+4+2 + d->token.size());
    hello.insert(hello.end(), reinterpret_cast<uint8_t*>(&ver), reinterpret_cast<uint8_t*>(&ver)+2);
    hello.insert(hello.end(), reinterpret_cast<uint8_t*>(&caps), reinterpret_cast<uint8_t*>(&caps)+4);
    hello.insert(hello.end(), reinterpret_cast<uint8_t*>(&tlen), reinterpret_cast<uint8_t*>(&tlen)+2);
    if (!d->token.empty()) hello.insert(hello.end(), d->token.begin(), d->token.end());
    if (!send_frame(fd, 0x30 /*CLIENT_HELLO*/, hello.data(), hello.size())) {
        LOG_ERR("remote: send CLIENT_HELLO failed");
        ::close(fd);
        return;
    }

    // Read response header
    uint8_t hdr[8]; ssize_t r = ::read(fd, hdr, 8);
    if (r != 8) { ::close(fd); return; }
    uint64_t len = 0; for (int i=0;i<8;i++){ len = (len<<8) | hdr[i]; }
    uint8_t op = 0; if (::read(fd, &op, 1) != 1) { ::close(fd); return; }
    std::vector<uint8_t> pl;
    if (len > 1) {
        pl.resize(static_cast<size_t>(len-1));
        if (::read(fd, pl.data(), pl.size()) != static_cast<ssize_t>(pl.size())) { ::close(fd); return; }
    }
    if (op == 0x7F /*ERROR*/) {
        if (pl.size() >= 4) {
            uint16_t c = (pl[0]<<8) | pl[1]; uint16_t mlen = (pl[2]<<8) | pl[3];
            std::string msg; if (pl.size() >= 4 + mlen) msg.assign(reinterpret_cast<char*>(pl.data()+4), reinterpret_cast<char*>(pl.data()+4)+mlen);
            LOG_ERR("remote: handshake ERROR code=%u msg=%s", (unsigned)c, msg.c_str());
        } else {
            LOG_ERR("remote: handshake ERROR");
        }
        ::close(fd);
        return;
    }
    if (op != 0x31 /*SERVER_HELLO*/ || pl.size() < 2+4+1) {
        LOG_ERR("remote: invalid SERVER_HELLO");
        ::close(fd);
        return;
    }
    uint16_t sver = (pl[0]<<8) | pl[1]; (void)sver;
    uint32_t scaps = (pl[2]<<24) | (pl[3]<<16) | (pl[4]<<8) | pl[5]; (void)scaps;
    uint8_t auth_req = pl[6]; (void)auth_req;

    d->sock = fd;
    d->enabled = true;
    d->handshakeDone = true;
    d->profileName = String("remote");
    LOG_INFO("%s remote connected to %s:%d (caps=0x%08x)", Tags::miner(), d->host.c_str(), d->port, scaps);

    // Optional: read META_RESP if present (non-blocking quick peek)
    ::fcntl(d->sock, F_SETFL, O_NONBLOCK);
    uint8_t pop; std::vector<uint8_t> ppl;
    if (recv_frame(d->sock, pop, ppl)) {
        // ignore content or parse JSON for max_batch
    }
    ::fcntl(d->sock, F_SETFL, 0);

    // batch size from env
    if (const char *bs = ::getenv("P2PRIG_BATCH")) {
        uint32_t v = static_cast<uint32_t>(::strtoul(bs, nullptr, 10));
        if (v > 0) d->batchSize = v;
    }

    // Start reader thread
    d->stopRx = false;
    d->rxThread = std::thread([d]() {
        for (;;) {
            if (d->stopRx) break;
            uint8_t op; std::vector<uint8_t> pay;
            if (!recv_frame(d->sock, op, pay)) break;
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
    return out;
}

void RemoteBackend::handleRequest(IApiRequest &) {}
#endif

} // namespace xmrig
