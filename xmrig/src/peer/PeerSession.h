#pragma once
#include <cstdint>
#include <string>
#include <vector>

#include <uv.h>
#include <atomic>

#include "base/tools/Object.h"

namespace xmrig { class Miner; }

namespace xmrig::peer {

class PeerSession {
public:
    PeerSession(xmrig::Miner* miner, struct uv_tcp_s* client, const std::string& token);
    ~PeerSession();

private:
    static void onRead(uv_stream_t* stream, ssize_t nread, const uv_buf_t* buf);
    static void onClosed(uv_handle_t* h);
    static void onWrite(uv_write_t* req, int status);
    static void onTimeout(uv_timer_t* t);
    static void onOfferTimer(uv_timer_t* t);
    static void onWork(uv_work_t* req);
    static void onWorkAfter(uv_work_t* req, int status);

    void handleRead(const char* data, size_t len);
    bool parseFrames();
    bool processFrame(uint8_t opcode, const uint8_t* payload, size_t len);
    bool sendFrame(uint8_t opcode, const uint8_t* payload, size_t len);
    void close();
    void sendMarketOffer();

    struct XJTask {
        uint64_t jobId = 0;
        uint64_t sliceId = 0;
        std::vector<uint8_t> blob;
        uint16_t blobLen = 0;
        uint8_t nonceSize = 0;
        uint16_t nonceOffset = 0;
        uint64_t target = 0;
        uint64_t nonceBegin = 0;
        uint32_t nonceCount = 0;
        uint8_t seed[32]{};
        bool hasSeed = false;
        uint32_t height = 0;
        bool rx = false;
        bool xl = false;
    };

    bool parseXJBinary(const uint8_t* payload, size_t len, XJTask& out);
    bool startXJ(const XJTask& t);
    void computeXJ();

    xmrig::Miner* miner_;
    std::string token_;
    std::vector<uint8_t> rbuf_;
    uint64_t need_ = 0;
    bool closing_ = false;
    bool helloDone_ = false;
    struct uv_tcp_s* client_ = nullptr;
    uv_timer_t* timer_ = nullptr;
    uv_timer_t* offerTimer_ = nullptr;
    std::atomic<bool> busy_{false};
    std::atomic<bool> cancel_{false};
    uv_work_t* work_ = nullptr;
    XJTask xj_;
    struct XJResult { uint64_t nonce; uint8_t hash[32]; };
    std::vector<XJResult> xjResults_;
    uint64_t workDurMs_ = 0;

    // Market (MVP) - single active lease per session
    uint64_t lastLeaseId_ = 0;
    uint64_t leaseEndMs_ = 0;
    uint32_t pricePerKhash_ = 0;
    uint32_t capacityKhash_ = 0;
    uint32_t ackPricePerKhash_ = 0;
    uint32_t ackCapacityKhash_ = 0;
    uint32_t leaseMsCfg_ = 0;
    uint16_t feeBps_ = 0;
    bool leaseActive_ = false;
    uint64_t usedKhashAccum_ = 0;
    uint64_t msAccum_ = 0;
    uint32_t resultsAccum_ = 0;
};

} // namespace xmrig::peer
