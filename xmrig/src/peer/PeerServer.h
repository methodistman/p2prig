#pragma once
#include <cstdint>
#include <string>
#include <atomic>
#include <memory>

#include "base/kernel/interfaces/ITcpServerListener.h"

namespace xmrig {
class Miner;
class TcpServer;
class String;
}

namespace xmrig::peer {

struct PeerServerConfig {
    std::string bindAddress;
    uint16_t port{9000};
    std::string token;
    bool tls{false};
};

class PeerServer : public ITcpServerListener {
public:
    explicit PeerServer(xmrig::Miner* miner);
    ~PeerServer() override;

    bool start(const PeerServerConfig& cfg);
    void stop();

    struct Stats {
        std::atomic<uint32_t> connections{0};
        std::atomic<uint64_t> received{0};
        std::atomic<uint64_t> sent{0};
    };

    const Stats& stats() const { return m_stats; }

protected:
    void onConnection(uv_stream_t *stream, uint16_t port) override;

private:
    xmrig::Miner* m_miner;
    Stats m_stats;
    std::unique_ptr<xmrig::TcpServer> m_server;
    PeerServerConfig m_cfg;
};

} // namespace xmrig::peer
