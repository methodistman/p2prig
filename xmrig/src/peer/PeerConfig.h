#pragma once
#include <string>
#include <vector>
#include <cstdint>

namespace xmrig::peer {

struct PeerEndpoint {
    std::string host;
    uint16_t port{9000};
    std::string token;
    int weight{1};
};

struct PeerTLSConfig {
    bool enabled{false};
    std::string cert;
    std::string key;
    std::string ca;
    bool requireClientCert{false};
};

struct PeerSchedulerConfig {
    uint32_t targetMs{800};
    uint32_t maxInflight{4};
    bool leaseMode{true};
};

struct PeerModeConfig {
    bool enabled{false};
    std::string bind{"127.0.0.1"};
    uint16_t port{9000};
    std::string token;
    PeerTLSConfig tls;
    PeerSchedulerConfig sched;
    std::vector<PeerEndpoint> peers;
};

} // namespace xmrig::peer
