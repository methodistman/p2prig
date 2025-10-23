#include "peer/PeerServer.h"
#include "base/net/tools/TcpServer.h"
#include "base/tools/String.h"
#include "peer/PeerSession.h"
#include <uv.h>

namespace xmrig::peer {

PeerServer::PeerServer(xmrig::Miner* miner) : m_miner(miner) {}
PeerServer::~PeerServer() { stop(); }

bool PeerServer::start(const PeerServerConfig& cfg) {
    if (m_server) {
        return true;
    }
    m_cfg = cfg;
    xmrig::String host(cfg.bindAddress.c_str());
    m_server.reset(new xmrig::TcpServer(host, cfg.port, this));
    const int rc = m_server->bind();
    return rc > 0;
}

void PeerServer::stop() {
    m_server.reset();
}

void PeerServer::onConnection(uv_stream_t *stream, uint16_t) {
    auto *client = new uv_tcp_t; // NOLINT
    uv_tcp_init(uv_default_loop(), client);
    if (uv_accept(stream, reinterpret_cast<uv_stream_t*>(client)) == 0) {
        m_stats.connections.fetch_add(1, std::memory_order_relaxed);
        // Hand ownership to session; session starts read and will close on error
        new PeerSession(m_miner, client, m_cfg.token);
    } else {
        uv_close(reinterpret_cast<uv_handle_t*>(client), [](uv_handle_t* h){ delete reinterpret_cast<uv_tcp_t*>(h); });
    }
}

} // namespace xmrig::peer
