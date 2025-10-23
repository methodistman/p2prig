#pragma once
#include <cstdint>

namespace xmrig {
namespace market {

class Market {
public:
    // Reserved opcodes for market frames (MVP)
    enum : uint8_t {
        MARKET_OFFER      = 0x71,
        MARKET_BID        = 0x72,
        MARKET_LEASE_ACK  = 0x73,
        MARKET_LEASE_NACK = 0x74,
        MARKET_SETTLE     = 0x75,
        MARKET_SETTLE_ACK = 0x76,
    };
};

} // namespace market
} // namespace xmrig
