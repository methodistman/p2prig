#pragma once
#include <cstddef>
#include <cstdint>
#include <vector>
#include <mutex>

namespace xmrig {
class RxDataset;
}

namespace xmrig::peer {

class ScratchpadAllocator {
public:
    ScratchpadAllocator();
    ~ScratchpadAllocator();

    // Try to get a scratchpad backed by dataset 1GB huge pages; fallback to heap VM (to be implemented)
    uint8_t* acquire(xmrig::RxDataset* ds, size_t l3Bytes);
    void release(uint8_t* pad, size_t l3Bytes);

private:
    std::mutex mtx_;
    std::vector<uint8_t*> pool_;
};

} // namespace xmrig::peer
