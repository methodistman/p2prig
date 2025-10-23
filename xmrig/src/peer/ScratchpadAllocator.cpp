#include "peer/ScratchpadAllocator.h"
#include "crypto/rx/RxDataset.h"

namespace xmrig::peer {

ScratchpadAllocator::ScratchpadAllocator() = default;
ScratchpadAllocator::~ScratchpadAllocator() = default;

uint8_t* ScratchpadAllocator::acquire(xmrig::RxDataset* ds, size_t l3Bytes) {
    if (ds) {
        if (auto* p = ds->tryAllocateScrathpad()) {
            return p;
        }
    }

    // Fallback: simple heap allocation placeholder; Phase 2 will switch to VirtualMemory
    std::lock_guard<std::mutex> lk(mtx_);
    if (!pool_.empty()) {
        auto* p = pool_.back();
        pool_.pop_back();
        return p;
    }
    return new (std::nothrow) uint8_t[l3Bytes];
}

void ScratchpadAllocator::release(uint8_t* pad, size_t) {
    if (!pad) return;
    std::lock_guard<std::mutex> lk(mtx_);
    pool_.push_back(pad);
}

} // namespace xmrig::peer
