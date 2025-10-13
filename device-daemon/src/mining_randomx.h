#ifndef MINING_RANDOMX_H
#define MINING_RANDOMX_H

#include "mining.h"

// RandomX-specific context
typedef struct {
    void *cache;        // randomx_cache*
    void *dataset;      // randomx_dataset*
    void **vms;         // randomx_vm* array, one per thread
    int num_threads;
    int flags;
    int is_initialized;
} randomx_context_t;

// Export interface
extern const mining_algo_interface_t randomx_interface;

#endif // MINING_RANDOMX_H
