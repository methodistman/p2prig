# Mining Algorithm Integration Guide

This document explains how to integrate RandomX and Ghostrider mining libraries into the P2P Mining Cluster.

## Current State

The framework provides:
- P2P networking for node communication
- Workload distribution system
- Capability detection and management
- Dataset hosting infrastructure

**What's Missing**: Actual mining algorithm implementations

## RandomX Integration

### 1. Install RandomX Library

```bash
# Clone RandomX
git clone https://github.com/tevador/randomx.git
cd randomx
mkdir build && cd build
cmake -DARCH=native ..
make
sudo make install
```

### 2. Update Makefile

```makefile
CFLAGS = -Wall -Wextra -O2 -std=c11 -pthread -I/usr/local/include
LDFLAGS = -pthread -lrandomx
```

### 3. Create RandomX Module

Create `src/mining_randomx.c` and `src/mining_randomx.h`:

```c
// mining_randomx.h
#ifndef MINING_RANDOMX_H
#define MINING_RANDOMX_H

#include <randomx.h>
#include "node.h"

typedef struct {
    randomx_cache *cache;
    randomx_dataset *dataset;
    randomx_vm *vm;
    randomx_flags flags;
} randomx_context_t;

int randomx_init(node_t *node);
void randomx_cleanup(node_t *node);
int randomx_compute_hash(node_t *node, const void *input, size_t input_len, void *output);
int randomx_init_dataset(node_t *node, const void *key, size_t key_len);

#endif
```

```c
// mining_randomx.c
#include "mining_randomx.h"
#include <stdlib.h>
#include <string.h>

int randomx_init(node_t *node) {
    randomx_context_t *ctx = malloc(sizeof(randomx_context_t));
    if (!ctx) return -1;
    
    // Determine flags based on capabilities
    ctx->flags = RANDOMX_FLAG_DEFAULT;
    if (node->capabilities.has_aes_ni) {
        ctx->flags |= RANDOMX_FLAG_HARD_AES;
    }
    
    // Use full memory mode if we can host dataset
    if (node->capabilities.can_host_dataset) {
        ctx->flags |= RANDOMX_FLAG_FULL_MEM;
    } else {
        ctx->flags |= RANDOMX_FLAG_LIGHT_MODE;
    }
    
    // Enable JIT if available
    ctx->flags |= RANDOMX_FLAG_JIT;
    
    // Allocate cache
    ctx->cache = randomx_alloc_cache(ctx->flags);
    if (!ctx->cache) {
        free(ctx);
        return -1;
    }
    
    // Allocate dataset if in full memory mode
    if (ctx->flags & RANDOMX_FLAG_FULL_MEM) {
        ctx->dataset = randomx_alloc_dataset(ctx->flags);
        if (!ctx->dataset) {
            randomx_release_cache(ctx->cache);
            free(ctx);
            return -1;
        }
    } else {
        ctx->dataset = NULL;
    }
    
    node->mining_ctx = ctx;
    return 0;
}

int randomx_init_dataset(node_t *node, const void *key, size_t key_len) {
    randomx_context_t *ctx = node->mining_ctx;
    if (!ctx) return -1;
    
    // Initialize cache with key
    randomx_init_cache(ctx->cache, key, key_len);
    
    // Initialize dataset if we have one
    if (ctx->dataset) {
        unsigned long dataset_items = randomx_dataset_item_count();
        
        // Multi-threaded dataset initialization
        #pragma omp parallel for
        for (unsigned long i = 0; i < dataset_items; i++) {
            randomx_init_dataset(ctx->dataset, ctx->cache, i, 1);
        }
        
        node->dataset_ptr = ctx->dataset;
    }
    
    // Create VM
    if (ctx->dataset) {
        ctx->vm = randomx_create_vm(ctx->flags, ctx->cache, ctx->dataset);
    } else {
        ctx->vm = randomx_create_vm(ctx->flags, ctx->cache, NULL);
    }
    
    return ctx->vm ? 0 : -1;
}

int randomx_compute_hash(node_t *node, const void *input, size_t input_len, void *output) {
    randomx_context_t *ctx = node->mining_ctx;
    if (!ctx || !ctx->vm) return -1;
    
    randomx_calculate_hash(ctx->vm, input, input_len, output);
    node->stats.hashes_computed++;
    
    return 0;
}

void randomx_cleanup(node_t *node) {
    randomx_context_t *ctx = node->mining_ctx;
    if (!ctx) return;
    
    if (ctx->vm) randomx_destroy_vm(ctx->vm);
    if (ctx->dataset) randomx_release_dataset(ctx->dataset);
    if (ctx->cache) randomx_release_cache(ctx->cache);
    
    free(ctx);
    node->mining_ctx = NULL;
}
```

### 4. Update Node Functions

In `node.c`, modify `node_start_mining()`:

```c
int node_start_mining(node_t *node) {
    if (!node || node->is_mining) return -1;
    
    if (node->config->algorithm == ALGO_RANDOMX) {
        if (randomx_init(node) != 0) {
            fprintf(stderr, "Failed to initialize RandomX\n");
            return -1;
        }
        
        // Initialize with a seed key (would come from pool)
        uint8_t seed_key[32] = {0};
        randomx_init_dataset(node, seed_key, sizeof(seed_key));
    }
    
    node->is_mining = 1;
    return 0;
}
```

### 5. Implement Mining Loop

Create dedicated mining threads in `workload.c`:

```c
void *mining_thread(void *arg) {
    node_t *node = (node_t *)arg;
    uint8_t hash[RANDOMX_HASH_SIZE];
    
    while (node->is_mining) {
        // Get work unit
        work_unit_t *work = get_current_work(node);
        if (!work) {
            usleep(100000);
            continue;
        }
        
        // Mine the work unit
        for (uint64_t nonce = work->nonce_start; nonce < work->nonce_end; nonce++) {
            // Prepare input
            uint8_t input[WORK_UNIT_SIZE + 8];
            memcpy(input, work->data, WORK_UNIT_SIZE);
            memcpy(input + WORK_UNIT_SIZE, &nonce, 8);
            
            // Compute hash
            randomx_compute_hash(node, input, sizeof(input), hash);
            
            // Check if it meets difficulty target
            if (check_difficulty(hash, work->target_difficulty)) {
                // Found a share!
                submit_share(node, work, nonce, hash);
                node->stats.shares_found++;
            }
        }
        
        // Mark work complete
        workload_complete_unit(work);
    }
    
    return NULL;
}
```

## Ghostrider Integration

### 1. Install Ghostrider

Ghostrider is a multi-algorithm system. You'll need:
- cpuminer-opt or similar implementation
- Multiple algorithm libraries (yespower, ghostrider variants)

```bash
git clone https://github.com/rplant8/cpuminer-opt-rplant
cd cpuminer-opt-rplant
./build.sh
```

### 2. Extract Algorithm Code

Extract the relevant algorithm implementations:
- `algo/ghostrider.c`
- `algo/yespower/`
- Supporting hash functions

### 3. Create Ghostrider Module

Similar structure to RandomX:

```c
// mining_ghostrider.h
#ifndef MINING_GHOSTRIDER_H
#define MINING_GHOSTRIDER_H

#include "node.h"

typedef struct {
    void *yespower_ctx;
    void *algo_contexts[16];  // Multiple algorithms
} ghostrider_context_t;

int ghostrider_init(node_t *node);
void ghostrider_cleanup(node_t *node);
int ghostrider_compute_hash(node_t *node, const void *input, void *output);

#endif
```

## Work Distribution

### Master Node Responsibilities

```c
// In master node logic
void master_distribute_work(network_t *network) {
    // Create work units based on current block
    for (int i = 0; i < network->peer_count; i++) {
        peer_t *peer = network->peers[i];
        
        // Calculate work size based on peer capabilities
        uint64_t nonce_range = calculate_nonce_range(peer);
        
        // Create work unit
        work_unit_t *work = workload_create_unit(
            wm, 
            current_block_data,
            next_nonce,
            next_nonce + nonce_range
        );
        
        // Assign to peer
        workload_assign_unit(work, peer->node_id);
        
        // Send via network
        send_work_assignment(peer, work);
        
        next_nonce += nonce_range;
    }
}
```

### Worker Node Mining

```c
// Worker receives work and mines
void worker_mine(node_t *node, work_unit_t *work) {
    uint8_t hash[32];
    
    for (uint64_t nonce = work->nonce_start; 
         nonce < work->nonce_end && node->is_mining; 
         nonce++) {
        
        // Prepare block with nonce
        uint8_t block[WORK_UNIT_SIZE + 8];
        memcpy(block, work->data, WORK_UNIT_SIZE);
        memcpy(block + WORK_UNIT_SIZE, &nonce, 8);
        
        // Compute hash
        if (node->config->algorithm == ALGO_RANDOMX) {
            randomx_compute_hash(node, block, sizeof(block), hash);
        } else {
            ghostrider_compute_hash(node, block, hash);
        }
        
        // Check difficulty
        if (meets_difficulty(hash, work->target_difficulty)) {
            // Submit share to master
            submit_result(node, work, nonce, hash);
        }
        
        // Update hashrate calculation
        update_hashrate(node);
    }
}
```

## Pool Integration

### 1. Stratum Protocol

Implement Stratum client on master node:

```c
// stratum.h
typedef struct {
    int socket;
    char *pool_url;
    int port;
    char *username;
    char *password;
    char current_job[256];
    uint32_t difficulty;
} stratum_context_t;

int stratum_connect(stratum_context_t *ctx);
int stratum_subscribe(stratum_context_t *ctx);
int stratum_authorize(stratum_context_t *ctx);
int stratum_get_job(stratum_context_t *ctx);
int stratum_submit_share(stratum_context_t *ctx, const char *nonce, const char *hash);
```

### 2. Job Distribution

Master receives jobs from pool and distributes to workers:

```
Pool → Master (Stratum) → Workers (P2P Protocol)
```

### 3. Share Submission

Workers find shares, submit to master, master forwards to pool:

```
Worker → Master (P2P) → Pool (Stratum)
```

## Performance Optimization

### 1. Huge Pages

Enable for RandomX dataset:

```c
ctx->flags |= RANDOMX_FLAG_LARGE_PAGES;
```

System configuration:
```bash
echo 1280 | sudo tee /proc/sys/vm/nr_hugepages
```

### 2. CPU Affinity

Pin threads to specific cores:

```c
#include <pthread.h>
#include <sched.h>

void set_thread_affinity(pthread_t thread, int core_id) {
    cpu_set_t cpuset;
    CPU_ZERO(&cpuset);
    CPU_SET(core_id, &cpuset);
    pthread_setaffinity_np(thread, sizeof(cpu_set_t), &cpuset);
}
```

### 3. NUMA Awareness

For multi-socket systems:

```c
#include <numa.h>

void initialize_numa() {
    if (numa_available() < 0) return;
    
    int num_nodes = numa_num_configured_nodes();
    // Bind threads to NUMA nodes appropriately
}
```

## Testing

### Unit Tests

Test individual algorithm implementations:

```c
void test_randomx_hash() {
    uint8_t input[] = "test input";
    uint8_t hash[RANDOMX_HASH_SIZE];
    uint8_t expected[RANDOMX_HASH_SIZE] = { /* known good hash */ };
    
    randomx_compute_hash(node, input, sizeof(input), hash);
    assert(memcmp(hash, expected, RANDOMX_HASH_SIZE) == 0);
}
```

### Integration Tests

Test full mining workflow:

```c
void test_full_mining_cycle() {
    // Start master
    // Start worker
    // Distribute work
    // Verify results
    // Check share submission
}
```

## Next Steps

1. Choose mining library (RandomX, Ghostrider, or both)
2. Integrate library into build system
3. Implement mining module
4. Add pool connectivity
5. Test thoroughly
6. Optimize for your specific hardware
7. Deploy to production

## References

- RandomX: https://github.com/tevador/randomx
- Ghostrider: https://github.com/rplant8/cpuminer-opt-rplant
- Stratum Protocol: https://braiins.com/stratum-v1/docs
- XMRig (reference implementation): https://github.com/xmrig/xmrig
