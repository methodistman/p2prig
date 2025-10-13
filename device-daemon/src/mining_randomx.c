#include "mining_randomx.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// Check if RandomX library is available
#ifdef HAVE_RANDOMX
#include <randomx.h>
#ifdef _OPENMP
#include <omp.h>
#endif

static int randomx_init_impl(void **ctx, int flags, int num_threads) {
    randomx_context_t *rx_ctx = calloc(1, sizeof(randomx_context_t));
    if (!rx_ctx) {
        fprintf(stderr, "RandomX: Failed to allocate context\n");
        return -1;
    }
    
    // Convert our flags to RandomX flags
    randomx_flags rx_flags = RANDOMX_FLAG_DEFAULT;
    
    if (flags & MINING_FLAG_HARD_AES) {
        rx_flags |= RANDOMX_FLAG_HARD_AES;
    }
    if (flags & MINING_FLAG_JIT) {
        rx_flags |= RANDOMX_FLAG_JIT;
    }
    if (flags & MINING_FLAG_LARGE_PAGES) {
        rx_flags |= RANDOMX_FLAG_LARGE_PAGES;
    }
    if (flags & MINING_FLAG_FULL_MEM) {
        rx_flags |= RANDOMX_FLAG_FULL_MEM;
    }
    
    rx_ctx->flags = rx_flags;
    rx_ctx->num_threads = num_threads;
    
    // Allocate cache
    rx_ctx->cache = randomx_alloc_cache(rx_flags);
    if (!rx_ctx->cache) {
        fprintf(stderr, "RandomX: Failed to allocate cache\n");
        free(rx_ctx);
        return -1;
    }
    
    // Allocate dataset if in full memory mode
    if (flags & MINING_FLAG_FULL_MEM) {
        rx_ctx->dataset = randomx_alloc_dataset(rx_flags);
        if (!rx_ctx->dataset) {
            fprintf(stderr, "RandomX: Failed to allocate dataset\n");
            randomx_release_cache(rx_ctx->cache);
            free(rx_ctx);
            return -1;
        }
    }
    
    // Allocate VM array
    rx_ctx->vms = calloc(num_threads, sizeof(void*));
    if (!rx_ctx->vms) {
        fprintf(stderr, "RandomX: Failed to allocate VM array\n");
        if (rx_ctx->dataset) randomx_release_dataset(rx_ctx->dataset);
        randomx_release_cache(rx_ctx->cache);
        free(rx_ctx);
        return -1;
    }
    
    *ctx = rx_ctx;
    printf("RandomX: Initialized with %d threads (flags: 0x%x)\n", num_threads, rx_flags);
    return 0;
}

static int randomx_init_dataset_impl(void *ctx, const uint8_t *key, size_t key_len) {
    randomx_context_t *rx_ctx = (randomx_context_t *)ctx;
    if (!rx_ctx || !key) return -1;
    
    printf("RandomX: Initializing dataset with key (len=%zu)...\n", key_len);
    
    // Initialize cache with key
    randomx_init_cache(rx_ctx->cache, key, key_len);
    
    // Initialize dataset if we have one
    if (rx_ctx->dataset) {
        unsigned long dataset_items = randomx_dataset_item_count();
        printf("RandomX: Building dataset (%lu items)...\n", dataset_items);
        
        // Multi-threaded dataset initialization
        #pragma omp parallel for if(rx_ctx->num_threads > 1)
        for (unsigned long i = 0; i < dataset_items; i++) {
            randomx_init_dataset(rx_ctx->dataset, rx_ctx->cache, i, 1);
            
            // Progress indicator
            unsigned long step = (dataset_items / 10) ? (dataset_items / 10) : 1;
            if (i % step == 0) {
                unsigned long pct = dataset_items ? ((i * 100UL) / dataset_items) : 100UL;
                printf("RandomX: Dataset init progress: %lu%%\n", pct);
            }
        }
        printf("RandomX: Dataset initialization complete\n");
    }
    
    // Create VMs for each thread
    for (int i = 0; i < rx_ctx->num_threads; i++) {
        if (rx_ctx->dataset) {
            rx_ctx->vms[i] = randomx_create_vm(rx_ctx->flags, rx_ctx->cache, rx_ctx->dataset);
        } else {
            rx_ctx->vms[i] = randomx_create_vm(rx_ctx->flags, rx_ctx->cache, NULL);
        }
        
        if (!rx_ctx->vms[i]) {
            fprintf(stderr, "RandomX: Failed to create VM %d\n", i);
            return -1;
        }
    }
    
    rx_ctx->is_initialized = 1;
    printf("RandomX: Ready for mining\n");
    return 0;
}

static int randomx_compute_hash_impl(void *ctx, const uint8_t *input, size_t input_len, uint8_t *output) {
    randomx_context_t *rx_ctx = (randomx_context_t *)ctx;
    if (!rx_ctx || !rx_ctx->is_initialized || !input || !output) return -1;
    
    // Use first VM for single hash computation
    // In real implementation, you'd use thread-local VM
    randomx_calculate_hash(rx_ctx->vms[0], input, input_len, output);
    return 0;
}

static size_t randomx_get_dataset_size_impl(void) {
    return (size_t)RANDOMX_DATASET_SIZE_MB * 1024ULL * 1024ULL;
}

static size_t randomx_get_thread_mem_size_impl(void) {
    return RANDOMX_SCRATCHPAD_SIZE_KB * 1024;
}

static void randomx_cleanup_impl(void *ctx) {
    randomx_context_t *rx_ctx = (randomx_context_t *)ctx;
    if (!rx_ctx) return;
    
    printf("RandomX: Cleaning up...\n");
    
    // Destroy VMs
    if (rx_ctx->vms) {
        for (int i = 0; i < rx_ctx->num_threads; i++) {
            if (rx_ctx->vms[i]) {
                randomx_destroy_vm(rx_ctx->vms[i]);
            }
        }
        free(rx_ctx->vms);
    }
    
    // Release dataset
    if (rx_ctx->dataset) {
        randomx_release_dataset(rx_ctx->dataset);
    }
    
    // Release cache
    if (rx_ctx->cache) {
        randomx_release_cache(rx_ctx->cache);
    }
    
    free(rx_ctx);
}

static int randomx_compute_batch_impl(void *ctx, const uint8_t **inputs, size_t *input_lens,
                                      uint8_t **outputs, int count) {
    randomx_context_t *rx_ctx = (randomx_context_t *)ctx;
    if (!rx_ctx || !rx_ctx->is_initialized) return -1;
    
    // Batch processing with multiple VMs; map OpenMP threads 1:1 to VMs
    #ifdef _OPENMP
    #pragma omp parallel for if(rx_ctx->num_threads > 1) num_threads(rx_ctx->num_threads)
    for (int i = 0; i < count; i++) {
        int tid = omp_get_thread_num();
        randomx_calculate_hash(rx_ctx->vms[tid], inputs[i], input_lens[i], outputs[i]);
    }
    #else
    for (int i = 0; i < count; i++) {
        randomx_calculate_hash(rx_ctx->vms[0], inputs[i], input_lens[i], outputs[i]);
    }
    #endif
    
    return 0;
}

#else // No RandomX library available

// Stub implementation for testing without RandomX
static int randomx_init_impl(void **ctx, int flags, int num_threads) {
    (void)flags;
    randomx_context_t *rx_ctx = calloc(1, sizeof(randomx_context_t));
    if (!rx_ctx) return -1;
    rx_ctx->num_threads = num_threads;
    rx_ctx->is_initialized = 0;
    *ctx = rx_ctx;
    printf("RandomX: Using STUB implementation (library not available)\n");
    return 0;
}

static int randomx_init_dataset_impl(void *ctx, const uint8_t *key, size_t key_len) {
    randomx_context_t *rx_ctx = (randomx_context_t *)ctx;
    if (!rx_ctx) return -1;
    (void)key; (void)key_len;
    rx_ctx->is_initialized = 1;
    printf("RandomX STUB: Dataset initialized\n");
    return 0;
}

static int randomx_compute_hash_impl(void *ctx, const uint8_t *input, size_t input_len, uint8_t *output) {
    randomx_context_t *rx_ctx = (randomx_context_t *)ctx;
    if (!rx_ctx || !rx_ctx->is_initialized) return -1;
    
    // Simple hash stub - NOT cryptographically secure, just for testing
    memset(output, 0, HASH_SIZE);
    for (size_t i = 0; i < input_len; i++) {
        output[i % HASH_SIZE] ^= input[i];
    }
    return 0;
}

static size_t randomx_get_dataset_size_impl(void) {
    return 2080UL * 1024 * 1024; // 2080 MB
}

static size_t randomx_get_thread_mem_size_impl(void) {
    return 2048 * 1024; // 2 MB
}

static void randomx_cleanup_impl(void *ctx) {
    if (ctx) free(ctx);
}

static int randomx_compute_batch_impl(void *ctx, const uint8_t **inputs, size_t *input_lens,
                                      uint8_t **outputs, int count) {
    for (int i = 0; i < count; i++) {
        if (randomx_compute_hash_impl(ctx, inputs[i], input_lens[i], outputs[i]) != 0) {
            return -1;
        }
    }
    return 0;
}

#endif // HAVE_RANDOMX

// Export the interface
const mining_algo_interface_t randomx_interface = {
    .name = "RandomX",
    .init = randomx_init_impl,
    .init_dataset = randomx_init_dataset_impl,
    .compute_hash = randomx_compute_hash_impl,
    .get_dataset_size = randomx_get_dataset_size_impl,
    .get_thread_mem_size = randomx_get_thread_mem_size_impl,
    .cleanup = randomx_cleanup_impl,
    .compute_batch = randomx_compute_batch_impl
};
