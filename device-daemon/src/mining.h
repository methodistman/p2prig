#ifndef MINING_H
#define MINING_H

#include <stdint.h>
#include <stddef.h>
#include "config.h"

#define HASH_SIZE 32
#define MAX_INPUT_SIZE 256

// Mining algorithm interface - all algorithms must implement these functions
typedef struct mining_algo_interface_s {
    const char *name;
    
    // Initialize algorithm context
    int (*init)(void **ctx, int flags, int num_threads);
    
    // Initialize dataset with seed key
    int (*init_dataset)(void *ctx, const uint8_t *key, size_t key_len);
    
    // Compute a single hash
    int (*compute_hash)(void *ctx, const uint8_t *input, size_t input_len, uint8_t *output);
    
    // Get dataset size in bytes
    size_t (*get_dataset_size)(void);
    
    // Get per-thread memory requirement
    size_t (*get_thread_mem_size)(void);
    
    // Cleanup and free resources
    void (*cleanup)(void *ctx);
    
    // Optional: multi-hash batch processing for efficiency
    int (*compute_batch)(void *ctx, const uint8_t **inputs, size_t *input_lens, 
                        uint8_t **outputs, int count);
} mining_algo_interface_t;

// Algorithm flags
#define MINING_FLAG_FULL_MEM     (1 << 0)  // Use full dataset in memory
#define MINING_FLAG_LIGHT_MODE   (1 << 1)  // Light mode (less memory)
#define MINING_FLAG_HARD_AES     (1 << 2)  // Use hardware AES
#define MINING_FLAG_JIT          (1 << 3)  // Enable JIT compilation
#define MINING_FLAG_LARGE_PAGES  (1 << 4)  // Use huge pages

// Get algorithm interface by type
const mining_algo_interface_t *mining_get_algorithm(mining_algo_t algo);

// Helper functions
int mining_check_difficulty(const uint8_t *hash, uint32_t difficulty);
void mining_format_hash(const uint8_t *hash, char *output, size_t output_size);
uint64_t mining_hash_to_uint64(const uint8_t *hash);
// Compare two 256-bit little-endian values: returns 1 if a <= b, 0 otherwise
int mining_hash256_le_compare(const uint8_t a[32], const uint8_t b[32]);

#endif // MINING_H
