#ifndef MINING_GHOSTRIDER_H
#define MINING_GHOSTRIDER_H

#include "mining.h"

// Ghostrider uses multiple algorithms in sequence
#define GHOSTRIDER_NUM_ALGOS 5

typedef struct {
    void *algo_contexts[GHOSTRIDER_NUM_ALGOS];
    int num_threads;
    int is_initialized;
    // Dynamic plugin loader state (optional real Ghostrider implementation)
    void *dl_handle; // from dlopen()
    int using_plugin;
    // Function pointers resolved from plugin
    int (*pl_init)(int flags, int threads);
    int (*pl_init_dataset)(const uint8_t *key, size_t key_len);
    int (*pl_hash)(const uint8_t *input, size_t input_len, uint8_t *output);
    int (*pl_hash_batch)(const uint8_t **inputs, const size_t *lens, uint8_t **outputs, int count);
    size_t (*pl_dataset_size)(void);
    size_t (*pl_thread_mem_size)(void);
    void (*pl_cleanup)(void);
} ghostrider_context_t;

// Export interface
extern const mining_algo_interface_t ghostrider_interface;

#endif // MINING_GHOSTRIDER_H
