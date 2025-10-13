#include "mining_ghostrider.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dlfcn.h>
#include <errno.h>

// Ghostrider stub implementation with optional dynamic plugin; real integration TBD
#ifdef HAVE_GHOSTRIDER
#warning "HAVE_GHOSTRIDER defined, but no real Ghostrider implementation is integrated; using stub fallback."
#endif

static void ghostrider_try_load_plugin(ghostrider_context_t *gr_ctx, int flags, int num_threads) {
    if (!gr_ctx) return;
    const char *envp = getenv("GHOSTRIDER_PLUGIN_PATH");
    const char *cands[] = {
        envp && envp[0] ? envp : NULL,
        "libghostrider.so",
        "libghostrider-rtm.so",
        "librtmghostrider.so",
        "libgrhash.so",
        NULL
    };
    for (int i = 0; cands[i]; i++) {
        void *h = dlopen(cands[i], RTLD_NOW | RTLD_LOCAL);
        if (!h) continue;
        gr_ctx->pl_init          = (int(*)(int,int))dlsym(h, "ghostrider_init");
        gr_ctx->pl_init_dataset  = (int(*)(const uint8_t*,size_t))dlsym(h, "ghostrider_init_dataset");
        gr_ctx->pl_hash          = (int(*)(const uint8_t*,size_t,uint8_t*))dlsym(h, "ghostrider_hash");
        gr_ctx->pl_hash_batch    = (int(*)(const uint8_t **, const size_t *, uint8_t **, int))dlsym(h, "ghostrider_hash_batch");
        gr_ctx->pl_dataset_size  = (size_t(*)(void))dlsym(h, "ghostrider_dataset_size");
        gr_ctx->pl_thread_mem_size = (size_t(*)(void))dlsym(h, "ghostrider_thread_mem_size");
        gr_ctx->pl_cleanup       = (void(*)(void))dlsym(h, "ghostrider_cleanup");
        if (!gr_ctx->pl_init || !gr_ctx->pl_hash) {
            dlclose(h);
            gr_ctx->pl_init = NULL; gr_ctx->pl_hash = NULL; gr_ctx->pl_init_dataset = NULL;
            gr_ctx->pl_hash_batch = NULL; gr_ctx->pl_dataset_size = NULL; gr_ctx->pl_thread_mem_size = NULL; gr_ctx->pl_cleanup = NULL;
            continue;
        }
        int rc = gr_ctx->pl_init(flags, num_threads);
        if (rc == 0) {
            gr_ctx->dl_handle = h;
            gr_ctx->using_plugin = 1;
            fprintf(stdout, "Ghostrider: Loaded plugin '%s' successfully\n", cands[i]);
            return;
        } else {
            fprintf(stderr, "Ghostrider: plugin init failed for '%s' (rc=%d); falling back\n", cands[i], rc);
            dlclose(h);
        }
    }
}

// Stub implementation for testing without Ghostrider
static int ghostrider_init_impl(void **ctx, int flags, int num_threads) {
    (void)flags;
    ghostrider_context_t *gr_ctx = calloc(1, sizeof(ghostrider_context_t));
    if (!gr_ctx) return -1;
    
    gr_ctx->num_threads = num_threads;
    
    // In real implementation, initialize each algorithm context
    for (int i = 0; i < GHOSTRIDER_NUM_ALGOS; i++) {
        gr_ctx->algo_contexts[i] = NULL;
    }
    
    // Try dynamic plugin first
    ghostrider_try_load_plugin(gr_ctx, flags, num_threads);

    *ctx = gr_ctx;
    if (gr_ctx->using_plugin) {
        printf("Ghostrider: Using plugin-backed implementation\n");
    } else {
        #ifdef HAVE_GHOSTRIDER
        printf("Ghostrider: HAVE_GHOSTRIDER set but using STUB fallback (real library not integrated)\n");
        #else
        printf("Ghostrider: Using STUB implementation (library not available)\n");
        #endif
    }
    printf("Ghostrider: Initialized with %d threads\n", num_threads);
    return 0;
}

static int ghostrider_init_dataset_impl(void *ctx, const uint8_t *key, size_t key_len) {
    ghostrider_context_t *gr_ctx = (ghostrider_context_t *)ctx;
    if (!gr_ctx) return -1;
    
    (void)key;
    (void)key_len;
    
    if (gr_ctx->using_plugin && gr_ctx->pl_init_dataset) {
        int rc = gr_ctx->pl_init_dataset(key, key_len);
        gr_ctx->is_initialized = (rc == 0);
        return rc;
    } else {
        gr_ctx->is_initialized = 1;
        printf("Ghostrider STUB: Dataset initialized\n");
        return 0;
    }
}

static int ghostrider_compute_hash_impl(void *ctx, const uint8_t *input, size_t input_len, uint8_t *output) {
    ghostrider_context_t *gr_ctx = (ghostrider_context_t *)ctx;
    if (!gr_ctx || !gr_ctx->is_initialized) return -1;
    
    if (gr_ctx->using_plugin && gr_ctx->pl_hash) {
        return gr_ctx->pl_hash(input, input_len, output);
    }
    // Stub: Simple hash implementation
    memset(output, 0, HASH_SIZE);
    uint32_t hash_state = 0x12345678;
    for (size_t i = 0; i < input_len; i++) {
        hash_state ^= input[i];
        hash_state = (hash_state << 7) | (hash_state >> 25);
        hash_state *= 0x9e3779b9;
    }
    for (int i = 0; i < HASH_SIZE / 4; i++) {
        uint32_t val = hash_state;
        for (int j = 0; j < 4; j++) {
            output[i * 4 + j] = (val >> (j * 8)) & 0xFF;
        }
        hash_state = hash_state * 0x9e3779b9 + i;
    }
    return 0;
}

static size_t ghostrider_get_dataset_size_impl(void) {
    // If plugin supplies a custom dataset size, use it
    // Note: No context passed here; rely on a typical size when plugin isn't loaded
    if (0) {}
    return (size_t)GHOSTRIDER_DATASET_SIZE_MB * 1024ULL * 1024ULL; // default 256 MB
}

static size_t ghostrider_get_thread_mem_size_impl(void) {
    return 128 * 1024; // 128 KB per thread (approximate)
}

static void ghostrider_cleanup_impl(void *ctx) {
    ghostrider_context_t *gr_ctx = (ghostrider_context_t *)ctx;
    if (!gr_ctx) return;
    
    printf("Ghostrider: Cleaning up...\n");
    if (gr_ctx->using_plugin) {
        if (gr_ctx->pl_cleanup) gr_ctx->pl_cleanup();
        if (gr_ctx->dl_handle) dlclose(gr_ctx->dl_handle);
        gr_ctx->dl_handle = NULL;
        gr_ctx->using_plugin = 0;
    }
    
    // Free algorithm contexts
    for (int i = 0; i < GHOSTRIDER_NUM_ALGOS; i++) {
        if (gr_ctx->algo_contexts[i]) {
            free(gr_ctx->algo_contexts[i]);
        }
    }
    
    free(gr_ctx);
}

static int ghostrider_compute_batch_impl(void *ctx, const uint8_t **inputs, size_t *input_lens,
                                         uint8_t **outputs, int count) {
    ghostrider_context_t *gr_ctx = (ghostrider_context_t *)ctx;
    if (gr_ctx && gr_ctx->using_plugin && gr_ctx->pl_hash_batch) {
        return gr_ctx->pl_hash_batch(inputs, input_lens, outputs, count);
    }
    // Batch processing via per-hash fallback
    for (int i = 0; i < count; i++) {
        if (ghostrider_compute_hash_impl(ctx, inputs[i], input_lens[i], outputs[i]) != 0) {
            return -1;
        }
    }
    return 0;
}

// Export the interface
const mining_algo_interface_t ghostrider_interface = {
    .name = "Ghostrider",
    .init = ghostrider_init_impl,
    .init_dataset = ghostrider_init_dataset_impl,
    .compute_hash = ghostrider_compute_hash_impl,
    .get_dataset_size = ghostrider_get_dataset_size_impl,
    .get_thread_mem_size = ghostrider_get_thread_mem_size_impl,
    .cleanup = ghostrider_cleanup_impl,
    .compute_batch = ghostrider_compute_batch_impl
};
