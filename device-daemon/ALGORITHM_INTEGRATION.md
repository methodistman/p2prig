# Algorithm Integration - Modular Design

## Overview

The P2P Mining Cluster uses a **modular algorithm interface** that allows easy integration of different mining algorithms without modifying core code.

## Architecture

### Abstraction Layer (`mining.h`)

All algorithms implement the `mining_algo_interface_t` interface:

```c
typedef struct mining_algo_interface_s {
    const char *name;
    int (*init)(void **ctx, int flags, int num_threads);
    int (*init_dataset)(void *ctx, const uint8_t *key, size_t key_len);
    int (*compute_hash)(void *ctx, const uint8_t *input, size_t input_len, uint8_t *output);
    size_t (*get_dataset_size)(void);
    size_t (*get_thread_mem_size)(void);
    void (*cleanup)(void *ctx);
    int (*compute_batch)(void *ctx, const uint8_t **inputs, size_t *input_lens, 
                        uint8_t **outputs, int count);
} mining_algo_interface_t;
```

### Current Implementations

1. **RandomX** (`mining_randomx.c`)
   - Stub implementation (works without RandomX library)
   - Full implementation available when compiled with `-DHAVE_RANDOMX`
   
2. **Ghostrider** (`mining_ghostrider.c`)
   - Stub implementation (works without Ghostrider libraries)
   - Full implementation available when compiled with `-DHAVE_GHOSTRIDER`

## File Structure

```
src/
├── mining.h              # Algorithm interface definition
├── mining.c              # Common utilities and algorithm registry
├── mining_randomx.h      # RandomX-specific headers
├── mining_randomx.c      # RandomX implementation
├── mining_ghostrider.h   # Ghostrider-specific headers
└── mining_ghostrider.c   # Ghostrider implementation
```

## Adding a New Algorithm

### Step 1: Create Algorithm Files

Create `src/mining_newalgo.h`:
```c
#ifndef MINING_NEWALGO_H
#define MINING_NEWALGO_H

#include "mining.h"

typedef struct {
    // Algorithm-specific context
    int num_threads;
    void *internal_state;
} newalgo_context_t;

extern const mining_algo_interface_t newalgo_interface;

#endif
```

Create `src/mining_newalgo.c`:
```c
#include "mining_newalgo.h"

static int newalgo_init(void **ctx, int flags, int num_threads) {
    newalgo_context_t *algo_ctx = calloc(1, sizeof(newalgo_context_t));
    if (!algo_ctx) return -1;
    
    algo_ctx->num_threads = num_threads;
    // Initialize your algorithm here
    
    *ctx = algo_ctx;
    return 0;
}

static int newalgo_compute_hash(void *ctx, const uint8_t *input, 
                                size_t input_len, uint8_t *output) {
    newalgo_context_t *algo_ctx = ctx;
    // Compute hash using your algorithm
    return 0;
}

// Implement other interface functions...

const mining_algo_interface_t newalgo_interface = {
    .name = "NewAlgo",
    .init = newalgo_init,
    .init_dataset = newalgo_init_dataset,
    .compute_hash = newalgo_compute_hash,
    .get_dataset_size = newalgo_get_dataset_size,
    .get_thread_mem_size = newalgo_get_thread_mem_size,
    .cleanup = newalgo_cleanup,
    .compute_batch = newalgo_compute_batch
};
```

### Step 2: Register Algorithm

In `config.h`, add enum value:
```c
typedef enum {
    ALGO_RANDOMX,
    ALGO_GHOSTRIDER,
    ALGO_NEWALGO  // Add your algorithm
} mining_algo_t;
```

In `mining.c`, add to registry:
```c
extern const mining_algo_interface_t newalgo_interface;

const mining_algo_interface_t *mining_get_algorithm(mining_algo_t algo) {
    switch (algo) {
        case ALGO_RANDOMX:
            return &randomx_interface;
        case ALGO_GHOSTRIDER:
            return &ghostrider_interface;
        case ALGO_NEWALGO:
            return &newalgo_interface;
        default:
            return NULL;
    }
}
```

### Step 3: Add CLI Support

In `main.c`, add command-line parsing:
```c
} else if (strcmp(argv[i], "newalgo") == 0) {
    config.algorithm = ALGO_NEWALGO;
```

That's it! Your algorithm is now integrated.

## Stub vs Full Implementation

### Stub Implementation (Current)

- Works immediately without external dependencies
- Uses simple hash functions for testing
- Perfect for development and testing the P2P infrastructure
- Allows the system to run and demonstrate functionality

### Full Implementation

To use real mining libraries:

1. **Install the library**
   ```bash
   # For RandomX
   git clone https://github.com/tevador/randomx.git
   cd randomx && mkdir build && cd build
   cmake -DARCH=native ..
   make && sudo make install
   ```

2. **Update Makefile**
   ```makefile
   # Uncomment these lines:
   CFLAGS += -DHAVE_RANDOMX -I/usr/local/include
   LDFLAGS += -lrandomx
   ```

3. **Rebuild**
   ```bash
   make clean && make
   ```

## Testing

### Test RandomX
```bash
./bin/p2p-miner --algo randomx --threads 2
```

### Test Ghostrider
```bash
./bin/p2p-miner --algo ghostrider --threads 2
```

## Benefits of Modular Design

1. **Easy to add algorithms** - Just implement the interface
2. **No core code changes** - Algorithms are isolated
3. **Testable** - Stub implementations allow testing without dependencies
4. **Switchable** - Change algorithms at runtime via CLI
5. **Maintainable** - Each algorithm in its own file

## Performance Considerations

### Flags

The system automatically sets optimal flags based on hardware:

- `MINING_FLAG_FULL_MEM` - Use full dataset (if RAM available)
- `MINING_FLAG_LIGHT_MODE` - Light mode for low-RAM systems
- `MINING_FLAG_HARD_AES` - Enable hardware AES (if supported)
- `MINING_FLAG_JIT` - Enable JIT compilation
- `MINING_FLAG_LARGE_PAGES` - Use huge pages for performance

### Batch Processing

Implement `compute_batch()` for better performance when processing multiple hashes:

```c
static int algo_compute_batch(void *ctx, const uint8_t **inputs, 
                              size_t *input_lens, uint8_t **outputs, int count) {
    #pragma omp parallel for
    for (int i = 0; i < count; i++) {
        compute_hash(ctx, inputs[i], input_lens[i], outputs[i]);
    }
    return 0;
}
```

## Real-World Example

See `src/mining_randomx.c` for a complete example with:
- Conditional compilation (`#ifdef HAVE_RANDOMX`)
- Full and stub implementations
- Multi-threaded dataset initialization
- VM management per thread
- Progress reporting
