#ifndef NODE_H
#define NODE_H

#include <stdint.h>
#include <time.h>
#include "config.h"

#define NODE_ID_SIZE 32

typedef struct {
    int cpu_cores;
    uint64_t ram_mb;
    int can_host_dataset;
    int has_aes_ni;  // Hardware AES support for RandomX
    double compute_power;  // Relative compute score
} node_capabilities_t;

typedef struct {
    uint64_t hashes_computed;
    uint64_t shares_found;
    uint64_t work_units_completed;
    double hashrate;
    time_t started_at;
} node_stats_t;

typedef struct node_s {
    uint8_t id[NODE_ID_SIZE];
    char id_str[NODE_ID_SIZE * 2 + 1];
    config_t *config;
    node_capabilities_t capabilities;
    node_stats_t stats;
    void *mining_ctx;  // Mining context (RandomX or Ghostrider)
    const void *mining_algo;  // Pointer to mining_algo_interface_t
    void *dataset_ptr;  // Pointer to dataset if hosted
    int is_mining;
    time_t last_hashrate_update;
    uint64_t hashes_at_last_update;
} node_t;

// Node lifecycle
node_t *node_create(config_t *config);
void node_destroy(node_t *node);

// Capability detection
int node_detect_capabilities(node_t *node);

// Statistics
void node_print_stats(node_t *node);

// Mining control
int node_start_mining(node_t *node);
int node_stop_mining(node_t *node);

#endif // NODE_H
