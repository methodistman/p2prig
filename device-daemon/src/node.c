#include "node.h"
#include "mining.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/sysinfo.h>

static void generate_node_id(node_t *node) {
    // Generate a random node ID
    FILE *urandom = fopen("/dev/urandom", "rb");
    if (urandom) {
        fread(node->id, 1, NODE_ID_SIZE, urandom);
        fclose(urandom);
    } else {
        // Fallback to time-based ID
        srand(time(NULL) ^ getpid());
        for (int i = 0; i < NODE_ID_SIZE; i++) {
            node->id[i] = rand() & 0xFF;
        }
    }

    // Convert to hex string
    for (int i = 0; i < NODE_ID_SIZE; i++) {
        sprintf(&node->id_str[i * 2], "%02x", node->id[i]);
    }
}

node_t *node_create(config_t *config) {
    node_t *node = calloc(1, sizeof(node_t));
    if (!node) {
        return NULL;
    }

    node->config = config;
    generate_node_id(node);
    node->stats.started_at = time(NULL);
    node->is_mining = 0;
    node->last_hashrate_update = time(NULL);
    node->hashes_at_last_update = 0;
    
    // Get algorithm interface
    node->mining_algo = mining_get_algorithm(config->algorithm);
    if (!node->mining_algo) {
        fprintf(stderr, "Failed to get algorithm interface\n");
        free(node);
        return NULL;
    }

    return node;
}

void node_destroy(node_t *node) {
    if (!node) {
        return;
    }

    if (node->is_mining) {
        node_stop_mining(node);
    }

    // Free dataset if allocated
    if (node->dataset_ptr) {
        free(node->dataset_ptr);
        node->dataset_ptr = NULL;
    }

    // Free mining context using algorithm's cleanup
    if (node->mining_ctx && node->mining_algo) {
        const mining_algo_interface_t *algo = node->mining_algo;
        algo->cleanup(node->mining_ctx);
        node->mining_ctx = NULL;
    }

    free(node);
}

int node_detect_capabilities(node_t *node) {
    if (!node) {
        return -1;
    }

    // Detect CPU cores
    node->capabilities.cpu_cores = sysconf(_SC_NPROCESSORS_ONLN);
    if (node->capabilities.cpu_cores <= 0) {
        node->capabilities.cpu_cores = 1;
    }

    // Auto-detect threads if not specified
    if (node->config->num_threads == 0) {
        node->config->num_threads = node->capabilities.cpu_cores;
    }

    // Detect available RAM
    struct sysinfo si;
    if (sysinfo(&si) == 0) {
        node->capabilities.ram_mb = (si.totalram * si.mem_unit) / (1024 * 1024);
    } else {
        node->capabilities.ram_mb = 0;
    }

    // Override with config if specified
    if (node->config->ram_mb > 0) {
        node->capabilities.ram_mb = node->config->ram_mb;
    }

    // Determine if this node can host dataset
    uint64_t required_mb = (node->config->algorithm == ALGO_RANDOMX) ?
                           RANDOMX_DATASET_SIZE_MB : GHOSTRIDER_DATASET_SIZE_MB;
    
    node->capabilities.can_host_dataset = 
        (node->capabilities.ram_mb >= required_mb * 1.5) || 
        node->config->is_dataset_host;

    // Check for AES-NI support (simplified - would need CPUID on real hardware)
    node->capabilities.has_aes_ni = 1;  // Assume yes for now

    // Calculate relative compute power
    node->capabilities.compute_power = node->capabilities.cpu_cores * 
                                      (node->capabilities.has_aes_ni ? 1.5 : 1.0);

    return 0;
}

void node_print_stats(node_t *node) {
    if (!node) {
        return;
    }

    time_t now = time(NULL);
    time_t uptime = now - node->stats.started_at;
    
    // Update hashrate
    time_t time_diff = now - node->last_hashrate_update;
    if (time_diff > 0) {
        uint64_t hash_diff = node->stats.hashes_computed - node->hashes_at_last_update;
        node->stats.hashrate = (double)hash_diff / (double)time_diff;
        node->last_hashrate_update = now;
        node->hashes_at_last_update = node->stats.hashes_computed;
    }

    printf("\n=== Node Statistics ===\n");
    printf("Node ID: %s\n", node->id_str);
    if (node->mining_algo) {
        const mining_algo_interface_t *algo = node->mining_algo;
        printf("Algorithm: %s\n", algo->name);
    }
    printf("Uptime: %ld seconds\n", uptime);
    printf("Hashes: %lu\n", node->stats.hashes_computed);
    printf("Shares: %lu\n", node->stats.shares_found);
    printf("Work Units: %lu\n", node->stats.work_units_completed);
    printf("Hashrate: %.2f H/s\n", node->stats.hashrate);
    printf("Mining: %s\n", node->is_mining ? "Active" : "Idle");
    printf("\n");
}

int node_start_mining(node_t *node) {
    if (!node || node->is_mining) {
        return -1;
    }
    
    const mining_algo_interface_t *algo = node->mining_algo;
    if (!algo) {
        fprintf(stderr, "No mining algorithm interface\n");
        return -1;
    }

    printf("Starting mining on node %s with %s...\n", node->id_str, algo->name);
    
    // Determine mining flags based on capabilities
    int flags = 0;
    if (node->capabilities.can_host_dataset) {
        flags |= MINING_FLAG_FULL_MEM;
    } else {
        flags |= MINING_FLAG_LIGHT_MODE;
    }
    
    if (node->capabilities.has_aes_ni) {
        flags |= MINING_FLAG_HARD_AES;
    }
    
    flags |= MINING_FLAG_JIT;
    
    // Initialize algorithm
    if (algo->init(&node->mining_ctx, flags, node->config->num_threads) != 0) {
        fprintf(stderr, "Failed to initialize %s\n", algo->name);
        return -1;
    }
    
    // Initialize dataset with a seed key
    // In production, this would come from the pool
    uint8_t seed_key[32];
    memset(seed_key, 0, sizeof(seed_key));
    // Use first 16 chars of node ID for seed
    memcpy(seed_key, "test_seed_", 10);
    memcpy(seed_key + 10, node->id_str, 22);
    
    if (algo->init_dataset(node->mining_ctx, seed_key, sizeof(seed_key)) != 0) {
        fprintf(stderr, "Failed to initialize dataset\n");
        algo->cleanup(node->mining_ctx);
        node->mining_ctx = NULL;
        return -1;
    }
    
    node->is_mining = 1;
    node->last_hashrate_update = time(NULL);
    node->hashes_at_last_update = node->stats.hashes_computed;
    
    printf("Mining started successfully\n");
    return 0;
}

int node_stop_mining(node_t *node) {
    if (!node || !node->is_mining) {
        return -1;
    }

    printf("Stopping mining on node %s...\n", node->id_str);
    node->is_mining = 0;
    
    // Cleanup mining context
    if (node->mining_ctx && node->mining_algo) {
        const mining_algo_interface_t *algo = node->mining_algo;
        algo->cleanup(node->mining_ctx);
        node->mining_ctx = NULL;
    }
    
    return 0;
}
