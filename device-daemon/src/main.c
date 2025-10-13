#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include "network.h"
#include "node.h"
#include "workload.h"
#include "config.h"
#include "stratum.h"
#include "mining.h"

static volatile int running = 1;

void signal_handler(int signum) {
    (void)signum;
    running = 0;
    fprintf(stderr, "\nShutting down gracefully...\n");
}

// Minimal hex -> bytes (utility for seed hash)
static int hex_to_bytes_util(const char *hex, uint8_t *out, size_t max_out, size_t *out_len) {
    if (!hex || !out) return -1;
    size_t n = strlen(hex);
    if (n % 2 != 0) return -1;
    size_t bytes = n / 2;
    if (bytes > max_out) return -1;
    for (size_t i = 0; i < bytes; i++) {
        char c1 = hex[2*i];
        char c2 = hex[2*i+1];
        int v1 = (c1 >= '0' && c1 <= '9') ? c1 - '0' : (c1 >= 'a' && c1 <= 'f') ? 10 + c1 - 'a' : (c1 >= 'A' && c1 <= 'F') ? 10 + c1 - 'A' : -1;
        int v2 = (c2 >= '0' && c2 <= '9') ? c2 - '0' : (c2 >= 'a' && c2 <= 'f') ? 10 + c2 - 'a' : (c2 >= 'A' && c2 <= 'F') ? 10 + c2 - 'A' : -1;
        if (v1 < 0 || v2 < 0) return -1;
        out[i] = (uint8_t)((v1 << 4) | v2);
    }
    if (out_len) *out_len = bytes;
    return 0;
}

void print_usage(const char *prog_name) {
    printf("Usage: %s [OPTIONS]\n", prog_name);
    printf("\nOptions:\n");
    printf("  -m, --mode MODE          Operation mode: master, worker, or auto (default: auto)\n");
    printf("  -p, --port PORT          Listen port (default: 9999)\n");
    printf("  -c, --connect HOST:PORT  Connect to master node\n");
    printf("  -a, --algo ALGO          Mining algorithm: randomx or ghostrider (default: randomx)\n");
    printf("  -t, --threads NUM        Number of mining threads (default: auto-detect)\n");
    printf("  -r, --ram SIZE           Available RAM in MB (default: auto-detect)\n");
    printf("  -d, --dataset-host       Act as dataset host for nodes with low RAM\n");
    printf("  --require-auth           Require peers to authenticate on HELLO (token)\n");
    printf("  --auth-token TOKEN       Shared token for peer authentication (with --require-auth)\n");
    printf("  --sign-messages          Sign critical RPC payloads with HMAC-SHA256 (uses auth token)\n");
    printf("\n");
    printf("Pool Mining Options:\n");
    printf("  -o, --pool HOST:PORT     Mining pool address\n");
    printf("  -u, --user USERNAME      Pool username/wallet address\n");
    printf("  -w, --password PASS      Pool password (default: x)\n");
    printf("\n");
    printf("  -h, --help               Show this help message\n");
    printf("\nExamples:\n");
    printf("  # Mine to pool\n");
    printf("  %s -o pool.example.com:3333 -u YOUR_WALLET -a randomx\n\n", prog_name);
    printf("  # Start as master node with dataset hosting\n");
    printf("  %s --mode master --port 9999 --dataset-host\n\n", prog_name);
    printf("  # Start as worker and connect to master\n");
    printf("  %s --mode worker --connect 192.168.1.100:9999\n\n", prog_name);
}

int main(int argc, char *argv[]) {
    config_t config;
    node_t *local_node = NULL;
    network_t *network = NULL;
    stratum_t *stratum = NULL;
    int ret = 0;

    // Initialize default configuration
    config_init(&config);

    // Parse command line arguments
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-m") == 0 || strcmp(argv[i], "--mode") == 0) {
            if (++i >= argc) {
                fprintf(stderr, "Error: --mode requires an argument\n");
                return 1;
            }
            if (strcmp(argv[i], "master") == 0) {
                config.mode = MODE_MASTER;
            } else if (strcmp(argv[i], "worker") == 0) {
                config.mode = MODE_WORKER;
            } else if (strcmp(argv[i], "auto") == 0) {
                config.mode = MODE_AUTO;
            } else {
                fprintf(stderr, "Error: Invalid mode '%s'\n", argv[i]);
                return 1;
            }
        } else if (strcmp(argv[i], "-p") == 0 || strcmp(argv[i], "--port") == 0) {
            if (++i >= argc) {
                fprintf(stderr, "Error: --port requires an argument\n");
                return 1;
            }
            config.port = atoi(argv[i]);
        } else if (strcmp(argv[i], "-c") == 0 || strcmp(argv[i], "--connect") == 0) {
            if (++i >= argc) {
                fprintf(stderr, "Error: --connect requires an argument\n");
                return 1;
            }
            strncpy(config.master_address, argv[i], sizeof(config.master_address) - 1);
            config.master_address[sizeof(config.master_address) - 1] = '\0';
        } else if (strcmp(argv[i], "-a") == 0 || strcmp(argv[i], "--algo") == 0) {
            if (++i >= argc) {
                fprintf(stderr, "Error: --algo requires an argument\n");
                return 1;
            }
            if (strcmp(argv[i], "randomx") == 0) {
                config.algorithm = ALGO_RANDOMX;
            } else if (strcmp(argv[i], "ghostrider") == 0) {
                config.algorithm = ALGO_GHOSTRIDER;
            } else {
                fprintf(stderr, "Error: Invalid algorithm '%s'\n", argv[i]);
                return 1;
            }
        } else if (strcmp(argv[i], "-t") == 0 || strcmp(argv[i], "--threads") == 0) {
            if (++i >= argc) {
                fprintf(stderr, "Error: --threads requires an argument\n");
                return 1;
            }
            config.num_threads = atoi(argv[i]);
        } else if (strcmp(argv[i], "-r") == 0 || strcmp(argv[i], "--ram") == 0) {
            if (++i >= argc) {
                fprintf(stderr, "Error: --ram requires an argument\n");
                return 1;
            }
            config.ram_mb = atoi(argv[i]);
        } else if (strcmp(argv[i], "--require-auth") == 0) {
            config.require_auth = 1;
        } else if (strcmp(argv[i], "--auth-token") == 0) {
            if (++i >= argc) {
                fprintf(stderr, "Error: --auth-token requires an argument\n");
                return 1;
            }
            strncpy(config.auth_token, argv[i], sizeof(config.auth_token) - 1);
            config.auth_token[sizeof(config.auth_token) - 1] = '\0';
        } else if (strcmp(argv[i], "--sign-messages") == 0) {
            config.sign_messages = 1;
        } else if (strcmp(argv[i], "-d") == 0 || strcmp(argv[i], "--dataset-host") == 0) {
            config.is_dataset_host = 1;
        } else if (strcmp(argv[i], "-o") == 0 || strcmp(argv[i], "--pool") == 0) {
            if (++i >= argc) {
                fprintf(stderr, "Error: --pool requires an argument\n");
                return 1;
            }
            config.use_pool = 1;
            // Parse HOST:PORT
            char *colon = strchr(argv[i], ':');
            if (colon) {
                size_t host_len = colon - argv[i];
                if (host_len >= sizeof(config.pool_host)) host_len = sizeof(config.pool_host) - 1;
                strncpy(config.pool_host, argv[i], host_len);
                config.pool_host[host_len] = '\0';
                config.pool_port = atoi(colon + 1);
            } else {
                strncpy(config.pool_host, argv[i], sizeof(config.pool_host) - 1);
                config.pool_host[sizeof(config.pool_host) - 1] = '\0';
            }
        } else if (strcmp(argv[i], "-u") == 0 || strcmp(argv[i], "--user") == 0) {
            if (++i >= argc) {
                fprintf(stderr, "Error: --user requires an argument\n");
                return 1;
            }
            strncpy(config.pool_user, argv[i], sizeof(config.pool_user) - 1);
            config.pool_user[sizeof(config.pool_user) - 1] = '\0';
        } else if (strcmp(argv[i], "-w") == 0 || strcmp(argv[i], "--password") == 0) {
            if (++i >= argc) {
                fprintf(stderr, "Error: --password requires an argument\n");
                return 1;
            }
            strncpy(config.pool_pass, argv[i], sizeof(config.pool_pass) - 1);
            config.pool_pass[sizeof(config.pool_pass) - 1] = '\0';
        } else if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
            print_usage(argv[0]);
            return 0;
        } else {
            fprintf(stderr, "Error: Unknown option '%s'\n", argv[i]);
            print_usage(argv[0]);
            return 1;
        }
    }
    
    // Set default pool password if not specified
    if (config.use_pool && config.pool_pass[0] == '\0') {
        strcpy(config.pool_pass, "x");
    }

    // Set up signal handlers
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);

    printf("=== P2P Mining Cluster ===\n");
    printf("Mode: %s\n", config.mode == MODE_MASTER ? "Master" :
                         config.mode == MODE_WORKER ? "Worker" : "Auto");
    printf("Algorithm: %s\n", config.algorithm == ALGO_RANDOMX ? "RandomX" : "Ghostrider");
    printf("Port: %d\n", config.port);
    printf("Threads: %d\n", config.num_threads);
    printf("RAM: %d MB\n", config.ram_mb);
    printf("Dataset Host: %s\n", config.is_dataset_host ? "Yes" : "No");
    printf("\n");

    // Initialize local node
    local_node = node_create(&config);
    if (!local_node) {
        fprintf(stderr, "Error: Failed to create local node\n");
        return 1;
    }

    // Detect hardware capabilities
    if (node_detect_capabilities(local_node) != 0) {
        fprintf(stderr, "Error: Failed to detect hardware capabilities\n");
        node_destroy(local_node);
        return 1;
    }

    printf("Hardware Capabilities:\n");
    printf("  CPU Cores: %d\n", local_node->capabilities.cpu_cores);
    printf("  Available RAM: %lu MB\n", local_node->capabilities.ram_mb);
    printf("  Can Host Dataset: %s\n", local_node->capabilities.can_host_dataset ? "Yes" : "No");
    printf("\n");

    // Initialize network
    network = network_create(&config, local_node);
    if (!network) {
        fprintf(stderr, "Error: Failed to initialize network\n");
        node_destroy(local_node);
        return 1;
    }

    // Start network listener
    if (network_start_listener(network) != 0) {
        fprintf(stderr, "Error: Failed to start network listener\n");
        network_destroy(network);
        node_destroy(local_node);
        return 1;
    }

    // Auto-discovery and master election for MODE_AUTO (when no explicit --connect provided)
    if (config.mode == MODE_AUTO && config.master_address[0] == '\0') {
        printf("Auto-discovery: searching for peers...\n");
        network_auto_discover_and_elect(network);
        printf("Role after election: %s\n", network->is_master ? "Master" : "Worker");
    }

    // Connect to master if specified
    if (config.master_address[0] != '\0') {
        printf("Connecting to master at %s...\n", config.master_address);
        if (network_connect_to_master(network, config.master_address) != 0) {
            fprintf(stderr, "Warning: Failed to connect to master\n");
        } else {
            printf("Connected to master successfully\n");
        }
    }

    // Initialize pool connection if specified
    if (config.use_pool) {
        printf("Pool Configuration:\n");
        printf("  Host: %s:%d\n", config.pool_host, config.pool_port);
        printf("  User: %s\n", config.pool_user);
        printf("\n");
        
        stratum = stratum_create(config.pool_host, config.pool_port, 
                                 config.pool_user, config.pool_pass);
        if (!stratum) {
            fprintf(stderr, "Error: Failed to create Stratum connection\n");
        } else {
            if (stratum_connect(stratum) == 0) {
                printf("Stratum: Connected, subscribing...\n");
                stratum_subscribe(stratum);
                sleep(1);
                stratum_authorize(stratum);
            } else {
                fprintf(stderr, "Warning: Failed to connect to pool\n");
            }
        }
    }

    // Start mining
    printf("Initializing mining...\n");
    if (node_start_mining(local_node) != 0) {
        fprintf(stderr, "Warning: Failed to start mining\n");
    }

    // Main loop
    printf("Node is running. Press Ctrl+C to stop.\n\n");
    // periodic timers
    static time_t last_broadcast = 0;
    // Pool mining state
    static char last_job_id[STRATUM_MAX_JOB_ID_LEN] = {0};
    static char last_seed_hash[65] = {0};
    static uint64_t local_nonce = 0;
    static uint8_t current_seed[32] = {0};
    static int current_seed_valid = 0;
    // Batch mining buffers (allocated on first use)
    static uint8_t *batch_inputs = NULL;   // BATCH_SIZE * 256
    static uint8_t *batch_outputs = NULL;  // BATCH_SIZE * HASH_SIZE
    static const uint8_t **in_ptrs = NULL;
    static size_t *in_lens = NULL;
    static uint8_t **out_ptrs = NULL;
    const int BATCH_SIZE = 1024; // tune as needed

    while (running) {
        // Process network events
        network_process_events(network, 100);

        // Process Stratum pool events
        if (stratum && stratum_is_connected(stratum)) {
            stratum_process(stratum, 100);
        }

        // Process workload (local synthetic when not using pool)
        if (!config.use_pool) {
            workload_process(local_node);
        }

        // Pool job mining step
        if (config.use_pool && stratum && stratum_is_connected(stratum)) {
            stratum_job_t job;
            if (stratum_get_job(stratum, &job) == 0) {
                // Initialize dataset if seed changed
                if (job.seed_hash[0] != '\0' && strcmp(job.seed_hash, last_seed_hash) != 0) {
                    uint8_t seed_bytes[32]; size_t seed_len = 0;
                    if (hex_to_bytes_util(job.seed_hash, seed_bytes, sizeof(seed_bytes), &seed_len) == 0 && local_node->mining_algo && local_node->mining_ctx) {
                        const mining_algo_interface_t *algo = (const mining_algo_interface_t *)local_node->mining_algo;
                        printf("%s: Reinitializing dataset for new seed...\n", (algo && algo->name) ? algo->name : "Algo");
                        if (algo->init_dataset(local_node->mining_ctx, seed_bytes, seed_len) == 0) {
                            strncpy(last_seed_hash, job.seed_hash, sizeof(last_seed_hash) - 1);
                            last_seed_hash[sizeof(last_seed_hash) - 1] = '\0';
                            // Cache seed for remote hashing requests
                            if (seed_len >= 32) {
                                memcpy(current_seed, seed_bytes, 32);
                                current_seed_valid = 1;
                            }
                            // Update dataset host selection in case roles depend on memory availability
                            network_select_dataset_host(network);
                        }
                    }
                }

                // Reset nonce on new job
                if (strncmp(job.job_id, last_job_id, sizeof(job.job_id)) != 0) {
                    strncpy(last_job_id, job.job_id, sizeof(last_job_id) - 1);
                    last_job_id[sizeof(last_job_id) - 1] = '\0';
                    local_nonce = 0;
                    printf("Job params: target_u32=0x%08x difficulty=%llu threshold64=%llu\n",
                           job.target_u32, (unsigned long long)job.difficulty, (unsigned long long)job.threshold64);
                }

                // Mine a small batch of nonces per loop
                const size_t nonce_offset = 39; // Monero nonce offset in header
                if (job.blob_size <= nonce_offset + 4) {
                    fprintf(stderr, "Mining: Invalid blob size %zu (nonce offset %zu)\n", job.blob_size, nonce_offset);
                } else if (local_node->mining_algo && local_node->mining_ctx) {
                    const mining_algo_interface_t *algo = (const mining_algo_interface_t *)local_node->mining_algo;

                    // Allocate batch buffers on first use
                    if (!batch_inputs) {
                        batch_inputs = (uint8_t*)malloc((size_t)BATCH_SIZE * 256);
                        batch_outputs = (uint8_t*)malloc((size_t)BATCH_SIZE * HASH_SIZE);
                        in_ptrs = (const uint8_t**)malloc((size_t)BATCH_SIZE * sizeof(uint8_t*));
                        in_lens = (size_t*)malloc((size_t)BATCH_SIZE * sizeof(size_t));
                        out_ptrs = (uint8_t**)malloc((size_t)BATCH_SIZE * sizeof(uint8_t*));
                        if (!batch_inputs || !batch_outputs || !in_ptrs || !in_lens || !out_ptrs) {
                            fprintf(stderr, "Mining: Failed to allocate batch buffers\n");
                            free(batch_inputs); free(batch_outputs); free(in_ptrs); free(in_lens); free(out_ptrs);
                            batch_inputs = batch_outputs = NULL; in_ptrs = NULL; in_lens = NULL; out_ptrs = NULL;
                        }
                    }

                    if (batch_inputs && batch_outputs && in_ptrs && in_lens && out_ptrs) {
                        // Prepare batch
                        int count = BATCH_SIZE;
                        for (int i = 0; i < count; i++) {
                            uint8_t *buf = batch_inputs + ((size_t)i * 256);
                            memcpy(buf, job.blob, job.blob_size);
                            uint32_t n = (uint32_t)((local_nonce + (uint64_t)i) & 0xFFFFFFFFu);
                            // write nonce little-endian
                            buf[nonce_offset + 0] = (uint8_t)(n & 0xFF);
                            buf[nonce_offset + 1] = (uint8_t)((n >> 8) & 0xFF);
                            buf[nonce_offset + 2] = (uint8_t)((n >> 16) & 0xFF);
                            buf[nonce_offset + 3] = (uint8_t)((n >> 24) & 0xFF);
                            in_ptrs[i] = buf;
                            in_lens[i] = job.blob_size;
                            out_ptrs[i] = batch_outputs + ((size_t)i * HASH_SIZE);
                        }

                        // Decide local vs remote hashing (dataset host sharing)
                        peer_t *host_peer = network_get_dataset_host(network);
                        int used_remote = 0;
                        int rc = -1;
                        if (host_peer && !local_node->capabilities.can_host_dataset && current_seed_valid) {
                            // Try remote hashing via dataset host
                            rc = network_request_remote_hashes(network, host_peer, current_seed,
                                                              in_ptrs, in_lens, out_ptrs, count, 2000);
                            if (rc == 0) {
                                used_remote = 1;
                            } else {
                                fprintf(stderr, "Remote hashing failed, falling back to local compute (rc=%d)\n", rc);
                            }
                        }
                        if (!used_remote) {
                            // Compute batch locally
                            rc = algo->compute_batch(local_node->mining_ctx, in_ptrs, in_lens, out_ptrs, count);
                            if (rc != 0) {
                                fprintf(stderr, "Mining: compute_batch failed (rc=%d)\n", rc);
                                // Fallback: try a smaller batch of 64
                                count = 64;
                                for (int i = 0; i < count; i++) {
                                    if (algo->compute_hash(local_node->mining_ctx, in_ptrs[i], in_lens[i], out_ptrs[i]) != 0) {
                                        fprintf(stderr, "Mining: compute_hash failed at i=%d\n", i);
                                    }
                                }
                            }
                        }

                        local_node->stats.hashes_computed += count;

                        // Check results using full 256-bit comparison
                        for (int i = 0; i < count; i++) {
                            uint8_t *h = out_ptrs[i];
                            // Use full 256-bit target comparison (hash256 <= target256)
                            if (job.target_u32 > 0 && mining_hash256_le_compare(h, job.target256)) {
                                local_node->stats.shares_found++;
                                uint32_t n = (uint32_t)((local_nonce + (uint64_t)i) & 0xFFFFFFFFu);
                                char result_hex[HASH_SIZE * 2 + 1];
                                mining_format_hash(h, result_hex, sizeof(result_hex));
                                // Log with 64-bit approximation for quick diagnosis, but submit is gated by full 256-bit check
                                uint64_t hv = mining_hash_to_uint64(h);
                                printf("Share candidate (256-bit valid): job=%s nonce=%u hash64=%llu (target_u32=0x%08x)\n", 
                                       job.job_id, n, (unsigned long long)hv, job.target_u32);
                                if (stratum_submit_share(stratum, job.job_id, n, result_hex) != 0) {
                                    fprintf(stderr, "Stratum: submit failed for nonce=%u\n", n);
                                }
                                local_nonce += (uint64_t)(i + 1);
                                goto after_batch;
                            }
                        }
                        local_nonce += (uint64_t)count;
                    }
                }
after_batch: ;
            }
        }

        // Broadcast local stats to peers every 5s for live hashrate table
        time_t now_bcast = time(NULL);
        if (now_bcast - last_broadcast >= 5) {
            network_broadcast_stats(network);
            last_broadcast = now_bcast;
        }

        // Print periodic stats
        static time_t last_stats = 0;
        time_t now = time(NULL);
        if (now - last_stats >= 30) {
            node_print_stats(local_node);
            network_print_stats(network);
            if (stratum) {
                stratum_print_stats(stratum);
            }
            last_stats = now;
        }
    }

    // Cleanup
    printf("Cleaning up...\n");
    if (stratum) {
        stratum_disconnect(stratum);
        stratum_destroy(stratum);
    }
    network_destroy(network);
    node_destroy(local_node);

    printf("Shutdown complete.\n");
    return ret;
}
