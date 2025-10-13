#ifndef CONFIG_H
#define CONFIG_H

#define DEFAULT_PORT 9999
#define DEFAULT_THREADS 0  // 0 = auto-detect
#define DEFAULT_RAM_MB 0   // 0 = auto-detect
#define MAX_ADDRESS_LEN 256

// RandomX dataset requirements
#define RANDOMX_DATASET_SIZE_MB 2080
#define RANDOMX_SCRATCHPAD_SIZE_KB 2048

// Ghostrider memory requirements (approximate)
#define GHOSTRIDER_DATASET_SIZE_MB 256

typedef enum {
    MODE_AUTO,
    MODE_MASTER,
    MODE_WORKER
} node_mode_t;

typedef enum {
    ALGO_RANDOMX,
    ALGO_GHOSTRIDER
} mining_algo_t;

typedef struct {
    node_mode_t mode;
    mining_algo_t algorithm;
    int port;
    char master_address[MAX_ADDRESS_LEN];
    int num_threads;
    int ram_mb;
    int is_dataset_host;
    
    // Pool configuration
    int use_pool;
    char pool_host[MAX_ADDRESS_LEN];
    int pool_port;
    char pool_user[MAX_ADDRESS_LEN];
    char pool_pass[MAX_ADDRESS_LEN];

    // Basic peer authentication (optional)
    // If require_auth is set, incoming peers must send HELLO v1 with matching token
    int require_auth;
    char auth_token[64];
    // If enabled, sign critical messages (e.g., hash requests/responses) with HMAC-SHA256
    int sign_messages;
} config_t;

void config_init(config_t *config);

#endif // CONFIG_H
