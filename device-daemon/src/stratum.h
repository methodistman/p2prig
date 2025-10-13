#ifndef STRATUM_H
#define STRATUM_H

#include <stdint.h>
#include <time.h>

#define STRATUM_MAX_HOST_LEN 256
#define STRATUM_MAX_USER_LEN 128
#define STRATUM_MAX_PASS_LEN 128
#define STRATUM_MAX_JOB_ID_LEN 64
#define STRATUM_BUFFER_SIZE 4096

// Stratum protocol states
typedef enum {
    STRATUM_STATE_DISCONNECTED,
    STRATUM_STATE_CONNECTING,
    STRATUM_STATE_CONNECTED,
    STRATUM_STATE_SUBSCRIBED,
    STRATUM_STATE_AUTHORIZED,
    STRATUM_STATE_READY
} stratum_state_t;

// Mining job from pool
typedef struct {
    char job_id[STRATUM_MAX_JOB_ID_LEN];
    uint8_t blob[256];          // Mining blob (block template)
    size_t blob_size;
    char target[65];            // Difficulty target (hex)
    char seed_hash[65];         // Monero seed hash (hex)
    char algo[16];              // e.g., rx/0
    uint32_t height;
    uint32_t target_u32;        // LE 32-bit target value from pool
    uint64_t difficulty;        // Derived difficulty ~= UINT32_MAX / target_u32
    uint64_t threshold64;       // 64-bit share threshold = (UINT64_MAX * target_u32) / UINT32_MAX
    uint8_t target256[32];      // Full 256-bit target in LE byte order for exact validation
    time_t received_at;
    int clean_jobs;             // Should clear old jobs
} stratum_job_t;

// Stratum connection context
typedef struct {
    // Connection info
    char host[STRATUM_MAX_HOST_LEN];
    int port;
    char user[STRATUM_MAX_USER_LEN];
    char password[STRATUM_MAX_PASS_LEN];
    
    // Socket
    int socket_fd;
    stratum_state_t state;
    
    // Protocol state
    uint64_t msg_id;
    char session_id[64];
    char extra_nonce[32];
    uint64_t pending_submit_id; // last submit's JSON-RPC id awaiting response
    
    // Current job
    stratum_job_t current_job;
    int has_job;
    
    // Statistics
    uint64_t jobs_received;
    uint64_t shares_submitted;
    uint64_t shares_accepted;
    uint64_t shares_rejected;
    time_t connected_at;
    time_t last_activity;
    
    // Buffers
    char recv_buffer[STRATUM_BUFFER_SIZE];
    size_t recv_len;
    char send_buffer[STRATUM_BUFFER_SIZE];
    
} stratum_t;

// Lifecycle
stratum_t *stratum_create(const char *host, int port, const char *user, const char *password);
void stratum_destroy(stratum_t *stratum);

// Connection
int stratum_connect(stratum_t *stratum);
int stratum_disconnect(stratum_t *stratum);
int stratum_is_connected(stratum_t *stratum);

// Protocol methods
int stratum_subscribe(stratum_t *stratum);
int stratum_authorize(stratum_t *stratum);
int stratum_submit_share(stratum_t *stratum, const char *job_id, uint64_t nonce, const char *result);

// Job management
int stratum_get_job(stratum_t *stratum, stratum_job_t *job);
int stratum_has_new_job(stratum_t *stratum);

// Event processing
int stratum_process(stratum_t *stratum, int timeout_ms);

// Utility
void stratum_print_stats(stratum_t *stratum);
const char *stratum_state_string(stratum_state_t state);

#endif // STRATUM_H
